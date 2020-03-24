"""Token parsing and storage."""

from __future__ import annotations

import base64
import json
import logging
import os
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, cast

import jwt
import redis
import requests
from cachetools import TTLCache, cached
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from flask import current_app
from flask_wtf import FlaskForm
from wtforms import BooleanField, HiddenField, SubmitField

from jwt_authorizer import config
from jwt_authorizer.session import Session, SessionStore, Ticket
from jwt_authorizer.util import add_padding, get_redis_client

__all__ = [
    "AlterTokenForm",
    "Issuer",
    "TokenVerifier",
    "add_padding",
    "api_capabilities_token_form",
    "create_token_verifier",
    "get_key_as_pem",
    "get_tokens",
    "issue_token",
    "revoke_token",
]


if TYPE_CHECKING:
    from flask import Flask
    from typing import Any, Dict, List, Mapping, Optional, Tuple

logger = logging.getLogger(__name__)


def issue_token(
    payload: Mapping[str, Any],
    aud: str,
    store_user_info: bool,
    oauth2_proxy_ticket: Ticket,
    redis_client: Optional[redis.Redis] = None,
) -> str:
    """Issue a token.

    This makes a copy of the token, sets the audience, expiration, issuer, and
    issue time as appropriate, and then returns the token in encoded form. If
    configured, it will also store the newly issued token a oauth2_proxy redis
    session store.

    Parameters
    ----------
    payload : Mapping[`str`, Any]
        The payload of claims for the token.
    aud : `str`
        The audience for the new token.
    store_user_info : `bool`
        Whether to store information about this token in the per-user token
        list used by the /auth/tokens route.
    oauth2_proxy_ticket : `Ticket`
        The Ticket to use to represent the token.
    redis_client : Optional[`redis.Redis`]
        The optional Redis client to use if one should not be created from the
        general application Redis pool.  Used primarily for testing.

    Returns
    -------
    token : `str`
        The new encoded token.
    """
    # Make a copy first
    exp = datetime.utcnow() + timedelta(
        minutes=current_app.config["OAUTH2_JWT_EXP"]
    )
    payload = _build_payload(aud, exp, payload, oauth2_proxy_ticket)

    private_key = current_app.config["OAUTH2_JWT.KEY"]
    headers = {"kid": current_app.config["OAUTH2_JWT.KEY_ID"]}
    encoded_reissued_token = jwt.encode(
        payload, private_key, algorithm=config.ALGORITHM, headers=headers
    ).decode("utf-8")

    if current_app.config.get("OAUTH2_STORE_SESSION"):
        session = Session(
            token=encoded_reissued_token,
            email=payload["email"],
            user=payload["email"],
            created_at=datetime.utcnow(),
            expires_on=exp,
        )
        o2proxy_store_token_redis(
            payload,
            session,
            store_user_info,
            oauth2_proxy_ticket,
            redis_client,
        )
    return encoded_reissued_token


def _build_payload(
    audience: str,
    expires: datetime,
    decoded_token: Mapping[str, Any],
    ticket: Ticket,
) -> Dict[str, Any]:
    """Build a new token payload based on an existing token.

    Parameters
    ----------
    audience : `str`
        The new token audience.
    expires : `datetime`
        When this token expires.
    decoded_token : Mapping[`str`, Any]
        The decoded token on which to base this token.
    ticket : `Ticket`
        The ticket to use (ticket handle used with JTI).

    Returns
    -------
    payload : Dict[`str`, Any]
        A new payload for issuing the new ticket.
    """
    prefix = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]

    previous_jti = decoded_token.get("jti")
    previous_act = decoded_token.get("act")
    previous_aud = decoded_token.get("aud")
    previous_iss = decoded_token.get("iss")

    payload = dict(decoded_token)
    payload["iss"] = current_app.config["OAUTH2_JWT.ISS"]
    payload["iat"] = datetime.utcnow()
    payload["exp"] = expires
    payload["jti"] = ticket.as_handle(prefix)
    payload["aud"] = audience

    if previous_aud and previous_iss:
        actor_claim = {"aud": previous_aud, "iss": previous_iss}
        if previous_jti:
            actor_claim["jti"] = previous_jti
        if previous_act:
            actor_claim["act"] = previous_act
        payload["act"] = actor_claim
    return payload


def api_capabilities_token_form(capabilities: Dict[str, str]) -> FlaskForm:
    """Dynamically generates a form with checkboxes for capabilities.

    Parameters
    ----------
    capabilities : Dict[`str`, `str`]
        A mapping of capability names to descriptions to include in the form.

    Returns
    -------
    form : `flask_wtf.FlaskForm`
        The generated form.
    """

    class NewCapabilitiesToken(FlaskForm):
        """Stub form, to which fields will be dynamically added."""

        submit = SubmitField("Generate New Token")

    NewCapabilitiesToken.capability_names = list(capabilities)
    for capability, description in capabilities.items():
        field = BooleanField(label=capability, description=description)
        setattr(NewCapabilitiesToken, capability, field)
    return NewCapabilitiesToken()


class AlterTokenForm(FlaskForm):
    """Form for altering an existing user token."""

    method_ = HiddenField("method_")


@cached(cache=TTLCache(maxsize=16, ttl=600))
def get_key_as_pem(issuer_url: str, request_key_id: str) -> bytearray:
    """Get the key for an issuer.

    Gets a key as PEM, given the issuer and the request key ticket_id.  This
    function is intended to help with the caching of keys, as we always get
    them dynamically.

    Parameters
    ----------
    issuer_url : `str`
        The URL of the issuer.
    request_key_id : `str`
        The key ID to retrieve for the issuer in question.

    Returns
    -------
    key : `bytearray`
        The issuer's key in PEM format.

    Raises
    ------
    Exception
        For any issue with the key ID, the issuer's OpenID or JWKS
        configuration, or some other configuration issue.

    Notes
    -----
    This function will automatically cache the last 16 keys for up to 10
    minutes to cut down on network retrieval of the keys.
    """

    def _base64_to_long(data: str) -> int:
        """Convert base64-encoded bytes to a long."""
        decoded = base64.urlsafe_b64decode(add_padding(data))
        unpacked = struct.unpack("%sB" % len(decoded), decoded)
        key_as_long = int("".join(["{:02x}".format(b) for b in unpacked]), 16)
        return key_as_long

    def _convert(exponent: int, modulus: int) -> bytearray:
        """Convert an exponent and modulus to a PEM-encoded key."""
        components = RSAPublicNumbers(exponent, modulus)
        pub = components.public_key(backend=default_backend())
        key_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cast(bytearray, key_bytes)

    issuer = current_app.config["ISSUERS"][issuer_url]
    logger.debug(f"Getting keys for: {issuer_url}")
    try:
        info_key_ids = issuer.get("issuer_key_ids")
        if info_key_ids and request_key_id not in info_key_ids:
            raise KeyError(
                f"kid {request_key_id} not found in issuer configuration"
            )

        # Try OIDC first
        oidc_config = os.path.join(
            issuer_url, ".well-known/openid-configuration"
        )
        oidc_resp = requests.get(oidc_config)
        if oidc_resp.ok:
            jwks_uri = oidc_resp.json()["jwks_uri"]
        else:
            # Assume jwks.json is available
            jwks_uri = os.path.join(issuer_url, ".well-known/jwks.json")

        keys_resp = requests.get(jwks_uri)
        keys_resp.raise_for_status()
        keys = keys_resp.json()["keys"]
        key = None
        for k in keys:
            if request_key_id == k["kid"] and request_key_id:
                key = k
        if not key:
            raise KeyError(f"Issuer may have removed kid={request_key_id}")

        if key["alg"] != config.ALGORITHM:
            raise Exception(
                "Bad Issuer Key and Global Algorithm Configuration"
            )
        e = _base64_to_long(key["e"])
        m = _base64_to_long(key["n"])
        return _convert(e, m)
    except Exception as e:
        # HTTPError, KeyError, or Exception
        logger.error(
            f"Unable to retrieve and store key for issuer: {issuer_url} "
        )
        logger.error(e)
        raise Exception(f"Unable to interace with issuer: {issuer_url}") from e


def o2proxy_store_token_redis(
    payload: Dict[str, Any],
    session: Session,
    store_user_info: bool,
    oauth2_proxy_ticket: Ticket,
    redis_client: Optional[redis.Redis] = None,
) -> None:
    """Store a token in redis in the oauth2_proxy encoded token format.

    Parameters
    ----------
    payload : Dict[`str`, Any]
        JWT payload.
    session : `Session`
        The oauth2_proxy session to store.
    store_user_info : `bool`
        Whether to add this token to the list of issued tokens for the user.
    ticket : `Ticket`
        Ticket to substitute for the token.
    redis_client : Optional[`redis.Redis`]
        The optional Redis client to use if one should not be created from the
        general application Redis pool.  Used primarily for testing.
    """
    user_id_raw = payload[current_app.config["JWT_UID_KEY"]]
    user_id = str(user_id_raw)
    prefix = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
    encoded_key = current_app.config["OAUTH2_STORE_SESSION"][
        "OAUTH2_PROXY_SECRET"
    ]
    key = base64.urlsafe_b64decode(encoded_key)
    if not redis_client:
        redis_client = get_redis_client(current_app)
    session_store = SessionStore(prefix, key, redis_client)
    with redis_client.pipeline() as pipeline:
        session_store.store_session(oauth2_proxy_ticket, session, pipeline)
        if store_user_info:
            pipeline.sadd(user_tokens_redis_key(user_id), json.dumps(payload))
        pipeline.execute()


def get_tokens(user_id: str) -> List[Mapping[str, Any]]:
    """Get all the decoded tokens for a given user ID.

    Parameters
    ----------
    user_id : `str`
        The user ID.

    Returns
    -------
    tokens : List[Mapping[`str`, Any]]
        The decoded user tokens.
    """
    user_tokens, _ = _get_tokens(user_id)
    return user_tokens


def _get_tokens(user_id: str) -> Tuple[List[Mapping[str, Any]], List[str]]:
    """Get al the tokens for a given user ID, delete expired ones.

    As a side effect, this function removes all expired tokens for that user
    from Redis.

    Parameters
    ----------
    user_id : `str`
        The user ID.

    Returns
    -------
    user_tokens : List[Mapping[`str`, Any]]
        The decoded user tokens.
    valid_serialized_user_tokens : List[`str`]
        The corresponding encoded tokens.
    """
    redis_client = get_redis_client(current_app)
    user_tokens = []
    expired_tokens = []
    key = user_tokens_redis_key(user_id)
    serialized_user_tokens = redis_client.smembers(key)
    valid_serialized_user_tokens = []
    # Clear out expired token references
    for serialized_token in serialized_user_tokens:
        token = json.loads(serialized_token)
        exp = datetime.utcfromtimestamp(token["exp"])
        if exp < datetime.now():
            expired_tokens.append(serialized_token)
        else:
            user_tokens.append(token)
            valid_serialized_user_tokens.append(serialized_token)
    with redis_client.pipeline() as pipeline:
        for expired_token in expired_tokens:
            pipeline.srem(key, expired_token)
        pipeline.execute()
    return user_tokens, valid_serialized_user_tokens


def revoke_token(user_id: str, handle: str) -> bool:
    """Revoke a token.

    Parameters
    ----------
    user_id : `str`
        User ID to whom the token was issued.
    handle : `str`
        Handle of the issued token.

    Returns
    -------
    success : `bool`
        True if the token was found and revoked, False otherwise.
    """
    tokens, serialized_tokens = _get_tokens(user_id)
    token_to_revoke: str = ""
    for token, serialized_token in zip(tokens, serialized_tokens):
        if token["jti"] == handle:
            token_to_revoke = serialized_token
    key = user_tokens_redis_key(user_id)
    redis_client = get_redis_client(current_app)
    if token_to_revoke:
        with redis_client.pipeline() as pipeline:
            pipeline.delete(handle)
            pipeline.srem(key, token_to_revoke)
            pipeline.execute()
        return True
    return False


def user_tokens_redis_key(user_id: str) -> str:
    """The Redis key for storing a user's tokens.

    Parameters
    ----------
    user_id : `str`
        The user ID.

    Returns
    -------
    redis_key : `str`
        The Redis key under which that user's tokens will be stored.
    """
    return f"tokens:{user_id}"


@dataclass
class Issuer:
    """Metadata about a token issuer for validation."""

    url: str
    audience: str
    key_ids: List[str]


class TokenVerifier:
    """Verifies the validity of a JWT.

    Parameters
    ----------
    issuers : Dict[`str`, `Issuer`]
        Known token issuers and their metadata.
    """

    def __init__(self, issuers: Dict[str, Issuer]) -> None:
        self.issuers = issuers

    def verify(self, token: str) -> None:
        """Verifies the provided JWT.

        Parameters
        ----------
        token : `str`
            JWT to verify.

        Raises
        ------
        jwt.exceptions.InvalidIssuerError
            The issuer of this token is unknown and therefore the token cannot
            be verified.
        Exception
            Some other verification failure.
        """
        unverified_header = jwt.get_unverified_header(token)
        unverified_token = jwt.decode(
            token, algorithms=config.ALGORITHM, verify=False
        )
        issuer_url = unverified_token["iss"]
        if issuer_url not in self.issuers:
            raise jwt.InvalidIssuerError(f"Unknown issuer: {issuer_url}")
        issuer = self.issuers[issuer_url]

        key = get_key_as_pem(issuer_url, unverified_header["kid"])
        jwt.decode(
            token, key, algorithms=config.ALGORITHM, audience=issuer.audience
        )


def create_token_verifier(app: Flask) -> TokenVerifier:
    """Create a TokenVerifier from a Flask app configuration.

    Parameters
    ----------
    app : `flask.Flask`
        The Flask application.

    Returns
    -------
    token_verifier : `TokenVerifier`
        A TokenVerifier created from that Flask application configuration.
    """
    issuers = {}
    for issuer_url, issuer_data in app.config["ISSUERS"].items():
        audience = issuer_data["audience"]
        key_ids = issuer_data.get("issuer_key_ids", [])
        issuer = Issuer(url=issuer_url, audience=audience, key_ids=key_ids)
        issuers[issuer_url] = issuer
    return TokenVerifier(issuers)
