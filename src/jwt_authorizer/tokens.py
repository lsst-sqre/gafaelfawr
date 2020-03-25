"""Token parsing and storage."""

from __future__ import annotations

import base64
import json
import logging
import os
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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

if TYPE_CHECKING:
    from flask import Flask
    from redis.client import Pipeline
    from typing import Any, Dict, List, Mapping, Optional, Tuple

__all__ = [
    "AlterTokenForm",
    "Issuer",
    "TokenStore",
    "TokenVerifier",
    "add_padding",
    "api_capabilities_token_form",
    "create_token_verifier",
    "get_key_as_pem",
    "get_tokens",
    "issue_token",
    "revoke_token",
]

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
    exp = datetime.now(timezone.utc) + timedelta(
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
            created_at=datetime.now(timezone.utc),
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
    payload["iat"] = int(datetime.now(timezone.utc).timestamp())
    payload["exp"] = int(expires.timestamp())
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
    prefix = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
    encoded_key = current_app.config["OAUTH2_STORE_SESSION"][
        "OAUTH2_PROXY_SECRET"
    ]
    key = base64.urlsafe_b64decode(encoded_key)
    if not redis_client:
        redis_client = get_redis_client(current_app)
    session_store = SessionStore(prefix, key, redis_client)
    if store_user_info:
        user_id_key = current_app.config["JWT_UID_KEY"]
        token_store = TokenStore(redis_client, user_id_key)
    with redis_client.pipeline() as pipeline:
        session_store.store_session(oauth2_proxy_ticket, session, pipeline)
        if store_user_info:
            token_store.store_token(payload, pipeline)
        pipeline.execute()


def get_tokens(user_id: str) -> List[Dict[str, Any]]:
    """Get all the decoded tokens for a given user ID.

    Parameters
    ----------
    user_id : `str`
        The user ID.

    Returns
    -------
    tokens : List[Dict[`str`, Any]]
        The decoded user tokens.
    """
    redis_client = get_redis_client(current_app)
    token_store = TokenStore(redis_client, current_app.config["JWT_UID_KEY"])
    return token_store.get_tokens(user_id)


def revoke_token(user_id: str, handle: str) -> bool:
    """Revoke a token.

    user_id : `str`
        User ID to whom the token was issued.
    handle : `str`
        Handle of the issued token.

    Returns
    -------
    success : `bool`
        True if the token was found and revoked, False otherwise.
    """
    redis_client = get_redis_client(current_app)
    token_store = TokenStore(redis_client, current_app.config["JWT_UID_KEY"])
    with redis_client.pipeline() as pipeline:
        success = token_store.revoke_token(user_id, handle, pipeline)
        if success:
            pipeline.delete(handle)
            pipeline.execute()
            return True
    return False


class NoUserIdException(Exception):
    """The token does not contain the expected user ID field."""


class TokenStore:
    """Store, retrieve, revoke, and expire user-created tokens.

    Parameters
    ----------
    redis : `redis.Redis`
        Redis client used to store and retrieve tokens.
    user_id_key : `str`
        The token field to use as the user ID for calculating a Redis key.
    """

    def __init__(self, redis: redis.Redis, user_id_key: str) -> None:
        self.redis = redis
        self.user_id_key = user_id_key

    def get_tokens(self, user_id: str) -> List[Dict[str, Any]]:
        """Retrieve all tokens for a given user.

        Parameters
        ----------
        user_id : `str`
            Retrieve the tokens of this User ID.

        Returns
        -------
        tokens : List[Dict[`str`, Any]]
            All of that user's tokens as a list of token contents.
        """
        tokens, _ = self._get_tokens(user_id)
        return tokens

    def revoke_token(
        self, user_id: str, handle: str, pipeline: Pipeline
    ) -> bool:
        """Revoke a token.

        To allow the caller to batch this with other Redis modifications, the
        session will be stored but the pipeline will not be executed.  The
        caller is responsible for executing the pipeline.

        Parameters
        ----------
        user_id : `str`
            User ID to whom the token was issued.
        handle : `str`
            Handle of the issued token.
        pipeline : `Pipeline`
            The pipeline in which to store the session.

        Returns
        -------
        success : `bool`
            True if the token was found and revoked, False otherwise.
        """
        tokens, serialized_tokens = self._get_tokens(user_id)
        token_to_revoke = ""
        for token, serialized_token in zip(tokens, serialized_tokens):
            if token["jti"] == handle:
                token_to_revoke = serialized_token

        if token_to_revoke:
            pipeline.srem(self._redis_key_for_user(user_id), token_to_revoke)
            return True
        else:
            return False

    def store_token(self, payload: Dict[str, Any], pipeline: Pipeline) -> None:
        """Store the data of a user-created token in a Redis pipeline.

        Used to populate the token list.  To allow the caller to batch this
        with other Redis modifications, the session will be stored but the
        pipeline will not be executed.  The caller is responsible for
        executing the pipeline.

        Parameters
        ----------
        payload : Dict[`str`, Any]
            The contents of the token.
        pipeline : `Pipeline`
            The pipeline in which to store the session.
        """
        pipeline.sadd(self._redis_key_for_token(payload), json.dumps(payload))

    def _get_tokens(
        self, user_id: str
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Get al the tokens for a given user ID, delete expired ones.

        As a side effect, this function removes all expired tokens for that
        user from Redis.

        Parameters
        ----------
        user_id : `str`
            The user ID.

        Returns
        -------
        user_tokens : List[Dict[`str`, Any]]
            The decoded user tokens.
        valid_serialized_user_tokens : List[`str`]
            The corresponding encoded tokens.
        """
        user_tokens = []
        expired_tokens = []
        key = self._redis_key_for_user(user_id)
        serialized_user_tokens = self.redis.smembers(key)
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
        with self.redis.pipeline() as pipeline:
            for expired_token in expired_tokens:
                pipeline.srem(key, expired_token)
            pipeline.execute()
        return user_tokens, valid_serialized_user_tokens

    def _redis_key_for_token(self, token: Dict[str, Any]) -> str:
        """The Redis key for user-created tokens.

        Parameters
        ----------
        token : Dict[`str`, Any]
            The contents of a token identifying the user.

        Returns
        -------
        key : `str`
            The Redis key under which those tokens will be stored.
        """
        if self.user_id_key not in token:
            raise NoUserIdException(f"Field {self.user_id_key} not found")
        user_id = str(token[self.user_id_key])
        return self._redis_key_for_user(user_id)

    def _redis_key_for_user(self, user_id: str) -> str:
        """The Redis key for user-created tokens.

        Parameters
        ----------
        user_id : `str`
            The user ID of the user.

        Returns
        -------
        key : `str`
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
