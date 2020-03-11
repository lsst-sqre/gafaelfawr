# This file is part of jwt_authorizer.
#
# Developed for the LSST Data Management System.
# This product includes software developed by the LSST Project
# (https://www.lsst.org).
# See the COPYRIGHT file at the top-level directory of this distribution
# for details of code ownership.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import struct
from binascii import Error
from calendar import timegm
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, cast

import jwt
import redis
import requests
from cachetools import TTLCache, cached
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import current_app
from flask_wtf import FlaskForm
from wtforms import BooleanField, HiddenField, SubmitField

from jwt_authorizer.config import ALGORITHM

if TYPE_CHECKING:
    from flask import Flask
    from typing import Any, Dict, List, Mapping, Optional, Tuple

logger = logging.getLogger(__name__)


def new_id() -> str:
    return hashlib.sha1(os.urandom(16)).hexdigest()


def new_secret() -> bytes:
    return os.urandom(16)


@dataclass
class Ticket:
    """A class represeting an oauth2_proxy ticket"""

    ticket_id: str = dc_field(default_factory=new_id)
    secret: bytes = dc_field(default_factory=new_secret)

    def as_handle(self, prefix: str) -> str:
        return f"{prefix}-{self.ticket_id}"

    def encode(self, prefix: str) -> str:
        secret_b64 = base64.urlsafe_b64encode(self.secret).decode().rstrip("=")
        return f"{prefix}-{self.ticket_id}.{secret_b64}"


def parse_ticket(prefix: str, ticket: str) -> Optional[Ticket]:
    """
    A function to parse an oauth2_proxy ticket string to a Ticket
    :param prefix: The prefix used for the ticket
    :param ticket: The encoded ticket string
    :return: The decoded ticket, or None if there was an error
    """
    full_prefix = f"{prefix}-"
    if not ticket.startswith(full_prefix):
        logger.info("Error decoding ticket: Ticket not in expected format")
        return None
    trimmed_ticket = ticket[len(full_prefix) :]
    if "." not in trimmed_ticket:
        logger.info("Error decoding ticket: Ticket not in expected format")
        return None
    ticket_id, secret_b64 = trimmed_ticket.split(".")
    try:
        int(ticket_id, 16)  # Check hex
        secret = base64.b64decode(
            add_padding(secret_b64), altchars=b"-_", validate=True
        )
        if secret == b"":
            raise ValueError("ticket secret is empty")
        return Ticket(ticket_id=ticket_id, secret=secret)
    except (ValueError, Error) as e:
        logger.info("Error decoding ticket: %s", str(e))
        return None


def issue_token(
    payload: Mapping[str, Any],
    aud: str,
    store_user_info: bool,
    oauth2_proxy_ticket: Ticket,
    redis_client: Optional[redis.Redis] = None,
) -> str:
    """
    Issue a token.
    This makes a copy of the token, sets the audience, expiration,
    issuer, and issue time as appropriate, and then returns the
    token in encoded form. If configured, it will also store the
    newly issued token a oauth2_proxy redis session store.
    :param payload: The payload of claims for the token.
    :param aud: The desired audience for the new token
    :param store_user_info: Store info about this token for the user.
    :param oauth2_proxy_ticket: The value of the oauth2_proxy_cookie
    :param redis_client: Optional Redis client to use
    :return: Encoded token
    """
    # Make a copy first
    exp = datetime.utcnow() + timedelta(
        minutes=current_app.config["OAUTH2_JWT_EXP"]
    )
    payload = _build_payload(aud, exp, payload, oauth2_proxy_ticket)

    private_key = current_app.config["OAUTH2_JWT.KEY"]
    headers = {"kid": current_app.config["OAUTH2_JWT.KEY_ID"]}
    encoded_reissued_token = jwt.encode(
        payload, private_key, algorithm=ALGORITHM, headers=headers
    ).decode("utf-8")

    if current_app.config.get("OAUTH2_STORE_SESSION"):
        o2proxy_store_token_redis(
            payload,
            exp,
            encoded_reissued_token,
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
    """
    Build a new token payload.
    iat, exp, etc... claims are handled at token issuance.
    :param audience: The new token audience
    :param expires: When this token expires.
    :param decoded_token: The previous decoded token
    :param ticket: The ticket to use (ticket handle used with JTI)
    :return: A new payload for issuing the new ticket.
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


def api_capabilities_token_form(
    capabilities: Dict[str, Dict[str, str]]
) -> FlaskForm:
    """
    Dynamically generates a form based on capability_names.
    :param capabilities: A grouping of capability_names.
    :return:
    """

    class NewCapabilitiesToken(FlaskForm):
        submit = SubmitField("Generate New Token")

    NewCapabilitiesToken.capability_names = list(capabilities)
    for capability, description in capabilities.items():
        field = BooleanField(label=capability, description=description)
        setattr(NewCapabilitiesToken, capability, field)
    return cast(FlaskForm, NewCapabilitiesToken())


class AlterTokenForm(FlaskForm):
    method_ = HiddenField("method_")


@cached(cache=TTLCache(maxsize=16, ttl=600))
def get_key_as_pem(issuer_url: str, request_key_id: str) -> bytearray:
    """
    Gets a key as PEM, given the issuer and the request key ticket_id.
    This function is intended to help with the caching of keys, as
    we always get them dynamically.
    :param issuer_url: The URL of the issuer
    :param request_key_id: The key ticket_id for the issuer in question
    :return: the key in a PEM format
    :raises Exception: if there's an issue with the key ticket_id, the
    issuer's .well-known/openid-configuration or JWKS URI, or if
    there's an obvious configuration issue
    """

    def _base64_to_long(data: str) -> int:
        decoded = base64.urlsafe_b64decode(add_padding(data))
        unpacked = struct.unpack("%sB" % len(decoded), decoded)
        key_as_long = int("".join(["{:02x}".format(b) for b in unpacked]), 16)
        return key_as_long

    def _convert(exponent: int, modulus: int) -> bytearray:
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

        if key["alg"] != ALGORITHM:
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
    expires: datetime,
    token: str,
    store_user_info: bool,
    oauth2_proxy_ticket: Ticket,
    redis_client: Optional[redis.Redis] = None,
) -> None:
    """
    Store a token in redis in the oauth2_proxy encoded token format.
    :param payload: The JWT payload
    :param expires: When this token expires.
    :param token: The token to encode.
    :param store_user_info: If true, store info user's issued token
    :param oauth2_proxy_ticket: Ticket to substitute for the token
    :param redis_client: Optional Redis client to use
    """
    # Use the same email field as oauth2_proxy
    email = payload["email"]
    # Use our definition of username, if possible
    user = payload.get(current_app.config["JWT_USERNAME_KEY"])
    user_id_raw = payload[current_app.config["JWT_UID_KEY"]]
    user_id = str(user_id_raw)
    prefix = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
    handle = oauth2_proxy_ticket.as_handle(prefix)
    encrypted_oauth2_session = _o2proxy_encrypted_session(
        oauth2_proxy_ticket.secret, user, email, expires, token
    )
    if not redis_client:
        redis_pool = current_app.redis_pool
        redis_client = redis.Redis(connection_pool=redis_pool)
    expires_delta = expires - datetime.utcnow()
    with redis_client.pipeline() as pipeline:
        pipeline.setex(handle, expires_delta, encrypted_oauth2_session)
        if store_user_info:
            pipeline.sadd(user_tokens_redis_key(user_id), json.dumps(payload))
        pipeline.execute()


def get_tokens(user_id: str) -> List[Mapping[str, Any]]:
    """
    Get all the tokens for a given user id
    :param user_id:
    :return:
    """
    user_tokens, _ = _get_tokens(user_id)
    return user_tokens


def _get_tokens(user_id: str) -> Tuple[List[Mapping[str, Any]], List[str]]:
    redis_pool = current_app.redis_pool
    redis_client = redis.Redis(connection_pool=redis_pool)
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
    tokens, serialized_tokens = _get_tokens(user_id)
    token_to_revoke: str = ""
    for token, serialized_token in zip(tokens, serialized_tokens):
        if token["jti"] == handle:
            token_to_revoke = serialized_token
    key = user_tokens_redis_key(user_id)
    redis_pool = current_app.redis_pool
    redis_client = redis.Redis(connection_pool=redis_pool)
    if token_to_revoke:
        with redis_client.pipeline() as pipeline:
            pipeline.delete(handle)
            pipeline.srem(key, token_to_revoke)
            pipeline.execute()
        return True
    return False


def _o2proxy_encrypted_session(
    secret: bytes,
    user: Optional[str],
    email: str,
    expires: datetime,
    token: str,
) -> bytes:
    """
    Take in the data for an encrypting an oauth2_proxy session and
    return the encrypted session and handle.
    :param user: username, if any
    :param email: email, if any
    :param expires: expiration of the token
    :param token: The encoded JWT.
    :return: encrypted session bytes
    """
    email = email or ""
    session_obj = dict(
        IDToken=_o2proxy_encrypt_field(token).decode(),
        Email=_o2proxy_encrypt_field(email).decode(),
        User=_o2proxy_encrypt_field(email).decode(),
        CreatedAt=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        ExpiresOn=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    session_payload_str = json.dumps(session_obj)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(secret), modes.CFB(secret), backend=backend)
    encryptor = cipher.encryptor()
    cipher_text = (
        encryptor.update(session_payload_str.encode()) + encryptor.finalize()
    )
    return cipher_text


def _o2proxy_encrypt_field(field: str) -> bytes:
    """
    Encrypt a field. This form generates the initialization vector and
    stores it with the field.
    :param field: The field to encrypt
    :return: The 16-byte initialization vector and encrypted bytes.
    """
    iv = os.urandom(16)
    cipher_text = _o2proxy_encrypt_string(iv, field)
    encrypted_field = iv + cipher_text
    return base64.b64encode(encrypted_field)


def _o2proxy_encrypt_string(iv: bytes, field: str) -> bytes:
    """
    Build the cipher from the configuration and encode the string in
    Cipher Feedback Mode.
    :param iv: Initialization vector
    :param field: The field to encrypt.
    :return: The encrypted bytes only.
    """
    secret_key_encoded = current_app.config["OAUTH2_STORE_SESSION"][
        "OAUTH2_PROXY_SECRET"
    ]
    secret_key = base64.urlsafe_b64decode(secret_key_encoded)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(secret_key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    cipher_text: bytes = encryptor.update(
        field.encode("utf-8")
    ) + encryptor.finalize()
    return cipher_text


def _o2proxy_signed_session(session_payload: str) -> str:
    """
    Perform an HMAC signature on the session payload with oauth2_proxy's
    secret key.
    :param session_payload: The payload to sign.
    :return: The signed session with the time and signature in the
    format oauth2_proxy is expecting.
    """
    secret_key_string = current_app.config["OAUTH2_STORE_SESSION"][
        "OAUTH2_PROXY_SECRET"
    ]
    secret_key = secret_key_string.encode()
    encoded_session_payload: bytes = base64.b64encode(session_payload.encode())
    now_str = str(timegm(datetime.utcnow().utctimetuple()))

    h = hmac.new(secret_key, digestmod=hashlib.sha1)
    h.update(
        current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"].encode()
    )
    h.update(encoded_session_payload)
    h.update(now_str.encode())
    # Use URL Safe base64 encode
    sig_base64: bytes = base64.urlsafe_b64encode(h.digest())
    return (
        f"{encoded_session_payload.decode()}|{now_str}|{sig_base64.decode()}"
    )


def add_padding(encoded: str) -> str:
    """Add padding to base64 encoded bytes"""
    underflow = len(encoded) % 4
    if underflow:
        return encoded + ("=" * (4 - underflow))
    else:
        return encoded


def user_tokens_redis_key(user_id: str) -> str:
    return f"tokens:{user_id}"


@dataclass
class Session:
    """An oauth2_proxy session.

    Tokens are currently stored in Redis as a JSON dump of a dictionary.  This
    class represents the deserialized form of a session.
    """

    token: str
    email: str
    user: str
    created_at: datetime
    expires_on: datetime


class TokenStore:
    """Stores tokens and retrieves them by ticket.

    Paramters
    ---------
    prefix : `str`
        Prefix used for storing oauth2_proxy session state.
    redis : `redis.Redis`
        A Redis client configured to talk to the backend store that holds the
        (encrypted) tokens.
    key : `bytes`
        Encryption key for the individual components of the stored session.
    """

    def __init__(self, prefix: str, key: bytes, redis: redis.Redis) -> None:
        self.prefix = prefix
        self.key = key
        self.redis = redis

    def get_session(self, ticket: Ticket) -> Optional[Session]:
        """Retrieve and decrypt the session for a ticket.

        Parameters
        ----------
        ticket : `Ticket`
            The ticket corresponding to the token.

        Returns
        -------
        session : `Session` or `None`
            The corresponding session, or `None` if no session exists for this
            ticket.
        """
        handle = ticket.as_handle(self.prefix)
        encrypted_session = self.redis.get(handle)
        if not encrypted_session:
            return None

        return self._decrypt_session(ticket.secret, encrypted_session)

    def _decrypt_session(
        self, secret: bytes, encrypted_session: bytes
    ) -> Session:
        cipher = Cipher(
            algorithms.AES(secret), modes.CFB(secret), default_backend()
        )
        decryptor = cipher.decryptor()
        session_dict = json.loads(
            decryptor.update(encrypted_session) + decryptor.finalize()
        )
        return Session(
            token=self._decrypt_session_component(session_dict["IDToken"]),
            email=self._decrypt_session_component(session_dict["Email"]),
            user=self._decrypt_session_component(session_dict["User"]),
            created_at=self._parse_session_date(session_dict["CreatedAt"]),
            expires_on=self._parse_session_date(session_dict["ExpiresOn"]),
        )

    def _decrypt_session_component(self, encrypted_str: str) -> str:
        encrypted_bytes = base64.b64decode(encrypted_str)
        iv = encrypted_bytes[:16]
        cipher = Cipher(
            algorithms.AES(self.key), modes.CFB(iv), default_backend()
        )
        decryptor = cipher.decryptor()
        field = decryptor.update(encrypted_bytes[16:]) + decryptor.finalize()
        return field.decode()

    @staticmethod
    def _parse_session_date(date_str: str) -> datetime:
        date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        return date.replace(tzinfo=timezone.utc)


def get_redis_client(app: Flask) -> redis.Redis:
    return redis.Redis(connection_pool=app.redis_pool)


def create_token_store(app: Flask) -> TokenStore:
    """Create a TokenStore from a Flask app configuration."""
    redis_client = get_redis_client(app)
    prefix = app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
    secret_str = app.config["OAUTH2_STORE_SESSION"]["OAUTH2_PROXY_SECRET"]
    secret = base64.urlsafe_b64decode(secret_str)
    return TokenStore(prefix, secret, redis_client)


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
    issuers : `Dict` [`str`, `Issuer`]
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
        jwt.InvalidUsserError
            The issuer of this token is unknown and therefore the token cannot
            be verified.
        Exception
            Some other verification failure.
        """
        unverified_header = jwt.get_unverified_header(token)
        unverified_token = jwt.decode(
            token, algorithms=ALGORITHM, verify=False
        )
        issuer_url = unverified_token["iss"]
        if issuer_url not in self.issuers:
            raise jwt.InvalidIssuerError(f"Unknown issuer: {issuer_url}")
        issuer = self.issuers[issuer_url]

        key = get_key_as_pem(issuer_url, unverified_header["kid"])
        jwt.decode(token, key, algorithms=ALGORITHM, audience=issuer.audience)


def create_token_verifier(app: Flask) -> TokenVerifier:
    """Create a TokenVerifier from a Flask app configuration."""
    issuers = {}
    for issuer_url, issuer_data in app.config["ISSUERS"].items():
        audience = issuer_data["audience"]
        key_ids = issuer_data.get("issuer_key_ids", [])
        issuer = Issuer(url=issuer_url, audience=audience, key_ids=key_ids)
        issuers[issuer_url] = issuer
    return TokenVerifier(issuers)
