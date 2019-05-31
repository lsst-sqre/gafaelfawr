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


import base64
import hashlib
import hmac
import json
import logging
import os
import struct
from binascii import Error
from calendar import timegm
from datetime import datetime, timedelta
from dataclasses import dataclass, field as dc_field
from typing import Any, Mapping, Optional, Dict, cast, Tuple, List

import jwt
import redis  # type: ignore
import requests
from cachetools import cached, TTLCache  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives import serialization  # type: ignore
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers  # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
from flask import current_app
from flask_wtf import FlaskForm  # type: ignore
from wtforms import BooleanField, SubmitField, HiddenField  # type: ignore

from .config import ALGORITHM

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
        print(1)
        return None
    trimmed_ticket = ticket[len(full_prefix) :]
    if "." not in trimmed_ticket:
        print(2)
        return None
    ticket_id, secret_b64 = trimmed_ticket.split(".")
    try:
        int(ticket_id, 16)  # Check hex
        secret = base64.urlsafe_b64decode(add_padding(secret_b64))
        return Ticket(ticket_id=ticket_id, secret=secret)
    except (ValueError, Error) as e:
        print(e)
        return None


def issue_token(
    payload: Mapping[str, Any], exp: datetime, store_user_info: bool, oauth2_proxy_ticket: Ticket
) -> str:
    """
    Issue a token.
    This makes a copy of the token, sets the audience, expiration,
    issuer, and issue time as appropriate, and then returns the
    token in encoded form. If configured, it will also store the
    newly issued token a oauth2_proxy redis session store.
    :param payload: The payload of claims for the token.
    :param exp: The time of expiration.
    :param store_user_info: Store info about this token for the user.
    :param oauth2_proxy_ticket: The value of the oauth2_proxy_cookie
    :return: Encoded token
    """
    # Make a copy first
    payload = dict(payload)
    # Overwrite relevant claims from previous issuer
    payload.update(iss=current_app.config["OAUTH2_JWT.ISS"], iat=datetime.utcnow(), exp=exp)

    private_key = current_app.config["OAUTH2_JWT.KEY"]
    headers = {"kid": current_app.config["OAUTH2_JWT.KEY_ID"]}
    encoded_reissued_token = jwt.encode(
        payload, private_key, algorithm=ALGORITHM, headers=headers
    ).decode("utf-8")

    if current_app.config.get("OAUTH2_STORE_SESSION"):
        o2proxy_store_token_redis(
            payload, exp, encoded_reissued_token, store_user_info, oauth2_proxy_ticket
        )
    return encoded_reissued_token


def issue_default_token(decoded_token: Mapping[str, Any], oauth2_proxy_ticket: Ticket) -> str:
    """
    Issue a new default token. This happens when we see a new session.
    We **replace** the oauth2_proxy session, via `oauth2_proxy_ticket`,
    in Redis with our new oauth2_proxy session.
    :param decoded_token: Decoded token representing the token we will
    replace.
    :param oauth2_proxy_ticket: The current ticket for the session
    with that token.
    :return: A new encoded token
    """
    default_audience = current_app.config.get("OAUTH2_JWT.AUD.DEFAULT", "")
    payload = _build_payload(default_audience, decoded_token, oauth2_proxy_ticket)
    exp = datetime.utcnow() + timedelta(seconds=current_app.config["OAUTH2_JWT_EXP"])
    return issue_token(
        payload, exp=exp, store_user_info=False, oauth2_proxy_ticket=oauth2_proxy_ticket
    )


def issue_internal_token(decoded_token: Mapping[str, Any]) -> Tuple[str, Ticket]:
    """
    Issue a new internal token. This should only be done when calling
    to to internal resources.
    We create a new oauth2_proxy session, with a new ticket, in
    Redis with our new oauth2_proxy session.
    :param decoded_token: Decoded token representing the token we will
    replace.
    :return The new token, encoded, as well as an oauth2_proxy ticket
    for that token.
    """
    internal_audience = current_app.config.get("OAUTH2_JWT.AUD.INTERNAL", "")
    oauth2_proxy_ticket = Ticket()
    payload = _build_payload(internal_audience, decoded_token, oauth2_proxy_ticket)
    exp = datetime.utcnow() + timedelta(seconds=current_app.config["OAUTH2_JWT_EXP"])
    # Note: Internal audiences should not need the ticket
    encoded_token = issue_token(
        payload, exp=exp, store_user_info=False, oauth2_proxy_ticket=oauth2_proxy_ticket
    )
    return encoded_token, oauth2_proxy_ticket


def _build_payload(
    audience: str, decoded_token: Mapping[str, Any], ticket: Ticket
) -> Mapping[str, Any]:
    """
    Build a new token payload.
    iat, exp, etc... claims are handled at token issuance.
    :param audience: The new token audience
    :param decoded_token: The previous decoded token
    :param ticket: The ticket to use (ticket handle used with JTI)
    :return: A new payload for issuing the new ticket.
    """
    payload = dict(decoded_token)
    prefix = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
    previous_jti = decoded_token.get("jti", "")
    previous_act = decoded_token.get("act", "")
    previous_iss = decoded_token["iss"]
    previous_aud = decoded_token["aud"]

    payload["iss"] = current_app.config["OAUTH2_JWT.ISS"]
    payload["jti"] = ticket.as_handle(prefix)
    payload["aud"] = audience
    actor_claim = {"aud": previous_aud, "iss": previous_iss}
    if previous_jti:
        actor_claim["jti"] = previous_jti
    if previous_act:
        actor_claim["act"] = previous_act
    payload["act"] = actor_claim
    return payload


def api_capabilities_token_form(capabilities: Dict[str, Dict[str, str]]) -> FlaskForm:
    """
    Dynamically generates a form based on capability_names.
    :param capabilities: A grouping of capability_names.
    :return:
    """

    class NewCapabilitiesToken(FlaskForm):  # type: ignore
        submit = SubmitField("Generate New Token")

    NewCapabilitiesToken.capability_names = list(capabilities)
    for capability, description in capabilities.items():
        field = BooleanField(label=capability, description=description)
        setattr(NewCapabilitiesToken, capability, field)
    return cast(FlaskForm, NewCapabilitiesToken())


class AlterTokenForm(FlaskForm):  # type: ignore
    method_ = HiddenField("method_")


@cached(cache=TTLCache(maxsize=16, ttl=600))  # type: ignore
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
            raise KeyError(f"kid {request_key_id} not found in issuer configuration")

        # Try OIDC first
        oidc_config = os.path.join(issuer_url, ".well-known/openid-configuration")
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
            raise Exception("Bad Issuer Key and Global Algorithm Configuration")
        e = _base64_to_long(key["e"])
        m = _base64_to_long(key["n"])
        return _convert(e, m)
    except Exception as e:
        # HTTPError, KeyError, or Exception
        logger.error(f"Unable to retrieve and store key for issuer: {issuer_url} ")
        logger.error(e)
        raise Exception(f"Unable to interace with issuer: {issuer_url}") from e


def o2proxy_store_token_redis(
    payload: Dict[str, Any],
    expires: datetime,
    token: str,
    store_user_info: bool,
    oauth2_proxy_ticket: Ticket,
) -> None:
    """
    Store a token in redis in the oauth2_proxy encoded token format.
    :param payload: The JWT payload
    :param expires: When this token expires.
    :param token: The token to encode.
    :param store_user_info: If true, store info user's issued token
    :param oauth2_proxy_ticket: A period-delimited pair of
    [handle].[initialization vector]
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
    secret: bytes, user: Optional[str], email: str, expires: datetime, token: str
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
    user = user or ""
    email = email or ""
    account_info = f"email:{email} user:{user}"
    access_token = ""
    id_token = _o2proxy_encrypt_field(token).decode("utf-8")
    refresh_token = ""
    expires_int = timegm(expires.utctimetuple())
    session_payload = f"{account_info}|{access_token}|{id_token}|{expires_int}|{refresh_token}"
    signed_session = _o2proxy_signed_session(session_payload)
    return _o2proxy_encrypt_string(secret, signed_session)


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
    secret_key_encoded = current_app.config["OAUTH2_STORE_SESSION"]["OAUTH2_PROXY_SECRET"]
    secret_key = base64.urlsafe_b64decode(secret_key_encoded)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(secret_key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    cipher_text: bytes = encryptor.update(field.encode("utf-8")) + encryptor.finalize()
    return cipher_text


def _o2proxy_signed_session(session_payload: str) -> str:
    """
    Perform an HMAC signature on the session payload with oauth2_proxy's
    secret key.
    :param session_payload: The payload to sign.
    :return: The signed session with the time and signature in the
    format oauth2_proxy is expecting.
    """
    secret_key_string = current_app.config["OAUTH2_STORE_SESSION"]["OAUTH2_PROXY_SECRET"]
    secret_key = secret_key_string.encode()
    encoded_session_payload: bytes = base64.b64encode(session_payload.encode())
    now_str = str(timegm(datetime.utcnow().utctimetuple()))

    h = hmac.new(secret_key, digestmod=hashlib.sha1)
    h.update(current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"].encode())
    h.update(encoded_session_payload)
    h.update(now_str.encode())
    # Use URL Safe base64 encode
    sig_base64: bytes = base64.urlsafe_b64encode(h.digest())
    return f"{encoded_session_payload.decode()}|{now_str}|{sig_base64.decode()}"


def add_padding(encoded: str) -> str:
    """Add padding to base64 encoded bytes"""
    underflow = len(encoded) % 4
    return encoded + ("=" * underflow)


def user_tokens_redis_key(user_id: str) -> str:
    return f"tokens:{user_id}"
