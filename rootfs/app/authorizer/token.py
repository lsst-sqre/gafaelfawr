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
import logging
import os
import struct
from calendar import timegm
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional

import jwt
import redis  # type: ignore
import requests
from cachetools import cached, TTLCache  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives import serialization  # type: ignore
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers  # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
from flask import current_app

from .config import ALGORITHM

logger = logging.getLogger(__name__)


def reissue_token(token: Mapping[str, Any], aud: str, oauth2_proxy_cookie: str) -> str:
    """
    Reissue a token.
    This makes a copy of the token, adjusts the audience, expiration,
    issuer, and issue time as appropriate, and then returns the
    token in encoded form.
    :param token: The token to reissues
    :param aud: The new audience for the token.
    :param oauth2_proxy_cookie: The value of the oauth2_proxy_cookie
    :return: Encoded token
    """
    reissued_token = dict(token)
    expires = datetime.utcnow() + timedelta(seconds=current_app.config["OAUTH2_JWT_EXP"])

    # Some fields may need to be masked from reissued_token
    reissued_token.update(
        exp=expires,
        iss=current_app.config["OAUTH2_JWT_ISS"],
        aud=aud,
        iat=datetime.utcnow(),
    )

    private_key = current_app.config["OAUTH2_JWT_KEY"]
    headers = {"kid": current_app.config["OAUTH2_JWT_KEY_ID"]}
    encoded_reissued_token = jwt.encode(
        reissued_token,
        private_key,
        algorithm=ALGORITHM,
        headers=headers
    ).decode("utf-8")

    if current_app.config.get("OAUTH2_STORE_SESSION") and oauth2_proxy_cookie:
        # Use the same email field as oauth2_proxy, if available
        email = reissued_token.get("email")
        # Use our definition of username, if possible
        user = reissued_token.get(current_app.config["JWT_USERNAME_KEY"])
        o2proxy_store_token_redis(
            user,
            email,
            expires,
            encoded_reissued_token,
            oauth2_proxy_cookie
        )
    return encoded_reissued_token


@cached(cache=TTLCache(maxsize=16, ttl=600))
def get_key_as_pem(issuer_url: str, request_key_id: str) -> bytearray:
    """
    Gets a key as PEM, given the issuer and the request key id.
    This function is intended to help with the caching of keys, as
    we always get them dynamically.
    :param issuer_url: The URL of the issuer
    :param request_key_id: The key id for the issuer in question
    :return: the key in a PEM format
    :raises Exception: if there's an issue with the key id, the
    issuer's .well-known/openid-configuration or JWKS URI, or if
    there's an obvious configuration issue
    """

    def _base64_to_long(data):
        data = data.encode("ascii")
        decoded = base64.urlsafe_b64decode(bytes(data) + b"==")
        unpacked = struct.unpack("%sB" % len(decoded), decoded)
        key_as_long = int("".join(["{:02x}".format(b) for b in unpacked]), 16)
        return key_as_long

    def _convert(exponent, modulus):
        components = RSAPublicNumbers(exponent, modulus)
        pub = components.public_key(backend=default_backend())
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

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
        user: Optional[str],
        email: Optional[str],
        expires: datetime,
        token: str,
        session_handle: str
) -> None:
    """
    Store a token in redis in the oauth2_proxy encoded token format.
    :param user: The username, if available
    :param email: The email, if available
    :param expires: When this token expires.
    :param token: The token to encode.
    :param session_handle: A period-delimited pair of [handle].[initialization vector]
    """
    session_key, iv_encoded = session_handle.split(".")
    iv = base64.b64decode(iv_encoded)
    encrypted_oauth2_session = _o2proxy_encrypted_session(
        iv,
        email,
        user,
        expires,
        token
    )
    redis_pool = current_app.redis_pool
    redis_client = redis.Redis(connection_pool=redis_pool)
    key_prefix = current_app.config["OAUTH2_STORE_SESSION"]["KEY_PREFIX"]
    key = key_prefix + ":" + session_key
    expires_delta = expires - datetime.utcnow()
    redis_client.setex(key, expires_delta, encrypted_oauth2_session)


def _o2proxy_encrypted_session(
        iv: bytes,
        user: Optional[str],
        email: Optional[str],
        expires: datetime,
        token: str
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
    return _o2proxy_encrypt_string(iv, signed_session)


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
    secret_key = base64.b64decode(secret_key_encoded)
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
    h.update("_oauth2_proxy".encode())
    h.update(encoded_session_payload)
    h.update(now_str.encode())
    sig_base64: bytes = base64.b64encode(h.digest())
    return f"{encoded_session_payload.decode()}|{now_str}|{sig_base64.decode()}"

