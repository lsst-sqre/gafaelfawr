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
import logging
import os
import struct
from datetime import datetime, timedelta
from typing import Any, Mapping

import jwt
import requests
from cachetools import cached, TTLCache  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives import serialization  # type: ignore
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers  # type: ignore
from flask import current_app

from .config import ALGORITHM

logger = logging.getLogger(__name__)


def reissue_token(token: Mapping[str, Any], aud: str) -> str:
    """
    Reissue a token.
    This makes a copy of the token, adjusts the audience, expiration,
    issuer, and issue time as appropriate, and then returns the
    token in encoded form.
    :param token: The token to reissues
    :param aud: The new audience for the token.
    :return: Encoded token
    """
    reissued_token = dict(token)
    reissued_token.update(
        exp=datetime.utcnow() + timedelta(seconds=current_app.config['OAUTH2_JWT_EXP']),
        iss=current_app.config["OAUTH2_JWT_ISS"],
        aud=aud,
        iat=datetime.utcnow(),
    )
    private_key = current_app.config['OAUTH2_JWT_KEY']
    headers = {"kid": current_app.config['OAUTH2_JWT_KEY_ID']}
    return jwt.encode(reissued_token, private_key,
                      algorithm=ALGORITHM, headers=headers).decode("utf-8")


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
        data = data.encode('ascii')
        decoded = base64.urlsafe_b64decode(bytes(data) + b'==')
        unpacked = struct.unpack('%sB' % len(decoded), decoded)
        key_as_long = int(''.join(['{:02x}'.format(b) for b in unpacked]), 16)
        return key_as_long

    def _convert(exponent, modulus):
        components = RSAPublicNumbers(exponent, modulus)
        pub = components.public_key(backend=default_backend())
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

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
            if request_key_id == k['kid'] and request_key_id:
                key = k
        if not key:
            raise KeyError(f"Issuer may have removed kid={request_key_id}")

        if key["alg"] != ALGORITHM:
            raise Exception("Bad Issuer Key and Global Algorithm Configuration")
        e = _base64_to_long(key['e'])
        m = _base64_to_long(key['n'])
        return _convert(e, m)
    except Exception as e:
        # HTTPError, KeyError, or Exception
        logger.error(f"Unable to retrieve and store key for issuer: {issuer_url} ")
        logger.error(e)
        raise Exception(f"Unable to interace with issuer: {issuer_url}") from e
