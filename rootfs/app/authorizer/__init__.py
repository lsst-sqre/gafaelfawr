# LSST Data Management System
# Copyright 2018 AURA/LSST.
#
# This product includes software developed by the
# LSST Project (http://www.lsst.org/).
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
# You should have received a copy of the LSST License Statement and
# the GNU General Public License along with this program.  If not,
# see <http://www.lsstcorp.org/LegalNotices/>.


import argparse
import base64
import logging
import os
import struct
from typing import Dict, Any, Tuple, Callable, List

import jwt
import requests
from cachetools import TTLCache, cached
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from flask import Flask, request, Response, current_app
from jwt import InvalidTokenError, InvalidIssuerError
from requests import HTTPError

from .config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = Flask(__name__)

ALGORITHM = 'RS256'


@app.route('/auth')
def authnz_token():
    """
    Authenticate and authorize a token.
    """
    # Default to Server Error for safety, so we must always set it to 200
    # if it's okay.
    response = Response(status=500)
    if 'Authorization' not in request.headers and "x-oauth-basic" not in request.cookies:
        response = _needs_authentication(response, "No Authorization header", "")
        return response

    encoded_token = _find_token()

    # Convert the token
    # Send a 401 error code if there is any problem
    try:
        unverified_header = jwt.get_unverified_header(encoded_token)
        unverified_token = jwt.decode(encoded_token, verify=False)
    except InvalidTokenError as e:
        response = _needs_authentication(response, "Invalid Token", str(e))
        logger.exception("Failed to decode Token")
        logger.exception(e)
        return response
    logging.debug("Received Unverified Token: " + str(unverified_token))
    try:
        issuer_url = unverified_token['iss']
        if current_app.config["NO_VERIFY"] is True:
            logger.debug("Skipping Verification of the token")
            verified_token = unverified_token
        else:
            if issuer_url not in current_app.config['ISSUERS']:
                raise InvalidIssuerError(f"Unauthorized Issuer: {issuer_url}")
            issuer = current_app.config['ISSUERS'][issuer_url]
            key = get_key_as_pem(issuer_url, unverified_header["kid"])
            verified_token = jwt.decode(encoded_token,
                                        key,
                                        algorithm=ALGORITHM,
                                        audience=issuer['audience'],
                                        options=current_app.config['JWT_VERIFICATION_OPTIONS'])
    except Exception as e:
        response = _needs_authentication(response, "Invalid Token", str(e))
        logger.exception("Failed to deserialize Token")
        logger.exception(e)
        return response

    if "Basic" in request.headers["Authorization"] and "x-oauth-basic" not in request.cookies:
        response.set_cookie("x-oauth-basic", encoded_token)

    if current_app.config['NO_AUTHORIZE'] is True:
        response.set_data("Authorization is Ok")
        response.status_code = 200
        set_headers(response, verified_token, encoded_token)
        return response

    # Authorization Checks
    capabilities = request.args.getlist("capability")
    satisfy = request.args.get("satisfy") or "all"

    # If no capability have been explicitly delineated in the URI,
    # get them from the request method
    assert satisfy != "any", "ERROR: Logic Error, Check nginx auth_request url (satisfy)"
    assert capabilities, "ERROR: Check nginx auth_request url (capabilities)"

    jti = str(verified_token['jti']) if "jti" in verified_token else None
    request_method = request.headers.get('X-Original-Method')
    request_path = request.headers.get('X-Original-URI')
    successes = []
    message = ""
    for capability in capabilities:
        logger.debug(f"Checking authorization for capability: {capability}")
        (success, message) = check_authorization(capability, request_method, request_path,
                                                 verified_token)
        successes.append(success)
        if satisfy == "any":
            break

    response.set_data(message)
    if satisfy == "any":
        success = len(successes)
    else:
        success = sum(successes) == len(capabilities)

    if success:
        response.status_code = 200
        set_headers(response, verified_token, encoded_token)
        if jti:
            logger.info(f"Allowed token with Token ID: {jti} from issuer {issuer_url}")
        return response

    if jti:
        logger.error(f"Failed to authenticate Token ID {jti} because {message}")
    else:
        logger.error(f"Failed to authenticate Token because {message}")
    response.status_code = 403
    return response


def set_headers(response: Response, verified_token: Dict[str, Any],
                encoded_token: str) -> Response:
    """Set Headers that will be returned in a successful response.
    :return: The mutated response object.
    """
    if current_app.config["SET_USER_HEADERS"]:
        email = verified_token.get("email")
        user = verified_token.get(current_app.config["JWT_USERNAME_KEY"])
        uid = verified_token.get(current_app.config["JWT_UID_KEY"])
        if email:
            response.headers['X-Auth-Request-Email'] = uid
        if user:
            response.headers['X-Auth-Request-User'] = user
        if uid:
            response.headers['X-Auth-Request-Uid'] = uid
    response.headers["X-Auth-Request-Token"] = encoded_token
    return response


def _find_token():
    """
    From the request, find the token we need. Normally it should
    be in the Authorization header of type ``Bearer``, but it may
    be of type Basic for clients that don't support OAuth.
    :return: The token
    """
    auth_type, auth_blob = request.headers['Authorization'].split(" ")
    encoded_token = None
    if auth_type.lower() == "bearer":
        encoded_token = auth_blob
    elif "x-forwarded-access-token" in request.headers:
        encoded_token = request.headers["x-forwarded-access-token"]
    elif "x-forwarded-id-token" in request.headers:
        encoded_token = request.headers["x-forwarded-id-token"]
    elif auth_type.lower() == "basic":
        logger.debug("Using OAuth with Basic")
        # We fallback to user:token. We ignore the user.
        # The Token is in the password
        encoded_basic_auth = auth_blob
        basic_auth = base64.b64decode(encoded_basic_auth)
        user, password = basic_auth.strip().split(b":")
        if password == "x-oauth-basic":
            # Recommended default
            encoded_token = user
        elif user == "x-oauth-basic":
            # ... Could be this though
            logger.warning("Protocol `x-oauth-basic` should be in password field")
            encoded_token = password
        else:
            logger.info("No protocol for token specified")
            encoded_token = user
    return encoded_token


def _needs_authentication(response: Response, error: str, message: str) -> Response:
    """Modify response for a 401 as appropriate"""
    response.status_code = 401
    response.set_data(error)
    if not current_app.config.get("WWW_AUTHENTICATE"):
        return response
    realm = current_app.config["REALM"]
    if current_app.config["WWW_AUTHENTICATE"].lower() == "basic":
        # Otherwise, send Bearer
        response.headers['WWW-Authenticate'] = \
            f'Basic realm="{realm}"'
    else:
        response.headers['WWW-Authenticate'] = \
            f'Bearer realm="{realm}",error="{error}",error_description="{message}"'
    return response


def check_authorization(capability: str, request_method: str, request_path: str,
                        verified_token: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Check the authorization of the request based on the original method,
    request path, and token.
    :param capability: The capability we are authorizing
    :param request_method: Original HTTP method
    :param request_path: The Original request path
    :param verified_token: The verified token
    :rtype: Tuple[bool, str]
    :returns: (True, message) with successful as True if the
    all checks pass, otherwiss returns (False, message)
    """

    check_access_callables = get_check_access_functions()

    successes = []
    message = ""
    for check_access in check_access_callables:
        logger.debug(f"Checking access using {check_access.__name__}")
        (successful, message) = check_access(capability, request_method, request_path,
                                             verified_token)
        if not successful:
            break
        successes.append(successful)

    success = sum(successes) == len(check_access_callables)
    return success, message


def get_check_access_functions() -> List[Callable]:
    """
    Return the check access callable for a resource.
    :return: A callable for check access
    """
    callables = []
    for checker_name in current_app.config['ACCESS_CHECKS']:
        callables.append(current_app.ACCESS_CHECK_CALLABLES[checker_name])
    return callables


@cached(cache=TTLCache(maxsize=16, ttl=600))
def get_key_as_pem(issuer_url, request_key_id):
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
    logging.debug(f"Getting keys for: {issuer_url}")
    oidc_config = os.path.join(issuer_url, ".well-known/openid-configuration")
    try:
        info_key_ids = issuer.get("issuer_key_ids")
        if info_key_ids and request_key_id not in info_key_ids:
            raise KeyError(f"kid {request_key_id} not found in Issuer configuration")

        oidc_resp = requests.get(oidc_config)
        oidc_resp.raise_for_status()
        jwks_uri = oidc_resp.json()["jwks_uri"]
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
    except (KeyError, HTTPError) as e:
        logger.error(f"Unable to retrieve and store key for issuer: {issuer_url} ")
        logger.error(e)
        raise e


def configure():
    parser = argparse.ArgumentParser(description='Authenticate HTTP Requests')
    parser.add_argument('-c', '--config', dest='config', type=str,
                        default="/etc/jwt-authorizer/authorizer.yaml",
                        help="Location of the yaml configuration file")

    args = parser.parse_args()

    # Read in configuration
    Config.validate(app, args.config)


configure()


def main():
    # Set up listener for events
    app.run(host='localhost', port=8080)


if __name__ == "__main__":
    main()
