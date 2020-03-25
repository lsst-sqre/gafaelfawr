"""Flask application routes for JWT Authorizer."""

from __future__ import annotations

import base64
import logging
import os
from typing import Any, Dict, Mapping, Optional, Tuple

from dynaconf import FlaskDynaconf
from flask import (
    Flask,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from jwt import PyJWTError

from jwt_authorizer.analyze import analyze_ticket, analyze_token
from jwt_authorizer.authnz import (
    authenticate,
    authorize,
    capabilities_from_groups,
    verify_authorization_strategy,
)
from jwt_authorizer.session import (
    InvalidTicketException,
    Ticket,
    create_session_store,
)
from jwt_authorizer.tokens import (
    AlterTokenForm,
    api_capabilities_token_form,
    create_token_verifier,
    get_tokens,
    issue_token,
    revoke_token,
)

__all__ = [
    "analyze",
    "authnz_token",
    "create_app",
    "new_tokens",
    "token_for_handle",
    "tokens",
]


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = Flask(__name__)


ORIGINAL_TOKEN_HEADER = "X-Orig-Authorization"


@app.route("/auth")
def authnz_token():  # type: ignore
    """Authenticate and authorize a token.

    Notes
    -----
    Expects the following query parameters to be set:

    capability
        One or more capabilities to check (required).
    satisfy
        Require that ``all`` (the default) or ``any`` of the capabilities
        requested via the ``capbility`` parameter be satisfied.

    Expects the following headers to be set in the request:

    Authorization
        The JWT token. This must always be the full JWT token. The token
        should be in this  header as type ``Bearer``, but it may be type
        ``Basic`` if ``x-oauth-basic`` is the username or password.
    X-Orig-Authorization
        The Authorization header as it was received before processing by
        ``oauth2_proxy``. This is useful when the original header was an
        ``oauth2_proxy`` ticket, as this gives access to the ticket.

    The following headers may be set in the response:

    X-Auth-Request-Email
        If enabled and email is available, this will be set based on the
        ``email`` claim.
    X-Auth-Request-User
        If enabled and the field is available, this will be set from token
        based on the ``JWT_USERNAME_KEY`` field.
    X-Auth-Request-Uid
        If enabled and the field is available, this will be set from token
        based on the ``JWT_UID_KEY`` field.
    X-Auth-Request-Groups
        When a token has groups available in the ``isMemberOf`` claim, the
        names of the groups will be returned, comma-separated, in this
        header.
    X-Auth-Request-Token
        If enabled, the encoded token will be set.
    X-Auth-Request-Token-Ticket
        When a ticket is available for the token, we will return it under this
        header.
    X-Auth-Request-Token-Capabilities
        If the token has capabilities in the ``scope`` claim, they will be
        returned in this header.
    X-Auth-Request-Token-Capabilities-Accepted
        A space-separated list of token capabilities the reliant resource
        accepts.
    X-Auth-Request-Token-Capabilities-Satisfy
        The strategy the reliant resource uses to accept a capability. Values
        include ``any`` or ``all``.
    WWW-Authenticate
        If the request is unauthenticated, this header will be set.
    """
    # Default to Server Error for safety, so we must always set it to
    # 200 if it's okay.
    response = Response(status=500)
    if "Authorization" not in request.headers:
        _make_needs_authentication(response, "No Authorization header", "")
        return response

    encoded_token = _find_token("Authorization")
    if not encoded_token:
        _make_needs_authentication(response, "Unable to find token", "")
        return response

    # Authentication
    try:
        verified_token = authenticate(encoded_token)
    except PyJWTError as e:
        # All JWT failures get 401s and are logged.
        _make_needs_authentication(response, "Invalid Token", str(e))
        logger.exception("Failed to authenticate Token")
        logger.exception(e)
        return response

    # Authorization
    success, message = authorize(verified_token)

    # Always add info about authorization
    _make_capability_headers(response, verified_token)

    jti = verified_token.get("jti", "UNKNOWN")
    if success:
        response.status_code = 200
        _make_success_headers(response, encoded_token, verified_token)
        user_id = verified_token[current_app.config["JWT_UID_KEY"]]
        logger.info(
            f"Allowed token with Token ID={jti} for user={user_id} "
            f"from issuer={verified_token['iss']}"
        )
        return response

    response.set_data(message)
    # All authorization failures get 403s
    response.status_code = 403
    logger.error(f"Failed to authorize Token ID {jti} because {message}")
    return response


@app.route("/auth/analyze", methods=["POST"])
def analyze() -> Any:
    """Analyze a token.

    Expects a POST with a single parameter, ``token``, which is either a
    ticket or a full token.  Returns a JSON structure with details about that
    token.
    """
    prefix = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
    token_verifier = create_token_verifier(current_app)
    ticket_or_token = request.form["token"]
    try:
        ticket = Ticket.from_str(prefix, ticket_or_token)
        token_store = create_session_store(current_app)
        return jsonify(
            analyze_ticket(ticket, prefix, token_store, token_verifier)
        )
    except InvalidTicketException:
        analysis = analyze_token(ticket_or_token, token_verifier)
        return jsonify({"token": analysis})


@app.route("/auth/tokens", methods=["GET"])
def tokens():  # type: ignore
    """Displays all tokens for the current user."""
    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        decoded_token = authenticate(encoded_token)
    except PyJWTError as e:
        response = Response()
        _make_needs_authentication(response, "Invalid Token", str(e))
        logger.exception("Failed to authenticate Token")
        logger.exception(e)
        return response
    user_id = decoded_token[current_app.config["JWT_UID_KEY"]]
    user_tokens = get_tokens(user_id)
    forms = {}
    for user_token in user_tokens:
        forms[user_token["jti"]] = AlterTokenForm()
    return render_template(
        "tokens.html", title="Tokens", tokens=user_tokens, forms=forms
    )


@app.route("/auth/tokens/<handle>", methods=["GET", "POST"])
def token_for_handle(handle: str):  # type: ignore
    """Displays or deletes a single token.

    On GET, displays information about a single token.  On POST with
    ``DELETE`` as the data, deletes a single token.

    Parameters
    ----------
    handle : `str`
        The identifier for the token.
    """
    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        decoded_token = authenticate(encoded_token)
    except PyJWTError as e:
        response = Response()
        _make_needs_authentication(response, "Invalid Token", str(e))
        logger.exception("Failed to authenticate Token")
        logger.exception(e)
        return response
    user_id = decoded_token[current_app.config["JWT_UID_KEY"]]
    user_tokens = {t["jti"]: t for t in get_tokens(user_id)}
    user_token = user_tokens[handle]

    form = AlterTokenForm()
    if request.method == "POST" and form.validate():
        if form.method_.data == "DELETE":
            success = revoke_token(user_id, handle)
            if success:
                flash(f"Your token with the ticket_id {handle} was deleted")
            if not success:
                flash(f"An error was encountered when deleting your token.")
            return redirect(url_for("tokens"))

    return render_template("token.html", title="Tokens", token=user_token)


@app.route("/auth/tokens/new", methods=["GET", "POST"])
def new_tokens():  # type: ignore
    """Create a new token.

    On GET, return a form for creating a new token.  On POST, create that new
    token based on the form parameters.
    """
    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        decoded_token = authenticate(encoded_token)
    except PyJWTError as e:
        response = Response()
        _make_needs_authentication(response, "Invalid Token", str(e))
        logger.exception("Failed to authenticate Token")
        logger.exception(e)
        return response

    capabilities = current_app.config["KNOWN_CAPABILITIES"]
    form = api_capabilities_token_form(capabilities)

    if request.method == "POST" and form.validate():
        new_capabilities = []
        for capability in capabilities:
            if form[capability].data:
                new_capabilities.append(capability)
        scope = " ".join(new_capabilities)
        audience = current_app.config.get(
            "OAUTH2_JWT.AUD.DEFAULT", decoded_token["aud"]
        )
        new_token: Dict[str, Any] = {"scope": scope}
        email = decoded_token.get("email")
        user = decoded_token.get(current_app.config["JWT_USERNAME_KEY"])
        uid = decoded_token.get(current_app.config["JWT_UID_KEY"])
        if email:
            new_token["email"] = email
        if user:
            new_token[current_app.config["JWT_USERNAME_KEY"]] = user
        if uid:
            new_token[current_app.config["JWT_UID_KEY"]] = uid

        # FIXME: Copies groups. Useful for WebDAV, maybe not necessary
        #
        # new_token['isMemberOf'] = decoded_token['isMemberOf']
        oauth2_proxy_ticket = Ticket()
        _ = issue_token(
            new_token,
            aud=audience,
            store_user_info=True,
            oauth2_proxy_ticket=oauth2_proxy_ticket,
        )
        prefix = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
        oauth2_proxy_ticket_str = oauth2_proxy_ticket.encode(prefix)
        flash(
            f"Your Newly Created Token. Keep these Secret!<br>\n"
            f"Token: {oauth2_proxy_ticket_str} <br>"
        )
        return redirect(url_for("tokens"))

    return render_template(
        "new_token.html",
        title="New Token",
        form=form,
        capabilities=capabilities,
    )


def _make_capability_headers(
    response: Response, verified_token: Mapping[str, Any]
) -> None:
    """Set capability information in response headers.

    Set headers that can be returned in the case of API authorization failure
    due to required capabiliites.

    Parameters
    ----------
    response : `Response`
        The response object to mutate in place.
    verified_token : `Mapping` [`str`, `Any`]
        A verified token containing group and scope information.
    """
    capabilities_required, satisfy = verify_authorization_strategy()
    group_capabilities_set = capabilities_from_groups(verified_token)
    if "scope" in verified_token:
        scope_capabilities_set = set(verified_token["scope"].split(" "))
        user_capabilities_set = group_capabilities_set.union(
            scope_capabilities_set
        )
    else:
        user_capabilities_set = group_capabilities_set

    response.headers["X-Auth-Request-Token-Capabilities"] = " ".join(
        sorted(user_capabilities_set)
    )
    response.headers["X-Auth-Request-Capabilities-Accepted"] = " ".join(
        sorted(capabilities_required)
    )
    response.headers["X-Auth-Request-Capabilities-Satisfy"] = satisfy


def _make_success_headers(
    response: Response, encoded_token: str, verified_token: Mapping[str, Any]
) -> None:
    """Set Headers that will be returned in a successful response.

    Parameters
    ----------
    response : `Response`
        The response object to mutate in place.
    encoded_token : `str`
        The token encoded as a JWT.
    verified_token : `Mapping` [`str`, `Any`]
        A verified token containing group and scope information.
    """
    _make_capability_headers(response, verified_token)

    if current_app.config["SET_USER_HEADERS"]:
        email = verified_token.get("email")
        user = verified_token.get(current_app.config["JWT_USERNAME_KEY"])
        uid = verified_token.get(current_app.config["JWT_UID_KEY"])
        groups_list = verified_token.get("isMemberOf", list())
        if email:
            response.headers["X-Auth-Request-Email"] = email
        if user:
            response.headers["X-Auth-Request-User"] = user
        if uid:
            response.headers["X-Auth-Request-Uid"] = uid
        if groups_list:
            groups = ",".join([g["name"] for g in groups_list])
            response.headers["X-Auth-Request-Groups"] = groups

    encoded_token, oauth2_proxy_ticket = _check_reissue_token(
        encoded_token, verified_token
    )
    response.headers["X-Auth-Request-Token"] = encoded_token
    response.headers["X-Auth-Request-Token-Ticket"] = oauth2_proxy_ticket


def _check_reissue_token(
    encoded_token: str, decoded_token: Mapping[str, Any]
) -> Tuple[str, str]:
    """Possibly reissue the token.

    Notes
    -----
    The token will be reissued under two scenarios.

    The first scenario is a newly logged in session with a cookie, indicated
    by the token being issued from another issuer.  We reissue the token with
    a default audience.

    The second scenario is a request to an internal resource, as indicated by
    the ``audience`` parameter being equal to the configured internal
    audience, where the current token's audience is from the default audience.
    We will reissue the token with an internal audience.

    Parameters
    ----------
    encoded_token : `str`
        The current token, encoded.
    decoded_token : `Mapping` [`str`, `Any`]
        The current token, decoded.

    Returns
    -------
    encoded_token : `str`
        An encoded token, which may have been reissued.
    oauth2_proxy_ticket_str : `str`
        A ticket for the oauth2_proxy session.
    """
    # Only reissue token if it's requested and if it's a different
    # issuer than this application uses to reissue a token
    iss = current_app.config.get("OAUTH2_JWT.ISS", "")
    assert len(iss), "ERROR: Reissue requested but no Issuer Configured"
    default_audience = current_app.config.get("OAUTH2_JWT.AUD.DEFAULT", "")
    internal_audience = current_app.config.get("OAUTH2_JWT.AUD.INTERNAL", "")
    to_internal_audience = request.args.get("audience") == internal_audience
    from_this_issuer = decoded_token["iss"] == iss
    from_default_audience = decoded_token["aud"] == default_audience
    cookie_name = current_app.config["OAUTH2_STORE_SESSION"]["TICKET_PREFIX"]
    ticket_str = request.cookies.get(cookie_name, "")
    ticket = None
    new_audience = None
    if not from_this_issuer:
        # If we didn't issue the token, it came from a provider as part of a
        # new session. This only happens once, after initial login, so there
        # should always be a cookie set. If there isn't, or we fail to parse
        # it, something funny is going on and we can abort with an exception.
        ticket = Ticket.from_cookie(cookie_name, ticket_str)

        # Make a copy of the previous token and add capabilities
        decoded_token = dict(decoded_token)
        decoded_token["scope"] = " ".join(
            sorted(capabilities_from_groups(decoded_token))
        )
        new_audience = current_app.config.get("OAUTH2_JWT.AUD.DEFAULT", "")
    elif from_this_issuer and from_default_audience and to_internal_audience:
        # In this case, we only reissue tokens from a default audience
        new_audience = current_app.config.get("OAUTH2_JWT.AUD.INTERNAL", "")
        ticket = Ticket()

    if new_audience:
        assert ticket
        encoded_token = issue_token(
            decoded_token,
            new_audience,
            store_user_info=False,
            oauth2_proxy_ticket=ticket,
        )
    return encoded_token, ticket.encode(cookie_name) if ticket else ""


def _find_token(header: str) -> Optional[str]:
    """From the request, find the token we need.

    Normally it should be in the Authorization header of type ``Bearer``, but
    it may be of type Basic for clients that don't support OAuth.

    Parameters
    ----------
    header : `str`
        Name of HTTP header to check for token.

    Returns
    -------
    encoded_token : `Optional` [`str`]
        The token text, if found, otherwise None.
    """
    header_value = request.headers.get(header, "")
    if not header_value or " " not in header_value:
        return None
    auth_type, auth_blob = header_value.split(" ")
    encoded_token = None
    if auth_type.lower() == "bearer":
        encoded_token = auth_blob
    elif "x-forwarded-access-token" in request.headers:
        encoded_token = request.headers["x-forwarded-access-token"]
    elif "x-forwarded-ticket-id-token" in request.headers:
        encoded_token = request.headers["x-forwarded-ticket-id-token"]
    elif auth_type.lower() == "basic":
        logger.debug("Using OAuth with Basic")
        # We fallback to user:token. We ignore the user.
        # The Token is in the password
        encoded_basic_auth = auth_blob
        basic_auth = base64.b64decode(encoded_basic_auth)
        user, password = basic_auth.strip().split(b":")
        if password == b"x-oauth-basic":
            # Recommended default
            encoded_token = user.decode()
        elif user == b"x-oauth-basic":
            # ... Could be this though
            encoded_token = password.decode()
        else:
            logger.debug("No protocol for token specified")
            encoded_token = user.decode()
    return encoded_token


def _make_needs_authentication(
    response: Response, error: str, message: str
) -> None:
    """Modify response for a 401 as appropriate.

    Parameters
    ----------
    response : `Response`
        The response to modify for authentication required.
    error : `str`
        The error message to use as the body of the message and the error
        parameter in the WWW-Authenticate header.
    message : `str`
        The error description for the WWW-Authetnicate header.
    """
    response.status_code = 401
    response.set_data(error)
    if not current_app.config.get("WWW_AUTHENTICATE"):
        return
    realm = current_app.config["REALM"]
    if current_app.config["WWW_AUTHENTICATE"].lower() == "basic":
        # Otherwise, send Bearer
        response.headers["WWW-Authenticate"] = f'Basic realm="{realm}"'
    else:
        info = f'realm="{realm}",error="{error}",error_description="{message}"'
        response.headers["WWW-Authenticate"] = f"Bearer {info}"


def create_app(**config: str) -> Flask:
    """Create the Flask app, optionally with Dynaconf settings.

    Parameters
    ----------
    **config : `str`
        Configuration key/value pairs that will be passed to Dynaconf to
        initialize its settings.

    Returns
    -------
    app : `Flask`
        Configured Flask application.

    Notes
    -----
    This is an as-yet incomplete reimplementation of the app initialization
    now done in Config.validate().  It is currently only used by the test
    suite.
    """
    defaults_file = os.path.join(os.path.dirname(__file__), "defaults.yaml")
    FlaskDynaconf(app, **config, SETTINGS_FILE_FOR_DYNACONF=defaults_file)
    return app
