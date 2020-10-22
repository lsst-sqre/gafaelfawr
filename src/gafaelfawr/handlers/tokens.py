"""Handlers for user-created tokens (``/auth/tokens``)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from wtforms import BooleanField, Form, HiddenField, SubmitField

from gafaelfawr.auth import verified_token
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.dependencies.csrf import set_csrf, verify_csrf
from gafaelfawr.session import Session, SessionHandle
from gafaelfawr.tokens import VerifiedToken

if TYPE_CHECKING:
    from typing import Dict, Optional

    from starlette.datastructures import FormData
    from starlette.templating import _TemplateResponse

router = APIRouter()
templates = Jinja2Templates(str(Path(__file__).parent.parent / "templates"))

__all__ = [
    "get_token_by_handle",
    "get_tokens",
    "get_tokens_new",
    "post_delete_token",
    "post_tokens_new",
]


class AlterTokenForm(Form):
    """Form for altering an existing user token."""

    method_ = HiddenField("method_")
    csrf = HiddenField("_csrf")


def build_new_token_form(
    scopes: Dict[str, str], data: Optional[FormData] = None
) -> Form:
    """Dynamically generates a form with checkboxes for scopes.

    Parameters
    ----------
    scopes : Dict[`str`, `str`]
        A mapping of scope names to descriptions to include in the form.
    data : MultiDictProxy[Union[`str`, `bytes`, FileField]], optional
        The submitted form data, if any.

    Returns
    -------
    form : `wtforms.Form`
        The generated form.
    """

    class NewTokenForm(Form):
        """Stub form, to which fields will be dynamically added."""

        csrf = HiddenField("_csrf")
        submit = SubmitField("Generate New Token")

    for scope, description in scopes.items():
        field = BooleanField(label=scope, description=description)
        setattr(NewTokenForm, scope, field)
    return NewTokenForm(data)


@router.get("/auth/tokens", dependencies=[Depends(set_csrf)])
async def get_tokens(
    token: VerifiedToken = Depends(verified_token),
    context: RequestContext = Depends(context_dependency),
) -> _TemplateResponse:
    """Displays all tokens for the current user.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    user_token_store = context.factory.create_user_token_store()
    await user_token_store.expire_tokens(token.uid)
    user_tokens = await user_token_store.get_tokens(token.uid)
    forms = {}
    for user_token in user_tokens:
        form = AlterTokenForm()
        form.csrf.data = context.request.state.cookie.csrf
        forms[user_token.key] = form

    context.logger.info("Listed tokens")
    return templates.TemplateResponse(
        "tokens.html",
        {
            "request": context.request,
            "message": context.request.state.cookie.message,
            "tokens": user_tokens,
            "forms": forms,
            "csrf_token": context.request.state.cookie.csrf,
        },
    )


@router.get("/auth/tokens/new", dependencies=[Depends(set_csrf)])
async def get_tokens_new(
    token: VerifiedToken = Depends(verified_token),
    context: RequestContext = Depends(context_dependency),
) -> _TemplateResponse:
    """Return a form for creating a new token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    scopes = {
        s: d
        for s, d in context.config.known_scopes.items()
        if s in token.scope
    }
    form = build_new_token_form(scopes)

    context.logger.info("Returned token creation form")
    return templates.TemplateResponse(
        "new_token.html",
        {
            "request": context.request,
            "form": form,
            "scopes": scopes,
            "csrf_token": context.request.state.cookie.csrf,
        },
    )


@router.post("/auth/tokens/new", dependencies=[Depends(verify_csrf)])
async def post_tokens_new(
    token: VerifiedToken = Depends(verified_token),
    context: RequestContext = Depends(context_dependency),
) -> RedirectResponse:
    """Create a new token based on form parameters.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    scopes = {
        s: d
        for s, d in context.config.known_scopes.items()
        if s in token.scope
    }
    form = build_new_token_form(scopes, await context.request.form())
    if not form.validate():
        msg = "Form validation failed"
        context.logger.warning("Token creation failed", error=msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"type": "form_validation", "msg": msg},
        )

    scope = " ".join([s for s in scopes if form[s].data])
    issuer = context.factory.create_token_issuer()
    handle = SessionHandle()
    user_token = issuer.issue_user_token(token, scope=scope, jti=handle.key)

    session_store = context.factory.create_session_store()
    user_token_store = context.factory.create_user_token_store()
    user_session = Session.create(handle, user_token)
    pipeline = context.redis.pipeline()
    await session_store.store_session(user_session, pipeline)
    user_token_store.store_session(token.uid, user_session, pipeline)
    await pipeline.execute()

    context.request.state.cookie.message = (
        f"Your Newly Created Token. Keep these Secret!<br>\n"
        f"Token: {handle.encode()} <br>"
    )

    context.logger.info("Created token %s with scope %s", handle.key, scope)
    return RedirectResponse(
        "/auth/tokens", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/auth/tokens/{handle}")
async def get_token_by_handle(
    handle: str,
    token: VerifiedToken = Depends(verified_token),
    context: RequestContext = Depends(context_dependency),
) -> _TemplateResponse:
    """Displays information about a single token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    user_token_store = context.factory.create_user_token_store()
    user_token = None
    for entry in await user_token_store.get_tokens(token.uid):
        if entry.key == handle:
            user_token = entry
            break

    if not user_token:
        msg = f"No token with handle {handle} found"
        context.logger.warning("Token not found", error=msg)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "type": "not_found",
                "loc": ["path", "handle"],
                "msg": msg,
            },
        )

    context.logger.info("Viewed token %s", handle)
    return templates.TemplateResponse(
        "token.html", {"request": context.request, "token": user_token}
    )


@router.post("/auth/tokens/{handle}", dependencies=[Depends(verify_csrf)])
async def post_delete_token(
    handle: str,
    token: VerifiedToken = Depends(verified_token),
    context: RequestContext = Depends(context_dependency),
) -> RedirectResponse:
    """Deletes a single token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : Dict[`str`, `object`]
        Form variables that are processed by the template decorator, which
        turns them into an `aiohttp.web.Response`.
    """
    form = AlterTokenForm(await context.request.form())
    if not form.validate() or form.method_.data != "DELETE":
        msg = "Invalid deletion request"
        context.logger.warning("Token deletion failed", error=msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"type": "form_validation", "msg": msg},
        )

    user_token_store = context.factory.create_user_token_store()
    session_store = context.factory.create_session_store()
    pipeline = context.redis.pipeline()
    success = await user_token_store.revoke_token(token.uid, handle, pipeline)
    if success:
        await session_store.delete_session(handle, pipeline)
        await pipeline.execute()

    if success:
        message = f"Your token with the handle {handle} was deleted"
    else:
        message = "An error was encountered when deleting your token"
    context.request.state.cookie.message = message

    context.logger.info("Deleted token %s", handle)
    return RedirectResponse(
        "/auth/tokens", status_code=status.HTTP_303_SEE_OTHER
    )
