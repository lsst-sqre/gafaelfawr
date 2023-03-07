"""Send alerts to Slack."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, root_validator, validator
from safir.datetime import current_datetime
from safir.dependencies.http_client import http_client_dependency
from structlog.stdlib import BoundLogger

_SLACK_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
"""Date format to use for dates in Slack alerts."""

__all__ = [
    "SlackClient",
    "SlackField",
    "SlackIgnoredException",
    "SlackMessage",
]


class SlackIgnoredException(Exception):
    """Parent class for exceptions that should not be reported to Slack.

    This exception has no built-in behavior or meaning except to suppress
    Slack notifications if it is thrown uncaught.  Application exceptions that
    should not result in a Slack alert (because, for example, they're intended
    to be caught by exception handlers) should inherit from this class.
    """


def _truncate_string_at_end(string: str, extra_needed: int = 0) -> str:
    """Truncate a string at 3000 characters from the end.

    Slack prohibits text blocks longer than 3000 characters anywhere in the
    mesage and, if present, the whole mesage is rejected with an HTTP error.
    Truncate a potentially long message at the end.

    Parameters
    ----------
    string
        String to truncate.
    extra_needed
        Additional characters needed (for a heading, for instance).

    Returns
    -------
    str
        The truncated string.
    """
    if len(string) < 3000 - extra_needed:
        return string
    truncated = "\n... truncated ...\n"
    last_newline = string.rfind("\n", 0, 3000 - len(truncated) - extra_needed)
    if last_newline == -1:
        return string[: 3000 - len(truncated) - extra_needed] + truncated
    else:
        return string[:last_newline] + truncated


def _truncate_string_at_start(string: str, extra_needed: int = 0) -> str:
    """Truncate a string at 3000 characters from the start.

    Slack prohibits text blocks longer than 3000 characters anywhere in the
    message and, if present, the whole message is rejected with an HTTP error.
    Truncate a potentially long message at the start. Use this for tracebacks
    and similar

    Parameters
    ----------
    string
        String to truncate.
    extra_needed
        Additional characters needed (for a heading, for instance).

    Returns
    -------
    str
        The truncated string.
    """
    length = len(string)
    if length < 3000 - extra_needed:
        return string
    lines = string.split("\n")
    if len(lines) == 1:
        truncated = "... truncated ...\n"
        start = length - 3000 + len(truncated) + extra_needed
        return truncated + string[start:]
    while length >= 3000 - extra_needed:
        line = lines.pop(0)
        length -= len(line) + 1
    return "\n".join(lines)


class SlackField(BaseModel):
    """A component of a Slack message with a heading."""

    heading: str
    """Heading of the field (shown in bold)."""

    text: Optional[str] = None
    """Text of the field as normal text (use this or ``code``)."""

    code: Optional[str] = None
    """Text of the field as a code block (use this or ``text``)."""

    @root_validator
    def _validate_content(cls, values: dict[str, Any]) -> dict[str, Any]:
        """Ensure only one of ``text`` or ``code`` is set."""
        if values["text"] and values["code"]:
            raise ValueError("Only one of text and code may be given")
        if values["text"] is None and values["code"] is None:
            raise ValueError("One of text or code must be given")
        return values

    @validator("text")
    def _validate_text(
        cls, v: str | None, values: dict[str, Any]
    ) -> str | None:
        """Truncate the text section if needed."""
        if v is None:
            return v
        extra_needed = len(values["heading"]) + 3  # *Heading*\n
        return _truncate_string_at_end(v.strip(), extra_needed)

    @validator("code")
    def _validate_code(
        cls, v: str | None, values: dict[str, Any]
    ) -> str | None:
        """Truncate the code section if needed."""
        if v is None:
            return v
        extra_needed = len(values["heading"]) + 3 + 8  # *Heading*\n```\n\n```
        return _truncate_string_at_start(v.strip(), extra_needed)

    def to_slack(self) -> dict[str, Any]:
        """Convert to a Slack Block Kit block.

        Returns
        -------
        dict
            A Slack Block Kit block suitable for including in the ``fields``
            or ``text`` section of a ``blocks`` element.
        """
        heading = f"*{self.heading}*\n"
        if self.code:
            body = f"```\n{self.code}\n```"
        else:
            if not self.text:
                raise RuntimeError("SlackField without code or text")
            body = self.text
        return {"type": "mrkdwn", "text": heading + body, "verbatim": True}


class SlackMessage(BaseModel):
    """Message to post to Slack."""

    message: str
    """Main part of the message."""

    fields: list[SlackField] = []
    """Short key/value fields to include in the message."""

    attachments: list[SlackField] = []
    """Longer sections to include as attachments."""

    @validator("message")
    def _validate_message(cls, v: str) -> str:
        """Truncate the message if needed."""
        return _truncate_string_at_end(v.strip())

    def to_slack(self) -> dict[str, Any]:
        """Convert to a Slack Block Kit message.

        Returns
        -------
        dict
            A Slack Block Kit data structure suitable for serializing to
            JSON and sending to Slack.
        """
        fields = [f.to_slack() for f in self.fields]
        attachments = [
            {"type": "section", "text": a.to_slack()} for a in self.attachments
        ]
        blocks: list[dict[str, Any]] = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": self.message},
            }
        ]
        if fields:
            blocks.append({"type": "section", "fields": fields})
        result: dict[str, Any] = {"blocks": blocks}
        if attachments:
            result["attachments"] = [{"blocks": attachments}]
        elif fields:
            result["blocks"].append({"type": "divider"})
        return result


class SlackClient:
    """Publish alerts to Slack.

    Use an incoming webhook to publish an alert to a Slack channel.

    Parameters
    ----------
    hook_url
        The URL of the incoming webhook to use to publish the message.
    application
        Name of the application reporting an error.
    logger
        Logger to which to report errors sending messages to Slack.
    """

    def __init__(
        self, hook_url: str, application: str, logger: BoundLogger
    ) -> None:
        self._hook_url = hook_url
        self._application = application
        self._logger = logger

    async def post(self, message: SlackMessage) -> None:
        """Post a message to Slack.

        Parameters
        ----------
        message
            Message to post.
        """
        self._logger.debug("Sending message to Slack")
        body = message.to_slack()
        try:
            client = await http_client_dependency()
            r = await client.post(self._hook_url, json=body)
            r.raise_for_status()
        except Exception:
            msg = "Posting Slack message failed"
            self._logger.exception(msg, message=body)

    async def post_uncaught_exception(self, exc: Exception) -> None:
        """Post an alert to Slack about an uncaught webapp exception.

        Parameters
        ----------
        exc
            The exception to report.
        """
        date = current_datetime().strftime(_SLACK_DATE_FORMAT)
        name = type(exc).__name__
        error = f"{name}: {str(exc)}"
        message = SlackMessage(
            message=f"Uncaught {name} exception in {self._application}",
            fields=[SlackField(heading="Failed at", text=date)],
            attachments=[SlackField(heading="Exception", code=error)],
        )
        await self.post(message)
