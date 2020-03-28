"""Tests for the jwt_authorizer.session package."""

from __future__ import annotations

import base64

import pytest

from jwt_authorizer.session import (
    InvalidCookieException,
    InvalidTicketException,
    SessionStore,
    Ticket,
)
from jwt_authorizer.util import add_padding


def test_parse_session_date() -> None:
    """Check that we can parse the session dates written by oauth2_proxy."""
    date = SessionStore._parse_session_date("2020-03-18T02:28:20.559385848Z")
    assert date.strftime("%Y-%m-%d %H:%M:%S %z") == "2020-03-18 02:28:20 +0000"


def test_ticket_from_cookie() -> None:
    """Check parsing a ticket from an oauth2_proxy session cookie.

    These are signed with an HMAC, but the code doesn't check it (and this
    construct will eventually go away), so don't bother to test that part.
    """
    with pytest.raises(InvalidCookieException):
        Ticket.from_cookie("oauth2_proxy", "")
    with pytest.raises(InvalidTicketException):
        Ticket.from_cookie("oauth2_proxy", "|")

    # Test with a valid ticket but invalid cookie format.
    t = "oauth2_proxy-5d366761c03b18d658fe63c050c65b8e.99P8KBWtmvOS36lhcnNzNA"
    base64_t = base64.urlsafe_b64encode(t.encode()).decode()
    with pytest.raises(InvalidCookieException):
        Ticket.from_cookie("oauth2_proxy", base64_t)

    # Test a valid cookie containing an invalid ticket.
    bad_ticket = "oauth2_proxy-NOT.VALID"
    bad_ticket_base64 = base64.urlsafe_b64encode(bad_ticket.encode()).decode()
    bad_cookie = bad_ticket_base64 + "|2222|xxxxx"
    with pytest.raises(InvalidTicketException):
        Ticket.from_cookie("oauth2_proxy", bad_cookie)

    # Test a valid cookie and ticket.
    good_cookie = base64_t + "|1585002877|SOME-HMAC"
    ticket = Ticket.from_cookie("oauth2_proxy", good_cookie)
    assert ticket
    assert ticket.ticket_id == "5d366761c03b18d658fe63c050c65b8e"
    secret = base64.urlsafe_b64decode(add_padding("99P8KBWtmvOS36lhcnNzNA"))
    assert ticket.secret == secret


def test_ticket_from_str() -> None:
    bad_tickets = [
        "",
        ".",
        "5d366761c03b18d658fe63c050c65b8e",
        "5d366761c03b18d658fe63c050c65b8e.",
        ".99P8KBWtmvOS36lhcnNzNA",
        "oauth2_proxy-.",
        "oauth2_proxy-.99P8KBWtmvOS36lhcnNzNA",
        "oauth2_proxy-5d366761c03b18d658fe63c050c65b8e",
        "oauth2_proxy-5d366761c03b18d658fe63c050c65b8e.",
        "oauth2_proxy-NOT.VALID",
        "oauth2_proxy-5d366761c03b18d658fe63c050c65b8e.!!!!!",
        "ticket-5d366761c03b18d658fe63c050c65b8e.99P8KBWtmvOS36lhcnNzNA",
        "oauth2_proxy5d366761c03b18d658fe63c050c65b8e.99P8KBWtmvOS36lhcnNzNA",
    ]
    for ticket_str in bad_tickets:
        with pytest.raises(InvalidTicketException):
            Ticket.from_str("oauth2_proxy", ticket_str)

    s = "oauth2_proxy-5d366761c03b18d658fe63c050c65b8e.99P8KBWtmvOS36lhcnNzNA"
    ticket = Ticket.from_str("oauth2_proxy", s)
    assert ticket
    assert ticket.ticket_id == "5d366761c03b18d658fe63c050c65b8e"
    secret = base64.urlsafe_b64decode(add_padding("99P8KBWtmvOS36lhcnNzNA"))
    assert ticket.secret == secret
    assert ticket.as_handle("oauth2_proxy") == s.split(".")[0]
    assert ticket.encode("oauth2_proxy") == s
