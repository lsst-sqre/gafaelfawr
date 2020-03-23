"""Tests for the jwt_authorizer.session package."""

from __future__ import annotations

import base64

import pytest

from jwt_authorizer.session import InvalidTicketException, SessionStore, Ticket
from jwt_authorizer.util import add_padding


def test_parse_session_date() -> None:
    """Check that we can parse the session dates written by oauth2_proxy."""
    date = SessionStore._parse_session_date("2020-03-18T02:28:20.559385848Z")
    assert date.strftime("%Y-%m-%d %H:%M:%S %z") == "2020-03-18 02:28:20 +0000"


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
