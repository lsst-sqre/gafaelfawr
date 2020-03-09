"""Tests for the jwt_authorizer.tokens package."""

from __future__ import annotations

import base64

from jwt_authorizer.tokens import add_padding, parse_ticket


def test_add_padding() -> None:
    assert add_padding("") == ""
    assert add_padding("Zg") == "Zg=="
    assert add_padding("Zgo") == "Zgo="
    assert add_padding("Zm8K") == "Zm8K"
    assert add_padding("Zm9vCg") == "Zm9vCg=="


def test_parse_ticket() -> None:
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
        assert not parse_ticket("oauth2_proxy", ticket_str)

    s = "oauth2_proxy-5d366761c03b18d658fe63c050c65b8e.99P8KBWtmvOS36lhcnNzNA"
    ticket = parse_ticket("oauth2_proxy", s)
    assert ticket
    assert ticket.ticket_id == "5d366761c03b18d658fe63c050c65b8e"
    secret = base64.urlsafe_b64decode(add_padding("99P8KBWtmvOS36lhcnNzNA"))
    assert ticket.secret == secret
    assert ticket.as_handle("oauth2_proxy") == s.split(".")[0]
    assert ticket.encode("oauth2_proxy") == s
