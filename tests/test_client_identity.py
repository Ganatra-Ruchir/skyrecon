from starlette.requests import Request

from app.deps import client_identity


def test_forwarding_header_cannot_choose_rate_limit_identity():
    request = Request({
        "type": "http",
        "client": ("203.0.113.10", 1234),
        "headers": [(b"x-forwarded-for", b"attacker-chosen")],
    })
    assert client_identity(request) == "203.0.113.10"
    other = Request({"type": "http", "client": ("203.0.113.11", 1234), "headers": []})
    assert client_identity(other) == "203.0.113.11"


def test_missing_peer_uses_shared_unknown_identity():
    request = Request({"type": "http", "headers": [(b"x-forwarded-for", b"chosen")]})
    assert client_identity(request) == "?"
