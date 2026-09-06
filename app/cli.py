"""Operational commands: `python -m app.cli <command>`."""

from __future__ import annotations

import secrets
import sys

from sqlmodel import Session, select

from app.db import get_engine, init_db
from app.models import User
from app.security.crypto import generate_master_key


def genkeys() -> None:
    print("SKYRECON_MASTER_KEY=" + generate_master_key())
    print("SKYRECON_JWT_SECRET=" + secrets.token_urlsafe(48))
    print("\nStore these in a secret manager. Losing the master key makes every")
    print("encrypted field unrecoverable — there is no backdoor by design.")


def verify_audit() -> None:
    from app.audit import verify_chain

    init_db()
    with Session(get_engine()) as session:
        intact, bad = verify_chain(session)
    print("audit chain intact" if intact else f"AUDIT CHAIN BROKEN at seq {bad}")
    sys.exit(0 if intact else 2)


def list_users() -> None:
    from app.deps import user_out

    init_db()
    with Session(get_engine()) as session:
        for u in session.exec(select(User)).all():
            info = user_out(u)
            print(f"{info['role']:<8} {info['email']:<34} "
                  f"mfa={'on' if info['mfa_enabled'] else 'off':<3} "
                  f"active={info['is_active']}")


COMMANDS = {"genkeys": genkeys, "verify-audit": verify_audit, "list-users": list_users}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd not in COMMANDS:
        print("usage: python -m app.cli [" + " | ".join(COMMANDS) + "]")
        sys.exit(1)
    COMMANDS[cmd]()
