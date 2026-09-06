"""Role-based access control with explicit, auditable permissions."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    VIEWER = "viewer"      # read-only analyst
    ANALYST = "analyst"    # can triage, tag, resolve
    ADMIN = "admin"        # can manage users, keys, rules


class Permission(StrEnum):
    IOC_READ = "ioc:read"
    IOC_WRITE = "ioc:write"
    IOC_DELETE = "ioc:delete"
    EVENT_READ = "event:read"
    EVENT_INGEST = "event:ingest"
    ALERT_READ = "alert:read"
    ALERT_TRIAGE = "alert:triage"
    RULE_READ = "rule:read"
    RULE_WRITE = "rule:write"
    USER_MANAGE = "user:manage"
    AUDIT_READ = "audit:read"
    KEY_ROTATE = "key:rotate"


_GRANTS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({
        Permission.IOC_READ, Permission.EVENT_READ,
        Permission.ALERT_READ, Permission.RULE_READ,
    }),
    Role.ANALYST: frozenset({
        Permission.IOC_READ, Permission.IOC_WRITE,
        Permission.EVENT_READ, Permission.EVENT_INGEST,
        Permission.ALERT_READ, Permission.ALERT_TRIAGE,
        Permission.RULE_READ,
    }),
    Role.ADMIN: frozenset(Permission),  # every permission
}


def permissions_for(role: str | Role) -> frozenset[Permission]:
    try:
        return _GRANTS[Role(role)]
    except ValueError:
        return frozenset()


def can(role: str | Role, permission: Permission) -> bool:
    return permission in permissions_for(role)
