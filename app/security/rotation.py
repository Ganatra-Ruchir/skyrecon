"""
Master-key rotation.

Rotation is where encryption-at-rest quietly goes wrong. Rewrapping the fields
someone remembered is easy; the failure mode is the field nobody remembered,
which becomes permanently unreadable the moment the old key is retired — and
nothing complains until an analyst opens an alert from before the rotation.

So the set of things to rotate is declared here, in one place, and
``tests/test_rotation.py`` cross-checks that declaration against the actual
table definitions. A new ``*_sealed`` column that is not listed fails the suite.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from sqlmodel import Session, select

from app.models import Alert, AuditEntry, Event, Indicator, User
from app.models import Session as UserSession
from app.security.crypto import FieldContext, Vault


@dataclass(frozen=True)
class TablePlan:
    """Every encrypted surface of one table."""

    model: type
    table: str
    #: column name -> the FieldContext column label it was sealed under
    sealed: tuple[str, ...]
    #: index column -> (blind-index domain, how to recover the plaintext input)
    indexes: dict[str, tuple[str, Callable[[object, Vault], str | None]]] = field(
        default_factory=dict
    )


def _open(vault: Vault, sealed: str | None, table: str, column: str, rid: str) -> str | None:
    if not sealed:
        return None
    return vault.open(sealed, FieldContext(table, column, rid))


PLAN: tuple[TablePlan, ...] = (
    TablePlan(
        model=User, table="users",
        sealed=("email_sealed", "display_name_sealed", "mfa_secret_sealed"),
        indexes={
            "email_index": (
                "user-email",
                lambda row, v: _open(v, row.email_sealed, "users", "email", row.id),
            )
        },
    ),
    TablePlan(
        model=Indicator, table="indicators",
        sealed=("value_sealed", "notes_sealed"),
        indexes={
            "value_index": (
                "indicator",
                lambda row, v: _open(v, row.value_sealed, "indicators", "value", row.id),
            )
        },
    ),
    TablePlan(
        model=Event, table="events",
        sealed=("payload_sealed", "src_ip_sealed", "dst_ip_sealed"),
        indexes={
            "src_ip_index": (
                "ip",
                lambda row, v: _open(v, row.src_ip_sealed, "events", "src_ip", row.id),
            ),
            "dst_ip_index": (
                "ip",
                lambda row, v: _open(v, row.dst_ip_sealed, "events", "dst_ip", row.id),
            ),
        },
    ),
    TablePlan(
        model=Alert, table="alerts",
        sealed=("title_sealed", "detail_sealed", "resolution_note_sealed"),
        # The dedupe key is derived from the title, which we can still read.
        indexes={
            "dedupe_index": (
                "alert-dedupe",
                lambda row, v: "{}|{}|{}".format(
                    row.rule_id or "-",
                    row.indicator_id or "-",
                    (_open(v, row.title_sealed, "alerts", "title", row.id) or "")[:120],
                ),
            )
        },
    ),
    TablePlan(
        model=UserSession, table="sessions",
        sealed=("user_agent_sealed", "ip_sealed"),
    ),
    TablePlan(
        model=AuditEntry, table="audit_log",
        sealed=("detail_sealed",),
    ),
)

#: FieldContext column label for a stored column name — `value_sealed` was
#: sealed as column "value".
def context_column(column: str) -> str:
    return column.removesuffix("_sealed")


def count_fields(session: Session) -> dict[str, int]:
    """How much work a rotation would be, per table."""
    sizes = {}
    for plan in PLAN:
        rows = len(session.exec(select(plan.model)).all())
        sizes[plan.table] = rows * (len(plan.sealed) + len(plan.indexes))
    return sizes


def rotate(session: Session, old: Vault, new: Vault) -> int:
    """
    Rewrap every sealed field and rebuild every blind index.

    Caller commits. Anything that cannot be opened under the old key aborts the
    rotation rather than silently writing a value nobody can read again.
    """
    touched = 0
    for plan in PLAN:
        for row in session.exec(select(plan.model)).all():
            # Index inputs are recovered *before* the sealed columns move, since
            # most of them are recovered by opening one of those very columns.
            index_inputs = {
                column: recover(row, old)
                for column, (_, recover) in plan.indexes.items()
                if getattr(row, column, None) is not None
            }

            for column in plan.sealed:
                sealed = getattr(row, column)
                if not sealed:
                    continue
                ctx = FieldContext(plan.table, context_column(column), row.id)
                setattr(row, column, new.seal(old.open(sealed, ctx), ctx))
                touched += 1

            for column, plain in index_inputs.items():
                domain = plan.indexes[column][0]
                setattr(row, column, new.blind_index(plain, domain) if plain else None)
                touched += 1

            session.add(row)
    return touched
