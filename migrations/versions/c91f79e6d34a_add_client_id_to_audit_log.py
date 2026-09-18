"""add client_id to audit_log

Revision ID: c91f79e6d34a
Revises: 9a7d4e51c6f8
Create Date: 2026-09-18 21:12:44.803117

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c91f79e6d34a"
down_revision: str | Sequence[str] | None = "9a7d4e51c6f8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Hardcoded, not imported from `postern_core.store.models`, exactly as
# 0eb813c87298, 3186c04c018c, 71a4c0d9e3b2 and 9a7d4e51c6f8 hardcode their
# own: this file records what the schema became on the date above, and
# importing a name a later task can redefine would silently change what an
# already-applied revision claims to have created.
_CLIENT_ID = "client_id"
_WIDTH = 512


def upgrade() -> None:
    """Upgrade schema.

    WHAT THE TABLE COULD NOT ANSWER. capo ruled on 2026-09-18 that
    `audit_log` records the customer data the operator TOUCHED rather than
    the calls it served, and 71a4c0d9e3b2 and 9a7d4e51c6f8 built the row
    shapes for that: which customer (`customer_ref`), what was asked for
    (`tool_name`, `arguments`), when the operator reached for it
    (`reaching_at`), and how the call ended. The party that did the asking
    was in none of them. An `audit_log` row could say that somebody's balance
    was read at 14:32 and could not say which OAuth client read it.

    That is not a reporting nicety under this repository's own design.
    CLAUDE.md's agent-to-server layer is OAuth 2.1 with CIMD, where anyone
    holding a metadata document can present themselves, and
    `docs/postern-design-handoff.md` answers that with per-client controls:
    "a known set, each with its own client ID, rate limits, and kill switch".
    Every one of those is a decision about a client id, and until this column
    the table a regulator reads held no client id to decide about.

    NULLABLE, and the absence it admits is a live path rather than a legacy
    one, which is what separates this column from `call_id`. `get_access
    _token()` returns None for every call arriving over the in-process
    `fastmcp.Client(transport=server)` transport -- the absence
    `models.py`'s `ABSENCE_NO_ACCESS_TOKEN` already names. A `NOT NULL`
    column would turn such a call into a failed INSERT, and under
    docs/decisions/0006-audit-write-failure.md a failed audit write takes the
    tool call with it, so the column would fail closed on a path that works
    as designed. NULL therefore carries two meanings on this table, told
    apart by a sibling column rather than by this one: on a row written since
    this revision it means "this call carried no access token", and that row
    also reads `customer_ref_absence_reason = 'no_access_token'`; on an older
    row it means the row predates the column.

    NO CHECK CONSTRAINT, which is the break from the four revisions before
    this one and is stated rather than left as an omission to be noticed. The
    biconditional those two sentences describe (`client_id IS NULL` =
    `customer_ref_absence_reason = 'no_access_token'`) is true of every row
    the application writes, because both values come from one
    `get_access_token()` read in `AuditMiddleware.on_call_tool`. It is a fact
    about one code path, not about the data: enforcing it would reject an
    honest row from any future writer whose token source yields no client id,
    and under the fail-closed policy that rejection costs the row and the
    call. `models.py`'s own comment on the column carries the same reasoning
    next to the constraints it declines to join.

    WIDTH, and the two costs it sits between, both measured on 2026-09-18
    against this repository's redaction code. A CIMD client id is a URL and
    nothing here bounds its length. Too narrow loses identity: the middleware
    clamps to this width and marks a clipped value with U+2026, but a URL's
    discriminating part is at its END, where `tool_name`'s and `request_id`'s
    are at the front, so a prefix clip costs more on this column than on
    either of those. Too wide spends the call's shared redaction allowance:
    `services/api/middleware/audit.py` scrubs this value in the same
    `redaction_budget()` scope as the tool name and the arguments, and the
    worst-case checksum cost measured on this repository's own adversarial
    shape (128-character maximum-density tokens) runs at 4.33 per character
    at every length from 256 to 16,384. At 512 that is 2,220 checksums, 2.22%
    of `_IBAN_SCAN_BUDGET`'s 100,000; unbounded, the same shape consumes the
    entire allowance at 23,100 characters (100,061 checksums), which would
    let an issuer-minted client id starve the scrubbing of the arguments
    stored beside it. 512 is also four times the 128 that `request_id` and
    `customer_ref` carry, and the headroom is what 1c64b7ed3f4b charged this
    repository for when it widened both `customer_ref` columns from 64 to 128
    because someone had matched a width to the then-current bound.

    Adding a nullable column with no default is catalog-only in PostgreSQL:
    no table rewrite, whatever the row count, and no scan, so unlike
    71a4c0d9e3b2 there is nothing here to plan a lock window around.

    MEASURED ON 2026-09-18 against a `postgres:17-alpine` container, and
    deliberately not against a clean database: the schema was taken to
    9a7d4e51c6f8 first, one `outcome='reaching'` row and one
    `outcome='returned'` row sharing a `call_id` were written under it in the
    pre-column shape, and this revision was applied over them. The
    `ALTER TABLE` itself timed at 0.572ms in psql; the whole
    `alembic upgrade head` took 0.21s wall, nearly all of it interpreter and
    Alembic startup. Both seeded rows came through untouched: still there,
    NULL in the new column, un-backfilled. `client_id` reads
    `character varying`, `character_maximum_length` 512, `is_nullable` YES,
    `column_default` NULL.

    The width was then checked at the database rather than assumed. A
    512-character value inserted and read back at `length()` 512; a
    513-character one was rejected, through psql with `value too long for
    type character varying(512)` and through asyncpg -- the driver this
    application uses -- as
    `asyncpg.exceptions.StringDataRightTruncationError`. That is the exact
    failure `_MAX_CLIENT_ID` and `_clamp` exist upstream of in
    `services/api/middleware/audit.py`, and under
    docs/decisions/0006-audit-write-failure.md it would cost the audit row
    and the tool call.

    The downgrade was then run: zero columns named `client_id` in
    `information_schema`, both seeded rows still present, `alembic_version`
    back to 9a7d4e51c6f8. The upgrade was run again and every reading above
    repeated identically, so the pair round trips.

    WHAT THE DRIFT GATE COVERS HERE, stated because 9a7d4e51c6f8's own note
    says the opposite for its constraint. `make migrations` (`alembic check`)
    DOES compare columns, their types and their nullability, and that was
    measured rather than assumed on the same database: narrowing the model to
    `String(256)` while leaving this file alone failed the check with
    "Detected type change from VARCHAR(length=512) to String(length=256) on
    'audit_log.client_id'". It still does not compare CHECK constraints,
    which is why that revision had to say so; this one adds none, so there is
    nothing here the gate is blind to.
    """
    op.add_column("audit_log", sa.Column(_CLIENT_ID, sa.String(length=_WIDTH), nullable=True))


def downgrade() -> None:
    """Downgrade schema.

    Drops the column, and with it the only record of which OAuth client made
    each call already recorded: `audit_log` is append-only and nothing else
    in this schema holds a copy, so those rows go back to naming the customer
    whose data was touched and not the party that asked for it.

    An application still running the newer code against a downgraded schema
    fails every audit write on the missing column, which under
    docs/decisions/0006-audit-write-failure.md fails the tool call -- on the
    entry write, before the backend is reached. That is the same shape
    71a4c0d9e3b2's and 9a7d4e51c6f8's downgrades leave, and it is the
    fail-closed direction: no customer data is touched without a row.
    """
    op.drop_column("audit_log", _CLIENT_ID)
