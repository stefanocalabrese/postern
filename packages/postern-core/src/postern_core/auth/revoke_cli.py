"""ZT-7 -- the operator's revocation surface.

WHY A CLI. The full argument lives in `postern_core.auth.revocation`'s module
docstring; the short form is that this repository has no admin identity to
authenticate, and an admin mutation endpoint on the internet-facing MCP
service, guarded by an authentication scheme invented for it, is a worse
trade than a command whose authorization is "can reach the configured Redis".

OPERATIONAL PROCEDURE. Run it from anywhere that already has
``POSTERN_REDIS_URL`` and network reach to that Redis -- a bastion, an ECS
exec session into a running task, a maintenance task definition. It is the
same store every `services/api` replica reads, so an entry written here
applies to all of them on their next call, with no deploy and no restart::

    POSTERN_REDIS_URL=rediss://... uv run python tools/revoke.py list
    POSTERN_REDIS_URL=rediss://... uv run python tools/revoke.py kill-switch vendor-claude
    POSTERN_REDIS_URL=rediss://... uv run python tools/revoke.py \\
        customer-client cust_7f3a vendor-claude
    POSTERN_REDIS_URL=rediss://... uv run python tools/revoke.py session tok-9f2a
    POSTERN_REDIS_URL=rediss://... uv run python tools/revoke.py prune-sessions [--limit N]

``prune-sessions`` removes revoked session ``jti`` values whose access token
has expired (one batch of at most ``--limit``, default 1000) and prints the
count removed, then how many revoked sessions have no expiry index and are
therefore never pruned (at least that many; members written by a plain
``SADD`` rather than by ``session``). Every ``session`` revoke also prunes one batch itself.

WITHOUT ``POSTERN_REDIS_URL`` THIS COMMAND DOES NOTHING USEFUL.
`create_revocation_store` falls back to an in-process store, so the entry is
written into the CLI's own memory and discarded when it exits. The command
says so on stderr rather than reporting success, because a revocation an
operator believes in and that never reached a replica is the worst available
outcome.

WHAT A REVOCATION STOPS. Every `services/api` tool call and every
``tools/list`` for that identity, refused before the operator's backend is
touched. The WRITE path -- ``POST /challenges/{challenge_id}/approve`` and
the RFC 8628 device-grant exchange -- is covered too, but by one scope only:

**TO STOP THE WRITE PATH, NAME THE CUSTOMER.** ``customer-client`` is the
command that stops a payment approval. It cuts that customer's approvals
through EVERY client, not only the one named, because the write path cannot
tell the clients apart.

``session`` does NOT stop a payment approval. The ``jti`` you name is the AI
client's access token, and the write path is called by the banking app
holding an assertion from a different issuer, which carries no such value.

``session`` entries are pruned 930 s after they are written, which is safe
only because POSTERN_JWKS_URI names confirm's ``/session/jwks.json`` and
confirm's tokens live 600 s. A ``jti`` of a longer-lived foreign token would
be pruned while that token could still verify.

``kill-switch`` does NOT stop a payment approval either. The ``challenges``
row does not record which vendor created it, so enforcing a kill switch there
would refuse every customer's approvals rather than that client's. It does
stop, while it stands, the device-grant exchange and the refresh of any
session declaring that ``client_id`` (since 3 October 2026 for the exchange).
A client that declares a different ``client_id`` is not stopped by it.

WHAT A RESTORE BRINGS BACK. ``restore-customer-client`` and
``restore-kill-switch`` let the identity back in for what is issued AFTER the
revocation; an access token or refresh family that existed at it stays
refused (the stamps in `postern_core.auth.revocation`). ``restore-session``
serves the one named access token again and nothing else.

So an operator cutting a compromised session runs ``session`` AND
``customer-client``: the first stops the reads, the second stops the money.
`postern_core.auth.revocation` carries the full argument and what would close
the gap.

WHICH ``jti``. The one in the CUSTOMER's access token, which is what
`services/api/middleware/revocation.py`'s `RevocationMiddleware` reads.
``audit_log`` records the client id per call; the jti of a live session comes
from the operator's own token issuer, not from this repository.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from typing import TextIO

from postern_core.auth.revocation import (
    SESSION_PRUNE_BATCH,
    RevocationStoreBase,
    RevocationStoreUnavailable,
    create_revocation_store,
)
from postern_core.config import redis_url_from_env

_NO_REDIS_WARNING = (
    "POSTERN_REDIS_URL is not set, so this wrote to an in-process store that "
    "no running replica can see and that is gone now. Set POSTERN_REDIS_URL "
    "to the same Redis the services use and run this again."
)


def _positive_int(raw: str) -> int:
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revoke",
        description="ZT-7 revocation: cut agent sessions without a deploy.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    session = sub.add_parser(
        "session",
        help=(
            "revoke one session by the access token's jti (pruned 930 s later; "
            "supported only for tokens confirm issued)"
        ),
    )
    session.add_argument("jti")

    pair = sub.add_parser(
        "customer-client",
        help="revoke every session of one customer through one OAuth client",
    )
    pair.add_argument("customer_ref")
    pair.add_argument("client_id")

    kill = sub.add_parser(
        "kill-switch",
        help="revoke every session from one OAuth client, across all customers",
    )
    kill.add_argument("client_id")

    restore_session = sub.add_parser(
        "restore-session",
        help=(
            "undo `session`: serves that one access token again for the rest of its "
            "600 s; a family revoked by reuse, recall or issued_before_revocation "
            "stays revoked, and if the family is presented again, its live jtis "
            "are listed again"
        ),
    )
    restore_session.add_argument("jti")

    restore_pair = sub.add_parser("restore-customer-client", help="undo `customer-client`")
    restore_pair.add_argument("customer_ref")
    restore_pair.add_argument("client_id")

    restore_kill = sub.add_parser(
        "restore-kill-switch",
        help=(
            "undo `kill-switch` for what is issued after it: access tokens and "
            "refresh families that existed at the kill stay refused (the families "
            "are revoked at their next refresh)"
        ),
    )
    restore_kill.add_argument("client_id")

    prune = sub.add_parser(
        "prune-sessions",
        help="remove revoked session jtis whose token has expired; print how many",
    )
    prune.add_argument(
        "--limit",
        type=_positive_int,
        default=SESSION_PRUNE_BATCH,
        help=f"most entries to remove in this run (default {SESSION_PRUNE_BATCH})",
    )

    sub.add_parser("list", help="print every entry currently revoked")
    return parser


async def _run(
    args: argparse.Namespace,
    store: RevocationStoreBase,
    out: TextIO,
    err: TextIO | None = None,
) -> int:
    if args.command == "prune-sessions":
        try:
            removed = await store.prune_sessions(limit=args.limit)
            unindexed = await store.unindexed_session_count()
        except RevocationStoreUnavailable as exc:
            print(f"prune-sessions failed: {exc}", file=err or sys.stderr)
            return 1
        print(f"pruned {removed} expired session entries", file=out)
        print(
            f"at least {unindexed} revoked sessions without an expiry index (never pruned)",
            file=out,
        )
        return 0
    if args.command == "session":
        await store.revoke_session(jti=args.jti)
        print(f"revoked session {args.jti}", file=out)
    elif args.command == "restore-session":
        await store.restore_session(jti=args.jti)
        print(f"restored session {args.jti}", file=out)
    elif args.command == "customer-client":
        await store.revoke_customer_client(customer_ref=args.customer_ref, client_id=args.client_id)
        print(f"revoked {args.customer_ref} for client {args.client_id}", file=out)
    elif args.command == "restore-customer-client":
        await store.restore_customer_client(
            customer_ref=args.customer_ref, client_id=args.client_id
        )
        print(f"restored {args.customer_ref} for client {args.client_id}", file=out)
    elif args.command == "kill-switch":
        await store.kill_switch(client_id=args.client_id)
        print(f"killed client {args.client_id} for every customer", file=out)
    elif args.command == "restore-kill-switch":
        await store.restore_client(client_id=args.client_id)
        print(f"restored client {args.client_id}", file=out)
    elif args.command == "list":
        snapshot = await store.entries()
        for jti in snapshot.sessions:
            print(f"session\t{jti}", file=out)
        for customer_ref, client_id in snapshot.customer_clients:
            print(f"customer-client\t{customer_ref}\t{client_id}", file=out)
        for client_id in snapshot.clients:
            print(f"kill-switch\t{client_id}", file=out)
        print(f"{snapshot.total} entries", file=out)
    else:  # pragma: no cover - argparse rejects anything else before this
        raise AssertionError(f"unhandled command {args.command!r}")
    return 0


async def _main_async(
    args: argparse.Namespace, store: RevocationStoreBase | None, out: TextIO, err: TextIO
) -> int:
    """One event loop for the command AND the close.

    Two `asyncio.run` calls would build the Redis client's connection pool on
    one loop and close it on another, which is how an async Redis client ends
    up raising about a loop it is not attached to. `create_revocation_store`
    itself is safe to call from anywhere -- `redis.from_url` builds the pool
    lazily, which is the same reason `services/api/main.py`'s `create_app`
    can construct one outside a request.
    """
    owned = store is None
    store = store or create_revocation_store()
    try:
        return await _run(args, store, out, err)
    finally:
        if owned:
            await store.close()


def main(
    argv: Sequence[str] | None = None,
    *,
    store: RevocationStoreBase | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Parse ``argv`` and apply one revocation command. Returns an exit code.

    ``store`` exists so a caller that already holds one can pass it; with
    nothing passed this calls `create_revocation_store`, which is the same
    call `services/api/main.py`'s `create_app` makes, so the CLI and the
    replicas cannot end up pointed at different stores by construction.

    Exit code 1 with no ``POSTERN_REDIS_URL`` even though the command itself
    succeeded: it succeeded into memory that no replica shares and that this
    process is about to discard, and an operator acting on a compromise needs
    that to be a failure rather than a line of reassuring output.
    """
    out = out or sys.stdout
    err = err or sys.stderr
    args = _parser().parse_args(argv)
    owned = store is None
    code = asyncio.run(_main_async(args, store, out, err))
    if owned and not redis_url_from_env():
        print(_NO_REDIS_WARNING, file=err)
        return 1
    return code
