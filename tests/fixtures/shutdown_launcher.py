"""A launcher for `tests/test_shutdown_signals.py`: real uvicorn, main thread, real signals.

Run as ``python -m tests.fixtures.shutdown_launcher PORT GRACEFUL WAIT RECORD``.

WHY A SUBPROCESS. uvicorn's ``Server.serve`` wraps its serving in
``capture_signals()``, which on exit restores the original handlers and then
calls ``signal.raise_signal`` for every signal it captured. For SIGTERM the
original handler is the default one, so the process dies on that line, INSIDE
the coroutine, before ``asyncio.run`` gets to cancel what is left. That only
happens in the main thread of a process that received a real signal, which is
what ECS and ``docker stop`` do and what a ``Server.run()`` in a pytest thread
never does (``capture_signals`` installs nothing off the main thread).

What runs is the real ``services.confirm.main._lifespan``, the real
``callback._record_executed_detached`` and the real ``_record_and_report``. Only
two things are replaced: the recording itself (it sleeps ``RECORD`` seconds, the
stand-in for a database that is slow) and the startup clock check (no database
here), and the wait is set to ``WAIT`` seconds so a test need not sit 25 s.

``GRACEFUL`` is the ``--timeout-graceful-shutdown`` value, or ``none`` for the
shipped command's no-timeout behaviour.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from services.confirm import callback, main


async def _fake_record(db: object, challenge_id: str) -> bool:
    logging.getLogger("launcher").info("record started for %s", challenge_id)
    await asyncio.sleep(float(sys.argv[4]))
    return True


async def _no_clock_check(db: object) -> None:
    return None


async def _approve(request: Request) -> PlainTextResponse:
    ok = await callback._record_executed_detached(
        None,  # type: ignore[arg-type]
        "chal_launcher",
        "payments.create_payment",
    )
    return PlainTextResponse(f"recorded={ok}")


def build_app() -> Starlette:
    app = Starlette(routes=[Route("/a", _approve, methods=["POST"])], lifespan=main._lifespan)
    app.state.postern_database = None
    return app


def run() -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format=f"[pid {os.getpid()}] %(name)s %(levelname)s %(message)s",
    )
    port = int(sys.argv[1])
    graceful = None if sys.argv[2] == "none" else int(sys.argv[2])
    callback._record_executed = _fake_record
    callback.SHUTDOWN_RECORD_WAIT_SECONDS = float(sys.argv[3])
    main.run_database_clock_check = _no_clock_check  # type: ignore[attr-defined,assignment]
    config = uvicorn.Config(
        build_app(),
        host="127.0.0.1",
        port=port,
        timeout_graceful_shutdown=graceful,
        log_config=None,
    )
    uvicorn.Server(config).run()


if __name__ == "__main__":
    run()
