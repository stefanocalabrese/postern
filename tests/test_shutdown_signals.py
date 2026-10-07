"""The lost-recording line under REAL signals, in a real process, uvicorn in the main thread.

`tests/test_executed_recording.py` drives ``uvicorn.Server.run()`` in a thread.
There ``capture_signals`` installs no handlers and re-raises nothing, so those
tests exercise a shutdown production never performs. Under SIGTERM, which is
what ECS and ``docker stop`` send, uvicorn restores the default handler after
its shutdown and calls ``signal.raise_signal(SIGTERM)`` inside the coroutine:
the process dies (exit 143) before ``asyncio.run`` cancels what is left, so a
task's own ``CancelledError`` handler never runs. Measured on uvicorn 0.52.4
before the fix: the request-side line promised a follow-up and none came.

The fix cancels and awaits the leftovers inside the lifespan, which runs before
that re-raise. These tests start `tests/fixtures/shutdown_launcher.py` (the real
lifespan and the real recording task, a sleeping stand-in for the database
work) as a child process and read its stderr. Each is bounded; only the child
this file started is ever killed.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOST = "was cancelled before it finished"
SHUTDOWN_COMPLETE = "Application shutdown complete"
DEADLINE = 15.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for(log: Path, needle: str, seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if needle in log.read_text():
            return
        time.sleep(0.05)
    raise AssertionError(f"{needle!r} never appeared; log:\n{log.read_text()}")


def _run(
    tmp_path: Path, *, graceful: str, wait: float, signals: list[int], gap: float = 0.3
) -> tuple[int, str]:
    """Start the launcher, hold one recording open, send ``signals``, return (exit code, stderr)."""
    log = tmp_path / "stderr.log"
    port = _free_port()
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    with log.open("w") as sink:
        child = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "tests.fixtures.shutdown_launcher",
                str(port),
                graceful,
                str(wait),
                "60",
            ],
            cwd=REPO_ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=sink,
        )
    client: socket.socket | None = None
    try:
        # Logged after the socket is bound ("startup complete" comes before it).
        _wait_for(log, "Uvicorn running on", DEADLINE)
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.sendall(b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        _wait_for(log, "record started", DEADLINE)
        for sig in signals:
            child.send_signal(sig)
            time.sleep(gap)
        try:
            code = child.wait(timeout=DEADLINE)
        except subprocess.TimeoutExpired:
            raise AssertionError(f"the child did not exit; log:\n{log.read_text()}") from None
        return code, log.read_text()
    finally:
        if client is not None:
            client.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_sigterm_writes_the_lost_line_before_uvicorn_re_raises_the_signal(tmp_path: Path) -> None:
    """What ECS sends. Wait 1 s, record 60 s: the line must exist, and before shutdown completes."""
    code, out = _run(tmp_path, graceful="1", wait=1.0, signals=[signal.SIGTERM])

    assert code == -signal.SIGTERM or code == 128 + signal.SIGTERM, (code, out)
    assert out.count(LOST) == 1, out
    assert "'chal_launcher'" in out and "payments.create_payment" in out
    assert out.index(LOST) < out.index(SHUTDOWN_COMPLETE), out
    # The request-side line promised a follow-up; this is it.
    assert out.index("the request was cancelled while recording it") < out.index(LOST)


def test_sigint_writes_the_lost_line_before_shutdown_completes(tmp_path: Path) -> None:
    _, out = _run(tmp_path, graceful="1", wait=1.0, signals=[signal.SIGINT])

    assert out.count(LOST) == 1, out
    assert out.index(LOST) < out.index(SHUTDOWN_COMPLETE), out


def test_a_second_sigint_forces_the_exit_and_the_lost_line_is_still_written(
    tmp_path: Path,
) -> None:
    """Forced exit: uvicorn skips the lifespan shutdown, so nothing waits and the loop cancels."""
    _, out = _run(tmp_path, graceful="none", wait=15.0, signals=[signal.SIGINT, signal.SIGINT])

    assert out.count(LOST) == 1, out
    assert SHUTDOWN_COMPLETE not in out.split(LOST)[0], out
