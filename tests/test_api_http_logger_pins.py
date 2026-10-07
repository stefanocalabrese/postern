"""``services/api`` holds ``httpx2`` and ``httpcore2`` at WARNING.

``httpx2`` logs ``HTTP Request: GET <url> "HTTP/1.1 200 <reason phrase>"`` at INFO and
``httpcore2`` logs every response header at DEBUG, and the text is the operator's
backend's. Dormant at the default root level, live once an operator lowers it.
"""

from __future__ import annotations

import logging

from services.api.main import create_app
from services.api.settings import Settings


def test_create_app_pins_the_http_client_loggers_to_warning() -> None:
    for name in ("httpx2", "httpcore2"):
        logging.getLogger(name).setLevel(logging.NOTSET)

    create_app(Settings.for_testing())

    assert logging.getLogger("httpx2").level == logging.WARNING
    assert logging.getLogger("httpcore2").level == logging.WARNING


def test_the_pin_is_one_function_in_the_shared_library() -> None:
    """`services/api` and `services/confirm` call the same `postern_core` function."""
    from postern_core.log_safety import pin_http_client_loggers

    for name in ("httpx2", "httpcore2"):
        logging.getLogger(name).setLevel(logging.NOTSET)

    pin_http_client_loggers()

    assert logging.getLogger("httpx2").level == logging.WARNING
    assert logging.getLogger("httpcore2").level == logging.WARNING
