"""The one definition of a string this system cannot store or sign.

Two code points, one rule, used by every site that takes caller-supplied text:

* U+0000. PostgreSQL text and JSONB refuse it (`CharacterNotInRepertoireError`),
  so an audit row, or a `client_id` bound into one, that carries it fails the
  insert.
* A surrogate, U+D800 to U+DFFF. A JSON escape (`"\\ud800"`) decodes to a lone
  surrogate `str` and UTF-8 cannot encode one (`UnicodeEncodeError`), at the
  database driver, at a Redis key and at the JWT serialiser alike. A VALID
  pair (`"\\ud83d\\ude00"`) is decoded by the JSON parser into one supplementary
  code point and is not a surrogate any more, so it passes.

The edges are exact and tested: U+D7FF and U+E000, the code points either side
of the block, are ordinary and accepted.

Callers: `services/api/asgi/header_validation.py` (every string in a request
body, keys included, before auth) and `services/confirm/device_auth.py`
(`client_id`, `scopes` and the presented pairing code). Keep the pattern here
and nowhere else: `tests/test_unstorable_confirm_input.py` fails when a second
copy of the range appears in `packages/` or `services/`.
"""

import re

_UNSTORABLE_CHARACTER = re.compile("[\x00\ud800-\udfff]")


def contains_unstorable_character(value: str) -> bool:
    """True when `value` holds U+0000 or a surrogate code point."""
    return _UNSTORABLE_CHARACTER.search(value) is not None
