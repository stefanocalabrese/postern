"""The citation gate, pinned against the failure it was built for.

On 2026-09-17 `docs/decisions/0007-audit-refusal-and-absence-reasons.md`
carried 39 bare `file:line` citations and 28 pointed at something other than
what the prose said. The one this file reproduces is
`services/api/middleware/audit.py:725`: at commit cb39533 that line held a
comment fragment, while the `consent.refusal_for` call the sentence described
sat at 743, eighteen lines below. Every one of the 28 named a line that
EXISTS, so `test_the_defect_a_line_count_would_have_passed` asserts both
halves -- the cited line is in range, and the gate fails anyway.

This module is the one file `tools/check_citations.py` refuses to read
(`SELF_EXEMPT`), because the fixtures below are deliberately broken
citations and scanning them would turn the gate red on its own evidence.

The last test is the honest one: it pins what the gate CANNOT do. An anchor
that resolves says a name is in a file and says nothing about whether the
sentence around it is true.
"""

from pathlib import Path
from textwrap import dedent

from tools.check_citations import Report, check, load_baseline, write_baseline

# Where the anchor sits in the stand-in for services/api/middleware/audit.py,
# and where the comment fragment that was cited instead sits. The gap is the
# 18 lines that separated audit.py:725 from the call at 743 at cb39533.
FRAGMENT_LINE = 725
CALL_LINE = 743


def _audit_module() -> str:
    """A stand-in for the middleware: it CALLS `refusal_for`, never defines it.

    Padded so the anchor lands at `CALL_LINE` and a comment fragment lands at
    `FRAGMENT_LINE`, which is what makes the file long enough for a
    line-existence check to pass on the wrong line.
    """
    lines = ["from services.api import consent", ""]
    while len(lines) < FRAGMENT_LINE - 1:
        lines.append("# padding that stands in for the middleware's own prose")
    lines.append("# leaving NULL and making the row indistinguishable from a")
    while len(lines) < CALL_LINE - 2:
        lines.append("# more padding")
    lines.append("def on_call_tool(name: str) -> str | None:")
    lines.append("    return consent.refusal_for(name)")
    return "\n".join(lines) + "\n"


def _write(root: Path, files: dict[str, str]) -> None:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(body).lstrip("\n"), encoding="utf-8")


def _historical_tree(root: Path, citation: str) -> Report:
    """The cb39533 shape: `refusal_for` in consent.py, called from audit.py."""
    _write(
        root,
        {
            "services/api/consent.py": """
                def refusal_for(tool_name: str) -> str | None:
                    return None
                """,
            "services/api/middleware/audit.py": _audit_module(),
            "docs/decisions/0007.md": f"""
                `_refuse` files the decision on `request.state`, and {citation}
                reads it back with `consent.refusal_for` after `call_next` raises.
                """,
        },
    )
    return check(root, baseline={})


def test_the_defect_a_line_count_would_have_passed(tmp_path: Path) -> None:
    """The historical failure, re-expressed as an anchor, goes red.

    The two assertions before the gate runs are the point: line 725 is inside
    the file and holds a comment fragment, so "does this file have 725 lines"
    answers yes. The anchor is what disagrees.
    """
    report = _historical_tree(tmp_path, "`services/api/middleware/audit.py::refusal_for`")

    middleware = (tmp_path / "services/api/middleware/audit.py").read_text().splitlines()
    assert len(middleware) > FRAGMENT_LINE
    assert middleware[FRAGMENT_LINE - 1].startswith("# leaving NULL")
    assert "consent.refusal_for" in middleware[CALL_LINE - 1]

    assert len(report.problems) == 1
    problem = report.problems[0]
    assert problem.source == "docs/decisions/0007.md"
    assert "carries no `refusal_for`" in problem.message
    assert "found at services/api/consent.py::refusal_for" in problem.message


def test_the_anchor_that_does_resolve_survives_the_code_moving(tmp_path: Path) -> None:
    """Eighteen lines inserted above the anchor break no anchored citation.

    This is the whole argument for a symbol with no line beside it. The four
    citations cb39533 wrote were each exactly 18 lines short of their anchor;
    the same displacement here moves the call and changes nothing the gate
    reads.
    """
    citation = "`services/api/consent.py::refusal_for`"
    assert _historical_tree(tmp_path, citation).problems == []

    consent = tmp_path / "services/api/consent.py"
    consent.write_text("\n".join(["# inserted"] * 18) + "\n" + consent.read_text())

    moved = consent.read_text().splitlines()
    assert moved.index("def refusal_for(tool_name: str) -> str | None:") == 18
    assert check(tmp_path, baseline={}).problems == []


def test_a_bare_line_citation_is_counted_and_never_resolved(tmp_path: Path) -> None:
    """A bare `file:line` pointing at a line that does not exist still passes.

    Deliberate. Checking it would be the existence check the first test
    rejects, and the only thing that would catch this citation is a reader.
    """
    _write(tmp_path, {"docs/note.md": "see `services/api/consent.py:99999`\n"})
    report = check(tmp_path, baseline={"docs/note.md": 1})
    assert report.problems == []
    assert report.bare_by_file == {"docs/note.md": 1}


def test_one_more_bare_citation_than_the_baseline_fails(tmp_path: Path) -> None:
    """The ratchet: the 183 already here stay, a 184th does not land."""
    _write(
        tmp_path,
        {"docs/note.md": "`consent.py:12` and `audit.py:13`\n"},
    )
    report = check(tmp_path, baseline={"docs/note.md": 1})
    assert len(report.problems) == 1
    assert "2 bare file:line citations, baseline 1" in report.problems[0].message


def test_a_file_the_baseline_never_saw_may_carry_no_bare_citation(tmp_path: Path) -> None:
    """A new document starts at zero, so nothing arrives pre-grandfathered."""
    _write(tmp_path, {"docs/new.md": "`consent.py:12`\n"})
    report = check(tmp_path, baseline={"docs/other.md": 40})
    assert len(report.problems) == 1
    assert report.problems[0].source == "docs/new.md"


def test_removing_a_bare_citation_is_always_allowed(tmp_path: Path) -> None:
    """Conversion must never be blocked by the thing that blocks regression."""
    _write(tmp_path, {"docs/note.md": "`consent.py:12`\n"})
    assert check(tmp_path, baseline={"docs/note.md": 9}).problems == []


def test_a_wrapped_node_id_is_rejoined(tmp_path: Path) -> None:
    """Long node ids do not fit in 100 columns, so the tree breaks them mid-name.

    `services/api/middleware/audit.py` and five other files carry citations
    split across a comment line. Reading only the first half would report a
    symbol nobody wrote.
    """
    _write(
        tmp_path,
        {
            "tests/test_audit_entry_row.py": """
                def test_a_second_touch_after_a_failed_entry_write_fails_too() -> None:
                    pass
                """,
            "services/api/middleware/audit.py": """
                # A row that does not exist
                # (`tests/test_audit_entry_row.py::test_a_second_touch_after_a_failed
                # _entry_write_fails_too`). A write that commits and then raises
                """,
        },
    )
    report = check(tmp_path, baseline={})
    assert report.problems == []
    assert report.verified == 1


def test_a_method_is_found_by_its_bare_name(tmp_path: Path) -> None:
    """Three files cite `build_middleware_stack`, which is a method on a class."""
    _write(
        tmp_path,
        {
            "services/api/middleware/audit.py": """
                class AuditMiddleware:
                    async def on_call_tool(self) -> None:
                        pass
                """,
            "docs/note.md": "`services/api/middleware/audit.py`'s `on_call_tool` writes the row\n",
        },
    )
    assert check(tmp_path, baseline={}).problems == []


def test_the_anchor_decides_between_two_files_with_one_name(tmp_path: Path) -> None:
    """This tree holds two `models.py` and two `audit.py`; the symbol picks."""
    _write(
        tmp_path,
        {
            "packages/domain/models.py": "class Account:\n    pass\n",
            "packages/store/models.py": 'ABSENCE_NO_ACCESS_TOKEN = "no_access_token"\n',
            "docs/note.md": "the absence `models.py`'s `ABSENCE_NO_ACCESS_TOKEN` already names\n",
        },
    )
    assert check(tmp_path, baseline={}).problems == []


def test_a_short_path_no_candidate_carries_is_reported_with_both(tmp_path: Path) -> None:
    """When the anchor decides nothing, the reader is told what the choices were."""
    _write(
        tmp_path,
        {
            "packages/domain/models.py": "class Account:\n    pass\n",
            "packages/store/models.py": "class AuditEntry:\n    pass\n",
            "docs/note.md": "`models.py`'s `Consent` holds the grant\n",
        },
    )
    report = check(tmp_path, baseline={})
    assert len(report.problems) == 1
    assert "ambiguous and none of its 2 matches" in report.problems[0].message
    assert "packages/domain/models.py, packages/store/models.py" in report.problems[0].message


def test_a_path_that_resolves_nowhere_is_reported(tmp_path: Path) -> None:
    """A renamed or invented file is caught before anyone follows the citation."""
    _write(tmp_path, {"docs/note.md": "`services/api/gone.py::vanished` did the work\n"})
    report = check(tmp_path, baseline={})
    assert len(report.problems) == 1
    assert "does not resolve" in report.problems[0].message


def test_a_pytest_command_line_is_not_a_citation(tmp_path: Path) -> None:
    """`CLAUDE.md` documents running one test; `test_name` is a hole, not a claim.

    The exemption is held to command lines by the backtick. A sentence that
    quotes a node id is still a citation even when it also says "pytest", so
    the second document below goes red on a test that does not exist.
    """
    _write(
        tmp_path,
        {
            "tests/test_masking_golden.py": "def test_no_leak() -> None:\n    pass\n",
            "CLAUDE.md": "    uv run pytest tests/test_masking_golden.py::test_name\n",
        },
    )
    report = check(tmp_path, baseline={})
    assert report.problems == []
    assert report.verified == 0

    _write(
        tmp_path,
        {"docs/note.md": "pytest proves it in `tests/test_masking_golden.py::test_gone`\n"},
    )
    quoted = check(tmp_path, baseline={})
    assert len(quoted.problems) == 1
    assert "carries no `test_gone`" in quoted.problems[0].message


def test_the_baseline_round_trips_through_the_file(tmp_path: Path) -> None:
    """Generated, never hand-written: `make citations-baseline` owns this file."""
    path = tmp_path / "citations-baseline.json"
    write_baseline(path, {"docs/b.md": 2, "docs/a.md": 37})
    assert load_baseline(path) == {"docs/a.md": 37, "docs/b.md": 2}
    assert '"docs/a.md": 37' in path.read_text()


def test_prose_that_contradicts_a_resolving_anchor_passes(tmp_path: Path) -> None:
    """The limitation, pinned so nobody reads a green gate as "the docs are right".

    Both citations below resolve. Both sentences are false: `refusal_for`
    returns a reason rather than a bool, and it is consent.py that writes it,
    not the middleware. No static check can see that, which is why the tool's
    docstring says a green gate means the citations point somewhere real and
    nothing more.
    """
    _write(
        tmp_path,
        {
            "services/api/consent.py": """
                def refusal_for(tool_name: str) -> str | None:
                    return None
                """,
            "docs/note.md": """
                `services/api/consent.py::refusal_for` returns a bool, and
                `services/api/consent.py`'s `refusal_for` is written by the
                middleware rather than read by it.
                """,
        },
    )
    report = check(tmp_path, baseline={})
    assert report.problems == []
    assert report.verified == 2
