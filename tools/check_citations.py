#!/usr/bin/env python3
"""Check that every anchored source citation still points at the symbol it names.

Run by `make citations`, which `make ci` runs between `lock` and `test`.
Regenerate the ratchet baseline with `make citations-baseline`.

WHY AN ANCHOR, AND NOT A LINE NUMBER

On 2026-09-17 `dev-docs/decisions/0007-audit-refusal-and-absence-reasons.md`
carried 39 bare `file:line` citations; 28 of them no longer pointed at what
the prose said was there. Nine were wrong the day they were written, by a
commit whose stated purpose was correcting citations, and four of those were
each exactly 18 lines short of their anchor -- the residue of applying a
delta to printed numbers instead of re-deriving against the file.

The defect that matters is that every one of those 28 pointed at a line that
EXISTS. Line 725 of `services/api/middleware/audit.py` was a real line of a
real file; at commit cb39533 it held the comment fragment `# leaving NULL
and making the row indistinguishable from a`, while the `consent.refusal_for`
call the sentence described sat 18 lines below it at 743. A checker that
asks "does this file have at least 725 lines" passes all 28. So this tool
never asks that question, and counting is the only thing it does with a bare
`file:line`.

A citation is mechanically checkable only when it carries the NAME of the
thing it points at. Two forms already in this tree carry one, both naming a
symbol and no line, so both survive the code moving:

    tests/conftest.py::pg_url                             pytest node-id form
    `services/api/server.py`'s `token_customer_resolver`  possessive form

Neither is new notation. On the day this tool landed the tree held 61 node
ids and 57 possessives, and it verifies 117 of those 118 -- the one it
passes over is a pytest command line in `CLAUDE.md` whose test name is a
metavariable. Neither form is paired with a line number and neither ever
should be: a symbol beside a line reintroduces exactly the number that went
stale 28 times, and the anchor would resolve while the line beside it lied.
Moving a function changes no anchored citation anywhere in the tree.

WHAT THIS CATCHES

- An anchored citation whose target file carries no such name, including the
  historical case above re-expressed as an anchor: prose naming
  `refusal_for` against the middleware, when `services/api/consent.py` is
  where it lives. The report says where the name actually is.
- An anchored citation to a symbol that was deleted outright. That is how
  `dev-docs/decisions/0004-base-images.md` was found still citing
  `_refuse_stub_minter_in_production`, which `d203606` removed on
  2026-09-17, on the first run of this tool.
- An anchored citation whose path resolves nowhere, in the repo or in the
  installed site-packages.
- A short path, e.g. a bare `audit.py` where the tree holds two, when no
  candidate carries the name. The anchor picks between them when one does.
- A NEW bare `file:line` citation, by ratchet: `tools/citations-baseline.json`
  records how many each file carries, and any file carrying more than its
  baseline fails. Converting citations is always allowed; adding an
  uncheckable one is not. The gate never fails when a file carries fewer
  bare citations than its baseline (a "LOOSE" baseline), because that
  means citations were converted to anchored form, which is the desired
  direction. A loose baseline is a signal that cleanup happened, not a
  regression.

WHAT THIS PROVABLY CANNOT CATCH

- SEMANTICS. An anchor that resolves says the symbol is in that file. It
  says nothing about whether the sentence around it describes the symbol
  correctly. A file converted to symbol-only citations on 2026-09-18 had all
  42 resolve while two cross-references still claimed something their
  referent does not say. A green gate here means the citations point
  somewhere real, NOT that the prose is true.
- The 183 bare `file:line` citations already in the tree. They are counted,
  never checked, and no existence check would have caught any of the 28.
- Claims that look like citations but name no location: "two import-linter
  contracts", "nine migrations", "945 tests". Nothing here reads a count.
- Anchors into anything that is not Python. `<path>.py::<name>` is a
  citation; `<path>.md::<name>` is ignored.
- The difference between a definition and an import. A file that imports a
  name counts as carrying it, because the tree cites call sites that way --
  `migrations/env.py`'s `fileConfig`, `services/api/server.py`'s
  `JWTVerifier`. So a citation can point at a file that only re-exports.
- The difference between a symbol and a value with the same shape. The
  possessive form is prose, so a sentence naming an `outcome` column value
  in backticks after a file name reads as a citation and gets reported.
  `services/api/consent.py` had one; the fix was to name the constant,
  `OUTCOME_RETURNED`, which is both checkable and more precise. Expect this
  on any word that looks like an identifier but names a value.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
import sysconfig
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "tools" / "citations-baseline.json"

# Directories never walked. Everything `.gitignore` lists, plus `.git` and
# `.claude`: in the primary checkout `.claude/worktrees/` holds entire copies
# of this repository, and walking those would scan every file twice or more.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".claude",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".import_linter_cache",
        "dist",
        "build",
        "node_modules",
    }
)

SKIP_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".lock", ".pyc"})

# Two files this tool must not read, both its own machinery. The test module
# builds deliberately broken citations as fixture strings, and scanning them
# would make the gate fail on its own evidence; the baseline is generated.
# Their own citations are therefore unchecked, which is the price.
SELF_EXEMPT = frozenset({"tools/citations-baseline.json", "tests/test_citation_gate.py"})

MAX_BYTES = 1_000_000

# `<path>.py::<symbol>`, the pytest node-id form.
NODE_ID_RE = re.compile(
    r"(?P<path>[A-Za-z0-9_][A-Za-z0-9_./-]*\.py)::(?P<symbol>[A-Za-z_][A-Za-z0-9_.]*)"
)

# The possessive prose form: a backticked `<path>.py`, then `'s`, then a
# backticked `<symbol>`. The `\s*` and the optional comment marker let the
# citation wrap across a line, which it does inside block comments.
POSSESSIVE_RE = re.compile(
    r"`(?P<path>[A-Za-z0-9_][A-Za-z0-9_./-]*\.py)`'s\s*(?:#+[ \t]*)?"
    r"`(?P<symbol>[A-Za-z_][A-Za-z0-9_.]*)`"
)

# A bare `file:line` or `file:line-line`. Counted, never checked.
BARE_RE = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:py|md|toml|yml|yaml|ini|cfg|mako):\d+(?:-\d+)?"
)

# The leading identifier fragment of a wrapped citation's continuation line.
CONTINUATION_RE = re.compile(r"^[ \t]*(?:[#*]+[ \t]*)?(?P<fragment>[A-Za-z0-9_]+)")


@dataclass(frozen=True)
class Citation:
    """One anchored citation: where it was written, and what it claims."""

    source: str
    line: int
    path: str
    symbols: tuple[str, ...]  # candidates, most specific first; >1 only when wrapped
    form: str  # "node-id" or "possessive"

    @property
    def symbol(self) -> str:
        return self.symbols[-1]


@dataclass(frozen=True)
class Problem:
    source: str
    line: int
    message: str

    def render(self) -> str:
        return f"{self.source}:{self.line}: {self.message}"


@dataclass
class Report:
    problems: list[Problem] = field(default_factory=list)
    verified: int = 0
    external: int = 0
    by_form: dict[str, int] = field(default_factory=dict)
    bare_by_file: dict[str, int] = field(default_factory=dict)

    @property
    def bare_total(self) -> int:
        return sum(self.bare_by_file.values())

    def resolved(self, citation: Citation, external: bool) -> None:
        if external:
            self.external += 1
        else:
            self.verified += 1
        self.by_form[citation.form] = self.by_form.get(citation.form, 0) + 1


def iter_source_files(root: Path) -> Iterator[Path]:
    """Yield every readable text file under `root`, skipping caches and binaries.

    `SKIP_DIRS` is pruned from `dirnames` rather than filtered afterwards:
    `.venv` alone holds about 21,000 files, and walking into it cost 0.33s of
    the 0.52s this gate first took.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            if path.suffix in SKIP_SUFFIXES:
                continue
            if path.relative_to(root).as_posix() in SELF_EXEMPT:
                continue
            if path.stat().st_size > MAX_BYTES:
                continue
            yield path


def _continuation(text: str, end: int) -> str | None:
    """The identifier fragment continuing a citation broken at `end`, if any.

    A long node id does not fit in 100 columns, so the tree wraps it mid-name
    across a comment line: `...::test_a_second_touch_after_a_failed` then
    `_entry_write_fails_too`. The joined candidate is tried first and the
    unjoined one second, so a citation that merely happens to end a line is
    never mangled by the word that follows it.
    """
    if end < len(text) and text[end] != "\n":
        return None
    start = end + 1
    if start >= len(text):
        return None
    stop = text.find("\n", start)
    next_line = text[start:] if stop == -1 else text[start:stop]
    match = CONTINUATION_RE.match(next_line)
    return match.group("fragment") if match else None


def _is_command(text: str, start: int) -> bool:
    """True when the node id is an argument to pytest, not a citation.

    `CLAUDE.md` documents `uv run pytest tests/test_masking_golden.py::test_name`
    as how to run one test, where `test_name` is a metavariable standing for
    whichever test you want. It is a runnable command with a hole in it, and
    reading it as a citation would flag a line that is not wrong.

    The backtick is the second half of the test, and it is what keeps this
    narrow: a citation in prose or in a comment is quoted, an argument on a
    command line is not. A sentence about pytest that cites a node id keeps
    its backticks and stays checked.
    """
    if start > 0 and text[start - 1] == "`":
        return False
    line_start = text.rfind("\n", 0, start) + 1
    return "pytest" in text[line_start:start]


def find_citations(text: str, source: str) -> list[Citation]:
    """Every anchored citation in `text`, in both accepted forms."""
    found: list[Citation] = []
    for form, pattern in (("node-id", NODE_ID_RE), ("possessive", POSSESSIVE_RE)):
        for match in pattern.finditer(text):
            if form == "node-id" and _is_command(text, match.start()):
                continue
            symbol = match.group("symbol")
            symbols = [symbol]
            fragment = _continuation(text, match.end())
            if fragment is not None:
                symbols.insert(0, symbol + fragment)
            found.append(
                Citation(
                    source=source,
                    line=text.count("\n", 0, match.start()) + 1,
                    path=match.group("path"),
                    symbols=tuple(symbols),
                    form=form,
                )
            )
    return sorted(found, key=lambda c: (c.line, c.path))


def _target_names(node: ast.expr) -> Iterator[str]:
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, ast.Tuple | ast.List):
        for element in node.elts:
            yield from _target_names(element)


@cache
def bound_names(path: Path) -> frozenset[str]:
    """Every name `path` binds, dotted for class and function nesting.

    Imports count. `dev-docs/decisions/0006-audit-write-failure.md` writes
    "`migrations/env.py`'s `fileConfig` call", and that file imports the name
    from `logging.config` rather than defining it -- the citation is about
    the call site, which is genuinely there. The cost of counting them is
    stated in this module's docstring: the gate cannot tell a definition from
    a re-export.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
        return frozenset()
    found: set[str] = set()

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                qualified = prefix + child.name
                found.add(qualified)
                walk(child, qualified + ".")
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    found.update(prefix + name for name in _target_names(target))
            elif isinstance(child, ast.AnnAssign):
                found.update(prefix + name for name in _target_names(child.target))
            elif isinstance(child, ast.Import | ast.ImportFrom):
                for alias in child.names:
                    found.add(prefix + (alias.asname or alias.name.split(".")[0]))
            elif isinstance(
                child,
                ast.If | ast.Try | ast.With | ast.AsyncWith | ast.For | ast.AsyncFor | ast.While,
            ):
                walk(child, prefix)

    walk(tree, "")
    return frozenset(found)


def binds(path: Path, symbol: str) -> bool:
    """Whether `path` carries `symbol`, with or without its enclosing scope.

    A bare method name matches its class: three files in this tree cite
    `starlette/applications.py`'s `build_middleware_stack`, which is
    `Starlette.build_middleware_stack`, and the same holds for the nested
    `consent_for.check` and `AuditMiddleware.on_call_tool`.
    """
    names = bound_names(path)
    if symbol in names:
        return True
    suffix = "." + symbol
    return any(name.endswith(suffix) for name in names)


@cache
def _repo_python_files(root: Path) -> tuple[Path, ...]:
    return tuple(p for p in iter_source_files(root) if p.suffix == ".py")


def resolve_path(root: Path, cited: str) -> tuple[tuple[Path, ...], bool]:
    """Every file a cited path could mean, and whether it left the repo.

    Order: exact repo path, then repo path suffix (the tree writes
    `facade/accounts.py` and `models.py` for files it has already named in
    full nearby), then exact path under the running interpreter's
    site-packages, which is what pins a citation into fastmcp or starlette to
    the version `uv.lock` installs. A suffix can match more than one file --
    this tree holds two `audit.py` and two `models.py` -- and the anchor is
    what decides between them.
    """
    exact = root / cited
    if exact.is_file():
        return (exact,), False
    needle = "/" + cited
    matches = tuple(
        p for p in _repo_python_files(root) if p.relative_to(root).as_posix().endswith(needle)
    )
    if matches:
        return matches, False
    external = Path(sysconfig.get_paths()["purelib"]) / cited
    if external.is_file():
        return (external,), True
    return (), False


def _elsewhere(root: Path, symbol: str) -> str | None:
    """Where the repo actually carries `symbol`, when exactly one file does."""
    hits = [p for p in _repo_python_files(root) if binds(p, symbol)]
    if len(hits) == 1:
        return f"{hits[0].relative_to(root).as_posix()}::{symbol}"
    if len(hits) > 1:
        return f"{len(hits)} files carry it"
    return None


def check_citation(root: Path, citation: Citation, report: Report) -> None:
    candidates, external = resolve_path(root, citation.path)
    if not candidates:
        report.problems.append(
            Problem(
                citation.source,
                citation.line,
                f"`{citation.path}` does not resolve, in this repo or in site-packages",
            )
        )
        return
    for target in candidates:
        if any(binds(target, symbol) for symbol in citation.symbols):
            report.resolved(citation, external)
            return
    if len(candidates) > 1:
        shown = ", ".join(sorted(c.relative_to(root).as_posix() for c in candidates))
        message = (
            f"`{citation.path}` is ambiguous and none of its {len(candidates)} "
            f"matches ({shown}) carries `{citation.symbol}`"
        )
    else:
        named = citation.path if external else candidates[0].relative_to(root).as_posix()
        message = f"`{named}` carries no `{citation.symbol}`"
    where = _elsewhere(root, citation.symbol)
    if where is not None:
        message += f"; found at {where}"
    report.problems.append(Problem(citation.source, citation.line, message))


def load_baseline(path: Path) -> dict[str, int]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    counts: dict[str, int] = data["bare_citations_by_file"]
    return counts


def write_baseline(path: Path, counts: dict[str, int]) -> None:
    payload = {
        "generated_by": "make citations-baseline",
        "what": (
            "Bare file:line citations per file. They are counted, never checked. "
            "The gate fails when a file carries more than its number here, so a "
            "new citation has to be anchored. Lowering a number is free; raising "
            "one is a decision a reviewer should see in the diff."
        ),
        "bare_citations_by_file": dict(sorted(counts.items())),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def check(root: Path, baseline: dict[str, int]) -> Report:
    # Both caches key on a path, so a second `check` in the same process -- which
    # is every test after the first -- would otherwise read a file's symbols from
    # before the test edited it.
    bound_names.cache_clear()
    _repo_python_files.cache_clear()
    report = Report()
    for path in iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        source = path.relative_to(root).as_posix()
        for citation in find_citations(text, source):
            check_citation(root, citation, report)
        bare = len(BARE_RE.findall(text))
        if bare:
            report.bare_by_file[source] = bare
    for source, count in sorted(report.bare_by_file.items()):
        allowed = baseline.get(source, 0)
        if count > allowed:
            report.problems.append(
                Problem(
                    source,
                    1,
                    f"{count} bare file:line citation{'s' if count > 1 else ''}, "
                    f"baseline {allowed}. A bare line "
                    f"number is not checkable: anchor the new one as `<path>.py::<symbol>`, "
                    f"or run `make citations-baseline` to raise the ratchet deliberately.",
                )
            )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check anchored source citations.")
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="rewrite the baseline from the current tree instead of checking it",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    if args.update_baseline:
        written = check(root, baseline={})
        write_baseline(args.baseline, written.bare_by_file)
        print(
            f"citations: baseline written, {written.bare_total} bare file:line "
            f"citations across {len(written.bare_by_file)} files"
        )
        return 0

    baseline = load_baseline(args.baseline)
    report = check(root, baseline)
    for problem in sorted(report.problems, key=lambda p: (p.source, p.line)):
        print(problem.render(), file=sys.stderr)
    forms = ", ".join(f"{count} {form}" for form, count in sorted(report.by_form.items()))
    summary = (
        f"citations: {report.verified + report.external} anchored resolved "
        f"({forms}; {report.external} into site-packages), "
        f"{report.bare_total} bare grandfathered (baseline {sum(baseline.values())})"
    )
    if report.problems:
        count = len(report.problems)
        print(f"{summary}, {count} PROBLEM{'S' if count > 1 else ''}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
