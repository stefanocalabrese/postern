.PHONY: ci lint fmt fmt-check type imports lock test migrations

ci: lint fmt-check type imports lock test

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

fmt-check:
	uv run ruff format --check packages services tests

type:
	uv run mypy packages services tests

imports:
	uv run lint-imports

lock:
	uv lock --check --offline

# `-rs` prints the reason line for every skip, not just the count, so a
# Docker-unreachable machine gets a loud "Docker is not reachable, skipping
# database-backed tests: ..." for each affected test instead of a number
# buried in "N passed, M skipped" that's easy to not read (Task 3). From
# Task 3 onward this starts a session-scoped `testcontainers` Postgres for
# tests/test_store_consents.py, so `make ci` is no longer fully offline nor
# sub-second (measured: ~0.9s -> ~2.4-2.6s for this step, ~1.5s -> ~3.3-3.6s
# total for `make ci`), trading that property for actually running the
# consent-enforcement tests (Task 4) by default rather than behind a marker
# nobody remembers to pass. Docker down degrades to an explicit skip per
# test, not a `docker.errors.DockerException` traceback; see `pg_url` in
# tests/conftest.py and the plan's Task 3 decision note.
test:
	@if [ -z "$$(find tests -name 'test_*.py' -print -quit 2>/dev/null)" ]; then \
		echo "no tests yet, skipping"; \
	else \
		uv run pytest -q -rs; \
	fi

# NOT a `ci` prerequisite: `alembic check` is a second, independent reason to
# need a reachable Postgres beyond the `test` gate above, and keeping it a
# standalone target means the drift check runs against a database an
# operator points it at explicitly, rather than the disposable container
# `test` starts and tears down itself. Run this by hand before committing
# any change to packages/postern-core/src/postern_core/store/models.py,
# against `docker compose up -d db` or any other reachable database, to
# catch a model change that has no matching migration before it surfaces at
# deploy time. The same check runs in `.github/workflows/ci.yml` against a
# free Postgres service container, dispatched manually.
migrations:
	POSTERN_DATABASE_URL=$${POSTERN_DATABASE_URL:-postgresql+asyncpg://postern:postern@localhost:5432/postern} uv run alembic check
