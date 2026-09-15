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

test:
	@if [ -z "$$(find tests -name 'test_*.py' -print -quit 2>/dev/null)" ]; then \
		echo "no tests yet, skipping"; \
	else \
		uv run pytest -q; \
	fi

# NOT a `ci` prerequisite, deliberately: `alembic check` needs a reachable
# Postgres, and `make ci` running fully offline in under a second is the
# property that lets it run locally for free instead of burning billed
# Actions minutes (see CLAUDE.md). Run this by hand before committing any
# change to packages/postern-core/src/postern_core/store/models.py, against
# `docker compose up -d db` or any other reachable database, to catch a model
# change that has no matching migration before it surfaces at deploy time.
# The same check runs in `.github/workflows/ci.yml` against a free Postgres
# service container, dispatched manually.
migrations:
	POSTERN_DATABASE_URL=$${POSTERN_DATABASE_URL:-postgresql+asyncpg://postern:postern@localhost:5432/postern} uv run alembic check
