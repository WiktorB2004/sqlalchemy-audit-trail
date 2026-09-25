# Contributing

Thanks for looking at the repo. Please follow the [Code of Conduct](https://github.com/WiktorB2004/sqlalchemy-audit-trail/blob/main/CODE_OF_CONDUCT.md).

## Scope

In scope:

- The `audit_trail` package: the flush listener, explicit events, the query API, partition maintenance, privacy helpers, the FastAPI integration and the testing helpers
- Docs

Out of scope (file those upstream):

- SQLAlchemy core and ORM behaviour
- PostgreSQL
- Database drivers (psycopg, asyncpg)
- FastAPI

## Issues

Use the GitHub issue templates. Search existing issues first.

Do **not** open a public issue for a vulnerability. See [SECURITY.md](https://github.com/WiktorB2004/sqlalchemy-audit-trail/blob/main/SECURITY.md).

## Setup

Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --frozen
uv run pre-commit install
```

`uv sync --frozen` installs the exact versions in `uv.lock`, which is what CI uses. `pre-commit` runs Ruff (lint with `--fix`, then format) and mypy on commit. To run the hooks over the whole tree:

```bash
uv run pre-commit run --all-files
```

## Dependencies

[Renovate](https://docs.renovatebot.com/) opens weekly grouped PRs for Python packages, GitHub Actions and pre-commit pins. Do not add Dependabot version updates; the two bots would conflict. Dependabot **alerts** (GitHub Security) are fine.

## Tests

Tests under `tests/unit` need nothing else:

```bash
uv run pytest tests/unit
```

Tests under `tests/db` need PostgreSQL. With Docker running, a throwaway `postgres:18` container is started with [testcontainers](https://testcontainers.com/):

```bash
uv run pytest
```

Pick another image with `AUDIT_TEST_PG_IMAGE`. PostgreSQL 14 is the oldest supported version, so check changes to SQL, DDL or partitioning there too:

```bash
AUDIT_TEST_PG_IMAGE=postgres:14 uv run pytest
```

To use a server you already have instead of Docker, set `AUDIT_TEST_DATABASE_URL`, for example `postgresql+psycopg://postgres:postgres@localhost:5432/postgres`.

CI runs the suite on PostgreSQL 14, 16, 17 and 18, SQLAlchemy 2.0 and 2.1, and Python 3.10 to 3.13. On Python 3.11+ `uv.lock` pins SQLAlchemy 2.1; to test against 2.0 locally:

```bash
uv pip install "sqlalchemy[asyncio]==2.0.*"
uv run --no-sync pytest
```

Run `uv sync --frozen` afterwards to go back to the locked version.

## Lint and types

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

mypy runs in strict mode over `audit_trail` and `tests`.

## Docs

```bash
uv sync --group docs
uv run mkdocs serve
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). CI runs `mkdocs build --strict`.

Narrative pages live in `docs/`. API pages are generated from Google-style docstrings; edit the docstrings when the API changes, not the generated HTML.

## Changelog

User-facing changes get a bullet under `## Unreleased` in `CHANGELOG.md` (the docs site includes that file). Skip internal refactors and CI-only changes if they do not affect callers.

## Pull requests

1. One concern per PR.
2. Tests for behaviour changes. Anything that writes or reads audit rows needs a test in `tests/db` against a real PostgreSQL, not a mock.
3. Docs and changelog when the public API changes.
4. Fill in the PR template.

Do not commit `.env` files, database URLs with passwords or pseudonymization keys.
