# Development

Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pre-commit install
```

## Tests

Tests under `tests/db` need PostgreSQL. Set `AUDIT_TEST_DATABASE_URL`, or have Docker running and a throwaway container is started with testcontainers (`AUDIT_TEST_PG_IMAGE` picks the image, default `postgres:18`).

```bash
uv run pytest
uv run pytest tests/unit   # no database
```

## Lint and types

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

## Docs

```bash
uv sync --group docs
uv run mkdocs serve
```

CI runs `mkdocs build --strict`. API pages are generated from Google-style docstrings; edit the docstrings, not the generated HTML.
