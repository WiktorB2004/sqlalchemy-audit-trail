## Summary

<!-- What changed and why. Link the issue if there is one. -->

## Test plan

- [ ] Tests added or updated (or N/A — say why)
- [ ] `uv run pytest` passes locally, including the PostgreSQL tests in `tests/db`
- [ ] Schema, SQL or partition changes checked on PostgreSQL 14 (`AUDIT_TEST_PG_IMAGE=postgres:14`) as well as the default image
- [ ] `ruff check`, `ruff format --check` and `mypy` pass
- [ ] Docs and docstrings updated if the public API changed
- [ ] `CHANGELOG.md` `Unreleased` bullet if callers should notice
