# Install

```bash
pip install sqlalchemy-audit-trail[psycopg]
```

Extras:

| Extra | Adds |
|---|---|
| `psycopg` | psycopg 3 driver |
| `asyncpg` | asyncpg driver and SQLAlchemy asyncio support |
| `asyncio` | SQLAlchemy asyncio support only |
| `pydantic` | payload schemas for domain events |
| `fastapi` | FastAPI middleware and dependencies |

Requires Python 3.10+, SQLAlchemy 2.0+ and PostgreSQL 14+.
