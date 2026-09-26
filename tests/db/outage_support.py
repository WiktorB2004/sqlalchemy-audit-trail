"""Durable engines that cannot connect, for the write policy tests.

Each outage is a URL (and driver ``connect_args``) that fails while
connecting, the way a database outage does. asyncpg raises some of these
unwrapped, depending on the SQLAlchemy and Python version; psycopg wraps them
all in a ``DBAPIError``.
"""

from __future__ import annotations

import socket
import uuid
from collections.abc import Iterator
from contextlib import closing, contextmanager
from typing import NamedTuple

from sqlalchemy import make_url

OUTAGES = ["unreachable", "missing_database", "connect_timeout"]
"""Parameters of ``outage``."""

_CONNECT_TIMEOUT: dict[str, dict[str, object]] = {
    "asyncpg": {"timeout": 0.5},
    "psycopg": {"connect_timeout": 1},
}


class Outage(NamedTuple):
    """How to build a durable engine that cannot connect."""

    url: str
    connect_args: dict[str, object]


def _free_port() -> int:
    # Bound and closed again: nothing listens on it afterwards.
    with closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@contextmanager
def outage(database_url: str, name: str, driver: str) -> Iterator[Outage]:
    """A URL on ``driver`` that fails to connect as ``name`` says.

    Args:
        database_url: URL of the test database.
        name: One of ``OUTAGES``: ``"unreachable"`` (nothing listens on the
            port), ``"missing_database"`` (the server refuses the database
            name), ``"connect_timeout"`` (the server accepts TCP connections
            and never answers, until the driver's connect timeout).
        driver: ``"psycopg"`` or ``"asyncpg"``.
    """
    url = make_url(database_url).set(drivername=f"postgresql+{driver}")
    match name:
        case "unreachable":
            url = url.set(host="127.0.0.1", port=_free_port())
            yield Outage(url.render_as_string(hide_password=False), {})
        case "missing_database":
            url = url.set(database=f"missing_{uuid.uuid4().hex[:12]}")
            yield Outage(url.render_as_string(hide_password=False), {})
        case "connect_timeout":
            with closing(socket.socket()) as silent:
                silent.bind(("127.0.0.1", 0))
                silent.listen()  # never accepts; the kernel completes TCP
                url = url.set(host="127.0.0.1", port=silent.getsockname()[1])
                yield Outage(
                    url.render_as_string(hide_password=False),
                    dict(_CONNECT_TIMEOUT[driver]),
                )
        case _:
            raise ValueError(name)
