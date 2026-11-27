"""Salted commitments to the parts of an entry that scrubbing may erase.

Each erasable part of a row is a *group*:

========= =========== ===================================================
Group     Table       Value
========= =========== ===================================================
label     activity    ``object_label``
changes   activity    ``data.changes``
payload   activity    ``data.payload``
actor     activity    the ``ACTOR_FIELDS`` keys of ``data.context``
actor     transaction the ``ACTOR_FIELDS`` columns
========= =========== ===================================================

A group is present when its value is not null; an ``actor`` group holds only
its non-null fields and is present when it holds any. For each present group
a fresh 16-byte salt is drawn, and::

    commitment = SHA-256("sqlalchemy-audit-trail/commit/v1" || 0x00
                         || u8(len(group)) || group || salt
                         || canonical(value))

The row stores ``{group: base64(commitment)}`` in ``seal_commitments``, which
never changes, and ``{group: base64(salt)}`` in ``seal_salts``. A scrub
deletes the salt of every group it erases, which leaves the commitment
unlinkable to the erased value, and stamps the group in ``seal_erased`` with
its own transaction id.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import secrets
from collections.abc import Mapping
from typing import TypedDict

from audit_trail.integrity._canonical import CanonicalEncodingError, canonical

ACTOR_FIELDS: tuple[str, ...] = ("actor_label", "remote_addr", "user_agent", "meta")
"""The fields of the ``actor`` group: the columns of ``audit_transaction``,
and keys of ``data.context``, that ``privacy.scrub_actor`` clears.

Defined here, in a module that imports no SQLAlchemy, so the verifier can
use it; ``privacy.ACTOR_FIELDS`` is the same tuple."""

ACTIVITY_GROUPS: tuple[str, ...] = ("label", "changes", "payload", "actor")
"""The groups of an ``audit_activity`` row."""

TRANSACTION_GROUPS: tuple[str, ...] = ("actor",)
"""The groups of an ``audit_transaction`` row."""

SALT_LENGTH = 16
"""Bytes of one salt."""

COMMIT_CONTEXT = b"sqlalchemy-audit-trail/commit/v1"
"""Domain separation string of a commitment."""

LEAF_CONTEXT = b"sqlalchemy-audit-trail/leaf/v1"
"""Domain separation string of a Merkle leaf."""


class SealColumns(TypedDict):
    """The integrity columns of a new row.

    Every row a writer builds carries all three keys: ``executemany`` takes
    its column list from the first row, raises for a later row that lacks a
    key, and silently drops a key the first row does not have.

    ``seal_commitments`` and ``seal_salts`` are ``{}`` for a row without any
    group, so SQL ``NULL`` keeps meaning "written without integrity".
    ``seal_erased`` is always ``None`` (SQL ``NULL``) until a scrub stamps it.
    """

    seal_commitments: dict[str, str]
    seal_salts: dict[str, str]
    seal_erased: None


def commitment(group: str, salt: bytes, value: object) -> bytes:
    """The commitment to one group's value.

    Args:
        group: The group name, at most 255 bytes of UTF-8.
        salt: The group's salt, ``SALT_LENGTH`` bytes.
        value: The group's value, as ``canonical`` accepts it.

    Returns:
        The 32-byte SHA-256 digest.

    Raises:
        ValueError: The group name is too long or the salt has the wrong
            length.
        CanonicalEncodingError: The value has no canonical encoding.
    """
    name = group.encode()
    if len(name) > 255:
        raise ValueError("a group name is at most 255 bytes")
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"a salt is {SALT_LENGTH} bytes")
    digest = hashlib.sha256(COMMIT_CONTEXT)
    digest.update(b"\x00")
    digest.update(bytes([len(name)]))
    digest.update(name)
    digest.update(salt)
    digest.update(canonical(value))
    return digest.digest()


def leaf_hash(row: Mapping[str, object]) -> bytes:
    """The RFC 6962 Merkle leaf hash of a row's sealed fields.

    Args:
        row: The fields, as ``canonical`` accepts them.

    Returns:
        ``SHA-256(0x00 || LEAF_CONTEXT || canonical(row))``.

    Raises:
        CanonicalEncodingError: A field has no canonical encoding.
    """
    return hashlib.sha256(b"\x00" + LEAF_CONTEXT + canonical(row)).digest()


def new_salt() -> bytes:
    """A fresh random salt; never reused, also not by a retried write."""
    return secrets.token_bytes(SALT_LENGTH)


def seal_columns(groups: Mapping[str, object]) -> SealColumns:
    """Commit to the present groups of a row, each with a fresh salt.

    Args:
        groups: Every group of the row's table mapped to its value; ``None``
            for a group that is not present.

    Returns:
        The values of the integrity columns.

    Raises:
        CanonicalEncodingError: A value has no canonical encoding.
    """
    commitments: dict[str, str] = {}
    salts: dict[str, str] = {}
    for group, value in groups.items():
        if value is None:
            continue
        salt = new_salt()
        commitments[group] = _b64(commitment(group, salt, value))
        salts[group] = _b64(salt)
    return {"seal_commitments": commitments, "seal_salts": salts, "seal_erased": None}


def activity_groups(
    object_label: str | None, data: Mapping[str, object]
) -> dict[str, object]:
    """The groups of an ``audit_activity`` row.

    Args:
        object_label: The row's ``object_label``.
        data: The row's ``data``.

    Returns:
        Every name of ``ACTIVITY_GROUPS`` mapped to its value, ``None`` when
        the group is not present.
    """
    context = data.get("context")
    actor = None
    if isinstance(context, Mapping):
        actor = _present({key: context.get(key) for key in ACTOR_FIELDS})
    return {
        "label": object_label,
        "changes": data.get("changes"),
        "payload": data.get("payload"),
        "actor": actor,
    }


def transaction_groups(row: Mapping[str, object]) -> dict[str, object]:
    """The groups of an ``audit_transaction`` row.

    ``remote_addr`` is committed to in the text PostgreSQL gives the stored
    ``inet`` value (see ``inet_text``), which is what a reader gets back.

    Args:
        row: The row's column values; missing columns count as ``None``.

    Returns:
        ``{"actor": ...}``, ``None`` when the group is not present.

    Raises:
        CanonicalEncodingError: ``remote_addr`` is not an address
            ``inet_text`` accepts.
    """
    fields = {key: row.get(key) for key in ACTOR_FIELDS}
    remote_addr = fields["remote_addr"]
    if remote_addr is not None:
        fields["remote_addr"] = inet_text(str(remote_addr))
    return {"actor": _present(fields)}


def inet_text(value: str) -> str:
    """The text PostgreSQL's ``inet`` output gives for an address.

    IPv4 is dotted; IPv6 is lowercase hex with the first longest run of two
    or more zero groups as ``::``, and an IPv4-compatible (``::a.b.c.d``) or
    IPv4-mapped (``::ffff:a.b.c.d``) address ends in dotted IPv4. A prefix is
    shown unless it covers the whole address; host bits are kept.

    Only an address in the strict form of ``ipaddress.ip_address``, with an
    optional ``/prefix`` of plain decimal digits and no leading zero, is
    accepted. PostgreSQL also accepts forms this function cannot match
    safely, and stores them differently from what they look like
    (``01.2.3.4`` is ``1.2.3.4``, ``10/8`` is ``10.0.0.0/8``, ``1.2.3.4.`` is
    ``1.2.3.4``), so those are refused, as is anything PostgreSQL rejects.

    Args:
        value: An address as the host passed it, with or without a prefix.

    Returns:
        The canonical text.

    Raises:
        CanonicalEncodingError: The value is not an address in that form.
    """
    address_text, slash, prefix_text = value.partition("/")
    try:
        address = ipaddress.ip_address(address_text)
    except ValueError:
        address = None
    if address is None or (
        isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None
    ):
        raise CanonicalEncodingError(_NOT_AN_ADDRESS)
    prefix: int = address.max_prefixlen
    if slash:
        if not (
            prefix_text.isascii()
            and prefix_text.isdigit()
            and (prefix_text == "0" or not prefix_text.startswith("0"))
            and int(prefix_text) <= address.max_prefixlen
        ):
            raise CanonicalEncodingError(_NOT_AN_ADDRESS)
        prefix = int(prefix_text)
    if isinstance(address, ipaddress.IPv4Address):
        text = str(address)
    else:
        text = _ipv6_text(address.packed)
    return text if prefix == address.max_prefixlen else f"{text}/{prefix}"


_NOT_AN_ADDRESS = (
    "cannot commit to a remote_addr that is not an IP address in strict form, "
    "with an optional /prefix"
)


def _ipv6_text(packed: bytes) -> str:
    # The rules of PostgreSQL's inet_net_ntop_ipv6 (src/port/inet_net_ntop.c).
    words = [int.from_bytes(packed[i : i + 2], "big") for i in range(0, 16, 2)]
    best_base, best_len = -1, 0
    base, length = -1, 0
    for index, word in enumerate(words):
        if word == 0:
            if base == -1:
                base, length = index, 1
            else:
                length += 1
            if length > best_len:
                best_base, best_len = base, length
        else:
            base, length = -1, 0
    if best_len < 2:
        best_base = -1
    if best_base == 0 and (best_len == 6 or (best_len == 5 and words[5] == 0xFFFF)):
        prefix = "::" if best_len == 6 else "::ffff:"
        return prefix + str(ipaddress.IPv4Address(packed[12:]))
    parts: list[str] = []
    index = 0
    while index < 8:
        if index == best_base:
            parts.append("")
            if index == 0:
                parts.append("")
            index += best_len
            if index == 8:
                parts.append("")
            continue
        parts.append(f"{words[index]:x}")
        index += 1
    return ":".join(parts)


def _present(fields: dict[str, object]) -> dict[str, object] | None:
    present = {key: value for key, value in fields.items() if value is not None}
    return present or None


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")
