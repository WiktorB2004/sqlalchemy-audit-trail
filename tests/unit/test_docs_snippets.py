"""Every Python code block in the documentation and the README parses.

Blocks that only include a file from ``examples/`` (``--8<--``) are left to
``tests/db/test_examples.py``, which runs those files.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
PAGES = sorted([*(ROOT / "docs").rglob("*.md"), ROOT / "README.md"])
BLOCK = re.compile(r"^```python\n(.*?)^```$", re.MULTILINE | re.DOTALL)
INCLUDE = re.compile(r'^--8<-- "[^"]+"$')
MIN_BLOCKS = 40
"""Fewer blocks than this means the pattern stopped matching the pages."""


def python_blocks() -> list[tuple[str, int, str]]:
    blocks = []
    for page in PAGES:
        text = page.read_text()
        for match in BLOCK.finditer(text):
            source = match.group(1)
            lines = [line for line in source.splitlines() if line.strip()]
            if all(INCLUDE.match(line) for line in lines):
                continue
            line = text.count("\n", 0, match.start()) + 1
            blocks.append((str(page.relative_to(ROOT)), line, source))
    return blocks


BLOCKS = python_blocks()


def test_blocks_are_found() -> None:
    assert len(BLOCKS) >= MIN_BLOCKS


@pytest.mark.parametrize(
    ("page", "line", "source"),
    BLOCKS,
    ids=[f"{page}:{line}" for page, line, _ in BLOCKS],
)
def test_block_parses(page: str, line: int, source: str) -> None:
    compile(
        source,
        f"{page}:{line}",
        "exec",
        flags=ast.PyCF_ONLY_AST | ast.PyCF_ALLOW_TOP_LEVEL_AWAIT,
        dont_inherit=True,
    )
