"""``audit_trail.testing`` is importable without pytest."""

from __future__ import annotations

import subprocess
import sys


def test_importing_the_package_and_testing_does_not_import_pytest() -> None:
    code = (
        "import sys, audit_trail, audit_trail.testing; "
        "print(sorted(m for m in sys.modules if m.split('.')[0] in "
        "{'pytest', '_pytest'}))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"
