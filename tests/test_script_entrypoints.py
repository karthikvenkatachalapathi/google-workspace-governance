#!/usr/bin/env python3
"""Pytest entrypoints for the repository's script-style regression tests."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_TESTS = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "scripts").glob("test*.py"))


@pytest.mark.parametrize("script", SCRIPT_TESTS)
def test_script_entrypoint_passes(script: str) -> None:
    result = subprocess.run(
        [sys.executable, script],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout
