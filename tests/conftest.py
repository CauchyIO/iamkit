"""Refuse to run the suite in a dev clone that bypasses the leak-guard hooks.

CI is exempt (GITHUB_ACTIONS is set): the runner never commits, and the
ci.yml leak-guard job scans there instead.
"""

import os
import subprocess
from pathlib import Path

import pytest


def pytest_sessionstart(session: pytest.Session) -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return
    repo_root = Path(__file__).resolve().parent.parent
    if not (repo_root / ".git").exists():
        return
    hooks_path = subprocess.run(
        ["git", "config", "core.hooksPath"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if hooks_path != ".githooks":
        pytest.exit(
            "leak-guard hooks are not enabled in this clone. "
            "Run: git config core.hooksPath .githooks "
            "(done automatically by `uv sync`), and see README § Development "
            "for the pattern file the hooks require.",
            returncode=1,
        )
