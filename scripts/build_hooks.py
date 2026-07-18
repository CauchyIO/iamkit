"""Hatchling build hook: enable the repo's leak-guard git hooks on dev installs.

Runs during every editable install (`uv sync`), so any contributor who sets up
the project gets `core.hooksPath = .githooks` configured without a manual
step. Regular (non-editable) wheel/sdist builds are untouched.
"""

import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class LeakGuardHookInstaller(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        if version != "editable":
            return
        repo_root = Path(self.root)
        if not (repo_root / ".git").exists():
            return
        subprocess.run(
            ["git", "config", "core.hooksPath", ".githooks"],
            cwd=repo_root,
            check=True,
        )
        self.app.display_info("leak-guard: enabled .githooks via core.hooksPath")
