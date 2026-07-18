"""Regression tests for scripts/leak-guard.sh.

Uses throwaway patterns in a throwaway git repo — the real pattern list is
never present in this codebase.
"""

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "leak-guard.sh"


@pytest.fixture()
def guarded_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "OSS Bot"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "bot@example.org"], cwd=repo, check=True)
    (tmp_path / "patterns.txt").write_text("zzz-forbidden\n")
    return repo


def run_guard(repo: Path, tmp_path: Path, mode: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(SCRIPT), mode, *args],
        cwd=repo,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(tmp_path),
            "IAMKIT_LEAK_PATTERNS": str(tmp_path / "patterns.txt"),
        },
        capture_output=True,
        text=True,
        check=False,
    )


def test_clean_staged_file_passes(guarded_repo: Path, tmp_path: Path) -> None:
    (guarded_repo / "ok.txt").write_text("harmless content\n")
    subprocess.run(["git", "add", "ok.txt"], cwd=guarded_repo, check=True)
    result = run_guard(guarded_repo, tmp_path, "pre-commit")
    assert result.returncode == 0, result.stderr


def test_staged_leak_is_blocked(guarded_repo: Path, tmp_path: Path) -> None:
    (guarded_repo / "leak.txt").write_text("mentions zzz-forbidden here\n")
    subprocess.run(["git", "add", "leak.txt"], cwd=guarded_repo, check=True)
    result = run_guard(guarded_repo, tmp_path, "pre-commit")
    assert result.returncode == 1
    assert "leak.txt" in result.stderr
    assert "zzz-forbidden" not in result.stderr  # content is never echoed


def test_leaky_commit_message_is_blocked(guarded_repo: Path, tmp_path: Path) -> None:
    msg = tmp_path / "msg.txt"
    msg.write_text("refs zzz-forbidden\n")
    result = run_guard(guarded_repo, tmp_path, "commit-msg", str(msg))
    assert result.returncode == 1


def test_missing_pattern_file_warns_and_passes(guarded_repo: Path, tmp_path: Path) -> None:
    # Outside contributors never have the pattern list; the CI backstop scans
    # for them. The local guard must warn loudly but not block.
    (tmp_path / "patterns.txt").unlink()
    result = run_guard(guarded_repo, tmp_path, "pre-commit")
    assert result.returncode == 0
    assert "pattern file missing" in result.stderr
    assert "UNSCANNED" in result.stderr


def test_missing_pattern_file_warns_and_passes_pre_push(guarded_repo: Path, tmp_path: Path) -> None:
    (tmp_path / "patterns.txt").unlink()
    result = run_guard(guarded_repo, tmp_path, "pre-push")
    assert result.returncode == 0
    assert "pattern file missing" in result.stderr
