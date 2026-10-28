"""Exercise release validation against real local Git history."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import textwrap

import pytest


@pytest.fixture
def release_validation_script() -> str:
    """Read the release validation shell directly from the publishing workflow."""
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/publish-pypi.yml"
    step = workflow.read_text().split("      - name: Validate the released revision\n", 1)[1]
    script = step.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0]
    return textwrap.dedent(script)


@pytest.mark.parametrize(
    ("target_kind", "off_branch", "expected_error"),
    [
        pytest.param("branch", False, "", id="branch-target"),
        pytest.param("sha", False, "", id="release-please-sha-target"),
        pytest.param(
            "sha", True, "Release tag must identify a default-branch commit.", id="off-branch"
        ),
    ],
)
def test_release_validation(
    tmp_path: Path,
    release_validation_script: str,
    target_kind: str,
    off_branch: bool,
    expected_error: str,
) -> None:
    """Accept default-branch tags regardless of metadata and reject off-branch tags."""
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Release test",
        "GIT_AUTHOR_EMAIL": "release@example.com",
        "GIT_COMMITTER_NAME": "Release test",
        "GIT_COMMITTER_EMAIL": "release@example.com",
        "DEFAULT_BRANCH": "main",
        "IS_PRERELEASE": "false",
        "RELEASE_TAG": "v1.4.2",
    }

    def git(*args: str) -> str:
        """Run Git in the isolated release repository."""
        return subprocess.run(
            ["git", *args], cwd=tmp_path, env=env, check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init", "--initial-branch=main")
    version_file = tmp_path / "src/openvpn_otp_auth/_version.py"
    version_file.parent.mkdir(parents=True)
    version_file.write_text('VERSION = "v1.4.2"  # x-release-please-version\n')
    git("add", ".")
    git("commit", "-m", "Release version")
    git("remote", "add", "origin", str(tmp_path))
    if off_branch:
        git("checkout", "-b", "unmerged")
        git("commit", "--allow-empty", "-m", "Unmerged revision")
    git("tag", "v1.4.2")
    env["RELEASE_TARGET"] = git("rev-parse", "HEAD") if target_kind == "sha" else "main"
    result = subprocess.run(
        ["bash", "-c", release_validation_script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        check=False,
        text=True,
    )
    if expected_error:
        assert result.returncode != 0
        assert expected_error in result.stderr
    else:
        assert result.returncode == 0, result.stderr
