"""Behavioral tests for the trusted Dependabot authorization helper."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from typing import Any

import pytest

SHA = "a" * 40
BASE_SHA = "b" * 40


@pytest.fixture
def authorization_helper_path() -> Path:
    """Return the trusted Dependabot authorization helper."""
    return Path(__file__).resolve().parents[1] / ".github/scripts/dependabot-auto-merge.mjs"


@pytest.fixture
def pull_request_event() -> dict[str, Any]:
    """Return a verified Dependabot pull-request event fixture."""
    return {
        "action": "opened",
        "repository": {
            "default_branch": "main",
            "fork": False,
            "full_name": "Snuffy2/openvpn_otp_auth",
        },
        "pull_request": {
            "base": {"ref": "main", "sha": BASE_SHA},
            "head": {
                "ref": "dependabot/uv/pytest-9.0.0",
                "repo": {"full_name": "Snuffy2/openvpn_otp_auth"},
                "sha": SHA,
            },
            "user": {"login": "dependabot[bot]"},
        },
    }


def dependabot_commit(sha: str = SHA) -> dict[str, Any]:
    """Create a verified Dependabot commit fixture."""
    return {
        "author": {"login": "dependabot[bot]"},
        "commit": {"verification": {"verified": True}},
        "parents": [],
        "sha": sha,
    }


def run_authorizer(
    tmp_path: Path,
    authorization_helper_path: Path,
    event: dict[str, Any],
    changed_files: list[str],
    commits: list[dict[str, Any]],
    actor: str,
    trusted_paths: list[str] | tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    """Run the helper with a synthetic GitHub event and trusted-base files."""
    trusted_base = tmp_path / "trusted-base"
    trusted_base.mkdir()
    for trusted_path in trusted_paths:
        path = trusted_base / trusted_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("trusted fixture\n")

    event_path = tmp_path / "event.json"
    changed_files_path = tmp_path / "changed-files"
    commits_path = tmp_path / "commits.json"
    event_path.write_text(json.dumps(event))
    changed_files_path.write_text("\n".join(changed_files))
    commits_path.write_text(json.dumps([commits]))
    return subprocess.run(
        [
            "node",
            str(authorization_helper_path),
            str(event_path),
            str(changed_files_path),
            str(commits_path),
        ],
        capture_output=True,
        check=False,
        cwd=trusted_base,
        env={**os.environ, "GITHUB_ACTOR": actor},
        text=True,
    )


def test_authorizer_accepts_verified_uv_lockfile_update(
    tmp_path: Path, authorization_helper_path: Path, pull_request_event: dict[str, Any]
) -> None:
    """A direct verified Dependabot lock update is accepted."""
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        ["uv.lock"],
        [dependabot_commit()],
        "dependabot[bot]",
    )

    assert result.returncode == 0


@pytest.mark.parametrize(
    ("changed_files", "trusted_paths"),
    [
        (["uv.lock", "pyproject.toml"], []),
        ([".github/workflows/new-workflow.yml"], [".github/workflows/pytest_check.yml"]),
    ],
)
def test_authorizer_rejects_updates_outside_the_trusted_scope(
    tmp_path: Path,
    authorization_helper_path: Path,
    pull_request_event: dict[str, Any],
    changed_files: list[str],
    trusted_paths: list[str],
) -> None:
    """Untrusted changed files are rejected without relying on workflow text."""
    if changed_files[0].startswith(".github"):
        pull_request_event["pull_request"]["head"]["ref"] = (
            "dependabot/github_actions/actions/checkout-7"
        )
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        changed_files,
        [dependabot_commit()],
        "dependabot[bot]",
        trusted_paths,
    )

    assert result.returncode != 0


def test_authorizer_accepts_verified_github_update_branch_history(
    tmp_path: Path, authorization_helper_path: Path, pull_request_event: dict[str, Any]
) -> None:
    """A verified GitHub Update branch merge retains Dependabot authorization."""
    initial_sha = "c" * 40
    pull_request_event["action"] = "synchronize"
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        ["uv.lock"],
        [
            dependabot_commit(initial_sha),
            {
                "author": {"login": "Snuffy2"},
                "commit": {"verification": {"verified": True}},
                "committer": {"login": "web-flow"},
                "parents": [{"sha": initial_sha}, {"sha": BASE_SHA}],
                "sha": SHA,
            },
        ],
        "Snuffy2",
    )

    assert result.returncode == 0


@pytest.mark.parametrize("changed_file", [".github/workflows/pytest_check.yml", "action.yml"])
def test_authorizer_requires_existing_trusted_action_manifest(
    tmp_path: Path,
    authorization_helper_path: Path,
    pull_request_event: dict[str, Any],
    changed_file: str,
) -> None:
    """An Actions update is accepted only when its target exists in the trusted base."""
    pull_request_event["pull_request"]["head"]["ref"] = (
        "dependabot/github_actions/actions/checkout-7"
    )
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        [changed_file],
        [dependabot_commit()],
        "dependabot[bot]",
        [changed_file],
    )

    assert result.returncode == 0
