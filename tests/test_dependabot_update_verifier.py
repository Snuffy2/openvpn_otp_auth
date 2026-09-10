"""Behavioral tests for the trusted Dependabot authorization helper."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any

import pytest

SHA = "a" * 40
BASE_SHA = "b" * 40
INITIAL_SHA = "c" * 40
INTERMEDIATE_BASE_SHA = "d" * 40
FIRST_UPDATE_SHA = "e" * 40


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
        "committer": {"login": "web-flow"},
        "parents": [],
        "sha": sha,
    }


def update_commit(sha: str, previous_sha: str, base_sha: str) -> dict[str, Any]:
    """Create a verified GitHub Update branch merge fixture."""
    return {
        "author": {"login": "Snuffy2"},
        "commit": {"verification": {"verified": True}},
        "committer": {"login": "web-flow"},
        "parents": [{"sha": previous_sha}, {"sha": base_sha}],
        "sha": sha,
    }


def ancestry_proof(parent_sha: str, status: str = "ahead") -> dict[str, Any]:
    """Create authoritative comparison data for a merge second parent."""
    return {
        "ahead_by": 0 if status == "identical" else 1,
        "base_commit": parent_sha,
        "base_sha": BASE_SHA,
        "behind_by": 0,
        "head_commit": BASE_SHA,
        "merge_base_commit": parent_sha,
        "parent_sha": parent_sha,
        "status": status,
    }


def update_chain() -> list[dict[str, Any]]:
    """Return a Dependabot update chain with an older intermediate base."""
    return [
        dependabot_commit(INITIAL_SHA),
        update_commit(FIRST_UPDATE_SHA, INITIAL_SHA, INTERMEDIATE_BASE_SHA),
        update_commit(SHA, FIRST_UPDATE_SHA, BASE_SHA),
    ]


def update_chain_proofs() -> list[dict[str, Any]]:
    """Return ancestry evidence for every merge in ``update_chain``."""
    return [
        ancestry_proof(INTERMEDIATE_BASE_SHA),
        ancestry_proof(BASE_SHA, "identical"),
    ]


def run_authorizer(
    tmp_path: Path,
    authorization_helper_path: Path,
    event: dict[str, Any],
    changed_files: list[str],
    commits: list[dict[str, Any]],
    ancestry_proofs: list[dict[str, Any]],
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
    ancestry_proofs_path = tmp_path / "ancestry-proofs.json"
    event_path.write_text(json.dumps(event))
    changed_files_path.write_text("\n".join(changed_files))
    commits_path.write_text(json.dumps([commits]))
    ancestry_proofs_path.write_text(json.dumps(ancestry_proofs))
    return subprocess.run(
        [
            "node",
            str(authorization_helper_path),
            str(event_path),
            str(changed_files_path),
            str(commits_path),
            str(ancestry_proofs_path),
        ],
        capture_output=True,
        check=False,
        cwd=trusted_base,
        text=True,
    )


def test_authorizer_accepts_verified_uv_lockfile_update(
    tmp_path: Path, authorization_helper_path: Path, pull_request_event: dict[str, Any]
) -> None:
    """A direct verified Dependabot lock update is accepted."""
    pull_request_event["action"] = "reopened"
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        ["uv.lock"],
        [dependabot_commit()],
        [],
        ["uv.lock"],
    )

    assert result.returncode == 0


@pytest.mark.parametrize("committer", [None, "Snuffy2"])
def test_authorizer_rejects_untrusted_direct_dependabot_committer(
    tmp_path: Path,
    authorization_helper_path: Path,
    pull_request_event: dict[str, Any],
    committer: str | None,
) -> None:
    """Direct history requires GitHub's verified Dependabot committer identity."""
    commit = dependabot_commit()
    if committer is None:
        del commit["committer"]
    else:
        commit["committer"] = {"login": committer}
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        ["uv.lock"],
        [commit],
        [],
        ["uv.lock"],
    )

    assert result.returncode != 0


@pytest.mark.parametrize(
    ("head_ref", "changed_files", "trusted_paths"),
    [
        ("dependabot/uv/pytest-9.0.0", ["uv.lock"], ["package.json", "package-lock.json"]),
        ("dependabot/npm_and_yarn/pytest-9.0.0", ["package-lock.json"], ["uv.lock"]),
    ],
)
def test_authorizer_derives_the_supported_ecosystem_from_the_trusted_base(
    tmp_path: Path,
    authorization_helper_path: Path,
    pull_request_event: dict[str, Any],
    head_ref: str,
    changed_files: list[str],
    trusted_paths: list[str],
) -> None:
    """A Dependency branch cannot select an ecosystem absent from the trusted base."""
    pull_request_event["pull_request"]["head"]["ref"] = head_ref
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        changed_files,
        [dependabot_commit()],
        [],
        trusted_paths,
    )

    assert result.returncode != 0


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
        [],
        trusted_paths,
    )

    assert result.returncode != 0


def test_authorizer_accepts_reopened_verified_github_update_branch_history(
    tmp_path: Path, authorization_helper_path: Path, pull_request_event: dict[str, Any]
) -> None:
    """A verified GitHub Update branch merge retains Dependabot authorization."""
    pull_request_event["action"] = "reopened"
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        ["uv.lock"],
        update_chain(),
        update_chain_proofs(),
        ["uv.lock"],
    )

    assert result.returncode == 0


def test_authorizer_rejects_non_web_flow_github_update_merge(
    tmp_path: Path, authorization_helper_path: Path, pull_request_event: dict[str, Any]
) -> None:
    """Only GitHub's Update branch committer can extend Dependabot history."""
    commits = update_chain()
    commits[1]["committer"] = {"login": "Snuffy2"}
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        ["uv.lock"],
        commits,
        update_chain_proofs(),
        ["uv.lock"],
    )

    assert result.returncode != 0


@pytest.mark.parametrize("committer", [None, "Snuffy2"])
def test_authorizer_rejects_untrusted_update_root_committer(
    tmp_path: Path,
    authorization_helper_path: Path,
    pull_request_event: dict[str, Any],
    committer: str | None,
) -> None:
    """An Update branch chain also requires a trusted Dependabot root commit."""
    commits = update_chain()
    if committer is None:
        del commits[0]["committer"]
    else:
        commits[0]["committer"] = {"login": committer}
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        ["uv.lock"],
        commits,
        update_chain_proofs(),
        ["uv.lock"],
    )

    assert result.returncode != 0


@pytest.mark.parametrize(
    "ancestry_proofs",
    [
        [],
        [{}, ancestry_proof(BASE_SHA, "identical")],
        [ancestry_proof(INTERMEDIATE_BASE_SHA), ancestry_proof("f" * 40)],
        [
            ancestry_proof(INTERMEDIATE_BASE_SHA, "diverged"),
            ancestry_proof(BASE_SHA, "identical"),
        ],
        [
            {**ancestry_proof(INTERMEDIATE_BASE_SHA), "head_commit": {"sha": "f" * 40}},
            ancestry_proof(BASE_SHA, "identical"),
        ],
    ],
)
def test_authorizer_rejects_incomplete_or_invalid_merge_ancestry_evidence(
    tmp_path: Path,
    authorization_helper_path: Path,
    pull_request_event: dict[str, Any],
    ancestry_proofs: list[dict[str, Any]],
) -> None:
    """Each GitHub Update branch merge needs current-base ancestry proof."""
    result = run_authorizer(
        tmp_path,
        authorization_helper_path,
        pull_request_event,
        ["uv.lock"],
        update_chain(),
        ancestry_proofs,
        ["uv.lock"],
    )

    assert result.returncode != 0


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
        [],
        [changed_file],
    )

    assert result.returncode == 0
