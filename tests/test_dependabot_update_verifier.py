"""Behavioral tests for the Dependabot auto-merge eligibility verifier."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


@pytest.fixture
def verifier_path() -> Path:
    """Return the trusted Dependabot eligibility verifier."""
    return (
        Path(__file__).resolve().parents[1] / ".github" / "scripts" / "verify-dependabot-update.sh"
    )


def run_verifier(
    tmp_path: Path,
    verifier_path: Path,
    package_ecosystem: str,
    changed_files: str,
    gh_exit_code: int = 0,
    pull_request_action: str | None = "synchronize",
    event_sender_login: str | None = "dependabot[bot]",
) -> tuple[subprocess.CompletedProcess[str], str]:
    """Run the verifier with a fake GitHub CLI response.

    Args:
        tmp_path: Temporary directory for the fake executable and job output.
        verifier_path: Path to the verifier script under test.
        package_ecosystem: Dependabot ecosystem supplied by the metadata action.
        changed_files: Newline-delimited filenames returned by the GitHub API.
        gh_exit_code: Exit code returned by the fake GitHub CLI.
        pull_request_action: Pull request action that triggered the workflow.
        event_sender_login: Actor that sent the pull request event.

    Returns:
        The verifier process result and its GitHub Actions output content.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(
        '#!/usr/bin/env bash\nprintf \'%s\\n\' "${FAKE_GH_FILES}"\nexit "${FAKE_GH_EXIT_CODE}"\n'
    )
    fake_gh.chmod(0o755)
    github_output = tmp_path / "github-output"
    environment = {
        **os.environ,
        "FAKE_GH_EXIT_CODE": str(gh_exit_code),
        "FAKE_GH_FILES": changed_files,
        "GITHUB_OUTPUT": str(github_output),
        "PACKAGE_ECOSYSTEM": package_ecosystem,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "PR_NUMBER": "42",
        "REPOSITORY": "Snuffy2/openvpn_otp_auth",
    }
    if pull_request_action is not None:
        environment["PULL_REQUEST_ACTION"] = pull_request_action
    if event_sender_login is not None:
        environment["EVENT_SENDER_LOGIN"] = event_sender_login
    result = subprocess.run(
        [str(verifier_path)],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )
    output = github_output.read_text() if github_output.exists() else ""
    return result, output


@pytest.mark.parametrize(
    ("package_ecosystem", "changed_files"),
    [
        ("uv", "uv.lock"),
        ("github_actions", ".github/workflows/ci.yml\n.github/workflows/release.yaml"),
    ],
)
@pytest.mark.parametrize("pull_request_action", ["opened", "synchronize"])
def test_verifier_accepts_supported_dependency_updates(
    tmp_path: Path,
    verifier_path: Path,
    package_ecosystem: str,
    changed_files: str,
    pull_request_action: str,
) -> None:
    """Supported updates explicitly report eligibility."""
    result, output = run_verifier(
        tmp_path,
        verifier_path,
        package_ecosystem,
        changed_files,
        pull_request_action=pull_request_action,
    )

    assert result.returncode == 0
    assert output == "eligibility=eligible\n"


@pytest.mark.parametrize(
    ("package_ecosystem", "changed_files"),
    [
        ("uv", "uv.lock\nREADME.md"),
        ("github_actions", ".github/workflows/ci.yml\nREADME.md"),
        ("pip", "requirements.txt"),
        ("uv", ""),
    ],
)
def test_verifier_marks_proven_policy_rejections(
    tmp_path: Path, verifier_path: Path, package_ecosystem: str, changed_files: str
) -> None:
    """Policy violations explicitly authorize auto-merge cleanup."""
    result, output = run_verifier(tmp_path, verifier_path, package_ecosystem, changed_files)

    assert result.returncode == 1
    assert output == "eligibility=rejected\n"


@pytest.mark.parametrize(
    ("pull_request_action", "event_sender_login"),
    [
        ("synchronize", "maintainer"),
        ("reopened", "dependabot[bot]"),
    ],
)
def test_verifier_rejects_events_without_dependabot_current_head_provenance(
    tmp_path: Path,
    verifier_path: Path,
    pull_request_action: str,
    event_sender_login: str,
) -> None:
    """Events that cannot prove the current head is Dependabot-produced enable cleanup."""
    result, output = run_verifier(
        tmp_path,
        verifier_path,
        "uv",
        "uv.lock",
        pull_request_action=pull_request_action,
        event_sender_login=event_sender_login,
    )

    assert result.returncode == 1
    assert output == "eligibility=rejected\n"


@pytest.mark.parametrize(
    ("package_ecosystem", "changed_files", "gh_exit_code"),
    [
        ("", "uv.lock", 0),
        ("uv", "", 2),
    ],
)
def test_verifier_leaves_operational_failures_semantically_distinct(
    tmp_path: Path,
    verifier_path: Path,
    package_ecosystem: str,
    changed_files: str,
    gh_exit_code: int,
) -> None:
    """Metadata and GitHub API failures leave their eligibility output unset."""
    result, output = run_verifier(
        tmp_path, verifier_path, package_ecosystem, changed_files, gh_exit_code
    )

    assert result.returncode != 0
    assert output == ""


@pytest.mark.parametrize(
    ("pull_request_action", "event_sender_login"),
    [
        (None, "dependabot[bot]"),
        ("synchronize", None),
    ],
)
def test_verifier_leaves_missing_event_provenance_semantically_distinct(
    tmp_path: Path,
    verifier_path: Path,
    pull_request_action: str | None,
    event_sender_login: str | None,
) -> None:
    """Unavailable event provenance leaves its eligibility output unset."""
    result, output = run_verifier(
        tmp_path,
        verifier_path,
        "uv",
        "uv.lock",
        pull_request_action=pull_request_action,
        event_sender_login=event_sender_login,
    )

    assert result.returncode != 0
    assert output == ""


def test_workflow_passes_pull_request_event_provenance_to_verifier() -> None:
    """The trusted verifier receives the event fields needed to validate the current head."""
    workflow_path = (
        Path(__file__).resolve().parents[1] / ".github/workflows/dependabot-auto-merge.yml"
    )
    workflow = workflow_path.read_text()

    assert "PULL_REQUEST_ACTION: ${{ github.event.action }}" in workflow
    assert "EVENT_SENDER_LOGIN: ${{ github.event.sender.login }}" in workflow


def test_workflow_fails_closed_when_verification_is_not_explicitly_eligible() -> None:
    """Unset verifier output still runs guarded cleanup, while enablement requires eligibility."""
    workflow_path = (
        Path(__file__).resolve().parents[1] / ".github/workflows/dependabot-auto-merge.yml"
    )
    workflow = workflow_path.read_text()

    assert "if: needs.verify-dependency-update.outputs.eligibility == 'eligible'" in workflow
    assert "always() && !cancelled() &&" in workflow
    assert "needs.verify-dependency-update.outputs.eligibility != 'eligible'" in workflow
