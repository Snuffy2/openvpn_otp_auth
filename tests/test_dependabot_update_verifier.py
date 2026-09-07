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


def load_workflow(path: Path) -> dict[str, Any]:
    """Parse a workflow through Ruby's standard YAML parser."""
    result = subprocess.run(
        [
            "ruby",
            "-ryaml",
            "-rjson",
            "-e",
            "puts JSON.generate(Psych.safe_load_file(ARGV.fetch(0), aliases: false))",
            str(path),
        ],
        capture_output=True,
        check=True,
        text=True,
    )
    return json.loads(result.stdout)


def step_with(job: dict[str, Any], capability: str) -> tuple[int, dict[str, Any]]:
    """Return one step whose definition contains a workflow capability."""
    steps = job["steps"]
    assert isinstance(steps, list)
    for index, step in enumerate(steps):
        if capability in str(step):
            return index, step
    pytest.fail(f"workflow is missing {capability!r}")


def uses_major_action(step: dict[str, Any], action: str) -> bool:
    """Return whether a step invokes an action through a major release line."""
    return str(step.get("uses", "")).startswith(f"{action}@v")


def job_with(workflow: dict[str, Any], capability: str) -> dict[str, Any]:
    """Return the unique job that provides a workflow capability."""
    jobs = workflow["jobs"]
    matches = [job for job in jobs.values() if capability in str(job.get("steps", []))]
    assert len(matches) == 1
    return matches[0]


def artifact_step(job: dict[str, Any], artifact_name: str) -> dict[str, Any]:
    """Return the upload step for a named workflow artifact."""
    steps = job["steps"]
    matches = [
        step
        for step in steps
        if uses_major_action(step, "actions/upload-artifact")
        and step.get("with", {}).get("name") == artifact_name
    ]
    assert len(matches) == 1
    return matches[0]


def coverage_step(job: dict[str, Any], activity: str) -> dict[str, Any]:
    """Return the coverage-action step for an explicit activity."""
    matches = [
        step
        for step in job["steps"]
        if uses_major_action(step, "py-cov-action/python-coverage-comment-action")
        and step.get("with", {}).get("ACTIVITY") == activity
    ]
    assert len(matches) == 1
    return matches[0]


def coverage_job(workflow: dict[str, Any], activity: str) -> dict[str, Any]:
    """Return the unique job that invokes a coverage-action activity."""
    matches = [
        job
        for job in workflow["jobs"].values()
        if any(
            uses_major_action(step, "py-cov-action/python-coverage-comment-action")
            and step.get("with", {}).get("ACTIVITY") == activity
            for step in job.get("steps", [])
        )
    ]
    assert len(matches) == 1
    return matches[0]


def assert_dependabot_author_guard(condition: object) -> None:
    """Verify that trusted-base authorization runs for every bot-authored PR."""
    value = str(condition)
    assert "pull_request.user.login == 'dependabot[bot]'" in value
    for term in (
        "repository.fork == false",
        "pull_request.head.repo.full_name == github.repository",
        "pull_request.base.ref == github.event.repository.default_branch",
    ):
        assert term not in value


def assert_trusted_checkout_precedes_authorization(job: dict[str, Any]) -> None:
    """Verify authorization runs from a credential-free base-SHA checkout."""
    authorization_index, _ = step_with(job, "dependabot-auto-merge.mjs")
    steps = job["steps"]
    assert isinstance(steps, list)
    trusted_checkouts = [
        step
        for step in steps[:authorization_index]
        if step.get("uses", "").startswith("actions/checkout@")
        and step.get("with", {}).get("ref") == "${{ github.event.pull_request.base.sha }}"
    ]
    assert len(trusted_checkouts) == 1
    assert trusted_checkouts[0]["with"]["persist-credentials"] is False


def test_dependabot_workflows_use_trusted_ancestry_authorization() -> None:
    """Read-only authorization fetches files, commits, and every merge proof."""
    workflows = {
        "auto_merge": load_workflow(
            Path(".github/workflows/dependabot-auto-merge.yml"),
        ),
        "pytest": load_workflow(Path(".github/workflows/pytest_check.yml")),
    }
    for workflow in workflows.values():
        job = job_with(workflow, "dependabot-auto-merge.mjs")
        assert job["permissions"]["contents"] == "read"
        assert job["permissions"]["pull-requests"] == "read"
        assert all(permission in {"contents", "pull-requests"} for permission in job["permissions"])
        guard = job["if"] if "if" in job else job["steps"][0]["if"]
        assert_dependabot_author_guard(guard)
        assert_trusted_checkout_precedes_authorization(job)
        _, step = step_with(job, "dependabot-auto-merge.mjs")
        if "if" not in job:
            assert_dependabot_author_guard(step["if"])
        run = step["run"]
        assert step["env"]["BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
        assert "github.event.pull_request.base.sha" not in run
        assert 'base_sha="${BASE_SHA}"' in run
        assert "pulls/${PR_NUMBER}/files" in run
        assert "pulls/${PR_NUMBER}/commits" in run
        assert "compare/${second_parent}...${base_sha}" in run
        assert "dependabot-auto-merge.mjs" in run

    auto_merge = workflows["auto_merge"]
    authorization_name = next(
        name
        for name, job in auto_merge["jobs"].items()
        if "dependabot-auto-merge.mjs" in str(job.get("steps", []))
    )
    enable = job_with(auto_merge, "--auto --squash")
    assert enable["needs"] == authorization_name
    assert "if" not in enable
    cleanup = job_with(auto_merge, "--disable-auto")
    for term in (
        "repository.fork == false",
        "pull_request.user.login == 'dependabot[bot]'",
        "pull_request.head.repo.full_name == github.repository",
        "pull_request.base.ref == github.event.repository.default_branch",
    ):
        assert term in cleanup["if"]


def test_coverage_workflows_keep_pr_head_read_only_and_commenting_checkout_free() -> None:
    """PR-head tests remain read-only while workflow-run handles trusted writes."""
    pytest_check = load_workflow(Path(".github/workflows/pytest_check.yml"))
    pytest_post = load_workflow(Path(".github/workflows/pytest_post_coverage.yml"))
    check_job = coverage_job(pytest_check, "process_pr")

    assert "permissions" not in pytest_check
    assert check_job["permissions"]["contents"] == "read"
    assert check_job["permissions"]["pull-requests"] == "read"
    assert "write" not in check_job["permissions"].values()
    process_pr_step = coverage_step(check_job, "process_pr")
    assert uses_major_action(process_pr_step, "py-cov-action/python-coverage-comment-action")
    assert process_pr_step["with"]["MINIMUM_GREEN"] == 90
    assert process_pr_step["with"]["MINIMUM_ORANGE"] == 70
    comment_artifact = artifact_step(check_job, "python-coverage-comment-action")
    assert uses_major_action(comment_artifact, "actions/upload-artifact")
    coverage_artifact = artifact_step(check_job, "python-coverage-data")
    assert uses_major_action(coverage_artifact, "actions/upload-artifact")
    assert coverage_artifact["with"]["path"] == ".coverage"
    assert coverage_artifact["with"]["include-hidden-files"] is True
    assert "github.event_name == 'push'" in coverage_artifact["if"]
    assert "github.ref_name == github.event.repository.default_branch" in coverage_artifact["if"]

    publisher = coverage_job(pytest_post, "save_coverage_data_files")
    publisher_permissions = publisher["permissions"]
    assert publisher_permissions["actions"] == "read"
    assert publisher_permissions["contents"] == "write"
    assert all(permission in {"actions", "contents"} for permission in publisher_permissions)
    assert "concurrency" not in pytest_post
    assert publisher["concurrency"]["cancel-in-progress"] is True
    assert "github.event.repository.default_branch" in publisher["concurrency"]["group"]
    publisher_save = coverage_step(publisher, "save_coverage_data_files")
    assert publisher_save["with"]["MINIMUM_GREEN"] == 90
    assert publisher_save["with"]["MINIMUM_ORANGE"] == 70
    assert "workflow_run.event == 'push'" in publisher["if"]
    assert "workflow_run.head_branch == github.event.repository.default_branch" in publisher["if"]
    assert "workflow_run.head_repository.full_name == github.repository" in publisher["if"]
    checkout_index, publisher_checkout = next(
        (index, step)
        for index, step in enumerate(publisher["steps"])
        if uses_major_action(step, "actions/checkout")
    )
    checkout_with = publisher_checkout["with"]
    assert checkout_with["persist-credentials"] is False
    assert checkout_with["ref"] == "${{ github.event.repository.default_branch }}"
    verification_index, verification = step_with(publisher, "git rev-parse HEAD")
    assert verification["env"]["EXPECTED_SHA"] == "${{ github.event.workflow_run.head_sha }}"
    artifact_index, publisher_artifact = step_with(publisher, "python-coverage-data")
    assert uses_major_action(publisher_artifact, "actions/download-artifact")
    artifact_with = publisher_artifact["with"]
    assert artifact_with["github-token"] == "${{ secrets.GITHUB_TOKEN }}"
    assert artifact_with["name"] == "python-coverage-data"
    assert artifact_with["path"] == "."
    assert artifact_with["run-id"] == "${{ github.event.workflow_run.id }}"
    save_index, _ = step_with(publisher, "save_coverage_data_files")
    assert checkout_index < verification_index < artifact_index < save_index

    commenter = coverage_job(pytest_post, "post_comment")
    assert commenter["permissions"]["actions"] == "read"
    assert commenter["permissions"]["contents"] == "read"
    assert commenter["permissions"]["pull-requests"] == "write"
    assert all(
        permission in {"actions", "contents", "pull-requests"}
        for permission in commenter["permissions"]
    )
    assert "concurrency" not in commenter
    assert not any(uses_major_action(step, "actions/checkout") for step in commenter["steps"])
    contents_writers = [
        job
        for job in pytest_post["jobs"].values()
        if job.get("permissions", {}).get("contents") == "write"
    ]
    assert len(contents_writers) == 1
    assert contents_writers[0] is publisher
