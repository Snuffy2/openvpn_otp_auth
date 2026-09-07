"""Validate and atomically promote OpenVPN OTP Auth release references."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys

VERSION_FILE = Path("src/openvpn_otp_auth/_version.py")
RELEASE_TAG_PATTERN = re.compile(r"^v\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?$")
VERSION_PATTERN = re.compile(r'^VERSION = "([^"]+)"$', re.MULTILINE)


class ReleaseStateError(RuntimeError):
    """Raised when release metadata or references are not safe to promote."""


@dataclass(frozen=True)
class ReleaseState:
    """Validated state of the release tag and target branch."""

    mode: str
    source_sha: str
    target_sha: str
    tag_oid: str
    candidate_sha: str


def run_git(arguments: Sequence[str], *, repository: Path) -> str:
    """Run git in a repository and return stripped standard output.

    Args:
        arguments: Arguments after ``git``.
        repository: Repository that owns the refs.

    Returns:
        Command standard output without trailing whitespace.

    Raises:
        ReleaseStateError: If git rejects the requested operation.
    """
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise ReleaseStateError(detail)
    return result.stdout.strip()


def require_release_tag(release_tag: str) -> None:
    """Require a supported, immutable semantic release tag.

    Args:
        release_tag: Requested GitHub release tag.

    Raises:
        ReleaseStateError: If the tag cannot represent a package release.
    """
    if not RELEASE_TAG_PATTERN.fullmatch(release_tag):
        raise ReleaseStateError(f"Unsupported release tag {release_tag!r}.")


def is_prerelease_tag(release_tag: str) -> bool:
    """Return whether a validated tag is a prerelease version.

    Args:
        release_tag: Requested release tag.

    Returns:
        Whether the tag has an accepted prerelease suffix.
    """
    require_release_tag(release_tag)
    return re.search(r"(?:a|b|rc)\d+$", release_tag) is not None


def version_from_text(text: str, *, source: str) -> str:
    """Read the single package version assignment from source text.

    Args:
        text: Version module contents.
        source: Human-readable source label for errors.

    Returns:
        The version string.

    Raises:
        ReleaseStateError: If the version assignment is absent or ambiguous.
    """
    matches = VERSION_PATTERN.findall(text)
    if len(matches) != 1:
        raise ReleaseStateError(f"{source} must contain exactly one VERSION assignment.")
    return matches[0]


def version_at(repository: Path, revision: str) -> str:
    """Read the package version at a Git revision.

    Args:
        repository: Git repository.
        revision: Commit or tag revision.

    Returns:
        The version stored in the tracked module.
    """
    contents = run_git(["show", f"{revision}:{VERSION_FILE.as_posix()}"], repository=repository)
    return version_from_text(contents, source=f"{revision}:{VERSION_FILE}")


def version_module_at(repository: Path, revision: str) -> str:
    """Read the raw version module at a Git revision.

    Args:
        repository: Repository containing the revision.
        revision: Commit revision to inspect.

    Returns:
        Raw version-module contents.
    """
    return run_git(["show", f"{revision}:{VERSION_FILE.as_posix()}"], repository=repository)


def parent_count(repository: Path, revision: str) -> int:
    """Return the number of parents for a commit.

    Args:
        repository: Git repository.
        revision: Commit revision.

    Returns:
        Number of direct parents.
    """
    return (
        len(run_git(["rev-list", "--parents", "-n", "1", revision], repository=repository).split())
        - 1
    )


def is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    """Return whether one commit is an ancestor of another.

    Args:
        repository: Git repository.
        ancestor: Candidate earlier commit.
        descendant: Candidate later commit.

    Returns:
        ``True`` when ``ancestor`` is reachable from ``descendant``.
    """
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode in (0, 1):
        return result.returncode == 0
    raise ReleaseStateError(result.stderr.strip() or "Could not compare release ancestry.")


def validate_state(
    repository: Path,
    *,
    release_tag: str,
    target_ref: str,
    prerelease: bool,
    event_sha: str,
) -> ReleaseState:
    """Validate fresh, resumed stable, or prerelease starting refs.

    Args:
        repository: Repository with fetched target and tag refs.
        release_tag: Immutable release tag.
        target_ref: Fully qualified local target ref.
        prerelease: Whether the GitHub release is a prerelease.
        event_sha: Immutable release-event commit SHA.

    Returns:
        The safe release state.

    Raises:
        ReleaseStateError: If refs cannot represent the requested release.
    """
    require_release_tag(release_tag)
    if not re.fullmatch(r"[0-9a-f]{40}", event_sha):
        raise ReleaseStateError("Release event SHA must be a lowercase full Git SHA.")
    if is_prerelease_tag(release_tag) != prerelease:
        raise ReleaseStateError("Release prerelease flag does not match the release tag.")
    target_sha = run_git(["rev-parse", target_ref], repository=repository)
    tag_sha = run_git(["rev-parse", f"refs/tags/{release_tag}^{{}}"], repository=repository)
    tag_oid = run_git(["rev-parse", f"refs/tags/{release_tag}"], repository=repository)
    tag_version = version_at(repository, tag_sha)

    if prerelease:
        if (
            event_sha != tag_sha
            or tag_version != release_tag
            or not is_ancestor(repository, tag_sha, target_sha)
        ):
            raise ReleaseStateError("Prerelease tag must be a matching default-branch commit.")
        return ReleaseState("prerelease", tag_sha, target_sha, tag_oid, tag_sha)

    subject = run_git(["log", "-1", "--format=%s", tag_sha], repository=repository)
    if subject == f"Release {release_tag}":
        parent = run_git(["rev-parse", f"{tag_sha}^"], repository=repository)
        changed = run_git(
            ["diff-tree", "--no-commit-id", "--name-only", "-r", tag_sha], repository=repository
        )
        if (
            parent_count(repository, tag_sha) != 1
            or tag_version != release_tag
            or parent != event_sha
            or changed != VERSION_FILE.as_posix()
            or not is_ancestor(repository, tag_sha, target_sha)
        ):
            raise ReleaseStateError("Existing release tag is not a valid promoted candidate.")
        parent_module = version_module_at(repository, parent)
        candidate_module = version_module_at(repository, tag_sha)
        expected, replacements = VERSION_PATTERN.subn(
            f'VERSION = "{release_tag}"', parent_module, count=1
        )
        if replacements != 1 or candidate_module != expected:
            raise ReleaseStateError(
                "Existing release tag does not contain the deterministic version update."
            )
        return ReleaseState("resume", tag_sha, target_sha, tag_oid, tag_sha)

    if target_sha != tag_sha or event_sha != target_sha:
        raise ReleaseStateError("Release tag and default branch must start at the same commit.")
    return ReleaseState("fresh", target_sha, target_sha, tag_oid, "")


def create_annotated_tag(repository: Path, *, release_tag: str, candidate_sha: str) -> None:
    """Create the local annotated tag that will move under a lease.

    Args:
        repository: Git repository.
        release_tag: Requested tag.
        candidate_sha: Candidate commit to tag.
    """
    run_git(
        ["tag", "-fa", release_tag, candidate_sha, "-m", f"Release {release_tag}"],
        repository=repository,
    )


def promote(
    repository: Path,
    *,
    remote: str,
    target_branch: str,
    expected_target_sha: str,
    release_tag: str,
    expected_tag_oid: str,
    candidate_sha: str,
) -> None:
    """Atomically promote one candidate branch and annotated release tag.

    Args:
        repository: Repository containing the candidate commit.
        remote: Remote name used for promotion.
        target_branch: Default branch name.
        expected_target_sha: Original target commit lease.
        release_tag: Immutable tag to advance.
        expected_tag_oid: Original tag object lease.
        candidate_sha: Candidate commit to promote.

    Raises:
        ReleaseStateError: If candidate ancestry or an atomic push fails.
    """
    remote_target = f"refs/remotes/{remote}/{target_branch}"
    remote_tag = f"refs/tags/{release_tag}"
    if run_git(["rev-parse", remote_target], repository=repository) != expected_target_sha:
        raise ReleaseStateError("Default branch changed before promotion.")
    if run_git(["rev-parse", remote_tag], repository=repository) != expected_tag_oid:
        raise ReleaseStateError("Release tag changed before promotion.")
    if (
        parent_count(repository, candidate_sha) != 1
        or run_git(["rev-parse", f"{candidate_sha}^"], repository=repository) != expected_target_sha
    ):
        raise ReleaseStateError("Candidate is not the deterministic child of the release target.")
    create_annotated_tag(repository, release_tag=release_tag, candidate_sha=candidate_sha)
    run_git(
        [
            "push",
            "--atomic",
            f"--force-with-lease=refs/heads/{target_branch}:{expected_target_sha}",
            f"--force-with-lease=refs/tags/{release_tag}:{expected_tag_oid}",
            remote,
            f"{candidate_sha}:refs/heads/{target_branch}",
            f"refs/tags/{release_tag}:refs/tags/{release_tag}",
        ],
        repository=repository,
    )


def write_outputs(state: ReleaseState) -> None:
    """Print GitHub Actions output values for a release state.

    Args:
        state: Validated release state.
    """
    for key, value in (
        ("mode", state.mode),
        ("source-sha", state.source_sha),
        ("target-sha", state.target_sha),
        ("tag-oid", state.tag_oid),
        ("candidate-sha", state.candidate_sha),
    ):
        print(f"{key}={value}")


def parse_arguments() -> argparse.Namespace:
    """Parse the release ref helper command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--repository", type=Path, default=Path())
    validate.add_argument("--release-tag", required=True)
    validate.add_argument("--target-ref", required=True)
    validate.add_argument("--prerelease", choices=("true", "false"), required=True)
    validate.add_argument("--event-sha", required=True)
    promote_parser = subparsers.add_parser("promote")
    promote_parser.add_argument("--repository", type=Path, default=Path())
    promote_parser.add_argument("--remote", default="origin")
    promote_parser.add_argument("--target-branch", required=True)
    promote_parser.add_argument("--expected-target-sha", required=True)
    promote_parser.add_argument("--release-tag", required=True)
    promote_parser.add_argument("--expected-tag-oid", required=True)
    promote_parser.add_argument("--candidate-sha", required=True)
    return parser.parse_args()


def main() -> int:
    """Run release ref validation or promotion."""
    arguments = parse_arguments()
    try:
        if arguments.command == "validate":
            state = validate_state(
                arguments.repository,
                release_tag=arguments.release_tag,
                target_ref=arguments.target_ref,
                prerelease=arguments.prerelease == "true",
                event_sha=arguments.event_sha,
            )
            write_outputs(state)
        else:
            promote(
                arguments.repository,
                remote=arguments.remote,
                target_branch=arguments.target_branch,
                expected_target_sha=arguments.expected_target_sha,
                release_tag=arguments.release_tag,
                expected_tag_oid=arguments.expected_tag_oid,
                candidate_sha=arguments.candidate_sha,
            )
    except ReleaseStateError as error:
        print(f"Release reference validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
