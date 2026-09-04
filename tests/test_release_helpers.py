"""Behavior tests for the release candidate trust and promotion boundaries."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
from io import BytesIO
from pathlib import Path
import subprocess
import sys
import tarfile
from types import ModuleType
import zipfile

import pytest


def load_script(name: str) -> ModuleType:
    """Load one release helper without making workflow scripts a package.

    Args:
        name: Script filename without its ``.py`` suffix.

    Returns:
        Loaded module.
    """
    path = Path(__file__).parents[1] / ".github" / "scripts" / f"{name}.py"
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


candidate = load_script("verify_release_candidate")
release_refs = load_script("release_refs")


def write_bytes_to_tar(archive: tarfile.TarFile, name: str, contents: bytes) -> None:
    """Add regular bytes to a gzip source distribution.

    Args:
        archive: Open source-distribution archive.
        name: Archive member name.
        contents: Bytes to store.
    """
    member = tarfile.TarInfo(name)
    member.size = len(contents)
    archive.addfile(member, BytesIO(contents))


def write_directory_to_tar(archive: tarfile.TarFile, name: str) -> None:
    """Add one expected directory header to the synthetic source distribution.

    Args:
        archive: Open source-distribution archive.
        name: Directory member name without a trailing slash.
    """
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    archive.addfile(member)


def rewrite_sdist_member(sdist: Path, member_name: str, replacement: bytes) -> None:
    """Replace one regular synthetic sdist member while retaining the archive layout.

    Args:
        sdist: Source distribution to rewrite.
        member_name: Exact member whose bytes must be replaced.
        replacement: New untrusted bytes for that member.
    """
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(sdist, "r:gz") as source:
        for member in source:
            extracted = source.extractfile(member)
            if member.isfile():
                assert extracted is not None
                members.append((member, extracted.read()))
            else:
                members.append((member, None))
    with tarfile.open(sdist, "w:gz") as target:
        for member, contents in members:
            clone = tarfile.TarInfo(member.name)
            clone.type = member.type
            clone.mode = member.mode
            clone.size = len(replacement) if member.name == member_name else member.size
            if clone.isfile():
                assert contents is not None
                target.addfile(
                    clone, BytesIO(replacement if member.name == member_name else contents)
                )
            else:
                target.addfile(clone)


def distribution_metadata(source_root: Path, release_tag: str) -> bytes:
    """Create canonical test metadata from the verifier's trusted inputs.

    Args:
        source_root: Root containing the synthetic trusted pyproject.
        release_tag: Candidate release tag.

    Returns:
        RFC metadata bytes with the exact trusted README body.
    """
    headers = candidate.expected_metadata_headers(source_root, release_tag)
    lines = [f"{name}: {value}" for name, values in headers.items() for value in values]
    return ("\n".join(lines) + "\n\n").encode() + (source_root / "README.md").read_bytes()


def make_candidate_artifact(
    candidate_directory: Path, trusted_source: Path, release_tag: str
) -> None:
    """Create a package-shaped candidate artifact from trusted test source.

    Args:
        candidate_directory: Candidate artifact directory to write.
        trusted_source: Trusted package source directory.
        release_tag: Requested package release tag.
    """
    version_path = trusted_source / "_version.py"
    expected_version = candidate.expected_version_module(version_path, release_tag)
    package = candidate.expected_payload(trusted_source, expected_version)
    metadata = candidate.expected_metadata_files(trusted_source.parents[1], release_tag)
    distribution = distribution_metadata(trusted_source.parents[1], release_tag)
    version = candidate.normalized_version(release_tag)
    dist = candidate_directory / "dist"
    dist.mkdir(parents=True)
    (candidate_directory / "_version.py").write_bytes(expected_version)
    wheel = dist / f"openvpn_otp_auth-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for relative, contents in package.items():
            archive.writestr(f"openvpn_otp_auth/{relative}", contents)
        archive.writestr(
            f"openvpn_otp_auth-{version}.dist-info/METADATA",
            distribution,
        )
        dist_info = f"openvpn_otp_auth-{version}.dist-info"
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: setuptools (80.0.0)\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/licenses/LICENSE", metadata["LICENSE"])
        archive.writestr(f"{dist_info}/entry_points.txt", metadata["entry_points.txt"])
        archive.writestr(f"{dist_info}/top_level.txt", metadata["top_level.txt"])
        members = {name: archive.read(name) for name in archive.namelist()}
        record_lines = []
        for name, contents in members.items():
            digest = (
                base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode().rstrip("=")
            )
            record_lines.append(f"{name},sha256={digest},{len(contents)}\n")
        record_lines.append(f"{dist_info}/RECORD,,\n")
        archive.writestr(f"{dist_info}/RECORD", "".join(record_lines))
    sdist = dist / f"openvpn_otp_auth-{version}.tar.gz"
    root = f"openvpn_otp_auth-{version}"
    with tarfile.open(sdist, "w:gz") as archive:
        for name in (
            root,
            f"{root}/src",
            f"{root}/src/openvpn_otp_auth",
            f"{root}/src/openvpn_otp_auth.egg-info",
        ):
            write_directory_to_tar(archive, name)
        for relative, contents in package.items():
            write_bytes_to_tar(archive, f"{root}/src/openvpn_otp_auth/{relative}", contents)
        for name in ("LICENSE", "README.md", "pyproject.toml"):
            write_bytes_to_tar(archive, f"{root}/{name}", metadata[name])
        write_bytes_to_tar(
            archive,
            f"{root}/PKG-INFO",
            distribution,
        )
        write_bytes_to_tar(
            archive, f"{root}/setup.cfg", b"[egg_info]\ntag_build = \ntag_date = 0\n\n"
        )
        egg = f"{root}/src/openvpn_otp_auth.egg-info"
        write_bytes_to_tar(archive, f"{egg}/PKG-INFO", distribution)
        for name in ("dependency_links.txt", "entry_points.txt", "requires.txt", "top_level.txt"):
            write_bytes_to_tar(archive, f"{egg}/{name}", metadata[name])
        root_names = {
            f"{root}/{name}"
            for name in ("LICENSE", "README.md", "pyproject.toml", "PKG-INFO", "setup.cfg")
        }
        root_names.update(f"{root}/src/openvpn_otp_auth/{name}" for name in package)
        root_names.update(
            f"{root}/src/openvpn_otp_auth.egg-info/{name}"
            for name in (
                "PKG-INFO",
                "SOURCES.txt",
                "dependency_links.txt",
                "entry_points.txt",
                "requires.txt",
                "top_level.txt",
            )
        )
        package_sources = sorted(f"src/openvpn_otp_auth/{name}" for name in package)
        egg_sources = [
            f"src/openvpn_otp_auth.egg-info/{name}"
            for name in (
                "PKG-INFO",
                "SOURCES.txt",
                "dependency_links.txt",
                "entry_points.txt",
                "requires.txt",
                "top_level.txt",
            )
        ]
        sources = "\n".join(
            ["LICENSE", "README.md", "pyproject.toml", *package_sources, *egg_sources]
        )
        write_bytes_to_tar(archive, f"{egg}/SOURCES.txt", sources.encode())


@pytest.fixture
def trusted_source(tmp_path: Path) -> Path:
    """Create a small trusted package source tree.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Package source directory.
    """
    source = tmp_path / "trusted" / "src" / "openvpn_otp_auth"
    source.mkdir(parents=True)
    root = source.parents[1]
    (root / "LICENSE").write_text("trusted license\n")
    (root / "README.md").write_text("trusted readme\n")
    (root / "pyproject.toml").write_text(
        "[project]\nname = 'openvpn-otp-auth'\ndescription = 'Trusted helper'\n"
        "requires-python = '>=3.14'\nlicense = 'Apache-2.0'\nlicense-files = ['LICENSE']\n"
        "authors = [{ name = 'Test' }]\nkeywords = ['trusted']\nclassifiers = ['Topic :: Security']\n"
        "dependencies = ['trusted-dependency']\n[project.urls]\nSource = 'https://example.invalid/source'\n"
        "[project.scripts]\nopenvpn-otp-auth = 'openvpn_otp_auth:cli'\n"
    )
    (source / "__init__.py").write_text("from .main import value\n")
    (source / "main.py").write_text("def value() -> str:\n    return 'trusted'\n")
    (source / "_version.py").write_text('VERSION = "v1.4.1"\n')
    return source


def test_verified_candidate_copies_exact_trusted_payload(
    tmp_path: Path, trusted_source: Path
) -> None:
    """A valid candidate is copied only after source and metadata identity checks."""
    handoff = tmp_path / "handoff"
    make_candidate_artifact(handoff, trusted_source, "v1.4.2")
    output = tmp_path / "verified"

    candidate.verify_candidate(
        handoff,
        trusted_source,
        trusted_source / "_version.py",
        output,
        "v1.4.2",
    )

    assert (output / "_version.py").read_text() == 'VERSION = "v1.4.2"\n'
    expected_wheel = handoff / "dist" / "openvpn_otp_auth-1.4.2-py3-none-any.whl"
    copied_wheel = output / "dist" / expected_wheel.name
    assert (
        hashlib.sha256(copied_wheel.read_bytes()).digest()
        == hashlib.sha256(expected_wheel.read_bytes()).digest()
    )


def test_candidate_rejects_altered_package_payload_before_copy(
    tmp_path: Path, trusted_source: Path
) -> None:
    """A forged wheel package module cannot reach the verified output directory."""
    handoff = tmp_path / "handoff"
    make_candidate_artifact(handoff, trusted_source, "v1.4.2")
    wheel = handoff / "dist" / "openvpn_otp_auth-1.4.2-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    members["openvpn_otp_auth/main.py"] = b"def value() -> str:\n    return 'forged'\n"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, contents in members.items():
            archive.writestr(name, contents)

    with pytest.raises(candidate.CandidateVerificationError, match="payload differs"):
        candidate.verify_candidate(
            handoff,
            trusted_source,
            trusted_source / "_version.py",
            tmp_path / "verified",
            "v1.4.2",
        )

    assert not (tmp_path / "verified").exists()


def test_candidate_rejects_oversized_handoff_before_archive_inspection(
    tmp_path: Path, trusted_source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bounded handoff fails before wheel or sdist parsing starts."""
    handoff = tmp_path / "handoff"
    make_candidate_artifact(handoff, trusted_source, "v1.4.2")
    wheel = handoff / "dist" / "openvpn_otp_auth-1.4.2-py3-none-any.whl"
    wheel.write_bytes(b"x" * (candidate.MAX_FILE_BYTES + 1))
    monkeypatch.setattr(candidate, "verify_wheel", pytest.fail)

    with pytest.raises(candidate.CandidateVerificationError, match="exceeds"):
        candidate.verify_candidate(
            handoff,
            trusted_source,
            trusted_source / "_version.py",
            tmp_path / "verified",
            "v1.4.2",
        )


def test_candidate_rejects_unlisted_wheel_script_before_copy(
    tmp_path: Path, trusted_source: Path
) -> None:
    """A wheel cannot smuggle a data-script member beside trusted package files."""
    handoff = tmp_path / "handoff"
    make_candidate_artifact(handoff, trusted_source, "v1.4.2")
    wheel = handoff / "dist" / "openvpn_otp_auth-1.4.2-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("openvpn_otp_auth-1.4.2.data/scripts/forged", b"#!/bin/sh\n")

    with pytest.raises(candidate.CandidateVerificationError, match="unexpected or missing"):
        candidate.verify_candidate(
            handoff,
            trusted_source,
            trusted_source / "_version.py",
            tmp_path / "verified",
            "v1.4.2",
        )

    assert not (tmp_path / "verified").exists()


def test_candidate_rejects_forged_wheel_dependency_metadata_before_copy(
    tmp_path: Path, trusted_source: Path
) -> None:
    """Installer dependencies in wheel METADATA must equal trusted pyproject inputs."""
    handoff = tmp_path / "handoff"
    make_candidate_artifact(handoff, trusted_source, "v1.4.2")
    wheel = handoff / "dist" / "openvpn_otp_auth-1.4.2-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    metadata_name = "openvpn_otp_auth-1.4.2.dist-info/METADATA"
    members[metadata_name] = members[metadata_name].replace(
        b"\n\ntrusted readme", b"\nRequires-Dist: forged-installer\n\ntrusted readme"
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, contents in members.items():
            archive.writestr(name, contents)

    with pytest.raises(candidate.CandidateVerificationError, match="Requires-Dist"):
        candidate.verify_candidate(
            handoff, trusted_source, trusted_source / "_version.py", tmp_path / "verified", "v1.4.2"
        )
    assert not (tmp_path / "verified").exists()


def test_candidate_rejects_wheel_record_digest_and_installer_tag_before_copy(
    tmp_path: Path, trusted_source: Path
) -> None:
    """WHEEL compatibility fields and RECORD digests cannot be forged."""
    handoff = tmp_path / "handoff"
    make_candidate_artifact(handoff, trusted_source, "v1.4.2")
    wheel = handoff / "dist" / "openvpn_otp_auth-1.4.2-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    wheel_name = "openvpn_otp_auth-1.4.2.dist-info/WHEEL"
    members[wheel_name] = members[wheel_name].replace(b"py3-none-any", b"py2-none-any")
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, contents in members.items():
            archive.writestr(name, contents)

    with pytest.raises(candidate.CandidateVerificationError, match="py3-none-any"):
        candidate.verify_candidate(
            handoff, trusted_source, trusted_source / "_version.py", tmp_path / "verified", "v1.4.2"
        )
    assert not (tmp_path / "verified").exists()


def test_candidate_rejects_wheel_record_digest_before_copy(
    tmp_path: Path, trusted_source: Path
) -> None:
    """RECORD hashes are checked after all allowed wheel members are read."""
    handoff = tmp_path / "handoff"
    make_candidate_artifact(handoff, trusted_source, "v1.4.2")
    wheel = handoff / "dist" / "openvpn_otp_auth-1.4.2-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    record_name = "openvpn_otp_auth-1.4.2.dist-info/RECORD"
    members[record_name] = members[record_name].replace(b"sha256=", b"sha256=x", 1)
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, contents in members.items():
            archive.writestr(name, contents)
    with pytest.raises(candidate.CandidateVerificationError, match="RECORD digest"):
        candidate.verify_candidate(
            handoff, trusted_source, trusted_source / "_version.py", tmp_path / "verified", "v1.4.2"
        )
    assert not (tmp_path / "verified").exists()


@pytest.mark.parametrize(
    "member_suffix",
    [
        "PKG-INFO",
        "src/openvpn_otp_auth.egg-info/PKG-INFO",
        "src/openvpn_otp_auth.egg-info/SOURCES.txt",
    ],
)
def test_candidate_rejects_forged_sdist_metadata_before_copy(
    tmp_path: Path, trusted_source: Path, member_suffix: str
) -> None:
    """Both sdist metadata copies and its source manifest are trusted boundaries."""
    handoff = tmp_path / "handoff"
    make_candidate_artifact(handoff, trusted_source, "v1.4.2")
    sdist = handoff / "dist" / "openvpn_otp_auth-1.4.2.tar.gz"
    name = f"openvpn_otp_auth-1.4.2/{member_suffix}"
    replacement = (
        b"forged\n"
        if member_suffix.endswith("SOURCES.txt")
        else b"Name: openvpn-otp-auth\nVersion: 1.4.2\nRequires-Dist: forged\n\ntrusted readme\n"
    )
    rewrite_sdist_member(sdist, name, replacement)
    with pytest.raises(candidate.CandidateVerificationError):
        candidate.verify_candidate(
            handoff, trusted_source, trusted_source / "_version.py", tmp_path / "verified", "v1.4.2"
        )
    assert not (tmp_path / "verified").exists()


@pytest.mark.parametrize(
    ("setting", "value", "match"),
    [
        ("MAX_ARCHIVE_MEMBERS", 1, "excessive member count"),
        ("MAX_ARCHIVE_CONTENT_BYTES", 1, "decompressed content limit"),
    ],
)
def test_candidate_enforces_streaming_sdist_limits_before_copy(
    tmp_path: Path,
    trusted_source: Path,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
    value: int,
    match: str,
) -> None:
    """Member-count and decompressed content bounds run on the public sdist path."""
    handoff = tmp_path / "handoff"
    make_candidate_artifact(handoff, trusted_source, "v1.4.2")
    monkeypatch.setattr(candidate, setting, value)
    if setting == "MAX_ARCHIVE_CONTENT_BYTES":
        monkeypatch.setattr(candidate, "verify_wheel", lambda *_args: None)
    with pytest.raises(candidate.CandidateVerificationError, match=match):
        candidate.verify_candidate(
            handoff, trusted_source, trusted_source / "_version.py", tmp_path / "verified", "v1.4.2"
        )
    assert not (tmp_path / "verified").exists()


def test_release_workflow_binds_immutable_event_sha_at_all_state_boundaries() -> None:
    """Candidate checkout and every release-state validation use the event SHA."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    assert "- name: Checkout immutable release event commit" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    state_steps = [
        "Prove the prerelease tag is already a matching default-branch commit",
        "Validate immutable starting refs or an exact resume candidate",
    ]
    for name in state_steps:
        block = workflow[workflow.index(f"- name: {name}") :]
        block = block[: block.find("\n      - name:", 1)]
        assert "RELEASE_EVENT_SHA: ${{ github.sha }}" in block
        assert '--event-sha "$RELEASE_EVENT_SHA"' in block


def test_release_workflow_authenticates_only_the_trusted_promotion_push() -> None:
    """The write-scoped promotion can push without persisting checkout credentials."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    promotion = workflow[workflow.index("- name: Atomically advance default branch") :]
    promotion = promotion[: promotion.find("\n      - name:", 1)]

    assert "GH_TOKEN: ${{ github.token }}" in promotion
    assert "gh auth setup-git --hostname github.com" in promotion
    assert promotion.index("gh auth setup-git --hostname github.com") < promotion.index(
        "release_refs.py promote"
    )
    checkout = workflow[
        workflow.index("- name: Checkout trusted default-branch workflow revision") :
    ]
    checkout = checkout[: checkout.find("\n      - name:", 1)]
    assert "persist-credentials: false" in checkout


def test_candidate_rejects_declared_archive_bomb_before_member_read() -> None:
    """Declared decompressed limits fail before an archive member can be opened."""
    with pytest.raises(candidate.CandidateVerificationError, match="uncompressed content limit"):
        candidate.bounded_member_sizes(
            [candidate.MAX_ARCHIVE_MEMBER_BYTES] * 3, source="test archive"
        )


def git(repository: Path, *arguments: str) -> str:
    """Run a local Git command for release promotion behavior tests.

    Args:
        repository: Repository in which to run Git.
        *arguments: Arguments after ``git``.

    Returns:
        Stripped standard output.
    """
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def create_release_repository(tmp_path: Path) -> tuple[Path, Path, str, str]:
    """Create a bare remote with main and a fresh lightweight release tag.

    Args:
        tmp_path: Temporary test root.

    Returns:
        Worktree, bare remote, initial main SHA, and initial tag object ID.
    """
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    seed = tmp_path / "seed"
    git(tmp_path, "init", "seed")
    git(seed, "config", "user.name", "Test")
    git(seed, "config", "user.email", "test@example.invalid")
    version = seed / "src" / "openvpn_otp_auth" / "_version.py"
    version.parent.mkdir(parents=True)
    version.write_text('VERSION = "v1.4.1"\n')
    git(seed, "add", ".")
    git(seed, "commit", "-m", "base")
    git(seed, "branch", "-M", "main")
    git(seed, "remote", "add", "origin", str(remote))
    git(seed, "push", "-u", "origin", "main")
    git(seed, "tag", "v1.4.2")
    git(seed, "push", "origin", "v1.4.2")
    initial_sha = git(seed, "rev-parse", "HEAD")
    initial_tag_oid = git(seed, "rev-parse", "refs/tags/v1.4.2")
    worktree = tmp_path / "worktree"
    subprocess.run(["git", "clone", str(remote), str(worktree)], check=True, capture_output=True)
    git(worktree, "checkout", "main")
    return worktree, remote, initial_sha, initial_tag_oid


def create_candidate_commit(worktree: Path) -> str:
    """Create the deterministic release commit in a test worktree.

    Args:
        worktree: Worktree based on the release target.

    Returns:
        Candidate commit SHA.
    """
    git(worktree, "config", "user.name", "Test")
    git(worktree, "config", "user.email", "test@example.invalid")
    version = worktree / "src" / "openvpn_otp_auth" / "_version.py"
    version.write_text('VERSION = "v1.4.2"\n')
    git(worktree, "add", str(version.relative_to(worktree)))
    git(worktree, "commit", "-m", "Release v1.4.2")
    return git(worktree, "rev-parse", "HEAD")


def test_promotion_advances_main_and_tag_together(tmp_path: Path) -> None:
    """The successful path produces an annotated tag for the promoted commit."""
    worktree, remote, base_sha, tag_oid = create_release_repository(tmp_path)
    candidate_sha = create_candidate_commit(worktree)

    release_refs.promote(
        worktree,
        remote="origin",
        target_branch="main",
        expected_target_sha=base_sha,
        release_tag="v1.4.2",
        expected_tag_oid=tag_oid,
        candidate_sha=candidate_sha,
    )

    assert git(worktree, "--git-dir", str(remote), "rev-parse", "refs/heads/main") == candidate_sha
    assert (
        git(worktree, "--git-dir", str(remote), "rev-parse", "refs/tags/v1.4.2^{}") == candidate_sha
    )
    assert git(worktree, "--git-dir", str(remote), "cat-file", "-t", "refs/tags/v1.4.2") == "tag"
    resumed = release_refs.validate_state(
        worktree,
        release_tag="v1.4.2",
        target_ref="refs/remotes/origin/main",
        prerelease=False,
        event_sha=base_sha,
    )
    assert resumed.mode == "resume"
    assert resumed.candidate_sha == candidate_sha
    with pytest.raises(release_refs.ReleaseStateError, match="valid promoted candidate"):
        release_refs.validate_state(
            worktree,
            release_tag="v1.4.2",
            target_ref="refs/remotes/origin/main",
            prerelease=False,
            event_sha="0" * 40,
        )


def test_mismatched_starting_tag_fails_before_promotion(tmp_path: Path) -> None:
    """A release tag behind its target cannot create a candidate or move refs."""
    worktree, remote, base_sha, tag_oid = create_release_repository(tmp_path)
    target_sha = create_candidate_commit(worktree)

    with pytest.raises(release_refs.ReleaseStateError, match="must start at the same commit"):
        release_refs.validate_state(
            worktree,
            release_tag="v1.4.2",
            target_ref=target_sha,
            prerelease=False,
            event_sha=base_sha,
        )

    assert git(worktree, "--git-dir", str(remote), "rev-parse", "refs/tags/v1.4.2") == tag_oid


def test_stable_tag_rejects_prerelease_event_flag(tmp_path: Path) -> None:
    """A release event cannot classify a stable tag as a prerelease candidate."""
    worktree, _, base_sha, _ = create_release_repository(tmp_path)

    with pytest.raises(release_refs.ReleaseStateError, match="prerelease flag"):
        release_refs.validate_state(
            worktree,
            release_tag="v1.4.2",
            target_ref="refs/remotes/origin/main",
            prerelease=True,
            event_sha=base_sha,
        )


def test_fresh_release_rejects_a_different_event_sha(tmp_path: Path) -> None:
    """Fresh promotion can only begin at the immutable release event commit."""
    worktree, _, base_sha, _ = create_release_repository(tmp_path)

    with pytest.raises(release_refs.ReleaseStateError, match="start at the same commit"):
        release_refs.validate_state(
            worktree,
            release_tag="v1.4.2",
            target_ref="refs/remotes/origin/main",
            prerelease=False,
            event_sha="0" * 40 if base_sha != "0" * 40 else "1" * 40,
        )


def test_prerelease_event_sha_must_match_the_tagged_default_branch_commit(tmp_path: Path) -> None:
    """Prerelease validation accepts only the immutable event commit at its tag."""
    worktree, _, _, _ = create_release_repository(tmp_path)
    version = worktree / "src" / "openvpn_otp_auth" / "_version.py"
    version.write_text('VERSION = "v1.4.2rc1"\n')
    git(worktree, "add", str(version.relative_to(worktree)))
    git(worktree, "commit", "-m", "prerelease")
    prerelease_sha = git(worktree, "rev-parse", "HEAD")
    git(worktree, "push", "origin", "main")
    git(worktree, "tag", "v1.4.2rc1")
    git(worktree, "push", "origin", "v1.4.2rc1")

    accepted = release_refs.validate_state(
        worktree,
        release_tag="v1.4.2rc1",
        target_ref="refs/remotes/origin/main",
        prerelease=True,
        event_sha=prerelease_sha,
    )
    assert accepted.mode == "prerelease"
    with pytest.raises(release_refs.ReleaseStateError, match="matching default-branch"):
        release_refs.validate_state(
            worktree,
            release_tag="v1.4.2rc1",
            target_ref="refs/remotes/origin/main",
            prerelease=True,
            event_sha="0" * 40,
        )


def test_resume_rejects_a_candidate_with_extra_changes(tmp_path: Path) -> None:
    """Resume accepts only a one-file deterministic child of the event commit."""
    worktree, remote, base_sha, tag_oid = create_release_repository(tmp_path)
    candidate_sha = create_candidate_commit(worktree)
    (worktree / "README.md").write_text("forged extra change\n")
    git(worktree, "add", "README.md")
    git(worktree, "commit", "--amend", "--no-edit")
    candidate_sha = git(worktree, "rev-parse", "HEAD")
    release_refs.promote(
        worktree,
        remote="origin",
        target_branch="main",
        expected_target_sha=base_sha,
        release_tag="v1.4.2",
        expected_tag_oid=tag_oid,
        candidate_sha=candidate_sha,
    )

    with pytest.raises(release_refs.ReleaseStateError, match="valid promoted candidate"):
        release_refs.validate_state(
            worktree,
            release_tag="v1.4.2",
            target_ref="refs/remotes/origin/main",
            prerelease=False,
            event_sha=base_sha,
        )


def test_stale_branch_lease_leaves_tag_and_branch_unmodified(tmp_path: Path) -> None:
    """An interrupted promotion cannot move only the release tag."""
    worktree, remote, base_sha, tag_oid = create_release_repository(tmp_path)
    candidate_sha = create_candidate_commit(worktree)
    competitor = tmp_path / "competitor"
    subprocess.run(["git", "clone", str(remote), str(competitor)], check=True, capture_output=True)
    git(competitor, "checkout", "main")
    git(competitor, "config", "user.name", "Competitor")
    git(competitor, "config", "user.email", "competitor@example.invalid")
    (competitor / "README.md").write_text("branch advanced\n")
    git(competitor, "add", "README.md")
    git(competitor, "commit", "-m", "advance main")
    git(competitor, "push", "origin", "main")
    advanced_sha = git(competitor, "rev-parse", "HEAD")

    with pytest.raises(release_refs.ReleaseStateError):
        release_refs.promote(
            worktree,
            remote="origin",
            target_branch="main",
            expected_target_sha=base_sha,
            release_tag="v1.4.2",
            expected_tag_oid=tag_oid,
            candidate_sha=candidate_sha,
        )

    assert git(worktree, "--git-dir", str(remote), "rev-parse", "refs/heads/main") == advanced_sha
    assert git(worktree, "--git-dir", str(remote), "rev-parse", "refs/tags/v1.4.2") == tag_oid
