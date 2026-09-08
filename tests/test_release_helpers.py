"""Behavior tests for the release candidate trust and promotion boundaries."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
from io import BytesIO
import os
from pathlib import Path
import shutil
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


@pytest.mark.parametrize(
    "release_tag",
    [
        "v1.2",
        "v1.2.3",
        "v1.2.3.4",
        "v1.2-alpha.01",
        "v1.2-dev.01",
        "v1.2-post.01",
    ],
)
def test_verified_candidate_accepts_artifacts_from_a_real_local_build(
    tmp_path: Path, release_tag: str
) -> None:
    """The verifier accepts artifacts from the build backend for accepted release tags."""
    project_root = Path(__file__).parents[1]
    trusted_source = project_root / "src" / "openvpn_otp_auth"
    trusted_version = trusted_source / "_version.py"
    build_project = tmp_path / "build-project"
    shutil.copytree(
        project_root,
        build_project,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", ".coverage", "htmlcov", "__pycache__", "build", "dist", "*.egg-info"
        ),
    )
    build_version = build_project / "src" / "openvpn_otp_auth" / "_version.py"
    candidate.prepare_version_module(build_version, release_tag)

    handoff = tmp_path / "handoff"
    dist = handoff / "dist"
    dist.mkdir(parents=True)
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist)],
        cwd=build_project,
        check=True,
        capture_output=True,
        text=True,
    )
    shutil.copyfile(build_version, handoff / "_version.py")

    version = candidate.normalized_version(release_tag)
    assert {path.name for path in dist.iterdir()} == {
        f"openvpn_otp_auth-{version}-py3-none-any.whl",
        f"openvpn_otp_auth-{version}.tar.gz",
    }
    output = tmp_path / "verified"
    candidate.verify_candidate(handoff, trusted_source, trusted_version, output, release_tag)

    assert (output / "_version.py").read_bytes() == build_version.read_bytes()
    assert (output / "dist" / f"openvpn_otp_auth-{version}-py3-none-any.whl").is_file()
    assert (output / "dist" / f"openvpn_otp_auth-{version}.tar.gz").is_file()


@pytest.mark.parametrize(
    ("release_tag", "version", "prerelease"),
    [
        ("v1.2", "1.2", False),
        ("v1.2.3", "1.2.3", False),
        ("v1.2.3.4", "1.2.3.4", False),
        ("v1.2-alpha.1", "1.2a1", True),
        ("v1.2.3-beta.2", "1.2.3b2", True),
        ("v1.2.3.4-rc.3", "1.2.3.4rc3", True),
        ("v1.2rc1", "1.2rc1", True),
        ("v1.2.3b2", "1.2.3b2", True),
        ("v1.2.3.4a3", "1.2.3.4a3", True),
        ("v1.2-dev.4", "1.2.dev4", True),
        ("v1.2post5", "1.2.post5", True),
    ],
)
def test_release_tag_policy_accepts_two_to_four_numeric_components(
    release_tag: str, version: str, prerelease: bool
) -> None:
    """Both release boundaries accept the shared fixed numeric tag policy."""
    release_refs.require_release_tag(release_tag)

    assert release_refs.is_prerelease_tag(release_tag) is prerelease
    assert candidate.normalized_version(release_tag) == version


@pytest.mark.parametrize(
    "release_tag",
    [
        "v1",
        "v01.2",
        "v1.2.3.4.5",
        "1.2",
        "v1.2.post1",
        "v1.2rc",
        "v1.2rc١",
        "v1.2rc٢",
        "v1.2b١",
        "v1.2dev١",
        "v1.2post١",
    ],
)
def test_release_tag_policy_rejects_unsupported_versions(release_tag: str) -> None:
    """Tag validation rejects unsupported components, forms, and Unicode serials.

    Args:
        release_tag (str): Invalid tag supplied to both release boundaries.
    """
    with pytest.raises(release_refs.ReleaseStateError, match="Unsupported release tag"):
        release_refs.require_release_tag(release_tag)
    with pytest.raises(candidate.CandidateVerificationError, match="Unsupported release tag"):
        candidate.normalized_version(release_tag)


@pytest.mark.parametrize(
    "release_tag",
    [
        "v01.2",
        "v1.02",
        "v1.2.03",
        "v1.2.3.04",
        "v01.2rc1",
        "v1.02rc1",
        "v1.2.03rc1",
        "v1.2.3.04rc1",
    ],
)
@pytest.mark.parametrize("prerelease", [False, True])
def test_leading_zero_tags_fail_before_prerelease_classification(
    tmp_path: Path, release_tag: str, prerelease: bool
) -> None:
    """Leading-zero numeric components are invalid for either release selection."""
    with pytest.raises(release_refs.ReleaseStateError, match="Unsupported release tag"):
        release_refs.validate_state(
            tmp_path,
            release_tag=release_tag,
            target_ref="refs/remotes/origin/main",
            prerelease=prerelease,
            event_sha="0" * 40,
        )
    with pytest.raises(candidate.CandidateVerificationError, match="Unsupported release tag"):
        candidate.normalized_version(release_tag)


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


def workflow_step_block(workflow: str, name: str) -> str:
    """Return one workflow step, stopping at the next step, job, or end of file.

    Args:
        workflow: Complete workflow YAML text.
        name: Exact workflow step name.

    Returns:
        Text beginning at the named step and ending before the next boundary.
    """
    start = workflow.index(f"      - name: {name}")
    block = workflow[start:]
    lines = block.splitlines(keepends=True)
    offset = len(lines[0])
    for line in lines[1:]:
        if line.startswith("      - name:") or (
            line.startswith("  ") and not line.startswith("    ")
        ):
            return block[:offset]
        offset += len(line)
    return block


@pytest.mark.parametrize(
    ("workflow", "name", "expected", "forbidden"),
    [
        (
            (
                "jobs:\n"
                "  first:\n"
                "    steps:\n"
                "      - name: final first-job step\n"
                "        run: echo first\n"
                "  second:\n"
                "    steps:\n"
                "      - name: later step\n"
                "        run: echo later\n"
            ),
            "final first-job step",
            "echo first",
            "echo later",
        ),
        (
            (
                "jobs:\n"
                "  only:\n"
                "    steps:\n"
                "      - name: final workflow step\n"
                "        run: echo final"
            ),
            "final workflow step",
            "echo final",
            "not present",
        ),
    ],
)
def test_workflow_step_block_handles_job_and_file_boundaries(
    workflow: str, name: str, expected: str, forbidden: str
) -> None:
    """Workflow step extraction excludes later jobs and preserves final bytes."""
    block = workflow_step_block(workflow, name)

    assert expected in block
    assert forbidden not in block


def test_release_workflow_binds_immutable_event_sha_at_all_state_boundaries() -> None:
    """Candidate checkout and every release-state validation use the event SHA."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    candidate_checkout = workflow_step_block(workflow, "Checkout immutable release event commit")
    candidate_prepare = workflow_step_block(
        workflow, "Prepare the release version in the isolated candidate"
    )
    assert "RELEASE_EVENT_SHA: ${{ github.sha }}" in candidate_checkout
    assert ".github/scripts/release_version.py \\" in candidate_checkout
    assert '.github/scripts/verify_release_candidate.py "$trusted_helpers/"' in candidate_checkout
    assert 'git checkout --detach "$RELEASE_EVENT_SHA"' in candidate_checkout
    assert (
        'python "$RUNNER_TEMP/trusted-release-helpers/verify_release_candidate.py"'
        in candidate_prepare
    )
    state_steps = [
        "Prove the prerelease tag is already a matching default-branch commit",
        "Validate immutable starting refs or an exact resume candidate",
    ]
    for name in state_steps:
        block = workflow_step_block(workflow, name)
        assert "RELEASE_EVENT_SHA: ${{ github.sha }}" in block
        assert '--event-sha "$RELEASE_EVENT_SHA"' in block


def test_release_workflow_authenticates_only_the_trusted_promotion_push() -> None:
    """The write-scoped promotion can push without persisting checkout credentials."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    promotion = workflow_step_block(
        workflow, "Atomically advance default branch and annotated release tag"
    )

    assert "GH_TOKEN: ${{ github.token }}" in promotion
    assert "gh auth setup-git --hostname github.com" in promotion
    assert promotion.index("gh auth setup-git --hostname github.com") < promotion.index(
        'release_refs.py" promote'
    )
    checkout = workflow_step_block(workflow, "Checkout trusted default-branch workflow revision")
    assert "persist-credentials: false" in checkout


def test_release_workflow_requires_exact_staged_version_file() -> None:
    """Fresh promotion must stage exactly the release version module."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    creation = workflow_step_block(workflow, "Create or reuse the deterministic release commit")

    assert "git diff --cached --name-only -z" in creation
    assert '[[ "$staged_path" == src/openvpn_otp_auth/_version.py ]]' in creation
    assert "if IFS= read -r -d ''; then" in creation


def test_release_workflow_reuses_one_gate_manifest_for_stable_and_prerelease() -> None:
    """Stable and prerelease paths dispatch the same existing checks without duplicate CI."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    candidate = workflow_step_block(workflow, "Test and build the candidate package")
    stable = workflow_step_block(workflow, "Dispatch and verify immutable release gates")
    prerelease = workflow_step_block(workflow, "Dispatch and verify immutable prerelease gates")

    assert workflow.count("prek-autofix-review.yml::review") == 1
    assert workflow.count("pytest_check.yml::pytest check and post coverage") == 1
    for dispatch in (stable, prerelease):
        assert 'done <<< "$REQUIRED_CHECKS"' in dispatch
        assert '--workflow-ref "$WORKFLOW_REF"' in dispatch
        assert '--workflow-sha "$WORKFLOW_SHA"' in dispatch
        assert '--sha "$CANDIDATE_SHA"' in dispatch
    assert "prek run --all-files" not in candidate
    assert "mypy ." not in candidate
    assert "pytest" not in candidate


def test_prerelease_validation_dispatches_existing_exact_sha_gates() -> None:
    """Prerelease validation uses trusted definitions without promotion.

    The event commit may be an ancestor of a newer default branch and lack the
    helper, so the job snapshots the helper and workflow SHA before detaching
    to the immutable candidate commit.
    """
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    prerelease = workflow[
        workflow.index("  validate_prerelease:") : workflow.index("  promote_stable:")
    ]
    dispatch = workflow_step_block(prerelease, "Dispatch and verify immutable prerelease gates")

    assert "actions: write" in prerelease
    assert "checks: read" in prerelease
    assert "statuses: write" in prerelease
    state = workflow_step_block(
        prerelease, "Prove the prerelease tag is already a matching default-branch commit"
    )
    assert state.index('workflow_sha="$(git rev-parse HEAD)"') < state.index("git fetch")
    assert state.index('trusted_helpers="$RUNNER_TEMP/trusted-release-helpers"') < state.index(
        'git checkout --detach "$source_sha"'
    )
    assert "cp .github/scripts/release_refs.py" in state
    assert '.github/scripts/verify_release_checks.py "$trusted_helpers/"' in state
    assert 'echo "source-sha=$source_sha"' in prerelease
    assert 'echo "workflow-sha=$workflow_sha"' in prerelease
    assert 'echo "verifier-path=$trusted_verifier"' in prerelease
    assert "VERIFIER_PATH: ${{ steps.state.outputs['verifier-path'] }}" in dispatch
    assert "WORKFLOW_REF: ${{ github.event.repository.default_branch }}" in dispatch
    assert '--workflow-ref "$WORKFLOW_REF"' in dispatch
    assert '--workflow-sha "$WORKFLOW_SHA"' in dispatch
    assert '--sha "$CANDIDATE_SHA"' in dispatch
    assert 'python "$VERIFIER_PATH"' in dispatch
    assert "release_refs.py promote" not in prerelease
    assert "Publish verified stable distribution" not in prerelease


def test_stable_resume_dispatch_keeps_the_trusted_workflow_revision() -> None:
    """A resumed candidate can be older than main without changing its controller proof."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    stable = workflow[workflow.index("  promote_stable:") :]
    state = workflow_step_block(
        stable, "Validate immutable starting refs or an exact resume candidate"
    )
    dispatch = workflow_step_block(stable, "Dispatch and verify immutable release gates")

    assert state.index('workflow_sha="$(git rev-parse HEAD)"') < state.index("git fetch")
    assert state.index('trusted_helpers="$RUNNER_TEMP/trusted-release-helpers"') < state.index(
        'git checkout --detach "$source_sha"'
    )
    assert '.github/scripts/verify_release_checks.py "$trusted_helpers/"' in state
    assert 'echo "workflow-sha=$workflow_sha"' in state
    assert 'echo "workflow-sha=$source_sha"' not in state
    assert "WORKFLOW_SHA: ${{ steps.state.outputs['workflow-sha'] }}" in dispatch
    assert "VERIFIER_PATH:" in dispatch
    assert 'python "$VERIFIER_PATH"' in dispatch


def _shared_contract_replaced_release_gate_dispatch_concurrency() -> None:
    """Dispatches isolate candidates while preserving pull-request and push grouping."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/prek-autofix-review.yml").read_text()

    assert (
        "group: prek-autofix-${{ github.event.pull_request.number || "
        "inputs.expected_sha || github.ref }}" in workflow
    )
    assert "cancel-in-progress: true" in workflow

    def group(pull_request: str = "", expected_sha: str = "", ref: str = "") -> str:
        """Resolve the ordered GitHub expression used by the asserted workflow text.

        Args:
            pull_request (str): Optional pull request number.
            expected_sha (str): Optional immutable dispatched candidate SHA.
            ref (str): Fallback branch or tag ref.

        Returns:
            str: The rendered concurrency key.
        """
        return "prek-autofix-" + (pull_request or expected_sha or ref)

    assert group(expected_sha="a" * 40) != group(expected_sha="b" * 40)
    assert group(expected_sha="a" * 40) == group(expected_sha="a" * 40)
    assert (
        group(pull_request="37", expected_sha="a" * 40, ref="refs/heads/main") == "prek-autofix-37"
    )
    assert group(ref="refs/heads/main") == "prek-autofix-refs/heads/main"


@pytest.mark.parametrize(
    "workflow_path",
    [
        Path(".github/workflows/pytest_check.yml"),
        Path(".github/workflows/prek-autofix-review.yml"),
    ],
)
def _shared_contract_replaced_dispatched_release_checkout(
    workflow_path: Path,
) -> None:
    """Accept a distinct controller SHA only when checkout reaches the candidate.

    Args:
        workflow_path (Path): Caller workflow containing the dispatch guards.
    """
    workflow = (Path(__file__).parents[1] / workflow_path).read_text()
    input_guard = workflow_step_block(workflow, "Require expected release commit")
    checkout_guard = workflow_step_block(workflow, "Require checked-out release commit")
    candidate_sha = "a" * 40
    controller_sha = "b" * 40

    def run_guard(
        step: str, expected_sha: str, checked_out_sha: str
    ) -> subprocess.CompletedProcess[str]:
        """Execute the extracted guard with a controlled checkout identity.

        Args:
            step (str): Workflow step containing the shell guard.
            expected_sha (str): Candidate requested by the release controller.
            checked_out_sha (str): Synthetic local Git HEAD value.

        Returns:
            subprocess.CompletedProcess[str]: Completed shell-guard process.
        """
        script = (
            step.split("        run: |\n", maxsplit=1)[1]
            .split("\n      - ", maxsplit=1)[0]
            .replace("          ", "")
        )
        command = (
            'git() { [[ "$1 $2" == "rev-parse HEAD" ]] && printf "%s\\n" "$CHECKED_OUT_SHA"; }\n'
            + script
        )
        return subprocess.run(
            ["bash", "-c", command],
            check=False,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "EXPECTED_SHA": expected_sha,
                "CHECKED_OUT_SHA": checked_out_sha,
                "GITHUB_SHA": controller_sha,
            },
        )

    assert run_guard(input_guard, candidate_sha, candidate_sha).returncode == 0
    assert run_guard(checkout_guard, candidate_sha, candidate_sha).returncode == 0
    assert run_guard(input_guard, "invalid", candidate_sha).returncode != 0
    assert run_guard(checkout_guard, candidate_sha, controller_sha).returncode != 0


def test_release_workflow_cleans_the_validation_ref_only_after_pypi_succeeds() -> None:
    """A failed package upload leaves the proven candidate ref available for diagnosis."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    cleanup = workflow[workflow.index("  cleanup_validation_ref:") :]

    assert "needs: [promote_stable, publish]" in cleanup
    assert "needs.publish.result == 'success'" in cleanup
    assert '--force-with-lease="refs/heads/$TEMP_REF:$CANDIDATE_SHA"' in cleanup


def test_testpypi_publisher_has_only_oidc_and_verified_artifacts() -> None:
    """The OIDC TestPyPI publisher cannot execute candidate source or reuse a cache."""
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    testpypi_job = workflow[workflow.index("  publish_testpypi:") :]
    assert "id-token: write" in testpypi_job
    assert "actions/download-artifact@v8" in testpypi_job
    assert "testpypi-python-distributions" in testpypi_job
    assert "actions/checkout@" not in testpypi_job
    assert "setup-python" not in testpypi_job
    assert "setup-uv" not in testpypi_job


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
    git(worktree, "config", "user.name", "Test")
    git(worktree, "config", "user.email", "test@example.invalid")
    return worktree, remote, initial_sha, initial_tag_oid


def create_candidate_commit(worktree: Path) -> str:
    """Create the deterministic release commit in a test worktree.

    Args:
        worktree: Worktree based on the release target.

    Returns:
        Candidate commit SHA.
    """
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
    (worktree / "README.md").write_text("default branch advanced\n")
    git(worktree, "add", "README.md")
    git(worktree, "commit", "-m", "advance default branch")
    git(worktree, "push", "origin", "main")
    git(worktree, "fetch", "origin", "main")

    advanced = release_refs.validate_state(
        worktree,
        release_tag="v1.4.2rc1",
        target_ref="refs/remotes/origin/main",
        prerelease=True,
        event_sha=prerelease_sha,
    )
    assert advanced.mode == "prerelease"
    assert advanced.source_sha == prerelease_sha
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
    worktree, _, base_sha, tag_oid = create_release_repository(tmp_path)
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
