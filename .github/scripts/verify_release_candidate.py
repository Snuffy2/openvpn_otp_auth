"""Verify the untrusted release-candidate artifact before promotion or publishing."""

from __future__ import annotations

import argparse
import base64
from collections.abc import Iterable
import csv
from email.parser import BytesParser
from email.policy import default
import gzip
import hashlib
from io import StringIO
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import tarfile
import tomllib
from typing import BinaryIO
import zipfile

VERSION_FILE = Path("src/openvpn_otp_auth/_version.py")
HANDOFF_VERSION_FILE = Path("_version.py")
DIST_DIRECTORY = Path("dist")
PACKAGE_DIRECTORY = Path("src/openvpn_otp_auth")
PROJECT_STEM = "openvpn_otp_auth"
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 50 * 1024 * 1024
MAX_ARCHIVE_CONTENT_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 64
VERSION_PATTERN = re.compile(r'^VERSION = "([^"]+)"$', re.MULTILINE)


class CandidateVerificationError(RuntimeError):
    """Raised when an artifact cannot prove the expected candidate contents."""


def normalized_version(release_tag: str) -> str:
    """Return the distribution-file version for a supported release tag.

    Args:
        release_tag: Immutable tag beginning with ``v``.

    Returns:
        The package version without its tag prefix.

    Raises:
        CandidateVerificationError: If the tag is not a supported package version.
    """
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?", release_tag):
        raise CandidateVerificationError(f"Unsupported release tag {release_tag!r}.")
    return release_tag.removeprefix("v")


def version_from_text(text: str, *, source: str) -> str:
    """Return the unambiguous package version in a version module.

    Args:
        text: Module text.
        source: Source label for diagnostic output.

    Returns:
        The declared version.

    Raises:
        CandidateVerificationError: If the assignment is missing or ambiguous.
    """
    matches = VERSION_PATTERN.findall(text)
    if len(matches) != 1:
        raise CandidateVerificationError(f"{source} must contain exactly one VERSION assignment.")
    return matches[0]


def expected_version_module(trusted_path: Path, release_tag: str) -> bytes:
    """Build the only allowed version-module change for a release candidate.

    Args:
        trusted_path: Version module from the trusted source checkout.
        release_tag: Requested release tag.

    Returns:
        Expected candidate module bytes.

    Raises:
        CandidateVerificationError: If the trusted module is malformed.
    """
    try:
        original = trusted_path.read_text(encoding="utf-8")
    except OSError as error:
        raise CandidateVerificationError(
            f"Could not read trusted version module: {error}"
        ) from error
    version_from_text(original, source=str(trusted_path))
    updated, count = VERSION_PATTERN.subn(f'VERSION = "{release_tag}"', original, count=1)
    if count != 1:
        raise CandidateVerificationError("Could not construct the release version module.")
    return updated.encode("utf-8")


def prepare_version_module(version_path: Path, release_tag: str) -> None:
    """Write the permitted release version in an unprivileged candidate checkout.

    Args:
        version_path: Candidate checkout version module.
        release_tag: Requested release tag.

    Raises:
        CandidateVerificationError: If the module cannot be safely updated.
    """
    expected = expected_version_module(version_path, release_tag)
    version_path.write_bytes(expected)


def expected_handoff_paths(release_tag: str) -> set[Path]:
    """Return the exact regular files accepted from the candidate job.

    Args:
        release_tag: Requested release tag.

    Returns:
        Relative files allowed in the artifact directory.
    """
    version = normalized_version(release_tag)
    return {
        HANDOFF_VERSION_FILE,
        DIST_DIRECTORY / f"{PROJECT_STEM}-{version}.tar.gz",
        DIST_DIRECTORY / f"{PROJECT_STEM}-{version}-py3-none-any.whl",
    }


def iter_regular_files(directory: Path) -> Iterable[Path]:
    """Yield every regular file beneath a candidate directory.

    Args:
        directory: Candidate artifact directory.

    Yields:
        Relative regular-file paths.

    Raises:
        CandidateVerificationError: If any path is missing, linked, or non-regular.
    """
    if not directory.is_dir() or directory.is_symlink():
        raise CandidateVerificationError("Candidate directory must be a real directory.")
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise CandidateVerificationError(f"Candidate artifact contains a symlink: {relative}")
        if path.is_dir():
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise CandidateVerificationError(
                f"Candidate artifact contains a non-regular path: {relative}"
            )
        yield relative


def verify_handoff_layout(candidate_directory: Path, release_tag: str) -> dict[Path, Path]:
    """Require exact paths and bounded regular files before reading an artifact.

    Args:
        candidate_directory: Downloaded untrusted artifact directory.
        release_tag: Requested release tag.

    Returns:
        Mapping of accepted relative paths to source paths.

    Raises:
        CandidateVerificationError: If paths or byte limits do not match.
    """
    expected = expected_handoff_paths(release_tag)
    actual = set(iter_regular_files(candidate_directory))
    if actual != expected:
        raise CandidateVerificationError(
            f"Candidate artifact paths do not match: expected={sorted(map(str, expected))!r}, "
            f"actual={sorted(map(str, actual))!r}."
        )
    files = {relative: candidate_directory / relative for relative in expected}
    total = 0
    for relative, path in files.items():
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise CandidateVerificationError(
                f"Candidate file exceeds {MAX_FILE_BYTES} bytes: {relative}"
            )
        total += size
    if total > MAX_TOTAL_BYTES:
        raise CandidateVerificationError(f"Candidate artifact exceeds {MAX_TOTAL_BYTES} bytes.")
    return files


def source_payload(source_root: Path) -> dict[str, bytes]:
    """Read the trusted Python package payload for distribution comparison.

    Args:
        source_root: Trusted package source directory.

    Returns:
        Mapping from package-relative paths to bytes.

    Raises:
        CandidateVerificationError: If the source package has unsafe paths.
    """
    if not source_root.is_dir() or source_root.is_symlink():
        raise CandidateVerificationError("Trusted package source directory is invalid.")
    payload: dict[str, bytes] = {}
    for path in sorted(source_root.rglob("*.py")):
        if path.is_symlink() or not path.is_file():
            raise CandidateVerificationError(f"Trusted package source is unsafe: {path}")
        payload[path.relative_to(source_root).as_posix()] = path.read_bytes()
    if not payload:
        raise CandidateVerificationError("Trusted package source is empty.")
    return payload


def expected_payload(trusted_source: Path, expected_version: bytes) -> dict[str, bytes]:
    """Return package bytes with the sole candidate version-file update applied.

    Args:
        trusted_source: Trusted package source directory.
        expected_version: Expected replacement version module bytes.

    Returns:
        Expected package file mapping.
    """
    payload = source_payload(trusted_source)
    payload["_version.py"] = expected_version
    return payload


def expected_metadata_headers(source_root: Path, release_tag: str) -> dict[str, list[str]]:
    """Derive installer-relevant core metadata from the trusted pyproject.

    Args:
        source_root: Repository root containing trusted project metadata.
        release_tag: Requested release tag.

    Raises:
        CandidateVerificationError: If trusted project metadata is malformed.
    """
    try:
        project = tomllib.loads((source_root / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]
    except (KeyError, OSError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise CandidateVerificationError(
            f"Trusted pyproject metadata is invalid: {error}"
        ) from error
    if not isinstance(project, dict):
        raise CandidateVerificationError("Trusted project metadata is invalid.")

    def require_string(name: str) -> str:
        value = project.get(name)
        if not isinstance(value, str):
            raise CandidateVerificationError(f"Trusted project metadata lacks {name!r}.")
        return value

    headers: dict[str, list[str]] = {
        "Metadata-Version": ["2.4"],
        "Name": [require_string("name")],
        "Version": [normalized_version(release_tag)],
        "Summary": [require_string("description")],
        "Requires-Python": [require_string("requires-python")],
        "License-Expression": [require_string("license")],
        "Description-Content-Type": ["text/markdown"],
    }
    list_fields = {
        "License-File": project.get("license-files", []),
        "Classifier": project.get("classifiers", []),
        "Requires-Dist": project.get("dependencies", []),
    }
    for header, values in list_fields.items():
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise CandidateVerificationError(
                f"Trusted project metadata has invalid {header} values."
            )
        if values:
            headers[header] = sorted(values)
    if headers.get("License-File"):
        headers["Dynamic"] = ["license-file"]
    keywords = project.get("keywords", [])
    if not isinstance(keywords, list) or not all(isinstance(value, str) for value in keywords):
        raise CandidateVerificationError("Trusted project metadata has invalid keywords.")
    if keywords:
        headers["Keywords"] = [",".join(keywords)]
    authors = project.get("authors", [])
    if not isinstance(authors, list) or not all(isinstance(author, dict) for author in authors):
        raise CandidateVerificationError("Trusted project metadata has invalid authors.")
    author_names = [author.get("name") for author in authors]
    if not all(isinstance(name, str) for name in author_names):
        raise CandidateVerificationError("Trusted project metadata has invalid author names.")
    if author_names:
        headers["Author"] = sorted(author_names)
    urls = project.get("urls", {})
    if not isinstance(urls, dict) or not all(
        isinstance(name, str) and isinstance(url, str) for name, url in urls.items()
    ):
        raise CandidateVerificationError("Trusted project metadata has invalid project URLs.")
    if urls:
        headers["Project-URL"] = sorted(f"{name}, {url}" for name, url in urls.items())
    return headers


def verify_metadata(metadata: bytes, release_tag: str, source_root: Path, *, source: str) -> None:
    """Require canonical trusted installer metadata and exact README content.

    Args:
        metadata: Candidate distribution metadata bytes.
        release_tag: Requested release tag.
        source_root: Repository root containing trusted metadata inputs.
        source: Metadata source label.

    Raises:
        CandidateVerificationError: If metadata differs from trusted build inputs.
    """
    message = BytesParser(policy=default).parsebytes(metadata)
    if message.defects:
        raise CandidateVerificationError(f"{source} contains malformed metadata headers.")
    expected = expected_metadata_headers(source_root, release_tag)
    if {name for name, _ in message.items()} != set(expected):
        raise CandidateVerificationError(
            f"{source} contains unexpected or missing metadata fields."
        )
    singleton = {
        "Metadata-Version",
        "Name",
        "Version",
        "Summary",
        "Requires-Python",
        "License-Expression",
        "Description-Content-Type",
    }
    for name, expected_values in expected.items():
        actual_values = message.get_all(name, [])
        if name in singleton and len(actual_values) != 1:
            raise CandidateVerificationError(f"{source} has duplicate or missing {name} metadata.")
        if sorted(actual_values) != sorted(expected_values):
            raise CandidateVerificationError(f"{source} {name} differs from trusted metadata.")
    body = message.get_payload(decode=True)
    if body != (source_root / "README.md").read_bytes():
        raise CandidateVerificationError(f"{source} description differs from the trusted README.")


def trusted_root(trusted_source: Path) -> Path:
    """Return the repository root that owns the trusted package source."""
    return trusted_source.parents[1]


def expected_metadata_files(source_root: Path, release_tag: str) -> dict[str, bytes]:
    """Build deterministic metadata payloads required by this distribution.

    Args:
        source_root: Trusted repository root.
        release_tag: Requested release tag.

    Returns:
        Expected non-archive source files keyed by relative path.
    """
    names = ("LICENSE", "README.md", "pyproject.toml")
    files = {name: (source_root / name).read_bytes() for name in names}
    try:
        project = tomllib.loads(files["pyproject.toml"].decode("utf-8"))["project"]
        scripts = project["scripts"]
        dependencies = project["dependencies"]
    except (KeyError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise CandidateVerificationError(
            f"Trusted pyproject metadata is invalid: {error}"
        ) from error
    if not isinstance(scripts, dict) or not isinstance(dependencies, list):
        raise CandidateVerificationError(
            "Trusted project metadata has invalid scripts or dependencies."
        )
    files["entry_points.txt"] = (
        "[console_scripts]\n"
        + "".join(f"{name} = {value}\n" for name, value in sorted(scripts.items()))
    ).encode()
    files["requires.txt"] = ("\n".join(dependencies) + "\n").encode()
    files["top_level.txt"] = f"{PROJECT_STEM}\n".encode()
    files["dependency_links.txt"] = b"\n"
    return files


def bounded_member_sizes(sizes: Iterable[int], *, source: str) -> None:
    """Reject archive bombs before any member payload is read.

    Args:
        sizes: Declared uncompressed member sizes.
        source: Archive label for diagnostics.
    """
    total = 0
    for size in sizes:
        if size < 0 or size > MAX_ARCHIVE_MEMBER_BYTES:
            raise CandidateVerificationError(f"{source} contains an oversized member.")
        total += size
    if total > MAX_ARCHIVE_CONTENT_BYTES:
        raise CandidateVerificationError(f"{source} exceeds its uncompressed content limit.")


class LimitedReader:
    """Bound reads from a decompressed stream before tar parsing consumes it."""

    def __init__(self, stream: BinaryIO, *, source: str) -> None:
        """Initialize the decompressed byte limiter.

        Args:
            stream: Decompressed archive stream.
            source: Archive label for error reporting.
        """
        self.stream = stream
        self.source = source
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        """Read bounded bytes and fail before returning an over-limit payload."""
        remaining = MAX_ARCHIVE_CONTENT_BYTES - self.total
        data = self.stream.read(remaining + 1 if size < 0 else min(size, remaining + 1))
        self.total += len(data)
        if self.total > MAX_ARCHIVE_CONTENT_BYTES:
            raise CandidateVerificationError(
                f"{self.source} exceeds its decompressed content limit."
            )
        return data


def zip_member_count(wheel_path: Path) -> int:
    """Read the classic ZIP end record before creating an untrusted ZipFile object."""
    try:
        tail = wheel_path.read_bytes()[-(65_535 + 22) :]
    except OSError as error:
        raise CandidateVerificationError(f"Could not inspect wheel: {error}") from error
    marker = tail.rfind(b"PK\x05\x06")
    if marker < 0 or len(tail) - marker < 22:
        raise CandidateVerificationError("Wheel has no complete end-of-central-directory record.")
    disk, start_disk, disk_count, total_count, size, offset, comment = struct.unpack(
        "<4H2LH", tail[marker + 4 : marker + 22]
    )
    if (
        disk
        or start_disk
        or disk_count != total_count
        or total_count == 0xFFFF
        or size == 0xFFFFFFFF
        or offset == 0xFFFFFFFF
    ):
        raise CandidateVerificationError("Wheel uses unsupported ZIP64 or multi-disk metadata.")
    if len(tail) - marker != 22 + comment or total_count > MAX_ARCHIVE_MEMBERS:
        raise CandidateVerificationError("Wheel has an invalid or excessive member count.")
    return total_count


def verify_wheel_headers(contents: bytes) -> None:
    """Require only canonical compatibility fields in a wheel WHEEL document."""
    message = BytesParser(policy=default).parsebytes(contents)
    allowed = {"Wheel-Version", "Generator", "Root-Is-Purelib", "Tag"}
    if message.defects or {name for name, _ in message.items()} - allowed:
        raise CandidateVerificationError(
            "Wheel contains malformed or unexpected installer metadata."
        )
    if message.get_all("Wheel-Version", []) != ["1.0"]:
        raise CandidateVerificationError("Wheel must declare Wheel-Version 1.0 exactly once.")
    if message.get_all("Root-Is-Purelib", []) != ["true"]:
        raise CandidateVerificationError("Wheel must declare purelib exactly once.")
    if message.get_all("Tag", []) != ["py3-none-any"]:
        raise CandidateVerificationError("Wheel must declare only py3-none-any.")
    generators = message.get_all("Generator", [])
    if len(generators) != 1 or not re.fullmatch(r"setuptools \([0-9][^) ]*\)", generators[0]):
        raise CandidateVerificationError("Wheel has an invalid generator declaration.")
    if message.get_payload(decode=True) not in (b"", None):
        raise CandidateVerificationError("Wheel metadata has an unexpected body.")


def verify_record(record: bytes, members: dict[str, bytes], record_name: str) -> None:
    """Require exact, hash-verified CSV RECORD rows for every wheel member."""
    try:
        rows = list(csv.reader(StringIO(record.decode("utf-8"), newline=""), strict=True))
    except (csv.Error, UnicodeDecodeError) as error:
        raise CandidateVerificationError(f"Wheel RECORD is malformed: {error}") from error
    names: set[str] = set()
    for row in rows:
        if len(row) != 3 or not row[0] or row[0] in names:
            raise CandidateVerificationError("Wheel RECORD contains malformed or duplicate rows.")
        name, digest, size = row
        names.add(name)
        if name == record_name:
            if digest or size:
                raise CandidateVerificationError(
                    "Wheel RECORD self-row must have empty digest and size."
                )
            continue
        if (
            name not in members
            or not re.fullmatch(r"sha256=[A-Za-z0-9_-]+", digest)
            or not size.isdecimal()
        ):
            raise CandidateVerificationError("Wheel RECORD contains an invalid member declaration.")
        member = members[name]
        expected_digest = (
            base64.urlsafe_b64encode(hashlib.sha256(member).digest()).decode().rstrip("=")
        )
        if digest != f"sha256={expected_digest}" or int(size) != len(member):
            raise CandidateVerificationError(
                "Wheel RECORD digest or size does not match the archive member."
            )
    if names != set(members) | {record_name}:
        raise CandidateVerificationError(
            "Wheel RECORD does not describe the exact archive members."
        )


def verify_wheel(
    wheel_path: Path, expected: dict[str, bytes], release_tag: str, source_root: Path
) -> None:
    """Verify wheel package bytes and distribution metadata against trusted source.

    Args:
        wheel_path: Wheel from the candidate artifact.
        expected: Expected package bytes.
        release_tag: Requested release tag.

    Raises:
        CandidateVerificationError: If archive members or payloads differ.
    """
    zip_member_count(wheel_path)
    try:
        with zipfile.ZipFile(wheel_path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise CandidateVerificationError("Wheel has an excessive member count.")
            names = [member.filename for member in members]
            if len(names) != len(set(names)):
                raise CandidateVerificationError("Wheel contains duplicate paths.")
            bounded_member_sizes((member.file_size for member in members), source="Wheel")
            for member in members:
                mode = member.external_attr >> 16
                if (
                    member.is_dir()
                    or member.filename.startswith("/")
                    or ".." in Path(member.filename).parts
                    or mode & 0o111
                    or stat.S_ISLNK(mode)
                ):
                    raise CandidateVerificationError("Wheel contains an unsafe archive path.")
            version = normalized_version(release_tag)
            dist_info = f"{PROJECT_STEM}-{version}.dist-info"
            expected_names = {f"{PROJECT_STEM}/{name}" for name in expected}
            expected_names.update(
                {
                    f"{dist_info}/METADATA",
                    f"{dist_info}/WHEEL",
                    f"{dist_info}/RECORD",
                    f"{dist_info}/licenses/LICENSE",
                    f"{dist_info}/entry_points.txt",
                    f"{dist_info}/top_level.txt",
                }
            )
            if set(names) != expected_names:
                raise CandidateVerificationError(
                    "Wheel contains unexpected or missing archive members."
                )
            record_name = f"{dist_info}/RECORD"
            contents = {name: archive.read(name) for name in expected_names - {record_name}}
            payload = {
                name.removeprefix(f"{PROJECT_STEM}/"): contents[name]
                for name in contents
                if name.startswith(f"{PROJECT_STEM}/")
            }
            if payload != expected:
                raise CandidateVerificationError(
                    "Wheel package payload differs from the trusted candidate."
                )
            verify_metadata(
                contents[f"{dist_info}/METADATA"], release_tag, source_root, source="Wheel metadata"
            )
            generated = expected_metadata_files(source_root, release_tag)
            for name in ("entry_points.txt", "top_level.txt"):
                if contents[f"{dist_info}/{name}"] != generated[name]:
                    raise CandidateVerificationError(f"Wheel {name} differs from trusted metadata.")
            if contents[f"{dist_info}/licenses/LICENSE"] != generated["LICENSE"]:
                raise CandidateVerificationError("Wheel license differs from trusted source.")
            verify_wheel_headers(contents[f"{dist_info}/WHEEL"])
            verify_record(archive.read(record_name), contents, record_name)
    except (OSError, zipfile.BadZipFile) as error:
        raise CandidateVerificationError(f"Could not inspect wheel: {error}") from error


def verify_sdist(
    sdist_path: Path, expected: dict[str, bytes], release_tag: str, source_root: Path
) -> None:
    """Verify sdist package bytes and metadata against trusted source.

    Args:
        sdist_path: Source distribution from the candidate artifact.
        expected: Expected package bytes.
        release_tag: Requested release tag.

    Raises:
        CandidateVerificationError: If archive members or payloads differ.
    """
    root = f"{PROJECT_STEM}-{normalized_version(release_tag)}"
    expected_names = {
        f"{root}/{name}"
        for name in ("LICENSE", "README.md", "pyproject.toml", "PKG-INFO", "setup.cfg")
    }
    expected_names.update(f"{root}/src/{PROJECT_STEM}/{name}" for name in expected)
    expected_names.update(
        f"{root}/src/{PROJECT_STEM}.egg-info/{name}"
        for name in (
            "PKG-INFO",
            "SOURCES.txt",
            "dependency_links.txt",
            "entry_points.txt",
            "requires.txt",
            "top_level.txt",
        )
    )
    expected_directories = {
        root,
        f"{root}/src",
        f"{root}/src/{PROJECT_STEM}",
        f"{root}/src/{PROJECT_STEM}.egg-info",
    }
    trusted_tests = source_root / "tests"
    trusted_test_payload: dict[str, bytes] = {}
    if trusted_tests.exists():
        if not trusted_tests.is_dir() or trusted_tests.is_symlink():
            raise CandidateVerificationError("Trusted test source directory is unsafe.")
        for test_path in sorted(trusted_tests.rglob("test_*.py")):
            if test_path.is_symlink() or not test_path.is_file():
                raise CandidateVerificationError(f"Trusted test source is unsafe: {test_path}")
            relative = test_path.relative_to(source_root).as_posix()
            trusted_test_payload[f"{root}/{relative}"] = test_path.read_bytes()
        expected_names.update(trusted_test_payload)
        if trusted_test_payload:
            expected_directories.add(f"{root}/tests")
    contents: dict[str, bytes] = {}
    directories: set[str] = set()
    total = 0
    try:
        with sdist_path.open("rb") as compressed, gzip.GzipFile(fileobj=compressed) as decompressed:
            limited = LimitedReader(decompressed, source="Source distribution")
            with tarfile.open(fileobj=limited, mode="r|") as archive:
                for count, member in enumerate(archive, start=1):
                    if count > MAX_ARCHIVE_MEMBERS:
                        raise CandidateVerificationError(
                            "Source distribution has an excessive member count."
                        )
                    if member.isdir():
                        if member.name not in expected_directories or member.name in directories:
                            raise CandidateVerificationError(
                                "Source distribution contains an unsafe or unexpected directory."
                            )
                        directories.add(member.name)
                        continue
                    if (
                        not member.isfile()
                        or member.name not in expected_names
                        or member.name in contents
                        or member.name.startswith("/")
                        or ".." in Path(member.name).parts
                    ):
                        raise CandidateVerificationError(
                            "Source distribution contains an unsafe or unexpected archive member."
                        )
                    bounded_member_sizes((member.size,), source="Source distribution")
                    total += member.size
                    if total > MAX_ARCHIVE_CONTENT_BYTES:
                        raise CandidateVerificationError(
                            "Source distribution exceeds its uncompressed content limit."
                        )
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise CandidateVerificationError(
                            "Could not read a source distribution member."
                        )
                    data = extracted.read(member.size + 1)
                    if len(data) != member.size:
                        raise CandidateVerificationError(
                            "Source distribution member is truncated or oversized."
                        )
                    contents[member.name] = data
    except (EOFError, OSError, gzip.BadGzipFile, tarfile.TarError) as error:
        raise CandidateVerificationError(
            f"Could not inspect source distribution: {error}"
        ) from error
    if set(contents) != expected_names:
        raise CandidateVerificationError(
            "Source distribution contains unexpected or missing archive members."
        )
    if directories != expected_directories:
        raise CandidateVerificationError(
            "Source distribution directories do not match the trusted manifest."
        )
    prefix = f"{root}/src/{PROJECT_STEM}/"
    payload = {
        name.removeprefix(prefix): value
        for name, value in contents.items()
        if name.startswith(prefix)
    }
    if payload != expected:
        raise CandidateVerificationError(
            "Source distribution payload differs from the trusted candidate."
        )
    generated = expected_metadata_files(source_root, release_tag)
    verify_metadata(
        contents[f"{root}/PKG-INFO"],
        release_tag,
        source_root,
        source="Source distribution metadata",
    )
    verify_metadata(
        contents[f"{root}/src/{PROJECT_STEM}.egg-info/PKG-INFO"],
        release_tag,
        source_root,
        source="Source distribution egg metadata",
    )
    if contents[f"{root}/setup.cfg"] != b"[egg_info]\ntag_build = \ntag_date = 0\n\n":
        raise CandidateVerificationError("Source distribution setup configuration is invalid.")
    for name in ("LICENSE", "README.md", "pyproject.toml"):
        if contents[f"{root}/{name}"] != generated[name]:
            raise CandidateVerificationError(
                f"Source distribution {name} differs from trusted source."
            )
    for name in ("entry_points.txt", "requires.txt", "top_level.txt", "dependency_links.txt"):
        if contents[f"{root}/src/{PROJECT_STEM}.egg-info/{name}"] != generated[name]:
            raise CandidateVerificationError(
                f"Source distribution {name} differs from trusted metadata."
            )
    for name, value in trusted_test_payload.items():
        if contents[name] != value:
            raise CandidateVerificationError("Source distribution test payload differs from trusted source.")
    package_sources = sorted(f"src/{PROJECT_STEM}/{name}" for name in expected)
    egg_sources = [
        f"src/{PROJECT_STEM}.egg-info/{name}"
        for name in (
            "PKG-INFO",
            "SOURCES.txt",
            "dependency_links.txt",
            "entry_points.txt",
            "requires.txt",
            "top_level.txt",
        )
    ]
    test_sources = sorted(name.removeprefix(f"{root}/") for name in trusted_test_payload)
    expected_sources = "\n".join(
        ["LICENSE", "README.md", "pyproject.toml", *package_sources, *egg_sources, *test_sources]
    )
    if contents[f"{root}/src/{PROJECT_STEM}.egg-info/SOURCES.txt"] != expected_sources.encode():
        raise CandidateVerificationError(
            "Source distribution SOURCES.txt differs from the exact source manifest."
        )


def copy_verified_artifacts(files: dict[Path, Path], output_directory: Path) -> None:
    """Copy bounded, verified handoff files into a fresh output directory.

    Args:
        files: Validated artifact files.
        output_directory: Destination used by later trusted release steps.
    """
    if output_directory.exists():
        raise CandidateVerificationError("Verified output directory must not already exist.")
    output_directory.mkdir(parents=True)
    for relative, source in files.items():
        destination = output_directory / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def verify_candidate(
    candidate_directory: Path,
    trusted_source: Path,
    trusted_version: Path,
    output_directory: Path,
    release_tag: str,
) -> None:
    """Validate and copy an immutable candidate distribution handoff.

    Args:
        candidate_directory: Untrusted downloaded artifact directory.
        trusted_source: Trusted package source checkout.
        trusted_version: Trusted version module path.
        output_directory: Fresh trusted output directory.
        release_tag: Requested release tag.
    """
    files = verify_handoff_layout(candidate_directory, release_tag)
    expected_version = expected_version_module(trusted_version, release_tag)
    if files[HANDOFF_VERSION_FILE].read_bytes() != expected_version:
        raise CandidateVerificationError(
            "Candidate version module is not the expected release update."
        )
    expected = expected_payload(trusted_source, expected_version)
    version = normalized_version(release_tag)
    source_root = trusted_root(trusted_source)
    verify_wheel(
        files[DIST_DIRECTORY / f"{PROJECT_STEM}-{version}-py3-none-any.whl"],
        expected,
        release_tag,
        source_root,
    )
    verify_sdist(
        files[DIST_DIRECTORY / f"{PROJECT_STEM}-{version}.tar.gz"],
        expected,
        release_tag,
        source_root,
    )
    copy_verified_artifacts(files, output_directory)


def parse_arguments() -> argparse.Namespace:
    """Parse candidate verification command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare-version")
    prepare.add_argument("--version-path", type=Path, default=VERSION_FILE)
    prepare.add_argument("--release-tag", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--candidate-directory", type=Path, required=True)
    verify.add_argument("--trusted-source", type=Path, default=PACKAGE_DIRECTORY)
    verify.add_argument("--trusted-version", type=Path, default=VERSION_FILE)
    verify.add_argument("--output-directory", type=Path, required=True)
    verify.add_argument("--release-tag", required=True)
    return parser.parse_args()


def main() -> int:
    """Validate a release candidate handoff."""
    arguments = parse_arguments()
    try:
        if arguments.command == "prepare-version":
            prepare_version_module(arguments.version_path, arguments.release_tag)
        else:
            verify_candidate(
                arguments.candidate_directory,
                arguments.trusted_source,
                arguments.trusted_version,
                arguments.output_directory,
                arguments.release_tag,
            )
    except CandidateVerificationError as error:
        print(f"Release candidate verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
