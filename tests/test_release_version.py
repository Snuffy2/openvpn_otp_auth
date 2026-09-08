"""Tests for the shared release-tag to PEP 440 normalization policy."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
from types import ModuleType

import pytest


def load_release_version() -> ModuleType:
    """Load the release policy without packaging GitHub workflow scripts.

    Returns:
        The release tag policy module.
    """
    path = Path(__file__).parents[1] / ".github" / "scripts" / "release_version.py"
    specification = importlib.util.spec_from_file_location("release_version_policy", path)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


policy = load_release_version()


@pytest.mark.parametrize(
    ("release_tag", "expected", "prerelease"),
    [
        ("v1.2", "1.2", False),
        ("v1.2.3", "1.2.3", False),
        ("v1.2.3.4", "1.2.3.4", False),
        ("v1.2a1", "1.2a1", True),
        ("v1.2-alpha.1", "1.2a1", True),
        ("v1.2b2", "1.2b2", True),
        ("v1.2-beta.2", "1.2b2", True),
        ("v1.2rc3", "1.2rc3", True),
        ("v1.2-rc.3", "1.2rc3", True),
        ("v1.2dev4", "1.2.dev4", True),
        ("v1.2-dev4", "1.2.dev4", True),
        ("v1.2-dev.4", "1.2.dev4", True),
        ("v1.2post5", "1.2.post5", True),
        ("v1.2-post5", "1.2.post5", True),
        ("v1.2-post.5", "1.2.post5", True),
        ("v1.2-alpha.0", "1.2a0", True),
        ("v1.2-alpha.01", "1.2a1", True),
        ("v1.2-alpha.10", "1.2a10", True),
        ("v1.2a01", "1.2a1", True),
        ("v1.2-beta.0", "1.2b0", True),
        ("v1.2-beta.01", "1.2b1", True),
        ("v1.2-beta.10", "1.2b10", True),
        ("v1.2b01", "1.2b1", True),
        ("v1.2-rc.0", "1.2rc0", True),
        ("v1.2-rc.01", "1.2rc1", True),
        ("v1.2-rc.10", "1.2rc10", True),
        ("v1.2rc01", "1.2rc1", True),
        ("v1.2-dev.0", "1.2.dev0", True),
        ("v1.2-dev.01", "1.2.dev1", True),
        ("v1.2-dev.10", "1.2.dev10", True),
        ("v1.2-post.0", "1.2.post0", True),
        ("v1.2-post.01", "1.2.post1", True),
        ("v1.2-post.10", "1.2.post10", True),
    ],
)
def test_normalized_version_accepts_the_shared_ascii_pep_440_union(
    release_tag: str, expected: str, prerelease: bool
) -> None:
    """Accepted stable and PEP 440 suffix forms map to canonical package versions."""
    assert policy.normalized_version(release_tag) == expected
    assert policy.is_prerelease_tag(release_tag) is prerelease


@pytest.mark.parametrize(
    "release_tag",
    [
        "v1",
        "v01.2",
        "v1.02",
        "v1.2.03",
        "v1.2.3.04",
        "v1.2.3.4.5",
        "1.2",
        "v1.2rc",
        "v1.2rc١",
        "v1.2-alpha.١",
        "v1.2-beta.١",
        "v1.2-rc.١",
        "v1.2dev١",
        "v1.2-dev.١",
        "v1.2post١",
        "v1.2-post.١",
    ],
)
def test_normalized_version_rejects_non_ascii_or_unsupported_tags(release_tag: str) -> None:
    """Only the fixed ASCII grammar reaches package version normalization."""
    with pytest.raises(policy.ReleaseTagError, match="Unsupported package release tag"):
        policy.normalized_version(release_tag)


def test_trusted_candidate_preparation_supports_an_old_source_without_the_policy(
    tmp_path: Path,
) -> None:
    """A trusted helper snapshot prepares a tagged source that predates the policy module."""
    helper_directory = tmp_path / "trusted-release-helpers"
    helper_directory.mkdir()
    script_directory = Path(__file__).parents[1] / ".github" / "scripts"
    for name in ("release_version.py", "verify_release_candidate.py"):
        shutil.copy2(script_directory / name, helper_directory / name)
    old_source = tmp_path / "old-source"
    version_path = old_source / "src" / "openvpn_otp_auth" / "_version.py"
    version_path.parent.mkdir(parents=True)
    version_path.write_text('VERSION = "v1.2.3"\n', encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(helper_directory / "verify_release_candidate.py"),
            "prepare-version",
            "--release-tag",
            "v1.2-dev.4",
        ],
        cwd=old_source,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert not (old_source / ".github" / "scripts" / "release_version.py").exists()
    assert version_path.read_text(encoding="utf-8") == 'VERSION = "v1.2-dev.4"\n'
