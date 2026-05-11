"""Regression tests for the OpenVPN OTP auth script."""

from __future__ import annotations

import argparse
import importlib.util
import logging
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import ModuleType
from typing import Any

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "openvpn_otp_auth.py"


def load_module(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> ModuleType:
    """Load the script module with a controlled command-line argument list."""
    module_name = "openvpn_otp_auth_under_test"
    monkeypatch.setattr(sys, "argv", argv)
    sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT_PATH)
    if spec is None or spec.loader is None:
        msg = f"Could not load module spec for {SCRIPT_PATH}"
        raise RuntimeError(msg)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_debug_import_handles_unavailable_log_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Debug startup should not crash when the file logger cannot be created."""

    def blocked_file_handler(*_args: Any, **_kwargs: Any) -> logging.FileHandler:
        """Raise the same error a protected installation directory would raise."""
        raise PermissionError("blocked")

    monkeypatch.setattr(logging, "FileHandler", blocked_file_handler)

    module = load_module(monkeypatch, ["openvpn_otp_auth.py", "--debug", "credentials"])

    assert module.args.debug is True


def test_main_uses_parsed_filename_when_debug_precedes_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The auth path should come from argparse, not the raw first argv item."""
    credentials = tmp_path / "credentials.txt"
    credentials.write_text("alice\nnot-scrv1\n")
    module = load_module(monkeypatch, ["openvpn_otp_auth.py", "--debug", str(credentials)])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    monkeypatch.setattr(auth, "get_user", lambda _username: ("alice", "hash", "secret", "uri"))

    with pytest.raises(SystemExit) as exc_info:
        auth.main()

    assert exc_info.value.code == 1


def test_changetotp_rewrites_existing_totp_file_when_qr_generation_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """TOTP rotation should not leave stale QR/file contents behind."""
    module = load_module(monkeypatch, ["openvpn_otp_auth.py", "--install"])
    args = argparse.Namespace(changetotp=["alice"])
    auth = module.OpenVPNOTPAuth(args, install=True)
    auth.issuer = "Test VPN"
    auth.totp_out_path = str(tmp_path)
    auth.user_db_file = str(tmp_path / "users.db")
    auth.session_db_file = str(tmp_path / "sessions.db")
    userdb, usercursor = auth.get_userdb_cursor()
    usercursor.execute(
        "INSERT INTO users (username, password_hash, totp_secret, totp_uri) VALUES (?,?,?,?)",
        ("alice", "hash", "old-secret", "old-uri"),
    )
    userdb.commit()
    userdb.close()
    totp_file = tmp_path / "alice.totp"
    totp_file.write_text("OLD QR CONTENT\nold-uri")
    monkeypatch.setattr(module.pyotp, "random_base32", lambda: "JBSWY3DPEHPK3PXP")

    def missing_qrencode(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        """Simulate a host that does not have qrencode installed."""
        raise FileNotFoundError("qrencode")

    monkeypatch.setattr(module.subprocess, "run", missing_qrencode)

    with pytest.raises(SystemExit) as exc_info:
        auth.changetotp()

    assert exc_info.value.code == 99
    with sqlite3.connect(auth.user_db_file) as db:
        totp_uri = db.execute(
            "SELECT totp_uri FROM users WHERE username = ?",
            ("alice",),
        ).fetchone()[0]
    assert totp_file.read_text() == totp_uri
    assert "OLD QR CONTENT" not in totp_file.read_text()


def test_deluser_removes_legacy_path_traversal_username_without_unlinking_outside_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Legacy unsafe usernames should be removed without unsafe file deletion."""
    module = load_module(monkeypatch, ["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(argparse.Namespace(deluser=["../outside"]), install=True)
    auth.totp_out_path = str(tmp_path)
    auth.user_db_file = str(tmp_path / "users.db")
    auth.session_db_file = str(tmp_path / "sessions.db")
    outside_file = tmp_path.parent / "outside.totp"
    outside_file.write_text("do not delete")
    userdb, usercursor = auth.get_userdb_cursor()
    usercursor.execute(
        "INSERT INTO users (username, password_hash, totp_secret, totp_uri) VALUES (?,?,?,?)",
        ("../outside", "hash", "secret", "uri"),
    )
    userdb.commit()
    userdb.close()

    with pytest.raises(SystemExit) as exc_info:
        auth.deluser()

    assert exc_info.value.code == 99
    with sqlite3.connect(auth.user_db_file) as db:
        assert (
            db.execute(
                "SELECT username FROM users WHERE username = ?",
                ("../outside",),
            ).fetchone()
            is None
        )
    assert outside_file.read_text() == "do not delete"
