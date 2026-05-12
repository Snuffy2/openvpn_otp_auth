"""Regression tests for the OpenVPN OTP auth script."""

from __future__ import annotations

import argparse
import base64
import contextlib
import importlib.util
import logging
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import ModuleType
from typing import Any

import pyotp
import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "openvpn_otp_auth.py"


def load_module(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> ModuleType:
    """Load the script module with a controlled command-line argument list."""
    module_name = "openvpn_otp_auth"
    monkeypatch.setattr(sys, "argv", argv)
    sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT_PATH)
    if spec is None or spec.loader is None:
        msg = f"Could not load module spec for {SCRIPT_PATH}"
        raise RuntimeError(msg)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_module_loads_with_controlled_cli_args(monkeypatch: pytest.MonkeyPatch) -> None:
    """The script should be importable when provided valid CLI arguments."""
    module = load_module(monkeypatch, ["openvpn_otp_auth.py", "--install"])

    assert module.VERSION
    assert module.args.install is True


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


def test_initial_scrv1_auth_accepts_valid_password_and_totp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Initial OpenVPN auth should accept valid password and TOTP credentials."""
    totp_seed = "JBSWY3DPEHPK3PXP"
    otp = "123456"
    encoded_password = base64.b64encode(b"correct-password").decode()
    encoded_otp = base64.b64encode(otp.encode()).decode()
    credentials = tmp_path / "credentials.txt"
    credentials.write_text(f"alice\nSCRV1:{encoded_password}:{encoded_otp}\n")
    module = load_module(monkeypatch, ["openvpn_otp_auth.py", str(credentials)])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    password_hash = auth.ph.hash("correct-password")
    stored_sessions: list[tuple[str, str, str]] = []
    monkeypatch.delenv("session_state", raising=False)
    monkeypatch.setenv("IV_GUI_VER", "OpenVPN Connect")
    monkeypatch.setenv("untrusted_ip", "198.51.100.10")
    monkeypatch.setattr(
        auth,
        "get_user",
        lambda _username: ("alice", password_hash, totp_seed, "otpauth://totp/alice"),
    )

    def verify_totp(totp_secret: str, entered_otp: str) -> bool:
        """Check the expected TOTP inputs from the auth flow."""
        return (totp_secret, entered_otp) == (totp_seed, otp)

    monkeypatch.setattr(
        auth,
        "verify_totp",
        verify_totp,
    )
    monkeypatch.setattr(
        auth,
        "store_session",
        lambda username, vpn_client, current_ip, _created: stored_sessions.append(
            (username, vpn_client, current_ip)
        ),
    )

    with pytest.raises(SystemExit) as exc_info:
        auth.main()

    assert exc_info.value.code == 0
    assert stored_sessions == [("alice", "OpenVPN Connect", "198.51.100.10")]


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
    with contextlib.closing(sqlite3.connect(auth.user_db_file)) as db:
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
    with contextlib.closing(sqlite3.connect(auth.user_db_file)) as db:
        assert (
            db.execute(
                "SELECT username FROM users WHERE username = ?",
                ("../outside",),
            ).fetchone()
            is None
        )
    assert outside_file.read_text() == "do not delete"


def test_changetotp_updates_legacy_path_traversal_username_without_writing_outside_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Legacy unsafe usernames should get new TOTP secrets without unsafe file writes."""
    module = load_module(monkeypatch, ["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(argparse.Namespace(changetotp=["../outside"]), install=True)
    auth.issuer = "Test VPN"
    auth.totp_out_path = str(tmp_path)
    auth.user_db_file = str(tmp_path / "users.db")
    auth.session_db_file = str(tmp_path / "sessions.db")
    outside_file = tmp_path.parent / "outside.totp"
    outside_file.write_text("do not overwrite")
    userdb, usercursor = auth.get_userdb_cursor()
    usercursor.execute(
        "INSERT INTO users (username, password_hash, totp_secret, totp_uri) VALUES (?,?,?,?)",
        ("../outside", "hash", "old-secret", "old-uri"),
    )
    userdb.commit()
    userdb.close()
    monkeypatch.setattr(module.pyotp, "random_base32", lambda: "JBSWY3DPEHPK3PXP")

    with pytest.raises(SystemExit) as exc_info:
        auth.changetotp()

    assert exc_info.value.code == 99
    stdout = capsys.readouterr().out
    with contextlib.closing(sqlite3.connect(auth.user_db_file)) as db:
        totp_secret, totp_uri = db.execute(
            "SELECT totp_secret, totp_uri FROM users WHERE username = ?",
            ("../outside",),
        ).fetchone()
    assert totp_secret in totp_uri
    assert totp_uri != "old-uri"
    assert outside_file.read_text() == "do not overwrite"
    assert totp_uri in stdout


def test_verify_totp_accepts_current_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """TOTP verification should accept the current valid one-time password."""
    module = load_module(monkeypatch, ["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    totp_seed = pyotp.random_base32()

    assert auth.verify_totp(totp_seed, pyotp.TOTP(totp_seed).now())


def test_store_session_persists_session(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Session storage should write retrievable SQLite session state."""
    module = load_module(monkeypatch, ["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    auth.session_db_file = str(tmp_path / "sessions.db")
    created = module.datetime.datetime(2026, 5, 12, 10, 30, 0)

    auth.store_session("alice", "OpenVPN Connect", "198.51.100.10", created)

    with contextlib.closing(sqlite3.connect(auth.session_db_file)) as verify_db:
        verify_cursor = verify_db.execute(
            "SELECT vpn_client, ip_address, verified_on FROM sessions WHERE username = ?",
            ("alice",),
        )
        try:
            assert verify_cursor.fetchone() == (
                "OpenVPN Connect",
                "198.51.100.10",
                "2026-05-12 10:30:00",
            )
        finally:
            verify_cursor.close()


def test_get_db_cursor_creates_schema(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Database cursor helper should create missing SQLite files with the schema."""
    module = load_module(monkeypatch, ["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    db_path = tmp_path / "users.db"
    auth.user_db_file = str(db_path)

    db, cursor = auth.get_userdb_cursor()
    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'users'")
        assert cursor.fetchone() == ("users",)
    finally:
        db.close()

    with contextlib.closing(sqlite3.connect(db_path)) as verify_db:
        verify_cursor = verify_db.execute("SELECT COUNT(*) FROM users")
        try:
            assert verify_cursor.fetchone() == (0,)
        finally:
            verify_cursor.close()
