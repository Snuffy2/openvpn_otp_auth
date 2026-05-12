"""Regression tests for the OpenVPN OTP auth script."""

from __future__ import annotations

import argparse
import base64
import contextlib
import logging
from pathlib import Path
import sqlite3
import subprocess
import sys
from typing import Any
import warnings

import pyotp
import pytest


def test_module_loads_with_controlled_cli_args(load_module: Any) -> None:
    """The script should be importable when provided valid CLI arguments."""
    module = load_module(["openvpn_otp_auth.py", "--install"])

    assert module.VERSION
    assert module.args.install is True


def test_debug_import_handles_unavailable_log_file(
    monkeypatch: pytest.MonkeyPatch, load_module: Any
) -> None:
    """Debug startup should not crash when the file logger cannot be created."""

    def blocked_file_handler(*_args: Any, **_kwargs: Any) -> logging.FileHandler:
        """Raise the same error a protected installation directory would raise."""
        raise PermissionError("blocked")

    monkeypatch.setattr(logging, "FileHandler", blocked_file_handler)

    module = load_module(["openvpn_otp_auth.py", "--debug", "credentials"])

    assert module.args.debug is True


def test_main_uses_parsed_filename_when_debug_precedes_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any
) -> None:
    """The auth path should come from argparse, not the raw first argv item."""
    credentials = tmp_path / "credentials.txt"
    credentials.write_text("alice\nnot-scrv1\n")
    module = load_module(["openvpn_otp_auth.py", "--debug", str(credentials)])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    monkeypatch.setattr(auth, "get_user", lambda _username: ("alice", "hash", "secret", "uri"))

    with pytest.raises(SystemExit) as exc_info:
        auth.main()

    assert exc_info.value.code == 1


def test_initial_scrv1_auth_accepts_valid_password_and_totp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any
) -> None:
    """Initial OpenVPN auth should accept valid password and TOTP credentials."""
    totp_seed = "JBSWY3DPEHPK3PXP"
    otp = "123456"
    encoded_password = base64.b64encode(b"correct-password").decode()
    encoded_otp = base64.b64encode(otp.encode()).decode()
    credentials = tmp_path / "credentials.txt"
    credentials.write_text(f"alice\nSCRV1:{encoded_password}:{encoded_otp}\n")
    module = load_module(["openvpn_otp_auth.py", str(credentials)])
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
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
) -> None:
    """TOTP rotation should not leave stale QR/file contents behind."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, argparse.Namespace(changetotp=["alice"]), tmp_path)
    insert_user(auth, stored_otp_seed="old-secret", totp_uri="old-uri")
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
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
) -> None:
    """Legacy unsafe usernames should be removed without unsafe file deletion."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, argparse.Namespace(deluser=["../outside"]), tmp_path)
    outside_file = tmp_path.parent / "outside.totp"
    outside_file.write_text("do not delete")
    insert_user(auth, username="../outside")

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
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
) -> None:
    """Legacy unsafe usernames should get new TOTP secrets without unsafe file writes."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, argparse.Namespace(changetotp=["../outside"]), tmp_path)
    outside_file = tmp_path.parent / "outside.totp"
    outside_file.write_text("do not overwrite")
    insert_user(auth, username="../outside", stored_otp_seed="old-secret", totp_uri="old-uri")
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


def test_verify_totp_accepts_current_code(
    monkeypatch: pytest.MonkeyPatch, load_module: Any
) -> None:
    """TOTP verification should accept the current valid one-time password."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    totp_seed = pyotp.random_base32()

    assert auth.verify_totp(totp_seed, pyotp.TOTP(totp_seed).now())


def test_store_session_persists_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any
) -> None:
    """Session storage should write retrievable SQLite session state."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    auth.session_db_file = str(tmp_path / "sessions.db")
    created = module.datetime.datetime(2026, 5, 12, 10, 30, 0)

    with warnings.catch_warnings(record=True) as caught_warnings:
        warnings.simplefilter("always")
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
    assert caught_warnings == []


def test_get_session_returns_datetime_from_stored_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any, make_auth: Any
) -> None:
    """Session lookup should return parsed datetime values for validation."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, module.args, tmp_path)
    created = module.datetime.datetime(2026, 5, 12, 10, 30, 0)
    auth.store_session("alice", "OpenVPN Connect", "198.51.100.10", created)

    assert auth.get_session("alice") == ("OpenVPN Connect", "198.51.100.10", created)


def test_load_config_reads_quoted_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any, script_path: Path
) -> None:
    """Configuration loading should strip shell-style quotes from path values."""
    config_file = script_path.with_suffix(".conf")
    config_text = config_file.read_text()
    config_file.write_text(
        "\n".join(
            [
                "[OpenVPN OTP Auth]",
                'ISSUER = "Quoted VPN"',
                f"TOTP_OUT_PATH = '{tmp_path}'",
                "SESSION_DURATION = 4",
                f'USER_DB_FILE = "{tmp_path / "users.db"}"',
                f"SESSION_DB_FILE = '{tmp_path / 'sessions.db'}'",
                "",
            ]
        )
    )
    try:
        module = load_module(["openvpn_otp_auth.py", "credentials"])
        auth = module.OpenVPNOTPAuth(module.args)
    finally:
        config_file.write_text(config_text)

    assert auth.issuer == "Quoted VPN"
    assert auth.totp_out_path == str(tmp_path)
    assert auth.session_duration == 4
    assert auth.user_db_file == str(tmp_path / "users.db")
    assert auth.session_db_file == str(tmp_path / "sessions.db")


@pytest.mark.parametrize("username", ["", ".", "..", "../alice", "nested/alice", "/alice"])
def test_totp_file_path_rejects_unsafe_usernames(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    username: str,
    load_module: Any,
    make_auth: Any,
) -> None:
    """TOTP file paths should reject empty, traversal, nested, and absolute names."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, module.args, tmp_path)

    with pytest.raises(ValueError):
        auth._totp_file_path(username)


def test_write_totp_file_appends_uri_after_qr_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any, make_auth: Any
) -> None:
    """Successful QR generation should append the provisioning URI to the TOTP file."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, module.args, tmp_path)

    def write_qr(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        """Pretend qrencode wrote the QR payload to the requested output file."""
        Path(args[5]).write_text("QR\n")
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(module.subprocess, "run", write_qr)

    totp_file = auth._write_totp_file("alice", "otpauth://totp/alice")

    assert totp_file.read_text() == "QR\n\notpauth://totp/alice"


def test_user_lookup_and_hash_update_use_database(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
) -> None:
    """User helpers should read existence and update password hashes in SQLite."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, module.args, tmp_path)
    insert_user(auth)

    assert auth.check_user("alice") is True
    assert auth.check_user("bob") is False
    assert auth.get_user("alice") == ("alice", "hash", "secret", "uri")

    auth.update_hash_for_user("alice", "new-hash")

    assert auth.get_user("alice") == ("alice", "new-hash", "secret", "uri")


def test_get_db_cursor_rejects_missing_path(
    monkeypatch: pytest.MonkeyPatch, load_module: Any
) -> None:
    """Database cursor helper should reject an unset database file path."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(module.args, install=True)

    with pytest.raises(ValueError):
        auth._get_db_cursor("", module.USER_DB_SCHEMA)


def test_get_db_cursor_logs_sqlite_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any
) -> None:
    """Database cursor helper should surface SQLite errors for invalid paths."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(module.args, install=True)

    with pytest.raises(sqlite3.Error):
        auth._get_db_cursor(str(tmp_path), module.USER_DB_SCHEMA)


def test_create_session_requires_openvpn_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any, make_auth: Any
) -> None:
    """Session creation should fail when OpenVPN has not provided client metadata."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, module.args, tmp_path)
    monkeypatch.delenv("IV_GUI_VER", raising=False)
    monkeypatch.delenv("untrusted_ip", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        auth.create_session("alice")

    assert exc_info.value.code == 1


def test_validate_session_accepts_matching_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any, make_auth: Any
) -> None:
    """Session validation should accept matching client, IP, and fresh timestamp."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, module.args, tmp_path, session_duration=1)
    monkeypatch.setenv("IV_GUI_VER", "OpenVPN Connect")
    monkeypatch.setenv("untrusted_ip", "198.51.100.10")
    auth.store_session(
        "alice",
        "OpenVPN Connect",
        "198.51.100.10",
        module.datetime.datetime.now(),
    )

    with pytest.raises(SystemExit) as exc_info:
        auth.validate_session("alice")

    assert exc_info.value.code == 0


@pytest.mark.parametrize(
    ("stored_client", "stored_ip", "created_offset_hours"),
    [
        ("Other Client", "198.51.100.10", 0),
        ("OpenVPN Connect", "203.0.113.25", 0),
        ("OpenVPN Connect", "198.51.100.10", 2),
    ],
)
def test_validate_session_rejects_changed_or_expired_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    stored_client: str,
    stored_ip: str,
    created_offset_hours: int,
) -> None:
    """Session validation should reject changed clients, changed IPs, and expiry."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, module.args, tmp_path, session_duration=1)
    monkeypatch.setenv("IV_GUI_VER", "OpenVPN Connect")
    monkeypatch.setenv("untrusted_ip", "198.51.100.10")
    auth.store_session(
        "alice",
        stored_client,
        stored_ip,
        module.datetime.datetime.now() - module.datetime.timedelta(hours=created_offset_hours),
    )

    with pytest.raises(SystemExit) as exc_info:
        auth.validate_session("alice")

    assert exc_info.value.code == 1


def test_validate_session_rejects_missing_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any, make_auth: Any
) -> None:
    """Session validation should reject usernames without stored session state."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, module.args, tmp_path)

    with pytest.raises(SystemExit) as exc_info:
        auth.validate_session("alice")

    assert exc_info.value.code == 1


@pytest.mark.parametrize(
    ("stored_user", "password_line", "session_state"),
    [
        (None, "SCRV1:cGFzcw==:MTIzNDU2", None),
        (("alice", "hash", "secret", "uri"), "SCRV1:***:MTIzNDU2", None),
        (("alice", "hash", "secret", "uri"), "plain-password", None),
        (("alice", "hash", "secret", "uri"), "SCRV1:cGFzcw==:MTIzNDU2", "Bogus"),
    ],
)
def test_main_rejects_invalid_auth_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    stored_user: tuple[str, str, str, str] | None,
    password_line: str,
    session_state: str | None,
) -> None:
    """Main auth should reject missing users, malformed credentials, and bad state."""
    credentials = tmp_path / "credentials.txt"
    credentials.write_text(f"alice\n{password_line}\n")
    module = load_module(["openvpn_otp_auth.py", str(credentials)])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    monkeypatch.setattr(auth, "get_user", lambda _username: stored_user)
    if session_state is None:
        monkeypatch.delenv("session_state", raising=False)
    else:
        monkeypatch.setenv("session_state", session_state)

    with pytest.raises(SystemExit) as exc_info:
        auth.main()

    assert exc_info.value.code == 1


def test_main_rehashes_password_when_needed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any
) -> None:
    """Successful auth should refresh stored hashes when Argon2 policy changes."""
    credentials = tmp_path / "credentials.txt"
    encoded_password = base64.b64encode(b"correct-password").decode()
    encoded_otp = base64.b64encode(b"123456").decode()
    credentials.write_text(f"alice\nSCRV1:{encoded_password}:{encoded_otp}\n")
    module = load_module(["openvpn_otp_auth.py", str(credentials)])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    updated_hashes: list[str] = []
    monkeypatch.delenv("session_state", raising=False)
    monkeypatch.setattr(auth, "get_user", lambda _username: ("alice", "hash", "secret", "uri"))

    class RehashingHasher:
        """Password hasher double that requests and creates a new hash."""

        def verify(self, _password_hash: str, _password: str) -> bool:
            """Accept the supplied password hash."""
            return True

        def check_needs_rehash(self, _password_hash: str) -> bool:
            """Request rehashing for the stored password hash."""
            return True

        def hash(self, password: str) -> str:
            """Return a visible replacement hash for assertions."""
            return f"new-{password}"

    auth.ph = RehashingHasher()
    monkeypatch.setattr(
        auth,
        "update_hash_for_user",
        lambda _username, new_hash: updated_hashes.append(new_hash),
    )
    monkeypatch.setattr(auth, "verify_totp", lambda _secret, _otp: True)
    monkeypatch.setattr(auth, "create_session", lambda _username: None)

    with pytest.raises(SystemExit) as exc_info:
        auth.main()

    assert exc_info.value.code == 0
    assert updated_hashes == ["new-correct-password"]


def test_main_authenticated_state_delegates_to_session_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any
) -> None:
    """Authenticated OpenVPN renegotiation should validate the existing session."""
    credentials = tmp_path / "credentials.txt"
    credentials.write_text("alice\nignored\n")
    module = load_module(["openvpn_otp_auth.py", str(credentials)])
    auth = module.OpenVPNOTPAuth(module.args, install=True)
    validated_users: list[str] = []
    monkeypatch.setattr(auth, "get_user", lambda _username: ("alice", "hash", "secret", "uri"))
    monkeypatch.setenv("session_state", "Authenticated")

    def validate_session(username: str) -> None:
        """Record the validated username before exiting like the real method."""
        validated_users.append(username)
        sys.exit(0)

    monkeypatch.setattr(auth, "validate_session", validate_session)

    with pytest.raises(SystemExit) as exc_info:
        auth.main()

    assert exc_info.value.code == 0
    assert validated_users == ["alice"]


def test_adduser_creates_database_row_and_totp_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    configure_auth_storage: Any,
) -> None:
    """Adding a user should persist credentials and write TOTP setup output."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(argparse.Namespace(adduser=["alice"]), install=True)
    configure_auth_storage(auth, tmp_path)
    passwords = iter(["new-password", "new-password"])
    monkeypatch.setattr(module, "getpass_asterisk", lambda _prompt: next(passwords))
    monkeypatch.setattr(module.pyotp, "random_base32", lambda: "JBSWY3DPEHPK3PXP")

    def missing_qrencode(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        """Simulate a host without qrencode installed."""
        raise FileNotFoundError("qrencode")

    monkeypatch.setattr(module.subprocess, "run", missing_qrencode)

    with pytest.raises(SystemExit) as exc_info:
        auth.adduser()

    assert exc_info.value.code == 99
    stored_user = auth.get_user("alice")
    assert stored_user is not None
    assert auth.ph.verify(stored_user[1], "new-password")
    assert (tmp_path / "alice.totp").read_text() == stored_user[3]


@pytest.mark.parametrize(
    ("username", "existing_username", "passwords"),
    [
        pytest.param("alice", "alice", None, id="duplicate"),
        pytest.param("bob", None, ["one", "two"], id="password-mismatch"),
        pytest.param("../outside", None, None, id="unsafe-username"),
    ],
)
def test_adduser_rejects_invalid_user_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
    username: str,
    existing_username: str | None,
    passwords: list[str] | None,
) -> None:
    """Adding users should reject duplicates, password mismatches, and unsafe names."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, argparse.Namespace(adduser=[username]), tmp_path)
    if existing_username is not None:
        insert_user(auth, username=existing_username)
    if passwords is not None:
        password_values = iter(passwords)
        monkeypatch.setattr(module, "getpass_asterisk", lambda _prompt: next(password_values))

    with pytest.raises(SystemExit) as exc_info:
        auth.adduser()

    assert exc_info.value.code == 99
    if existing_username is None and "/" not in username:
        assert auth.get_user(username) is None


def test_install_reports_existing_config(monkeypatch: pytest.MonkeyPatch, load_module: Any) -> None:
    """Install should exit cleanly when the repository config already exists."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = module.OpenVPNOTPAuth(module.args, install=True)

    with pytest.raises(SystemExit) as exc_info:
        auth.install()

    assert exc_info.value.code == 99


def test_changepass_updates_existing_user(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
) -> None:
    """Changing a password should replace the stored Argon2 hash."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, argparse.Namespace(changepass=["alice"]), tmp_path)
    insert_user(auth, stored_hash=auth.ph.hash("old-password"))
    passwords = iter(["new-password", "new-password"])
    monkeypatch.setattr(module, "getpass_asterisk", lambda _prompt: next(passwords))

    with pytest.raises(SystemExit) as exc_info:
        auth.changepass()

    assert exc_info.value.code == 99
    stored_user = auth.get_user("alice")
    assert stored_user is not None
    assert auth.ph.verify(stored_user[1], "new-password")


@pytest.mark.parametrize("passwords", [None, ["one", "two"]])
def test_changepass_rejects_missing_user_or_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
    passwords: list[str] | None,
) -> None:
    """Changing a password should reject missing users and mismatched confirmation."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, argparse.Namespace(changepass=["alice"]), tmp_path)
    if passwords is not None:
        insert_user(auth)
        password_values = iter(passwords)
        monkeypatch.setattr(module, "getpass_asterisk", lambda _prompt: next(password_values))

    with pytest.raises(SystemExit) as exc_info:
        auth.changepass()

    assert exc_info.value.code == 99


def test_deluser_removes_safe_totp_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
) -> None:
    """Deleting a normal user should remove both the row and the TOTP file."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, argparse.Namespace(deluser=["alice"]), tmp_path)
    insert_user(auth)
    totp_file = tmp_path / "alice.totp"
    totp_file.write_text("totp")

    with pytest.raises(SystemExit) as exc_info:
        auth.deluser()

    assert exc_info.value.code == 99
    assert auth.get_user("alice") is None
    assert not totp_file.exists()


def test_showtotp_outputs_existing_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
) -> None:
    """Showing a TOTP should read the stored setup file for an existing user."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, argparse.Namespace(showtotp=["alice"]), tmp_path)
    insert_user(auth)
    (tmp_path / "alice.totp").write_text("totp-output")

    with pytest.raises(SystemExit) as exc_info:
        auth.showtotp()

    assert exc_info.value.code == 99


@pytest.mark.parametrize("username", ["missing", "../outside"])
def test_showtotp_handles_missing_or_unsafe_user(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
    username: str,
) -> None:
    """Showing a TOTP should exit cleanly for missing users and unsafe legacy names."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, argparse.Namespace(showtotp=[username]), tmp_path)
    if username != "missing":
        insert_user(auth, username=username)

    with pytest.raises(SystemExit) as exc_info:
        auth.showtotp()

    assert exc_info.value.code == 99


def test_listusers_orders_usernames(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    load_module: Any,
    make_auth: Any,
    insert_user: Any,
) -> None:
    """Listing users should query users in ascending username order."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
    auth = make_auth(module, argparse.Namespace(listusers=True), tmp_path)
    logged_messages: list[str] = []
    insert_user(auth, username="charlie")
    insert_user(auth, username="alice")

    def record_log(message: str, *args: Any) -> None:
        """Record formatted setup log messages for assertion."""
        logged_messages.append(message % args)

    monkeypatch.setattr(module.setup_logger, "info", record_log)

    with pytest.raises(SystemExit) as exc_info:
        auth.listusers()

    assert exc_info.value.code == 99
    assert logged_messages == ["Users: 2\n_______________________", "alice", "charlie"]


def test_get_db_cursor_creates_schema(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, load_module: Any
) -> None:
    """Database cursor helper should create missing SQLite files with the schema."""
    module = load_module(["openvpn_otp_auth.py", "--install"])
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
