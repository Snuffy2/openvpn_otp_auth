"""Shared pytest fixtures for the OpenVPN OTP auth tests."""

from __future__ import annotations

import argparse
from collections.abc import Callable
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

import pytest


@pytest.fixture
def script_path() -> Path:
    """Return the path to the standalone OpenVPN OTP auth script."""
    return Path(__file__).resolve().parents[1] / "openvpn_otp_auth.py"


@pytest.fixture
def load_module(
    monkeypatch: pytest.MonkeyPatch, script_path: Path
) -> Callable[[list[str]], ModuleType]:
    """Return a loader for the script module with controlled command-line arguments."""

    def _load_module(argv: list[str]) -> ModuleType:
        """Load the script module and optionally parse controlled command-line arguments."""
        module_name = "openvpn_otp_auth"
        monkeypatch.setattr(sys, "argv", argv)
        sys.modules.pop(module_name, None)
        spec = importlib.util.spec_from_file_location(module_name, script_path)
        if spec is None or spec.loader is None:
            msg = f"Could not load module spec for {script_path}"
            raise RuntimeError(msg)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if argv:
            module.__dict__["args"] = module.parse_args(argv[1:])
        return module

    return _load_module


@pytest.fixture
def configure_auth_storage() -> Callable[[Any, Path, int], None]:
    """Return a helper that points an auth instance at temporary storage."""

    def _configure_auth_storage(auth: Any, tmp_path: Path, session_duration: int = 164) -> None:
        """Point an auth instance at temporary databases and TOTP output."""
        auth.issuer = "Test VPN"
        auth.totp_out_path = str(tmp_path)
        auth.session_duration = session_duration
        auth.user_db_file = str(tmp_path / "users.db")
        auth.session_db_file = str(tmp_path / "sessions.db")

    return _configure_auth_storage


@pytest.fixture
def make_auth(configure_auth_storage: Callable[[Any, Path, int], None]) -> Callable[..., Any]:
    """Return a helper that creates an auth instance backed by temporary storage."""

    def _make_auth(
        module: ModuleType,
        args: argparse.Namespace,
        tmp_path: Path,
        session_duration: int = 164,
    ) -> Any:
        """Create an auth instance backed by temporary storage."""
        auth = module.OpenVPNOTPAuth(args, install=True)
        configure_auth_storage(auth, tmp_path, session_duration)
        return auth

    return _make_auth


@pytest.fixture
def insert_user() -> Callable[..., None]:
    """Return a helper that inserts a user row into an auth database."""

    def _insert_user(
        auth: Any,
        username: str = "alice",
        stored_hash: str | None = None,
        stored_otp_seed: str | None = None,
        totp_uri: str = "uri",
    ) -> None:
        """Insert a user row into the temporary user database."""
        password_hash_value = "hash" if stored_hash is None else stored_hash
        totp_seed_value = "secret" if stored_otp_seed is None else stored_otp_seed
        userdb, usercursor = auth.get_userdb_cursor()
        try:
            usercursor.execute(
                "INSERT INTO users (username, password_hash, totp_secret, totp_uri) "
                "VALUES (?,?,?,?)",
                (username, password_hash_value, totp_seed_value, totp_uri),
            )
            userdb.commit()
        finally:
            userdb.close()

    return _insert_user
