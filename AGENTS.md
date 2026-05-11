# AGENTS.md

Instructions for agents working in this repository.

## Project Overview

This repository contains `openvpn_otp_auth.py`, a standalone OpenVPN
`auth-user-pass-verify via-file` helper that validates username, password, and
TOTP credentials. It stores user credentials and OTP sessions in SQLite, exposes
user-management commands from the CLI, and can generate `.totp` files through
`qrencode` when that command is available.

The project is packaged as the single Python module `openvpn_otp_auth` using
`setuptools` metadata in `pyproject.toml`.

## Repository Layout

- `openvpn_otp_auth.py`: Main script and module. Keep it executable and usable
  as a directly invoked script.
- `pyproject.toml`: Build metadata, runtime dependencies, dev dependency group,
  Ruff, MyPy, pytest, coverage, and codespell configuration.
- `prek.toml`: Hook configuration for formatting, linting, codespell, TOML/YAML
  checks, and GitHub Actions linting.
- `README.md`: User-facing installation and OpenVPN configuration guidance.

## Runtime And Compatibility

- Target Python is `>=3.14`; do not lower the package requirement or tool
  targets unless explicitly asked.
- Preserve direct script behavior: `python openvpn_otp_auth.py ...` must remain
  the primary execution path.
- Preserve OpenVPN environment variable contracts. In particular,
  `session_state` and `untrusted_ip` are lowercase because OpenVPN provides
  them that way.
- Existing session timestamps are SQLite `TIMESTAMP` values using naive local
  datetimes. Do not switch to timezone-aware timestamps unless you also handle
  existing stored rows and validation compatibility.
- `qrencode` is an optional external executable resolved from `PATH`. The script
  should continue user creation/TOTP rotation even when QR generation fails.

## Development Environment

Use the repository-local virtual environment:

```bash
./.venv/bin/python
./.venv/bin/prek
./.venv/bin/mypy
./.venv/bin/ruff
```

If dependencies are missing, install them into `./.venv` from `pyproject.toml`.
Do not rely on global Python tooling for validation.

## Validation Commands

Run these before claiming code or tooling changes are complete:

```bash
./.venv/bin/mypy .
./.venv/bin/prek run --all-files
```

For focused Ruff checks while iterating:

```bash
./.venv/bin/ruff check openvpn_otp_auth.py pyproject.toml
./.venv/bin/ruff format --check openvpn_otp_auth.py
```

There is currently no committed `tests/` suite. If behavior changes are made,
add focused pytest coverage under `tests/` unless the user explicitly says not
to add tests.

## Coding Standards

- Keep edits narrowly scoped to the requested behavior.
- Prefer root-cause fixes over suppressions. Add Ruff ignores only when they
  document an intentional project or external-system contract.
- Keep functions and classes typed.
- Use Google-style docstrings for new or changed public methods. Maintain the
  existing docstring style unless doing a targeted cleanup.
- Preserve existing comments unless they are inaccurate.
- Use `pathlib.Path` for filesystem paths.
- Catch specific exceptions; do not introduce broad `except Exception` blocks.
- Do not convert the script into a package directory without explicit approval.
- Do not remove attribution in `README.md` or file headers.

## Git And File Safety

- Do not push to GitHub or create PRs unless explicitly requested.
- The worktree may contain unrelated user changes. Do not revert or overwrite
  changes you did not make.
