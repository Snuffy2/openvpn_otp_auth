"""OpenVPN username, password, and TOTP authentication helper."""

from ._version import VERSION


def cli(argv: list[str] | None = None) -> int:
    """Run the OpenVPN OTP Auth console entry point."""
    # Keep this lazy so package metadata can load without runtime dependencies.
    from .main import cli as main_cli  # noqa: PLC0415

    return main_cli(argv)


__all__ = ["VERSION", "cli"]
