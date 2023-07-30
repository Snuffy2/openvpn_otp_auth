# OpenVPN TOTP Auth Python Script

Validates OpenVPN username/password/TOTP from file passed as the first arg when called using auth-user-pass-verify.
TOTP/2FA/MFA uses Google Authenticator (or Authenticator-supporting third-party applications)
User management is done from the CLI and stores users credentials and sessions in SQLite DBs.

**Use cases:**
1. Initial connect or after manual disconnect - a new OTP session record is created.
2. If using auth-gen-token with external-auth - a user session is validated.

## Authors

**Current Author:** @Snuffy2
**Initial Author:** @roman-vynar
**Expanded from:** https://github.com/roman-vynar/random-scripts
