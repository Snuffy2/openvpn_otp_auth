# OpenVPN OTP Auth

* Validates OpenVPN username/password/TOTP from file passed as the first arg when called from OpenVPN server using auth-user-pass-verify.
* TOTP (aka. 2FA, MFA) uses Google Authenticator (or Authenticator-supporting third-party applications).
* User management is done from the CLI and stores users credentials and sessions in SQLite DBs.

## Installation

Install the PyPI package as an isolated command-line tool with
[uv](https://docs.astral.sh/uv/):

```bash
uv tool install openvpn-otp-auth
```

Then create the default OpenWrt config file in `/etc/config/openvpn_otp_auth`.
This is also the path the helper reads at runtime:

```bash
openvpn-otp-auth --install
```

If the current user cannot write to `/etc/config`, run the command with the
needed privileges. If `sudo` cannot find the uv-installed command, use the full
path shown by `uv tool dir --bin`.

Review the generated `openvpn_otp_auth.conf` and make any necessary changes so
the storage locations are correct and the issuer name is set.

For local development, sync the checkout with uv and run the package module or
console script from that environment:

```bash
uv sync --all-groups
uv run python -m openvpn_otp_auth --help
uv run openvpn-otp-auth --help
```

The generated config defaults the SQLite databases and TOTP output files under
`/etc/config/openvpn_otp_auth` too.

<details><summary><h3>Default openvpn_otp_auth.conf (Created by running: openvpn-otp-auth --install)</h3></summary>

```
[OpenVPN OTP Auth]
; set to your business name or name of your vpn
issuer = OpenVPN OTP Auth Issuer
; where the totp qr code files are saved to
totp_out_path = /etc/config/openvpn_otp_auth
; number of hours before requiring new totp if nothing else changes
session_duration = 164
user_db_file = /etc/config/openvpn_otp_auth/users.db
session_db_file = /etc/config/openvpn_otp_auth/sessions.db
```

</details>

<details><summary><h3>Example server.ovpn (incomplete)</h3></summary>

```
mode server
server xx.yy.zz.0 255.255.255.0
port 1234
proto udp4
dev tun0
topology subnet
verb 3
mute 10
log-append '/var/log/openvpn.log'
status '/var/log/openvpn-status.log'
status-version 2
persist-key
persist-tun
user openvpn
group openvpn
script-security 2
auth-user-pass-verify /etc/config/openvpn_otp_auth/openvpn-otp-auth via-file
auth-gen-token 0 external-auth
reneg-sec 3600
keepalive 10 60
explicit-exit-notify
client-to-client
username-as-common-name
mtu-test
push "persist-key"
push "persist-tun"
push "topology subnet"
push "route xx.yy.bb.0 255.255.255.0"
push "dhcp-option DNS xx.yy.bb.1"
push "dhcp-option DOMAIN-SEARCH vpn"
```

</details>

<details><summary><h3>Example client.ovpn (incomplete)</h3></summary>

```
client
remote vpn.server.address port
proto udp4
dev tun
verb 3
nobind
persist-key
persist-tun
remote-cert-tls server
resolv-retry 5
connect-retry-max 5
explicit-exit-notify
auth-user-pass
auth-nocache
auth-retry interact
static-challenge "Enter Authentication Code (TOTP)" 1
```

</details>

## Command Line Options

Option | Description |
-- | -- 
-h, --help | Show help message and exit
--install | Generate the config file with default values
--adduser \<username\> | Add a new user
--deluser \<username\> | Delete an existing user
--changepass \<username\> | Change the password for an existing user
--changetotp \<username\> | Generate a new TOTP for an existing user
--showtotp \<username\> | Show the TOTP for an existing user
--listusers | List all users

### Notes

* Put the username in quotes if getting errors with not enough or too many arguments.
* When new users are created or TOTP is changed, the TOTP QR Code and URL will display and also be saved to a file called \<username\>.totp

## Authors

* **Current Author:** @Snuffy2
* **Initial Author:** @roman-vynar
* **Expanded from:** https://github.com/roman-vynar/random-scripts
