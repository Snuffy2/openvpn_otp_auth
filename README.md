# OpenVPN TOTP Auth Python Script

* Validates OpenVPN username/password/TOTP from file passed as the first arg when called from OpenVPN server using auth-user-pass-verify. 
* TOTP (aka. 2FA, MFA) uses Google Authenticator (or Authenticator-supporting third-party applications).
* User management is done from the CLI and stores users credentials and sessions in SQLite DBs.

## Installation

1. Place the openvpn_otp_auth.py script in a location that ideally wont be removed by system updates (ex. /etc/config/ovpnauth).
2. Run: `python openvpn_otp_auth.py --install` to build the config file `openvpn_otp_auth.conf` in the same folder as the python script.
3. Review the Config file and make any neccesary changes making sure the locations are correct and the issuer name is set.

<details><summary><h3>Default openvpn_otp_auth.conf (Created by running: python openvpn_otp_auth.py --install)</h3></summary>

```
[OpenVPN Auth]
; set to your business name or name of your vpn
issuer = OVPNAuth Issuer
; where the totp qr code files are saved to
totp_out_path = /etc/config/ovpnauth
; number of hours before requiring new totp if nothing else changes
session_duration = 164
user_db_file = /etc/config/ovpnauth/users.db
session_db_file = /etc/config/ovpnauth/sessions.db
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
auth-user-pass-verify /etc/config/ovpnauth/openvpn_otp_auth.py via-file
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
--adduser \<username\> \<password\> | Add a new user
--deluser \<username\> | Delete an existing user
--changepass \<username\> \<new_password\> | Change the password for an existing user
--changetotp \<username\> | Generate a new TOTP for an existing user
--showtotp \<username\> | Show the TOTP for an existing user
--listusers | List all users

### Notes

* Put the username or password in quotes if getting errors with not enough arguments. 
* When new users are created or TOTP is changed, the TOTP QR Code and URL will display and also be saved to a file called \<username\>.totp

## Authors

* **Current Author:** @Snuffy2
* **Initial Author:** @roman-vynar
* **Expanded from:** https://github.com/roman-vynar/random-scripts
