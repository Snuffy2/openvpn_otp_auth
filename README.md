# OpenVPN TOTP Auth Python Script

* Validates OpenVPN username/password/TOTP from file passed as the first arg when called from OpenVPN server using auth-user-pass-verify. 
* TOTP (aka. 2FA, MFA) uses Google Authenticator (or Authenticator-supporting third-party applications).
* User management is done from the CLI and stores users credentials and sessions in SQLite DBs.

## Installation

1. Place the openvpn_otp_auth.py script in a location that ideally wont be removed by system updates (ex. /etc/config/ovpnauth).
2. Run: `python openvpn_otp_auth.py --install` to build the config file `openvpn_otp_auth.conf` in the same folder as the python script.
3. Review the Config file and make any neccesary changes making sure the locations are correct and the issuer name is set.

### Example server.ovpn lines

```
        auth-user-pass-verify /etc/config/ovpnauth/openvpn_otp_auth.py via-file
        auth-gen-token 0 external-auth
```

## Command Line Options

Option | Description |
-- | -- 
-h, --help | show help message and exit
--install | Generate the config file with default values
--adduser \<username\> \<password\> | Add a new user
--deluser \<username\> | Delete an existing user
--changepass \<username\> \<new_password\> | Change the password for an existing user
--changetotp \<username\> | Generate a new TOTP for an existing user
--showtotp \<username\> | Show the TOTP for an existing user
--listusers | List all users

### Notes

* Put the username or password in quotes if getting errors with not enough arguments. 
* When new users are created or TOTP is changed, the TOTP QR Code and URL will display and also be saved to a file called <name>.totp

## Authors

* **Current Author:** @Snuffy2
* **Initial Author:** @roman-vynar
* **Expanded from:** https://github.com/roman-vynar/random-scripts
