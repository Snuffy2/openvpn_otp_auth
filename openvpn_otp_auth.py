#!/usr/bin/env python3
"""OpenVPN OTP auth script.
Version: v1.2

Author: @Snuffy2
Initial Author: @roman-vynar
Expanded from: https://github.com/roman-vynar/random-scripts

https://github.com/Snuffy2/openvpn_otp_auth
"""
import argparse
import base64
import configparser
import datetime
import hashlib
import os
import pwd
import sqlite3
import subprocess
import sys

import argon2
import pyotp
from getpass_asterisk.getpass_asterisk import getpass_asterisk

ph = argon2.PasswordHasher()
parser = argparse.ArgumentParser(
    description=f"""OpenVPN python authentication script with password and multi-factor authentication (MFA) [TOTP] for use with auth-user-pass-verify via-file option.\n
Current path: {os.path.dirname(os.path.abspath(__file__))}
Installation:
1. Place the {os.path.basename(__file__)} script in a location that ideally wont be removed by system updates (ex. /etc/config/openvpn_otp_auth).
2. Run: 'python {os.path.basename(__file__)} --install' to build the config file {os.path.basename(__file__).split('.')[0]}.conf in the same folder as the python script.
3. Review the Config file and make any neccesary changes making sure the locations are correct and the issuer name is set.\n
Example server.ovpn lines:\n\tauth-user-pass-verify /etc/config/openvpn_otp_auth/{os.path.basename(__file__)} via-file\n\tauth-gen-token 0 external-auth\n\n""",
    epilog="Put the username in quotes if getting errors with not enough or too many arguments. When new users are created or TOTP is changed, the TOTP QR Code and URL will display and also be saved to a file called <name>.totp",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)

ovpnauth = parser.add_mutually_exclusive_group(required=True)
ovpnauth.add_argument(
    "filename", help="Called by OpenVPN with the file of login credentials", nargs="?"
)
ovpnauth.add_argument(
    "--install",
    help="Generate the config file with default values",
    action="store_true",
)
ovpnauth.add_argument(
    "--adduser",
    help="Add a new user",
    type=str,
    nargs=1,
    metavar=("<username>"),
)
ovpnauth.add_argument(
    "--deluser",
    help="Delete an existing user",
    type=str,
    nargs=1,
    metavar=("<username>"),
)
ovpnauth.add_argument(
    "--changepass",
    help="Change the password for an existing user",
    type=str,
    nargs=1,
    metavar=("<username>"),
)
ovpnauth.add_argument(
    "--changetotp",
    help="Generate a new TOTP for an existing user",
    type=str,
    nargs=1,
    metavar=("<username>"),
)
ovpnauth.add_argument(
    "--showtotp",
    help="Show the TOTP for an existing user",
    type=str,
    nargs=1,
    metavar=("<username>"),
)
ovpnauth.add_argument("--listusers", help="List all users", action="store_true")
args = parser.parse_args()
# print(f"Debug: args: {args}")

SESSION_DB_SCHEMA = "CREATE TABLE sessions (username VARCHAR PRIMARY KEY, vpn_client VARCHAR, ip_address VARCHAR, verified_on TIMESTAMP)"
USER_DB_SCHEMA = "CREATE TABLE users (username VARCHAR PRIMARY KEY, password_hash VARCHAR, totp_secret VARCHAR, totp_uri VARCHAR)"


def main():
    """Main func."""
    print(
        f">> Running {os.path.basename(__file__)} as User: {pwd.getpwuid(os.geteuid()).pw_name} [{os.geteuid()}]"
    )
    # First arg is a tmp file with 2 lines: username and password
    with open(sys.argv[1], "r") as tmpfile:
        username = tmpfile.readline().rstrip("\n")
        password = tmpfile.readline().rstrip("\n")

    user = get_user(username)
    # user: 0=username, 1=password_hash, 2=totp_secret, 3=totp_uri
    if not user:
        print(f">> No account for user: {username}")
        sys.exit(1)
    print(f">> Username: {username}")
    # print(f"Debug: User Db: {user}")
    session_state = os.environ.get("session_state")
    # print(f"Debug: session_state: {session_state}")
    if session_state is None or session_state == "Initial":
        # Initial connect or full re-connect phase.
        # print(f"Debug: Encoded: full password string: {password}")
        password_data = password.split(":")
        if password.startswith("SCRV1:") and len(password_data) == 3:
            # print(f"Debug: Encoded: password: {password_data[1]}, otp: {password_data[2]}")
            try:
                entered_pass = base64.b64decode(password_data[1]).decode()
            except (base64.binascii.Error, UnicodeDecodeError) as e:
                print(f">> Invalid password for user: {username} [{e}]")
                sys.exit(1)
            # print(f"Debug: Decoded: password: {entered_pass}")

            # Verify password, raises exception if wrong.
            try:
                ph.verify(user[1], entered_pass)
            except (
                argon2.exceptions.VerifyMismatchError,
                argon2.exceptions.VerificationError,
                argon2.exceptions.InvalidHash,
            ) as e:
                entered_legacy_pass_hash = legacy_pass_hash(entered_pass)
                # print(f"Debug: entered_legacy_pass_hash: {entered_legacy_pass_hash}")
                if entered_legacy_pass_hash != user[1]:
                    print(f">> Wrong password for user: {username}. Error: {e}")
                    sys.exit(1)
                else:
                    # Move from legacy sha256 to argon2 hash
                    update_hash_for_user(username, ph.hash(entered_pass))
            else:
                # print("Debug: Password Correct")
                # Now that we have the cleartext password,
                # check the hash's parameters and if outdated,
                # rehash the user's password in the database.
                if ph.check_needs_rehash(user[1]):
                    update_hash_for_user(username, ph.hash(entered_pass))

            try:
                entered_otp = base64.b64decode(password_data[2]).decode()
            except base64.binascii.Error as e:
                print(f">> Invalid TOTP for user: {username} [{e}]")
                sys.exit(1)
            except UnicodeDecodeError as e:
                print(f">> Invalid TOTP for user: {username} [{e}]")
                sys.exit(1)
            # print(f"Debug: Decoded: otp: {entered_otp}")

            if not verify_totp(user[2], entered_otp):
                print(f">> Wrong TOTP for user: {username}")
                sys.exit(1)

            print(f">> Login valid for user: {username}")

            create_session(username)
            sys.exit(0)

        else:
            print(f">> Invalid password for user: {username}")
            sys.exit(1)

    elif session_state == "Authenticated":
        # external-auth is enabled and auth-token is Authenticated
        # Verify OTP user session previously saved into sqlite.
        validate_session(username)
    else:
        print(
            f">> Invalid auth-token for user: {username}. session_state: {session_state}"
        )
        sys.exit(1)


def legacy_pass_hash(password):
    return hashlib.sha256(f"{password}.{ISSUER}".encode("utf-8")).hexdigest()


def update_hash_for_user(username, new_hash):
    # print(f"Debug: New Password Hash: {new_hash}")
    print(f">> Rehashing password for user: {username}")
    userdb, usercursor = get_userdb_cursor()
    usercursor.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (new_hash, username),
    )
    userdb.commit()


def verify_totp(secret, otp):
    """Verify TOTP."""
    totp = pyotp.TOTP(secret)
    return totp.verify(otp, valid_window=1)


def create_session(username):
    """Create/update user OTP session."""
    vpn_client = os.environ["IV_GUI_VER"]
    current_ip = os.environ["untrusted_ip"]
    created = datetime.datetime.now()
    store_session(username, vpn_client, current_ip, created)
    print(
        f">> New OTP session for user {username} from {current_ip} using {vpn_client}."
    )


def validate_session(username):
    """Validate user OTP session."""
    vpn_client = os.environ.get("IV_GUI_VER")
    current_ip = os.environ.get("untrusted_ip")
    now = datetime.datetime.now()
    session = get_session(username)
    # session: 0=vpn_client, 1=ip_address, 2=verified_on
    # print(f"Debug: session: {session}")
    # print(f"Debug: vpn_client: {vpn_client}")
    # print(f"Debug: session vpn_client: {session[0]}")
    # print(f"Debug: current_ip: {current_ip}")
    # print(f"Debug: session ip_address: {session[1]}")
    # print(f"Debug: expiration before: {(now - datetime.timedelta(hours=SESSION_DURATION))}")
    # print(f"Debug: session verified_on: {session[2]}")

    if not session:
        print(
            f">> Renegotiation forbidden. No record of TOTP session for user: {username}"
        )
        sys.exit(1)

    if session[0] != vpn_client:
        print(
            f">> Renegotiation forbidden. User {username} is using a different VPN client: old {session[0]}, new {vpn_client}."
        )
        sys.exit(1)

    if session[2] < (now - datetime.timedelta(hours=SESSION_DURATION)):
        print(
            f'>> Renegotiation forbidden. TOTP session for user {username} expired on {session[2].strftime("%Y-%m-%dT%H:%M:%SZ")}.'
        )
        sys.exit(1)

    if session[1] != current_ip:
        print(
            f">> Renegotiation forbidden. User {username} is coming from different IP: {current_ip}, previous: {session[1]}"
        )
        sys.exit(1)

    # All good.
    print(
        f">> Validated TOTP session for user {username} from {current_ip} using {vpn_client}."
    )
    sys.exit(0)


def get_sessiondb_cursor():
    """Connect to sqlite db file."""
    if not os.path.exists(SESSION_DB_FILE):
        sessiondb = sqlite3.connect(SESSION_DB_FILE)
        sessioncursor = sessiondb.cursor()
        sessioncursor.execute(SESSION_DB_SCHEMA)
        sessiondb.commit()
    else:
        sessiondb = sqlite3.connect(
            SESSION_DB_FILE,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        sessioncursor = sessiondb.cursor()

    return sessiondb, sessioncursor


def store_session(username, vpn_client, current_ip, created):
    """Store session record into sqlite."""
    sessiondb, sessioncursor = get_sessiondb_cursor()
    sessioncursor.execute(
        "REPLACE INTO sessions (username, vpn_client, ip_address, verified_on) VALUES (?,?,?,?)",
        (username, vpn_client, current_ip, created),
    )
    sessiondb.commit()


def get_session(username):
    """Get session record from sqlite."""
    _, sessioncursor = get_sessiondb_cursor()
    sessioncursor.execute(
        "SELECT vpn_client, ip_address, verified_on FROM sessions WHERE username=?",
        (username,),
    )
    session = sessioncursor.fetchone()
    return session


def get_user(username):
    """Get user record from sqlite."""
    _, usercursor = get_userdb_cursor()
    usercursor.execute(
        "SELECT username, password_hash, totp_secret, totp_uri FROM users WHERE username=?",
        (username,),
    )
    user = usercursor.fetchone()
    return user


def check_user(username):
    """Get user record from sqlite."""
    _, usercursor = get_userdb_cursor()
    usercursor.execute(
        "SELECT username FROM users WHERE username=?",
        (username,),
    )
    chuser = usercursor.fetchall()
    return bool(len(chuser))


def get_userdb_cursor():
    """Connect to sqlite user db file."""
    if not os.path.exists(USER_DB_FILE):
        userdb = sqlite3.connect(USER_DB_FILE)
        usercursor = userdb.cursor()
        usercursor.execute(USER_DB_SCHEMA)
        userdb.commit()
    else:
        userdb = sqlite3.connect(
            USER_DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        usercursor = userdb.cursor()

    return userdb, usercursor


def adduser():
    new_user = args.adduser[0]
    if check_user(new_user):
        print(f"User Already Exists: {new_user}")
        sys.exit(99)
    new_pass = getpass_asterisk("Enter password: ")
    pass_conf = getpass_asterisk("Confirm password: ")
    if new_pass != pass_conf:
        print(f"Passwords don't match. Account not created for: {new_user}")
        sys.exit(99)
    # print(f"Debug: Username: {new_user} / Password: {new_pass}")
    totp_secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=new_user, issuer_name=ISSUER
    )
    userdb, usercursor = get_userdb_cursor()
    # print(f"Debug: Password Hash: {ph.hash(new_pass)}")
    usercursor.execute(
        "INSERT INTO users (username, password_hash, totp_secret, totp_uri) VALUES (?,?,?,?)",
        (new_user, ph.hash(new_pass), totp_secret, totp_uri),
    )
    userdb.commit()
    if check_user(new_user):
        print(f"User Added: {new_user}")
        subprocess.run(
            f"qrencode '{totp_uri}' -t UTF8 -o '{TOTP_OUT_PATH}/{new_user}.totp'",
            shell=True,
            check=True,
            text=True,
        )
        with open(f"{TOTP_OUT_PATH}/{new_user}.totp", "a") as f:
            f.write(f"{totp_uri}")
        with open(f"{TOTP_OUT_PATH}/{new_user}.totp", "r") as f:
            print(f.read())
    else:
        print(f"Add Failed: {new_user}")
    sys.exit(99)


def deluser():
    del_user = args.deluser[0]
    if not check_user(del_user):
        print(f"User Doesn't Exist: {del_user}")
        sys.exit(99)
    f = f"{TOTP_OUT_PATH}/{del_user}.totp"
    try:
        os.remove(f)
    except FileNotFoundError:
        pass
    userdb, usercursor = get_userdb_cursor()
    usercursor.execute(
        "DELETE FROM users WHERE username=?",
        (del_user,),
    )
    userdb.commit()
    if check_user(del_user):
        print(f"Delete Failed: {del_user}")
    else:
        print(f"User Deleted: {del_user}")
    sys.exit(99)


def changepass():
    user = args.changepass[0]
    if not check_user(user):
        print(f"User Doesn't Exist: {user}")
        sys.exit(99)
    new_pass = getpass_asterisk("Enter password: ")
    pass_conf = getpass_asterisk("Confirm password: ")
    if new_pass != pass_conf:
        print(f"Passwords don't match. Password not changed for: {user}")
        sys.exit(99)
    # print(f"Debug: Username: {user} / New Password: {new_pass}")
    # print(f"Debug: New Password Hash: {ph.hash(new_pass)}")
    userdb, usercursor = get_userdb_cursor()
    usercursor.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (ph.hash(new_pass), user),
    )
    userdb.commit()
    print(f"Password Updated: {user}")
    sys.exit(99)


def changetotp():
    user = args.changetotp[0]
    if not check_user(user):
        print(f"User Doesn't Exist: {user}")
        sys.exit(99)
    totp_secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
        name=user, issuer_name=ISSUER
    )
    userdb, usercursor = get_userdb_cursor()
    usercursor.execute(
        "UPDATE users SET totp_secret = ?, totp_uri = ? WHERE username = ?",
        (totp_secret, totp_uri, user),
    )
    userdb.commit()
    print(f"TOTP Updated: {user}")
    subprocess.run(
        f"qrencode '{totp_uri}' -t UTF8 -o '{TOTP_OUT_PATH}/{user}.totp'",
        shell=True,
        check=True,
        text=True,
    )
    with open(f"{TOTP_OUT_PATH}/{user}.totp", "a") as f:
        f.write(f"{totp_uri}")
    with open(f"{TOTP_OUT_PATH}/{user}.totp", "r") as f:
        print(f.read())
    sys.exit(99)


def showtotp():
    user = args.showtotp[0]
    if not check_user(user):
        print(f"User Doesn't Exist: {user}")
        sys.exit(99)
    with open(f"{TOTP_OUT_PATH}/{user}.totp", "r") as f:
        print(f.read())
    sys.exit(99)


def listusers():
    _, usercursor = get_userdb_cursor()
    usercursor.execute(
        "SELECT username FROM users ORDER BY username ASC",
    )
    users = usercursor.fetchall()
    print(f"Users: {len(users)}\n_______________________")
    for user in users:
        print(f"{user[0]}")
    sys.exit(99)


def load_config():
    global ISSUER
    global TOTP_OUT_PATH
    global SESSION_DURATION
    global USER_DB_FILE
    global SESSION_DB_FILE
    file_path = f"{os.path.realpath(__file__).split('.')[0]}.conf"
    config = configparser.ConfigParser()
    config.read(file_path)
    try:
        ovpnauth_conf = config["OpenVPN Auth"]
    except KeyError:
        print(
            f">> Config file not found. You must run 'python {os.path.basename(__file__)} --install' before running the script."
        )
        sys.exit(1)
    else:
        ISSUER = ovpnauth_conf.get("ISSUER", "OVPNAuth Issuer").strip('"').strip("'")
        TOTP_OUT_PATH = (
            ovpnauth_conf.get(
                "TOTP_OUT_PATH", f"{os.path.dirname(os.path.abspath(__file__))}"
            )
            .strip('"')
            .strip("'")
        )
        SESSION_DURATION = ovpnauth_conf.getint(
            "SESSION_DURATION", 164
        )  # hours (1 week)
        USER_DB_FILE = (
            ovpnauth_conf.get(
                "USER_DB_FILE", f"{os.path.dirname(os.path.abspath(__file__))}/users.db"
            )
            .strip('"')
            .strip("'")
        )
        SESSION_DB_FILE = (
            ovpnauth_conf.get(
                "SESSION_DB_FILE",
                f"{os.path.dirname(os.path.abspath(__file__))}/sessions.db",
            )
            .strip('"')
            .strip("'")
        )


def install():
    file_path = f"{os.path.realpath(__file__).split('.')[0]}.conf"
    if os.path.isfile(file_path):
        print(f"Config file aready exists: {file_path}")
    else:
        ISSUER = "OVPNAuth Issuer"
        # RUNAS_USERID = os.geteuid()
        TOTP_OUT_PATH = f"{os.path.dirname(os.path.abspath(__file__))}"
        SESSION_DURATION = 164
        USER_DB_FILE = f"{os.path.dirname(os.path.abspath(__file__))}/users.db"
        SESSION_DB_FILE = f"{os.path.dirname(os.path.abspath(__file__))}/sessions.db"
        config = configparser.ConfigParser(allow_no_value=True)
        config["OpenVPN Auth"] = {
            "; Set to your business name or name of your VPN": None,
            "ISSUER": f"{ISSUER}",
            "; Where the TOTP QR Code files are saved to": None,
            "TOTP_OUT_PATH": f"{TOTP_OUT_PATH}",
            "; Number of hours before requiring new TOTP if nothing else changes": None,
            "SESSION_DURATION": SESSION_DURATION,
            "USER_DB_FILE": f"{USER_DB_FILE}",
            "SESSION_DB_FILE": f"{SESSION_DB_FILE}",
        }
        with open(f"{file_path}", "w") as configfile:
            config.write(configfile)
        print(f"Config file created: {file_path}")
    sys.exit(99)


if __name__ == "__main__":
    if args.install:
        install()
    load_config()
    if args.filename:
        main()
    elif args.adduser:
        adduser()
    elif args.deluser:
        deluser()
    elif args.changepass:
        changepass()
    elif args.changetotp:
        changetotp()
    elif args.showtotp:
        showtotp()
    elif args.listusers:
        listusers()
    sys.exit(99)
