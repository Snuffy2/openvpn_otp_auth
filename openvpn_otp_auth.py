#!/usr/bin/env python3
"""OpenVPN OTP auth script.

Version: v1.2.1

Author: @Snuffy2
Initial Author: @roman-vynar
Expanded from: https://github.com/roman-vynar/random-scripts

https://github.com/Snuffy2/openvpn_otp_auth
"""

import argparse
import base64
from binascii import Error as binascii_Error
import configparser
import contextlib
import datetime
import logging
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import sys

import argon2
from getpass_asterisk.getpass_asterisk import getpass_asterisk  # type: ignore[import-untyped]
import pyotp

VERSION = "v1.2.1"

# Main logger setup (stdout + file)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# stdout_formatter = logging.Formatter(">> %(message)s")
stdout_formatter = logging.Formatter(
    "%(asctime)s openvpn_otp_auth %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.INFO)
stdout_handler.setFormatter(stdout_formatter)
logger.addHandler(stdout_handler)

file_formatter = logging.Formatter(
    "%(asctime)s %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
log_file_path = Path(__file__).resolve().parent / "openvpn_otp_auth.log"
try:
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
except PermissionError as e:
    logger.warning("Could not write to logfile: %s", e)

logger.propagate = False

# Separate setup_logger (stdout only, different formatter)
setup_logger = logging.getLogger("setup_logger")  # <-- unique name!
setup_logger.setLevel(logging.INFO)
setup_stdout_handler = logging.StreamHandler(sys.stdout)
setup_stdout_handler.setLevel(logging.INFO)
setup_stdout_handler.setFormatter(logging.Formatter("%(message)s"))
setup_logger.handlers = []  # Remove any inherited handlers
setup_logger.addHandler(setup_stdout_handler)
setup_logger.propagate = False

parser = argparse.ArgumentParser(
    description=f"""OpenVPN python authentication script with password and multi-factor authentication (MFA) [TOTP] for use with auth-user-pass-verify via-file option.\n
Current path: {Path(__file__).resolve().parent}
Installation:
1. Place the {Path(__file__).name} script in a location that ideally wont be removed by system updates (ex. /etc/config/openvpn_otp_auth).
2. Run: 'python {Path(__file__).name} --install' to build the config file {Path(__file__).stem}.conf in the same folder as the python script.
3. Review the Config file and make any neccesary changes making sure the locations are correct and the issuer name is set.\n
Example server.ovpn lines:\n\tauth-user-pass-verify /etc/config/openvpn_otp_auth/{Path(__file__).name} via-file\n\tauth-gen-token 0 external-auth\n\n""",
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
parser.add_argument(
    "--debug",
    help="Enable debug logging",
    action="store_true",
)

args = parser.parse_args()

# Set log level to DEBUG if --debug is passed
if args.debug:
    logger.setLevel(logging.DEBUG)
    stdout_handler.setLevel(logging.DEBUG)
    file_handler.setLevel(logging.DEBUG)
    setup_logger.setLevel(logging.DEBUG)
    setup_stdout_handler.setLevel(logging.DEBUG)

# print(f"Debug: args: {args}")

SESSION_DB_SCHEMA = "CREATE TABLE sessions (username VARCHAR PRIMARY KEY, vpn_client VARCHAR, ip_address VARCHAR, verified_on TIMESTAMP)"
USER_DB_SCHEMA = "CREATE TABLE users (username VARCHAR PRIMARY KEY, password_hash VARCHAR, totp_secret VARCHAR, totp_uri VARCHAR)"


class OpenVPNOTPAuth:
    """Handles OpenVPN authentication with password and TOTP multi-factor authentication.

    This class manages user and session databases, provides methods for user management,
    authentication, session validation, and configuration handling for OpenVPN OTP authentication.
    """

    def __init__(self, args: argparse.Namespace, install: bool = False) -> None:
        """Initialize OpenVPNOTPAuth with command-line arguments and load configuration."""
        self.args = args
        self.ph = argon2.PasswordHasher()
        if not install:
            self.load_config()

    def _strip_quotes(self, value: str) -> str:
        """Remove surrounding quotes from config values."""
        return value.strip('"').strip("'")

    def load_config(self) -> None:
        """Load configuration settings from the config file.

        Reads the configuration file and sets instance variables for issuer, TOTP output path,
        session duration, user database file, and session database file. Exits if the config file is missing.

        Raises
        ------
        SystemExit
            If the configuration file is not found.

        """
        file_path = f"{Path(__file__).resolve().with_suffix('.conf')}"
        config = configparser.ConfigParser()
        config.read(file_path)
        try:
            ovpnauth_conf = config["OpenVPN OTP Auth"]
        except KeyError:
            logger.error(
                "Config file not found. You must run 'python %s --install' before running the script.",
                Path(__file__).name,
            )
            sys.exit(1)
        else:
            self.issuer = self._strip_quotes(ovpnauth_conf.get("ISSUER", "OpenVPN OTP Auth Issuer"))
            self.totp_out_path = self._strip_quotes(
                ovpnauth_conf.get("TOTP_OUT_PATH", f"{Path(__file__).resolve().parent}")
            )
            self.session_duration = ovpnauth_conf.getint("SESSION_DURATION", 164)
            self.user_db_file = self._strip_quotes(
                ovpnauth_conf.get("USER_DB_FILE", f"{Path(__file__).resolve().parent}/users.db")
            )
            self.session_db_file = self._strip_quotes(
                ovpnauth_conf.get(
                    "SESSION_DB_FILE", f"{Path(__file__).resolve().parent}/sessions.db"
                )
            )

    def _get_db_cursor(
        self, db_file: str, schema: str
    ) -> tuple[sqlite3.Connection, sqlite3.Cursor]:
        """Get a database connection and cursor, creating the database with the given schema if it does not exist.

        Parameters
        ----------
        db_file : str
            Path to the database file.
        schema : str
            SQL schema to create the database if it does not exist.

        Returns
        -------
        tuple
            A tuple containing the sqlite3.Connection and sqlite3.Cursor objects.

        Raises
        ------
        ValueError
            If the database file path is not set in configuration.

        """

        if not db_file:
            raise ValueError("Database file path is not set in configuration.")

        try:
            db_path = Path(db_file)
            if not db_path.exists():
                db = sqlite3.connect(db_file)
                cursor = db.cursor()
                cursor.execute(schema)
                db.commit()
            else:
                db = sqlite3.connect(
                    db_file,
                    detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
                )
                cursor = db.cursor()
        except sqlite3.Error as e:
            logger.error("Database error for %s. %s: %s", db_file, type(e).__name__, e)
            raise
        else:
            return db, cursor

    def get_sessiondb_cursor(self) -> tuple[sqlite3.Connection, sqlite3.Cursor]:
        """Get a cursor and connection to the session database, creating it if necessary.

        Returns
        -------
        tuple
            A tuple containing the sqlite3.Connection and sqlite3.Cursor objects for the session database.

        """
        return self._get_db_cursor(self.session_db_file, SESSION_DB_SCHEMA)

    def get_userdb_cursor(self) -> tuple[sqlite3.Connection, sqlite3.Cursor]:
        """Get a cursor and connection to the user database, creating it if necessary.

        Returns
        -------
        tuple
            A tuple containing the sqlite3.Connection and sqlite3.Cursor objects for the user database.

        """
        return self._get_db_cursor(self.user_db_file, USER_DB_SCHEMA)

    def get_user(self, username: str) -> tuple | None:
        """Retrieve user information from the database.

        Parameters
        ----------
        username : str
            The username to look up.

        Returns
        -------
        tuple or None
            Returns a tuple (username, password_hash, totp_secret, totp_uri) if the user exists, otherwise None.

        """
        _, usercursor = self.get_userdb_cursor()
        usercursor.execute(
            "SELECT username, password_hash, totp_secret, totp_uri FROM users WHERE username=?",
            (username,),
        )
        return usercursor.fetchone()

    def check_user(self, username: str) -> bool:
        """Check if a user exists in the database.

        Parameters
        ----------
        username : str
            The username to check.

        Returns
        -------
        bool
            True if the user exists, False otherwise.

        """
        _, usercursor = self.get_userdb_cursor()
        usercursor.execute(
            "SELECT username FROM users WHERE username=?",
            (username,),
        )
        return usercursor.fetchone() is not None

    def update_hash_for_user(self, username: str, new_hash: str) -> None:
        """Update the password hash for a user in the database.

        Parameters
        ----------
        username : str
            The username whose password hash will be updated.
        new_hash : str
            The new password hash to store for the user.

        """
        logger.info("Rehashing password for user: %s", username)
        userdb, usercursor = self.get_userdb_cursor()
        usercursor.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (new_hash, username),
        )
        userdb.commit()

    def verify_totp(self, secret: str, otp: str) -> bool:
        """Verify a TOTP code against the user's secret.

        valid_window=1 → current and previous code accepted
        valid_window=2 → current, previous, and next code accepted
        valid_window=0 → only current code accepted

        Parameters
        ----------
        secret : str
            The TOTP secret for the user.
        otp : str
            The one-time password to verify.

        Returns
        -------
        bool
            True if the OTP is valid, False otherwise.

        """
        totp = pyotp.TOTP(secret)
        return totp.verify(otp, valid_window=1)

    def store_session(
        self, username: str, vpn_client: str, current_ip: str, created: datetime.datetime
    ) -> None:
        """Store or update a session record in the session database.

        Parameters
        ----------
        username : str
            The username for the session.
        vpn_client : str
            The VPN client version or identifier.
        current_ip : str
            The IP address of the user.
        created : datetime.datetime
            The timestamp when the session was created or verified.

        Returns
        -------
        None

        """
        sessiondb, sessioncursor = self.get_sessiondb_cursor()
        sessioncursor.execute(
            "REPLACE INTO sessions (username, vpn_client, ip_address, verified_on) VALUES (?,?,?,?)",
            (username, vpn_client, current_ip, created),
        )
        sessiondb.commit()

    def get_session(self, username: str) -> tuple | None:
        """Retrieve session information for a given username from the session database.

        Parameters
        ----------
        username : str
            The username to look up.

        Returns
        -------
        tuple or None
            Returns a tuple (vpn_client, ip_address, verified_on) if the session exists, otherwise None.

        """
        _, sessioncursor = self.get_sessiondb_cursor()
        sessioncursor.execute(
            "SELECT vpn_client, ip_address, verified_on FROM sessions WHERE username=?",
            (username,),
        )
        return sessioncursor.fetchone()

    def main(self) -> None:
        """Execute main authentication logic for OpenVPN OTP Auth.

        Reads username and password from the provided file, verifies credentials and TOTP,
        manages session creation and validation, and handles authentication states.

        Raises
        ------
        SystemExit
            Exits with code 0 for successful authentication, 1 for authentication errors,
            or 99 for configuration/user management actions.

        """
        logger.info(
            "Running %s %s as User: %s [%s]",
            Path(__file__).name,
            VERSION,
            pwd.getpwuid(os.geteuid()).pw_name,
            os.geteuid(),
        )
        with Path(sys.argv[1]).open() as tmpfile:
            username = tmpfile.readline().rstrip("\n")
            password = tmpfile.readline().rstrip("\n")

        user = self.get_user(username)
        if not user:
            logger.error("No account for user: %s", username)
            sys.exit(1)
        logger.info("Username: %s", username)
        session_state = os.environ.get("session_state")
        if session_state is None or session_state == "Initial":
            password_data = password.split(":")
            if password.startswith("SCRV1:") and len(password_data) == 3:
                try:
                    entered_pass = base64.b64decode(password_data[1]).decode()
                except (binascii_Error, UnicodeDecodeError) as e:
                    logger.error("Invalid password for user: %s [%s]", username, e)
                    sys.exit(1)
                try:
                    self.ph.verify(user[1], entered_pass)
                except (
                    argon2.exceptions.VerifyMismatchError,
                    argon2.exceptions.VerificationError,
                    argon2.exceptions.InvalidHash,
                ) as e:
                    logger.error("Wrong password for user: %s. Error: %s", username, e)
                    sys.exit(1)
                else:
                    if self.ph.check_needs_rehash(user[1]):
                        self.update_hash_for_user(username, self.ph.hash(entered_pass))
                try:
                    entered_otp = base64.b64decode(password_data[2]).decode()
                except (binascii_Error, UnicodeDecodeError) as e:
                    logger.error("Invalid TOTP for user: %s [%s]", username, e)
                    sys.exit(1)
                if not self.verify_totp(user[2], entered_otp):
                    logger.error("Wrong TOTP for user: %s", username)
                    sys.exit(1)
                logger.info("Login valid for user: %s", username)
                self.create_session(username)
                sys.exit(0)
            else:
                logger.error("Invalid password for user: %s", username)
                sys.exit(1)
        elif session_state == "Authenticated":
            self.validate_session(username)
        else:
            logger.error(
                "Invalid auth-token for user: %s. session_state: %s", username, session_state
            )
            sys.exit(1)

    def create_session(self, username: str) -> None:
        """Create a new OTP session for the specified user.

        Parameters
        ----------
        username : str
            The username for whom to create the session.

        Returns
        -------
        None

        """
        vpn_client = os.environ.get("IV_GUI_VER")
        current_ip = os.environ.get("untrusted_ip")
        created = datetime.datetime.now()
        if vpn_client is None or current_ip is None:
            logger.error(
                "VPN client or IP address not found in environment variables. Cannot create session for user: %s",
                username,
            )
            sys.exit(1)
        self.store_session(username, vpn_client, current_ip, created)
        logger.info(
            "New OTP session for user %s from %s using %s.", username, current_ip, vpn_client
        )

    def validate_session(self, username: str) -> None:
        """Validate an existing OTP session for the specified user.

        Parameters
        ----------
        username : str
            The username whose session is to be validated.

        Raises
        ------
        SystemExit
            Exits with code 0 for successful validation, or 1 for validation errors.

        """
        vpn_client = os.environ.get("IV_GUI_VER")
        current_ip = os.environ.get("untrusted_ip")
        now = datetime.datetime.now()
        session = self.get_session(username)
        if not session:
            logger.error(
                "Renegotiation forbidden. No record of TOTP session for user: %s", username
            )
            sys.exit(1)
        if session[0] != vpn_client:
            logger.error(
                "Renegotiation forbidden. User %s is using a different VPN client: old %s, new %s.",
                username,
                session[0],
                vpn_client,
            )
            sys.exit(1)
        if session[2] < (now - datetime.timedelta(hours=self.session_duration)):
            logger.error(
                "Renegotiation forbidden. TOTP session for user %s expired on %s.",
                username,
                session[2].strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            sys.exit(1)
        if session[1] != current_ip:
            logger.error(
                "Renegotiation forbidden. User %s is coming from different IP: %s, previous: %s",
                username,
                current_ip,
                session[1],
            )
            sys.exit(1)
        logger.info(
            "Validated TOTP session for user %s from %s using %s.",
            username,
            current_ip,
            vpn_client,
        )
        sys.exit(0)

    def install(self) -> None:
        """Create a default configuration file for OpenVPN OTP Auth if it does not exist.

        Raises
        ------
        SystemExit
            Exits with code 99 after creating or detecting the config file.

        """
        file_path = f"{Path(__file__).resolve().with_suffix('.conf')}"
        if Path(file_path).is_file():
            setup_logger.info("Config file already exists: %s", file_path)
        else:
            ISSUER = "OpenVPN OTP Auth Issuer"
            TOTP_OUT_PATH = f"{Path(__file__).resolve().parent}"
            SESSION_DURATION = "164"
            USER_DB_FILE = f"{Path(__file__).resolve().parent}/users.db"
            SESSION_DB_FILE = f"{Path(__file__).resolve().parent}/sessions.db"
            config = configparser.ConfigParser(allow_no_value=True)
            config["OpenVPN OTP Auth"] = {
                "; Set to your business name or name of your VPN": "",
                "ISSUER": f"{ISSUER}",
                "; Where the TOTP QR Code files are saved to": "",
                "TOTP_OUT_PATH": f"{TOTP_OUT_PATH}",
                "; Number of hours before requiring new TOTP if nothing else changes": "",
                "SESSION_DURATION": SESSION_DURATION,
                "USER_DB_FILE": f"{USER_DB_FILE}",
                "SESSION_DB_FILE": f"{SESSION_DB_FILE}",
            }
            with Path(f"{file_path}").open("w") as configfile:
                config.write(configfile)
            setup_logger.info("Config file created: %s", file_path)
        sys.exit(99)

    def adduser(self) -> None:
        """Add a new user to the authentication system.

        Prompts for password, generates TOTP secret and URI, saves user to database,
        creates QR code for TOTP, and logs the result.

        Raises
        ------
        SystemExit
            Exits with code 99 after user creation or error.

        """
        new_user = self.args.adduser[0]
        if self.check_user(new_user):
            setup_logger.error("User Already Exists: %s", new_user)
            sys.exit(99)
        new_pass = getpass_asterisk("Enter password: ")
        pass_conf = getpass_asterisk("Confirm password: ")
        if new_pass != pass_conf:
            setup_logger.error("Passwords don't match. Account not created for: %s", new_user)
            sys.exit(99)
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=new_user, issuer_name=self.issuer
        )
        userdb, usercursor = self.get_userdb_cursor()
        usercursor.execute(
            "INSERT INTO users (username, password_hash, totp_secret, totp_uri) VALUES (?,?,?,?)",
            (new_user, self.ph.hash(new_pass), totp_secret, totp_uri),
        )
        userdb.commit()
        if self.check_user(new_user):
            setup_logger.info("User Added: %s", new_user)
            try:
                subprocess.run(
                    [
                        "qrencode",
                        totp_uri,
                        "-t",
                        "UTF8",
                        "-o",
                        f"{self.totp_out_path}/{new_user}.totp",
                    ],
                    check=True,
                    text=True,
                    capture_output=True,
                )
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                setup_logger.warning(
                    "Failed to generate QR code: %s. Make sure qrencode is installed.", e
                )
                # Continue without QR code generation
            with Path(f"{self.totp_out_path}/{new_user}.totp").open("a") as f:
                f.write(f"{totp_uri}")
            with Path(f"{self.totp_out_path}/{new_user}.totp").open() as f:
                setup_logger.info(f.read())
        else:
            setup_logger.error("Add Failed: %s", new_user)
        sys.exit(99)

    def deluser(self) -> None:
        """Delete an existing user from the authentication system.

        Removes the user from the database and deletes their TOTP file.
        Logs the result and exits with code 99.

        Raises
        ------
        SystemExit
            Exits with code 99 after user deletion or error.

        """
        del_user = self.args.deluser[0]
        if not self.check_user(del_user):
            setup_logger.error("User Doesn't Exist: %s", del_user)
            sys.exit(99)
        f = Path(f"{self.totp_out_path}/{del_user}.totp")
        with contextlib.suppress(FileNotFoundError):
            f.unlink()
        userdb, usercursor = self.get_userdb_cursor()
        usercursor.execute(
            "DELETE FROM users WHERE username=?",
            (del_user,),
        )
        userdb.commit()
        if self.check_user(del_user):
            setup_logger.error("Delete Failed: %s", del_user)
        else:
            setup_logger.info("User Deleted: %s", del_user)
        sys.exit(99)

    def changepass(self) -> None:
        """Change the password for an existing user.

        Prompts for a new password and confirmation, updates the password hash in the database,
        logs the result, and exits with code 99.

        Raises
        ------
        SystemExit
            Exits with code 99 after password change or error.

        """
        user = self.args.changepass[0]
        if not self.check_user(user):
            setup_logger.error("User Doesn't Exist: %s", user)
            sys.exit(99)
        new_pass = getpass_asterisk("Enter password: ")
        pass_conf = getpass_asterisk("Confirm password: ")
        if new_pass != pass_conf:
            setup_logger.error("Passwords don't match. Password not changed for: %s", user)
            sys.exit(99)
        userdb, usercursor = self.get_userdb_cursor()
        usercursor.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (self.ph.hash(new_pass), user),
        )
        userdb.commit()
        setup_logger.info("Password Updated: %s", user)
        sys.exit(99)

    def changetotp(self) -> None:
        """Change the TOTP secret for an existing user.

        Generates a new TOTP secret and URI, updates the user in the database,
        creates a new QR code for the TOTP, and logs the result.

        Raises
        ------
        SystemExit
            Exits with code 99 after TOTP change or error.

        """
        user = self.args.changetotp[0]
        if not self.check_user(user):
            setup_logger.error("User Doesn't Exist: %s", user)
            sys.exit(99)
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=user, issuer_name=self.issuer)
        userdb, usercursor = self.get_userdb_cursor()
        usercursor.execute(
            "UPDATE users SET totp_secret = ?, totp_uri = ? WHERE username = ?",
            (totp_secret, totp_uri, user),
        )
        userdb.commit()
        setup_logger.info("TOTP Updated: %s", user)
        try:
            subprocess.run(
                ["qrencode", totp_uri, "-t", "UTF8", "-o", f"{self.totp_out_path}/{user}.totp"],
                check=True,
                text=True,
                capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            setup_logger.warning(
                "Failed to generate QR code: %s. Make sure qrencode is installed.", e
            )
            # Continue without QR code generation
        with Path(f"{self.totp_out_path}/{user}.totp").open("a") as f:
            f.write(f"{totp_uri}")
        with Path(f"{self.totp_out_path}/{user}.totp").open() as f:
            setup_logger.info(f.read())
        sys.exit(99)

    def showtotp(self) -> None:
        """Show the TOTP QR code and URI for an existing user.

        Logs the contents of the user's TOTP file and exits with code 99.

        Raises
        ------
        SystemExit
            Exits with code 99 if the user does not exist or after displaying the TOTP.

        """
        user = self.args.showtotp[0]
        if not self.check_user(user):
            setup_logger.error("User Doesn't Exist: %s", user)
            sys.exit(99)
        try:
            with Path(f"{self.totp_out_path}/{user}.totp").open() as f:
                setup_logger.info(f.read())
        except FileNotFoundError:
            setup_logger.error("TOTP file not found for user: %s", user)
        sys.exit(99)

    def listusers(self) -> None:
        """List all users in the authentication system.

        Retrieves all usernames from the database, logs the count and each username, and exits with code 99.

        Returns
        -------
        None

        Raises
        ------
        SystemExit
            Exits with code 99 after listing users.

        """
        _, usercursor = self.get_userdb_cursor()
        usercursor.execute(
            "SELECT username FROM users ORDER BY username ASC",
        )
        users = usercursor.fetchall()
        setup_logger.info("Users: %d\n_______________________", len(users))
        for user in users:
            setup_logger.info("%s", user[0])
        sys.exit(99)


if __name__ == "__main__":
    if not args.filename:
        setup_logger.info("Running %s %s", Path(__file__).name, VERSION)
        setup_logger.debug("Arguments: %s", args)
    else:
        logger.debug("Arguments: %s", args)
    if args.install:
        OpenVPNOTPAuth(args=args, install=True).install()
    else:
        auth = OpenVPNOTPAuth(args)
        if args.filename:
            auth.main()
        elif args.adduser:
            auth.adduser()
        elif args.deluser:
            auth.deluser()
        elif args.changepass:
            auth.changepass()
        elif args.changetotp:
            auth.changetotp()
        elif args.showtotp:
            auth.showtotp()
        elif args.listusers:
            auth.listusers()
        sys.exit(99)
