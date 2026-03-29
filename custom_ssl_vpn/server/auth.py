"""
Credential validation for incoming VPN client connections.

Handles all authentication logic: PBKDF2-HMAC password hashing, per-IP
brute-force tracking with lockout windows, global rate-limit defence, and
input sanitisation.  The ``AuthManager`` class is the single source of truth
for who is allowed to tunnel through the server.

Design decisions:

* **PBKDF2 HMAC-SHA256** with 100 000 iterations and a 32-byte random salt
  is used instead of bcrypt to stay inside the standard library.
* **Timing-safe comparison** via ``hmac.compare_digest`` prevents an attacker
  from learning partial hash information through response-time differences.
* **Atomic write** (write to ``.tmp`` then ``os.replace``) of the JSON user
  store prevents credential file corruption on power failure.
* **Dummy hash** is computed even for unknown usernames to equalise timing
  between "user not found" and "wrong password" responses.
"""

import os
import json
import re
import hmac
import hashlib
import threading
import argparse
import getpass
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from custom_ssl_vpn.shared.exceptions import (
    AuthenticationError,
    InvalidCredentialsError,
    TooManyAttemptsError,
)

__all__ = ["AuthManager", "AuthAttemptRecord"]


@dataclass
class AuthAttemptRecord:
    """Per-IP authentication failure tracker for brute-force detection.

    Maintained in-memory only — resets on server restart.  Persistent
    IP banning at the network level should be handled by ``SecurityPolicy``.

    Attributes:
        failure_timestamps: List of ``time.time()`` values for recent failures.
            Entries older than ``AuthManager._window_seconds`` are pruned on
            each new failure, keeping this list bounded.
        locked_until: Unix epoch timestamp at which the lockout expires.
            ``0.0`` means the IP is not currently locked out.
    """

    failure_timestamps: List[float]
    locked_until: float = 0.0


class AuthManager:
    """
    Service responsible for validating client credentials securely.

    Provides thread-safe access to user datastores, implements PBKDF2 HMAC
    password validation, and tracks IP-based rate limiting to prevent
    brute-force attacks.
    """

    def __init__(
        self, db_path: str = "server_users.json", max_attempts: int = 3
    ) -> None:
        """
        Initializes the authenticator with user storage routing.

        Args:
            db_path (str): The persistent JSON file storing user credentials.
            max_attempts (int): Maximum allowed failures before locking an IP.
        """
        self._db_path = db_path
        self._max_attempts = max_attempts
        self._lock = threading.Lock()

        # State tracking for brute-force protection
        # Maps IP address -> AuthAttemptRecord
        self._attempts: Dict[str, AuthAttemptRecord] = {}

        # Security constants
        self._hash_algo = "sha256"
        self._iterations = 100000
        self._salt_bytes = 32
        self._window_seconds = 60
        self._lockout_seconds = 300  # 5 minutes

        # Ensure that the credential store file exists
        self._ensure_db()

    def _ensure_db(self) -> None:
        """Create the JSON credential store file if it does not exist.

        Creates any missing parent directories as well, so the server can be
        started from any working directory as long as the path is valid.
        """
        with self._lock:
            if not os.path.exists(self._db_path):
                # Ensure the subdirectory exists if one is specified
                dir_path = os.path.dirname(self._db_path)
                if dir_path:
                    os.makedirs(dir_path, exist_ok=True)
                with open(self._db_path, "w", encoding="utf-8") as f:
                    json.dump({}, f)

    def _load_users(self) -> Dict[str, Any]:
        """Load and return the parsed contents of the JSON user store.

        Returns an empty dict on ``JSONDecodeError`` or ``FileNotFoundError``
        (fail-closed) rather than crashing the server.

        Returns:
            A dict mapping usernames to ``{"hash": hex, "salt": hex}`` records.
        """
        try:
            with open(self._db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            # Fail closed on corrupt storage
            return {}

    def _save_users(self, data: Dict[str, Any]) -> None:
        """Atomically persist the updated user store to disk.

        Writes to a ``.tmp`` file then calls ``os.replace`` so the destination
        file is replaced in a single atomic filesystem operation, preventing
        corruption when the process is interrupted mid-write.

        Args:
            data: Complete user store dict (all usernames, not just the updated one).
        """
        # Using a temporary file ensures atomic writes to prevent corruption
        # inside docker/networking edge cases where power cuts matter.
        tmp_path = self._db_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, self._db_path)

    def is_locked_out(self, client_ip: str) -> bool:
        """
        Checks whether a given IP address is currently locked out from auth attempts.

        Args:
            client_ip (str): The connecting client's IP address.

        Returns:
            bool: True if the IP is currently locked, False otherwise.
        """
        with self._lock:
            record = self._attempts.get(client_ip)
            if not record:
                return False

            current_time = time.time()
            if current_time < record.locked_until:
                return True

            # Lock duration expired, clear strict lock
            return False

    def record_failure(self, client_ip: str, username: str) -> None:
        """
        Records an authentication failure for a specific IP and evaluates lockout.

        Args:
            client_ip (str): The connecting client's IP address.
            username (str): The attempted user. Included for potential logging extensions.
        """
        current_time = time.time()
        with self._lock:
            record = self._attempts.setdefault(client_ip, AuthAttemptRecord([]))

            # Prune failures older than the tracking window
            cutoff_time = current_time - self._window_seconds
            record.failure_timestamps = [
                t for t in record.failure_timestamps if t > cutoff_time
            ]

            # Record current failure
            record.failure_timestamps.append(current_time)

            # If we hit max attempts within the 60s window, apply the 5 min penalty
            if len(record.failure_timestamps) >= self._max_attempts:
                record.locked_until = current_time + self._lockout_seconds
                record.failure_timestamps.clear()  # Reset counter immediately on lock

    def _validate_input_formats(self, username: str, password: str) -> bool:
        """Check username and password against safe input constraints.

        Applied before any cryptographic operations to prevent CPU exhaustion
        from long payloads and injection of null bytes into C extensions.

        Args:
            username: Raw username string from the network.  Must be 3–32
                word characters (``[A-Za-z0-9_]``) with no null bytes.
            password: Raw password string from the network.  Must be 8–128
                characters with no null bytes.

        Returns:
            ``True`` if both fields pass all constraints, ``False`` otherwise.

        Security note:
            A length cap of 64 / 256 chars is enforced *before* the regex
            check to prevent ReDoS on pathological inputs.
        """
        # Limit inputs strictly before RegEx to prevent CPU exhaustion on long payloads
        if len(username) > 64 or len(password) > 256:
            return False

        if not (3 <= len(username) <= 32) or not re.match(r"^\w+$", username):
            return False

        if not (8 <= len(password) <= 128):
            return False

        # Refuse explicit null bytes which could truncate C-extensions underneath
        if "\x00" in password or "\x00" in username:
            return False

        return True

    def rate_limit_check(self, client_ip: str) -> None:
        """Assert that the IP is neither individually locked out nor globally throttled.

        Combines two checks:

        1. **Per-IP lockout** — if ``is_locked_out(client_ip)`` returns ``True``,
           raises immediately without acquiring the global lock.
        2. **Global rate limit** — counts *all* recent failures across every IP;
           if the total exceeds 100 within ``_window_seconds``, raises to
           protect the server under a distributed brute-force campaign.

        Args:
            client_ip: The IP address of the connecting client.

        Raises:
            TooManyAttemptsError: If this IP is individually locked out, or if
                the global failure rate threshold is exceeded.

        Security note:
            Always call this before ``authenticate`` and before any I/O that
            could reveal the existence or non-existence of a username.
        """
        if self.is_locked_out(client_ip):
            raise TooManyAttemptsError("Maximum login attempts exceeded for your IP.")

        # Implementation of global block metrics added here alongside IP specifics
        with self._lock:
            # Determine global failures in the last 60 seconds
            cutoff_time = time.time() - self._window_seconds
            total_active_failures = 0
            for record in self._attempts.values():
                total_active_failures += len(
                    [t for t in record.failure_timestamps if t > cutoff_time]
                )

            if total_active_failures > 100:
                raise TooManyAttemptsError(
                    "Server authentication is globally rate limited due to high volumes."
                )

    def clear_failures(self, client_ip: str) -> None:
        """
        Clears the tracking history on a successful authentication.

        Args:
            client_ip (str): The client IP to prune from tracking.
        """
        with self._lock:
            if client_ip in self._attempts:
                del self._attempts[client_ip]

    def authenticate(self, username: str, password: str, client_ip: str) -> bool:
        """
        Validates client credentials using secure timing-safe PBKDF2 hashing.

        Args:
            username (str): Target account.
            password (str): The raw plaintext password to verify.
            client_ip (str): Client origin used for brute-force accounting.

        Returns:
            bool: True if credentials are valid.

        Raises:
            TooManyAttemptsError: If the IP is currently locked out or server globally throttled.
            InvalidCredentialsError: If authentication fails for any reason.
        """
        self.rate_limit_check(client_ip)

        if not self._validate_input_formats(username, password):
            self.record_failure(client_ip, username)
            raise InvalidCredentialsError("Invalid username or password format.")

        with self._lock:
            users = self._load_users()

        user_record = users.get(username)
        if not user_record:
            # Mitigation: Emulate the processing cost even if user doesn't exist
            # to prevent simple username enumeration via timing attacks.
            dummy_salt = os.urandom(self._salt_bytes)
            hashlib.pbkdf2_hmac(
                self._hash_algo, password.encode("utf-8"), dummy_salt, self._iterations
            )
            self.record_failure(client_ip, username)
            raise InvalidCredentialsError("Authentication failed.")

        try:
            stored_salt = bytes.fromhex(user_record["salt"])
            stored_hash = bytes.fromhex(user_record["hash"])
        except (KeyError, ValueError):
            self.record_failure(client_ip, username)
            raise InvalidCredentialsError("System credential corruption detected.")

        # Compute hash
        derived_hash = hashlib.pbkdf2_hmac(
            self._hash_algo, password.encode("utf-8"), stored_salt, self._iterations
        )

        # Security Note: hmac.compare_digest executes in constant time to explicitly prevent
        # timing-based measurement attacks where partial strings failing faster can reveal data.
        if hmac.compare_digest(derived_hash, stored_hash):
            self.clear_failures(client_ip)
            return True

        # Failed password matching
        self.record_failure(client_ip, username)
        raise InvalidCredentialsError("Authentication failed.")

    def register_user(self, username: str, password: str) -> None:
        """Provision or overwrite a user entry in the persistent credential store.

        Generates a fresh 32-byte cryptographic random salt for every call, so
        re-registering the same password results in a different stored hash.
        The plaintext password is never written to disk.

        Args:
            username: Target username identifier.  Must be 3–32 word characters.
            password: Plaintext password to hash and store.  Must be 8–128
                characters with no null bytes.

        Raises:
            ValueError: If *username* or *password* fail the input-format
                constraints enforced by ``_validate_input_formats``.

        Security note:
            Only the PBKDF2-HMAC-SHA256 hash and its salt are persisted —
            the plaintext password is not accessible after this call returns.

        Example:
            >>> auth = AuthManager()
            >>> auth.register_user("alice", "SecurePass1!")
            >>> auth.authenticate("alice", "SecurePass1!", "127.0.0.1")
            True
        """
        if not self._validate_input_formats(username, password):
            raise ValueError(
                "Invalid format. Username must be 3-32 alphanumeric characters. "
                "Password must be 8-128 characters without null bytes."
            )

        salt = os.urandom(self._salt_bytes)
        derived_hash = hashlib.pbkdf2_hmac(
            self._hash_algo, password.encode("utf-8"), salt, self._iterations
        )

        with self._lock:
            users = self._load_users()
            users[username] = {"hash": derived_hash.hex(), "salt": salt.hex()}
            self._save_users(users)


def _cli_entry() -> None:
    """Provides an interactive terminal prompt for safe user provisioning."""
    parser = argparse.ArgumentParser(
        description="VPN Server Authentication Manager CLI"
    )
    parser.add_argument(
        "--add-user", dest="add_user", type=str, help="Add or update a user account"
    )
    parser.add_argument(
        "--db-path",
        dest="db_path",
        type=str,
        default="server_users.json",
        help="Path to credentials database",
    )

    args = parser.parse_args()

    if args.add_user:
        username = args.add_user
        try:
            password = getpass.getpass(f"Enter new secure password for '{username}': ")
            confirm = getpass.getpass("Confirm password: ")

            if password != confirm:
                print("Error: Passwords do not match.")
                return

            auth = AuthManager(db_path=args.db_path)
            auth.register_user(username, password)
            print(
                f"Success: User '{username}' provisioned securely in '{args.db_path}'."
            )

        except ValueError as e:
            print(f"Format Error: {e}")
        except Exception as e:
            print(f"System Error: {e}")
    else:
        parser.print_help()


if __name__ == "__main__":
    _cli_entry()
