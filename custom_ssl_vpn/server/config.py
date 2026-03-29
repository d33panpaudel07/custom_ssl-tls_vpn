"""
Server configuration constants and validation.

Centralises every tunable parameter behind the ``ServerConfig`` frozen
dataclass, preventing accidental mutation after start-up.  All magic strings
and numbers used by other server modules are sourced exclusively from this
module.

Loading configuration from a JSON file is handled by ``load_config``, which
validates every field via ``ServerConfig.__post_init__`` and raises descriptive
``ValueError`` instances instead of cryptic ``AttributeError`` or ``TypeError``
messages from deeper in the stack.
"""

import json
import os
from dataclasses import dataclass
from typing import Dict, Any

__all__ = [
    "ServerConfig",
    "load_config",
]


@dataclass(frozen=True)
class ServerConfig:
    """Immutable, validated configuration for the VPN server daemon.

    All fields have sensible production-like defaults except for certificate
    paths, which must match the actual file-system layout of the deployment.
    The ``frozen=True`` flag makes every attribute read-only after construction,
    preventing accidental runtime mutation.

    Attributes:
        HOST: IP address the server binds to.  ``"0.0.0.0"`` binds all
            available interfaces; use ``"127.0.0.1"`` to restrict to loopback.
        PORT: TCP port to listen on.  Must be 1–65535.  Ports below 1024
            require elevated privileges on Unix systems.
        CERT_PATH: File-system path to the PEM-encoded TLS server certificate.
        KEY_PATH: File-system path to the PEM-encoded TLS private key.
        MAX_CLIENTS: Maximum simultaneous TLS sessions.  The OS ``listen()``
            backlog is set to this value.  Must be ≥ 1.
        AUTH_TIMEOUT_SECONDS: Seconds a connected client has to send a valid
            AUTH message before the socket is closed.  Must be > 0.
        MAX_LOGIN_ATTEMPTS: Consecutive failures allowed per IP address within
            ``AuthManager._window_seconds`` before the IP is locked out.
        SESSION_TIMEOUT_SECONDS: Idle seconds after which the background reaper
            terminates a session.  Must be > 0.
        BUFFER_SIZE: Read/write buffer size in bytes used by ``TunnelRelay``
            and ``vpn_server.py`` when calling ``socket.recv()``.
        LOG_PATH: File path for the JSON-formatted log output.
        LOG_LEVEL: Minimum log level string.  Must be one of
            ``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``, ``CRITICAL``.
        TLS_VERSION: Minimum TLS version token recognised by
            ``ssl.TLSVersion``.  Defaults to ``"TLSv1_2"``.
        ALLOWED_CIPHERS: OpenSSL cipher list string passed to
            ``SSLContext.set_ciphers()``.  Defaults to a set that excludes
            anonymous, MD5, and RC4 cipher suites.

    Example:
        >>> cfg = ServerConfig(HOST="0.0.0.0", PORT=8443, SERVER_HOST="")
        >>> cfg.PORT
        8443
        >>> cfg.MAX_CLIENTS
        50
    """

    HOST: str = "0.0.0.0"
    PORT: int = 8443
    CERT_PATH: str = os.path.join(os.path.dirname(__file__), "certs", "server.crt")
    KEY_PATH: str = os.path.join(os.path.dirname(__file__), "certs", "server.key")
    MAX_CLIENTS: int = 50
    AUTH_TIMEOUT_SECONDS: int = 10
    MAX_LOGIN_ATTEMPTS: int = 3
    SESSION_TIMEOUT_SECONDS: int = 3600
    BUFFER_SIZE: int = 4096
    LOG_PATH: str = os.path.join(os.path.dirname(__file__), "logs", "vpn.log")
    LOG_LEVEL: str = "INFO"
    TLS_VERSION: str = "TLSv1_2"
    ALLOWED_CIPHERS: str = "HIGH:!aNULL:!MD5:!RC4"

    def __post_init__(self) -> None:
        """Validates every field immediately after construction.

        Called automatically by the dataclass machinery.  Raises ``ValueError``
        with a descriptive message for the first invalid field encountered.

        Raises:
            ValueError: If any field is outside its valid range or set.

        Example:
            >>> ServerConfig(PORT=0)
            Traceback (most recent call last):
                ...
            ValueError: PORT must be between 1 and 65535, got 0
        """
        if not (1 <= self.PORT <= 65535):
            raise ValueError(f"PORT must be between 1 and 65535, got {self.PORT}")

        if self.MAX_CLIENTS < 1:
            raise ValueError(f"MAX_CLIENTS must be at least 1, got {self.MAX_CLIENTS}")

        if self.AUTH_TIMEOUT_SECONDS <= 0:
            raise ValueError(
                f"AUTH_TIMEOUT_SECONDS must be positive, got {self.AUTH_TIMEOUT_SECONDS}"
            )

        if self.MAX_LOGIN_ATTEMPTS < 1:
            raise ValueError(
                f"MAX_LOGIN_ATTEMPTS must be at least 1, got {self.MAX_LOGIN_ATTEMPTS}"
            )

        if self.SESSION_TIMEOUT_SECONDS <= 0:
            raise ValueError(
                f"SESSION_TIMEOUT_SECONDS must be positive, got {self.SESSION_TIMEOUT_SECONDS}"
            )

        if self.BUFFER_SIZE <= 0:
            raise ValueError(
                f"BUFFER_SIZE must be strictly positive, got {self.BUFFER_SIZE}"
            )

        valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.LOG_LEVEL.upper() not in valid_log_levels:
            raise ValueError(
                f"LOG_LEVEL must be one of {valid_log_levels}, got {self.LOG_LEVEL}"
            )


def load_config(path: str) -> ServerConfig:
    """Load and validate a ``ServerConfig`` from a JSON file.

    Reads the JSON file at *path*, passes all key-value pairs as keyword
    arguments to ``ServerConfig``, and returns the validated instance.

    Any unknown JSON keys are silently forwarded to the dataclass constructor,
    which raises ``TypeError`` (re-raised as ``ValueError`` with a clear message).
    Missing JSON keys fall back to the dataclass field defaults.

    Args:
        path: Absolute or relative path to a JSON configuration file.
            The file must be UTF-8 encoded and contain a single top-level
            JSON object whose keys match ``ServerConfig`` field names.

    Returns:
        A validated ``ServerConfig`` instance ready for use.

    Raises:
        FileNotFoundError: If *path* does not point to an existing file.
        ValueError: If the file cannot be parsed as JSON, or if any field
            fails the ``ServerConfig.__post_init__`` validation.

    Example:
        >>> import json, tempfile, os
        >>> with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        ...     json.dump({"HOST": "0.0.0.0", "PORT": 8443}, f)
        ...     path = f.name
        >>> cfg = load_config(path)
        >>> cfg.PORT
        8443
        >>> os.unlink(path)
    """
    if not os.path.isfile(path):
        return ServerConfig()

    try:
        with open(path, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON configuration file: {e}")

    try:
        return ServerConfig(**data)
    except TypeError as e:
        raise ValueError(f"Invalid configuration fields encountered: {e}")
