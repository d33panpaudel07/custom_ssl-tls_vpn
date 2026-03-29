"""
Client configuration constants and validation.

Mirrors the server-side ``ServerConfig`` pattern for the VPN client side.
All connection parameters, certificate paths, and local-proxy settings are
centralised here so no magic strings appear in ``VPNClient`` or
``LocalForwarder``.

Load config from JSON via ``load_config``; override specific fields at CLI
parse time using ``dataclasses.replace`` or ``ClientConfig(**{**cfg.__dict__, ...})``.
"""

import json
import os
from dataclasses import dataclass
from typing import Dict, Any

__all__ = [
    "ClientConfig",
    "load_config",
]


@dataclass(frozen=True)
class ClientConfig:
    """Immutable, validated configuration for the VPN client application.

    ``SERVER_HOST`` is the only field without a default because a VPN client
    must always know which server to connect to.  All other fields default to
    reasonable values that can be overridden in a JSON config file or via CLI
    arguments.

    Attributes:
        SERVER_HOST: Hostname or IP address of the VPN server.  Required; no
            default is provided.  Must be a non-empty string.
        SERVER_PORT: TCP port on the VPN server accepting TLS connections.
            Must be 1–65535.  Defaults to ``8443``.
        CA_CERT_PATH: Path to the PEM-encoded Certificate Authority certificate
            used to verify the server's TLS certificate.  Must match the CA
            that signed the server cert.  Defaults to ``"client/certs/ca.crt"``.
        LOCAL_LISTEN_HOST: Loopback address the ``LocalForwarder`` binds to.
            Applications proxy through this address.  Defaults to ``"127.0.0.1"``.
        LOCAL_LISTEN_PORT: Port on ``LOCAL_LISTEN_HOST`` that local applications
            connect to.  Must be 1–65535.  Defaults to ``9000``.
        CONNECT_TIMEOUT_SECONDS: Timeout in seconds for the initial TCP and TLS
            handshake.  Must be > 0.  Defaults to ``10``.
        BUFFER_SIZE: Read/write buffer size in bytes for the relay loop.
            Must be > 0.  Defaults to ``4096``.

    Example:
        >>> cfg = ClientConfig(SERVER_HOST="vpn.example.com")
        >>> cfg.SERVER_PORT
        8443
        >>> cfg.LOCAL_LISTEN_PORT
        9000
    """

    SERVER_HOST: str
    SERVER_PORT: int = 8443
    CA_CERT_PATH: str = os.path.join(os.path.dirname(__file__), "certs", "ca.crt")
    LOCAL_LISTEN_HOST: str = "127.0.0.1"
    LOCAL_LISTEN_PORT: int = 9000
    CONNECT_TIMEOUT_SECONDS: int = 10
    BUFFER_SIZE: int = 4096

    def __post_init__(self) -> None:
        """Validates every field immediately after construction.

        Called automatically by the dataclass machinery after ``__init__``.
        Raises ``ValueError`` with a descriptive message for the first
        invalid field discovered.

        Raises:
            ValueError: If ``SERVER_HOST`` or ``LOCAL_LISTEN_HOST`` is empty,
                if any port is outside 1–65535, if ``CONNECT_TIMEOUT_SECONDS``
                is non-positive, or if ``BUFFER_SIZE`` is non-positive.

        Example:
            >>> ClientConfig(SERVER_HOST="")
            Traceback (most recent call last):
                ...
            ValueError: SERVER_HOST cannot be empty or null.
        """
        if not self.SERVER_HOST:
            raise ValueError("SERVER_HOST cannot be empty or null.")

        if not self.LOCAL_LISTEN_HOST:
            raise ValueError("LOCAL_LISTEN_HOST cannot be empty or null.")

        if not (1 <= self.SERVER_PORT <= 65535):
            raise ValueError(
                f"SERVER_PORT must be between 1 and 65535, got {self.SERVER_PORT}"
            )

        if not (1 <= self.LOCAL_LISTEN_PORT <= 65535):
            raise ValueError(
                f"LOCAL_LISTEN_PORT must be between 1 and 65535, got {self.LOCAL_LISTEN_PORT}"
            )

        if self.CONNECT_TIMEOUT_SECONDS <= 0:
            raise ValueError(
                f"CONNECT_TIMEOUT_SECONDS must be strictly positive, got {self.CONNECT_TIMEOUT_SECONDS}"
            )

        if self.BUFFER_SIZE <= 0:
            raise ValueError(
                f"BUFFER_SIZE must be strictly positive, got {self.BUFFER_SIZE}"
            )


def load_config(path: str) -> ClientConfig:
    """Load and validate a ``ClientConfig`` from a JSON file.

    Reads the UTF-8 encoded JSON file at *path*, unpacks all keys as keyword
    arguments into ``ClientConfig``, and returns the validated instance.
    Unknown JSON keys cause a ``ValueError``; missing keys fall back to
    dataclass field defaults (except ``SERVER_HOST``, which is mandatory).

    Args:
        path: Absolute or relative path to a JSON configuration file.
            The JSON must contain at minimum ``{"SERVER_HOST": "<host>"}``.

    Returns:
        A validated ``ClientConfig`` ready for use by the ``VPNClient``.

    Raises:
        FileNotFoundError: If *path* does not point to an existing file.
        ValueError: If the JSON is malformed, contains unknown keys, or any
            field fails the ``__post_init__`` validation.

    Example:
        >>> import json, tempfile, os
        >>> with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        ...     json.dump({"SERVER_HOST": "vpn.example.com", "SERVER_PORT": 8443}, f)
        ...     path = f.name
        >>> cfg = load_config(path)
        >>> cfg.SERVER_HOST
        'vpn.example.com'
        >>> os.unlink(path)
    """
    if not os.path.isfile(path):
        return ClientConfig(SERVER_HOST="127.0.0.1")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse JSON configuration file: {e}")

    try:
        return ClientConfig(**data)
    except TypeError as e:
        raise ValueError(f"Invalid configuration fields encountered: {e}")
