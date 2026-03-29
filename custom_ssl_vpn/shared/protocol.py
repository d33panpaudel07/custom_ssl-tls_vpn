"""
Canonical protocol definitions and message formats for the VPN tunnel.

Defines the binary wire format used between VPN client and server over the
TLS transport layer.  Both sides share this module through Python's standard
import mechanism; the server and client ``protocol.py`` shims simply re-export
from here.

Wire format (big-endian)::

    ┌─────────────────────────────────────────────────────────────────┐
    │  4 bytes  │  1 byte   │       36 bytes        │   N bytes       │
    │  length   │  command  │  session_id (or zeros) │  payload bytes  │
    └─────────────────────────────────────────────────────────────────┘

* **length** — total frame size in bytes (including the 4-byte length field itself).
* **command** — single unsigned byte mapped to a ``Commands`` enum member.
* **session_id** — ASCII UUID-4 string, or 36 null bytes when no session is open.
* **payload** — arbitrary bytes whose interpretation depends on the command.

All edge cases (unknown command, malformed length, non-ASCII session_id) raise
subclasses of ``ProtocolError`` so callers can handle them uniformly.
"""

import struct
from dataclasses import dataclass
from enum import Enum
from typing import Optional

try:
    from custom_ssl_vpn.shared.exceptions import MalformedMessageError, UnknownCommandError
except ImportError:
    from shared.exceptions import MalformedMessageError, UnknownCommandError  # type: ignore

__all__ = [
    "Commands",
    "VPNMessage",
    "encode_message",
    "decode_message",
]


class Commands(str, Enum):
    """Enumeration of all valid command tokens in the VPN application protocol.

    Inherits from ``str`` so a ``Commands`` member compares equal to its string
    value, which simplifies comparisons like ``msg.command == Commands.AUTH``.

    Members:
        AUTH: Client → Server.  Initiates credential verification.
        CONNECT: Client → Server.  Requests a tunnel to a target host:port.
        DATA: Bidirectional.  Raw tunnel payload (rarely used; relay is usually transparent).
        DISCONNECT: Either direction.  Signals graceful session teardown.
        OK: Server → Client.  Positive acknowledgement of AUTH or CONNECT.
        ERROR: Server → Client.  Negative acknowledgement with reason in payload.

    Example:
        >>> Commands.AUTH == "AUTH"
        True
        >>> Commands("OK")
        <Commands.OK: 'OK'>
    """

    AUTH = "AUTH"
    CONNECT = "CONNECT"
    DATA = "DATA"
    DISCONNECT = "DISCONNECT"
    OK = "OK"
    ERROR = "ERROR"


# Internal codec tables — kept module-private to prevent direct byte manipulation.
_CMD_TO_BYTE = {
    Commands.AUTH.value: 1,
    Commands.CONNECT.value: 2,
    Commands.DATA.value: 3,
    Commands.DISCONNECT.value: 4,
    Commands.OK.value: 5,
    Commands.ERROR.value: 6,
}

_BYTE_TO_CMD = {v: k for k, v in _CMD_TO_BYTE.items()}


@dataclass
class VPNMessage:
    """A fully structured VPN application-layer message.

    This dataclass is the lingua franca passed between all layers.  Raw bytes
    received from the network are immediately parsed into a ``VPNMessage``
    via ``decode_message``; application code builds ``VPNMessage`` objects and
    serialises them via ``encode_message`` before writing to a socket.

    Attributes:
        command: One of the ``Commands`` enum values (stored as its string value).
        payload: Arbitrary byte payload whose semantics depend on *command*.
            For AUTH, this is a JSON object ``{"username": ..., "password": ...}``.
            For CONNECT, this is ``{"host": ..., "port": ...}``.
            For OK/ERROR, this is a human-readable ASCII reason string.
        session_id: Optional 36-character UUID-4 string that ties the message to
            an authenticated session.  ``None`` when no session exists yet (e.g.
            during the AUTH handshake).

    Example:
        >>> msg = VPNMessage(command=Commands.OK.value, payload=b"Authenticated.", session_id="abc-...")
        >>> msg.command
        'OK'
    """

    command: str
    payload: bytes
    session_id: Optional[str] = None


def encode_message(msg: VPNMessage) -> bytes:
    """Serialise a ``VPNMessage`` into the binary wire format.

    The output is a contiguous byte sequence ready to be passed directly to
    ``socket.sendall()``.  No framing or length-prefix negotiation is required
    on the caller's side because the length is embedded in the frame itself.

    Args:
        msg: The structured message to encode.  ``msg.command`` must be a valid
            ``Commands`` enum value (or its string equivalent).  If
            ``msg.session_id`` is provided it must be exactly 36 ASCII characters
            (a standard UUID-4 string).

    Returns:
        A ``bytes`` object encoding the full frame:
        ``[4-byte length][1-byte cmd][36-byte session_id][payload]``.

    Raises:
        UnknownCommandError: If ``msg.command`` is not in the ``Commands`` enum.
        MalformedMessageError: If ``msg.session_id`` is not exactly 36 ASCII bytes.

    Security note:
        Never pass raw user-controlled data as ``msg.command``; always use the
        ``Commands`` enum to prevent injection of undefined opcodes.

    Example:
        >>> from custom_ssl_vpn.shared.protocol import VPNMessage, Commands, encode_message, decode_message
        >>> msg = VPNMessage(command=Commands.DATA.value, payload=b"hello")
        >>> wire = encode_message(msg)
        >>> decode_message(wire).payload
        b'hello'
    """
    try:
        cmd_byte = _CMD_TO_BYTE[msg.command]
    except KeyError:
        raise UnknownCommandError(
            f"Cannot encode unknown command: {msg.command}",
            context={"command": msg.command},
        )

    session_id_bytes = b"\x00" * 36
    if msg.session_id is not None:
        try:
            session_id_encoded = msg.session_id.encode("ascii")
        except UnicodeEncodeError:
            raise MalformedMessageError(
                "session_id must be valid ASCII.",
                context={"session_id": msg.session_id},
            )

        if len(session_id_encoded) != 36:
            raise MalformedMessageError(
                "session_id must be exactly 36 bytes long (e.g. a valid UUID string).",
                context={"session_id_length": len(session_id_encoded)},
            )
        session_id_bytes = session_id_encoded

    total_length = 4 + 1 + 36 + len(msg.payload)

    # Pack: !I = 4-byte big-endian unsigned int, B = 1-byte unsigned char.
    header = struct.pack("!I B", total_length, cmd_byte)

    return header + session_id_bytes + msg.payload


def decode_message(raw: bytes) -> VPNMessage:
    """Deserialise a raw byte frame received from the network into a ``VPNMessage``.

    Validates both structural constraints (minimum length, length consistency)
    and semantic constraints (known command byte, ASCII session_id).  Any
    violation raises a ``ProtocolError`` subclass.

    Args:
        raw: A complete binary frame as received from ``socket.recv()``.
            The frame must be self-contained; partial frames will raise
            ``MalformedMessageError``.

    Returns:
        A ``VPNMessage`` with ``command``, ``payload``, and ``session_id``
        populated from the frame.  ``session_id`` is ``None`` when the 36-byte
        field is all null bytes.

    Raises:
        MalformedMessageError: When *raw* has fewer than 41 bytes, when the
            embedded ``total_length`` field does not match ``len(raw)``, or
            when the session_id bytes cannot be decoded as ASCII.
        UnknownCommandError: When the 1-byte command field has no mapping in
            the ``_BYTE_TO_CMD`` table.

    Security note:
        Always call ``decode_message`` inside a ``try/except ProtocolError``
        block.  Do not trust any field of the returned ``VPNMessage`` before
        checking its ``command`` against the set of values expected at the
        current protocol state.

    Example:
        >>> wire = encode_message(VPNMessage(command=Commands.AUTH.value, payload=b'{}'))
        >>> msg = decode_message(wire)
        >>> msg.command
        'AUTH'
        >>> msg.payload
        b'{}'
    """
    min_length = 41  # 4 (length) + 1 (cmd) + 36 (session_id)
    if len(raw) < min_length:
        raise MalformedMessageError(
            f"Message too short: {len(raw)} bytes received, minimum 41 required.",
            context={"received_length": len(raw)},
        )

    total_length, cmd_byte = struct.unpack("!I B", raw[:5])

    if len(raw) != total_length:
        raise MalformedMessageError(
            f"Message length mismatch. Expected {total_length}, got {len(raw)}.",
            context={"expected_length": total_length, "actual_length": len(raw)},
        )

    try:
        command_str = _BYTE_TO_CMD[cmd_byte]
    except KeyError:
        raise UnknownCommandError(
            f"Received unknown command byte: {cmd_byte}",
            context={"cmd_byte": cmd_byte},
        )

    session_id_bytes = raw[5:41]
    if session_id_bytes == b"\x00" * 36:
        session_id = None
    else:
        try:
            session_id = session_id_bytes.decode("ascii")
        except UnicodeDecodeError:
            raise MalformedMessageError(
                "session_id could not be decoded as ASCII.",
                context={"session_id_hex": session_id_bytes.hex()},
            )

    payload = raw[41:]

    return VPNMessage(
        command=command_str,
        payload=payload,
        session_id=session_id,
    )
