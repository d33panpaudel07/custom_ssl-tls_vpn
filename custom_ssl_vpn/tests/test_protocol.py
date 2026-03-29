"""
Unit tests for shared/protocol.py.

Verifies encode/decode roundtrips, error cases for malformed messages,
session ID handling, large payloads, and every defined command type.
"""

import sys
import os
import unittest

# Ensure project root is on sys.path for both plain-python and module runs
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from custom_ssl_vpn.shared.protocol import Commands, VPNMessage, encode_message, decode_message
from custom_ssl_vpn.shared.exceptions import MalformedMessageError, UnknownCommandError


class TestProtocolRoundtrip(unittest.TestCase):

    def test_encode_decode_roundtrip(self):
        """Encoding then decoding a message yields an identical VPNMessage object."""
        original = VPNMessage(command=Commands.DATA.value, payload=b"hello world")
        wire = encode_message(original)
        recovered = decode_message(wire)

        self.assertEqual(recovered.command, original.command)
        self.assertEqual(recovered.payload, original.payload)
        self.assertIsNone(recovered.session_id)

    def test_session_id_roundtrip(self):
        """A 36-character session_id is preserved exactly after encode/decode."""
        session_id = "12345678-1234-1234-1234-1234567890ab"
        msg = VPNMessage(command=Commands.OK.value, payload=b"", session_id=session_id)
        recovered = decode_message(encode_message(msg))
        self.assertEqual(recovered.session_id, session_id)

    def test_large_payload(self):
        """Encode/decode handles a 64 KB payload without data loss."""
        large_payload = os.urandom(65536)
        msg = VPNMessage(command=Commands.DATA.value, payload=large_payload)
        recovered = decode_message(encode_message(msg))
        self.assertEqual(recovered.payload, large_payload)

    def test_each_command_type(self):
        """Every Commands enum value can be successfully encoded and decoded."""
        for cmd in Commands:
            with self.subTest(command=cmd.value):
                msg = VPNMessage(command=cmd.value, payload=b"test")
                recovered = decode_message(encode_message(msg))
                self.assertEqual(recovered.command, cmd.value)

    def test_empty_payload_roundtrip(self):
        """A message with zero-byte payload encodes and decodes cleanly."""
        msg = VPNMessage(command=Commands.DISCONNECT.value, payload=b"")
        recovered = decode_message(encode_message(msg))
        self.assertEqual(recovered.payload, b"")

    def test_malformed_bytes_raises_protocol_error(self):
        """Feeding truncated bytes to decode_message raises MalformedMessageError."""
        with self.assertRaises(MalformedMessageError):
            decode_message(b"\x00\x00\x00\x05")  # Only 4 bytes, needs at least 41

    def test_too_short_single_byte_raises(self):
        """A single byte raises MalformedMessageError, not any other exception."""
        with self.assertRaises(MalformedMessageError):
            decode_message(b"\xff")

    def test_length_mismatch_raises(self):
        """A message whose embedded length field disagrees with actual length raises."""
        msg = VPNMessage(command=Commands.AUTH.value, payload=b"payload")
        wire = encode_message(msg)
        # Truncate last byte to create a length mismatch
        with self.assertRaises(MalformedMessageError):
            decode_message(wire[:-1])

    def test_unknown_command_byte_raises(self):
        """An unrecognised command byte in a correctly sized frame raises UnknownCommandError."""
        # Build 41 bytes with command byte = 0xFF (undefined)
        import struct
        total_length = 41
        raw = struct.pack("!I B", total_length, 0xFF) + b"\x00" * 36
        with self.assertRaises(UnknownCommandError):
            decode_message(raw)

    def test_unknown_command_string_raises_on_encode(self):
        """Encoding a VPNMessage with an unknown command string raises UnknownCommandError."""
        msg = VPNMessage(command="INVALID_CMD", payload=b"x")
        with self.assertRaises(UnknownCommandError):
            encode_message(msg)

    def test_session_id_wrong_length_raises(self):
        """A session_id that is not exactly 36 characters raises MalformedMessageError."""
        msg = VPNMessage(command=Commands.AUTH.value, payload=b"", session_id="short")
        with self.assertRaises(MalformedMessageError):
            encode_message(msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
