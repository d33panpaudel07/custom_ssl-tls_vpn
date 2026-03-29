"""
Server-specific protocol message parsing and handling.

Extends the shared protocol components by providing integration specifically
tailored for server-side processing flow.
"""

import sys
import os

# Append parent directory to sys.path to allow importing from shared module
# without requiring the package to be explicitly installed.
sys.path.append(os.path.normpath(os.path.join(os.path.dirname(__file__), '..')))

from shared.protocol import VPNMessage

__all__ = [
    "ServerMessageHandler"
]


class ServerMessageHandler:
    """
    Parses and produces raw protocol messages for the server connections.
    """

    def __init__(self) -> None:
        """
        Initializes the server message handler instance.
        """
        pass

    def process_incoming(self, raw_data: bytes) -> VPNMessage:
        """
        Converts a raw byte stream from the client into a structured VPN message.
        
        Args:
            raw_data (bytes): The bytes received over the wire.
            
        Returns:
            VPNMessage: The structured representation.
        """
        pass
