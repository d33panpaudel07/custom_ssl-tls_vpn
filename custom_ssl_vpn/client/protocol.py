"""
Client-specific protocol handling and message formatting.

Provides the components necessary for the client to parse server
responses and structure outgoing VPN messages based on the shared protocol.
"""

import sys
import os

# Append parent directory to sys.path to allow importing from shared module
# without requiring the package to be explicitly installed.
sys.path.append(os.path.normpath(os.path.join(os.path.dirname(__file__), '..')))

from shared.protocol import VPNMessage

__all__ = [
    "ClientMessageHandler"
]


class ClientMessageHandler:
    """
    Parses server messages and formats client requests for transmission.
    """

    def __init__(self) -> None:
        """
        Initializes the client message handler instance.
        """
        pass

    def format_request(self, payload: bytes) -> VPNMessage:
        """
        Packages application payload into a standard VPN message.
        
        Args:
            payload (bytes): The raw data to be sent across the tunnel.
            
        Returns:
            VPNMessage: Application payload wrapped in protocol structure.
        """
        pass
