"""
Network-level security policy enforcement for the VPN server.

Maintains two independent block lists:

* **Permanent blocklist** (``ip_blocklist``) — IPs added via ``block_ip`` with
  ``duration_seconds=0``.  Persists for the life of the process.  Intended for
  known-hostile addresses that an operator wants to ban indefinitely.
* **Temporal blocklist** (``_temporal_blocks``) — IPs added with a positive
  ``duration_seconds``.  A background daemon thread (``_scheduled_unblock_loop``)
  sweeps expired entries every 10 seconds.

``SecurityPolicy.is_blocked`` is called in the ``VPNServer._accept_loop`` for
every incoming connection *before* TLS wrapping, so hostile traffic is dropped
at the TCP level without incurring any cryptographic cost.
"""

import time
import threading
from typing import Set, Dict

from custom_ssl_vpn.server.logger import get_logger

__all__ = [
    "SecurityPolicy"
]


class SecurityPolicy:
    """Enforces IP-level access control for all inbound connections.

    Operates at the lowest possible level: ``VPNServer._accept_loop`` calls
    ``is_blocked`` immediately after ``accept()``, before any TLS work is
    done, so blocked peers waste zero server CPU on cryptographic operations.

    Attributes:
        ip_blocklist: The public set of permanently blocked IPs.  Can be
            read directly for diagnostic purposes but should only be mutated
            via ``block_ip`` and ``unblock_ip`` to keep logging consistent.
    """

    def __init__(self) -> None:
        """
        Initializes the synchronized ban structures and background unblock daemon.
        """
        self._logger = get_logger("SecurityPolicy")
        self._lock = threading.Lock()
        
        # Manually blocked IPs (persistent across runtime unless manually lifted)
        self.ip_blocklist: Set[str] = set()
        
        # Temporarily blocked IPs mapped to their unblock epoch timestamp
        self._temporal_blocks: Dict[str, float] = {}
        
        # Starts the background sweep thread to lift temporary bans when their duration clears
        self._running = True
        self._unblock_thread = threading.Thread(
            target=self._scheduled_unblock_loop,
            daemon=True,
            name="UnblockScheduler"
        )
        self._unblock_thread.start()

    def block_ip(self, ip: str, reason: str, duration_seconds: int = 0) -> None:
        """Add *ip* to the block list and log the enforcement action.

        Two blocking modes are available:

        * **Temporary** (``duration_seconds > 0``) — the IP is stored in
          ``_temporal_blocks`` with an expiry timestamp and automatically
          removed by the background thread.
        * **Permanent** (``duration_seconds == 0``) — the IP is added to
          ``ip_blocklist`` and any existing temporal block for it is cleared
          so the permanent ban takes precedence.

        Args:
            ip: Dotted-decimal IPv4 or IPv6 address string to block.
            reason: Free-text justification logged with the ban event.
            duration_seconds: How long to enforce the block.  Use ``0``
                for an indefinite / permanent ban.  Defaults to ``0``.

        Security note:
            Permanent bans survive until ``unblock_ip`` is called or the server
            process restarts.  They are stored in-memory only — add IP firewall
            rules for persistence across restarts.
        """
        with self._lock:
            if duration_seconds > 0:
                unblock_time = time.time() + duration_seconds
                self._temporal_blocks[ip] = unblock_time
                event_type = "TEMPORAL_IP_BLOCK"
            else:
                self.ip_blocklist.add(ip)
                # Ensure it's not in the temporary list so the permanent ban takes precedence
                self._temporal_blocks.pop(ip, None)
                event_type = "PERMANENT_IP_BLOCK"
                
        self._logger.log_security_event(event_type, {
            "ip": ip,
            "reason": reason,
            "duration_seconds": duration_seconds if duration_seconds > 0 else "indefinite"
        })

    def is_blocked(self, ip: str) -> bool:
        """Return ``True`` if *ip* is currently restricted from connecting.

        Checks the permanent blocklist first, then evaluates the temporal
        blocklist.  If a temporal entry has expired but the background thread
        hasn't swept it yet, this method cleans it up defensively.

        Args:
            ip: The source IP of the connection attempt.

        Returns:
            ``True`` if the connection should be immediately dropped,
            ``False`` if it should be allowed through to TLS wrapping.

        Example:
            >>> policy = SecurityPolicy()
            >>> policy.block_ip("1.2.3.4", reason="test", duration_seconds=60)
            >>> policy.is_blocked("1.2.3.4")
            True
            >>> policy.is_blocked("9.9.9.9")
            False
        """
        with self._lock:
            # Check permanent manual blocklist first
            if ip in self.ip_blocklist:
                return True
                
            # Check active temporal blocks
            if ip in self._temporal_blocks:
                # If the current time hasn't passed the unblock threshold, it's still blocked
                if time.time() < self._temporal_blocks[ip]:
                    return True
                # Clean up expired entry defensively if the background thread hasn't hit it yet
                del self._temporal_blocks[ip]
                
            return False

    def unblock_ip(self, ip: str) -> None:
        """Lift all active restrictions (permanent and temporary) from *ip*.

        Removes *ip* from both ``ip_blocklist`` and ``_temporal_blocks``,
        logging an ``IP_UNBLOCKED`` event only if at least one restriction
        was active.

        Args:
            ip: The IP address to pardon.
        """
        cleared = False
        with self._lock:
            if ip in self.ip_blocklist:
                self.ip_blocklist.remove(ip)
                cleared = True
            if ip in self._temporal_blocks:
                del self._temporal_blocks[ip]
                cleared = True
                
        if cleared:
            self._logger.log_security_event("IP_UNBLOCKED", {"ip": ip})

    def _scheduled_unblock_loop(self) -> None:
        """Background thread that lifts expired temporal bans every 10 seconds.

        Iterates over ``_temporal_blocks`` inside the lock, collects expired
        entries, then logs outside the lock to avoid I/O under the mutex.
        Runs until ``self._running`` is set to ``False`` by ``shutdown()``.
        """
        while self._running:
            time.sleep(10)
            now = time.time()
            expired_ips = []
            
            with self._lock:
                for ip, unblock_time in list(self._temporal_blocks.items()):
                    if now >= unblock_time:
                        expired_ips.append(ip)
                        del self._temporal_blocks[ip]
                        
            # Log outside the lock to avoid risking IO blocking the mutex
            for ip in expired_ips:
                self._logger.log_security_event("TEMPORAL_BLOCK_EXPIRED", {"ip": ip})

    def shutdown(self) -> None:
        """Signal the background unblock thread to exit on its next sleep cycle.

        Sets ``_running = False``.  The daemon thread is non-joinable from
        here because it may be sleeping for up to 10 seconds; since it is a
        daemon thread, it will be killed automatically when the main thread
        exits.
        """
        self._running = False
