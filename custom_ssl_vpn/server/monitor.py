"""
Real-time SOC-style monitoring dashboard for the running VPN server.

Exposes current server health via two mechanisms:

1. **``print_dashboard()``** — writes an ASCII table to ``stderr`` for
   quick operator inspection during development or manual triage.
2. **HTTP endpoint** — ``GET http://127.0.0.1:9999/stats`` returns the full
   ``get_snapshot()`` payload as a pretty-printed JSON document suitable for
   ingestion by Grafana, Datadog, or custom dashboards.

All data is pulled from the live ``SessionManager`` (under its own lock) and
from ``VPNLogger.get_stats()`` / ``VPNLogger.get_ip_auth_failures()``.  No
separate state is maintained here; the dashboard is read-only.

Anomaly detection thresholds (configurable in ``detect_anomalies``):

* ``>= 10`` auth failures from one IP in 5 min → brute-force warning.
* ``>= 80%`` of ``MAX_CLIENTS`` active → capacity warning.
* Any session active ``> 24 h`` → long-session warning.
"""

import json
import logging
import threading
import time
from datetime import datetime
from typing import Dict, Any, List
from http.server import HTTPServer, BaseHTTPRequestHandler

from custom_ssl_vpn.server.logger import get_logger
from custom_ssl_vpn.server.session import SessionManager

__all__ = [
    "MonitoringDashboard"
]


class MonitoringDashboard:
    """Aggregates VPN server telemetry and exposes it via print and HTTP.

    The dashboard is a lightweight read-only view over ``SessionManager``
    and ``VPNLogger``.  No state is mutated here; all counters live in
    those two objects.

    Attributes:
        session_manager: Reference to the live session pool.
        max_clients: Server capacity ceiling, used by ``detect_anomalies``
            to calculate the 80% capacity threshold.
        http_port: Port on ``127.0.0.1`` the HTTP feed listens on.
    """

    def __init__(self, session_manager: SessionManager, max_clients: int, http_port: int = 9999) -> None:
        """
        Initializes the monitors and binds the local HTTP port.
        
        Args:
            session_manager (SessionManager): Reference to the active VPN session pool.
            max_clients (int): Configured ceiling for capacity warnings.
            http_port (int): The local bind port for the HTTP JSON feed.
        """
        self.session_manager = session_manager
        self.max_clients = max_clients
        self.http_port = http_port
        self._logger = get_logger("MonitoringDashboard")
        self._running = False
        self._httpd = None
        self._server_thread = None

    def get_snapshot(self) -> Dict[str, Any]:
        """Return a complete, JSON-serialisable snapshot of current server health.

        Pulls data from three sources atomically:

        * ``VPNLogger.get_stats()`` — global byte and connection counters.
        * ``VPNLogger.get_ip_auth_failures(window_seconds=300)`` — per-IP
          failure rates within the last 5 minutes.
        * ``SessionManager.list_sessions()`` (inside ``session_manager.lock()``)
          — live session metadata.

        Returns:
            A dict with the following keys: ``uptime_seconds``,
            ``total_connections_handled``, ``total_bytes_forwarded_up``,
            ``total_bytes_forwarded_down``, ``auth_failures_last_5m_by_ip``,
            ``active_sessions_count``, ``max_capacity_allowed``,
            ``anomalies``, ``sessions``, ``snapshot_timestamp`` (ISO-8601).
        """
        # Pull global aggregated stats safely from the logger locking tier
        global_stats = get_logger().get_stats()
        
        # Pull sliding-window brute-force attempts map
        failure_rates = get_logger().get_ip_auth_failures(window_seconds=300)

        # Pull active session mappings safely from the session_manager lock
        sessions_data = []
        with self.session_manager.lock():
            active_sessions = self.session_manager.list_sessions()
            now = datetime.now()
            
            for s in active_sessions:
                duration = int((now - s.created_at).total_seconds())
                sessions_data.append({
                    "session_id": s.session_id,
                    "username": s.username or "[pending_auth]",
                    "client_ip": s.client_ip,
                    "duration_seconds": duration,
                    "bytes_up": s.bytes_up,
                    "bytes_down": s.bytes_down,
                    "is_authenticated": s.is_authenticated
                })

        return {
            "uptime_seconds": global_stats.get("uptime_seconds", 0),
            "total_connections_handled": global_stats.get("connection_count", 0),
            "total_bytes_forwarded_up": global_stats.get("total_bytes_up", 0),
            "total_bytes_forwarded_down": global_stats.get("total_bytes_down", 0),
            "auth_failures_last_5m_by_ip": failure_rates,
            "active_sessions_count": len(sessions_data),
            "max_capacity_allowed": self.max_clients,
            "anomalies": self.detect_anomalies(failure_rates, sessions_data),
            "sessions": sessions_data,
            "snapshot_timestamp": datetime.now().isoformat() + "Z"
        }

    def detect_anomalies(
        self, failure_rates: Dict[str, int], sessions_data: List[Dict[str, Any]]
    ) -> List[str]:
        """Evaluate raw metrics against predefined SOC security thresholds.

        Checks three anomaly categories in order:

        1. **Brute force** — ``>= 10`` failures from a single IP in 5 minutes.
        2. **Capacity warning** — ``>= 80%`` of ``max_clients`` are active.
        3. **Long session** — any session has been active ``> 86 400`` seconds.

        Args:
            failure_rates: Dict mapping IP string → recent failure count,
                as returned by ``VPNLogger.get_ip_auth_failures``.
            sessions_data: List of session summary dicts, as built inside
                ``get_snapshot``.

        Returns:
            A list of human-readable warning strings, one per triggered rule.
            Empty list when no anomalies are detected.

        Example:
            >>> dashboard.detect_anomalies({"1.2.3.4": 15}, [])
            ['Brute force suspected: 1.2.3.4 (15 failures recently)']
        """
        warnings = []
        
        # 1. High Velocity Brute Force Signatures (10 fails / 5 min from 1 IP)
        for ip, fails in failure_rates.items():
            if fails >= 10:
                warnings.append(f"Brute force suspected: {ip} ({fails} failures recently)")
                
        # 2. Denial of Service / Connection Exhaustion Capacity Checks
        active_count = len(sessions_data)
        if active_count > 0 and (active_count / self.max_clients) >= 0.8:
            warnings.append(f"Capacity warning: {active_count}/{self.max_clients} sessions active")
            
        # 3. Zombie or Exfiltrating Long-Lived Tunnel Checks (24 hours)
        for s in sessions_data:
            if s["duration_seconds"] > 86400:  # 60 * 60 * 24
                warnings.append(f"Long session detected: {s['session_id']} ({s['username']}) - active for >24h")
                
        return warnings

    def print_dashboard(self) -> None:
        """Write a formatted ASCII telemetry table to ``stderr``.

        Always writes to ``sys.stderr`` (never ``stdout``) so it does not
        interfere with piped output in scripts.  Calls ``get_snapshot()``
        internally, so it reflects the current live state.
        """
        import sys
        snap = self.get_snapshot()
        
        lines = [
            "\n" + "="*60,
            f"  VPN SOC DASHBOARD | Uptime: {snap['uptime_seconds']}s",
            "="*60,
            f" Total Connections : {snap['total_connections_handled']}",
            f" Active Sessions   : {snap['active_sessions_count']} / {snap['max_capacity_allowed']}",
            f" Global Traffic    : {snap['total_bytes_forwarded_up']} B (Up) | {snap['total_bytes_forwarded_down']} B (Down)",
            "-"*60
        ]
        
        if snap['anomalies']:
            lines.append(" [!] ANOMALIES DETECTED:")
            for w in snap['anomalies']:
                lines.append(f"     - {w}")
            lines.append("-" * 60)
            
        lines.append(" ACTIVE SESSIONS:")
        if not snap['sessions']:
            lines.append("    (None)")
        else:
            for s in snap['sessions']:
                auth_mark = "[✔]" if s['is_authenticated'] else "[?]"
                lines.append(f"    {auth_mark} {s['username']} ({s['client_ip']}) - {s['duration_seconds']}s - {s['bytes_up']}B/{s['bytes_down']}B")
                
        lines.append("="*60 + "\n")
        
        sys.stderr.write("\n".join(lines) + "\n")
        sys.stderr.flush()

    def start(self) -> None:
        """Bind and start the background HTTP telemetry server on ``127.0.0.1:<http_port>``.

        Spawns a daemon ``threading.Thread`` running
        ``HTTPServer.serve_forever``.  The server handles only ``GET /stats``;
        all other paths return 404.  HTTP access logging is suppressed so
        monitoring poll traffic does not pollute the VPN log file.

        This method is idempotent: calling it a second time while already
        running is a no-op.

        Raises:
            OSError: If the port is already in use (caught and logged; the
                dashboard degrades gracefully).
        """
        if self._running:
            return
            
        class StatsHandler(BaseHTTPRequestHandler):
            dashboard_ref = self  # Inject reference for the route handler
            
            def do_GET(self):
                if self.path == '/stats':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    data = self.dashboard_ref.get_snapshot()
                    self.wfile.write(json.dumps(data, indent=2).encode('utf-8'))
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                # Suppress standard logging to prevent log file pollution from internal SOC scraping
                pass

        try:
            self._httpd = HTTPServer(('127.0.0.1', self.http_port), StatsHandler)
            self._running = True
            
            self._server_thread = threading.Thread(
                target=self._httpd.serve_forever,
                daemon=True,
                name="MonitoringDashboardHTTP"
            )
            self._server_thread.start()
            self._logger._log(logging.INFO, "Monitor listening on http://127.0.0.1:9999/stats")
        except Exception as e:
            self._logger._log(logging.ERROR, f"Failed to bind monitor dashboard: {e}")

    def stop(self) -> None:
        """Shut down the HTTP telemetry server cleanly.

        Calls ``HTTPServer.shutdown()`` (which signals ``serve_forever`` to
        exit) and then ``server_close()`` to release the socket.  Safe to call
        even if ``start()`` was never successfully invoked.
        """
        self._running = False
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
