"""Tailscale integration: node discovery via 'tailscale status --json'."""

import json
import subprocess
from typing import Dict, List, Optional


class TailscaleDiscovery:
    """Discovers Tailscale peers using the local CLI."""

    @staticmethod
    def is_available() -> bool:
        """Check if the tailscale CLI is installed and reachable."""
        try:
            subprocess.check_output(
                ["tailscale", "version"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    @staticmethod
    def get_status() -> Optional[dict]:
        """Run 'tailscale status --json' and return parsed JSON."""
        try:
            raw = subprocess.check_output(
                ["tailscale", "status", "--json"],
                stderr=subprocess.DEVNULL,
                timeout=10,
            ).decode(errors="ignore")
            return json.loads(raw)
        except (FileNotFoundError, subprocess.SubprocessError, json.JSONDecodeError):
            return None

    @staticmethod
    def get_peers() -> List[dict]:
        """Return a list of peer dicts with normalized fields.

        Each dict contains:
            ip        - first Tailscale IPv4 address
            hostname  - machine hostname
            dns_name  - full FQDN in the tailnet (e.g. 'mypc.tail1234.ts.net.')
            os        - operating system reported by the node
            online    - whether the peer is currently connected
            last_seen - ISO timestamp of last connection (or empty)
            is_self   - True for the local machine
            exit_node - True if this peer is the active exit node
        """
        data = TailscaleDiscovery.get_status()
        if data is None:
            return []

        peers = []  # type: List[dict]

        # --- Self node ---
        self_info = data.get("Self")
        if self_info:
            ip = TailscaleDiscovery._first_ipv4(self_info.get("TailscaleIPs", []))
            if ip:
                peers.append({
                    "ip": ip,
                    "hostname": self_info.get("HostName", ""),
                    "dns_name": self_info.get("DNSName", ""),
                    "os": self_info.get("OS", ""),
                    "online": True,
                    "last_seen": "",
                    "is_self": True,
                    "exit_node": False,
                })

        # --- Remote peers ---
        peer_map = data.get("Peer") or {}
        for _key, p in peer_map.items():
            ip = TailscaleDiscovery._first_ipv4(p.get("TailscaleIPs", []))
            if not ip:
                continue

            last_seen_raw = p.get("LastSeen", "")
            last_seen = ""
            if last_seen_raw:
                try:
                    last_seen = last_seen_raw.replace("Z", "+00:00")
                except Exception:
                    last_seen = last_seen_raw

            peers.append({
                "ip": ip,
                "hostname": p.get("HostName", ""),
                "dns_name": p.get("DNSName", ""),
                "os": p.get("OS", ""),
                "online": bool(p.get("Online", False)),
                "last_seen": last_seen,
                "is_self": False,
                "exit_node": bool(p.get("ExitNode", False)),
            })

        return peers

    @staticmethod
    def _first_ipv4(addrs) -> str:
        """Extract the first IPv4 address from a list of IPs."""
        for addr in addrs:
            a = str(addr).split("/")[0]
            if "." in a and ":" not in a:
                return a
        return ""

    @staticmethod
    def os_to_guess(os_str: str) -> str:
        """Map Tailscale OS strings to the format used by Analyzer."""
        os_lower = os_str.lower()
        if os_lower in ("windows",):
            return "Windows"
        if os_lower in ("linux",):
            return "Linux / macOS"
        if os_lower in ("macos", "darwin"):
            return "Linux / macOS"
        if os_lower in ("android",):
            return "Android"
        if os_lower in ("ios",):
            return "iOS"
        return os_str

    @staticmethod
    def os_to_device_type(os_str: str) -> str:
        """Guess a device type from the Tailscale OS field."""
        os_lower = os_str.lower()
        mapping = {
            "windows": "Windows PC",
            "linux": "Linux PC",
            "macos": "Mac",
            "darwin": "Mac",
            "android": "Mobile Device",
            "ios": "iOS Device",
            "freebsd": "Server",
            "openbsd": "Server",
        }
        return mapping.get(os_lower, "Unknown")
