"""Tailscale integration: node discovery via 'tailscale status --json'."""

import json, subprocess
from typing import Optional, List

_OS_GUESS = {"windows": "Windows", "linux": "Linux / macOS",
             "macos": "Linux / macOS", "darwin": "Linux / macOS",
             "android": "Android", "ios": "iOS"}

_OS_TYPE = {"windows": "Windows PC", "linux": "Linux PC",
            "macos": "Mac", "darwin": "Mac",
            "android": "Mobile Device", "ios": "iOS Device",
            "freebsd": "Server", "openbsd": "Server"}


class TailscaleDiscovery:

    @staticmethod
    def is_available() -> bool:
        try:
            subprocess.check_output(["tailscale", "version"],
                                    stderr=subprocess.DEVNULL, timeout=5)
            return True
        except (FileNotFoundError, subprocess.SubprocessError):
            return False

    @staticmethod
    def get_status() -> Optional[dict]:
        try:
            raw = subprocess.check_output(["tailscale", "status", "--json"],
                                          stderr=subprocess.DEVNULL, timeout=10)
            return json.loads(raw.decode(errors="ignore"))
        except (FileNotFoundError, subprocess.SubprocessError, json.JSONDecodeError):
            return None

    @staticmethod
    def get_peers() -> List[dict]:
        data = TailscaleDiscovery.get_status()
        if not data: return []

        def first_ipv4(addrs):
            for a in addrs:
                s = str(a).split("/")[0]
                if "." in s and ":" not in s: return s
            return ""

        def parse_node(info, is_self=False):
            ip = first_ipv4(info.get("TailscaleIPs", []))
            if not ip: return None
            return {
                "ip": ip,
                "hostname": info.get("HostName", ""),
                "dns_name": info.get("DNSName", ""),
                "os": info.get("OS", ""),
                "online": True if is_self else bool(info.get("Online", False)),
                "is_self": is_self,
                "exit_node": bool(info.get("ExitNode", False)),
            }

        peers = []
        self_info = data.get("Self")
        if self_info:
            p = parse_node(self_info, is_self=True)
            if p: peers.append(p)

        for _, p_info in (data.get("Peer") or {}).items():
            p = parse_node(p_info)
            if p: peers.append(p)

        return peers

    @staticmethod
    def os_to_guess(os_str):
        return _OS_GUESS.get(os_str.lower(), os_str)

    @staticmethod
    def os_to_device_type(os_str):
        return _OS_TYPE.get(os_str.lower(), "Unknown")
