"""Device classification and port scanning utilities."""

import re
import socket
import subprocess
import threading

from .device import Device
from .device_types import OUI_HINTS, PORT_SIGS, SCAN_PORTS, TYPE_LABELS


class Analyzer:
    """Scores and classifies a device based on multiple heuristics."""

    @staticmethod
    def get_default_gateway() -> str:
        try:
            out = subprocess.check_output(
                "ipconfig", stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in out.split('\n'):
                if "gateway" in line.lower():
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        return m.group(1)
        except Exception:
            pass
        return ""

    @staticmethod
    def classify(dev: Device) -> dict:
        """Return a dict with device_type, os_guess, confidence, details, badge."""
        scores: dict[str, int] = {}
        details: list[str] = []
        os_guess = ""

        # --- Vendor OUI matching ---
        vendor_l = (dev.vendor or "").lower()
        for key, dtype in OUI_HINTS.items():
            if key in vendor_l:
                scores[dtype] = scores.get(dtype, 0) + 30
                details.append(f"Vendor [{dev.vendor}] suggests {dtype}")
                break

        # --- Open ports ---
        open_set = set(dev.open_ports)
        for port in dev.open_ports:
            if port in PORT_SIGS:
                svc, hint = PORT_SIGS[port]
                dev.services.append(f"{port}/{svc}")
                scores[hint] = scores.get(hint, 0) + 15
                details.append(f"Port {port} ({svc}) indicates {hint}")

        if {9100, 515, 631} & open_set:
            scores["Printer"] = scores.get("Printer", 0) + 35
        if {554, 8000} & open_set:
            scores["Camera"] = scores.get("Camera", 0) + 30
        if {8008, 8009} & open_set:
            scores["Chromecast"] = scores.get("Chromecast", 0) + 40
        if 62078 in open_set:
            scores["iOS Device"] = scores.get("iOS Device", 0) + 40
        if 3389 in open_set:
            scores["Windows PC"] = scores.get("Windows PC", 0) + 30
        if 22 in open_set and 3389 not in open_set:
            scores["Linux PC"] = scores.get("Linux PC", 0) + 15
        if {5000, 548} & open_set:
            scores["NAS"] = scores.get("NAS", 0) + 25
        if 32400 in open_set:
            scores["Media Server"] = scores.get("Media Server", 0) + 40

        # --- TTL-based OS guess ---
        if dev.ttl:
            if dev.ttl <= 64:
                os_guess = "Linux / macOS"
                details.append(f"TTL {dev.ttl} indicates Unix family")
            elif dev.ttl <= 128:
                os_guess = "Windows"
                scores["Windows PC"] = scores.get("Windows PC", 0) + 10
                details.append(f"TTL {dev.ttl} indicates Windows")
            else:
                os_guess = "Network equipment"
                scores["Router"] = scores.get("Router", 0) + 15
                details.append(f"TTL {dev.ttl} indicates network device")

        # --- Hostname keywords ---
        hn = (dev.hostname or "").lower()
        hostname_map = {
            "iphone": ("iOS Device", 40), "ipad": ("iOS Device", 40),
            "macbook": ("Mac", 40), "imac": ("Mac", 40),
            "android": ("Mobile Device", 35), "galaxy": ("Samsung Device", 30),
            "pixel": ("Google Device", 35), "desktop": ("Windows PC", 25),
            "laptop": ("Computer", 25), "xbox": ("Game Console", 45),
            "playstation": ("Game Console", 45), "switch": ("Game Console", 30),
            "roku": ("Media Player", 40), "chromecast": ("Chromecast", 45),
            "printer": ("Printer", 45), "camera": ("Camera", 40),
            "nas": ("NAS", 40), "raspberrypi": ("Raspberry Pi", 45),
            "pi": ("Raspberry Pi", 20), "echo": ("Smart Home", 40),
            "alexa": ("Smart Home", 40), "sonos": ("Speaker", 40),
            "tv": ("Smart TV", 20), "server": ("Server", 25),
            "router": ("Router", 35), "gateway": ("Gateway", 35),
        }
        for kw, (dtype, sc) in hostname_map.items():
            if kw in hn:
                scores[dtype] = scores.get(dtype, 0) + sc
                details.append(f"Hostname contains '{kw}' -> {dtype}")
                break

        # --- Default gateway check ---
        try:
            gw = Analyzer.get_default_gateway()
            if dev.ip == gw:
                scores["Router"] = scores.get("Router", 0) + 50
                details.append("This is the default gateway")
        except Exception:
            pass

        # --- NetBIOS name ---
        if dev.netbios_name:
            scores["Windows PC"] = scores.get("Windows PC", 0) + 15
            details.append(f"NetBIOS name: {dev.netbios_name}")

        # --- HTTP banner ---
        if dev.http_banner:
            bl = dev.http_banner.lower()
            for kw, (dt, sc) in {
                "synology": ("NAS", 35), "qnap": ("NAS", 35),
                "hikvision": ("Camera", 35), "printer": ("Printer", 30),
                "plex": ("Media Server", 35), "nginx": ("Server", 15),
                "apache": ("Server", 15),
            }.items():
                if kw in bl:
                    scores[dt] = scores.get(dt, 0) + sc
                    details.append(f"HTTP banner indicates {dt}")
                    break

        # --- Pick the best match ---
        if scores:
            best = max(scores, key=scores.get)
            conf = min(100, int(scores[best]))
        else:
            best = "Unknown"
            conf = 0

        badge = TYPE_LABELS.get(best, "---")

        return {
            "device_type": best,
            "os_guess": os_guess,
            "confidence": conf,
            "details": details,
            "badge": badge,
        }


class PortScanner:
    """TCP port scanning and network probing helpers."""

    @staticmethod
    def scan(ip: str, ports: list[int],
             timeout: float = 0.7, workers: int = 25) -> list[int]:
        found: list[int] = []
        lock = threading.Lock()
        sem = threading.Semaphore(workers)

        def _check(port):
            with sem:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        with lock:
                            found.append(port)
                    s.close()
                except Exception:
                    pass

        threads = [threading.Thread(target=_check, args=(p,), daemon=True)
                   for p in ports]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout + 1)
        return sorted(found)

    @staticmethod
    def get_ttl(ip: str, timeout: float = 1.0) -> int:
        try:
            out = subprocess.check_output(
                ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip],
                stderr=subprocess.DEVNULL,
            ).decode(errors="ignore")
            m = re.search(r"TTL[=:](\d+)", out, re.IGNORECASE)
            return int(m.group(1)) if m else 0
        except Exception:
            return 0

    @staticmethod
    def http_banner(ip: str, port: int = 80, timeout: float = 1.5) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(
                b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = s.recv(1024).decode(errors="ignore")
            s.close()
            for line in data.split('\r\n'):
                if line.lower().startswith('server:'):
                    return line.split(':', 1)[1].strip()
            return data[:120]
        except Exception:
            return ""

    @staticmethod
    def netbios(ip: str, timeout: float = 1.0) -> str:
        try:
            payload = (
                b'\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                b'\x20\x43\x4b' + b'\x41' * 30 +
                b'\x00\x00\x21\x00\x01')
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(payload, (ip, 137))
            data, _ = s.recvfrom(1024)
            s.close()
            if len(data) > 57:
                return data[57:57 + 15].decode(errors="ignore").strip()
        except Exception:
            pass
        return ""
