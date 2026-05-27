"""Device classification and port scanning utilities."""

import re, socket, subprocess, threading
from .device import Device
from .device_types import OUI_HINTS, PORT_SIGS, TYPE_LABELS


class Analyzer:
    """Scores and classifies a device based on multiple heuristics."""

    @staticmethod
    def get_default_gateway():
        try:
            out = subprocess.check_output("ipconfig", stderr=subprocess.DEVNULL).decode(errors="ignore")
            for line in out.split('\n'):
                if "gateway" in line.lower():
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m: return m.group(1)
        except Exception:
            pass
        return ""

    @staticmethod
    def classify(dev: Device) -> dict:
        scores, details, os_guess = {}, [], ""

        def add(dtype, pts, reason):
            scores[dtype] = scores.get(dtype, 0) + pts
            details.append(reason)

        # Vendor OUI
        vl = (dev.vendor or "").lower()
        for key, dtype in OUI_HINTS.items():
            if key in vl:
                add(dtype, 30, f"Vendor [{dev.vendor}] suggests {dtype}")
                break

        # Open ports
        open_set = set(dev.open_ports)
        for port in dev.open_ports:
            if port in PORT_SIGS:
                svc, hint = PORT_SIGS[port]
                dev.services.append(f"{port}/{svc}")
                add(hint, 15, f"Port {port} ({svc}) indicates {hint}")

        port_combos = [
            ({9100, 515, 631}, "Printer", 35), ({554, 8000}, "Camera", 30),
            ({8008, 8009}, "Chromecast", 40), ({5000, 548}, "NAS", 25),
        ]
        for ports, dtype, pts in port_combos:
            if ports & open_set: add(dtype, pts, f"Port combo suggests {dtype}")

        singles = [(62078, "iOS Device", 40), (3389, "Windows PC", 30), (32400, "Media Server", 40)]
        for p, dtype, pts in singles:
            if p in open_set: add(dtype, pts, f"Port {p} indicates {dtype}")

        if 22 in open_set and 3389 not in open_set:
            add("Linux PC", 15, "SSH without RDP suggests Linux")

        # TTL
        if dev.ttl:
            if dev.ttl <= 64:
                os_guess = "Linux / macOS"
                details.append(f"TTL {dev.ttl} indicates Unix family")
            elif dev.ttl <= 128:
                os_guess = "Windows"
                add("Windows PC", 10, f"TTL {dev.ttl} indicates Windows")
            else:
                os_guess = "Network equipment"
                add("Router", 15, f"TTL {dev.ttl} indicates network device")

        # Hostname keywords
        hn = (dev.hostname or "").lower()
        hostname_map = {
            "iphone": ("iOS Device", 40), "ipad": ("iOS Device", 40),
            "macbook": ("Mac", 40), "imac": ("Mac", 40),
            "android": ("Mobile Device", 35), "galaxy": ("Samsung Device", 30),
            "pixel": ("Google Device", 35), "desktop": ("Windows PC", 25),
            "laptop": ("Computer", 25), "xbox": ("Game Console", 45),
            "playstation": ("Game Console", 45), "chromecast": ("Chromecast", 45),
            "printer": ("Printer", 45), "camera": ("Camera", 40),
            "nas": ("NAS", 40), "raspberrypi": ("Raspberry Pi", 45),
            "echo": ("Smart Home", 40), "alexa": ("Smart Home", 40),
            "sonos": ("Speaker", 40), "router": ("Router", 35),
        }
        for kw, (dtype, sc) in hostname_map.items():
            if kw in hn:
                add(dtype, sc, f"Hostname contains '{kw}' -> {dtype}")
                break

        # Default gateway
        try:
            if dev.ip == Analyzer.get_default_gateway():
                add("Router", 50, "This is the default gateway")
        except Exception:
            pass

        # NetBIOS
        if dev.netbios_name:
            add("Windows PC", 15, f"NetBIOS name: {dev.netbios_name}")

        # HTTP banner
        if dev.http_banner:
            bl = dev.http_banner.lower()
            banner_map = {
                "synology": ("NAS", 35), "qnap": ("NAS", 35),
                "hikvision": ("Camera", 35), "printer": ("Printer", 30),
                "plex": ("Media Server", 35), "nginx": ("Server", 15),
                "apache": ("Server", 15),
            }
            for kw, (dt, sc) in banner_map.items():
                if kw in bl:
                    add(dt, sc, f"HTTP banner indicates {dt}")
                    break

        best = max(scores, key=scores.get) if scores else "Unknown"
        conf = min(100, scores.get(best, 0))

        return {"device_type": best, "os_guess": os_guess,
                "confidence": conf, "details": details,
                "badge": TYPE_LABELS.get(best, "---")}


class PortScanner:

    @staticmethod
    def scan(ip, ports, timeout=0.7, workers=25):
        found, lock, sem = [], threading.Lock(), threading.Semaphore(workers)

        def check(port):
            with sem:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        with lock: found.append(port)
                    s.close()
                except Exception: pass

        threads = [threading.Thread(target=check, args=(p,), daemon=True) for p in ports]
        for t in threads: t.start()
        for t in threads: t.join(timeout=timeout + 1)
        return sorted(found)

    @staticmethod
    def get_ttl(ip, timeout=1.0):
        try:
            out = subprocess.check_output(
                ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip],
                stderr=subprocess.DEVNULL).decode(errors="ignore")
            m = re.search(r"TTL[=:](\d+)", out, re.IGNORECASE)
            return int(m.group(1)) if m else 0
        except Exception: return 0

    @staticmethod
    def http_banner(ip, port=80, timeout=1.5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = s.recv(1024).decode(errors="ignore")
            s.close()
            for line in data.split('\r\n'):
                if line.lower().startswith('server:'):
                    return line.split(':', 1)[1].strip()
            return data[:120]
        except Exception: return ""

    @staticmethod
    def netbios(ip, timeout=1.0):
        try:
            payload = (b'\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                       b'\x20\x43\x4b' + b'\x41' * 30 + b'\x00\x00\x21\x00\x01')
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(payload, (ip, 137))
            data, _ = s.recvfrom(1024)
            s.close()
            if len(data) > 57:
                return data[57:57 + 15].decode(errors="ignore").strip()
        except Exception: pass
        return ""
