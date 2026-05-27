"""Network scan engine: ARP/ping discovery + device analysis + Tailscale."""

import re
import socket
import subprocess
import threading
import time
from collections import OrderedDict
from datetime import datetime

from .analyzer import Analyzer, PortScanner
from .device import Device
from .device_types import SCAN_PORTS, TYPE_LABELS
from .tailscale import TailscaleDiscovery

SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    pass

try:
    from mac_vendor_lookup import MacLookup
    HAS_MAC_LOOKUP = True
except ImportError:
    HAS_MAC_LOOKUP = False


class ScanEngine:

    def __init__(self, on_new, on_update, on_offline, on_scan_done,
                 on_analysis, on_log):
        self.devices: OrderedDict[str, Device] = OrderedDict()
        self._lock = threading.Lock()
        self._scanning = False
        self._monitoring = False
        self._stop = threading.Event()
        self._thread = None

        self.on_new = on_new
        self.on_update = on_update
        self.on_offline = on_offline
        self.on_scan_done = on_scan_done
        self.on_analysis = on_analysis
        self.log = on_log

        self._mac_db = None
        if HAS_MAC_LOOKUP:
            try:
                self._mac_db = MacLookup()
                self._mac_db.update_vendors()
            except Exception:
                self._mac_db = None

        self._method = self._detect()
        self.tailscale_available = TailscaleDiscovery.is_available()

    # ------------------------------------------------------------------ #
    #  Detection
    # ------------------------------------------------------------------ #
    def _detect(self) -> str:
        if SCAPY_AVAILABLE:
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="127.0.0.1/32")
                srp(pkt, timeout=0.1, verbose=0)
                return "scapy"
            except RuntimeError:
                pass
        return "fallback"

    @staticmethod
    def local_ip() -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    @staticmethod
    def net_range(ip: str) -> str:
        return '.'.join(ip.split('.')[:3]) + ".0/24"

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #
    def _hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def _vendor(self, mac: str) -> str:
        if not self._mac_db:
            return ""
        try:
            return self._mac_db.lookup(mac)
        except Exception:
            return ""

    # ------------------------------------------------------------------ #
    #  Sweep methods
    # ------------------------------------------------------------------ #
    def _sweep_scapy(self, r, t):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=r)
        a, _ = srp(pkt, timeout=t, verbose=0)
        return [(rx.psrc, rx.hwsrc.lower()) for _, rx in a]

    def _sweep_fallback(self, r, t):
        base = r.split('/')[0].rsplit('.', 1)[0]
        sem = threading.Semaphore(50)
        threads = []

        def _p(ip):
            with sem:
                subprocess.call(
                    ["ping", "-n", "1", "-w", str(int(t * 1000)), ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for i in range(1, 255):
            if self._stop.is_set():
                return []
            th = threading.Thread(
                target=_p, args=(f"{base}.{i}",), daemon=True)
            threads.append(th)
            th.start()

        dl = time.time() + t + 6
        for th in threads:
            th.join(timeout=max(0.1, dl - time.time()))

        results = []
        try:
            out = subprocess.check_output(
                ["arp", "-a"], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            pat = re.compile(
                r'(\d+\.\d+\.\d+\.\d+)\s+'
                r'([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-]'
                r'[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-]'
                r'[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})')
            for m in pat.finditer(out):
                ip = m.group(1)
                mac = m.group(2).replace('-', ':').lower()
                if mac in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
                    continue
                if base and not ip.startswith(base):
                    continue
                results.append((ip, mac))
        except Exception:
            pass
        return results

    def _sweep(self, r, t):
        if self._method == "scapy":
            try:
                return self._sweep_scapy(r, t)
            except RuntimeError:
                self._method = "fallback"
                return self._sweep_fallback(r, t)
        return self._sweep_fallback(r, t)

    # ------------------------------------------------------------------ #
    #  Analysis
    # ------------------------------------------------------------------ #
    def _analyze(self, dev: Device):
        if self._stop.is_set():
            return
        self.log(f"Analyzing {dev.ip}")
        dev.open_ports = PortScanner.scan(dev.ip, SCAN_PORTS, timeout=0.6)
        dev.ttl = PortScanner.get_ttl(dev.ip)

        for hp in [80, 8080, 443]:
            if hp in dev.open_ports:
                dev.http_banner = PortScanner.http_banner(dev.ip, hp)
                if dev.http_banner:
                    break

        if 445 in dev.open_ports or (dev.ttl and 65 <= dev.ttl <= 128):
            dev.netbios_name = PortScanner.netbios(dev.ip)

        r = Analyzer.classify(dev)
        with self._lock:
            dev.device_type = r["device_type"]
            dev.os_guess = r["os_guess"]
            dev.confidence = r["confidence"]
            dev.details = r["details"]
            dev.badge = r["badge"]
            dev.analyzed = True

        self.on_analysis(dev)
        self.log(
            f"  {dev.ip}  ->  {dev.device_type} ({dev.confidence}%)"
            f"  ports={dev.open_ports}")

    def _analyze_new(self):
        with self._lock:
            pending = [d for d in self.devices.values()
                       if not d.analyzed and d.status == "Online"]
        sem = threading.Semaphore(4)
        threads = []
        for d in pending:
            if self._stop.is_set():
                break

            def _do(dev=d):
                with sem:
                    self._analyze(dev)

            t = threading.Thread(target=_do, daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=30)

    # ------------------------------------------------------------------ #
    #  Standard LAN scan cycle
    # ------------------------------------------------------------------ #
    def _cycle(self, ip_range, timeout):
        label = "ARP" if self._method == "scapy" else "Ping+ARP"
        self.log(f"Scan started  [{label}]  {ip_range}")
        t0 = time.perf_counter()

        with self._lock:
            for d in self.devices.values():
                d.seen_this_cycle = False

        seen: dict[str, str] = {}
        passes = 2 if self._method == "scapy" else 1
        for _ in range(passes):
            if self._stop.is_set():
                return
            for ip, mac in self._sweep(ip_range, timeout):
                seen[mac] = ip

        for mac, ip in seen.items():
            if self._stop.is_set():
                return
            with self._lock:
                if mac in self.devices:
                    d = self.devices[mac]
                    d.ip = ip
                    d.last_seen = datetime.now()
                    d.status = "Online"
                    d.seen_this_cycle = True
                    self.on_update(d)
                else:
                    v = self._vendor(mac)
                    h = self._hostname(ip)
                    d = Device(ip, mac, v, h)
                    self.devices[mac] = d
                    self.on_new(d)

        with self._lock:
            for d in self.devices.values():
                if not d.seen_this_cycle and d.status == "Online":
                    d.status = "Offline"
                    self.on_offline(d)

        elapsed = time.perf_counter() - t0
        online = sum(1 for d in self.devices.values() if d.status == "Online")
        self.log(
            f"Discovery complete  {elapsed:.1f}s  "
            f"{online} online / {len(self.devices)} total")
        self.on_scan_done(elapsed)
        self._analyze_new()

    # ------------------------------------------------------------------ #
    #  Tailscale scan cycle
    # ------------------------------------------------------------------ #
    def _cycle_tailscale(self):
        self.log("Tailscale scan started")
        t0 = time.perf_counter()

        with self._lock:
            for d in self.devices.values():
                d.seen_this_cycle = False

        peers = TailscaleDiscovery.get_peers()

        if not peers:
            self.log("Tailscale: no peers found (is Tailscale running?)")
            self.on_scan_done(time.perf_counter() - t0)
            return

        self.log(f"Tailscale: found {len(peers)} node(s)")

        for p in peers:
            if self._stop.is_set():
                return

            ip = p["ip"]
            # Tailscale nodes have no MAC; use IP as key
            key = f"ts-{ip}"
            hostname = p["hostname"]
            dns_name = p.get("dns_name", "").rstrip(".")
            ts_os = p.get("os", "")
            is_online = p.get("online", False)

            with self._lock:
                if key in self.devices:
                    d = self.devices[key]
                    d.ip = ip
                    d.last_seen = datetime.now()
                    d.status = "Online" if is_online else "Offline"
                    d.seen_this_cycle = True
                    if ts_os and not d.os_guess:
                        d.os_guess = TailscaleDiscovery.os_to_guess(ts_os)
                    self.on_update(d)
                else:
                    d = Device(ip, key, "Tailscale", hostname or dns_name)
                    d.status = "Online" if is_online else "Offline"
                    d.seen_this_cycle = True

                    # Pre-fill with Tailscale metadata
                    if ts_os:
                        d.os_guess = TailscaleDiscovery.os_to_guess(ts_os)
                        d.device_type = TailscaleDiscovery.os_to_device_type(ts_os)
                        d.badge = TYPE_LABELS.get(d.device_type, "---")
                        d.confidence = 40
                        d.details.append(f"Tailscale OS: {ts_os}")
                    if dns_name:
                        d.details.append(f"DNS: {dns_name}")
                    if p.get("is_self"):
                        d.details.append("This is the local machine")
                    if p.get("exit_node"):
                        d.details.append("Active exit node")

                    self.devices[key] = d
                    self.on_new(d)

        # Mark missing peers as offline
        with self._lock:
            for d in self.devices.values():
                if not d.seen_this_cycle and d.status == "Online":
                    d.status = "Offline"
                    self.on_offline(d)

        elapsed = time.perf_counter() - t0
        online = sum(1 for d in self.devices.values() if d.status == "Online")
        self.log(
            f"Tailscale discovery complete  {elapsed:.1f}s  "
            f"{online} online / {len(self.devices)} total")
        self.on_scan_done(elapsed)

        # Port scan + analysis on online peers
        self._analyze_new()

    # ------------------------------------------------------------------ #
    #  Public interface
    # ------------------------------------------------------------------ #
    def start_scan(self, r, t=3.0):
        if self._scanning:
            return
        self._scanning = True
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._scan_w, args=(r, t), daemon=True)
        self._thread.start()

    def _scan_w(self, r, t):
        try:
            self._cycle(r, t)
        finally:
            self._scanning = False

    def start_tailscale_scan(self):
        """Run a single Tailscale discovery + analysis cycle."""
        if self._scanning:
            return
        self._scanning = True
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._ts_scan_w, daemon=True)
        self._thread.start()

    def _ts_scan_w(self):
        try:
            self._cycle_tailscale()
        finally:
            self._scanning = False

    def start_tailscale_monitor(self, interval=30):
        """Continuously monitor the Tailscale tailnet."""
        if self._monitoring:
            return
        self._monitoring = True
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._ts_mon_w, args=(interval,), daemon=True)
        self._thread.start()

    def _ts_mon_w(self, interval):
        try:
            while not self._stop.is_set():
                self._scanning = True
                self._cycle_tailscale()
                self._scanning = False
                w = 0.0
                while w < interval and not self._stop.is_set():
                    time.sleep(0.5)
                    w += 0.5
        finally:
            self._scanning = False
            self._monitoring = False

    def start_monitor(self, r, interval=30, t=3.0):
        if self._monitoring:
            return
        self._monitoring = True
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._mon_w, args=(r, interval, t), daemon=True)
        self._thread.start()

    def _mon_w(self, r, interval, t):
        try:
            while not self._stop.is_set():
                self._scanning = True
                self._cycle(r, t)
                self._scanning = False
                w = 0.0
                while w < interval and not self._stop.is_set():
                    time.sleep(0.5)
                    w += 0.5
        finally:
            self._scanning = False
            self._monitoring = False

    def reanalyze(self, mac):
        with self._lock:
            d = self.devices.get(mac)
        if d:
            d.analyzed = False
            d.services = []
            threading.Thread(
                target=self._analyze, args=(d,), daemon=True).start()

    def stop_all(self):
        self._stop.set()
        self._monitoring = False

    @property
    def is_scanning(self):
        return self._scanning

    @property
    def is_monitoring(self):
        return self._monitoring

    def clear(self):
        with self._lock:
            self.devices.clear()
