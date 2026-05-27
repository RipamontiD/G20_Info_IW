"""Network scan engine: ARP/ping discovery + Tailscale + device analysis."""

import re, socket, subprocess, threading, time
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
        self.devices = OrderedDict()
        self._lock = threading.Lock()
        self._scanning = self._monitoring = False
        self._stop = threading.Event()
        self._thread = None

        self.on_new, self.on_update, self.on_offline = on_new, on_update, on_offline
        self.on_scan_done, self.on_analysis, self.log = on_scan_done, on_analysis, on_log

        self._mac_db = None
        if HAS_MAC_LOOKUP:
            try:
                self._mac_db = MacLookup()
                self._mac_db.update_vendors()
            except Exception:
                pass

        self._method = self._detect()
        self.tailscale_available = TailscaleDiscovery.is_available()

    def _detect(self):
        if SCAPY_AVAILABLE:
            try:
                srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="127.0.0.1/32"),
                    timeout=0.1, verbose=0)
                return "scapy"
            except RuntimeError:
                pass
        return "fallback"

    @staticmethod
    def local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    @staticmethod
    def net_range(ip):
        return '.'.join(ip.split('.')[:3]) + ".0/24"

    def _hostname(self, ip):
        try: return socket.gethostbyaddr(ip)[0]
        except Exception: return ""

    def _vendor(self, mac):
        if not self._mac_db: return ""
        try: return self._mac_db.lookup(mac)
        except Exception: return ""

    # ── Sweep methods ────────────────────────────────────────────────
    def _sweep_scapy(self, r, t):
        a, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=r),
                    timeout=t, verbose=0)
        return [(rx.psrc, rx.hwsrc.lower()) for _, rx in a]

    def _sweep_fallback(self, r, t):
        base = r.split('/')[0].rsplit('.', 1)[0]
        sem = threading.Semaphore(50)

        def ping(ip):
            with sem:
                subprocess.call(["ping", "-n", "1", "-w", str(int(t * 1000)), ip],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        threads = []
        for i in range(1, 255):
            if self._stop.is_set(): return []
            th = threading.Thread(target=ping, args=(f"{base}.{i}",), daemon=True)
            threads.append(th); th.start()

        deadline = time.time() + t + 6
        for th in threads:
            th.join(timeout=max(0.1, deadline - time.time()))

        results = []
        try:
            out = subprocess.check_output(["arp", "-a"],
                                          stderr=subprocess.DEVNULL).decode(errors="ignore")
            for m in re.finditer(
                    r'(\d+\.\d+\.\d+\.\d+)\s+'
                    r'([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-]'
                    r'[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-]'
                    r'[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})', out):
                ip, mac = m.group(1), m.group(2).replace('-', ':').lower()
                if mac not in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00') and ip.startswith(base):
                    results.append((ip, mac))
        except Exception:
            pass
        return results

    def _sweep(self, r, t):
        if self._method == "scapy":
            try: return self._sweep_scapy(r, t)
            except RuntimeError:
                self._method = "fallback"
        return self._sweep_fallback(r, t)

    # ── Analysis ─────────────────────────────────────────────────────
    def _analyze(self, dev):
        if self._stop.is_set(): return
        self.log(f"Analyzing {dev.ip}")
        dev.open_ports = PortScanner.scan(dev.ip, SCAN_PORTS, timeout=0.6)
        dev.ttl = PortScanner.get_ttl(dev.ip)

        for p in (80, 8080, 443):
            if p in dev.open_ports:
                dev.http_banner = PortScanner.http_banner(dev.ip, p)
                if dev.http_banner: break

        if 445 in dev.open_ports or (dev.ttl and 65 <= dev.ttl <= 128):
            dev.netbios_name = PortScanner.netbios(dev.ip)

        r = Analyzer.classify(dev)
        with self._lock:
            for k in ('device_type', 'os_guess', 'confidence', 'details', 'badge'):
                setattr(dev, k, r[k])
            dev.analyzed = True

        self.on_analysis(dev)
        self.log(f"  {dev.ip}  ->  {dev.device_type} ({dev.confidence}%)  ports={dev.open_ports}")

    def _analyze_new(self):
        with self._lock:
            pending = [d for d in self.devices.values()
                       if not d.analyzed and d.status == "Online"]
        sem = threading.Semaphore(4)
        threads = []
        for d in pending:
            if self._stop.is_set(): break
            def work(dev=d):
                with sem: self._analyze(dev)
            t = threading.Thread(target=work, daemon=True)
            threads.append(t); t.start()
        for t in threads:
            t.join(timeout=30)

    # ── LAN scan cycle ───────────────────────────────────────────────
    def _cycle(self, ip_range, timeout):
        label = "ARP" if self._method == "scapy" else "Ping+ARP"
        self.log(f"Scan started  [{label}]  {ip_range}")
        t0 = time.perf_counter()

        with self._lock:
            for d in self.devices.values(): d.seen_this_cycle = False

        seen = {}
        for _ in range(2 if self._method == "scapy" else 1):
            if self._stop.is_set(): return
            for ip, mac in self._sweep(ip_range, timeout):
                seen[mac] = ip

        self._process_seen(seen)
        self._finish_cycle(t0)

    # ── Tailscale scan cycle ─────────────────────────────────────────
    def _cycle_tailscale(self):
        self.log("Tailscale scan started")
        t0 = time.perf_counter()

        with self._lock:
            for d in self.devices.values(): d.seen_this_cycle = False

        peers = TailscaleDiscovery.get_peers()
        if not peers:
            self.log("Tailscale: no peers found (is Tailscale running?)")
            self.on_scan_done(time.perf_counter() - t0)
            return

        self.log(f"Tailscale: found {len(peers)} node(s)")
        for p in peers:
            if self._stop.is_set(): return
            ip, key = p["ip"], f"ts-{p['ip']}"
            is_online = p.get("online", False)

            with self._lock:
                if key in self.devices:
                    d = self.devices[key]
                    d.ip, d.last_seen = ip, datetime.now()
                    d.status = "Online" if is_online else "Offline"
                    d.seen_this_cycle = True
                    if p.get("os") and not d.os_guess:
                        d.os_guess = TailscaleDiscovery.os_to_guess(p["os"])
                    self.on_update(d)
                else:
                    d = Device(ip, key, "Tailscale", p.get("hostname") or p.get("dns_name", "").rstrip("."))
                    d.status = "Online" if is_online else "Offline"
                    d.seen_this_cycle = True
                    ts_os = p.get("os", "")
                    if ts_os:
                        d.os_guess = TailscaleDiscovery.os_to_guess(ts_os)
                        d.device_type = TailscaleDiscovery.os_to_device_type(ts_os)
                        d.badge = TYPE_LABELS.get(d.device_type, "---")
                        d.confidence = 40
                        d.details.append(f"Tailscale OS: {ts_os}")
                    dns = p.get("dns_name", "").rstrip(".")
                    if dns: d.details.append(f"DNS: {dns}")
                    if p.get("is_self"): d.details.append("This is the local machine")
                    if p.get("exit_node"): d.details.append("Active exit node")
                    self.devices[key] = d
                    self.on_new(d)

        self._mark_offline()
        elapsed = time.perf_counter() - t0
        online = sum(1 for d in self.devices.values() if d.status == "Online")
        self.log(f"Tailscale discovery complete  {elapsed:.1f}s  {online} online / {len(self.devices)} total")
        self.on_scan_done(elapsed)
        self._analyze_new()

    # ── Shared helpers ───────────────────────────────────────────────
    def _process_seen(self, seen):
        for mac, ip in seen.items():
            if self._stop.is_set(): return
            with self._lock:
                if mac in self.devices:
                    d = self.devices[mac]
                    d.ip, d.last_seen, d.status, d.seen_this_cycle = ip, datetime.now(), "Online", True
                    self.on_update(d)
                else:
                    d = Device(ip, mac, self._vendor(mac), self._hostname(ip))
                    self.devices[mac] = d
                    self.on_new(d)

    def _mark_offline(self):
        with self._lock:
            for d in self.devices.values():
                if not d.seen_this_cycle and d.status == "Online":
                    d.status = "Offline"
                    self.on_offline(d)

    def _finish_cycle(self, t0):
        self._mark_offline()
        elapsed = time.perf_counter() - t0
        online = sum(1 for d in self.devices.values() if d.status == "Online")
        self.log(f"Discovery complete  {elapsed:.1f}s  {online} online / {len(self.devices)} total")
        self.on_scan_done(elapsed)
        self._analyze_new()

    # ── Public interface ─────────────────────────────────────────────
    def _run_threaded(self, target, *args):
        if self._scanning: return
        self._scanning = True
        self._stop.clear()
        self._thread = threading.Thread(target=target, args=args, daemon=True)
        self._thread.start()

    def start_scan(self, r, t=3.0):
        def work():
            try: self._cycle(r, t)
            finally: self._scanning = False
        self._run_threaded(work)

    def start_tailscale_scan(self):
        def work():
            try: self._cycle_tailscale()
            finally: self._scanning = False
        self._run_threaded(work)

    def _monitor_loop(self, cycle_fn, interval):
        try:
            while not self._stop.is_set():
                self._scanning = True
                cycle_fn()
                self._scanning = False
                w = 0.0
                while w < interval and not self._stop.is_set():
                    time.sleep(0.5); w += 0.5
        finally:
            self._scanning = self._monitoring = False

    def start_monitor(self, r, interval=30, t=3.0):
        if self._monitoring: return
        self._monitoring = True
        self._run_threaded(lambda: self._monitor_loop(lambda: self._cycle(r, t), interval))

    def start_tailscale_monitor(self, interval=30):
        if self._monitoring: return
        self._monitoring = True
        self._run_threaded(lambda: self._monitor_loop(self._cycle_tailscale, interval))

    def reanalyze(self, mac):
        with self._lock:
            d = self.devices.get(mac)
        if d:
            d.analyzed, d.services = False, []
            threading.Thread(target=self._analyze, args=(d,), daemon=True).start()

    def stop_all(self):
        self._stop.set()
        self._monitoring = False

    @property
    def is_scanning(self): return self._scanning
    @property
    def is_monitoring(self): return self._monitoring

    def clear(self):
        with self._lock: self.devices.clear()
