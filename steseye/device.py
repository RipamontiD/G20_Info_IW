"""Device data record."""

from datetime import datetime


class Device:
    __slots__ = (
        'ip', 'mac', 'vendor', 'hostname', 'first_seen', 'last_seen',
        'status', 'seen_this_cycle', 'device_type', 'os_guess',
        'services', 'confidence', 'details', 'open_ports', 'ttl',
        'http_banner', 'netbios_name', 'analyzed', 'badge',
    )

    def __init__(self, ip, mac, vendor, hostname):
        now = datetime.now()
        self.ip, self.mac, self.vendor, self.hostname = ip, mac, vendor, hostname
        self.first_seen = self.last_seen = now
        self.status = "Online"
        self.seen_this_cycle = True
        self.device_type = "Unknown"
        self.os_guess = self.http_banner = self.netbios_name = ""
        self.services, self.details, self.open_ports = [], [], []
        self.confidence = self.ttl = 0
        self.analyzed = False
        self.badge = "---"
