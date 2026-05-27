"""Device data record."""

from datetime import datetime


class Device:
    __slots__ = (
        'ip', 'mac', 'vendor', 'hostname', 'first_seen', 'last_seen',
        'status', 'seen_this_cycle', 'device_type', 'os_guess',
        'services', 'confidence', 'details', 'open_ports', 'ttl',
        'http_banner', 'netbios_name', 'analyzed', 'badge',
    )

    def __init__(self, ip: str, mac: str, vendor: str, hostname: str):
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.hostname = hostname
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.status = "Online"
        self.seen_this_cycle = True
        self.device_type = "Unknown"
        self.os_guess = ""
        self.services: list[str] = []
        self.confidence = 0
        self.details: list[str] = []
        self.open_ports: list[int] = []
        self.ttl = 0
        self.http_banner = ""
        self.netbios_name = ""
        self.analyzed = False
        self.badge = "---"
