"""Device type classification tables: OUI hints, port signatures, labels, colors."""

from .colors import Colors

OUI_HINTS = {
    "tp-link": "Router", "netgear": "Router", "cisco": "Router",
    "ubiquiti": "Access Point", "mikrotik": "Router", "asus": "Router",
    "d-link": "Router", "linksys": "Router", "arris": "Modem",
    "huawei": "Router", "zte": "Modem", "meraki": "Router",
    "aruba": "Access Point", "ruckus": "Access Point",
    "fortinet": "Firewall", "sonicwall": "Firewall",
    "apple": "Apple Device", "samsung": "Samsung Device",
    "xiaomi": "Mobile Device", "oneplus": "Mobile Device",
    "oppo": "Mobile Device", "vivo": "Mobile Device",
    "google": "Google Device", "motorola": "Mobile Device",
    "lg": "LG Device", "sony": "Sony Device", "nokia": "Mobile Device",
    "dell": "Computer", "hewlett": "Computer", "hp inc": "Computer",
    "lenovo": "Computer", "intel": "Computer", "acer": "Computer",
    "msi": "Computer", "gigabyte": "Computer",
    "microsoft": "Microsoft Device",
    "vmware": "Virtual Machine", "parallels": "Virtual Machine",
    "virtualbox": "Virtual Machine",
    "amazon": "Smart Home", "ring": "Smart Home", "nest": "Smart Home",
    "sonos": "Speaker", "philips": "Smart Home",
    "espressif": "IoT Device", "raspberry": "Raspberry Pi",
    "tuya": "IoT Device", "shelly": "IoT Device",
    "canon": "Printer", "epson": "Printer", "brother": "Printer",
    "xerox": "Printer", "ricoh": "Printer", "lexmark": "Printer",
    "roku": "Media Player", "nvidia": "Media Player",
    "nintendo": "Game Console", "valve": "Game Console",
    "hikvision": "Camera", "dahua": "Camera", "axis": "Camera",
    "reolink": "Camera", "amcrest": "Camera", "wyze": "Camera",
    "synology": "NAS", "qnap": "NAS", "western digital": "NAS",
}

PORT_SIGS = {
    22: ("SSH", "Server"), 23: ("Telnet", "Network Device"),
    53: ("DNS", "DNS Server"), 80: ("HTTP", "Web Server"),
    443: ("HTTPS", "Web Server"), 445: ("SMB", "File Share"),
    515: ("LPR", "Printer"), 548: ("AFP", "Mac/NAS"),
    554: ("RTSP", "Camera"), 631: ("IPP", "Printer"),
    3389: ("RDP", "Windows PC"), 5000: ("HTTP", "NAS"),
    5353: ("mDNS", "Apple Device"), 5900: ("VNC", "Remote Desktop"),
    7000: ("AirPlay", "Apple TV"), 8008: ("HTTP", "Chromecast"),
    8009: ("Cast", "Chromecast"), 8080: ("HTTP", "Server"),
    9100: ("RAW Print", "Printer"), 32400: ("Plex", "Media Server"),
    62078: ("Lockdown", "iOS Device"),
}

SCAN_PORTS = [
    22, 23, 53, 80, 443, 445, 515, 548, 554, 631,
    3389, 5000, 5353, 5900, 7000, 8008, 8009, 8080,
    9100, 32400, 62078,
]

TYPE_LABELS = {
    "Router": "RTR", "Access Point": "AP", "Modem": "MDM",
    "Firewall": "FW", "Switch": "SW", "Gateway": "GW",
    "Computer": "PC", "Windows PC": "WIN", "Linux PC": "LNX",
    "Apple Device": "APL", "Mac": "MAC", "Server": "SRV",
    "Virtual Machine": "VM",
    "Mobile Device": "MOB", "Samsung Device": "MOB",
    "iOS Device": "IOS", "Google Device": "GGL",
    "Microsoft Device": "MS",
    "Printer": "PRT", "Camera": "CAM", "NAS": "NAS",
    "Smart Home": "IOT", "IoT Device": "IOT", "Speaker": "SPK",
    "Media Player": "MDA", "Media Server": "MDA",
    "Chromecast": "CST", "Apple TV": "ATV",
    "Game Console": "GAM", "Raspberry Pi": "RPI",
    "Smart TV": "TV", "LG Device": "LG", "Sony Device": "SNY",
    "DNS Server": "DNS", "Web Server": "WEB",
    "File Share": "FS", "Remote Desktop": "RDP",
    "Unknown": "---",
}

TYPE_COLORS = {
    "RTR": Colors.ACCENT, "AP": Colors.ACCENT, "MDM": Colors.ACCENT,
    "FW": Colors.ORANGE, "SW": Colors.ACCENT, "GW": Colors.ACCENT,
    "PC": Colors.GREEN, "WIN": Colors.GREEN, "LNX": Colors.GREEN,
    "APL": Colors.TEXT_PRIMARY, "MAC": Colors.TEXT_PRIMARY,
    "SRV": Colors.YELLOW, "VM": Colors.YELLOW,
    "MOB": "#a371f7", "IOS": "#a371f7", "GGL": "#a371f7",
    "MS": Colors.GREEN,
    "PRT": Colors.ORANGE, "CAM": Colors.RED, "NAS": Colors.YELLOW,
    "IOT": "#d2a8ff", "SPK": "#d2a8ff",
    "MDA": "#f778ba", "CST": "#f778ba", "ATV": "#f778ba",
    "GAM": "#79c0ff", "RPI": Colors.GREEN,
    "TV": "#f778ba", "LG": "#f778ba", "SNY": "#f778ba",
    "DNS": Colors.ACCENT, "WEB": Colors.ACCENT,
    "FS": Colors.YELLOW, "RDP": Colors.GREEN,
    "---": Colors.TEXT_MUTED,
}
