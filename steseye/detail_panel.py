"""Right-side detail panel showing full device information."""

import customtkinter as ctk

from .colors import Colors
from .device import Device
from .device_types import PORT_SIGS, TYPE_COLORS
from .file_transfer import FileTransfer


class DetailPanel(ctk.CTkFrame):
    """Slide-in detail panel on the right."""

    def __init__(self, parent, reanalyze_cb, send_file_cb=None, **kwargs):
        super().__init__(parent, fg_color=Colors.BG_CARD,
                         corner_radius=0, width=340, **kwargs)
        self.reanalyze_cb = reanalyze_cb
        self.send_file_cb = send_file_cb
        self._dev = None
        self.pack_propagate(False)
        self._build_empty()

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()

    def _build_empty(self):
        self._clear()
        ctk.CTkLabel(
            self, text="Select a device\nto view details",
            font=("Segoe UI", 12),
            text_color=Colors.TEXT_MUTED,
            justify="center").pack(expand=True)

    def show_device(self, dev: Device):
        self._dev = dev
        self._clear()
        c = Colors

        # --- Header ---
        hdr = ctk.CTkFrame(self, fg_color=c.BG_CARD_ALT,
                            corner_radius=0, height=90)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        badge_color = TYPE_COLORS.get(dev.badge, c.TEXT_MUTED)
        ctk.CTkLabel(
            hdr, text=dev.badge, width=50, height=26,
            corner_radius=4, fg_color=c.BG_DARK,
            text_color=badge_color,
            font=("Consolas", 12, "bold")
        ).place(x=16, y=14)

        ctk.CTkLabel(
            hdr, text=dev.device_type,
            font=("Segoe UI", 16, "bold"),
            text_color=c.TEXT_PRIMARY
        ).place(x=76, y=10)

        status_color = c.GREEN if dev.status == "Online" else c.RED
        ctk.CTkLabel(
            hdr, text=dev.status,
            font=("Segoe UI", 11),
            text_color=status_color
        ).place(x=76, y=40)

        conf_color = (c.GREEN if dev.confidence > 60
                      else c.YELLOW if dev.confidence > 30
                      else c.TEXT_MUTED)
        ctk.CTkLabel(
            hdr, text=f"{dev.confidence}% confidence",
            font=("Segoe UI", 10),
            text_color=conf_color
        ).place(x=76, y=62)

        # --- Scrollable body ---
        body = ctk.CTkScrollableFrame(
            self, fg_color=c.BG_CARD,
            scrollbar_button_color=c.BORDER,
            scrollbar_button_hover_color=c.BORDER_LIGHT)
        body.pack(fill="both", expand=True)

        def _section(title):
            ctk.CTkLabel(body, text=title,
                         font=("Segoe UI", 11, "bold"),
                         text_color=c.TEXT_ACCENT).pack(
                anchor="w", padx=16, pady=(14, 2))
            ctk.CTkFrame(body, height=1, fg_color=c.BORDER).pack(
                fill="x", padx=16, pady=(0, 6))

        def _row(label, value):
            r = ctk.CTkFrame(body, fg_color="transparent")
            r.pack(fill="x", padx=16, pady=1)
            ctk.CTkLabel(r, text=label, width=110, anchor="w",
                         font=("Segoe UI", 10),
                         text_color=c.TEXT_SECONDARY).pack(side="left")
            ctk.CTkLabel(r, text=value, anchor="w",
                         font=("Consolas", 10),
                         text_color=c.TEXT_PRIMARY).pack(
                side="left", padx=6, fill="x", expand=True)

        _section("Network")
        _row("IP Address", dev.ip)
        _row("MAC", dev.mac.upper())
        _row("Vendor", dev.vendor or "Unknown")
        _row("Hostname", dev.hostname or "-")

        _section("Identity")
        _row("Type", dev.device_type)
        _row("OS", dev.os_guess or "-")
        _row("TTL", str(dev.ttl) if dev.ttl else "-")
        if dev.netbios_name:
            _row("NetBIOS", dev.netbios_name)
        if dev.http_banner:
            _row("HTTP Server", dev.http_banner[:40])

        _section("Services")
        if dev.open_ports:
            for port in dev.open_ports:
                svc = PORT_SIGS.get(port, (str(port), ""))
                pr = ctk.CTkFrame(body, fg_color="transparent")
                pr.pack(fill="x", padx=20, pady=1)
                ctk.CTkLabel(
                    pr, text=str(port), width=50, anchor="w",
                    font=("Consolas", 10),
                    text_color=c.GREEN).pack(side="left")
                ctk.CTkLabel(
                    pr, text=svc[0], anchor="w",
                    font=("Segoe UI", 10),
                    text_color=c.TEXT_PRIMARY).pack(side="left", padx=6)
        else:
            ctk.CTkLabel(body, text="  No open ports found",
                         font=("Segoe UI", 10),
                         text_color=c.TEXT_MUTED).pack(anchor="w", padx=20)

        _section("Analysis")
        if dev.details:
            for detail in dev.details:
                ctk.CTkLabel(
                    body, text=f"  {detail}",
                    font=("Segoe UI", 9),
                    text_color=c.TEXT_MUTED,
                    wraplength=290, justify="left"
                ).pack(anchor="w", padx=16, pady=1)
        else:
            ctk.CTkLabel(body, text="  Pending analysis",
                         font=("Segoe UI", 10),
                         text_color=c.TEXT_MUTED).pack(anchor="w", padx=20)

        _section("Timeline")
        _row("First seen", dev.first_seen.strftime("%Y-%m-%d %H:%M:%S"))
        _row("Last seen", dev.last_seen.strftime("%Y-%m-%d %H:%M:%S"))

        # --- Action buttons ---
        btn_frame = ctk.CTkFrame(self, fg_color=c.BG_CARD_ALT,
                                  corner_radius=0, height=52)
        btn_frame.pack(fill="x", side="bottom")
        btn_frame.pack_propagate(False)

        ctk.CTkButton(
            btn_frame, text="Re-analyze", width=100, height=30,
            corner_radius=4, fg_color=c.ACCENT,
            hover_color=c.ACCENT_HOVER,
            font=("Segoe UI", 11),
            command=lambda: self._reanalyze(dev.mac)
        ).pack(side="left", padx=12, pady=10)

        ctk.CTkButton(
            btn_frame, text="Copy info", width=90, height=30,
            corner_radius=4, fg_color=c.BORDER_LIGHT,
            hover_color=c.BG_HOVER,
            font=("Segoe UI", 11),
            command=lambda: self._copy(dev)
        ).pack(side="left", padx=4, pady=10)

        if FileTransfer.is_windows_target(dev) and dev.status == "Online":
            ctk.CTkButton(
                btn_frame, text="Send file", width=90, height=30,
                corner_radius=4,
                fg_color=c.GREEN_DIM,
                hover_color="#1d4a2f",
                text_color=c.GREEN,
                font=("Segoe UI", 11),
                command=lambda: self._send_file(dev)
            ).pack(side="right", padx=12, pady=10)

    def _reanalyze(self, mac):
        self.reanalyze_cb(mac)

    def _send_file(self, dev):
        if self.send_file_cb:
            self.send_file_cb(dev)

    def _copy(self, dev):
        lines = [
            f"IP: {dev.ip}", f"MAC: {dev.mac.upper()}",
            f"Vendor: {dev.vendor}", f"Hostname: {dev.hostname}",
            f"Type: {dev.device_type}", f"OS: {dev.os_guess}",
            f"Ports: {dev.open_ports}", f"Confidence: {dev.confidence}%",
        ]
        self.clipboard_clear()
        self.clipboard_append('\n'.join(lines))
