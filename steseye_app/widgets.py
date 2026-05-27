"""Custom reusable widgets: logo, status dot, device card."""

import customtkinter as ctk
from tkinter import Canvas

from .colors import Colors
from .device import Device
from .device_types import TYPE_COLORS


class StesEyeLogo(Canvas):
    """Hand-drawn text logo with a subtle accent line."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Colors.BG_DARK, highlightthickness=0,
                         height=40, **kwargs)
        self.bind("<Configure>", self._draw)

    def _draw(self, event=None):
        self.delete("all")
        self.create_text(
            24, 20, text="StesEye", anchor="w",
            font=("Segoe UI", 18, "bold"), fill=Colors.TEXT_PRIMARY)
        self.create_oval(132, 10, 140, 18, fill=Colors.ACCENT, outline="")
        self.create_text(
            150, 22, text="network scanner", anchor="w",
            font=("Segoe UI", 9), fill=Colors.TEXT_MUTED)


class StatusDot(Canvas):
    """Tiny colored circle indicating online/offline."""

    def __init__(self, parent, size=8, color=Colors.GREEN, **kwargs):
        super().__init__(parent, width=size + 4, height=size + 4,
                         bg=Colors.BG_CARD, highlightthickness=0, **kwargs)
        self._size = size
        self._color = color
        self._draw()

    def _draw(self):
        self.delete("all")
        p = 2
        self.create_oval(p, p, p + self._size, p + self._size,
                         fill=self._color, outline="")

    def set_color(self, color):
        self._color = color
        self._draw()


class DeviceCard(ctk.CTkFrame):
    """A single device row rendered as a card-style row."""

    def __init__(self, parent, dev: Device, on_click=None, on_right=None,
                 **kwargs):
        super().__init__(parent, fg_color=Colors.BG_CARD,
                         corner_radius=6, height=56, **kwargs)
        self.dev = dev
        self._on_click = on_click
        self._on_right = on_right
        self._selected = False

        self.pack_propagate(False)
        self.grid_columnconfigure(0, weight=0, minsize=14)
        self.grid_columnconfigure(1, weight=0, minsize=52)
        self.grid_columnconfigure(2, weight=1, minsize=120)
        self.grid_columnconfigure(3, weight=1, minsize=120)
        self.grid_columnconfigure(4, weight=1, minsize=140)
        self.grid_columnconfigure(5, weight=0, minsize=70)
        self.grid_columnconfigure(6, weight=0, minsize=45)
        self.grid_columnconfigure(7, weight=0, minsize=100)

        self._build()
        self.bind("<Button-1>", self._click)
        self.bind("<Double-Button-1>", self._dblclick)
        self.bind("<Button-3>", self._right)
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)

        for child in self.winfo_children():
            child.bind("<Button-1>", self._click)
            child.bind("<Double-Button-1>", self._dblclick)
            child.bind("<Button-3>", self._right)
            child.bind("<Enter>", self._enter)
            child.bind("<Leave>", self._leave)

    def _build(self):
        d = self.dev
        c = Colors

        dot_color = c.GREEN if d.status == "Online" else c.RED
        self._dot = StatusDot(self, color=dot_color)
        self._dot.grid(row=0, column=0, padx=(10, 4), pady=12)

        badge_color = TYPE_COLORS.get(d.badge, c.TEXT_MUTED)
        self._badge = ctk.CTkLabel(
            self, text=d.badge, width=44, height=22,
            corner_radius=4,
            fg_color=c.BG_CARD_ALT,
            text_color=badge_color,
            font=("Consolas", 10, "bold"))
        self._badge.grid(row=0, column=1, padx=(2, 8), pady=12)

        name_frame = ctk.CTkFrame(self, fg_color="transparent")
        name_frame.grid(row=0, column=2, sticky="w", padx=4, pady=4)
        display_name = d.hostname or d.device_type
        self._name_label = ctk.CTkLabel(
            name_frame, text=display_name,
            font=("Segoe UI", 12, "bold"),
            text_color=c.TEXT_PRIMARY, anchor="w")
        self._name_label.pack(anchor="w")
        sub = d.device_type if d.hostname else ""
        if sub:
            self._sub_label = ctk.CTkLabel(
                name_frame, text=sub,
                font=("Segoe UI", 10),
                text_color=c.TEXT_SECONDARY, anchor="w")
            self._sub_label.pack(anchor="w")

        addr_frame = ctk.CTkFrame(self, fg_color="transparent")
        addr_frame.grid(row=0, column=3, sticky="w", padx=4, pady=4)
        self._ip_label = ctk.CTkLabel(
            addr_frame, text=d.ip,
            font=("Consolas", 11),
            text_color=c.TEXT_PRIMARY, anchor="w")
        self._ip_label.pack(anchor="w")
        self._mac_label = ctk.CTkLabel(
            addr_frame, text=d.mac.upper(),
            font=("Consolas", 9),
            text_color=c.TEXT_MUTED, anchor="w")
        self._mac_label.pack(anchor="w")

        self._vendor_label = ctk.CTkLabel(
            self, text=d.vendor or "Unknown",
            font=("Segoe UI", 10),
            text_color=c.TEXT_SECONDARY, anchor="w")
        self._vendor_label.grid(row=0, column=4, sticky="w", padx=4, pady=4)

        self._os_label = ctk.CTkLabel(
            self, text=d.os_guess or "-",
            font=("Segoe UI", 10),
            text_color=c.TEXT_SECONDARY, anchor="w")
        self._os_label.grid(row=0, column=5, sticky="w", padx=4, pady=4)

        conf_text = f"{d.confidence}%" if d.analyzed else "..."
        conf_color = (c.GREEN if d.confidence > 60
                      else c.YELLOW if d.confidence > 30
                      else c.TEXT_MUTED)
        self._conf_label = ctk.CTkLabel(
            self, text=conf_text,
            font=("Consolas", 10),
            text_color=conf_color, anchor="center")
        self._conf_label.grid(row=0, column=6, padx=4, pady=4)

        time_str = d.last_seen.strftime("%H:%M:%S")
        self._time_label = ctk.CTkLabel(
            self, text=time_str,
            font=("Consolas", 10),
            text_color=c.TEXT_MUTED, anchor="e")
        self._time_label.grid(row=0, column=7, padx=(4, 12), pady=4)

    def update_from_device(self):
        d = self.dev
        c = Colors

        dot_color = c.GREEN if d.status == "Online" else c.RED
        self._dot.set_color(dot_color)

        badge_color = TYPE_COLORS.get(d.badge, c.TEXT_MUTED)
        self._badge.configure(text=d.badge, text_color=badge_color)

        display_name = d.hostname or d.device_type
        self._name_label.configure(text=display_name)

        self._ip_label.configure(text=d.ip)
        self._mac_label.configure(text=d.mac.upper())
        self._vendor_label.configure(text=d.vendor or "Unknown")
        self._os_label.configure(text=d.os_guess or "-")

        conf_text = f"{d.confidence}%" if d.analyzed else "..."
        conf_color = (c.GREEN if d.confidence > 60
                      else c.YELLOW if d.confidence > 30
                      else c.TEXT_MUTED)
        self._conf_label.configure(text=conf_text, text_color=conf_color)

        self._time_label.configure(text=d.last_seen.strftime("%H:%M:%S"))

        if d.status == "Offline":
            self.configure(fg_color=Colors.RED_DIM)
        else:
            fg = Colors.BG_SELECTED if self._selected else Colors.BG_CARD
            self.configure(fg_color=fg)

    def set_selected(self, val: bool):
        self._selected = val
        if self.dev.status == "Offline":
            self.configure(fg_color=Colors.RED_DIM)
        elif val:
            self.configure(fg_color=Colors.BG_SELECTED)
        else:
            self.configure(fg_color=Colors.BG_CARD)

    def _click(self, e=None):
        if self._on_click:
            self._on_click(self)

    def _dblclick(self, e=None):
        pass

    def _right(self, e=None):
        if self._on_right:
            self._on_right(self, e)

    def _enter(self, e=None):
        if not self._selected and self.dev.status != "Offline":
            self.configure(fg_color=Colors.BG_HOVER)

    def _leave(self, e=None):
        if not self._selected and self.dev.status != "Offline":
            self.configure(fg_color=Colors.BG_CARD)
        elif self.dev.status == "Offline":
            self.configure(fg_color=Colors.RED_DIM)
