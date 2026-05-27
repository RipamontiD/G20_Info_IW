"""Custom reusable widgets: logo, status dot, device card."""

import os
import customtkinter as ctk
from tkinter import Canvas
from .colors import Colors
from .columns import COLUMNS
from .device import Device
from .device_types import TYPE_COLORS

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

_PKG_DIR = os.path.dirname(__file__)


class StesEyeLogo(ctk.CTkFrame):
    """Logo widget: PNG icon + app name."""

    def __init__(self, parent, bg_color=None, **kwargs):
        bg = bg_color or Colors.BG_DARK
        super().__init__(parent, fg_color=bg, corner_radius=0, **kwargs)

        self._logo_img = None
        if HAS_PIL:
            try:
                path = os.path.join(_PKG_DIR, "logo_small.png")
                if os.path.exists(path):
                    pil = Image.open(path)
                    self._logo_img = ctk.CTkImage(
                        light_image=pil, dark_image=pil, size=(28, 28))
            except Exception:
                pass

        if self._logo_img:
            ctk.CTkLabel(self, image=self._logo_img, text="",
                         fg_color="transparent", height=28
                         ).pack(side="left", padx=(6, 4))

        ctk.CTkLabel(self, text="StesEye", font=("Segoe UI", 15, "bold"),
                     text_color=Colors.TEXT_PRIMARY, fg_color="transparent",
                     height=28).pack(side="left", padx=(0, 2))


class StatusDot(Canvas):
    """Tiny colored circle indicating online/offline."""

    def __init__(self, parent, size=8, color=Colors.GREEN, **kwargs):
        super().__init__(parent, width=size + 4, height=size + 4,
                         highlightthickness=0, **kwargs)
        self._size = size
        self._color = color
        self.configure(bg=Colors.BG_CARD)
        self._draw()

    def _draw(self):
        self.delete("all")
        self.create_oval(2, 2, 2 + self._size, 2 + self._size,
                         fill=self._color, outline="")

    def set_color(self, c):
        self._color = c
        self._draw()

    def set_bg(self, bg):
        self.configure(bg=bg)


def _col(col_id):
    """Return (relx, relwidth) for a column id."""
    for cid, _, rx, rw, _ in COLUMNS:
        if cid == col_id:
            return rx, rw
    return 0.0, 0.05


class DeviceCard(ctk.CTkFrame):
    """Device row with place()-based column alignment and zebra striping."""

    ROW_H = 56

    def __init__(self, parent, dev: Device, row_index=0,
                 on_click=None, on_right=None, **kwargs):
        self._row_index = row_index
        self._base_bg = Colors.BG_CARD if row_index % 2 == 0 else Colors.BG_CARD_ALT

        super().__init__(parent, fg_color=self._base_bg,
                         corner_radius=6, height=self.ROW_H, **kwargs)
        self.dev = dev
        self._on_click = on_click
        self._on_right = on_right
        self._selected = False
        self.pack_propagate(False)
        self._build()
        self._bind_all(self)

    def _bind_all(self, w):
        w.bind("<Button-1>", self._click)
        w.bind("<Button-3>", self._right)
        w.bind("<Enter>", self._enter)
        w.bind("<Leave>", self._leave)
        for ch in w.winfo_children():
            self._bind_all(ch)

    def _build(self):
        d = self.dev
        c = Colors
        badge_bg = Colors.BG_CARD_ALT if self._row_index % 2 == 0 else Colors.BG_CARD

        # Dot
        rx, _ = _col("dot")
        self._dot = StatusDot(self, color=c.GREEN if d.status == "Online" else c.RED)
        self._dot.set_bg(self._base_bg)
        self._dot.place(relx=rx, rely=0.5, anchor="w")

        # Badge
        rx, _ = _col("badge")
        self._badge = ctk.CTkLabel(
            self, text=d.badge, width=44, height=22, corner_radius=4,
            fg_color=badge_bg, text_color=TYPE_COLORS.get(d.badge, c.TEXT_MUTED),
            font=("Consolas", 10, "bold"))
        self._badge.place(relx=rx, rely=0.5, anchor="w")

        # Device name
        rx, rw = _col("device")
        nf = ctk.CTkFrame(self, fg_color="transparent")
        nf.place(relx=rx, rely=0.1, relwidth=rw, relheight=0.8)
        self._name_label = ctk.CTkLabel(
            nf, text=d.hostname or d.device_type,
            font=("Segoe UI", 12, "bold"), text_color=c.TEXT_PRIMARY, anchor="w")
        self._name_label.pack(anchor="w", fill="x")
        sub = d.device_type if d.hostname else ""
        if sub:
            ctk.CTkLabel(nf, text=sub, font=("Segoe UI", 10),
                         text_color=c.TEXT_SECONDARY, anchor="w").pack(anchor="w", fill="x")

        # Address
        rx, rw = _col("address")
        af = ctk.CTkFrame(self, fg_color="transparent")
        af.place(relx=rx, rely=0.1, relwidth=rw, relheight=0.8)
        self._ip_label = ctk.CTkLabel(
            af, text=d.ip, font=("Consolas", 11),
            text_color=c.TEXT_PRIMARY, anchor="w")
        self._ip_label.pack(anchor="w", fill="x")
        mac_text = d.mac.lower() if d.mac.startswith("ts-") else d.mac.upper()
        self._mac_label = ctk.CTkLabel(
            af, text=mac_text, font=("Consolas", 9),
            text_color=c.TEXT_MUTED, anchor="w")
        self._mac_label.pack(anchor="w", fill="x")

        # Vendor
        rx, rw = _col("vendor")
        self._vendor_label = ctk.CTkLabel(
            self, text=d.vendor or "Unknown", font=("Segoe UI", 10),
            text_color=c.TEXT_SECONDARY, anchor="w")
        self._vendor_label.place(relx=rx, rely=0.1, relwidth=rw, relheight=0.8)

        # OS
        rx, rw = _col("os")
        self._os_label = ctk.CTkLabel(
            self, text=d.os_guess or "-", font=("Segoe UI", 10),
            text_color=c.TEXT_SECONDARY, anchor="w")
        self._os_label.place(relx=rx, rely=0.1, relwidth=rw, relheight=0.8)

        # Confidence
        rx, rw = _col("conf")
        ct = f"{d.confidence}%" if d.analyzed else "..."
        cc = c.GREEN if d.confidence > 60 else c.YELLOW if d.confidence > 30 else c.TEXT_MUTED
        self._conf_label = ctk.CTkLabel(
            self, text=ct, font=("Consolas", 10), text_color=cc, anchor="e")
        self._conf_label.place(relx=rx, rely=0.1, relwidth=rw, relheight=0.8)

        # Last seen
        rx, rw = _col("seen")
        self._time_label = ctk.CTkLabel(
            self, text=d.last_seen.strftime("%H:%M:%S"),
            font=("Consolas", 10), text_color=c.TEXT_MUTED, anchor="e")
        self._time_label.place(relx=rx, rely=0.1, relwidth=rw, relheight=0.8)

    def update_from_device(self):
        d = self.dev
        c = Colors
        self._dot.set_color(c.GREEN if d.status == "Online" else c.RED)
        self._badge.configure(text=d.badge,
                              text_color=TYPE_COLORS.get(d.badge, c.TEXT_MUTED))
        self._name_label.configure(text=d.hostname or d.device_type)
        self._ip_label.configure(text=d.ip)
        self._mac_label.configure(
            text=d.mac.lower() if d.mac.startswith("ts-") else d.mac.upper())
        self._vendor_label.configure(text=d.vendor or "Unknown")
        self._os_label.configure(text=d.os_guess or "-")
        ct = f"{d.confidence}%" if d.analyzed else "..."
        cc = c.GREEN if d.confidence > 60 else c.YELLOW if d.confidence > 30 else c.TEXT_MUTED
        self._conf_label.configure(text=ct, text_color=cc)
        self._time_label.configure(text=d.last_seen.strftime("%H:%M:%S"))
        self._apply_bg()

    def set_selected(self, v):
        self._selected = v
        self._apply_bg()

    def _apply_bg(self):
        bg = (Colors.RED_DIM if self.dev.status == "Offline"
              else Colors.BG_SELECTED if self._selected
              else self._base_bg)
        self.configure(fg_color=bg)
        self._dot.set_bg(bg)

    def _click(self, e=None):
        if self._on_click:
            self._on_click(self)

    def _right(self, e=None):
        if self._on_right:
            self._on_right(self, e)

    def _enter(self, e=None):
        if not self._selected and self.dev.status != "Offline":
            self.configure(fg_color=Colors.BG_HOVER)

    def _leave(self, e=None):
        if not self._selected and self.dev.status != "Offline":
            self.configure(fg_color=self._base_bg)
        elif self.dev.status == "Offline":
            self.configure(fg_color=Colors.RED_DIM)
