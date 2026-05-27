"""Main application window."""

import csv
import os
import json
import sys
import time
from datetime import datetime
from tkinter import filedialog, messagebox

import customtkinter as ctk

try:
    import winsound
except ImportError:
    winsound = None

from .colors import Colors
from .detail_panel import DetailPanel
from .device import Device
from .dialogs import SendFileDialog
from .file_transfer import FileTransfer
from .scan_engine import ScanEngine
from .columns import COLUMNS
from .widgets import DeviceCard, StesEyeLogo


class StesEyeApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("StesEye")
        self.geometry("1340x800")
        self.minsize(1000, 560)
        self.configure(fg_color=Colors.BG_DARK)
        ctk.set_appearance_mode("dark")
        self._set_window_icon()

        self.engine = ScanEngine(
            on_new=lambda d: self.after(0, self._on_new, d),
            on_update=lambda d: self.after(0, self._on_update, d),
            on_offline=lambda d: self.after(0, self._on_offline, d),
            on_scan_done=lambda e: self.after(0, self._on_scan_done, e),
            on_analysis=lambda d: self.after(0, self._on_analysis, d),
            on_log=lambda m: self.after(0, self._log, m),
        )

        try:
            lip = ScanEngine.local_ip()
            self._default_range = ScanEngine.net_range(lip)
            self._local_ip = lip
        except Exception:
            self._default_range = "192.168.1.0/24"
            self._local_ip = "unknown"

        self._cards: dict[str, DeviceCard] = {}
        self._row_counter = 0
        self._selected_mac = None

        self._build()
        self.protocol("WM_DELETE_WINDOW", self._quit)
        self.after(300, self._startup_log)

    def _set_window_icon(self):
        """Set the window icon from .ico file (Windows titlebar + taskbar)."""
        try:
            ico_path = os.path.join(
                os.path.dirname(__file__), "steseye.ico")
            if os.path.exists(ico_path):
                self.after(200, lambda: self.iconbitmap(ico_path))
        except Exception:
            pass  # icon is cosmetic, never crash for it

    def _startup_log(self):
        m = self.engine._method
        label = "ARP (Scapy/Npcap)" if m == "scapy" else "Ping + ARP table"
        self._log(f"Scan method: {label}")
        self._log(f"Local IP: {self._local_ip}")
        if self.engine.tailscale_available:
            self._log("Tailscale CLI detected")
        else:
            self._log("Tailscale CLI not found (Tailscale scan disabled)")

    # ================================================================== #
    #  Layout
    # ================================================================== #
    def _build(self):
        self._build_topbar()

        self._main = ctk.CTkFrame(self, fg_color=Colors.BG_DARK,
                                   corner_radius=0)
        self._main.pack(fill="both", expand=True)
        self._main.grid_columnconfigure(0, weight=1)
        self._main.grid_columnconfigure(1, weight=0)
        self._main.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(self._main, fg_color=Colors.BG_DARK,
                             corner_radius=0)
        left.grid(row=0, column=0, sticky="nsew")
        left.grid_rowconfigure(0, weight=1)
        left.grid_columnconfigure(0, weight=1)

        self._scroll = ctk.CTkScrollableFrame(
            left, fg_color=Colors.BG_DARK,
            scrollbar_button_color=Colors.BORDER,
            scrollbar_button_hover_color=Colors.BORDER_LIGHT,
            corner_radius=0)
        self._scroll.grid(row=0, column=0, sticky="nsew")

        self._build_col_headers(self._scroll)

        self._detail = DetailPanel(
            self._main,
            reanalyze_cb=self._reanalyze,
            send_file_cb=self._open_send_file)
        self._detail.grid(row=0, column=1, sticky="ns")

        self._build_bottom()

    def _build_topbar(self):
        c = Colors

        # ── Single compact toolbar row ───────────────────────────────
        bar = ctk.CTkFrame(self, fg_color=c.BG_TOOLBAR,
                            corner_radius=0, height=48)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        # ── Logo (left) ──────────────────────────────────────────────
        logo = StesEyeLogo(bar, bg_color=c.BG_TOOLBAR)
        logo.pack(side="left", fill="y", padx=(8, 0))

        # thin vertical separator after logo
        ctk.CTkFrame(bar, width=1, fg_color=c.BORDER_LIGHT).pack(
            side="left", fill="y", padx=12, pady=8)

        # ── Network range ────────────────────────────────────────────
        self.range_var = ctk.StringVar(value=self._default_range)
        ctk.CTkEntry(
            bar, textvariable=self.range_var,
            width=170, height=30, corner_radius=4,
            font=("Consolas", 12),
            fg_color=c.BG_INPUT, border_color=c.BORDER_LIGHT,
            text_color=c.TEXT_PRIMARY,
            placeholder_text="192.168.1.0/24"
        ).pack(side="left", padx=(0, 6))

        # ── Timeout ──────────────────────────────────────────────────
        self.timeout_var = ctk.StringVar(value="3")
        ctk.CTkEntry(
            bar, textvariable=self.timeout_var,
            width=40, height=30, corner_radius=4,
            font=("Consolas", 12),
            fg_color=c.BG_INPUT, border_color=c.BORDER_LIGHT,
            text_color=c.TEXT_PRIMARY,
            placeholder_text="T"
        ).pack(side="left", padx=(0, 6))

        # ── Interval ─────────────────────────────────────────────────
        self.interval_var = ctk.StringVar(value="30")
        ctk.CTkEntry(
            bar, textvariable=self.interval_var,
            width=40, height=30, corner_radius=4,
            font=("Consolas", 12),
            fg_color=c.BG_INPUT, border_color=c.BORDER_LIGHT,
            text_color=c.TEXT_PRIMARY,
            placeholder_text="I"
        ).pack(side="left", padx=(0, 2))

        # thin separator before LAN buttons
        ctk.CTkFrame(bar, width=1, fg_color=c.BORDER_LIGHT).pack(
            side="left", fill="y", padx=10, pady=8)

        # ── LAN buttons ─────────────────────────────────────────────
        self._scan_btn = ctk.CTkButton(
            bar, text="Scan", width=64, height=30,
            corner_radius=4, font=("Segoe UI", 11, "bold"),
            fg_color=c.ACCENT, hover_color=c.ACCENT_HOVER,
            command=self._do_scan)
        self._scan_btn.pack(side="left", padx=2)

        self._monitor_btn = ctk.CTkButton(
            bar, text="Monitor", width=76, height=30,
            corner_radius=4, font=("Segoe UI", 11),
            fg_color=c.GREEN_DIM, text_color=c.GREEN,
            hover_color="#1d4a2f",
            command=self._do_monitor)
        self._monitor_btn.pack(side="left", padx=2)

        self._stop_btn = ctk.CTkButton(
            bar, text="Stop", width=52, height=30,
            corner_radius=4, font=("Segoe UI", 11),
            fg_color=c.RED_DIM, text_color=c.RED,
            hover_color="#4d1a1a", state="disabled",
            command=self._do_stop)
        self._stop_btn.pack(side="left", padx=2)

        # thin separator before Tailscale buttons
        ctk.CTkFrame(bar, width=1, fg_color=c.BORDER_LIGHT).pack(
            side="left", fill="y", padx=10, pady=8)

        # ── Tailscale buttons ────────────────────────────────────────
        ts_state = "normal" if self.engine.tailscale_available else "disabled"

        self._ts_scan_btn = ctk.CTkButton(
            bar, text="TS Scan", width=70, height=30,
            corner_radius=4, font=("Segoe UI", 11),
            fg_color="#1a2740", text_color="#58a6ff",
            hover_color="#1e3a5f", state=ts_state,
            command=self._do_tailscale_scan)
        self._ts_scan_btn.pack(side="left", padx=2)

        self._ts_mon_btn = ctk.CTkButton(
            bar, text="TS Monitor", width=86, height=30,
            corner_radius=4, font=("Segoe UI", 11),
            fg_color="#1a2740", text_color="#58a6ff",
            hover_color="#1e3a5f", state=ts_state,
            command=self._do_tailscale_monitor)
        self._ts_mon_btn.pack(side="left", padx=2)

        # ── Right side: Alerts, Clear, Export ────────────────────────
        ctk.CTkButton(
            bar, text="Export", width=60, height=28,
            corner_radius=4, font=("Segoe UI", 10),
            fg_color=c.BORDER_LIGHT,
            hover_color=c.BG_HOVER,
            text_color=c.TEXT_SECONDARY,
            command=self._do_export
        ).pack(side="right", padx=(4, 10))

        ctk.CTkButton(
            bar, text="Clear", width=52, height=28,
            corner_radius=4, font=("Segoe UI", 10),
            fg_color=c.BORDER_LIGHT,
            hover_color=c.BG_HOVER,
            text_color=c.TEXT_SECONDARY,
            command=self._do_clear
        ).pack(side="right", padx=2)

        self._notify_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            bar, text="Alerts",
            variable=self._notify_var, width=60, height=24,
            font=("Segoe UI", 10),
            text_color=c.TEXT_SECONDARY,
            fg_color=c.ACCENT,
            hover_color=c.ACCENT_HOVER,
            border_color=c.BORDER_LIGHT
        ).pack(side="right", padx=(0, 8))

        # ── Bottom border line (visual separator from content) ───────
        ctk.CTkFrame(self, height=1, fg_color=c.BORDER_LIGHT,
                     corner_radius=0).pack(fill="x")

    def _build_col_headers(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color=Colors.BG_HEADER,
                            corner_radius=0, height=28)
        hdr.pack(fill="x", pady=(4, 2))
        hdr.pack_propagate(False)

        for col_id, label, relx, relw, anchor in COLUMNS:
            if not label:
                continue
            lbl = ctk.CTkLabel(
                hdr, text=label, font=("Segoe UI", 9),
                text_color=Colors.TEXT_MUTED, anchor=anchor)
            lbl.place(relx=relx, rely=0.1, relwidth=relw, relheight=0.8)

    def _build_bottom(self):
        bottom = ctk.CTkFrame(self, fg_color=Colors.BG_HEADER,
                               corner_radius=0, height=130)
        bottom.pack(fill="x", side="bottom")
        bottom.pack_propagate(False)

        status_bar = ctk.CTkFrame(bottom, fg_color="transparent", height=28)
        status_bar.pack(fill="x", padx=12, pady=(4, 0))
        status_bar.pack_propagate(False)

        self._status_text = ctk.CTkLabel(
            status_bar, text="Ready", font=("Segoe UI", 10),
            text_color=Colors.TEXT_SECONDARY, anchor="w")
        self._status_text.pack(side="left")

        self._count_text = ctk.CTkLabel(
            status_bar, text="0 devices", font=("Segoe UI", 10),
            text_color=Colors.TEXT_MUTED, anchor="e")
        self._count_text.pack(side="right")

        self._progress = ctk.CTkProgressBar(
            bottom, width=300, height=3,
            fg_color=Colors.BORDER,
            progress_color=Colors.ACCENT,
            corner_radius=1)
        self._progress.pack(fill="x", padx=12, pady=(2, 4))
        self._progress.set(0)

        self._logbox = ctk.CTkTextbox(
            bottom, height=75, font=("Consolas", 9),
            fg_color=Colors.BG_DARK,
            text_color=Colors.TEXT_MUTED,
            scrollbar_button_color=Colors.BORDER,
            state="disabled", wrap="word",
            corner_radius=4, border_width=1,
            border_color=Colors.BORDER)
        self._logbox.pack(fill="x", padx=12, pady=(0, 8))

    # ================================================================== #
    #  Engine callbacks
    # ================================================================== #
    def _on_new(self, dev: Device):
        card = DeviceCard(
            self._scroll, dev,
            row_index=self._row_counter,
            on_click=self._select_card,
            on_right=self._ctx_menu)
        self._row_counter += 1
        card.pack(fill="x", pady=2)
        self._cards[dev.mac] = card
        self._counts()

        if self._notify_var.get():
            self._log(f"New device: {dev.ip}  {dev.mac.upper()}"
                      f"  {dev.vendor or ''}")
            if winsound:
                try:
                    winsound.MessageBeep(winsound.MB_ICONASTERISK)
                except Exception:
                    pass

    def _on_update(self, dev: Device):
        card = self._cards.get(dev.mac)
        if card:
            card.update_from_device()
        self._counts()
        if self._selected_mac == dev.mac:
            self._detail.show_device(dev)

    def _on_offline(self, dev: Device):
        card = self._cards.get(dev.mac)
        if card:
            card.update_from_device()
        self._counts()
        if self._selected_mac == dev.mac:
            self._detail.show_device(dev)

        if self._notify_var.get():
            self._log(f"Offline: {dev.ip}  {dev.mac.upper()}")
            if winsound:
                try:
                    winsound.MessageBeep(winsound.MB_ICONHAND)
                except Exception:
                    pass

    def _on_scan_done(self, elapsed):
        self._progress.set(1.0)
        self.after(600, lambda: self._progress.set(0))
        if not self.engine.is_monitoring:
            self._scan_btn.configure(state="normal")
            self._monitor_btn.configure(state="normal")
            self._stop_btn.configure(state="disabled")
            ts_state = ("normal" if self.engine.tailscale_available
                        else "disabled")
            self._ts_scan_btn.configure(state=ts_state)
            self._ts_mon_btn.configure(state=ts_state)
            self._status_text.configure(text=f"Scan complete ({elapsed:.1f}s)")
        else:
            self._status_text.configure(
                text=f"Monitoring  |  next scan in ~{self.interval_var.get()}s")

    def _on_analysis(self, dev: Device):
        card = self._cards.get(dev.mac)
        if card:
            card.update_from_device()
        if self._selected_mac == dev.mac:
            self._detail.show_device(dev)
        self._counts()

    # ================================================================== #
    #  UI actions
    # ================================================================== #
    def _select_card(self, card: DeviceCard):
        if self._selected_mac and self._selected_mac in self._cards:
            self._cards[self._selected_mac].set_selected(False)
        self._selected_mac = card.dev.mac
        card.set_selected(True)
        self._detail.show_device(card.dev)

    def _ctx_menu(self, card: DeviceCard, event):
        self._select_card(card)
        dev = card.dev

        menu = ctk.CTkToplevel(self)
        menu.overrideredirect(True)
        x = event.x_root if event else self.winfo_pointerx()
        y = event.y_root if event else self.winfo_pointery()
        menu.geometry(f"+{x}+{y}")
        menu.attributes("-topmost", True)
        menu.configure(fg_color=Colors.BG_CARD_ALT)

        def _copy(t):
            self.clipboard_clear()
            self.clipboard_append(t)
            menu.destroy()

        def _reanalyze():
            menu.destroy()
            self._reanalyze(dev.mac)

        def _send():
            menu.destroy()
            self._open_send_file(dev)

        items = [
            (f"Copy IP      {dev.ip}", lambda: _copy(dev.ip)),
            (f"Copy MAC     {dev.mac.upper()}",
             lambda: _copy(dev.mac.upper())),
            ("Copy all info", lambda: _copy(
                f"{dev.ip} | {dev.mac.upper()} | {dev.vendor} | "
                f"{dev.device_type} | {dev.hostname}")),
            ("Re-analyze", _reanalyze),
        ]

        if FileTransfer.is_windows_target(dev) and dev.status == "Online":
            items.append(("Send file", _send))

        for text, cmd in items:
            fg = Colors.GREEN_DIM if text == "Send file" else Colors.BG_CARD_ALT
            tc = Colors.GREEN if text == "Send file" else Colors.TEXT_PRIMARY
            ctk.CTkButton(
                menu, text=text, width=280, height=28,
                corner_radius=2, anchor="w",
                font=("Consolas", 10),
                fg_color=fg, hover_color=Colors.BG_HOVER,
                text_color=tc, command=cmd
            ).pack(padx=2, pady=1)

        menu.bind("<FocusOut>", lambda e: menu.destroy())
        menu.focus_set()

    def _reanalyze(self, mac):
        self.engine.reanalyze(mac)
        self._log(f"Re-analyzing {mac.upper()}")

    def _do_scan(self):
        r = self.range_var.get().strip()
        if not r:
            return
        t = float(self.timeout_var.get() or 3)
        self._disable_all_scan_buttons()
        self._status_text.configure(text="Scanning...")
        self._pulse()
        self.engine.start_scan(r, t)

    def _do_monitor(self):
        r = self.range_var.get().strip()
        if not r:
            return
        t = float(self.timeout_var.get() or 3)
        i = int(self.interval_var.get() or 30)
        self._disable_all_scan_buttons()
        self._status_text.configure(text="Monitoring...")
        self._pulse()
        self.engine.start_monitor(r, i, t)

    def _do_tailscale_scan(self):
        if not self.engine.tailscale_available:
            messagebox.showinfo(
                "StesEye",
                "Tailscale CLI not found.\n"
                "Make sure Tailscale is installed and running.")
            return
        self._disable_all_scan_buttons()
        self._status_text.configure(text="Tailscale scan...")
        self._pulse()
        self.engine.start_tailscale_scan()

    def _do_tailscale_monitor(self):
        if not self.engine.tailscale_available:
            messagebox.showinfo(
                "StesEye",
                "Tailscale CLI not found.\n"
                "Make sure Tailscale is installed and running.")
            return
        i = int(self.interval_var.get() or 30)
        self._disable_all_scan_buttons()
        self._status_text.configure(text="Tailscale monitoring...")
        self._pulse()
        self.engine.start_tailscale_monitor(interval=i)

    def _disable_all_scan_buttons(self):
        self._scan_btn.configure(state="disabled")
        self._monitor_btn.configure(state="disabled")
        self._ts_scan_btn.configure(state="disabled")
        self._ts_mon_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")

    def _do_stop(self):
        self.engine.stop_all()
        self._stop_btn.configure(state="disabled")
        self._scan_btn.configure(state="normal")
        self._monitor_btn.configure(state="normal")
        ts_state = "normal" if self.engine.tailscale_available else "disabled"
        self._ts_scan_btn.configure(state=ts_state)
        self._ts_mon_btn.configure(state=ts_state)
        self._status_text.configure(text="Stopped")
        self._progress.set(0)
        self._log("Stopped")

    def _do_clear(self):
        if self.engine.is_scanning or self.engine.is_monitoring:
            messagebox.showinfo("StesEye", "Stop scanning first.")
            return
        self.engine.clear()
        for card in self._cards.values():
            card.destroy()
        self._cards.clear()
        self._row_counter = 0
        self._selected_mac = None
        self._detail._build_empty()
        self._counts()
        self._log("Cleared all devices")

    def _do_export(self):
        if not self.engine.devices:
            messagebox.showinfo("StesEye", "No devices to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")])
        if not path:
            return
        try:
            devs = list(self.engine.devices.values())
            if path.endswith(".json"):
                data = [{
                    "ip": d.ip, "mac": d.mac.upper(),
                    "vendor": d.vendor, "hostname": d.hostname,
                    "type": d.device_type, "os": d.os_guess,
                    "ports": d.open_ports, "confidence": d.confidence,
                    "status": d.status,
                    "first_seen": d.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": d.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                } for d in devs]
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["Status", "Type", "IP", "MAC", "Vendor",
                                 "Hostname", "OS", "Ports", "Confidence"])
                    for d in devs:
                        w.writerow([
                            d.status, d.device_type, d.ip, d.mac.upper(),
                            d.vendor, d.hostname, d.os_guess,
                            str(d.open_ports), f"{d.confidence}%"])
            self._log(f"Exported -> {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _open_send_file(self, dev: Device):
        if dev.status != "Online":
            messagebox.showinfo("StesEye", "Device is offline.")
            return
        if 445 not in dev.open_ports:
            messagebox.showinfo(
                "StesEye",
                "SMB port (445) is not open on this device.\n"
                "File sharing may be disabled.")
            return
        SendFileDialog(self, dev, log_cb=self._log)

    # ================================================================== #
    #  Helpers
    # ================================================================== #
    def _log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self._logbox.configure(state="normal")
        self._logbox.insert("end", f"{ts}  {msg}\n")
        self._logbox.see("end")
        self._logbox.configure(state="disabled")

    def _counts(self):
        total = len(self.engine.devices)
        online = sum(1 for d in self.engine.devices.values()
                     if d.status == "Online")
        analyzed = sum(1 for d in self.engine.devices.values()
                       if d.analyzed)
        self._count_text.configure(
            text=f"{online} online  /  {total} total  /  {analyzed} analyzed")

    def _pulse(self):
        if self.engine.is_scanning or self.engine.is_monitoring:
            v = self._progress.get() + 0.015
            self._progress.set(v if v <= 0.92 else 0.05)
            self.after(180, self._pulse)

    def _quit(self):
        self.engine.stop_all()
        time.sleep(0.2)
        self.destroy()
