"""Dialog windows: transfer result, remote folder browser, send file."""

import os
import threading
from datetime import datetime
from tkinter import filedialog

import customtkinter as ctk

try:
    import winsound
except ImportError:
    winsound = None

from .colors import Colors
from .device import Device
from .file_transfer import FileTransfer


class TransferResultDialog(ctk.CTkToplevel):
    """Popup shown after file transfer completes."""

    def __init__(self, parent, results: list, target_ip: str,
                 target_path: str):
        super().__init__(parent)
        self.title("Transfer Complete")
        self.configure(fg_color=Colors.BG_DARK)
        self.attributes("-topmost", True)
        self.resizable(False, False)

        successes = [r for r in results if r["success"]]
        failures = [r for r in results if not r["success"]]
        all_ok = len(failures) == 0

        height = 280 + min(len(results), 6) * 22
        self.geometry(f"460x{height}")
        self.after(50, lambda: self._center_on_parent(parent))
        self._build(successes, failures, all_ok, target_ip, target_path)

        if winsound:
            try:
                if all_ok:
                    winsound.MessageBeep(winsound.MB_ICONASTERISK)
                else:
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass

        self.transient(parent)
        self.grab_set()
        self.focus_set()
        self.bind("<Return>", lambda e: self.destroy())
        self.bind("<Escape>", lambda e: self.destroy())

    def _center_on_parent(self, parent):
        try:
            self.update_idletasks()
            px = parent.winfo_rootx()
            py = parent.winfo_rooty()
            pw = parent.winfo_width()
            ph = parent.winfo_height()
            ww = self.winfo_width()
            wh = self.winfo_height()
            x = px + (pw - ww) // 2
            y = py + (ph - wh) // 2
            self.geometry(f"+{x}+{y}")
        except Exception:
            pass

    def _build(self, successes, failures, all_ok, target_ip, target_path):
        c = Colors

        if all_ok:
            banner_color, text_color = c.GREEN_DIM, c.GREEN
            indicator, title = "OK", "Transfer Successful"
        elif successes:
            banner_color, text_color = c.YELLOW_DIM, c.YELLOW
            indicator, title = "!", "Transfer Partially Complete"
        else:
            banner_color, text_color = c.RED_DIM, c.RED
            indicator, title = "X", "Transfer Failed"

        banner = ctk.CTkFrame(self, fg_color=banner_color,
                               corner_radius=0, height=70)
        banner.pack(fill="x")
        banner.pack_propagate(False)

        ind_frame = ctk.CTkFrame(
            banner, fg_color=c.BG_DARK, corner_radius=4,
            width=46, height=46)
        ind_frame.pack(side="left", padx=16, pady=12)
        ind_frame.pack_propagate(False)
        ctk.CTkLabel(
            ind_frame, text=indicator,
            font=("Consolas", 20, "bold"),
            text_color=text_color
        ).pack(expand=True)

        text_frame = ctk.CTkFrame(banner, fg_color="transparent")
        text_frame.pack(side="left", fill="both", expand=True, pady=12)
        ctk.CTkLabel(
            text_frame, text=title,
            font=("Segoe UI", 14, "bold"),
            text_color=c.TEXT_PRIMARY, anchor="w"
        ).pack(anchor="w")

        summary = f"{len(successes)} sent"
        if failures:
            summary += f"  -  {len(failures)} failed"
        ctk.CTkLabel(
            text_frame, text=summary,
            font=("Segoe UI", 11),
            text_color=text_color, anchor="w"
        ).pack(anchor="w")

        # Destination info
        dest_frame = ctk.CTkFrame(self, fg_color="transparent")
        dest_frame.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(
            dest_frame, text="DESTINATION",
            font=("Segoe UI", 9, "bold"),
            text_color=c.TEXT_MUTED
        ).pack(anchor="w")
        ctk.CTkLabel(
            dest_frame, text=target_path,
            font=("Consolas", 11),
            text_color=c.TEXT_ACCENT, anchor="w"
        ).pack(anchor="w", pady=(2, 0))

        # File list
        list_label = ctk.CTkFrame(self, fg_color="transparent")
        list_label.pack(fill="x", padx=16, pady=(12, 2))
        ctk.CTkLabel(
            list_label, text="FILES",
            font=("Segoe UI", 9, "bold"),
            text_color=c.TEXT_MUTED
        ).pack(anchor="w")

        list_card = ctk.CTkFrame(self, fg_color=c.BG_CARD, corner_radius=6)
        list_card.pack(fill="x", padx=16, pady=(2, 0))

        for r in successes[:6]:
            row = ctk.CTkFrame(list_card, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=2)
            ctk.CTkLabel(
                row, text="OK", width=24,
                font=("Consolas", 9, "bold"),
                text_color=c.GREEN, anchor="w"
            ).pack(side="left")
            filename = os.path.basename(r.get("dest_path", "")) or "?"
            ctk.CTkLabel(
                row, text=filename,
                font=("Consolas", 10),
                text_color=c.TEXT_PRIMARY, anchor="w"
            ).pack(side="left", fill="x", expand=True)

        for r in failures[:3]:
            row = ctk.CTkFrame(list_card, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=2)
            ctk.CTkLabel(
                row, text="X", width=24,
                font=("Consolas", 9, "bold"),
                text_color=c.RED, anchor="w"
            ).pack(side="left")
            ctk.CTkLabel(
                row, text=r.get("message", "Unknown error")[:55],
                font=("Consolas", 10),
                text_color=c.TEXT_SECONDARY, anchor="w"
            ).pack(side="left", fill="x", expand=True)

        total_shown = min(len(successes), 6) + min(len(failures), 3)
        total_all = len(successes) + len(failures)
        if total_shown < total_all:
            ctk.CTkLabel(
                list_card,
                text=f"  ... and {total_all - total_shown} more",
                font=("Segoe UI", 9),
                text_color=c.TEXT_MUTED, anchor="w"
            ).pack(anchor="w", padx=8, pady=(0, 4))

        ctk.CTkFrame(list_card, height=4,
                     fg_color="transparent").pack()

        # Buttons
        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(16, 16), side="bottom")

        if all_ok and successes:
            ctk.CTkButton(
                btn_row, text="Open destination folder",
                width=180, height=32,
                corner_radius=4, font=("Segoe UI", 11),
                fg_color=c.BORDER_LIGHT, hover_color=c.BG_HOVER,
                text_color=c.TEXT_SECONDARY,
                command=lambda: self._open_folder(target_path)
            ).pack(side="left")

        ctk.CTkButton(
            btn_row, text="Close", width=90, height=32,
            corner_radius=4, font=("Segoe UI", 11, "bold"),
            fg_color=c.ACCENT, hover_color=c.ACCENT_HOVER,
            command=self.destroy
        ).pack(side="right")

    @staticmethod
    def _open_folder(path):
        try:
            os.startfile(path)
        except Exception:
            pass


class RemoteFolderBrowser(ctk.CTkToplevel):
    """Modal dialog for navigating folders inside an SMB share."""

    def __init__(self, parent, ip: str, share: str, on_select):
        super().__init__(parent)
        self.title(f"Browse  -  \\\\{ip}\\{share}")
        self.geometry("560x520")
        self.configure(fg_color=Colors.BG_DARK)
        self.attributes("-topmost", True)
        self.minsize(420, 380)

        self.ip = ip
        self.share = share.replace(" (admin)", "")
        self.on_select = on_select
        self._path_parts: list[str] = []
        self._loading = False

        self._build()
        self.transient(parent)
        self.grab_set()
        self.focus_set()
        self.bind("<Escape>", lambda e: self.destroy())
        self.after(100, self._load_current)

    def _reset_scroll(self):
        try:
            self._list_frame.update_idletasks()
            self._list_frame._parent_canvas.yview_moveto(0.0)
        except Exception:
            pass

    def _build(self):
        c = Colors

        hdr = ctk.CTkFrame(self, fg_color=c.BG_CARD,
                            corner_radius=0, height=56)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text="Browse Folders",
            font=("Segoe UI", 14, "bold"),
            text_color=c.TEXT_PRIMARY
        ).pack(side="left", padx=16, pady=14)

        bottom = ctk.CTkFrame(self, fg_color=c.BG_CARD,
                               corner_radius=0, height=52)
        bottom.pack(fill="x", side="bottom")
        bottom.pack_propagate(False)

        self._select_btn = ctk.CTkButton(
            bottom, text="Use this folder", width=140, height=34,
            corner_radius=4, font=("Segoe UI", 11, "bold"),
            fg_color=c.ACCENT, hover_color=c.ACCENT_HOVER,
            command=self._do_select)
        self._select_btn.pack(side="right", padx=12, pady=9)

        ctk.CTkButton(
            bottom, text="Cancel", width=80, height=34,
            corner_radius=4, font=("Segoe UI", 11),
            fg_color=c.BORDER_LIGHT, hover_color=c.BG_HOVER,
            text_color=c.TEXT_SECONDARY,
            command=self.destroy
        ).pack(side="right", padx=4, pady=9)

        path_frame = ctk.CTkFrame(self, fg_color=c.BG_CARD_ALT,
                                   corner_radius=0, height=44)
        path_frame.pack(fill="x", side="top", pady=(1, 0))
        path_frame.pack_propagate(False)
        ctk.CTkLabel(
            path_frame, text="LOCATION",
            font=("Segoe UI", 8, "bold"),
            text_color=c.TEXT_MUTED
        ).pack(side="left", padx=(12, 8))
        self._path_label = ctk.CTkLabel(
            path_frame, text="",
            font=("Consolas", 11),
            text_color=c.TEXT_ACCENT, anchor="w")
        self._path_label.pack(side="left", fill="x", expand=True)

        tb = ctk.CTkFrame(self, fg_color="transparent", height=40)
        tb.pack(fill="x", side="top", padx=12, pady=(8, 4))
        tb.pack_propagate(False)

        self._up_btn = ctk.CTkButton(
            tb, text="< Up", width=70, height=28,
            corner_radius=4, font=("Segoe UI", 10),
            fg_color=c.BORDER_LIGHT, hover_color=c.BG_HOVER,
            text_color=c.TEXT_SECONDARY,
            command=self._go_up)
        self._up_btn.pack(side="left")

        ctk.CTkButton(
            tb, text="Refresh", width=80, height=28,
            corner_radius=4, font=("Segoe UI", 10),
            fg_color=c.BORDER_LIGHT, hover_color=c.BG_HOVER,
            text_color=c.TEXT_SECONDARY,
            command=self._load_current
        ).pack(side="left", padx=(4, 0))

        self._status = ctk.CTkLabel(
            tb, text="",
            font=("Segoe UI", 9),
            text_color=c.TEXT_MUTED)
        self._status.pack(side="right")

        list_container = ctk.CTkFrame(self, fg_color=c.BG_CARD,
                                       corner_radius=6)
        list_container.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        self._list_frame = ctk.CTkScrollableFrame(
            list_container, fg_color=c.BG_CARD, corner_radius=6,
            scrollbar_button_color=c.BORDER,
            scrollbar_button_hover_color=c.BORDER_LIGHT)
        self._list_frame.pack(fill="both", expand=True, padx=2, pady=2)

    def _current_subpath(self) -> str:
        return "\\".join(self._path_parts)

    def _current_full_path(self) -> str:
        base = f"\\\\{self.ip}\\{self.share}"
        sub = self._current_subpath()
        return os.path.join(base, sub) if sub else base

    def _update_path_display(self):
        display = f"\\\\{self.ip}\\{self.share}"
        if self._path_parts:
            display += "\\" + "\\".join(self._path_parts)
        self._path_label.configure(text=display)
        state = "normal" if self._path_parts else "disabled"
        self._up_btn.configure(state=state)

    def _load_current(self):
        if self._loading:
            return
        self._loading = True
        self._update_path_display()
        self._clear_list()

        ctk.CTkLabel(
            self._list_frame, text="Loading...",
            font=("Segoe UI", 10),
            text_color=Colors.TEXT_MUTED
        ).pack(padx=12, pady=20)
        self._status.configure(text="")

        full_path = self._current_full_path()

        def _worker():
            entries = []
            error = None
            try:
                folders = []
                file_count = 0
                with os.scandir(full_path) as it:
                    for entry in it:
                        try:
                            if entry.is_dir():
                                folders.append(entry.name)
                            else:
                                file_count += 1
                        except OSError:
                            continue
                folders.sort(key=str.lower)
                entries = (folders, file_count)
            except PermissionError:
                error = "Access denied. You may not have permission."
            except FileNotFoundError:
                error = "Folder not found."
            except OSError as e:
                error = f"Cannot access: {e}"
            except Exception as e:
                error = f"Error: {e}"
            self.after(0, self._show_results, entries, error)

        threading.Thread(target=_worker, daemon=True).start()

    def _clear_list(self):
        for w in self._list_frame.winfo_children():
            try:
                w.destroy()
            except Exception:
                pass
        try:
            self._list_frame._parent_canvas.yview_moveto(0.0)
        except Exception:
            pass

    def _show_results(self, entries, error):
        self._loading = False
        self._clear_list()

        if error:
            ctk.CTkLabel(
                self._list_frame, text=error,
                font=("Segoe UI", 10),
                text_color=Colors.RED,
                justify="left", anchor="w"
            ).pack(padx=12, pady=12, anchor="w", fill="x")
            self._status.configure(text="error")
            self._reset_scroll()
            return

        folders, file_count = entries

        if not folders and file_count == 0:
            ctk.CTkLabel(
                self._list_frame, text="(empty folder)",
                font=("Segoe UI", 10),
                text_color=Colors.TEXT_MUTED
            ).pack(padx=12, pady=20)
            self._status.configure(text="0 folders")
            self._reset_scroll()
            return

        if not folders:
            ctk.CTkLabel(
                self._list_frame,
                text=f"(no subfolders, {file_count} file(s) here)",
                font=("Segoe UI", 10),
                text_color=Colors.TEXT_MUTED
            ).pack(padx=12, pady=20)
            self._status.configure(text=f"0 folders, {file_count} files")
            self._reset_scroll()
            return

        st = f"{len(folders)} folder(s)"
        if file_count:
            st += f", {file_count} file(s)"
        self._status.configure(text=st)

        for name in folders:
            self._make_folder_row(name)
        self._reset_scroll()

    def _make_folder_row(self, name: str):
        ctk.CTkButton(
            self._list_frame,
            text=f"  [DIR]   {name}",
            height=34, corner_radius=4, anchor="w",
            font=("Consolas", 11),
            fg_color=Colors.BG_CARD_ALT,
            hover_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_PRIMARY,
            command=lambda n=name: self._enter_folder(n)
        ).pack(fill="x", padx=4, pady=2)

    def _enter_folder(self, name: str):
        self._path_parts.append(name)
        self._load_current()

    def _go_up(self):
        if self._path_parts:
            self._path_parts.pop()
            self._load_current()

    def _do_select(self):
        sub = self._current_subpath()
        self.on_select(sub)
        self.destroy()


class SendFileDialog(ctk.CTkToplevel):
    """Dialog for selecting files and sending them to a device via SMB."""

    def __init__(self, parent, dev: Device, log_cb=None):
        super().__init__(parent)
        self.title(f"Send File  —  {dev.ip}")
        self.geometry("560x640")
        self.configure(fg_color=Colors.BG_DARK)
        self.attributes("-topmost", True)
        self.resizable(True, True)
        self.minsize(480, 500)

        self.dev = dev
        self.log_cb = log_cb or (lambda m: None)
        self._selected_files: list[str] = []
        self._selected_share = None
        self._share_buttons: dict[str, ctk.CTkButton] = {}
        self._transferring = False
        self._discovering = False
        self._selected_subfolder = ""

        self._build()
        self.after(300, self._discover_shares)

    def _build(self):
        c = Colors

        # Header
        hdr = ctk.CTkFrame(self, fg_color=c.BG_CARD, corner_radius=0,
                            height=64)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        ctk.CTkLabel(
            hdr, text="Send File",
            font=("Segoe UI", 16, "bold"),
            text_color=c.TEXT_PRIMARY
        ).pack(side="left", padx=16, pady=10)

        target_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        target_frame.pack(side="right", padx=16)
        ctk.CTkLabel(
            target_frame, text=self.dev.ip,
            font=("Consolas", 12),
            text_color=c.TEXT_ACCENT
        ).pack(anchor="e")
        name = (self.dev.hostname or self.dev.netbios_name
                or self.dev.device_type)
        ctk.CTkLabel(
            target_frame, text=name,
            font=("Segoe UI", 10),
            text_color=c.TEXT_SECONDARY
        ).pack(anchor="e")

        # Bottom buttons
        bottom = ctk.CTkFrame(self, fg_color=c.BG_CARD,
                               corner_radius=0, height=52)
        bottom.pack(fill="x", side="bottom")
        bottom.pack_propagate(False)

        self._send_btn = ctk.CTkButton(
            bottom, text="Send", width=100, height=34,
            corner_radius=4, font=("Segoe UI", 12, "bold"),
            fg_color=c.ACCENT, hover_color=c.ACCENT_HOVER,
            command=self._do_send)
        self._send_btn.pack(side="right", padx=12, pady=9)

        ctk.CTkButton(
            bottom, text="Cancel", width=80, height=34,
            corner_radius=4, font=("Segoe UI", 11),
            fg_color=c.BORDER_LIGHT, hover_color=c.BG_HOVER,
            text_color=c.TEXT_SECONDARY,
            command=self.destroy
        ).pack(side="right", padx=4, pady=9)

        # Transfer log
        self._transfer_log = ctk.CTkTextbox(
            self, height=70, font=("Consolas", 9),
            fg_color=c.BG_CARD, text_color=c.TEXT_MUTED,
            state="disabled", corner_radius=4,
            border_width=1, border_color=c.BORDER)
        self._transfer_log.pack(fill="x", side="bottom", padx=16, pady=(4, 8))

        # Progress
        prog_frame = ctk.CTkFrame(self, fg_color="transparent")
        prog_frame.pack(fill="x", side="bottom", padx=16, pady=(4, 4))
        self._progress_text = ctk.CTkLabel(
            prog_frame, text="",
            font=("Segoe UI", 9),
            text_color=c.TEXT_MUTED, anchor="w")
        self._progress_text.pack(fill="x", side="bottom", pady=(2, 0))
        self._progress_bar = ctk.CTkProgressBar(
            prog_frame, height=6, fg_color=c.BORDER,
            progress_color=c.ACCENT, corner_radius=2)
        self._progress_bar.pack(fill="x", side="bottom")
        self._progress_bar.set(0)

        # Destination display
        self._dest_label = ctk.CTkLabel(
            self, text="No destination selected",
            font=("Consolas", 10),
            text_color=c.TEXT_MUTED, anchor="w")
        self._dest_label.pack(fill="x", side="bottom", padx=16, pady=(4, 4))

        # Step 1: Select files
        s1 = ctk.CTkFrame(self, fg_color="transparent")
        s1.pack(fill="x", side="top", padx=16, pady=(12, 4))
        ctk.CTkLabel(
            s1, text="1. SELECT FILES",
            font=("Segoe UI", 9, "bold"),
            text_color=c.TEXT_MUTED
        ).pack(anchor="w")

        file_card = ctk.CTkFrame(s1, fg_color=c.BG_CARD, corner_radius=6)
        file_card.pack(fill="x", pady=(4, 0))
        self._file_list = ctk.CTkTextbox(
            file_card, height=70, font=("Consolas", 9),
            fg_color=c.BG_CARD, text_color=c.TEXT_SECONDARY,
            state="disabled", corner_radius=4)
        self._file_list.pack(fill="x", padx=8, pady=(8, 4))

        btn_row = ctk.CTkFrame(file_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(
            btn_row, text="Browse files", width=110, height=28,
            corner_radius=4, font=("Segoe UI", 10),
            fg_color=c.ACCENT, hover_color=c.ACCENT_HOVER,
            command=self._browse_files
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            btn_row, text="Clear", width=60, height=28,
            corner_radius=4, font=("Segoe UI", 10),
            fg_color=c.BORDER_LIGHT, hover_color=c.BG_HOVER,
            text_color=c.TEXT_SECONDARY,
            command=self._clear_files
        ).pack(side="left")
        self._file_size_label = ctk.CTkLabel(
            btn_row, text="",
            font=("Segoe UI", 9),
            text_color=c.TEXT_MUTED)
        self._file_size_label.pack(side="right")

        # Step 2: Select destination
        s2 = ctk.CTkFrame(self, fg_color="transparent")
        s2.pack(fill="x", side="top", padx=16, pady=(12, 4))

        s2_header = ctk.CTkFrame(s2, fg_color="transparent")
        s2_header.pack(fill="x")
        ctk.CTkLabel(
            s2_header, text="2. SELECT DESTINATION",
            font=("Segoe UI", 9, "bold"),
            text_color=c.TEXT_MUTED
        ).pack(side="left", anchor="w")

        self._refresh_btn = ctk.CTkButton(
            s2_header, text="Refresh", width=65, height=22,
            corner_radius=3, font=("Segoe UI", 9),
            fg_color=c.BORDER_LIGHT, hover_color=c.BG_HOVER,
            text_color=c.TEXT_SECONDARY,
            command=self._discover_shares)
        self._refresh_btn.pack(side="right")

        self._browse_btn = ctk.CTkButton(
            s2_header, text="Browse subfolders...", width=140, height=22,
            corner_radius=3, font=("Segoe UI", 9),
            fg_color=c.BORDER_LIGHT, hover_color=c.BG_HOVER,
            text_color=c.TEXT_SECONDARY, state="disabled",
            command=self._open_browser)
        self._browse_btn.pack(side="right", padx=(0, 6))

        # Manual path input
        manual = ctk.CTkFrame(s2, fg_color="transparent")
        manual.pack(fill="x", side="bottom", pady=(6, 0))
        ctk.CTkLabel(
            manual, text="Or type path:",
            font=("Segoe UI", 9),
            text_color=c.TEXT_MUTED
        ).pack(side="left", padx=(0, 6))
        self._manual_path = ctk.CTkEntry(
            manual, height=28, corner_radius=4,
            font=("Consolas", 10),
            fg_color=c.BG_INPUT, border_color=c.BORDER,
            text_color=c.TEXT_PRIMARY,
            placeholder_text=f"\\\\{self.dev.ip}\\ShareName")
        self._manual_path.pack(side="left", fill="x", expand=True)

        # Shares list container
        self._shares_container = ctk.CTkFrame(
            s2, fg_color=c.BG_CARD, corner_radius=6)
        self._shares_container.pack(fill="x", side="top", pady=(4, 0))
        self._build_shares_list()

    # ------------------------------------------------------------------ #
    #  Shares list management
    # ------------------------------------------------------------------ #
    def _build_shares_list(self):
        self._shares_frame = ctk.CTkFrame(
            self._shares_container,
            fg_color=Colors.BG_CARD, corner_radius=6)
        self._shares_frame.pack(fill="x", padx=2, pady=2)

    def _rebuild_shares_list(self):
        if hasattr(self, '_shares_frame') and self._shares_frame:
            try:
                self._shares_frame.destroy()
            except Exception:
                pass
        self._share_buttons.clear()
        self._build_shares_list()

    # ------------------------------------------------------------------ #
    #  File selection
    # ------------------------------------------------------------------ #
    def _browse_files(self):
        paths = filedialog.askopenfilenames(
            title="Select files to send",
            filetypes=[("All files", "*.*")])
        if paths:
            self._selected_files = list(paths)
            self._update_file_list()

    def _clear_files(self):
        self._selected_files = []
        self._update_file_list()

    def _update_file_list(self):
        self._file_list.configure(state="normal")
        self._file_list.delete("1.0", "end")
        total_size = 0
        for f in self._selected_files:
            name = os.path.basename(f)
            try:
                size = os.path.getsize(f)
            except Exception:
                size = 0
            total_size += size
            self._file_list.insert(
                "end", f"  {name}  ({self._fmt_size(size)})\n")
        self._file_list.configure(state="disabled")

        if self._selected_files:
            self._file_size_label.configure(
                text=f"{len(self._selected_files)} file(s), "
                     f"{self._fmt_size(total_size)}")
        else:
            self._file_size_label.configure(text="")

    def _update_browse_button_state(self):
        state = "normal" if self._selected_share else "disabled"
        self._browse_btn.configure(state=state)

    def _open_browser(self):
        if not self._selected_share:
            self._tlog("Select a share first")
            return

        def _on_picked(subfolder):
            self._selected_subfolder = subfolder
            clean = self._selected_share.replace(" (admin)", "")
            full = f"\\\\{self.dev.ip}\\{clean}"
            if subfolder:
                full = os.path.join(full, subfolder)
            self._dest_label.configure(text=full)
            self._tlog(f"Folder picked: {full}")

        RemoteFolderBrowser(
            self, ip=self.dev.ip, share=self._selected_share,
            on_select=_on_picked)

    @staticmethod
    def _fmt_size(n):
        if n < 1024:
            return f"{n} B"
        elif n < 1024 ** 2:
            return f"{n / 1024:.1f} KB"
        elif n < 1024 ** 3:
            return f"{n / 1024 ** 2:.1f} MB"
        else:
            return f"{n / 1024 ** 3:.2f} GB"

    # ------------------------------------------------------------------ #
    #  Share discovery
    # ------------------------------------------------------------------ #
    def _discover_shares(self):
        if self._discovering:
            return
        self._discovering = True
        self._refresh_btn.configure(state="disabled", text="Scanning...")
        self._rebuild_shares_list()

        ctk.CTkLabel(
            self._shares_frame,
            text="Scanning for shared folders...",
            font=("Segoe UI", 10),
            text_color=Colors.TEXT_MUTED
        ).pack(padx=12, pady=20)

        self._tlog(f"Discovering shares on {self.dev.ip}...")

        def _worker():
            shares = FileTransfer.get_all_shares(self.dev.ip)
            self.after(0, self._populate_shares, shares)

        threading.Thread(target=_worker, daemon=True).start()

    def _populate_shares(self, shares):
        self._discovering = False
        self._refresh_btn.configure(state="normal", text="Refresh")
        self._rebuild_shares_list()

        if not shares:
            ctk.CTkLabel(
                self._shares_frame,
                text="No accessible shares found.\nType a path manually below.",
                font=("Segoe UI", 10),
                text_color=Colors.TEXT_MUTED,
                justify="left", anchor="w"
            ).pack(padx=12, pady=12, anchor="w", fill="x")
            self._tlog("No shares found")
            return

        self._tlog(f"Found {len(shares)} share(s)")
        ctk.CTkLabel(
            self._shares_frame,
            text=f"  {len(shares)} share(s) available - click to select:",
            font=("Segoe UI", 9),
            text_color=Colors.TEXT_MUTED, anchor="w"
        ).pack(fill="x", padx=4, pady=(6, 2))

        for share in shares:
            btn = ctk.CTkButton(
                self._shares_frame,
                text=f"  {share}", height=36,
                corner_radius=4, anchor="w",
                font=("Consolas", 11),
                fg_color=Colors.BG_CARD_ALT,
                hover_color=Colors.BG_HOVER,
                text_color=Colors.TEXT_PRIMARY,
                command=lambda s=share: self._select_share(s))
            btn.pack(fill="x", padx=6, pady=2)
            self._share_buttons[share] = btn

        ctk.CTkFrame(self._shares_frame, height=4,
                     fg_color="transparent").pack()

    def _select_share(self, share):
        self._selected_share = share
        self._selected_subfolder = ""
        clean = share.replace(" (admin)", "")
        self._dest_label.configure(text=f"\\\\{self.dev.ip}\\{clean}")

        for name, btn in self._share_buttons.items():
            if name == share:
                btn.configure(fg_color=Colors.BG_SELECTED,
                              text_color=Colors.TEXT_ACCENT)
            else:
                btn.configure(fg_color=Colors.BG_CARD_ALT,
                              text_color=Colors.TEXT_PRIMARY)
        self._tlog(f"Selected: {share}")
        self._update_browse_button_state()

    # ------------------------------------------------------------------ #
    #  Transfer
    # ------------------------------------------------------------------ #
    def _do_send(self):
        if self._transferring:
            return
        if not self._selected_files:
            self._tlog("Select files first (step 1)")
            return

        manual = self._manual_path.get().strip()
        if manual:
            if not manual.startswith("\\\\"):
                self._tlog("Path must start with \\\\")
                return
            parts = manual.strip("\\").split("\\")
            if len(parts) < 2:
                self._tlog("Path must be \\\\IP\\ShareName")
                return
            ip = parts[0]
            share = parts[1]
            subfolder = "\\".join(parts[2:]) if len(parts) > 2 else ""
        elif self._selected_share:
            ip = self.dev.ip
            share = self._selected_share
            subfolder = self._selected_subfolder
        else:
            self._tlog("Select a destination first (step 2)")
            return

        self._transferring = True
        self._send_btn.configure(state="disabled", text="Sending...")
        self._progress_bar.set(0)
        self._progress_text.configure(text="Starting transfer...")

        def _worker():
            total_files = len(self._selected_files)
            success_count = 0
            fail_count = 0
            results = []

            clean_share = share.replace(" (admin)", "")
            target_path = f"\\\\{ip}\\{clean_share}"
            if subfolder:
                target_path = os.path.join(target_path, subfolder)

            for i, fpath in enumerate(self._selected_files):
                filename = os.path.basename(fpath)
                self.after(0, self._tlog,
                           f"[{i + 1}/{total_files}] Sending: {filename}")

                def _progress(copied, total, _i=i):
                    if total > 0:
                        file_pct = copied / total
                        overall = (_i + file_pct) / total_files
                        size_text = (f"{self._fmt_size(copied)} / "
                                     f"{self._fmt_size(total)}")
                        self.after(0, self._set_progress,
                                   overall, f"{filename}  {size_text}")

                result = FileTransfer.send_file(
                    fpath, ip, share, subfolder, _progress)
                results.append(result)

                if result["success"]:
                    success_count += 1
                    self.after(0, self._tlog, f"  Sent: {filename}")
                    if self.log_cb:
                        self.after(0, self.log_cb,
                                   f"File sent: {filename} -> {target_path}")
                else:
                    fail_count += 1
                    self.after(0, self._tlog,
                               f"  FAILED: {result['message']}")

            summary = f"Done: {success_count} sent"
            if fail_count:
                summary += f", {fail_count} failed"
            self.after(0, self._transfer_done, summary, results, target_path)

        threading.Thread(target=_worker, daemon=True).start()

    def _set_progress(self, value, text):
        try:
            self._progress_bar.set(min(value, 1.0))
            self._progress_text.configure(text=text)
        except Exception:
            pass

    def _transfer_done(self, summary, results=None, target_path=""):
        self._transferring = False
        self._send_btn.configure(state="normal", text="Send")
        self._progress_bar.set(1.0)
        self._progress_text.configure(text=summary)
        self._tlog(summary)
        self.after(2000, lambda: self._progress_bar.set(0))

        if results:
            TransferResultDialog(self, results, self.dev.ip, target_path)

    def _tlog(self, msg):
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            self._transfer_log.configure(state="normal")
            self._transfer_log.insert("end", f"{ts}  {msg}\n")
            self._transfer_log.see("end")
            self._transfer_log.configure(state="disabled")
        except Exception:
            pass
