"""SMB-based file transfer logic."""

import os
import pathlib
import shutil
import subprocess

from .device import Device


class FileTransfer:
    """Handles SMB file transfers to Windows PCs on the LAN."""

    @staticmethod
    def is_windows_target(dev: Device) -> bool:
        """Check if a device likely accepts SMB file transfers."""
        if 445 not in dev.open_ports:
            return False
        hints = [
            dev.os_guess and "windows" in dev.os_guess.lower(),
            dev.device_type and "pc" in dev.device_type.lower(),
            dev.device_type and "windows" in dev.device_type.lower(),
            dev.device_type and "computer" in dev.device_type.lower(),
            dev.netbios_name != "",
            dev.badge in ("WIN", "PC", "MS"),
            445 in dev.open_ports,
        ]
        return any(hints)

    @staticmethod
    def discover_shares(ip: str, timeout: float = 5.0) -> list[str]:
        """Discover SMB shares via ``net view``."""
        shares: list[str] = []
        try:
            output = subprocess.check_output(
                ["net", "view", f"\\\\{ip}"],
                stderr=subprocess.STDOUT,
                timeout=timeout,
            ).decode(errors="ignore")

            in_shares = False
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('---'):
                    in_shares = True
                    continue
                if in_shares and line:
                    if line.startswith("The command"):
                        break
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].lower() == "disk":
                        shares.append(parts[0])
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
        except Exception:
            pass
        return shares

    @staticmethod
    def discover_shares_wmic(ip: str) -> list[str]:
        """Alternative share discovery using PowerShell/WMI."""
        shares: list[str] = []
        try:
            cmd = (
                f'powershell -Command "'
                f"Get-WmiObject -Class Win32_Share "
                f"-ComputerName {ip} "
                f"-ErrorAction SilentlyContinue | "
                f"Where-Object {{$_.Type -eq 0}} | "
                f'Select-Object -ExpandProperty Name"'
            )
            output = subprocess.check_output(
                cmd, shell=True, timeout=8,
                stderr=subprocess.DEVNULL,
            ).decode(errors="ignore")
            for line in output.strip().split('\n'):
                name = line.strip()
                if name and name not in ('Name', '----'):
                    shares.append(name)
        except Exception:
            pass
        return shares

    @staticmethod
    def get_all_shares(ip: str) -> list[str]:
        """Try multiple methods to find shares."""
        shares = FileTransfer.discover_shares(ip)
        if not shares:
            shares = FileTransfer.discover_shares_wmic(ip)

        admin_shares: list[str] = []
        for default in ["C$", "D$", "Users", "Public"]:
            if default not in shares:
                test_path = f"\\\\{ip}\\{default}"
                try:
                    if os.path.exists(test_path):
                        admin_shares.append(f"{default} (admin)")
                except Exception:
                    pass
        return shares + admin_shares

    @staticmethod
    def test_share_access(ip: str, share: str) -> bool:
        clean_share = share.replace(" (admin)", "")
        path = f"\\\\{ip}\\{clean_share}"
        try:
            return os.path.isdir(path)
        except Exception:
            return False

    @staticmethod
    def list_share_contents(ip: str, share: str,
                            subfolder: str = "") -> list[dict]:
        clean_share = share.replace(" (admin)", "")
        path = f"\\\\{ip}\\{clean_share}"
        if subfolder:
            path = os.path.join(path, subfolder)
        try:
            entries = []
            for entry in os.scandir(path):
                entries.append({
                    "name": entry.name,
                    "is_dir": entry.is_dir(),
                    "path": entry.path,
                })
            return sorted(entries, key=lambda e: (not e["is_dir"], e["name"]))
        except PermissionError:
            return [{"name": "[Access Denied]", "is_dir": False, "path": ""}]
        except Exception:
            return []

    @staticmethod
    def send_file(source_path: str, ip: str, share: str,
                  dest_folder: str = "",
                  progress_cb=None) -> dict:
        """Copy a file to a remote SMB share.

        Args:
            source_path: Local file path.
            ip: Target IP address.
            share: Share name.
            dest_folder: Subfolder within the share (optional).
            progress_cb: ``callback(bytes_copied, total_bytes)``.

        Returns:
            ``{"success": bool, "message": str, "dest_path": str}``
        """
        clean_share = share.replace(" (admin)", "")
        dest_dir = f"\\\\{ip}\\{clean_share}"
        if dest_folder:
            dest_dir = os.path.join(dest_dir, dest_folder)

        filename = os.path.basename(source_path)
        dest_path = os.path.join(dest_dir, filename)

        try:
            if not os.path.isfile(source_path):
                return {"success": False,
                        "message": f"Source file not found: {source_path}",
                        "dest_path": ""}

            if not os.path.isdir(dest_dir):
                return {"success": False,
                        "message": f"Cannot access: {dest_dir}",
                        "dest_path": ""}

            # Handle duplicate filenames
            if os.path.exists(dest_path):
                stem = pathlib.Path(filename).stem
                ext = pathlib.Path(filename).suffix
                counter = 1
                while os.path.exists(dest_path):
                    dest_path = os.path.join(
                        dest_dir, f"{stem} ({counter}){ext}")
                    counter += 1

            total = os.path.getsize(source_path)

            if progress_cb and total > 1024 * 1024:
                copied = 0
                chunk_size = 1024 * 1024
                with open(source_path, 'rb') as src:
                    with open(dest_path, 'wb') as dst:
                        while True:
                            chunk = src.read(chunk_size)
                            if not chunk:
                                break
                            dst.write(chunk)
                            copied += len(chunk)
                            progress_cb(copied, total)
            else:
                shutil.copy2(source_path, dest_path)
                if progress_cb:
                    progress_cb(total, total)

            return {
                "success": True,
                "message": f"Sent {filename} to \\\\{ip}\\{clean_share}",
                "dest_path": dest_path,
            }

        except PermissionError:
            return {"success": False,
                    "message": f"Permission denied on {dest_dir}",
                    "dest_path": ""}
        except OSError as e:
            return {"success": False,
                    "message": f"OS error: {e}",
                    "dest_path": ""}
        except Exception as e:
            return {"success": False,
                    "message": f"Error: {e}",
                    "dest_path": ""}

    @staticmethod
    def send_multiple(files: list[str], ip: str, share: str,
                      dest_folder: str = "",
                      progress_cb=None,
                      file_done_cb=None) -> list[dict]:
        """Send multiple files. Returns a list of result dicts."""
        results = []
        for i, fpath in enumerate(files):
            result = FileTransfer.send_file(
                fpath, ip, share, dest_folder, progress_cb)
            results.append(result)
            if file_done_cb:
                file_done_cb(i + 1, len(files), result)
        return results
