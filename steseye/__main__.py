"""Entry point for ``python -m steseye``."""

import sys
from tkinter import messagebox

from .app import StesEyeApp


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch():
    import ctypes
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        " ".join(f'"{a}"' for a in sys.argv), None, 1)


def main():
    if not is_admin():
        ans = messagebox.askyesno(
            "StesEye",
            "Network scanning requires Administrator privileges.\n"
            "Restart as Administrator?")
        if ans:
            relaunch()
        sys.exit(0)

    app = StesEyeApp()
    app.mainloop()


if __name__ == "__main__":
    main()
