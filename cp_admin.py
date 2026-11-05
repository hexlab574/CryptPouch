# -*- coding: utf-8 -*-
"""CryptPouch admin helpers: dependency installation and elevated
(administrator) operations. Elevation is only attempted after explicit
user consent, and falls back to a printable command otherwise."""

import cp_shared
import cp_utils
import os
import subprocess
import sys
import time
from typing import Optional, List, Tuple, Dict, Any, Union


def is_admin() -> bool:
    """Return True when the current process runs with administrator rights.
    No-op check on non-Windows platforms (always False there is not useful,
    so on POSIX we return False and elevation falls back to a sudo hint)."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    return False


def _elevate_pip_install(packages: List[str]) -> bool:
    """Re-run `pip install` with a UAC elevation prompt (Windows only).
    The user already consented before this is called. Returns True when the
    elevated process was started; completion is reported by the user."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        # ShellExecuteW with "runas" triggers the UAC consent dialog.
        res = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            "-m pip install " + " ".join(packages), None, 1)
        return res > 32  # ShellExecuteW returns an error code <= 32 on failure
    except Exception:
        return False


def _restart_args() -> List[str]:
    """sys.argv with password-bearing options stripped so a restart never
    re-exposes a password supplied on the command line."""
    argv = list(sys.argv)
    out: List[str] = []
    skip_next = False
    for i, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        low = arg.lower()
        if low in ("-p", "--password"):
            # the next argument is the password value
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                skip_next = True
            continue
        if low.startswith("--password="):
            continue
        out.append(arg)
    return out


def install_packages(packages: List[str], i18n: cp_shared.I18n) -> bool:
    printer = cp_shared.Printer(i18n)

    global_cmd = "pip install " + " ".join(packages)
    cn_cmd = "pip install " + " ".join(packages) + " -i https://pypi.tuna.tsinghua.edu.cn/simple"

    printer.info(i18n.t("install_cmd_global") + " " + global_cmd)
    printer.info(i18n.t("install_cmd_cn") + " " + cn_cmd)
    print()

    confirm = cp_utils._safe_input(i18n.t("ask_install")).strip().lower()
    if confirm != "y":
        printer.warn(i18n.t("install_cancel"))
        return False

    printer.info(i18n.t("installing"))
    print()

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install"] + packages,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            printer.ok(i18n.t("install_success"))
            time.sleep(1.5)
            # Restart as a subprocess instead of os.execv so cleanup logic is not
            # bypassed; password options are stripped from the restarted argv.
            subprocess.Popen([sys.executable] + _restart_args())
            sys.exit(0)
            return True
        else:
            printer.fail(i18n.t("install_fail"))
            print(result.stderr)
            # Permission failure -> offer an elevated retry, but ONLY with the
            # user's explicit consent (a UAC prompt appears when they agree).
            low_err = (result.stderr or "").lower()
            permission_issue = any(k in low_err for k in (
                "permission denied", "access is denied", "permissionerror",
                "not permitted", "is not writable", "read-only file system"))
            if not permission_issue:
                return False
            printer.warn(i18n.t("install_denied"))
            agree = cp_utils._safe_input(i18n.t("ask_elevate")).strip().lower()
            if agree != "y":
                printer.warn(i18n.t("elevate_cancel"))
                return False
            printer.info(i18n.t("elevate_note"))
            ok = _elevate_pip_install(packages)
            if ok:
                printer.ok(i18n.t("elevate_ok"))
                # The elevated pip runs in its own process, so completion is
                # confirmed by the user before the app restarts.
                cp_utils._safe_input(i18n.t("elevate_continue"))
                subprocess.Popen([sys.executable] + _restart_args())
                sys.exit(0)
            printer.fail(i18n.t("elevate_fail", err="elevation returned no success"))
            return False
    except Exception as e:
        printer.fail(i18n.t("install_fail"))
        print(str(e))
        return False
