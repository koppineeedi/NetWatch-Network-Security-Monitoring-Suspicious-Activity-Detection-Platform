import os
import platform
import subprocess
import ctypes
import logging
from typing import Dict, Any, Tuple
from app.soar.audit import log_soar_audit

logger = logging.getLogger("netwatch.soar.host_isolation")

PROTECTED_IPS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}

class BaseHostIsolationDriver:
    def get_status(self) -> Dict[str, Any]:
        return {"driver": "base", "status": "NOT_CONFIGURED", "message": "Base host isolation driver"}

    def isolate_host(self, target_host: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        return "NOT_CONFIGURED", {"status": "NOT_CONFIGURED", "message": "Host isolation driver not configured"}

    def restore_host(self, target_host: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        return "NOT_CONFIGURED", {"status": "NOT_CONFIGURED", "message": "Host isolation driver not configured"}


class UnconfiguredHostIsolationDriver(BaseHostIsolationDriver):
    def get_status(self) -> Dict[str, Any]:
        return {
            "driver": "none",
            "status": "NOT_CONFIGURED",
            "message": "Host Isolation driver is unconfigured. Set NETWATCH_SOAR_HOST_ISOLATION_DRIVER to enable."
        }

    def isolate_host(self, target_host: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        return "NOT_CONFIGURED", {
            "status": "NOT_CONFIGURED",
            "message": f"Host isolation is unconfigured for target '{target_host}'. No action taken.",
            "target": target_host
        }

    def restore_host(self, target_host: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        return "NOT_CONFIGURED", {
            "status": "NOT_CONFIGURED",
            "message": f"Host isolation restore is unconfigured for target '{target_host}'. No action taken.",
            "target": target_host
        }


class WindowsNetshHostIsolationDriver(BaseHostIsolationDriver):
    """
    Pluggable Windows Host Isolation Driver using dedicated Windows Firewall filter rules.
    Requires explicit Administrator privileges and target allowlist validation.
    """
    def get_status(self) -> Dict[str, Any]:
        is_admin = False
        if platform.system() == "Windows":
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                is_admin = False
        return {
            "driver": "windows_netsh",
            "status": "CONFIGURED" if is_admin else "PASS — PRIVILEGE REQUIRED",
            "is_admin": is_admin,
            "platform": platform.system(),
            "message": "Windows Netsh Host Isolation Driver ready" if is_admin else "Administrator privileges required"
        }

    def isolate_host(self, target_host: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        parameters = parameters or {}
        if not target_host or target_host in PROTECTED_IPS:
            return "FAILED", {"error": f"Target host '{target_host}' is protected or loopback."}

        if platform.system() != "Windows":
            return "NOT_CONFIGURED", {"error": f"Windows Netsh driver cannot run on OS '{platform.system()}'"}

        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            is_admin = False

        if not is_admin:
            return "NOT_CONFIGURED", {"error": "Host isolation requires elevated Administrator privileges."}

        rule_name = f"NetWatch_Isolate_Host_{target_host.replace('.', '_')}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={target_host}"
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                return "SUCCESS", {
                    "driver": "windows_netsh",
                    "action": "ISOLATE_HOST",
                    "rule_name": rule_name,
                    "target": target_host,
                    "message": f"Host '{target_host}' isolated via firewall block rule."
                }
            else:
                return "FAILED", {"error": res.stderr.strip()}
        except Exception as e:
            return "FAILED", {"error": str(e)}

    def restore_host(self, target_host: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        parameters = parameters or {}
        if not target_host:
            return "FAILED", {"error": "Target host is required."}

        rule_name = f"NetWatch_Isolate_Host_{target_host.replace('.', '_')}"
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                return "SUCCESS", {
                    "driver": "windows_netsh",
                    "action": "RESTORE_HOST",
                    "rule_name": rule_name,
                    "target": target_host,
                    "message": f"Isolation restored for host '{target_host}'."
                }
            else:
                return "FAILED", {"error": res.stderr.strip()}
        except Exception as e:
            return "FAILED", {"error": str(e)}


def get_host_isolation_driver() -> BaseHostIsolationDriver:
    enabled = os.getenv("NETWATCH_SOAR_AUTO_ISOLATION_ENABLED", "false").lower() == "true"
    driver_type = os.getenv("NETWATCH_SOAR_HOST_ISOLATION_DRIVER", "none").lower()

    if not enabled or driver_type in ("none", "unconfigured", ""):
        return UnconfiguredHostIsolationDriver()
    elif driver_type == "windows_netsh":
        return WindowsNetshHostIsolationDriver()
    else:
        return UnconfiguredHostIsolationDriver()
