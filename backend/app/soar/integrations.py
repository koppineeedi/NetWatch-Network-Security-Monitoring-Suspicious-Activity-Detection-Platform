import os
import sys
import platform
import subprocess
import psutil
import requests
from typing import Dict, Any, Tuple
from app.soar.drivers.host_isolation import get_host_isolation_driver
from app.soar.drivers.iam import get_iam_driver

PROTECTED_IPS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}
PROTECTED_PROCESS_NAMES = {
    "system", "system idle process", "init", "systemd", "svchost.exe",
    "lsass.exe", "csrss.exe", "smss.exe", "services.exe", "explorer.exe",
    "python", "python.exe", "uvicorn", "uvicorn.exe"
}

class LocalFirewallIntegration:
    @staticmethod
    def block_ip(target_ip: str) -> Tuple[str, Dict[str, Any]]:
        """
        Blocks target IP on local OS firewall if privileges and platform tools exist.
        """
        if not target_ip or target_ip in PROTECTED_IPS:
            return "FAILED", {"error": f"Target IP '{target_ip}' is protected or invalid."}

        system_os = platform.system()

        if system_os == "Windows":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                is_admin = False

            if not is_admin:
                return "NOT_CONFIGURED", {
                    "error": "Windows Firewall manipulation requires Administrator privileges.",
                    "platform": system_os,
                    "target": target_ip
                }

            rule_name = f"NetWatch_Block_{target_ip.replace('.', '_')}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", f"remoteip={target_ip}"
            ]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    return "SUCCESS", {"rule_name": rule_name, "output": res.stdout.strip()}
                else:
                    return "FAILED", {"error": res.stderr.strip(), "returncode": res.returncode}
            except Exception as e:
                return "FAILED", {"error": str(e)}

        elif system_os == "Linux":
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                return "NOT_CONFIGURED", {
                    "error": "Linux Firewall manipulation requires root privileges.",
                    "platform": system_os,
                    "target": target_ip
                }

            cmd = ["iptables", "-A", "INPUT", "-s", target_ip, "-j", "DROP"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    return "SUCCESS", {"target": target_ip, "command": " ".join(cmd)}
                else:
                    return "FAILED", {"error": res.stderr.strip()}
            except Exception as e:
                return "NOT_CONFIGURED", {"error": f"iptables execution failed: {str(e)}"}

        return "NOT_CONFIGURED", {"error": f"Firewall control not supported on OS '{system_os}'."}

    @staticmethod
    def unblock_ip(target_ip: str) -> Tuple[str, Dict[str, Any]]:
        """
        Unblocks target IP on local OS firewall.
        """
        if not target_ip:
            return "FAILED", {"error": "Target IP required."}

        system_os = platform.system()

        if system_os == "Windows":
            rule_name = f"NetWatch_Block_{target_ip.replace('.', '_')}"
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    return "SUCCESS", {"rule_name": rule_name, "output": res.stdout.strip()}
                else:
                    return "FAILED", {"error": res.stderr.strip()}
            except Exception as e:
                return "FAILED", {"error": str(e)}

        elif system_os == "Linux":
            cmd = ["iptables", "-D", "INPUT", "-s", target_ip, "-j", "DROP"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    return "SUCCESS", {"target": target_ip}
                else:
                    return "FAILED", {"error": res.stderr.strip()}
            except Exception as e:
                return "FAILED", {"error": str(e)}

        return "NOT_CONFIGURED", {"error": f"Firewall control not supported on OS '{system_os}'."}

class HostIsolationIntegration:
    @staticmethod
    def isolate_host(target_host: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        """
        Delegates to configured pluggable Host Isolation Driver.
        """
        driver = get_host_isolation_driver()
        return driver.isolate_host(target_host, parameters or {})

    @staticmethod
    def restore_host(target_host: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        """
        Delegates to configured pluggable Host Isolation Driver.
        """
        driver = get_host_isolation_driver()
        return driver.restore_host(target_host, parameters or {})

    @staticmethod
    def get_status() -> Dict[str, Any]:
        driver = get_host_isolation_driver()
        return driver.get_status()

class ProcessControlIntegration:
    @staticmethod
    def kill_process(target_pid_str: str) -> Tuple[str, Dict[str, Any]]:
        """
        Safely terminates a specific process PID with strict protected PID safeguards.
        """
        try:
            pid = int(target_pid_str)
        except (ValueError, TypeError):
            return "FAILED", {"error": f"Invalid PID '{target_pid_str}'. PID must be an integer."}

        if not psutil.pid_exists(pid):
            return "FAILED", {"error": f"Process PID {pid} does not exist or has already terminated."}

        current_pid = os.getpid()
        if pid in (0, 1, 4, current_pid):
            return "FAILED", {"error": f"Cannot terminate protected system or NetWatch PID {pid}."}

        try:
            proc = psutil.Process(pid)
            proc_name = proc.name().lower()
            if proc_name in PROTECTED_PROCESS_NAMES:
                return "FAILED", {"error": f"Cannot terminate protected system process '{proc.name()}' (PID {pid})."}

            proc.terminate()
            proc.wait(timeout=3)
            return "SUCCESS", {"pid": pid, "process_name": proc.name(), "action": "TERMINATED"}
        except psutil.TimeoutExpired:
            try:
                proc.kill()
                return "SUCCESS", {"pid": pid, "action": "KILLED"}
            except Exception as e:
                return "FAILED", {"error": str(e)}
        except Exception as e:
            return "FAILED", {"error": str(e)}

class IdentityProviderIntegration:
    @staticmethod
    def disable_account(username: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        """
        Delegates to configured pluggable IAM Driver.
        """
        driver = get_iam_driver()
        return driver.disable_account(username, parameters or {})

    @staticmethod
    def enable_account(username: str, parameters: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        """
        Delegates to configured pluggable IAM Driver.
        """
        driver = get_iam_driver()
        return driver.enable_account(username, parameters or {})

    @staticmethod
    def get_status() -> Dict[str, Any]:
        driver = get_iam_driver()
        return driver.get_status()

class NotificationIntegration:
    @staticmethod
    def notify_analyst(target_channel: str, message: str, details: Dict[str, Any] = None) -> Tuple[str, Dict[str, Any]]:
        webhook_url = os.getenv("NETWATCH_SOAR_WEBHOOK_URL") or (details.get("webhook_url") if details else None)
        if webhook_url:
            try:
                res = requests.post(webhook_url, json={"channel": target_channel, "message": message, "details": details}, timeout=5)
                if res.status_code in (200, 201, 202, 204):
                    return "SUCCESS", {"channel": target_channel, "status_code": res.status_code}
                else:
                    return "FAILED", {"error": f"Webhook returned status code {res.status_code}"}
            except Exception as e:
                return "FAILED", {"error": str(e)}

        return "SUCCESS", {
            "channel": target_channel or "SOC_PANEL",
            "message": message,
            "delivery": "INTERNAL_SOC_QUEUE"
        }
