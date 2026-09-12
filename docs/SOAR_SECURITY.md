# SOAR Security Controls & Safeguards

## Allowlists & Protection Rules

1. **IP Allowlist**: Localhost (`127.0.0.1`, `::1`), `0.0.0.0`, and default gateway IPs cannot be blocked by `BLOCK_IP` or firewall actions.
2. **Process Safeguards**: Critical OS processes (`init`, `svchost.exe`, `lsass.exe`, `systemd`, `system`, `python.exe`, `uvicorn.exe`) and NetWatch server PID (`os.getpid()`) cannot be terminated by `KILL_PROCESS`.
3. **No Arbitrary Code Execution**: Playbook conditions are evaluated using safe deterministic comparisons. Arbitrary code execution is strictly prohibited.
4. **Command Injection Prevention**: Platform commands utilize array-based parameter invocation (`subprocess.run(["cmd", "arg"])`) avoiding shell interpolation.
5. **Credential Sanitization**: Passwords, API keys, bearer tokens, and secrets are automatically redacted from `AuditLog` records.
