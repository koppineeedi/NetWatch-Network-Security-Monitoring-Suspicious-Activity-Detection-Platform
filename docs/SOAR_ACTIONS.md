# SOAR Action Framework & Real Integrations

## Action Status Lifecycle

Actions return one of the following explicit status codes:

- `PENDING_APPROVAL`: Action created and awaiting authorization.
- `APPROVED`: Action approved by authorized user.
- `RUNNING`: Action currently executing.
- `SUCCESS`: Action executed successfully by real OS integration.
- `FAILED`: Action execution failed (error message recorded).
- `DENIED`: Action request denied by analyst/admin.
- `CANCELLED`: Action cancelled due to duplicate idempotency key.
- `DRY_RUN`: Action simulated in dry-run mode.
- `NOT_CONFIGURED`: Action integration is unconfigured or unsupported on host OS.

---

## Action Types

1. `BLOCK_IP` / `UNBLOCK_IP`: Local OS firewall rule via `netsh` (Windows) or `iptables` (Linux).
2. `ISOLATE_HOST` / `RESTORE_HOST`: Host network isolation interface.
3. `KILL_PROCESS`: Process termination via `psutil` with protected process safeguards.
4. `DISABLE_ACCOUNT` / `ENABLE_ACCOUNT`: Identity provider integration interface.
5. `NOTIFY_ANALYST`: Webhook and internal SOC notification queue.
