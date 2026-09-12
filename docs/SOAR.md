# NetWatch Security Orchestration, Automation, and Response (SOAR)

## Overview

NetWatch SOAR provides production-grade security orchestration, playbook execution, real OS/system response integration, authorization workflows, dry-run simulation, and rollback controls for security incidents.

---

## Architecture Pipeline

```
Real Telemetry / Logs / Ingestion
              ↓
   Detection & Analytics Engine (Core / Cycle 1 / Cycle 2 / Cycle 3)
              ↓
          SOC Alert
              ↓
    SOAR Trigger Evaluator
              ↓
      Playbook Engine
              ↓
  Approval Policy Enforcement
              ↓
   Action Executor & Integrations
              ↓
   Real OS Execution / Response
              ↓
Audit Logging & WebSocket Timeline
```

---

## Key Features

1. **Deterministic Playbook Engine**: Versioned playbooks executed over ordered steps with condition evaluation, retries, timeouts, and depth loop limits.
2. **Real System Integrations**: Native platform firewall interfaces (Windows `netsh`, Linux `iptables`), process control (`psutil` with protected process safeguards), and notification channels. Zero fake execution.
3. **Safe Execution Policies**: Destructive actions (`BLOCK_IP`, `ISOLATE_HOST`, `KILL_PROCESS`, `DISABLE_ACCOUNT`) require explicit `ANALYST` or `ADMIN` approval by default.
4. **Dry-Run Mode**: Full simulation capability (`NETWATCH_SOAR_DRY_RUN=true` or `--dry-run`) producing complete execution records without modifying production OS state.
5. **Rollback Engine**: Inverse operation support (`BLOCK_IP` → `UNBLOCK_IP`, `ISOLATE_HOST` → `RESTORE_HOST`) with audit log tracking.
