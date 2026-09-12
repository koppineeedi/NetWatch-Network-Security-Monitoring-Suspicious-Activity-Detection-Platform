# SOAR Operations & Configuration Guide

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `NETWATCH_SOAR_ENABLED` | Enables SOAR Subsystem | `true` |
| `NETWATCH_SOAR_DRY_RUN` | Global Dry-Run Safety Toggle | `true` |
| `NETWATCH_SOAR_MAX_ACTIONS_PER_MINUTE` | Rate Limit Window Cap | `20` |
| `NETWATCH_SOAR_MAX_CONCURRENT_ACTIONS` | Max Parallel Workers | `4` |
| `NETWATCH_SOAR_APPROVAL_TIMEOUT_MINUTES` | Authorization Expiry Timeout | `30` |
| `NETWATCH_SOAR_MAX_PLAYBOOK_DEPTH` | Max Playbook Step Depth | `20` |
| `NETWATCH_SOAR_AUTO_BLOCK_ENABLED` | Automated Unapproved IP Blocking | `false` |
| `NETWATCH_SOAR_AUTO_ISOLATION_ENABLED` | Automated Host Isolation | `false` |
