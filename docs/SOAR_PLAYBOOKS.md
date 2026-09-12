# Playbook Engine & Builder Specification

## Playbook Structure

Each playbook defines an automated orchestration rule:

- `playbook_id`: Unique identifier (`PB-SOAR-XXX`).
- `version`: Immutable version integer.
- `trigger_type`: Event trigger (`ALERT_CREATED`, `ALERT_UPDATED`, `SIGMA_MATCH`, `IOC_MATCH`, `UEBA_ANOMALY`, `ENTITY_RISK_THRESHOLD`, `MANUAL`).
- `approval_policy`: Policy (`AUTOMATIC`, `ANALYST_APPROVAL`, `ADMIN_APPROVAL`, `MANUAL_ONLY`).
- `steps`: Ordered step configurations.

---

## Step Execution Logic

Each step specifies:
- `step_id`: Identifier.
- `action`: Action type (`BLOCK_IP`, `KILL_PROCESS`, etc.).
- `conditions`: Deterministic field match rules.
- `continue_on_failure`: Boolean flag.

Loop Protection: Playbook executions with more than `NETWATCH_SOAR_MAX_PLAYBOOK_DEPTH` (default 20) steps are rejected to prevent infinite execution loops.
