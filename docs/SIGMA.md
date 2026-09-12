# NetWatch Sigma Rule Engine Subsystem

## Overview

NetWatch Enterprise Enhancement Cycle 3 introduces a production-grade **Sigma Rule Engine** and **Detection Sandbox**. The engine evaluates industry-standard Sigma YAML detection rules against real telemetry (psutil local network, remote UDP Syslog, and cloud audit logs).

All live Sigma evaluations and Sandbox tests operate strictly on real telemetry and ingested logs, strictly adhering to NetWatch's Zero Fake Production Data contract.

## Key Features

1. **Safe PyYAML Parser**: Enforces `yaml.safe_load` and payload size limits (`NETWATCH_SIGMA_MAX_RULE_SIZE_MB`, default 1MB).
2. **Explicit Field Mapping**: Maps Sigma attributes (`src_ip`, `dst_ip`, `Image`, `User`, `EventID`, etc.) to NetWatch `NetworkEvent` fields. Returns `UNSUPPORTED_FIELD` for missing fields.
3. **Deterministic Evaluator**: Evaluates selections, logical conditions (`and`, `or`, `not`, `1 of selection*`, `all of selection*`), wildcards (`*`, `?`), and modifiers (`|contains`, `|startswith`, `|endswith`, `|all`).
4. **Rule Lifecycle & Versioning**: Manages states (`DRAFT`, `VALIDATED`, `ENABLED`, `DISABLED`, `ERROR`), rule versions (`sigma_rule_versions`), and audit logging.
5. **Detection Sandbox**: Tests rules safely against real historical data without creating live production alerts.
6. **Enrichment & SOC Workflow**: Automatically enriches matches with Threat Intelligence (IOCs), UEBA (entity risk scores), and MITRE ATT&CK techniques, triggering SOC Alerts and WebSocket streams (`SIGMA_RULE_MATCHED`).

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `NETWATCH_SIGMA_ENABLED` | `true` | Enables/disables the Sigma engine subsystem |
| `NETWATCH_SIGMA_SANDBOX_MAX_DAYS` | `7` | Maximum historical lookback for Sandbox queries |
| `NETWATCH_SIGMA_MAX_RULE_SIZE_MB` | `1` | Maximum file size for imported Sigma YAML rules |
| `NETWATCH_SIGMA_MAX_CONCURRENT_TESTS` | `2` | Bounded sandbox test limit |
| `NETWATCH_SIGMA_REFRESH_SECONDS` | `60` | Periodic rule update check interval |
| `NETWATCH_SIGMA_MAX_MATCHES` | `10000` | Maximum result limit for sandbox evaluation |
