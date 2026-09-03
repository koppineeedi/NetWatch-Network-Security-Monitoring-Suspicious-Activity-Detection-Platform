# NETWATCH — Real Telemetry Collection & Attribution Guidelines

## Telemetry Sources
1. `LOCAL_NETWORK`: Real system socket connections observed via `psutil`.
2. `LOG_FILE`: Uploaded raw log files (.log, .json, .csv).
3. `SURICATA`: Suricata EVE JSON alert telemetry (Future integration).
4. `ZEEK`: Zeek connection logs (Future integration).

## Collection Rules
- Telemetry collectors MUST default to `STOPPED` state.
- Collectors MUST NEVER scan external networks or generate probe/attack traffic.
- Every event MUST contain an explicit `source` attribute.
- Missing values MUST default to `null` / `None` and NEVER be fabricated.
