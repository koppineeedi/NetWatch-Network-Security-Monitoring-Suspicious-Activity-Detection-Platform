# NETWATCH — Security Policy & Authorization Controls

## Defensive Security Scope
NetWatch is an educational defensive security monitoring tool. It operates exclusively in passive monitoring mode on authorized local network adapters and explicitly provided log files.

## Prohibited Capabilities
The codebase explicitly forbids:
- Malware or exploit payloads
- Automated brute-force or credential spray tools
- Network vulnerability scanning / port scanning tools targeting unauthorized hosts
- Unsolicited packet injection or active disruption

## Role-Based Access Control (RBAC)
NetWatch defines 3 analyst permission tiers:
1. **SOC Analyst**: Triage alerts, view events, post investigation notes, update alert status.
2. **SOC Manager**: Manage detection rules, generate reports, oversee investigations.
3. **SecOps Administrator**: Full system configuration, user role management.
