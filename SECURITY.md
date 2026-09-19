# NetWatch — Security & Responsible Use Policy

## Authorized Use & Boundaries
NetWatch is a defensive cybersecurity monitoring, SIEM, UEBA, and threat hunting platform designed exclusively for authorized defensive operations, security research, and SOC training in controlled environments.

### Prohibited Actions
- NetWatch must **NOT** be used to execute unauthorized credential attacks, password spraying, or brute-force against external systems.
- NetWatch must **NOT** deploy malware, perform denial-of-service, or execute active exploits against unauthorized targets.
- All response actions must operate within authorized network administrative boundaries.

---

## Security Model & Authentication
- **Authentication**: JWT Bearer Tokens with `HS256` signature verification.
- **Passwords**: Hashed with salted `bcrypt` algorithms.
- **Role-Based Access Control**: Enforced across all endpoints (`ADMIN`, `ANALYST`, `VIEWER`).
- **Audit Logging**: All security-relevant actions are recorded in `audit_logs` without storing sensitive tokens or passwords.
