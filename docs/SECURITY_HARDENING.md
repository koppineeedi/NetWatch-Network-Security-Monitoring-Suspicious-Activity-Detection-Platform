# NetWatch Security Hardening Specification

**Document Version:** 1.0.0  
**Target Environment:** High-Security Enterprise SOC Operations  
**Compliance Baseline:** OWASP Top 10 Security Architecture  

---

## 1. Authentication & RBAC Hardening

### Password Security & Hashing
- Password hashes use **salted `bcrypt` / `passlib`** algorithms. Raw passwords are never stored in database tables or logs.
- Enforces minimum 8-character password length with upper, lower, digit, and special character checks.

### OAuth2 Bearer Token & JWT Security
- JWT access tokens signed with `HS256` HMAC algorithm using `NETWATCH_SECRET_KEY`.
- Token payload contains user ID, role, and expiration timestamp (`exp`). Default expiration set to 24 hours (`1440` minutes).

### Role-Based Access Control (RBAC) Matrix

| Endpoint Group | Role Required | Access Scope |
| :--- | :--- | :--- |
| `GET /api/telemetry`, `GET /api/alerts`, `GET /api/statistics` | `VIEWER`, `ANALYST`, `ADMIN` | Read-only dashboards and metrics |
| `POST /api/investigations`, `POST /api/iocs` | `ANALYST`, `ADMIN` | Alert triage, case notes, IOC entry |
| `POST /api/soar/playbooks`, `POST /api/soar/approvals/*/decide` | `ANALYST`, `ADMIN` | Playbook creation, action approval |
| `POST /api/users`, `DELETE /api/users/*`, `POST /api/connectors` | `ADMIN` | User management, connector setup |

### Active Administrator Self-Protection
- The system enforces a **final active administrator protection rule**: An admin user cannot delete or demote their own account if they are the sole remaining active `ADMIN` in the database.

---

## 2. Input Validation & Subprocess Safety

### Command Injection Prevention
- **Zero `shell=True` Policy:** All operating system command executions (`netsh`, `iptables`, `psutil`) pass parameters as distinct list arrays (e.g. `["netsh", "advfirewall", "firewall", "add", "rule", ...]`).
- Arguments are explicitly typed and validated (e.g., target IPs checked against IP regex or `ipaddress` library; process PIDs validated as integers).

### Path Traversal & Upload Safeguards
- File ingestion endpoint (`POST /api/logs/upload`) resolves input file paths with `os.path.abspath()` and verifies target files remain inside designated sandbox storage directories.
- Enforces strict 10 MB maximum file size upload limits (`NETWATCH_SIGMA_MAX_RULE_SIZE_MB=1`).

---

## 3. Secret Management & Data Redaction

### Secret Storage Guidelines
- Production secrets (`NETWATCH_SECRET_KEY`, `ABUSEIPDB_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, `GCP_CREDENTIALS_JSON`) are read strictly from environment variables.
- Hardcoded passwords, API keys, or JWT secrets are strictly forbidden in source repositories.

### API & Audit Log Redaction
- Connector configuration endpoints automatically mask secret fields (`aws_secret_access_key` → `"********"`, `client_secret` → `"********"`).
- Audit log service (`audit_service.py`) automatically strips sensitive payload attributes before persisting audit events to `audit_logs`.

---

## 4. Network & CORS Hardening

### CORS Origin Restrictions
- In production, `NETWATCH_CORS_ORIGINS` must specify explicit domain origins (e.g. `https://soc.netwatch.local`).
- Wildcard `*` allow-origins with `allow_credentials=True` is prohibited by middleware logic.

### WebSocket Authentication & Timeout
- WebSockets (`ws://<host>:<port>/ws/events`) require valid JWT bearer tokens passed via query string or connection header.
- Implements 30-second ping/pong heartbeat and disconnects stale or unauthenticated clients automatically.

---

## 5. Recommended Production Security Headers (Nginx / Gateway)

Configure Nginx or API Gateway to inject standard security headers:
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss:;" always;
```
