# NETWATCH — Authentication & Role-Based Access Control (RBAC) Documentation

## Overview
Phase 6 introduces database-backed authentication and granular Role-Based Access Control (RBAC) to NetWatch. All protected endpoints require valid JWT authentication headers (`Authorization: Bearer <token>`), and mutating endpoints strictly enforce role permissions.

## Roles & Permissions Matrix
| Role | Dashboard & Telemetry | Events & Logs | Detections & Alerts | Investigations | Detection Rules | User Management |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`ADMIN`** | Read / Start / Stop | Read / Upload | Read / Evaluate / Triage | Read / Create / Resolve | Read / Create / Edit | Full Access |
| **`ANALYST`** | Read / Start / Stop | Read / Upload | Read / Evaluate / Triage | Read / Create / Resolve | Read Only | Forbidden (403) |
| **`VIEWER`** | Read Only | Read Only | Read Only | Read Only | Read Only | Forbidden (403) |

- **`ADMIN`**: Complete administrative control including User Management (`GET /api/users`, `POST /api/users`, `PATCH /api/users/{id}/role`, `PATCH /api/users/{id}/status`), Detection Rule creation/editing, and full operational triage.
- **`ANALYST`**: Full SOC operational triage (Alert triage, Investigation case creation, Analyst Notes, Resolution, Telemetry start/stop, Log upload, Detection evaluation). Cannot manage users.
- **`VIEWER`**: Read-only visibility across all SOC pages. Any attempt to invoke mutating API endpoints returns HTTP 403 Forbidden.

## Security Controls
- **Password Hashing**: Modern Argon2id / bcrypt via `passlib.context.CryptContext`. Plaintext passwords are never stored, logged, or returned in API responses.
- **JWT Authentication**: Signed JWT bearer tokens with configurable expiration (`NETWATCH_ACCESS_TOKEN_EXPIRE_MINUTES`). Secrets configured via `NETWATCH_SECRET_KEY`.
- **Final Admin Protection**: Backend logic prevents demoting or disabling the final active `ADMIN` account to prevent locking down system administration.
- **Audit Logging**: All authentication events (`LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `PASSWORD_CHANGED`, `USER_CREATED`, `USER_ROLE_CHANGED`, `USER_ENABLED`, `USER_DISABLED`, `UNAUTHORIZED_ACCESS_ATTEMPT`) are recorded in the SQLite `audit_logs` table without recording passwords or tokens.

## Admin Bootstrap Command
Initial admin user creation is explicitly invoked and does not run automatically on server startup:
```bash
python -m app.scripts.create_admin
```
Environment variables (optional):
- `NETWATCH_ADMIN_USER` (default: `admin`)
- `NETWATCH_ADMIN_EMAIL` (default: `admin@netwatch.local`)
- `NETWATCH_ADMIN_PASSWORD` (default: `Admin123!`)

## API Endpoints
- `POST /api/auth/login`: Authenticate username/email & password. Returns JWT token and safe user details.
- `POST /api/auth/logout`: Log out event recording.
- `GET /api/auth/me`: Current user profile.
- `POST /api/auth/change-password`: Authenticated password change.
- `GET /api/users`: List users (ADMIN only).
- `POST /api/users`: Provision user (ADMIN only).
- `PATCH /api/users/{id}/role`: Update role (ADMIN only).
- `PATCH /api/users/{id}/status`: Enable/disable user (ADMIN only).
