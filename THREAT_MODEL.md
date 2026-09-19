# NetWatch — Threat Model & Security Risk Assessment

## Executive Summary
This document provides a threat model for the NetWatch platform according to STRIDE and SOC security guidelines.

---

## 1. Threat Inventory & Risk Matrix

| Threat Category | Potential Risk | Impact | Mitigation in NetWatch |
|---|---|---|---|
| **Spoofing** | Telemetry forgery or fake event injection | High | API routes require OAuth2 JWT authentication; WebSocket connections enforce token validation. |
| **Tampering** | Modifying audit logs or detection rules | High | Immutable audit logging service; rule modifications require `ADMIN` role with RBAC enforcement. |
| **Repudiation** | Analyst denying an executed SOAR action | Medium | Tamper-evident `audit_logs` tracking user ID, action, timestamp, object, and result. |
| **Information Disclosure** | Secret / API key leakage in reports or logs | Critical | Secret redaction filters; API keys hidden from client responses; zero logging of tokens/passwords. |
| **Denial of Service** | Resource exhaustion via large log uploads | Medium | Strict 10 MB upload file size limits; streaming log parser; backend pagination on queries. |
| **Elevation of Privilege** | Analyst escalating privileges to Admin | High | Role-based authorization (`require_role("ADMIN")`) enforced at the FastAPI route middleware layer. |

---

## 2. Defensive Boundaries & Safety Controls
1. **SOAR Active Response Safety**: All response actions (e.g. host isolation, IP block) require explicit analyst approval or operate in `DRY_RUN` mode.
2. **Path Traversal Prevention**: File log ingestion validates absolute paths and restricts reading to allowed target directories.
3. **Database Integrity**: Primary keys, foreign key constraints, and additive migrations prevent data corruption or table dropping.
