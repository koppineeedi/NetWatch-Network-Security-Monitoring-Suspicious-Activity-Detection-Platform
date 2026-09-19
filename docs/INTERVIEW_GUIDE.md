# NetWatch — Technical Interview & Architecture Cheat Sheet

This guide provides precise, technically accurate answers to 25 common architectural, detection, and software engineering questions about **NetWatch**. All answers are grounded directly in the NetWatch codebase.

---

## Technical Questions & Detailed Answers

### 1. What problem does NetWatch solve?
**Answer:** NetWatch bridges the gap between passive network security monitoring, SIEM log correlation, UEBA behavioral anomaly detection, and automated incident response (SOAR). It provides SOC analysts with a unified, end-to-end workflow—from telemetry ingestion and detection explainability to threat hunting, forensic evidence management, MITRE ATT&CK mapping, and approval-gated response actions.

---

### 2. Walk me through the high-level architecture of NetWatch.
**Answer:** NetWatch uses a decoupled client-server architecture:
- **Backend:** Built with Python (FastAPI), SQLAlchemy ORM, and Pydantic validation schemas.
- **Database:** Relational persistence (SQLite for development/testing, PostgreSQL for production) storing events, alerts, investigations, rules, baselines, and audit records.
- **Frontend:** Single-page React application built with TypeScript, Vite, and Tailwind CSS.
- **Real-Time Pipeline:** Authenticated WebSocket pipeline (`/ws/events`) with 30s heartbeats broadcasting events, detections, and SOAR execution updates live to connected frontend clients.

---

### 3. What happens when raw telemetry enters the system?
**Answer:**
1. Telemetry arrives via passive local socket collection (`psutil`), log file parsing (`.log`, `.json`, `.csv`), remote Syslog listener (UDP/TCP Port 514), or cloud connector endpoints.
2. The `NetworkEvent` normalizer parses raw payloads into a standardized schema containing timestamps, source/destination IPs/ports, protocol, action, user, process name, command line, payload size, and raw message bytes.
3. The event is persisted to the database and simultaneously passed through the multi-stage evaluation pipeline (Detection Engine, IOC Matcher, UEBA baseline, and Sigma Evaluator).

---

### 4. How does the core Detection Engine evaluate events?
**Answer:** The detection engine evaluates normalized events against configurable sliding correlation time windows (e.g., 60 seconds). It checks event velocity, port scan patterns, brute-force failure thresholds, and suspicious protocol combinations. When thresholds are breached, an evidence-backed `Alert` record is generated with a calculated risk score (0–100) and mapped MITRE ATT&CK metadata.

---

### 5. How does the Sigma Rule Engine work in NetWatch?
**Answer:** NetWatch includes a PyYAML-backed Sigma rule importer and evaluator (`app/sigma/`). It parses standard Sigma YAML specifications, validates syntax (`VALID`, `UNSUPPORTED`, `INVALID`), maps standard Sigma fields (`src_ip`, `dst_ip`, `CommandLine`, `Image`, `EventID`) to NetWatch attributes, and evaluates complex logical conditions (`selection`, `1 of selection*`, `all of selection*`, `and`, `or`, `not`, wildcards, regex). Rule versions are tracked immutably in `sigma_rule_versions`.

---

### 6. How does multi-stage event correlation work?
**Answer:** Correlation rules (`R-CORR-01` through `R-CORR-03`) look across sliding time windows for sequences of related events—such as an initial port scan followed by an authentication failure and subsequent large data transfer. When a sequence is matched across a single entity or IP within the correlation window, a high-severity correlated alert or unified Campaign (`CMP-2026-XXXX`) is automatically generated.

---

### 7. How does alert deduplication work?
**Answer:** To prevent alert fatigue, NetWatch computes a deduplication hash based on `rule_id`, `src_ip`, `dst_ip`, and `destination_port` within a configurable sliding suppression window (e.g., 300 seconds). Subsequent identical detection triggers update the existing alert's `occurrence_count` and `last_seen` timestamp rather than flooding the triage queue with duplicate entries.

---

### 8. How does UEBA / Behavioral Anomaly Detection work?
**Answer:** NetWatch maintains statistical baselines over 168-hour (7-day) historical windows across network, temporal, entity, and process dimensions. It requires a minimum threshold of 20 historical observed events before activating anomaly evaluation; otherwise, it returns `INSUFFICIENT_DATA`. When sufficient data exists, it evaluates standard deviations (z-scores) and percentiles to flag anomalous traffic volume, unusual access times, or off-hours process execution.

---

### 9. How is risk scored in NetWatch, and is it explainable?
**Answer:** Risk scoring is completely deterministic and explainable (0–100 bounded scale). Risk is computed by adding base severity scores (Low: 25, Medium: 50, High: 75, Critical: 90) to weighted contextual modifiers (e.g., velocity multiplier, target asset criticality, threat intelligence match, UEBA z-score). NetWatch returns a structured mathematical explanation object detailing every point addition.

---

### 10. How does Threat Hunting work in NetWatch?
**Answer:** Threat hunting allows analysts to search across raw telemetry, normalized events, and alerts using structured query parameters (`/api/hunting/query`). Analysts can filter by time range, event category, severity, source/destination subnets, or custom key-value attributes. Hunt results can be saved into formal Hunt Reports (`/api/hunting/reports`) or directly converted into investigation cases.

---

### 11. How do analysts pivot from alerts to investigations?
**Answer:** From any alert in the triage queue (`/api/alerts`), an analyst can trigger case creation (`/api/investigations`). The backend creates an `Investigation` record, links the triggering alert and raw events, generates an initial event timeline, and sets the case status to `OPEN`.

---

### 12. How are MITRE ATT&CK mappings generated?
**Answer:** Every detection rule and Sigma rule in NetWatch is tagged with official MITRE ATT&CK tactic IDs (e.g., `TA0006: Credential Access`) and technique IDs (e.g., `T1110: Brute Force`). The `/api/mitre/coverage` endpoint aggregates all active rules to build an interactive matrix view showing coverage depth across all 14 tactics and highlighting detection gaps.

---

### 13. How does IOC / Threat Intelligence matching work?
**Answer:** NetWatch integrates an IOC Engine (`app/threat_intelligence/`) that ingests IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, and email indicators. Incoming telemetry fields are matched against stored IOC lists in real time. In addition, the system includes modular provider adapters (AbuseIPDB, AlienVault OTX, MISP) with sliding-window reputation caching.

---

### 14. How does the SOAR subsystem execute playbooks?
**Answer:** SOAR playbooks (`app/soar/`) consist of versioned, ordered execution steps. Each step specifies a target action (e.g., `BLOCK_IP`, `TERMINATE_PROCESS`, `ISOLATE_HOST`, `DISABLE_USER`), conditions, timeouts, retries, and max loop depth safeguards (limit 5).

---

### 15. Why are SOAR response actions approval-gated?
**Answer:** To prevent automated response logic from accidentally disrupting critical operations or causing host self-lockouts, destructive response actions (such as host network isolation or account disabling) require explicit human authorization based on policy (`ANALYST_APPROVAL` or `ADMIN_APPROVAL`). Pending actions wait in a secure approval queue (`/api/soar/approvals`) until authorized.

---

### 16. How does SOAR Dry-Run mode work?
**Answer:** When global dry-run mode is enabled (`NETWATCH_SOAR_DRY_RUN=true`), the SOAR engine evaluates playbook conditions, checks authorization policies, logs idempotency keys, and generates simulated result payloads without invoking real OS drivers or modifying system state.

---

### 17. How does SOAR state rollback work?
**Answer:** Every state-modifying SOAR action tracks an inverse action pair (e.g., `BLOCK_IP` ↔ `UNBLOCK_IP`, `ISOLATE_HOST` ↔ `UNISOLATE_HOST`). When an analyst requests a rollback (`/api/soar/actions/{id}/rollback`), the engine verifies the original idempotency key, checks authorization, and executes the inverse driver action to safely restore previous state.

---

### 18. How is Audit Logging implemented?
**Answer:** Audit logging (`app/services/audit_service.py`) records all analyst state changes, authentication events, rule updates, case modifications, and SOAR executions. Audit entries store timestamp, actor user ID, role, client IP, action name, target entity, and detailed payload changes in an immutable append-only table (`audit_logs`).

---

### 19. How do you prevent sensitive secrets from entering logs or audit trails?
**Answer:** The audit service and loggers scrub sensitive keys (such as `password`, `token`, `secret`, `api_key`, `access_token`) using regex and dictionary key redaction before persisting records to database or log outputs.

---

### 20. What parts of NetWatch are simulated vs real?
**Answer:**
- **Real:** FastApi REST API, SQLite/PostgreSQL persistence, JWT authentication, RBAC, PyYAML Sigma engine, statistical UEBA math, real local socket telemetry (`psutil`), log file ingestion, Windows `netsh` firewall manipulation, audit logging, React UI.
- **Controlled Laboratory Telemetry:** The 5 Demo Scenarios (`ssh_brute_force`, `suspicious_login`, `c2_beacon`, `port_scan`, `dns_anomaly`) stream synthetic telemetry within local memory/database to allow safe offline testing without targeting external networks.
- **Optional External Integrations:** Cloud Connectors (AWS/Azure/GCP) and Threat Intel Providers (AbuseIPDB/OTX/MISP) default to `NOT_CONFIGURED` status unless valid API credentials are supplied.

---

### 21. What would need to change for a production enterprise deployment?
**Answer:**
1. Database: Migrate SQLite to PostgreSQL with read-replicas.
2. Queue/Ingestion: Replace direct in-process queue with Apache Kafka or RabbitMQ.
3. Search: Deploy Elasticsearch or OpenSearch for indexing multi-terabyte raw log streams.
4. Security: Enable TLS/HTTPS, HSM-backed secret management, and Enterprise SSO (SAML/OIDC).
5. Agents: Deploy cross-platform Endpoint Agents (e.g., Osquery/Sysmon/eBPF) for host event collection.

---

### 22. What are the main technical limitations of the current implementation?
**Answer:**
- Single-instance SQLite/in-memory state limits horizontal scalability without external PostgreSQL/Redis.
- Ingestion rate is bounded by single-process Python async execution (~5,000 events/sec without Kafka).
- Syslog UDP receiver performance requires dedicated socket buffer tuning under heavy network flooding.

---

### 23. What security threats exist against the NetWatch platform itself, and how are they mitigated?
**Answer:**
- **Log Injection / Path Traversal:** Mitigated via `secure_filename` sanitization and 10 MB strict file size limits.
- **Privilege Escalation:** Mitigated via JWT RBAC middleware (`ADMIN`, `ANALYST`, `VIEWER`) and last-admin self-deletion protections.
- **SOAR Self-Lockout:** Mitigated via strict loopback (`127.0.0.1`) allowlists and mandatory approval queues.

---

### 24. How would you scale NetWatch horizontally?
**Answer:** Decouple ingestion into stateless FastAPI collector instances behind a Layer 7 Load Balancer (Nginx/HAProxy). Collectors publish normalized events to Kafka topics. Asynchronous worker pools process detection, UEBA baselining, and Sigma evaluation in parallel, persisting to PostgreSQL and indexing into Elasticsearch/OpenSearch.

---

### 25. How do you verify system integrity and prevent regressions?
**Answer:** NetWatch maintains a comprehensive automated test suite of 50 backend tests in `backend/tests/` covering authentication, RBAC, telemetry ingestion, detection engine, Sigma evaluation, UEBA baselines, SOAR playbooks, WebSocket broadcasting, and threat hunting. Frontend stability is verified via Vite production builds (`npx vite build`).
