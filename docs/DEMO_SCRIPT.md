# NetWatch — 3-Minute SOC Analyst Technical Demo Script

This document provides a structured, 3-to-5-minute technical presentation script for demonstrating **NetWatch** during technical interviews, portfolio reviews, or architecture walkthroughs.

---

## Technical Presentation Overview

- **Target Duration:** 3–5 Minutes
- **Primary Technical Scenario:** `ssh_brute_force` (Controlled Defensive Laboratory Scenario)
- **Primary Core Workflow:**
  `Telemetry → Normalization → Detection → Alert → Triage → Investigation → Threat Hunting → MITRE ATT&CK → IOC Enrichment → Controlled Response → Audit → Incident Report`
- **Key Message:** NetWatch is a defensive, rule- and anomaly-driven SOC, SIEM, UEBA, and SOAR platform built with FastAPI, SQLAlchemy, React, and Tailwind CSS. It processes structured network telemetry and log streams with zero fake data, full rule explainability, approval-gated SOAR execution, and complete audit tracking.

---

## Segment Breakdown & Narration

```
0:00 ── 0:30 | Project Overview & Value Proposition
0:30 ── 1:00 | Architecture & Analyst Dashboard
1:00 ── 1:45 | Ingest Laboratory Telemetry (SSH Brute Force)
1:45 ── 2:15 | Alert Triage & Explainable Risk Scoring
2:15 ── 2:45 | Threat Hunting & Investigation Pivot
2:45 ── 3:15 | Forensic Evidence & MITRE ATT&CK Mapping
3:15 ── 3:45 | SOAR Playbook Execution, Dry-Run & Approval
3:45 ── 4:15 | Immutable Audit Log & State Rollback
4:15 ── 5:00 | Incident Reporting & Platform Defense Wrap-Up
```

---

### Segment 1: Project Overview & Value Proposition (0:00 – 0:30)

**Screen:** Main Landing / Login Screen or Overview Section

> **Suggested Narration:**
> "NetWatch is an enterprise-oriented defensive SOC, SIEM, UEBA, and SOAR platform engineered to bridge real-time network security monitoring with automated incident response. 
>
> Unlike typical frontend mocks, NetWatch relies on deterministic detection logic, statistical baselining, real OS socket telemetry, and structured log parsers. Every alert, anomaly, threat hunt result, and automated response action is grounded in verified telemetry and mathematical explanations."

---

### Segment 2: Architecture & Analyst Dashboard (0:30 – 1:00)

**Screen:** Analyst Dashboard (`/`)

> **Suggested Narration:**
> "Here on the Analyst Dashboard, we see real-time network throughput, active connection metrics, top talking IP addresses, live security alerts, and system health status. 
>
> Behind this interface lies an asynchronous FastAPI backend connected to SQLite/PostgreSQL, a PyYAML-backed Sigma rule engine, a statistical UEBA baseline engine calculating z-scores over 168-hour windows, and an authenticated WebSocket pipeline delivering real-time events to React clients with a 30-second heartbeat."

---

### Segment 3: Laboratory Telemetry Ingestion — SSH Brute Force (1:00 – 1:45)

**Screen:** Dashboard → Demo Scenario Launcher Widget

> **Suggested Narration:**
> "To demonstrate the SOC analyst workflow safely, NetWatch includes controlled laboratory attack scenarios. I'll launch the **SSH Brute Force** scenario.
>
> This scenario streams a rapid sequence of failed SSH authentication attempts from external IP `192.168.1.150` targeting internal server `10.0.0.5` on Port 22, followed by a successful authentication event.
>
> As telemetry flows through the normalization parser into unified `NetworkEvent` models, the detection engine evaluates event velocity over a sliding window."

---

### Segment 4: Alert Triage & Explainable Risk Scoring (1:45 – 2:15)

**Screen:** Alert Triage Queue (`/alerts`) → Click Alert Detail / Explainability Modal

> **Suggested Narration:**
> "Within seconds, an **HIGH** severity alert is generated: `R-AUTH-01: High-Velocity Authentication Failure / Potential Brute Force`.
>
> Notice our **Alert Explainability Modal**. NetWatch doesn't use black-box scores. It provides a mathematical risk breakdown:
> - Base severity score: 75/100
> - Velocity multiplier: 12 failed attempts in 30 seconds (+15 points)
> - Target asset criticality: Production SSH Server (+10 points)
> - Resulting risk score: **95/100**
>
> The alert is automatically mapped to **MITRE ATT&CK T1110 (Brute Force)** under the **Credential Access** tactic."

---

### Segment 5: Threat Hunting & Investigation Pivot (2:15 – 2:45)

**Screen:** Threat Hunting Page (`/hunting`) → Run Query → Pivot to Investigation

> **Suggested Narration:**
> "As a SOC analyst, I want to scope the breadth of this attack. I navigate to **Threat Hunting** and run a structured query for `src_ip == '192.168.1.150' AND category == 'authentication'`.
>
> The hunt query returns 15 correlated raw events across the timeframe. From the hunt results, I click **Create Investigation** to open Case `INV-2026-0042` and assign it to myself for incident management."

---

### Segment 6: Forensic Evidence & MITRE ATT&CK Mapping (2:45 – 3:15)

**Screen:** Investigation Detail Page (`/investigations/{id}`) → Evidence Tab & MITRE Matrix (`/mitre`)

> **Suggested Narration:**
> "Inside the investigation case, I upload forensic evidence—a raw log extract and PCAP hash snippet—using the `/api/investigations/{id}/evidence` endpoint.
>
> I can also view the **MITRE ATT&CK Matrix Coverage** page, which highlights our active rule coverage across all 14 tactics from Reconnaissance to Impact, showing exactly where this detection fits in our defensive posture."

---

### Segment 7: SOAR Execution, Dry-Run & Approval Safety (3:15 – 3:45)

**Screen:** SOAR Playbooks / Approvals Page (`/soar`)

> **Suggested Narration:**
> "To contain the attacker, we trigger the `SSH_Brute_Force_Containment` playbook. 
>
> Safety is paramount in NetWatch:
> 1. **Dry-Run Mode**: Allows testing the playbook steps without modifying OS firewall rules or state.
> 2. **Approval Gate**: Host isolation and account lock actions require explicit `ADMIN_APPROVAL`.
> 3. **Idempotency & Safeguards**: Protected loopback addresses (`127.0.0.1`) cannot be blocked, preventing analyst self-lockout.
>
> Once an Administrator approves the action, the `WindowsNetshHostIsolationDriver` executes a netsh rule blocking `192.168.1.150` on port 22."

---

### Segment 8: Immutable Audit Trail & Rollback (3:45 – 4:15)

**Screen:** Audit Logs Page (`/audit`)

> **Suggested Narration:**
> "Every analyst action—login, alert status update, note creation, evidence upload, hunt query execution, and SOAR trigger—is logged to an append-only audit trail accessible under **Audit Logs**.
>
> If the block was a false positive, NetWatch supports atomic **State Rollback**, executing the `UNBLOCK_IP` action to safely restore host network connectivity."

---

### Segment 9: Incident Report & Portfolio Summary (4:15 – 5:00)

**Screen:** Investigation Detail → Export Incident Report / Dashboard Summary

> **Suggested Narration:**
> "Finally, I set the investigation verdict to `TRUE_POSITIVE`, update the status to `CLOSED`, and export a formal **Incident Summary Report**.
>
> To summarize: NetWatch combines real-time network telemetry, rule-based detection, explainable UEBA, threat hunting, MITRE ATT&CK mapping, and approval-gated SOAR into a cohesive, production-grade architecture verified by 50 automated tests and a production Vite build.
>
> Thank you! I'm happy to dive deeper into any architectural component, database schema, or detection algorithm."
