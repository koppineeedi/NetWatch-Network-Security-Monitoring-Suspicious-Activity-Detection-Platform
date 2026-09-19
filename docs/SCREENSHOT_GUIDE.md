# NetWatch — Visual Portfolio Screenshot & UI Documentation Guide

This document provides a documentation checklist and exact capturing instructions for creating high-resolution screenshots for portfolio presentations, GitHub README, or technical case studies of **NetWatch**.

---

## Portfolio Screenshot Checklist (10 Recommended Screens)

| # | Screen Name | Route / Component | Description & Key UI Elements to Highlight |
| :- | :--- | :--- | :--- |
| **1** | **Analyst Dashboard** | `/` (`Dashboard.tsx`) | Real-time network throughput charts, active socket connections, system status widgets, live alert feed, and Demo Scenario Launcher. |
| **2** | **Alert Triage Queue** | `/alerts` (`Alerts.tsx`) | Filterable alert list, severity badges (CRITICAL, HIGH, MEDIUM, LOW), verdict indicators, and quick action buttons. |
| **3** | **Alert Explainability Modal** | `/alerts` (Modal View) | Detailed breakdown showing mathematical risk calculation, rule ID, velocity metrics, asset criticality, and MITRE ATT&CK mapping. |
| **4** | **Threat Hunting Query Builder** | `/hunting` (`ThreatHunting.tsx`) | EQL/Structured query bar (`src_ip == ...`), time range selector, execution output table, and "Save Hunt Report" action. |
| **5** | **Investigation & Case Detail** | `/investigations/{id}` (`InvestigationDetail.tsx`) | Case header, timeline of events, analyst investigation notes, verdict selector, and evidence upload tab. |
| **6** | **MITRE ATT&CK Coverage Matrix** | `/mitre` (`MitreCoverage.tsx`) | Interactive heatmap grid across all 14 tactics (Reconnaissance to Impact) displaying active rule count per technique. |
| **7** | **Detection Sandbox & Sigma Rules** | `/rules` (`Rules.tsx`) | PyYAML Sigma rule editor, syntax validator status badge (`VALID`), sandbox execution button, and historical replay stats. |
| **8** | **SOAR Approvals & Dry-Run** | `/soar` (`Soar.tsx`) | Pending response actions queue, approval authorization toggle, global Dry-Run status badge, and execution logs. |
| **9** | **Immutable Audit Logs** | `/audit` (`AuditLogs.tsx`) | Filterable, append-only system audit table showing timestamp, actor, role, IP, action name, and detail payload. |
| **10** | **Incident Summary Report** | Export View / PDF Modal | Structured, printable executive incident report summarizing case timeline, evidence hashes, MITRE mappings, and containment actions. |

---

## Step-by-Step Screenshot Capture Guide

### Environment Setup for Screenshots
1. Launch NetWatch Backend in single-user mode:
   ```bash
   cd backend
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```
2. Start Frontend UI:
   ```bash
   cd frontend
   npm run dev
   ```
3. Open browser at `http://localhost:5173` and log in as Administrator (`admin` / `admin123`).
4. Click **Launch Demo Scenario** on the Dashboard and select `ssh_brute_force` to populate live alerts, events, anomalies, and investigations.

### Capture Guidelines
- **Resolution:** 1920x1080 (1080p) or 2560x1440 (1440p) unscaled.
- **Theme:** Dark Mode preferred for high-contrast SOC dashboard aesthetic.
- **Formatting:** PNG format saved to `docs/images/` or `assets/screenshots/`.
