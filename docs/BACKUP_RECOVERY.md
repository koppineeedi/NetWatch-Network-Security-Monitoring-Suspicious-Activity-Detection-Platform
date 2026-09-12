# NetWatch Database Backup & Disaster Recovery Guide

**System:** NetWatch Network Security Monitoring Platform  
**Document Version:** 1.0.0  
**Target RPO / RTO:** RPO < 1 hour | RTO < 15 minutes  

---

## Executive Summary

This guide outlines authoritative backup, integrity verification, and disaster recovery procedures for the NetWatch platform across **SQLite** (staging/edge deployment) and **PostgreSQL** (enterprise production deployment).

---

## 1. SQLite Database Backup & Recovery

### Online Safe Backup Procedure (Without Server Downtime)
SQLite database files (`netwatch.db`) must be backed up using SQLite's online backup API or atomic file snapshotting to prevent database lock issues or partial reads during active ingestion.

#### Method A: SQLite Online Backup Python Script
Execute the native NetWatch backup helper:
```bash
python -c "
import sqlite3, datetime, os
os.makedirs('backups', exist_ok=True)
timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
backup_path = f'backups/netwatch_backup_{timestamp}.db'
src = sqlite3.connect('netwatch.db')
dst = sqlite3.connect(backup_path)
with dst:
    src.backup(dst)
dst.close()
src.close()
print(f'Successfully created online backup: {backup_path}')
"
```

#### Method B: SQLite CLI Backup Command
```bash
sqlite3 netwatch.db ".backup 'backups/netwatch_backup.db'"
```

### Database Integrity Verification
Prior to restoring or archiving a backup, verify file integrity:
```bash
sqlite3 backups/netwatch_backup.db "PRAGMA integrity_check;"
# Output MUST be: ok
```

### Restore Procedure
1. Stop NetWatch backend process:
   ```bash
   # Windows PowerShell
   Stop-Process -Name "python" -Force
   # Linux
   sudo systemctl stop netwatch-backend
   ```
2. Archive existing database file safely:
   ```bash
   cp netwatch.db netwatch_corrupted_archive.db
   ```
3. Restore verified backup file:
   ```bash
   cp backups/netwatch_backup.db netwatch.db
   ```
4. Restart NetWatch backend process.

---

## 2. Enterprise PostgreSQL Backup & Recovery

In production environments using PostgreSQL (`DATABASE_URL=postgresql://user:pass@host:5432/netwatch_db`), utilize standard `pg_dump` and `pg_restore` workflows.

### Automated Backup Command (`pg_dump`)
```bash
# Compressed Custom Format Backup
pg_dump -h localhost -U netwatch_user -F c -b -v -f "backups/netwatch_pg_$(date +%Y%m%d_%H%M%S).dump" netwatch_db
```

### Scheduled Daily Cron (Linux)
Add to `/etc/cron.d/netwatch-backup`:
```cron
0 2 * * * postgres pg_dump -U netwatch_user -F c netwatch_db > /var/backups/netwatch/netwatch_$(date +\%Y\%m\%d).dump
```

### Restoration Procedure (`pg_restore`)
1. Stop backend services.
2. Create or reset destination database:
   ```bash
   dropdb -h localhost -U postgres netwatch_db
   createdb -h localhost -U postgres -O netwatch_user netwatch_db
   ```
3. Restore database schema and data:
   ```bash
   pg_restore -h localhost -U postgres -d netwatch_db -v "backups/netwatch_pg_20260912_120000.dump"
   ```
4. Perform schema migration check and restart services.

---

## 3. Data Retention & Archival Policies

- **Telemetry & Logs (`network_events`, `log_ingestions`):** 90 days retention by default (`NETWATCH_ANALYTICS_RETENTION_DAYS=90`).
- **Audit Logs (`audit_logs`):** 365 days immutable retention for SOC compliance.
- **Alerts & Incidents (`alerts`, `investigations`):** Permanent retention until explicitly closed or archived by an administrator.

---

## 4. Emergency Disaster Recovery Checklist

- [ ] Stop incoming collector pipelines (`netwatch-backend` service).
- [ ] Verify backup file exists and passes `PRAGMA integrity_check` or `pg_restore --list`.
- [ ] Replace active database file/schema.
- [ ] Run configuration validator (`python backend/app/scripts/config_check.py`).
- [ ] Verify readiness probe (`GET /ready` returns HTTP 200).
- [ ] Confirm WebSockets and SOC dashboards reconnect successfully.
