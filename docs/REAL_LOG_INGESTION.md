# NETWATCH — Real Log Ingestion Pipeline Documentation

## Overview
Phase 3 implements authorized log file upload and ingestion for `.log`, `.txt`, `.json`, and `.csv` files. User-provided log data is validated, safely stored in `data/raw/`, parsed, deduplicated, and normalized into `NetworkEvent` records stored in SQLite database (`netwatch.db`).

## Supported Log Formats
- **JSON**: Single JSON objects, JSON arrays (`[...]`), and newline-delimited JSON (NDJSON).
- **CSV**: Keyed header-based column mapping (`source_ip`, `dest_ip`, `source_port`, `dest_port`, `protocol`, `process_name`, `timestamp`).
- **Generic LOG/TXT**: Pattern matching for Syslog / Zeek / raw text lines. Lines missing IP/port observations increment `records_rejected` without crashing the upload process.

## Ingestion Data Flow
```
USER UPLOAD (POST /api/logs/upload)
        ↓
Validation (Extension, Size Limit <= 25MB, Path Traversal Sanitization)
        ↓
Raw File Storage (data/raw/{uuid}.ext)
        ↓
Parser Selection (json_parser, csv_parser, generic_parser)
        ↓
Normalizer & Deduplication (Fingerprint matching)
        ↓
NetworkEvent & LogIngestion Model Persistence (SQLite DB)
        ↓
Detection Pipeline Evaluation (evaluate_event)
        ↓
API History (GET /api/logs) & React Log Analysis UI
```

## Security Protections
- **Filename Sanitization**: Uploaded files are renamed using UUIDs under `data/raw/`. Original filenames are stored as string metadata only.
- **No File Execution**: Uploaded files are strictly processed as static text streams and never executed.
- **Size Limits**: Enforced by `NETWATCH_MAX_UPLOAD_MB` (Default: 25MB).
- **Error Isolation**: Malformed lines increment `records_rejected` without throwing unhandled exceptions.

## Test Data vs Real Data Attribution
- Ingested files with `TEST` in their filename are tagged with `source = "TEST_LOG"`.
- Production log files are tagged with `source = "LOG_FILE"`.
