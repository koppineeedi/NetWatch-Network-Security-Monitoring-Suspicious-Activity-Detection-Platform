# NetWatch Enterprise Connectors Architecture

## Overview
NetWatch Enterprise Enhancement Cycle 1 introduces a generic connector architecture to integrate real remote syslog feeds and major cloud provider audit trails (AWS CloudTrail, Azure Activity Log, GCP Audit Logs).

## Connector Lifecycle & States
Each connector maintains an isolated lifecycle state:
- `DISABLED`: Connector configured but disabled by administrative policy.
- `CONFIGURED`: Valid credentials/configuration supplied.
- `CONNECTED`: Active connectivity verified with remote provider API.
- `ERROR`: Authentication or communication failure encountered.
- `NOT_CONFIGURED`: Missing environment variables or secret credentials.

## API Endpoints
- `GET /api/connectors`: List all connectors (secrets redacted).
- `POST /api/connectors`: Register new connector (ADMIN only).
- `GET /api/connectors/{id}`: Inspect connector status and metadata.
- `PUT /api/connectors/{id}`: Update connector configuration.
- `DELETE /api/connectors/{id}`: Remove connector configuration.
- `POST /api/connectors/{id}/test`: Execute credential validation test.
- `POST /api/connectors/{id}/enable`: Enable connector.
- `POST /api/connectors/{id}/disable`: Disable connector.

## Supported Adapters
1. **Remote Syslog (`syslog-remote`)**: Listens on configured UDP/TCP ports for network telemetry.
2. **AWS CloudTrail (`aws-cloudtrail`)**: Reads CloudTrail security logs via AWS SDK.
3. **Azure Activity Log (`azure-activity`)**: Collects Azure monitor logs.
4. **GCP Audit Log (`gcp-audit`)**: Ingests GCP Stackdriver security logs.

## Security Controls
- **Secret Redaction**: API keys, access secrets, and connection strings are masked (`*****`) in API responses.
- **RBAC**: Write, test, and toggle operations require `ADMIN` role. Read operations available to `ANALYST` and `VIEWER`.
- **Graceful Error Handling**: Missing cloud credentials result in state `NOT_CONFIGURED` without interrupting backend telemetry ingestion.
