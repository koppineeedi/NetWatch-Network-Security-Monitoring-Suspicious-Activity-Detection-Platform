# NetWatch Indicator of Compromise (IOC) Data Model & Ingestion

## Overview
NetWatch persistent IOC storage maintains standardized indicators of compromise for threat detection and real-time correlation.

## Supported IOC Types
- `IP`: IPv4 and IPv6 addresses.
- `DOMAIN`: FQDNs and domain names.
- `URL`: Full web URLs.
- `HASH_MD5`: 32-character MD5 checksums.
- `HASH_SHA1`: 40-character SHA1 checksums.
- `HASH_SHA256`: 64-character SHA256 checksums.
- `EMAIL`: Malicious email sender addresses.

## Value Normalization Rules
1. **IP Normalization**: Strips whitespace and leading zeroes.
2. **Domain / URL Normalization**: Strips scheme prefix (`http://`, `https://`) and converts to lowercase.
3. **Hash Normalization**: Strips whitespace and converts hex strings to lowercase.
4. **Email Normalization**: Strips whitespace and converts to lowercase.

## Deduplication
Before inserting IOC records, NetWatch checks for existing entries with identical `(normalized_value, ioc_type)`. If present, existing records are updated with revised confidence ratings, last seen timestamps, and tags.

## Feed Import API
- `POST /api/iocs/import`: Upload threat feed files (`.json`, `.csv`, `.txt`).
- **File Validation**: Enforces maximum file size limit (10MB), checks file extension, prevents path traversal attacks, and verifies IOC string format.
- **Audit Tracking**: Returns detailed ingestion report: total records received, accepted, and rejected.
