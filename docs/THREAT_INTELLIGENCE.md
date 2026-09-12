# NetWatch Threat Intelligence Framework

## Overview
NetWatch Threat Intelligence provides modular enrichment and IOC correlation across network events, alerts, and investigations.

## Threat Intelligence Providers
- **AbuseIPDB**: High-confidence IP abuse scores and community reports.
- **AlienVault OTX**: Threat pulse indicators (IPs, domains, hashes).
- **MISP**: Structured malware and threat campaign indicators.
- **Generic Feed / Manual Upload**: Standard JSON/CSV/TXT threat list ingestion.

## Configuration
Set provider API keys in environment variables:
```bash
ABUSEIPDB_API_KEY=your_abuseipdb_key
OTX_API_KEY=your_alienvault_otx_key
MISP_URL=https://misp.local
MISP_API_KEY=your_misp_key
NETWATCH_TI_CACHE_MINUTES=60
```
If an API key is absent, the provider status remains `NOT_CONFIGURED`. No fake scores or mock alerts are generated.

## Features
- **Real-Time IOC Matching**: Telemetry event IP addresses, domains, and hashes are automatically matched against active IOC records during event processing.
- **IP Reputation & Geolocation**: Caches IP reputation scores and geographic metadata (Country, ASN, Organization) using configured cache TTL (`NETWATCH_TI_CACHE_MINUTES`).
- **Enrichment in Alerts & Investigations**: Alert inspection modals and incident timelines automatically display matched IOC details, confidence ratings, and provider origins.
- **WebSocket Streaming**: High-severity IOC matches trigger real-time `IOC_MATCH` WebSocket broadcast events.
