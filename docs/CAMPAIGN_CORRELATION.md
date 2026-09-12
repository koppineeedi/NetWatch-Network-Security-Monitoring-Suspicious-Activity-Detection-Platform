# Campaign Clustering & Multi-Event Correlation

## Overview

NetWatch correlates multi-stage suspicious activities across entities, time windows, and threat intelligence matches into unified threat campaigns (`CMP-2026-XXXX`).

## Correlation Engine (`R-CORR-01` to `R-CORR-03`)

The correlation engine identifies sequences of events such as:
1. Destination port scanning followed by high outbound traffic.
2. Threat intelligence (IOC) match coupled with failed connection spikes.
3. Multi-entity suspicious communication within a tight temporal window.

## Campaign Clustering (`R-CAMP-01`)

Campaigns group related suspicious events based on shared attributes:
- **Shared Entity**: Common source IP, destination IP, or host.
- **Time Proximity**: Events occurring within the correlation window (default: 4 hours).
- **IOC Overlap**: Events matching common threat intelligence indicators.
- **MITRE Technique Overlap**: Events mapped to common MITRE ATT&CK techniques (e.g. `T1046`).

## Campaign Lifecycle & Identifiers

Campaign identifiers follow the format `CMP-YYYY-XXXX` (e.g. `CMP-2026-0001`).

Campaign statuses:
- `ACTIVE`: New suspicious events actively being associated.
- `MONITORING`: No recent events, under observation.
- `RESOLVED`: Analyst investigated and resolved campaign.
- `CLOSED`: Closed campaign.
