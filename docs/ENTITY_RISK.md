# Entity Risk Scoring & Decay Subsystem

## Overview

NetWatch maintains persistent entity risk scores (bounded 0–100) for all observed entities. Risk scores accumulate based on active alerts, detected anomalies, threat intelligence matches, and campaign associations, while decaying deterministically over time during periods of normal activity.

## Risk Contribution Formula

$$\text{Entity Risk} = \text{Min}\left(100, \sum \text{Alert Contributions} + \sum \text{Anomaly Contributions} + \sum \text{IOC Contributions} + \sum \text{Campaign Contributions}\right)$$

### Factor Weighting
- **Active SOC Alert**: Up to +25 points per HIGH/CRITICAL alert.
- **Statistical Anomaly**: Up to +20 points (scaled by anomaly score).
- **Threat Intelligence Match**: Up to +30 points for high-confidence IOC matches.
- **Campaign Association**: Up to +25 points for active campaign involvement.

## Risk Levels

| Score Range | Risk Level |
|---|---|
| 0 - 24 | `LOW` |
| 25 - 49 | `MEDIUM` |
| 50 - 74 | `HIGH` |
| 75 - 100 | `CRITICAL` |

## Deterministic Risk Decay

When suspicious activity ceases, entity risk decays exponentially with a default half-life of 24 hours (`NETWATCH_RISK_DECAY_HOURS`):

$$\text{Risk}_{\text{decayed}} = \text{Risk}_{\text{previous}} \times e^{-\frac{\Delta t}{\tau}}$$

All risk adjustments are audit-logged in `entity_risk_history` with the exact contributing factor and evidence reference.
