# Explainable Anomaly Detection Engine

## Overview

NetWatch implements deterministic statistical anomaly detection, avoiding unexplainable black-box machine learning models. Every anomaly detected provides full transparency into the mathematical basis of the alert.

## Detection Methodology

1. **Z-Score Calculation**:
   $$\text{Z-Score} = \frac{\text{Observed Value} - \text{Baseline Mean}}{\text{Baseline Standard Deviation}}$$

2. **Percentile Deviation**:
   Checks whether observed values exceed the historical 95th percentile ($P_{95}$).

3. **Peer Group Deviation**:
   Compares an entity's feature value against the median and distribution of its peer group (e.g. entities within the same IP subnet).

## Anomaly Scoring & Severity Mapping

Anomaly scores range strictly from 0 to 100:

| Score Range | Severity | Action / Rule Trigger |
|---|---|---|
| 0 - 29 | `LOW` | Informational logging |
| 30 - 59 | `MEDIUM` | Risk accumulation |
| 60 - 79 | `HIGH` | High-risk alert & rule `R-UEBA-01` trigger |
| 80 - 100 | `CRITICAL` | Critical alert & campaign correlation trigger |

## Structure of Anomaly Detections

Every anomaly record contains:
- `entity_type` & `entity_id`
- `feature_name`
- `observed_value`
- `baseline_mean` & `baseline_p95`
- `anomaly_score` (0-100)
- `confidence` (0.0 - 1.0)
- `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `explanation`: Deterministic human-readable evidence summary.
- `mitre_techniques`: Associated MITRE ATT&CK technique IDs (e.g., `T1046`).
