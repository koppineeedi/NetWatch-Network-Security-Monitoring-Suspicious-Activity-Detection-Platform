# NetWatch Detection Sandbox Architecture

## Overview

The Detection Sandbox (`/api/sigma/sandbox/test` and `/sigma/sandbox`) allows security analysts to test proposed or draft Sigma rules against real historical telemetry and ingested logs before production deployment.

## Key Principles

- **Real Telemetry Only**: Queries real database records collected over past hours (1h to 168h).
- **Insufficient Data Behavior**: If no historical telemetry records exist for the selected lookback timeframe, the API returns `status: "INSUFFICIENT_DATA"` rather than fabricating test events.
- **Safety Isolation**: Sandbox execution records metrics in `sigma_rule_executions` (`execution_type: "SANDBOX"`), but **NEVER** creates production alerts or toggles rule activation.
- **Execution Preview**: Returns execution duration in milliseconds, historical match count, evidence summary, and unsupported field list.
