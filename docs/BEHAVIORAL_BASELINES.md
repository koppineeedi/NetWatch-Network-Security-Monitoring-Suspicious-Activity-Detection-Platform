# Behavioral Baseline Engine

## Concept

The NetWatch Behavioral Baseline Engine computes statistical metrics over historical telemetry windows for observed entities across network, temporal, process, and entity dimensions.

## Dimensions & Features

1. **Network**:
   - `connection_count`
   - `unique_destination_count`
   - `unique_port_count`
   - `failed_connection_count`
   - `dns_query_count`
   - `outbound_connection_count`
   - `inbound_connection_count`
   - `destination_port_entropy`
   - `connection_rate`
   - `unique_external_destination_count`

2. **Temporal**:
   - Hourly and daily connection distributions.
   - Weekday vs. weekend frequency comparisons.

3. **Process**:
   - Process to network relationship pairs.
   - Process destination and port diversity.

## Statistical Properties

For each feature, NetWatch computes and stores:
- `mean_value`
- `standard_deviation`
- `median_value`
- `percentile_95`
- `minimum_value`
- `maximum_value`
- `sample_count`

## Baseline Statuses

- `ACTIVE`: Baseline successfully computed with $\ge$ `NETWATCH_UEBA_MIN_EVENTS`.
- `INSUFFICIENT_DATA`: Telemetry sample count is below the minimum event threshold.
- `STALE`: Baseline has not been refreshed within the configured interval.
