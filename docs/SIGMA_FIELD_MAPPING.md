# Sigma Field Mapping Specification

## Mappings Table

| Sigma Field Name | NetWatch Model Attribute | Status | Description |
|---|---|---|---|
| `src_ip`, `sourceip`, `source_ip` | `source_ip` | Supported | Source IP address |
| `dst_ip`, `destinationip`, `dest_ip` | `dest_ip` | Supported | Destination IP address |
| `src_port`, `sourceport` | `source_port` | Supported | Source port number |
| `dst_port`, `destinationport`, `port` | `dest_port` | Supported | Destination port number |
| `proto`, `protocol` | `protocol` | Supported | Transport protocol (TCP, UDP, ICMP) |
| `image`, `process_name`, `process` | `process_name` | Supported | Process executable name |
| `user`, `username` | `username` | Supported | User identity |
| `hostname`, `computername`, `host` | `hostname` | Supported | Host computer name |
| `commandline`, `payload_summary` | `payload_summary` | Supported | Command line payload |
| `event_type` | `event_type` | Supported | Network event type |
| `collector`, `event_id` | `collector` | Supported | Collector or event identifier |

Fields not present in the table above will be reported as `UNSUPPORTED_FIELD`.
