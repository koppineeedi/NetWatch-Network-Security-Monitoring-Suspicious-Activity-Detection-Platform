from typing import Dict, Any, Optional

SIGMA_TO_NETWATCH_MAPPINGS: Dict[str, str] = {
    # Network IP fields
    "src_ip": "source_ip",
    "sourceip": "source_ip",
    "source_ip": "source_ip",
    "dst_ip": "dest_ip",
    "destinationip": "dest_ip",
    "dest_ip": "dest_ip",
    "ip": "source_ip",
    
    # Network Port fields
    "src_port": "source_port",
    "sourceport": "source_port",
    "dst_port": "dest_port",
    "destinationport": "dest_port",
    "port": "dest_port",

    # Protocol & Connection
    "proto": "protocol",
    "protocol": "protocol",
    "connection_state": "connection_state",

    # Host & System
    "hostname": "hostname",
    "computername": "hostname",
    "host": "hostname",
    "source_host": "source_host",
    "dest_host": "dest_host",

    # Process & User
    "image": "process_name",
    "process_name": "process_name",
    "process": "process_name",
    "user": "username",
    "username": "username",
    "commandline": "payload_summary",
    "payload_summary": "payload_summary",

    # Event Meta
    "event_type": "event_type",
    "event_id": "collector",
    "source": "source",
    "collector": "collector"
}

class SigmaFieldMapper:
    @staticmethod
    def map_field(sigma_field: str) -> Optional[str]:
        """
        Maps a Sigma field name to its corresponding NetWatch NetworkEvent model attribute.
        Returns None if the field is not supported.
        """
        clean_field = sigma_field.lower().strip()
        return SIGMA_TO_NETWATCH_MAPPINGS.get(clean_field, None)

    @staticmethod
    def is_field_supported(sigma_field: str) -> bool:
        """
        Returns True if the Sigma field has an explicit mapping to NetWatch telemetry.
        """
        return SigmaFieldMapper.map_field(sigma_field) is not None

    @staticmethod
    def get_all_mappings() -> Dict[str, Any]:
        """
        Returns complete mapping list for API visibility.
        """
        result = []
        for s_field, n_field in SIGMA_TO_NETWATCH_MAPPINGS.items():
            result.append({
                "sigma_field": s_field,
                "netwatch_field": n_field,
                "supported": True,
                "description": f"Maps Sigma {s_field} to NetWatch {n_field}"
            })
        return result
