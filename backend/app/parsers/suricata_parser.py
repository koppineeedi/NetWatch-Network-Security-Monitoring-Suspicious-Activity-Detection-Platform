import json
from typing import List, Dict, Any

def parse_suricata_eve(text: str) -> List[Dict[str, Any]]:
    """
    Parses Suricata EVE JSON log lines.
    """
    events = []
    lines = text.strip().splitlines()
    for line in lines:
        if line.strip():
            try:
                data = json.loads(line.strip())
                events.append(data)
            except Exception:
                pass
    return events
