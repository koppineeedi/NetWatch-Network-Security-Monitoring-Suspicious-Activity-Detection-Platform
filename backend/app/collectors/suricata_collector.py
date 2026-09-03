from app.collectors.base import BaseCollector
from typing import List, Dict, Any

class SuricataCollector(BaseCollector):
    """
    Interface for Suricata EVE JSON telemetry ingestion.
    Not auto-installed or auto-started.
    """

    def __init__(self):
        super().__init__(name="SURICATA_COLLECTOR")

    def start(self):
        self.is_running = True

    def stop(self):
        self.is_running = False

    def collect(self) -> List[Dict[str, Any]]:
        return []
