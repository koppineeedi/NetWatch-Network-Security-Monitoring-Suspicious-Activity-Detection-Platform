from app.collectors.base import BaseCollector
from typing import List, Dict, Any

class ZeekCollector(BaseCollector):
    """
    Interface for Zeek log telemetry ingestion.
    Not auto-installed or auto-started.
    """

    def __init__(self):
        super().__init__(name="ZEEK_COLLECTOR")

    def start(self):
        self.is_running = True

    def stop(self):
        self.is_running = False

    def collect(self) -> List[Dict[str, Any]]:
        return []
