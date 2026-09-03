from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseCollector(ABC):
    """
    Abstract base collector class for NetWatch telemetry ingestion.
    All collectors must observe real telemetry without generating network probes or attack traffic.
    """

    def __init__(self, name: str):
        self.name = name
        self.is_running = False

    @abstractmethod
    def start(self):
        """Start passive telemetry collection."""
        pass

    @abstractmethod
    def stop(self):
        """Stop telemetry collection cleanly."""
        pass

    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """Collect current available telemetry snapshot."""
        pass
