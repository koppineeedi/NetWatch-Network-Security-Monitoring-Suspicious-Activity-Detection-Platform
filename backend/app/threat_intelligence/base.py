from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseTIProvider(ABC):
    """
    Abstract base provider for Threat Intelligence integrations.
    Supports AbuseIPDB, AlienVault OTX, MISP, and custom feed sources.
    """

    def __init__(self, provider_name: str, display_name: str):
        self.provider_name = provider_name
        self.display_name = display_name

    @abstractmethod
    def test_connection(self) -> Dict[str, Any]:
        """Validates API credentials and endpoint connectivity safely."""
        pass

    @abstractmethod
    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """Looks up reputation / threat information for a specific IP address."""
        pass

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Returns current operational configuration status."""
        pass
