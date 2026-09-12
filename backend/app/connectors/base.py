from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseConnectorAdapter(ABC):
    """
    Abstract adapter for network & cloud log connectors.
    Must handle status validation, credential testing, and safe execution without exposing secrets.
    """

    def __init__(self, connector_id: str, name: str, connector_type: str):
        self.connector_id = connector_id
        self.name = name
        self.connector_type = connector_type

    @abstractmethod
    def test_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Tests connector configuration and credentials safely."""
        pass

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Returns current operational status dict."""
        pass

    @abstractmethod
    def redact_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Redacts sensitive keys, secrets, and API tokens from configuration dict."""
        pass
