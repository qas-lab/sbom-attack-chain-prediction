from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..builder import KnowledgeGraphBuilder


class BaseProcessor(ABC):
    """Base class for knowledge graph data processors."""

    def __init__(self, builder: "KnowledgeGraphBuilder"):
        self.builder = builder

    @abstractmethod
    def process(self, data: Any, *args: Any, **kwargs: Any) -> Any:
        """Process data and add to knowledge graph.

        Args:
            data: The data to process

        Returns:
            Any processing results or statistics
        """
        pass

    def add_node(self, *args, **kwargs):
        """Delegate to builder's add_node method."""
        return self.builder.add_node(*args, **kwargs)

    def add_edge(self, *args, **kwargs):
        """Delegate to builder's add_edge method."""
        return self.builder.add_edge(*args, **kwargs)
