"""
Heterogeneous Graph Attention Network (HGAT) for SBOM graphs.

Defines a minimal HGAT using torch_geometric. To keep import-time side effects
low (so other sbom_toolkit modules can be used without torch installed), this
module builds the real torch.nn.Module lazily inside the constructor.
"""

from __future__ import annotations

from typing import Any, cast

EdgeType = tuple[str, str, str]


class HeteroGAT:
    """Lightweight wrapper that constructs the real HGAT only when needed.

    The underlying implementation is a torch.nn.Module created at runtime. All
    attribute access not found on this wrapper is delegated to the inner module
    (so .to(), .eval(), .load_state_dict() work transparently).
    """

    def __init__(
        self,
        in_dims: dict[str, int],
        hidden_dim: int = 64,
        heads: int = 2,
        num_layers: int = 2,
        dropout: float = 0.2,
    ) -> None:
        try:
            import torch
            import torch.nn as nn
            from torch_geometric.nn import GATConv, HeteroConv
        except Exception as e:
            raise ImportError(
                "Missing torch/torch-geometric. Install with: pip install torch torch-geometric"
            ) from e

        class _Impl(nn.Module):
            hidden_dim: int
            heads: int
            num_layers: int
            dropout: float

            def __init__(self, in_dims_local: dict[str, int]) -> None:
                super().__init__()
                # `torch.nn.Module` has a custom `__setattr__` that some type checkers
                # treat as restrictive for non-Module attributes. Assign via `Any`
                # while keeping explicit attribute annotations above.
                self_any = cast(Any, self)
                self_any.hidden_dim = int(hidden_dim)
                self_any.heads = int(heads)
                self_any.num_layers = int(num_layers)
                self_any.dropout = float(dropout)

                self.proj = nn.ModuleDict(
                    {t: nn.Linear(in_dim, hidden_dim) for t, in_dim in in_dims_local.items()}
                )

                self.edge_types: tuple[EdgeType, ...] = (
                    ("component", "DEPENDS_ON", "component"),
                    ("component", "HAS_VULNERABILITY", "cve"),
                    ("cve", "HAS_CWE", "cwe"),
                )

                convs = []
                for _ in range(self.num_layers):
                    rel_convs = {}
                    for et in self.edge_types:
                        rel_convs[et] = GATConv(
                            (-1, -1),
                            hidden_dim,
                            heads=self.heads,
                            dropout=self.dropout,
                            add_self_loops=False,
                            concat=False,
                        )
                    convs.append(HeteroConv(rel_convs, aggr="sum"))
                self.convs = nn.ModuleList(convs)

                self.act = nn.ReLU()
                self.drop = nn.Dropout(p=self.dropout)
                self.component_head = nn.Linear(hidden_dim, 2)

            def forward(
                self, x_dict: dict[str, Any], edge_index_dict: dict[EdgeType, Any]
            ) -> dict[str, Any]:
                h: dict[str, Any] = {}
                for t, x in x_dict.items():
                    if t not in self.proj:
                        continue
                    h[t] = self.proj[t](x)
                for conv in self.convs:
                    h = conv(h, edge_index_dict)
                    for t in h:
                        h[t] = self.drop(self.act(h[t]))
                return h

            def component_logits(
                self, x_dict: dict[str, Any], edge_index_dict: dict[EdgeType, Any]
            ) -> Any:
                h = self.forward(x_dict, edge_index_dict)
                comp = h.get("component")
                if comp is None:
                    return torch.empty(
                        (0, 2), dtype=torch.float32, device=next(self.parameters()).device
                    )
                return self.component_head(comp)

        self._impl = _Impl(in_dims)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._impl, name)

    def component_logits(self, x_dict: dict[str, Any], edge_index_dict: dict[EdgeType, Any]) -> Any:
        return self._impl.component_logits(x_dict, edge_index_dict)
