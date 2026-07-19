from __future__ import annotations

import heapq
from collections.abc import Sequence
from dataclasses import dataclass

from riec_guard.evidence.ids import EvidenceError, EvidenceErrorCode
from riec_guard.evidence.models import EvidenceItem


@dataclass(frozen=True, slots=True)
class ProvenanceGraph:
    """Immutable deterministic view of one finalized ledger's parent DAG."""

    topological_order: tuple[str, ...]
    parent_records: tuple[tuple[str, tuple[str, ...]], ...]
    child_records: tuple[tuple[str, tuple[str, ...]], ...]

    @property
    def node_count(self) -> int:
        return len(self.topological_order)

    @property
    def edge_count(self) -> int:
        return sum(len(parents) for _, parents in self.parent_records)

    def direct_ancestors(self, evidence_id: str) -> tuple[str, ...]:
        """Return direct parents in their frozen identity-significant array order."""

        return self._lookup(self.parent_records, evidence_id)

    def ancestors(self, evidence_id: str) -> tuple[str, ...]:
        """Return all transitive ancestors in stable lexical order."""

        self._require_node(evidence_id)
        found: set[str] = set()
        pending = list(self.direct_ancestors(evidence_id))
        while pending:
            parent = pending.pop()
            if parent in found:
                continue
            found.add(parent)
            pending.extend(self.direct_ancestors(parent))
        return tuple(sorted(found))

    def descendants(self, evidence_id: str) -> tuple[str, ...]:
        """Return all transitive descendants in stable lexical order."""

        self._require_node(evidence_id)
        found: set[str] = set()
        pending = list(self._lookup(self.child_records, evidence_id))
        while pending:
            child = pending.pop()
            if child in found:
                continue
            found.add(child)
            pending.extend(self._lookup(self.child_records, child))
        return tuple(sorted(found))

    def _require_node(self, evidence_id: str) -> None:
        if evidence_id not in self.topological_order:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_PARENT_NOT_FOUND,
                "Requested provenance node does not belong to this ledger.",
            )

    @staticmethod
    def _lookup(
        records: tuple[tuple[str, tuple[str, ...]], ...], evidence_id: str
    ) -> tuple[str, ...]:
        for node_id, linked_ids in records:
            if node_id == evidence_id:
                return linked_ids
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_PARENT_NOT_FOUND,
            "Requested provenance node does not belong to this ledger.",
        )


def validate_provenance_graph(items: Sequence[EvidenceItem]) -> ProvenanceGraph:
    """Validate one insertion-order-independent DAG and return stable traversals."""

    by_id: dict[str, EvidenceItem] = {}
    for item in items:
        if item.evidence_id in by_id:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_DUPLICATE_ID,
                "Evidence ledger contains a duplicate evidence ID.",
            )
        by_id[item.evidence_id] = item

    parent_map: dict[str, tuple[str, ...]] = {}
    children: dict[str, list[str]] = {evidence_id: [] for evidence_id in by_id}
    for evidence_id in sorted(by_id):
        parents = tuple(by_id[evidence_id].parent_evidence_ids)
        if len(parents) != len(set(parents)):
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_DUPLICATE_PARENT,
                "Evidence ledger contains a duplicate parent edge.",
            )
        if evidence_id in parents:
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_SELF_PARENT,
                "Evidence item cannot parent itself.",
            )
        if any(parent not in by_id for parent in parents):
            raise EvidenceError(
                EvidenceErrorCode.EVIDENCE_PARENT_NOT_FOUND,
                "Evidence parent does not belong to this ledger.",
            )
        parent_map[evidence_id] = parents
        for parent in parents:
            children[parent].append(evidence_id)

    indegree = {evidence_id: len(parents) for evidence_id, parents in parent_map.items()}
    ready = [evidence_id for evidence_id, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)
    order: list[str] = []
    while ready:
        evidence_id = heapq.heappop(ready)
        order.append(evidence_id)
        for child in sorted(children[evidence_id]):
            indegree[child] -= 1
            if indegree[child] == 0:
                heapq.heappush(ready, child)
    if len(order) != len(by_id):
        raise EvidenceError(
            EvidenceErrorCode.EVIDENCE_GRAPH_CYCLE,
            "Evidence provenance graph contains a cycle.",
        )

    return ProvenanceGraph(
        topological_order=tuple(order),
        parent_records=tuple((node, parent_map[node]) for node in sorted(parent_map)),
        child_records=tuple((node, tuple(sorted(children[node]))) for node in sorted(children)),
    )


def direct_ancestors(graph: ProvenanceGraph, evidence_id: str) -> tuple[str, ...]:
    return graph.direct_ancestors(evidence_id)


def descendants(graph: ProvenanceGraph, evidence_id: str) -> tuple[str, ...]:
    return graph.descendants(evidence_id)


__all__ = [
    "ProvenanceGraph",
    "descendants",
    "direct_ancestors",
    "validate_provenance_graph",
]
