"""The dependency graph: which package pulls in which.

Built from lock files, which record the resolved tree. It answers two
questions the risk rules need: is a package asked for directly or only pulled
in by something else, and through which chain does it arrive.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

Node = Tuple[str, str, str]  # (ecosystem, name, version)


def node_label(node: Node) -> str:
    return f"{node[1]} {node[2]}".strip()


@dataclass
class DependencyGraph:
    """roots     Packages the project asks for directly.
    children  parent -> packages it pulls in, in file order.
    """

    roots: List[Node] = field(default_factory=list)
    children: Dict[Node, List[Node]] = field(default_factory=dict)

    def add_root(self, node: Node) -> None:
        if node not in self.roots:
            self.roots.append(node)

    def add_edge(self, parent: Node, child: Node) -> None:
        if parent == child:
            return
        kids = self.children.setdefault(parent, [])
        if child not in kids:
            kids.append(child)

    @property
    def nodes(self) -> List[Node]:
        seen: List[Node] = []
        known: Set[Node] = set()
        for node in list(self.roots) + [n for p, kids in self.children.items() for n in [p] + kids]:
            if node not in known:
                known.add(node)
                seen.append(node)
        return seen

    def __bool__(self) -> bool:
        return bool(self.roots or self.children)

    def reachable(self, starts: Iterable[Node]) -> Set[Node]:
        """Every node reachable from `starts`, including the starts. Cycles are safe."""
        seen: Set[Node] = set()
        queue = deque(starts)
        while queue:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            queue.extend(self.children.get(node, ()))
        return seen

    def shortest_paths(self, starts: Optional[Iterable[Node]] = None) -> Dict[Node, Tuple[Node, ...]]:
        """Shortest chain from a root to every reachable node (breadth first).

        The chain includes both ends, so a root maps to a one-item tuple.
        """
        paths: Dict[Node, Tuple[Node, ...]] = {}
        queue = deque()
        for root in (self.roots if starts is None else starts):
            if root not in paths:
                paths[root] = (root,)
                queue.append(root)
        while queue:
            node = queue.popleft()
            for child in self.children.get(node, ()):
                if child not in paths:
                    paths[child] = paths[node] + (child,)
                    queue.append(child)
        return paths

    def merge(self, other: "DependencyGraph") -> None:
        for root in other.roots:
            self.add_root(root)
        for parent, kids in other.children.items():
            for child in kids:
                self.add_edge(parent, child)
