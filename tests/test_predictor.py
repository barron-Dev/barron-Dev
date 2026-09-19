from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest

from cyclothone.predict.predictor import AttackPathPredictor, PredictionInputError

@dataclass
class Node:
    id: UUID
    external_id: str
    node_type: str
    criticality: float

@dataclass
class Edge:
    target_id: UUID
    relation: str
    weight: float = 1.0

class Graph:
    def __init__(self, nodes, edges):
        self.nodes = {str(n.id): n for n in nodes}
        self.edges = edges
    def node(self, node_id):
        return self.nodes.get(str(node_id))
    def neighbors(self, node_id):
        return self.edges.get(str(node_id), [])

def test_predicts_best_path_and_is_cycle_safe():
    a, b, c = uuid4(), uuid4(), uuid4()
    g = Graph(
        [Node(a,"a","device",.7), Node(b,"b","service",.9), Node(c,"c","database",.95)],
        {str(a): [Edge(b,"connects_to"), Edge(c,"writes")],
         str(b): [Edge(c,"hosts"), Edge(a,"depends_on")]}
    )
    result = AttackPathPredictor(g, {"service": .8, "database": .9}).predict(str(a), 3, 10)
    assert [x.node_external for x in result] == ["c", "b"]
    assert result[0].hops == 2
    assert result[0].path[-1]["relation"] == "hosts"

def test_rejects_invalid_inputs():
    a = uuid4()
    g = Graph([Node(a,"a","device",.7)], {})
    p = AttackPathPredictor(g)
    with pytest.raises(PredictionInputError):
        p.predict("not-a-uuid")
    with pytest.raises(PredictionInputError):
        p.predict(str(a), 0)
    with pytest.raises(PredictionInputError):
        p.predict(str(a), 3, 0)

def test_rejects_invalid_criticality():
    a = uuid4()
    g = Graph([Node(a,"a","device",1.5)], {})
    with pytest.raises(PredictionInputError):
        AttackPathPredictor(g).predict(str(a))

def test_geometric_mean_requires_all_three_signals():
    assert AttackPathPredictor._combine(.8,.8,.8) > 0
    assert AttackPathPredictor._combine(.8,0,.8) == 0
