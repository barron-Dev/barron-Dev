from uuid import uuid4

from cyclothone.twin.graph import CascadeSimulator, TwinEdge, TwinGraph, TwinNode


def node(criticality=0.5):
    return TwinNode(uuid4(), "device", str(uuid4()), criticality, {})


def test_digital_twin_simulation_is_deterministic():
    graph = TwinGraph()
    root, mid, critical = node(1.0), node(0.8), node(0.9)
    for item in (root, mid, critical):
        graph.add_node(item)
    graph.add_edge(TwinEdge(root.id, mid.id, "runs_on", 1.0, 0.8))
    graph.add_edge(TwinEdge(mid.id, critical.id, "controls", 1.0, 0.9))
    graph.finalize()

    simulator = CascadeSimulator(graph)
    first = simulator.simulate(root.id, action="isolate_host")
    second = simulator.simulate(root.id, action="isolate_host")

    assert first == second
    assert first["cascade_size"] == 2
    assert first["critical_impact"]


def test_digital_twin_rejects_invalid_graph_edges():
    graph = TwinGraph()
    root, target = node(), node()
    graph.add_node(root)
    graph.add_node(target)

    try:
        graph.add_edge(TwinEdge(root.id, uuid4(), "runs", 1.0, 0.5))
        raise AssertionError("orphan edge was accepted")
    except ValueError:
        pass

    try:
        graph.add_edge(TwinEdge(root.id, target.id, "runs", 11.0, 0.5))
        raise AssertionError("out-of-range weight was accepted")
    except ValueError:
        pass
