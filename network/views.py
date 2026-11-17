
import json
from datetime import datetime
from pathlib import Path

from django.shortcuts import render

from algorithms.graph import Graph
from algorithms.traversal import bfs, dfs
from algorithms.anomaly_detection import detect_suspicious_connections


# Project directory: D:\DS\netsenitel
BASE_DIR = Path(__file__).resolve().parent.parent

# JSONL file written by connection_collector.py
EVENT_LOG = BASE_DIR / "connection_events.jsonl"


def load_events():
    """
    Load recorded TCP connection events.
    Invalid or incomplete log lines are skipped.
    """
    events = []

    if not EVENT_LOG.exists():
        return events

    with EVENT_LOG.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                record = json.loads(line)

                timestamp_text = record["timestamp"]

                timestamp = datetime.fromisoformat(
                    timestamp_text.replace("Z", "+00:00")
                ).timestamp()

                source = str(record["source"])
                destination = str(record["destination"])

                events.append({
                    "timestamp": timestamp,
                    "source": source,
                    "destination": destination,
                })

            except (
                ValueError,
                KeyError,
                TypeError,
                json.JSONDecodeError,
            ):
                continue

    return events


def dashboard(request):
    """
    Prepare data for the NetSentinel security dashboard.
    """

    # 1. Load real events or use clearly labelled simulation data.
    events = load_events()

    if events:
        data_mode = "Recorded TCP connection events"
    else:
        data_mode = "Demo data — simulated network"

        events = [
            {
                "timestamp": 1,
                "source": "PC1",
                "destination": "PC2",
            },
            {
                "timestamp": 2,
                "source": "PC1",
                "destination": "PC3",
            },
            {
                "timestamp": 3,
                "source": "PC1",
                "destination": "PC4",
            },
            {
                "timestamp": 4,
                "source": "PC2",
                "destination": "PC5",
            },
            {
                "timestamp": 5,
                "source": "PC3",
                "destination": "PC5",
            },
        ]

    # 2. Construct the network graph.
    graph = Graph()

    for event in events:
        graph.add_edge(
            event["source"],
            event["destination"],
        )

    devices = list(graph.adjacency_list.keys())

    # Each undirected edge is counted only once.
    connections = sum(
        len(neighbours)
        for neighbours in graph.adjacency_list.values()
    ) // 2

    # 3. Run BFS and DFS from the first observed device.
    start_device = devices[0] if devices else None

    bfs_result = (
        bfs(graph, start_device)
        if start_device
        else []
    )

    dfs_result = (
        dfs(graph, start_device)
        if start_device
        else []
    )

    # 4. Detect suspicious connection patterns.
    alerts = detect_suspicious_connections(
        events,
        window_size=5,
        threshold=3,
    )

    # 5. Generate unique edges for the topology display.
    topology_edges = []
    seen_edges = set()

    for source, neighbours in graph.adjacency_list.items():
        for destination in neighbours:
            edge_key = frozenset((source, destination))

            if edge_key not in seen_edges:
                seen_edges.add(edge_key)

                topology_edges.append({
                    "source": source,
                    "destination": destination,
                })

    # 6. Prepare the most recent 20 events.
    recent_events = []

    for event in reversed(events[-20:]):
        recent_events.append({
            "source": event["source"],
            "destination": event["destination"],
            "time": datetime.fromtimestamp(
                event["timestamp"]
            ).strftime("%H:%M:%S"),
        })

    # 7. Send the data to dashboard.html.
    context = {
        "data_mode": data_mode,
        "devices": devices,
        "connections": connections,
        "events_count": len(events),
        "alerts": alerts,
        "topology_edges": topology_edges,
        "bfs_result": bfs_result,
        "dfs_result": dfs_result,
        "recent_events": recent_events,
    }

    return render(
        request,
        "network/dashboard.html",
        context,
    )
