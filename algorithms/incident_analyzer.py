from algorithms.graph import Graph
from algorithms.traversal import bfs
from algorithms.anomaly_detection import detect_suspicious_connections

def analyze_network(events, investigation_device):
    # Step 1: Build the network graph
    network = Graph()

    for event in events:
        network.add_edge(
            event["source"],
            event["destination"]
        )

    # Step 2: Detect suspicious activity
    alerts = detect_suspicious_connections(
        events,
        window_size=5,
        threshold=3
    )

    # Step 3: Find reachable devices
    reachable_devices = bfs(network, investigation_device)

    # Step 4: Return the complete analysis
    return {
        "total_devices": len(network.adjacency_list),
        "total_connections": sum(
            len(neighbours)
            for neighbours in network.adjacency_list.values()
        ) // 2,
        "investigation_device": investigation_device,
        "reachable_devices": reachable_devices,
        "alerts": alerts
    }


if __name__ == "__main__":
    # Simulated network events
    sample_events = [
        {"timestamp": 1, "source": "PC1", "destination": "PC2"},
        {"timestamp": 2, "source": "PC1", "destination": "PC3"},
        {"timestamp": 3, "source": "PC1", "destination": "PC4"},
        {"timestamp": 4, "source": "PC2", "destination": "PC5"},
        {"timestamp": 5, "source": "PC3", "destination": "PC5"},
    ]

    result = analyze_network(sample_events, "PC1")

    print("\n========== NetSentinel Report ==========")
    print("Total devices:", result["total_devices"])
    print("Total connections:", result["total_connections"])
    print("Investigation device:", result["investigation_device"])
    print("Reachable devices:", result["reachable_devices"])

    print("\nSuspicious Activity Alerts:")

    if result["alerts"]:
        for alert in result["alerts"]:
            print(
                f"Device: {alert['device']} | "
                f"Destinations: {alert['destinations']} | "
                f"Reason: {alert['reason']}"
            )
    else:
        print("No suspicious patterns detected.")

    print("\n========================================")
