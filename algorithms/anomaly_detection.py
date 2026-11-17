
from collections import defaultdict, deque


def detect_suspicious_connections(events, window_size=5, threshold=3):
    """
    Detect devices contacting many distinct destinations
    within a sliding window of recent events.

    window_size: Number of events considered in each window.
    threshold: Minimum distinct destinations to trigger an alert.
    """

    recent_events = defaultdict(deque)
    alerts = []

    for event in events:
        source = event["source"]
        destination = event["destination"]
        timestamp = event["timestamp"]

        # Store each event for its source device
        device_events = recent_events[source]
        device_events.append((timestamp, destination))

        # Keep only events inside the time window
        while (
            device_events
            and timestamp - device_events[0][0] >= window_size
        ):
            device_events.popleft()

        # Count distinct destinations using a set
        destinations = {
            dest for _, dest in device_events
        }

        if len(destinations) >= threshold:
            alerts.append({
                "device": source,
                "timestamp": timestamp,
                "distinct_destinations": len(destinations),
                "destinations": sorted(destinations),
                "reason": (
                    "Contacted many distinct devices "
                    "within a short time window"
                )
            })

    return alerts


if __name__ == "__main__":
    # Simulated network events
    sample_events = [
        {"timestamp": 1, "source": "PC1", "destination": "PC2"},
        {"timestamp": 2, "source": "PC1", "destination": "PC3"},
        {"timestamp": 3, "source": "PC1", "destination": "PC4"},
        {"timestamp": 4, "source": "PC2", "destination": "PC3"},
        {"timestamp": 5, "source": "PC1", "destination": "PC5"},
    ]

    alerts = detect_suspicious_connections(
        sample_events,
        window_size=5,
        threshold=3
    )

    print("Suspicious Activity Alerts:")

    if not alerts:
        print("No suspicious patterns detected.")
    else:
        for alert in alerts:
            print(alert)
