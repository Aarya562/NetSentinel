
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

HOST = "0.0.0.0"
PORT = 5050

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "connection_events.jsonl"


def record_event(client_ip, client_port):
    """Record a connection received by this collector."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": client_ip,
        "source_port": client_port,
        "destination": "NetSentinel-Collector",
        "event_type": "tcp_connection",
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")

    print("\nConnection recorded:")
    print(json.dumps(event, indent=2))


def main():
    print("NetSentinel Connection Collector")
    print(f"Listening on {HOST}:{PORT}")
    print(f"Events will be saved to: {LOG_FILE}")
    print("Press Ctrl+C to stop.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(10)

        while True:
            connection, address = server.accept()

            with connection:
                client_ip, client_port = address
                record_event(client_ip, client_port)

                # Send a small acknowledgement to the test client.
                connection.sendall(
                    b"NetSentinel received your test connection.\n"
                )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCollector stopped.")
    except OSError as error:
        print(f"\nCollector could not start: {error}")
        print("Check whether port 5050 is already in use.")
