
from collections import deque
from algorithms.graph import Graph

# Breadth-First Search (BFS)
def bfs(graph, start):
    if start not in graph.adjacency_list:
        return []

    visited = {start}
    queue = deque([start])
    order = []

    while queue:
        current = queue.popleft()
        order.append(current)

        for neighbour in graph.adjacency_list[current]:
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append(neighbour)

    return order


# Depth-First Search (DFS)
def dfs(graph, start):
    if start not in graph.adjacency_list:
        return []

    visited = set()
    stack = [start]
    order = []

    while stack:
        current = stack.pop()

        if current in visited:
            continue

        visited.add(current)
        order.append(current)

        for neighbour in reversed(graph.adjacency_list[current]):
            if neighbour not in visited:
                stack.append(neighbour)

    return order


# Network Impact Analysis
def find_reachable_devices(graph, start):
    """
    Find all devices reachable from the selected device.
    """
    return bfs(graph, start)


# Test the algorithms
if __name__ == "__main__":
    network = Graph()

    network.add_edge("PC1", "PC2")
    network.add_edge("PC1", "PC3")
    network.add_edge("PC2", "PC4")
    network.add_edge("PC3", "PC5")

    network.display()

    print("\nBFS:", bfs(network, "PC1"))
    print("DFS:", dfs(network, "PC1"))

    print(
        "Potentially reachable devices from PC1:",
        find_reachable_devices(network, "PC1")
    )
