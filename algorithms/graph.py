
class Graph:
    def __init__(self):
        # Store each device and its connected devices
        self.adjacency_list = {}

    def add_node(self, node):
        if node not in self.adjacency_list:
            self.adjacency_list[node] = []

    def add_edge(self, source, destination):
        self.add_node(source)
        self.add_node(destination)

        if destination not in self.adjacency_list[source]:
            self.adjacency_list[source].append(destination)

        if source not in self.adjacency_list[destination]:
            self.adjacency_list[destination].append(source)

    def display(self):
        print("\nNetwork Connections:")
        for node, neighbours in self.adjacency_list.items():
            print(f"{node} -> {neighbours}")
