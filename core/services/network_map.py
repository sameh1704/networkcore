import matplotlib.pyplot as plt
import networkx as nx


def draw_network(graph):

    plt.figure(figsize=(12, 8))

    pos = nx.spring_layout(graph)

    nx.draw(
        graph,
        pos,
        with_labels=True,
        node_size=3000,
        node_color="lightblue",
        font_size=10
    )

    plt.savefig("/app/static/topology.png")
