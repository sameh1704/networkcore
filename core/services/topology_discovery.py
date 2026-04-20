from graphviz import Graph
from .snmp import snmp_walk

# CDP neighbor OID
OID_CDP_NEIGHBOR = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"

# LLDP neighbor OID
OID_LLDP_NEIGHBOR = "1.0.8802.1.1.2.1.4.1.1.9"


def discover_neighbors(ip, community):

    neighbors = []

    cdp = snmp_walk(ip, community, OID_CDP_NEIGHBOR)
    lldp = snmp_walk(ip, community, OID_LLDP_NEIGHBOR)

    if cdp:
        neighbors.extend(cdp)

    if lldp:
        neighbors.extend(lldp)

    return neighbors


def generate_topology(switches):

    g = Graph("Network Topology")

    for sw in switches:

        g.node(sw.hostname)

        neighbors = discover_neighbors(sw.ip_address, sw.snmp_community)

        for n in neighbors:

            g.edge(sw.hostname, n)

    g.render("/app/topology", view=False)

    return "/app/topology.png"


def build_topology(switches):

    links = []

    for sw in switches:

        neighbors = discover_neighbors(sw.ip_address, sw.snmp_community)

        for n in neighbors:

            links.append({
                "source": sw.hostname,
                "target": n
            })

    return links