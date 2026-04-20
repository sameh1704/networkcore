from .cdp import get_cdp_neighbors


def build_topology(switches):

    topology = []

    for sw in switches:

        neighbors = get_cdp_neighbors(sw.ip_address, sw.snmp_community)

        for n in neighbors:

            topology.append({
                "source": sw.hostname,
                "target": n
            })

    return topology