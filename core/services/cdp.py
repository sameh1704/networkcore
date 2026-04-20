from .snmp import snmp_walk


OID_CDP_DEVICE = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"


def get_cdp_neighbors(ip, community):

    neighbors = snmp_walk(ip, community, OID_CDP_DEVICE)

    return neighbors



# core/services/cdp.py

def get_switch_ports_info(switch_name):
    """
    استرجاع حالة المنافذ لكل سويتش
    كل عنصر: port, status, vlan
    """
    # مثال وهمي، يمكن ربط SNMP لاحقاً
    return [
        {'port': 'Fa0/1', 'status': 'up', 'vlan': 10},
        {'port': 'Fa0/2', 'status': 'down', 'vlan': 20},
        {'port': 'Fa0/3', 'status': 'up', 'vlan': 30},
    ]