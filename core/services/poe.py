from .snmp import snmp_get


OID_POE_USED = "1.3.6.1.4.1.9.9.402.1.2.1.7.1"


def get_poe_usage(ip, community):

    power = snmp_get(ip, community, OID_POE_USED)

    return power