from .snmp import snmp_walk
from core.models import Switch

OID_CDP_IP = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
OID_CDP_NAME = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"

OID_LLDP_IP = "1.0.8802.1.1.2.1.4.2.1.4"
OID_LLDP_NAME = "1.0.8802.1.1.2.1.4.1.1.9"


def smart_discovery(seed_ip, community):

    discovered = []

    try:

        cdp_names = snmp_walk(seed_ip, community, OID_CDP_NAME)
        cdp_ips = snmp_walk(seed_ip, community, OID_CDP_IP)

        for i in range(len(cdp_names)):

            hostname = cdp_names[i]
            ip = cdp_ips[i]

            sw, created = Switch.objects.get_or_create(
                ip_address=ip,
                defaults={"hostname": hostname}
            )
 
            discovered.append({
                "hostname": hostname,
                "ip": ip
            })

    except:
        pass

    try:

        lldp_names = snmp_walk(seed_ip, community, OID_LLDP_NAME)
        lldp_ips = snmp_walk(seed_ip, community, OID_LLDP_IP)

        for i in range(len(lldp_names)):

            hostname = lldp_names[i]
            ip = lldp_ips[i]

            sw, created = Switch.objects.get_or_create(
                ip_address=ip,
                defaults={"hostname": hostname}
            )

            discovered.append({
                "hostname": hostname,
                "ip": ip
            })

    except:
        pass

    return discovered