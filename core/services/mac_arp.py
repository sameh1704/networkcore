def correlate(mac_table, arp_table):

    devices = []

    for mac in mac_table:

        for arp in arp_table:

            if mac["mac"] == arp["mac"]:

                devices.append({
                    "ip": arp["ip"],
                    "mac": mac["mac"],
                    "port": mac["port"],
                    "vlan": mac["vlan"]
                })

    return devices