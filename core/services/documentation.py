def generate_network_doc(switches):

    report = []

    for sw in switches:

        report.append({
            "hostname": sw.hostname,
            "ip": sw.ip_address,
            "interfaces": sw.interface_set.count()
        })

    return report