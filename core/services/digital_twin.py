def build_network_model(switches):

    model = []

    for sw in switches:

        model.append({
            "hostname": sw.hostname,
            "interfaces": sw.interface_set.count(),
        })

    return model