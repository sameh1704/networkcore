def build_errors_heatmap(errors):

    heatmap = []

    for e in errors:
        heatmap.append({
            "interface": e.interface.name,
            "crc": e.crc_errors
        })

    return heatmap