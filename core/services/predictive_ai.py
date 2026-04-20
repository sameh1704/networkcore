import statistics


def predict_cable_failure(crc_history):

    if len(crc_history) < 5:
        return "Not enough data"

    trend = crc_history[-1] - crc_history[0]

    if trend > 50:
        return "⚠ Cable degradation detected"

    return "Cable healthy"


def predict_port_overload(traffic_history):

    avg = statistics.mean(traffic_history)

    if avg > 800000000:  # 800 Mbps
        return "⚠ Port may overload soon"

    return "Normal"


def predict_broadcast_storm(broadcast_history):

    if max(broadcast_history) > 5000:
        return "⚠ Broadcast storm risk"

    return "Normal"


def predict_cpu_crash(cpu_history):

    avg = statistics.mean(cpu_history)

    if avg > 85:
        return "⚠ CPU overload risk"

    return "CPU healthy"



