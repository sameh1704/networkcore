def detect_broadcast(rate):

    if rate > 5000:
        return "Broadcast storm detected"

    return "Normal"
    
def detect_broadcast_storm(rate):

    if rate > 5000:
        return "Broadcast Storm Detected"

    return "Normal"


def protect_port(rate, ip, interface, username, password):

    if rate > 5000:

        shutdown_port(ip, username, password, interface)

        return "Port shutdown due to broadcast storm"