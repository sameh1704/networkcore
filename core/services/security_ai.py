def detect_attack(packet_rate):

    if packet_rate > 100000:
        return "⚠ Possible network attack"

    return "Traffic normal"