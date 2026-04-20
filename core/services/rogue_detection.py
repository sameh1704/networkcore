


def detect_rogue_device(mac, known_devices):

    if mac not in known_devices:
        return "⚠ Rogue device detected"

    return "Device trusted"

