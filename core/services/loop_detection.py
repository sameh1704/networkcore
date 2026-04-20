from netmiko import ConnectHandler


def detect_loop(mac_flaps, broadcast_rate):

    problems = []

    if mac_flaps > 50:
        problems.append("Possible network loop (MAC flapping)")

    if broadcast_rate > 10000:
        problems.append("Broadcast storm detected")

    return problems


def shutdown_port(ip, username, password, interface):

    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
    }

    connection = ConnectHandler(**device)

    connection.send_config_set([
        f"interface {interface}",
        "shutdown"
    ])

    return "Port shutdown to isolate loop"

