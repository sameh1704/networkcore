from netmiko import ConnectHandler


def run_tdr(ip, username, password, interface):

    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
    }

    connection = ConnectHandler(**device)

    connection.send_command(f"test cable-diagnostics tdr interface {interface}")

    result = connection.send_command(
        f"show cable-diagnostics tdr interface {interface}"
    )

    return result


