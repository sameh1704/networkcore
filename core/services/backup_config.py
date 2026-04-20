



from netmiko import ConnectHandler


def backup_switch_config(ip, username, password):

    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
    }

    connection = ConnectHandler(**device)

    config = connection.send_command("show running-config")

    file = f"/app/backups/{ip}.cfg"

    with open(file, "w") as f:
        f.write(config)

    return file