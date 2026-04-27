def detect_broadcast(rate):

    if rate > 5000:
        return "Broadcast storm detected"

    return "Normal"
    
def detect_broadcast_storm(rate):

    if rate > 5000:
        return "Broadcast Storm Detected"

    return "Normal"


def shutdown_port(ip, username, password, interface):
    """
    Shutdown a network port on a device to prevent broadcast storms.
    
    Args:
        ip (str): IP address of the device
        username (str): Username for device authentication
        password (str): Password for device authentication
        interface (str): Interface/port to shutdown
        
    Returns:
        str: Status message indicating success or failure
    """
    # TODO: Implement actual port shutdown logic
    # This would typically involve:
    # 1. Connecting to the device via SSH/Telnet
    # 2. Executing shutdown commands for the specified interface
    # 3. Verifying the shutdown was successful
    # 4. Logging the action
    
    return f"Port {interface} on device {ip} has been shutdown"


def protect_port(rate, ip, interface, username, password):

    if rate > 5000:

        shutdown_port(ip, username, password, interface)

        return "Port shutdown due to broadcast storm"