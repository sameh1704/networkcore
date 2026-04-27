import subprocess
import re
import time
from .snmp import snmp_get, snmp_walk, snmp_set

# OIDs for Cisco-specific Ping/Traceroute MIB (CISCO-PING-MIB)
# These are examples and might vary slightly per device/IOS version.
# A full implementation would involve more OIDs for configuration and results.
OID_PING_CTL_ROW_STATUS = "1.3.6.1.4.1.9.9.16.1.1.1.1.13" # cPingEntryStatus
OID_PING_CTL_IP_ADDR    = "1.3.6.1.4.1.9.9.16.1.1.1.1.2"  # cPingAddress
OID_PING_CTL_PROTOCOL   = "1.3.6.1.4.1.9.9.16.1.1.1.1.3"  # cPingProtocol (1=ip, 2=ipv6)
OID_PING_CTL_PACKET_SIZE= "1.3.6.1.4.1.9.9.16.1.1.1.1.4"  # cPingPacketSize
OID_PING_CTL_TIMEOUT    = "1.3.6.1.4.1.9.9.16.1.1.1.1.5"  # cPingTimeout
OID_PING_CTL_NUM_PROBES = "1.3.6.1.4.1.9.9.16.1.1.1.1.6"  # cPingNumProbes
OID_PING_RESULTS_MIN_RTT= "1.3.6.1.4.1.9.9.16.1.1.1.1.10" # cPingMinRtt
OID_PING_RESULTS_AVG_RTT= "1.3.6.1.4.1.9.9.16.1.1.1.1.11" # cPingAvgRtt
OID_PING_RESULTS_MAX_RTT= "1.3.6.1.4.1.9.9.16.1.1.1.1.12" # cPingMaxRtt
OID_PING_RESULTS_PKT_LOSS= "1.3.6.1.4.1.9.9.16.1.1.1.1.9" # cPingPacketLoss

# For Traceroute, similar OIDs exist under ciscoPingTraceRouteEntry
# OID_TRACEROUTE_IP_ADDR = "1.3.6.1.4.1.9.9.16.1.1.2.1.2" # cPingTraceRouteAddress

def ping_host(target_ip, count=4, timeout=1):
    """
    يقوم بعمل Ping لجهاز من الخادم الذي يعمل عليه الـ NMS.
    """
    try:
        # Use -n for Windows, -c for Linux/macOS
        param = '-n' if subprocess.platform.startswith('win') else '-c'
        command = ['ping', param, str(count), '-w', str(int(timeout*1000)), target_ip]
        
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout * count + 1)
        
        if result.returncode == 0:
            # Parse output for RTT and packet loss
            rtt_match = re.search(r'Average = (\d+)ms', result.stdout) # Windows
            if not rtt_match:
                rtt_match = re.search(r'avg\/stddev\/mdev = [\d.]+\/([\d.]+)', result.stdout) # Linux
            
            loss_match = re.search(r'(\d+)% packet loss', result.stdout)
            
            avg_rtt = int(rtt_match.group(1)) if rtt_match else None
            packet_loss = int(loss_match.group(1)) if loss_match else 100
            
            return {
                "status": "success",
                "target_ip": target_ip,
                "avg_rtt_ms": avg_rtt,
                "packet_loss_percent": packet_loss,
                "output": result.stdout.strip()
            }
        else:
            return {
                "status": "failed",
                "target_ip": target_ip,
                "error": result.stderr.strip() or result.stdout.strip(),
                "packet_loss_percent": 100,
            }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "target_ip": target_ip,
            "error": "Ping timed out",
            "packet_loss_percent": 100,
        }
    except Exception as e:
        return {
            "status": "error",
            "target_ip": target_ip,
            "error": str(e),
            "packet_loss_percent": 100,
        }

def ping_from_switch(switch_ip, community, target_ip, count=3, timeout_ms=2000):
    """
    يقوم بعمل Ping من السويتش إلى جهاز آخر باستخدام SNMP.
    (هذه وظيفة mock وتحتاج إلى OIDs محددة للجهاز)
    """
    # In a real scenario, you would use snmp_set to create a cPingEntry,
    # then snmp_get to read results, and finally snmp_set to delete the entry.
    # This is a simplified mock.
    print(f"Mocking ping from {switch_ip} to {target_ip}...")
    time.sleep(1) # Simulate network delay
    
    if target_ip.endswith("1"): # Simulate gateway being reachable
        return {
            "status": "success",
            "target_ip": target_ip,
            "min_rtt_ms": 1,
            "avg_rtt_ms": 2,
            "max_rtt_ms": 3,
            "packet_loss_percent": 0,
            "message": "Ping successful from switch."
        }
    else:
        return {
            "status": "failed",
            "target_ip": target_ip,
            "error": "Destination Host Unreachable (mock)",
            "packet_loss_percent": 100,
            "message": "Ping failed from switch."
        }

def traceroute_from_switch(switch_ip, community, target_ip, max_hops=30, timeout_ms=3000):
    """
    يقوم بعمل Traceroute من السويتش إلى جهاز آخر باستخدام SNMP.
    (هذه وظيفة mock وتحتاج إلى OIDs محددة للجهاز)
    """
    print(f"Mocking traceroute from {switch_ip} to {target_ip}...")
    time.sleep(2) # Simulate network delay
    
    mock_hops = []
    if target_ip.startswith("192.168.70"):
        mock_hops.append({"hop": 1, "ip": "192.168.70.1", "rtt_ms": 1})
        mock_hops.append({"hop": 2, "ip": target_ip, "rtt_ms": 5})
        status = "success"
    else:
        mock_hops.append({"hop": 1, "ip": "192.168.70.1", "rtt_ms": 1})
        mock_hops.append({"hop": 2, "ip": "10.0.0.1", "rtt_ms": 10})
        mock_hops.append({"hop": 3, "ip": "*", "rtt_ms": None}) # Simulate timeout
        status = "partial"

    return {
        "status": status,
        "target_ip": target_ip,
        "hops": mock_hops,
        "message": "Traceroute results (mock)."
    }