"""
Passive real-time port throughput sampling with optional iperf3 probing.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from datetime import datetime

from core.services import switch_inspector
from core.services.snmp import clear_cache as clear_snmp_cache
from core.services.switch_inspector import get_interfaces_detail


class IPerfTest:
    def __init__(self, server_ip="127.0.0.1", server_port=5201):
        self.server_ip = server_ip
        self.server_port = server_port

    def run_test(self, duration: int = 10, reverse: bool = False) -> dict:
        if not shutil.which("iperf3"):
            return {"success": False, "error": "iperf3 is not installed on the server"}

        cmd = [
            "iperf3",
            "-c",
            self.server_ip,
            "-p",
            str(self.server_port),
            "-t",
            str(duration),
            "-J",
        ]
        if reverse:
            cmd.append("-R")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration + 5,
            )
            if result.returncode != 0:
                return {"success": False, "error": (result.stderr or result.stdout).strip()}
            return self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "iperf3 test timed out"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _parse_output(self, output: str) -> dict:
        try:
            data = json.loads(output)
            sent = (data.get("end") or {}).get("sum_sent") or {}
            received = (data.get("end") or {}).get("sum_received") or {}
            bps = sent.get("bits_per_second") or received.get("bits_per_second") or 0
            return {
                "success": True,
                "speed_mbps": round(bps / 1_000_000, 2),
                "retransmits": sent.get("retransmits", 0),
                "loss_percent": received.get("lost_percent", 0),
            }
        except json.JSONDecodeError:
            match = re.search(r"([\d.]+)\s+([GMK])bits/sec", output)
            if not match:
                return {"success": False, "error": "Unable to parse iperf3 output"}

            speed = float(match.group(1))
            unit = match.group(2)
            if unit == "G":
                speed *= 1000
            elif unit == "K":
                speed /= 1000
            return {"success": True, "speed_mbps": round(speed, 2)}


def sample_port_traffic(switch, port_name: str, duration_seconds: int = 12, interval_seconds: int = 2) -> dict:
    duration_seconds = max(6, min(int(duration_seconds or 12), 120))
    interval_seconds = max(1, min(int(interval_seconds or 2), 10))

    samples = []
    deadline = time.time() + duration_seconds
    previous = _read_port_counters(switch, port_name)
    if not previous:
        return {
            "success": False,
            "port": port_name,
            "error": f"Port {port_name} was not found on switch {switch.hostname}",
            "samples": [],
        }

    while time.time() < deadline:
        time.sleep(interval_seconds)
        current = _read_port_counters(switch, port_name)
        if not current:
            continue

        delta_seconds = max(current["timestamp"] - previous["timestamp"], 1e-6)
        in_delta = max(current["in_octets"] - previous["in_octets"], 0)
        out_delta = max(current["out_octets"] - previous["out_octets"], 0)
        in_mbps = (in_delta * 8) / delta_seconds / 1_000_000
        out_mbps = (out_delta * 8) / delta_seconds / 1_000_000
        total_mbps = in_mbps + out_mbps
        utilization = 0
        if current["speed_bps"] > 0:
            utilization = round((total_mbps * 1_000_000 / current["speed_bps"]) * 100, 2)

        samples.append({
            "time": datetime.utcnow().isoformat(),
            "in_mbps": round(in_mbps, 2),
            "out_mbps": round(out_mbps, 2),
            "total_mbps": round(total_mbps, 2),
            "utilization_percent": utilization,
        })
        previous = current

    totals = [sample["total_mbps"] for sample in samples]
    return {
        "success": True,
        "port": port_name,
        "switch": switch.hostname,
        "duration_seconds": duration_seconds,
        "interval_seconds": interval_seconds,
        "samples": samples,
        "current_speed_mbps": round(totals[-1], 2) if totals else 0,
        "average_speed_mbps": round(sum(totals) / len(totals), 2) if totals else 0,
        "peak_speed_mbps": round(max(totals), 2) if totals else 0,
        "timestamp": datetime.utcnow().isoformat(),
    }


def _read_port_counters(switch, port_name: str) -> dict | None:
    clear_snmp_cache(switch.ip_address)
    switch_inspector._CACHE.pop(f"ifaces:{switch.ip_address}", None)
    interfaces = get_interfaces_detail(switch.ip_address, switch.snmp_community) or []
    for interface in interfaces:
        if interface.get("name") == port_name:
            return {
                "timestamp": time.time(),
                "in_octets": int(interface.get("in_octets") or 0),
                "out_octets": int(interface.get("out_octets") or 0),
                "speed_bps": int(interface.get("speed_bps") or 0),
            }
    return None


def test_port_speed(
    switch,
    port_name: str,
    target_ip: str | None = None,
    duration_seconds: int = 12,
    interval_seconds: int = 2,
) -> dict:
    passive = sample_port_traffic(
        switch,
        port_name,
        duration_seconds=duration_seconds,
        interval_seconds=interval_seconds,
    )

    result = {
        "port": port_name,
        "switch": switch.hostname,
        "target_ip": target_ip,
        "passive": passive,
        "download": {},
        "upload": {},
        "timestamp": datetime.utcnow().isoformat(),
    }

    if target_ip:
        iperf = IPerfTest(server_ip=target_ip)
        result["download"] = iperf.run_test(duration=min(duration_seconds, 30), reverse=False)
        result["upload"] = iperf.run_test(duration=min(duration_seconds, 30), reverse=True)

    if passive.get("success"):
        result["current_speed_mbps"] = passive.get("current_speed_mbps", 0)
        result["average_speed_mbps"] = passive.get("average_speed_mbps", 0)
        result["peak_speed_mbps"] = passive.get("peak_speed_mbps", 0)

    return result
