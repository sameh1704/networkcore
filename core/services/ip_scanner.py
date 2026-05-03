"""
Switch-aware IP and endpoint discovery helpers.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import subprocess
from datetime import datetime

from django.core.cache import cache

from core.models import ARPTable, MACTable
from core.services.snmp import extract_ip_from_octet, extract_mac_from_octet, snmp_walk_with_index
from core.services.switch_inspector import get_interfaces_detail, get_mac_table

OUI_MAP = {
    "00:19:8c": "Tiandy",
    "00:23:8c": "Tiandy",
    "4c:11:ae": "Hikvision",
    "c0:56:e3": "Hikvision",
    "7c:b5:9b": "Dahua",
    "9c:8e:cd": "Dahua",
    "00:0c:43": "Axis",
    "ac:cc:8e": "Axis",
}


def _normalize_mac(value: str) -> str:
    raw = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if len(raw) != 12:
        return ""
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2)).lower()


def _vendor_for_mac(mac: str) -> str:
    return OUI_MAP.get((mac or "").lower()[:8], "Unknown")


class AdvancedIPScanner:
    def __init__(self, community="public"):
        self.community = community

    def scan_network(self, network_cidr: str, max_workers=50, timeout=1) -> dict:
        cache_key = f"ip_scan:{network_cidr}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        network = ipaddress.ip_network(network_cidr, strict=False)
        devices = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._ping_host, str(ip), timeout): str(ip)
                for ip in network.hosts()
            }
            for future in concurrent.futures.as_completed(futures):
                device = future.result()
                if device:
                    devices.append(device)

        devices.sort(key=lambda item: tuple(int(part) for part in item["ip"].split(".")))
        result = {
            "mode": "network_scan",
            "network": network_cidr,
            "total_hosts": network.num_addresses - 2 if network.num_addresses >= 2 else network.num_addresses,
            "active_hosts": len(devices),
            "devices": devices,
            "scan_time": datetime.utcnow().isoformat(),
        }
        cache.set(cache_key, result, 60)
        return result

    def discover_switch_devices(self, switch, network_cidr: str | None = None, refresh_arp: bool = False) -> dict:
        cidr = (network_cidr or "").strip() or self._default_network_from_switch(switch.ip_address)
        cache_key = f"switch_ip_discovery:{switch.id}:{cidr}:{int(refresh_arp)}"
        cached = cache.get(cache_key)
        if cached and not refresh_arp:
            return cached

        # The primary source of truth is the switch MAC/ARP/VLAN tables.
        # Optional subnet probing is only used to populate ARP when requested.
        if refresh_arp and cidr:
            self._seed_arp_table(cidr)

        interfaces = get_interfaces_detail(switch.ip_address, switch.snmp_community) or []
        ports = {item["name"]: item for item in interfaces}
        mac_rows = self._load_mac_rows(switch)
        arp_map = self._load_arp_map(switch, mac_rows)

        interesting_macs = {
            _normalize_mac(row.get("mac"))
            for row in mac_rows
            if _normalize_mac(row.get("mac"))
        }
        if interesting_macs and len(arp_map) < max(3, int(len(interesting_macs) * 0.3)):
            fallback_map = self._resolve_from_neighbor_scan(cidr, interesting_macs)
            for mac, ip_addresses in fallback_map.items():
                arp_map.setdefault(mac, set()).update(ip_addresses)

        gateway_candidates = self._gateway_candidates(cidr)
        devices = []
        ports_summary = {}
        seen = set()
        for row in mac_rows:
            mac = _normalize_mac(row.get("mac"))
            port = str(row.get("port") or "").strip()
            vlan_id = row.get("vlan_id")
            row_type = str(row.get("type") or "learned").lower()

            if not mac or not port or row_type in {"self", "invalid"}:
                continue

            key = (mac, port, vlan_id)
            if key in seen:
                continue
            seen.add(key)

            interface = ports.get(port, {})
            ip_addresses = self._select_preferred_ips(
                arp_map.get(mac, set()),
                switch_ip=switch.ip_address,
                gateway_candidates=gateway_candidates,
            )
            current_mbps = round(float(interface.get("traffic_mbps") or 0), 2)

            devices.append({
                "ip_address": ip_addresses[0] if ip_addresses else "Unresolved",
                "ip_addresses": ip_addresses,
                "mac_address": mac,
                "vlan_id": vlan_id,
                "port": port,
                "port_status": interface.get("status") or "unknown",
                "port_speed": interface.get("speed_str") or self._speed_to_label(interface.get("speed_bps")),
                "current_traffic_mbps": current_mbps,
                "vendor": _vendor_for_mac(mac),
                "entry_type": row_type,
                "alias": interface.get("alias") or "",
            })

            summary = ports_summary.setdefault(port, {
                "port": port,
                "alias": interface.get("alias") or "",
                "vlan_id": vlan_id,
                "port_status": interface.get("status") or "unknown",
                "port_speed": interface.get("speed_str") or self._speed_to_label(interface.get("speed_bps")),
                "current_traffic_mbps": current_mbps,
                "mac_addresses": set(),
                "ip_addresses": set(),
                "vendors": set(),
            })
            if summary["vlan_id"] is None and vlan_id is not None:
                summary["vlan_id"] = vlan_id
            summary["mac_addresses"].add(mac)
            summary["ip_addresses"].update(ip_addresses)
            summary["vendors"].add(_vendor_for_mac(mac))

        devices.sort(key=lambda item: (
            item["vlan_id"] if item["vlan_id"] is not None else 99999,
            self._natural_port_key(item["port"]),
            self._ip_sort_key(item["ip_address"]),
            item["mac_address"],
        ))

        grouped_ports = []
        for port, summary in ports_summary.items():
            grouped_ports.append({
                "port": port,
                "alias": summary["alias"],
                "vlan_id": summary["vlan_id"],
                "port_status": summary["port_status"],
                "port_speed": summary["port_speed"],
                "current_traffic_mbps": summary["current_traffic_mbps"],
                "mac_addresses": sorted(summary["mac_addresses"]),
                "ip_addresses": sorted(summary["ip_addresses"], key=self._ip_sort_key),
                "vendors": sorted(summary["vendors"]),
                "device_count": len(summary["mac_addresses"]),
            })

        grouped_ports.sort(key=lambda item: (
            item["vlan_id"] if item["vlan_id"] is not None else 99999,
            self._natural_port_key(item["port"]),
        ))

        result = {
            "mode": "switch_scan",
            "switch": {
                "id": switch.id,
                "hostname": switch.hostname,
                "ip_address": switch.ip_address,
            },
            "network": cidr,
            "discovery_source": "switch_mac_arp_vlan_tables",
            "generated_at": datetime.utcnow().isoformat(),
            "total_devices": len(devices),
            "resolved_ip_count": sum(1 for item in devices if item["ip_address"] != "Unresolved"),
            "mac_count": len({item["mac_address"] for item in devices}),
            "vlan_count": len({item["vlan_id"] for item in devices if item["vlan_id"] is not None}),
            "devices": devices,
            "ports": grouped_ports,
        }
        cache.set(cache_key, result, 45)
        return result

    def _load_mac_rows(self, switch) -> list[dict]:
        rows = []

        try:
            rows.extend((get_mac_table(switch.ip_address, switch.snmp_community, limit=5000) or {}).get("mac_table", []))
        except Exception:
            pass

        if not rows:
            rows.extend([
                {
                    "mac": row["mac_address"],
                    "port": row["interface"],
                    "vlan_id": row["vlan"],
                    "type": "cached",
                }
                for row in MACTable.objects.filter(switch=switch).values("mac_address", "interface", "vlan")
            ])

        return rows

    def _load_arp_map(self, switch, mac_rows: list[dict]) -> dict[str, set[str]]:
        interesting_vlans = {
            int(row["vlan_id"])
            for row in mac_rows
            if row.get("vlan_id") is not None and str(row.get("vlan_id")).isdigit()
        }
        arp_map: dict[str, set[str]] = {}

        def merge_rows(community: str):
            mac_rows_local = snmp_walk_with_index(
                switch.ip_address,
                community,
                "1.3.6.1.2.1.4.22.1.2",
                timeout=3,
            ) or []
            ip_rows_local = snmp_walk_with_index(
                switch.ip_address,
                community,
                "1.3.6.1.2.1.4.22.1.3",
                timeout=3,
            ) or []

            ip_by_suffix = {}
            for suffix, value in ip_rows_local:
                ip_addr = extract_ip_from_octet(value)
                if ip_addr:
                    ip_by_suffix[suffix] = ip_addr
                    continue

                suffix_ip = self._ip_from_suffix(suffix)
                if suffix_ip:
                    ip_by_suffix[suffix] = suffix_ip

            for suffix, value in mac_rows_local:
                mac = _normalize_mac(extract_mac_from_octet(value))
                ip_addr = ip_by_suffix.get(suffix)
                if mac and ip_addr:
                    arp_map.setdefault(mac, set()).add(ip_addr)

        try:
            merge_rows(switch.snmp_community)
        except Exception:
            pass

        for vlan_id in sorted(interesting_vlans):
            try:
                merge_rows(f"{switch.snmp_community}@{vlan_id}")
            except Exception:
                continue

        for row in ARPTable.objects.filter(switch=switch).values("mac_address", "ip_address"):
            normalized = _normalize_mac(row["mac_address"])
            if normalized:
                arp_map.setdefault(normalized, set()).add(str(row["ip_address"]))

        return arp_map

    def _resolve_from_neighbor_scan(self, network_cidr: str, interesting_macs: set[str], timeout: int = 1) -> dict[str, set[str]]:
        if not network_cidr or not interesting_macs:
            return {}

        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError:
            return {}

        hosts = [str(ip) for ip in list(network.hosts())[:512]]
        if not hosts:
            return {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
            futures = [executor.submit(self._ping_host, ip, timeout, include_metadata=False) for ip in hosts]
            for future in concurrent.futures.as_completed(futures):
                future.result()

        resolved: dict[str, set[str]] = {}
        for ip_addr in hosts:
            mac = self._lookup_neighbor_mac(ip_addr)
            if not mac or mac not in interesting_macs:
                continue
            resolved.setdefault(mac, set()).add(ip_addr)

        return resolved

    def _lookup_neighbor_mac(self, ip_addr: str) -> str | None:
        commands = [
            ["ip", "neigh", "show", ip_addr],
            ["arp", "-n", ip_addr],
        ]

        for command in commands:
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=2)
            except Exception:
                continue

            output = f"{result.stdout}\n{result.stderr}"
            mac_match = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", output, re.I)
            if mac_match:
                return mac_match.group(1).lower()

        return None

    def _ip_from_suffix(self, suffix: str) -> str | None:
        parts = re.findall(r"\d+", str(suffix))
        if len(parts) < 4:
            return None

        last_four = parts[-4:]
        try:
            octets = [int(part) for part in last_four]
        except ValueError:
            return None

        if all(0 <= octet <= 255 for octet in octets):
            return ".".join(str(octet) for octet in octets)

        return None

    def _seed_arp_table(self, network_cidr: str, max_hosts: int = 256, timeout: int = 1) -> None:
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError:
            return

        hosts = [str(ip) for ip in list(network.hosts())[:max_hosts]]
        if not hosts:
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
            futures = [executor.submit(self._ping_host, ip, timeout, include_metadata=False) for ip in hosts]
            for future in concurrent.futures.as_completed(futures):
                future.result()

    def _ping_host(self, ip: str, timeout: int = 1, include_metadata: bool = True) -> dict | None:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), ip],
                capture_output=True,
                text=True,
                timeout=timeout + 1,
            )
            if result.returncode != 0:
                return None

            if not include_metadata:
                return {"ip": ip}

            rtt_match = re.search(r"time=([\d.]+)\s*ms", result.stdout)
            arp_result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=2)
            mac_match = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", arp_result.stdout, re.I)

            mac = mac_match.group(1).lower() if mac_match else None
            rtt = round(float(rtt_match.group(1)), 2) if rtt_match else None
            return {
                "ip": ip,
                "rtt_ms": rtt,
                "mac": mac,
                "device_type": _vendor_for_mac(mac) if mac else "Unknown",
                "quality": self._quality_from_rtt(rtt),
                "alive": True,
            }
        except Exception:
            return None

    def _quality_from_rtt(self, rtt: float | None) -> dict:
        if rtt is None:
            return {"rating": "unknown", "grade": "Unknown"}
        if rtt < 5:
            return {"rating": "excellent", "grade": "Excellent"}
        if rtt < 20:
            return {"rating": "good", "grade": "Good"}
        if rtt < 50:
            return {"rating": "fair", "grade": "Fair"}
        return {"rating": "poor", "grade": "Poor"}

    def _default_network_from_switch(self, ip_address: str) -> str:
        parts = str(ip_address).split(".")
        if len(parts) == 4:
            return ".".join(parts[:3]) + ".0/24"
        return ""

    def _gateway_candidates(self, network_cidr: str) -> set[str]:
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError:
            return set()

        candidates = set()
        network_parts = str(network.network_address).split(".")
        if len(network_parts) == 4:
            candidates.add(".".join(network_parts[:3] + ["1"]))
            candidates.add(".".join(network_parts[:3] + ["254"]))
        return candidates

    def _select_preferred_ips(self, ip_addresses, switch_ip: str, gateway_candidates: set[str]) -> list[str]:
        unique_ips = []
        for ip_addr in sorted(ip_addresses or [], key=self._ip_sort_key):
            if ip_addr not in unique_ips:
                unique_ips.append(ip_addr)

        filtered = [
            ip_addr for ip_addr in unique_ips
            if not self._is_infrastructure_ip(ip_addr, switch_ip, gateway_candidates)
        ]

        return filtered or unique_ips

    def _is_infrastructure_ip(self, ip_addr: str, switch_ip: str, gateway_candidates: set[str]) -> bool:
        if not ip_addr:
            return True

        if ip_addr == switch_ip:
            return True

        if ip_addr in gateway_candidates:
            return True

        if ip_addr.startswith(("0.", "127.", "169.254.", "224.", "239.", "255.")):
            return True

        return False

    def _ip_sort_key(self, value: str):
        try:
            return tuple(int(part) for part in str(value).split("."))
        except Exception:
            return (999, 999, 999, 999)

    def _natural_port_key(self, value: str):
        parts = re.split(r"(\d+)", str(value or ""))
        normalized = []
        for part in parts:
            if part.isdigit():
                normalized.append(int(part))
            elif part:
                normalized.append(part.lower())
        return normalized

    def _speed_to_label(self, speed_bps) -> str:
        try:
            speed_bps = int(speed_bps or 0)
        except (TypeError, ValueError):
            speed_bps = 0

        if speed_bps >= 1_000_000_000:
            return f"{round(speed_bps / 1_000_000_000, 1)}G"
        if speed_bps >= 1_000_000:
            return f"{round(speed_bps / 1_000_000, 1)}M"
        return "Unknown"


def quick_scan_range(start_ip: str, end_ip: str) -> list[dict]:
    scanner = AdvancedIPScanner()
    start = int(ipaddress.ip_address(start_ip))
    end = int(ipaddress.ip_address(end_ip))

    devices = []
    for ip_int in range(start, end + 1):
        device = scanner._ping_host(str(ipaddress.ip_address(ip_int)), timeout=1)
        if device:
            devices.append(device)
    return devices
