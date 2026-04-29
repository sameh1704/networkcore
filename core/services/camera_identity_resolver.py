import re

from core.services.switch_inspector import get_mac_table


CAMERA_VLAN_ID = 100
MAX_MACS_PER_CAMERA = 2
MAX_IPS_PER_CAMERA = 2

_OUI_MAP = {
    "00:19:8C": "Tiandy",
    "00:23:8C": "Tiandy",
    "00:50:C2": "Tiandy",
    "4C:0F:6E": "Tiandy",
    "8C:1F:64": "Tiandy",
    "B8:4D:43": "Tiandy",
    "DC:08:56": "Tiandy",
    "E4:71:85": "Tiandy",
    "F8:3E:6F": "Tiandy",
    "00:0C:43": "Axis",
    "AC:CC:8E": "Axis",
    "00:40:8C": "Hikvision",
    "4C:11:AE": "Hikvision",
    "CC:1A:FA": "Hikvision",
    "C0:56:E3": "Hikvision",
    "7C:B5:9B": "Dahua",
    "9C:8E:CD": "Dahua",
    "E0:50:8B": "Dahua",
    "BC:32:5F": "Dahua",
}


def resolve_camera_identities(switch, vlan_ports: list[str]) -> dict:
    allowed_ports = {_canonical_port(port) for port in vlan_ports if port}
    mac_entries = _collect_mac_entries(switch, allowed_ports)
    arp_map = _collect_arp_entries(switch, {entry["mac"] for entry in mac_entries})

    by_port = {}
    for entry in mac_entries:
        by_port.setdefault(entry["port"], []).append(entry)

    identity_map = {}
    manufacturer_detected_count = 0
    camera_mac_matches = 0

    for port in allowed_ports:
        entries = sorted(by_port.get(port, []), key=_entry_rank, reverse=True)
        macs = []
        for entry in entries:
            if entry["mac"] not in macs:
                macs.append(entry["mac"])
            if len(macs) >= MAX_MACS_PER_CAMERA:
                break

        ips = []
        for mac in macs:
            for ip in arp_map.get(mac, []):
                if ip not in ips:
                    ips.append(ip)
                if len(ips) >= MAX_IPS_PER_CAMERA:
                    break
            if len(ips) >= MAX_IPS_PER_CAMERA:
                break

        manufacturer = _lookup_vendor(macs[0] if macs else "")
        if manufacturer not in ("Unknown", "Generic IP Camera"):
            manufacturer_detected_count += 1

        camera_mac_matches += len(macs)
        identity_map[port] = {
            "mac_addresses": macs,
            "ip_addresses": ips,
            "manufacturer": manufacturer,
        }

    return {
        "identity_map": identity_map,
        "diagnostics": {
            "mac_table_count": len(mac_entries),
            "camera_mac_matches": camera_mac_matches,
            "arp_matches": sum(len(v) for v in arp_map.values()),
            "manufacturer_detected_count": manufacturer_detected_count,
        },
    }


def _collect_mac_entries(switch, allowed_ports: set[str]) -> list[dict]:
    datasets = []

    try:
        datasets.append((get_mac_table(switch.ip_address, f"{switch.snmp_community}@{CAMERA_VLAN_ID}", limit=5000) or {}).get("mac_table", []))
    except Exception:
        datasets.append([])

    try:
        datasets.append((get_mac_table(switch.ip_address, switch.snmp_community, limit=5000) or {}).get("mac_table", []))
    except Exception:
        datasets.append([])

    try:
        from core.models import MACTable

        datasets.append([
            {
                "mac": str(row["mac_address"]).lower(),
                "port": row["interface"],
                "type": "cached",
                "vlan_id": row["vlan"],
            }
            for row in MACTable.objects.filter(switch=switch).values("mac_address", "interface", "vlan")
        ])
    except Exception:
        datasets.append([])

    merged = []
    seen = set()
    for dataset in datasets:
        for entry in dataset:
            mac = _format_mac(entry.get("mac"))
            port = _canonical_port(entry.get("port"))
            vlan_id = _safe_int(entry.get("vlan_id"))
            if not mac or not port:
                continue
            if allowed_ports and port not in allowed_ports and vlan_id != CAMERA_VLAN_ID:
                continue
            key = (mac, port, vlan_id)
            if key in seen:
                continue
            seen.add(key)
            merged.append({
                "mac": mac,
                "port": port,
                "type": str(entry.get("type", "learned")),
                "vlan_id": vlan_id,
            })
    return merged


def _collect_arp_entries(switch, interesting_macs: set[str]) -> dict:
    arp_map = {}

    try:
        from core.models import ARPTable

        for row in ARPTable.objects.filter(switch=switch).values("mac_address", "ip_address"):
            mac = _format_mac(row["mac_address"])
            if interesting_macs and mac not in interesting_macs:
                continue
            arp_map.setdefault(mac, []).append(str(row["ip_address"]))
    except Exception:
        pass

    try:
        from core.services.snmp import snmp_walk_with_index

        mac_rows = snmp_walk_with_index(switch.ip_address, switch.snmp_community, "1.3.6.1.2.1.4.22.1.2", timeout=1) or []
        ip_rows = snmp_walk_with_index(switch.ip_address, switch.snmp_community, "1.3.6.1.2.1.4.22.1.3", timeout=1) or []
        ip_by_suffix = {suffix: str(val).strip() for suffix, val in ip_rows}
        for suffix, mac_val in mac_rows:
            ip_addr = ip_by_suffix.get(suffix, "")
            mac = _format_mac(mac_val)
            if not mac or not ip_addr:
                continue
            if interesting_macs and mac not in interesting_macs:
                continue
            arp_map.setdefault(mac, []).append(ip_addr)
    except Exception:
        pass

    deduped = {}
    for mac, ips in arp_map.items():
        deduped[mac] = list(dict.fromkeys(ips))[:MAX_IPS_PER_CAMERA]
    return deduped


def _entry_rank(entry: dict) -> tuple:
    return (
        1 if entry.get("vlan_id") == CAMERA_VLAN_ID else 0,
        1 if entry.get("type") == "learned" else 0,
        1 if entry.get("type") == "cached" else 0,
    )


def _lookup_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return "Unknown"
    upper = mac[:8].upper()
    return _OUI_MAP.get(upper, "Generic IP Camera")


def _canonical_port(port_name) -> str:
    s = str(port_name or "").strip()
    if not s:
        return ""
    s = re.sub(r"(?i)^gigabitethernet", "Gi", s)
    s = re.sub(r"(?i)^fastethernet", "Fa", s)
    s = re.sub(r"(?i)^tengigabitethernet", "Te", s)
    s = re.sub(r"(?i)^ethernet", "Eth", s)
    s = re.sub(r"\s+", "", s)
    return s


def _format_mac(raw) -> str:
    s = str(raw or "").strip()
    if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", s, re.I):
        return s.lower()
    h = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(h) >= 12:
        return ":".join(h[i:i + 2] for i in range(0, 12, 2)).lower()
    return ""


def _safe_int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
