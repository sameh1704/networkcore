# core/services/camera_identity_resolver.py

import re
import logging
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.services.switch_inspector import get_mac_table

log = logging.getLogger(__name__)

CAMERA_VLAN_ID = 100
MAX_MACS_PER_CAMERA = 2
MAX_IPS_PER_CAMERA = 2

# OUI database للكاميرات
_OUI_MAP = {
    "00:19:8C": "Tiandy", "00:23:8C": "Tiandy", "00:50:C2": "Tiandy",
    "4C:0F:6E": "Tiandy", "8C:1F:64": "Tiandy", "B8:4D:43": "Tiandy",
    "DC:08:56": "Tiandy", "E4:71:85": "Tiandy", "F8:3E:6F": "Tiandy",
    "00:0C:43": "Axis", "AC:CC:8E": "Axis",
    "00:40:8C": "Hikvision", "4C:11:AE": "Hikvision",
    "CC:1A:FA": "Hikvision", "C0:56:E3": "Hikvision",
    "7C:B5:9B": "Dahua", "9C:8E:CD": "Dahua",
    "E0:50:8B": "Dahua", "BC:32:5F": "Dahua",
    "00:1C:F2": "Bosch", "00:1B:8F": "Panasonic",
    "00:06:5B": "Sony", "00:0D:6D": "Samsung",
    "00:1A:A7": "Vivotek", "00:0E:74": "ACTi",
    "00:19:6D": "Mobotix",
}


# ═══════════════════════════════════════════════════════════════
#  الدالة الرئيسية لربط MAC و IP
# ═══════════════════════════════════════════════════════════════
def resolve_camera_identities(switch, vlan_ports: list[str]) -> dict:
    """
    ربط MAC addresses و IP addresses لكل كاميرا في VLAN 100
    """
    log_prefix = f"[Identity {switch.hostname}]"
    allowed_ports = {_canonical_port(port) for port in vlan_ports if port}
    
    # جمع MAC addresses من مصادر متعددة
    mac_entries = _collect_mac_entries(switch, allowed_ports)
    
    # جمع كل MACs المهمة لاستخدامها في ARP
    all_macs = {entry["mac"] for entry in mac_entries}
    log.info(f"{log_prefix} Collected {len(all_macs)} unique MACs from MAC table")
    
    # جمع ARP entries (ربط MAC → IP)
    arp_map = _collect_arp_entries(switch, interesting_macs=all_macs, timeout=5)
    
    # إذا لم نجد IP كافية، جرب الاكتشاف عبر ping
    if len(arp_map) < len(all_macs) * 0.5 and all_macs:
        print(f"[Identity] Low ARP matches ({len(arp_map)}), running discovery...")
        discovered_ips = discover_camera_ips_from_arp(switch, subnet="192.168.2.0/22")
        for mac, ip in discovered_ips.items():
            if mac not in arp_map:
                arp_map[mac] = [ip]
            elif ip not in arp_map[mac]:
                arp_map[mac].append(ip)
    
    # تنظيم البيانات حسب المنفذ
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


# ═══════════════════════════════════════════════════════════════
#  اكتشاف IP الكاميرات عبر Ping (الحل الأمثل للـ Static IPs)
# ═══════════════════════════════════════════════════════════════
def discover_camera_ips_from_arp(switch, subnet="192.168.2.0/22", timeout=1, max_workers=30):
    """
    اكتشاف IP الكاميرات عن طريق ping جميع العناوين في الشبكة الفرعية
    وإجبار السويتش على تعلم ARP entries.
    
    Args:
        switch: كائن Switch
        subnet: الشبكة الفرعية (مثال: 192.168.2.0/22)
        timeout: مهلة ping بالثواني
        max_workers: عدد الـ threads المتوازية
    
    Returns:
        dict: {mac: ip}
    """
    ip_map = {}
    
    try:
        # إنشاء جميع العناوين في الشبكة الفرعية
        network = ipaddress.ip_network(subnet, strict=False)
        hosts = list(network.hosts())[:254]  # أول 254 عنوان فقط للسرعة
        
        print(f"[Discovery] Scanning {len(hosts)} IPs in {subnet}")
        
        def ping_host(ip):
            """Ping عنوان واحد وإرجاع IP و MAC إذا استجاب"""
            try:
                # Ping من الخادم
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', str(timeout), str(ip)],
                    capture_output=True,
                    timeout=timeout + 1
                )
                if result.returncode == 0:
                    # جلب MAC من ARP table بعد ping
                    arp_result = subprocess.run(['arp', '-n', str(ip)], capture_output=True, text=True)
                    import re
                    mac_match = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', arp_result.stdout, re.I)
                    if mac_match:
                        return str(ip), mac_match.group(1).lower()
            except:
                pass
            return None, None
        
        # ping بالتوازي للسرعة
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in hosts}
            for future in as_completed(futures):
                ip, mac = future.result()
                if ip and mac:
                    ip_map[mac] = ip
                    print(f"[Discovery] Found: {mac} -> {ip}")
        
        # حفظ النتائج في قاعدة البيانات
        if ip_map:
            from core.models import ARPTable
            for mac, ip in ip_map.items():
                ARPTable.objects.update_or_create(
                    switch=switch,
                    mac_address=mac,
                    defaults={"ip_address": ip, "vlan": CAMERA_VLAN_ID}
                )
            print(f"[Discovery] Saved {len(ip_map)} mappings to database")
        
    except Exception as e:
        print(f"[Discovery] Error: {e}")
    
    return ip_map


# ═══════════════════════════════════════════════════════════════
#  جمع MAC addresses
# ═══════════════════════════════════════════════════════════════
def _collect_mac_entries(switch, allowed_ports: set[str]) -> list[dict]:
    """جمع MAC addresses من مصادر متعددة"""
    datasets = []
    
    # المحاولة 1: SNMP مع community@100 (الأكثر دقة)
    try:
        data = get_mac_table(switch.ip_address, f"{switch.snmp_community}@{CAMERA_VLAN_ID}", limit=5000) or {}
        datasets.append(data.get("mac_table", []))
    except Exception:
        datasets.append([])
    
    # المحاولة 2: SNMP عالمي (بدون فلتر VLAN)
    try:
        data = get_mac_table(switch.ip_address, switch.snmp_community, limit=5000) or {}
        datasets.append(data.get("mac_table", []))
    except Exception:
        datasets.append([])
    
    # المحاولة 3: من قاعدة البيانات (MACTable model)
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
    
    # دمج النتائج وإزالة التكرارات
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


# ═══════════════════════════════════════════════════════════════
#  جمع ARP entries
# ═══════════════════════════════════════════════════════════════
# core/services/camera_identity_resolver.py - عدّل _collect_arp_entries

def _collect_arp_entries(switch, interesting_macs: set = None, timeout: int = 5) -> dict:
    """
    جلب جدول ARP من VLAN 100 مباشرة باستخدام community@vlan
    """
    arp_map = {}
    interesting_macs = {str(mac).lower() for mac in (interesting_macs or set())}
    
    # استخدام community@100 لجلب ARP خاص بـ VLAN 100
    vlan_community = f"{switch.snmp_community}@100"
    
    try:
        from core.services.snmp import snmp_walk_with_index, extract_mac_from_octet
        
        OID_ARP_MAC = "1.3.6.1.2.1.4.22.1.2"
        OID_ARP_IP = "1.3.6.1.2.1.4.22.1.3"
        
        print(f"[ARP] Fetching ARP for VLAN 100 on {switch.hostname}")
        
        mac_rows = snmp_walk_with_index(switch.ip_address, vlan_community, OID_ARP_MAC, timeout=timeout) or []
        ip_rows = snmp_walk_with_index(switch.ip_address, vlan_community, OID_ARP_IP, timeout=timeout) or []
        
        print(f"[ARP] Got {len(mac_rows)} MAC entries, {len(ip_rows)} IP entries")
        
        # بناء خريطة IP لكل suffix
        ip_by_suffix = {}
        for suffix, val in ip_rows:
            # استخراج IP من String
            s = str(val)
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', s)
            if ip_match:
                ip_by_suffix[suffix] = ip_match.group(1)
        
        # ربط MAC بـ IP
        for suffix, mac_val in mac_rows:
            # استخراج MAC من الترميز المشوه
            mac = extract_mac_from_octet(mac_val)
            ip_addr = ip_by_suffix.get(suffix, "")
            
            if not mac or not ip_addr:
                continue
            
            # تجاهل الـ Gateway والـ broadcast
            if mac.startswith(("ff:ff:", "01:00:5e")):
                continue
            if ip_addr.startswith(("0.", "127.", "169.", "224.")):
                continue
            if ip_addr == switch.ip_address or ip_addr == "192.168.70.1":
                continue
            
            if interesting_macs and mac not in interesting_macs:
                continue
            
            if mac not in arp_map:
                arp_map[mac] = []
            if ip_addr not in arp_map[mac]:
                arp_map[mac].append(ip_addr)
                print(f"[ARP] Found camera: {mac} -> {ip_addr}")
        
        print(f"[ARP] Total cameras found: {len(arp_map)}")
        
    except Exception as e:
        print(f"[ARP] SNMP error: {e}")
    
    return arp_map

# ═══════════════════════════════════════════════════════════════
#  دوال مساعدة
# ═══════════════════════════════════════════════════════════════
def _extract_ip_from_snmp(value):
    """استخراج IP من قيمة SNMP (Hex-STRING أو IpAddress)"""
    s = str(value)
    
    # إذا كان IP بصيغة IpAddress
    import re
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', s)
    if ip_match:
        return ip_match.group(1)
    
    # إذا كان Hex-STRING مثل "C0 A8 46 01"
    hex_numbers = re.findall(r'([0-9a-fA-F]{2})', s)
    if len(hex_numbers) == 4:
        try:
            return '.'.join(str(int(h, 16)) for h in hex_numbers)
        except:
            pass
    
    return None


def _format_mac_from_hex(value):
    """تنسيق MAC من قيمة SNMP (Hex-STRING)"""
    import re
    s = str(value)
    
    # استخراج الأرقام السداسية
    hex_parts = re.findall(r'([0-9a-fA-F]{2})', s)
    if len(hex_parts) >= 6:
        mac = ':'.join(hex_parts[:6]).lower()
        return mac
    
    return None


def _entry_rank(entry: dict) -> tuple:
    """ترتيب أولوية المداخل (الأفضل أولاً)"""
    return (
        1 if entry.get("vlan_id") == CAMERA_VLAN_ID else 0,
        1 if entry.get("type") == "learned" else 0,
        1 if entry.get("type") == "cached" else 0,
    )


def _lookup_vendor(mac: str) -> str:
    """التعرف على الشركة المصنعة من OUI"""
    if not mac or len(mac) < 8:
        return "Unknown"
    oui = mac[:8].upper().replace(":", "")
    for prefix, name in _OUI_MAP.items():
        if oui.startswith(prefix.replace(":", "")):
            return name
    return "Generic IP Camera"


def _canonical_port(port_name) -> str:
    """تنسيق اسم المنفذ إلى صيغة موحدة (Gi1/0/1, Fa0/1, إلخ)"""
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
    """تنسيق MAC address إلى xx:xx:xx:xx:xx:xx"""
    s = str(raw or "").strip()
    if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", s, re.I):
        return s.lower()
    h = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(h) >= 12:
        return ":".join(h[i:i+2] for i in range(0, 12, 2)).lower()
    return ""


def _safe_int(value, default=0) -> int:
    """تحويل آمن إلى int"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default