# core/services/auto_discovery.py

"""
auto_discovery.py
═══════════════════════════════════════════════════════════════
يكتشف السويتشات في الشبكة ويحفظها في قاعدة البيانات.
يدعم:
  - IP واحد (مثل 192.168.70.20)
  - Range IP (مثل 192.168.70.1-192.168.70.50)
  - شبكة CIDR (مثل 192.168.70.0/24)
"""

import ipaddress
import re
import concurrent.futures

from .snmp import snmp_get, snmp_walk, snmp_get_v3

# OIDs القياسية
OID_HOSTNAME  = "1.3.6.1.2.1.1.5.0"
OID_DESCR     = "1.3.6.1.2.1.1.1.0"
OID_LOCATION  = "1.3.6.1.2.1.1.6.0"
OID_CONTACT   = "1.3.6.1.2.1.1.4.0"
OID_ENT_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"
OID_ENT_SER   = "1.3.6.1.2.1.47.1.1.1.1.11"
OID_ENT_SW    = "1.3.6.1.2.1.47.1.1.1.1.10"

# قائمة المجتمعات الافتراضية
DEFAULT_COMMUNITIES = [
    "NMSCOMM",
    "private",
    "public",
    "cisco",
    "snmp",
    "community",
    "network",
    "monitor",
    "readonly",
    "read",
    "admin",
    "secret",
]


def parse_ip_range(range_str):
    """
    تحويل المدخلات إلى قائمة IPs
    يدعم:
      - IP واحد: "192.168.70.20"
      - Range: "192.168.70.1-192.168.70.50"
      - CIDR: "192.168.70.0/24"
    """
    # حالة IP واحد
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', range_str):
        return [range_str]
    
    # حالة Range (مثل 192.168.70.1-192.168.70.50)
    range_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', range_str)
    if range_match:
        start_ip = range_match.group(1)
        end_ip = range_match.group(2)
        start = int(ipaddress.IPv4Address(start_ip))
        end = int(ipaddress.IPv4Address(end_ip))
        return [str(ipaddress.IPv4Address(i)) for i in range(start, end + 1)]
    
    # حالة CIDR (مثل 192.168.70.0/24)
    try:
        network = ipaddress.ip_network(range_str, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def _probe_ip(ip_str, communities):
    """
    فحص IP واحد لمعرفة إذا كان سويتشاً وتجميع معلوماته
    """
    # SNMPv3
    hostname = snmp_get_v3(ip_str, "snmpuser", "authpass", "privpass", OID_HOSTNAME)
    if hostname:
        return {
            "ip": ip_str,
            "hostname": hostname,
            "community": "SNMPv3",
            "model": "",
            "serial": "",
            "ios": "",
            "created": True,
        }
    
    # SNMP v2/v1
    for community in communities:
        try:
            hostname = snmp_get(ip_str, community, OID_HOSTNAME)
            if not hostname:
                hostname = snmp_get(ip_str, community, OID_DESCR)
            if not hostname:
                continue
        except:
            continue
        
        if not hostname:
            continue
        
        hostname = str(hostname).strip()
        descr = snmp_get(ip_str, community, OID_DESCR) or ""
        location = snmp_get(ip_str, community, OID_LOCATION) or ""
        contact = snmp_get(ip_str, community, OID_CONTACT) or ""
        
        # جلب الموديل والسيريال (يدعم الـ Stack)
        models = snmp_walk(ip_str, community, OID_ENT_MODEL) or []
        serials = snmp_walk(ip_str, community, OID_ENT_SER) or []
        sw_vers = snmp_walk(ip_str, community, OID_ENT_SW) or []
        
        models = [str(m).strip() for m in models if str(m).strip() and str(m) not in ("", "0")]
        serials = [str(s).strip() for s in serials if str(s).strip() and str(s) not in ("", "0")]
        
        model = " | ".join(models[:3]) if models else ""
        serial = " | ".join(serials[:3]) if serials else ""
        
        # استخراج IOS version من sysDescr
        ios = ""
        ios_match = re.search(r'Version\s+([\d\w\.\(\)]+)', descr)
        if ios_match:
            ios = ios_match.group(1)
        
        # تحديد نوع الجهاز
        device_type = _detect_device_type(descr, model)
        
        return {
            "ip": ip_str,
            "hostname": hostname,
            "community": community,
            "model": model,
            "serial": serial,
            "ios": ios,
            "location": location,
            "contact": contact,
            "device_type": device_type,
            "created": True,
        }
    
    return None


def _detect_device_type(descr, model):
    """تحديد نوع الجهاز من sysDescr أو Model"""
    text = (descr + " " + model).lower()
    if any(x in text for x in ["router", "isr", "asr", "c29", "c38"]):
        return "router"
    if any(x in text for x in ["firewall", "asa", "ftd", "pix"]):
        return "firewall"
    if any(x in text for x in ["access point", "aironet", "wlc", "wireless"]):
        return "wireless"
    return "switch"


def _build_communities(primary, extras):
    """بناء قائمة المجتمعات المرتبة"""
    result = []
    if primary and primary.strip():
        result.append(primary.strip())
    for c in (extras or []):
        c = str(c).strip()
        if c and c not in result:
            result.append(c)
    for c in DEFAULT_COMMUNITIES:
        if c not in result:
            result.append(c)
    return result


def discover_network(network, community=None, extra_communities=None, max_workers=60):
    """
    اكتشاف السويتشات في الشبكة وحفظها في قاعدة البيانات
    
    Args:
        network: IP واحد أو Range أو CIDR (مثل 192.168.70.20 أو 192.168.70.1-50 أو 192.168.70.0/24)
        community: المجتمع الرئيسي
        extra_communities: مجتمعات إضافية
        max_workers: عدد الـ threads
    
    Returns:
        dict: نتائج الاكتشاف
    """
    from core.models import Switch
    
    communities = _build_communities(community, extra_communities)
    
    # تحويل المدخلات إلى قائمة IPs
    all_ips = parse_ip_range(network)
    
    if not all_ips:
        return {"error": "Invalid IP range format", "discovered": [], "total": 0}
    
    print(f"[Discovery] Scanning {len(all_ips)} IPs with {len(communities)} communities")
    
    discovered = []
    created_count = 0
    updated_count = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_probe_ip, ip, communities): ip for ip in all_ips}
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result(timeout=5)
                if not result:
                    continue
                
                # حفظ أو تحديث في قاعدة البيانات
                sw, created = Switch.objects.update_or_create(
                    ip_address=result["ip"],
                    defaults={
                        "hostname": result["hostname"],
                        "snmp_community": result["community"],
                        "model": result.get("model", ""),
                        "serial_number": result.get("serial", ""),
                        "ios_version": result.get("ios", ""),
                    }
                )
                
                result["created"] = created
                result["db_id"] = sw.id
                discovered.append(result)
                
                if created:
                    created_count += 1
                else:
                    updated_count += 1
                
                action = "NEW" if created else "UPD"
                print(f"[{action}] {result['ip']:16} {result['hostname']:25} comm={result['community']:10}")
                
            except Exception as e:
                print(f"[!] Error scanning {futures[future]}: {e}")
    
    # ترتيب حسب IP
    discovered.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])
    
    print(f"\n[Discovery] Complete: {len(discovered)} devices found ({created_count} new, {updated_count} updated)")
    
    return {
        "discovered": discovered,
        "total_scanned": len(all_ips),
        "total_found": len(discovered),
        "new_count": created_count,
        "updated_count": updated_count,
    }


def discover_single_ip(ip, community, extra_communities=None):
    """
    اكتشاف سويتش واحد فقط
    """
    communities = _build_communities(community, extra_communities)
    result = _probe_ip(ip, communities)
    
    if result:
        from core.models import Switch
        sw, created = Switch.objects.update_or_create(
            ip_address=result["ip"],
            defaults={
                "hostname": result["hostname"],
                "snmp_community": result["community"],
                "model": result.get("model", ""),
                "serial_number": result.get("serial", ""),
                "ios_version": result.get("ios", ""),
            }
        )
        result["created"] = created
        result["db_id"] = sw.id
    
    return result