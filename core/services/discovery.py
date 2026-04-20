"""
discovery.py
────────────────────────────────────────────────────────
المسؤول عن صفحة /discovery/
يدعم:
  - communities متعددة تلقائياً
  - scan متوازي سريع
  - جلب model + IOS + serial
  - لا يحفظ في DB (مجرد اكتشاف للعرض)
"""

import ipaddress
import re
import concurrent.futures

from .snmp import snmp_get, snmp_walk


# ── OIDs ─────────────────────────────────────────────────
OID_HOSTNAME  = "1.3.6.1.2.1.1.5.0"
OID_DESCR     = "1.3.6.1.2.1.1.1.0"
OID_LOCATION  = "1.3.6.1.2.1.1.6.0"
OID_ENT_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"
OID_ENT_SER   = "1.3.6.1.2.1.47.1.1.1.1.11"

# ── Communities تُجرَّب بالترتيب ──────────────────────────
DEFAULT_COMMUNITIES = [
    "private",   # الأول دائماً لأنه الصحيح في شبكتك
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


def _probe_ip(ip_str, communities):
    from .snmp import snmp_get, snmp_walk, snmp_get_v3

    OID_HOSTNAME  = "1.3.6.1.2.1.1.5.0"
    OID_DESCR     = "1.3.6.1.2.1.1.1.0"
    OID_LOCATION  = "1.3.6.1.2.1.1.6.0"
    OID_ENT_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"
    OID_ENT_SER   = "1.3.6.1.2.1.47.1.1.1.1.11"

    # ── 1. SNMPv3 (جديد)
    hostname = snmp_get_v3(ip_str, "snmpuser", "authpass", "privpass", OID_HOSTNAME)
    if hostname:
        return {
            "ip": ip_str,
            "hostname": hostname,
            "community": "SNMPv3",
            "model": "",
            "serial": "",
            "ios": "",
            "device_type": "switch"
        }

    # ── 2. SNMP v2/v1
    for community in communities:
        try:
            hostname = snmp_get(ip_str, community, OID_HOSTNAME)

            # fallback
            if not hostname:
                hostname = snmp_get(ip_str, community, OID_DESCR)

        except:
            continue

        if not hostname:
            continue

        hostname = str(hostname).strip()

        descr = snmp_get(ip_str, community, OID_DESCR) or ""
        location = snmp_get(ip_str, community, OID_LOCATION) or ""

        # ── STACK SUPPORT
        models = snmp_walk(ip_str, community, OID_ENT_MODEL) or []
        serials = snmp_walk(ip_str, community, OID_ENT_SER) or []

        models = [str(m).strip() for m in models if str(m).strip()]
        serials = [str(s).strip() for s in serials if str(s).strip()]

        model = " | ".join(models[:3])
        serial = " | ".join(serials[:3])

        return {
            "ip": ip_str,
            "hostname": hostname,
            "community": community,
            "model": model,
            "serial": serial,
            "ios": "",
            "location": location,
            "device_type": "switch",
            "descr": descr[:150],
        }

    return None


def _detect_device_type(descr, model):
    """يُحدد نوع الجهاز من sysDescr أو Model"""
    text = (descr + " " + model).lower()
    if any(x in text for x in ["router", "isr", "asr", "c29", "c38"]):
        return "router"
    if any(x in text for x in ["firewall", "asa", "ftd", "pix"]):
        return "firewall"
    if any(x in text for x in ["access point", "aironet", "wlc", "wireless"]):
        return "wireless"
    if any(x in text for x in ["catalyst", "3750", "3850", "9300", "9200",
                                 "2960", "4500", "6500", "c3750", "c3850"]):
        return "switch"
    return "switch"   # default


def discover_switches(network, community=None, extra_communities=None,
                      max_workers=60):
    """
    الدالة الرئيسية — تُستدعى من views.py لصفحة /discovery/
    لا تحفظ في DB، ترجع قائمة للعرض فقط.

    Parameters:
        network           : "192.168.70.0/24"
        community         : community رئيسي من المستخدم
        extra_communities : قائمة إضافية
        max_workers       : threads متوازية
    """
    # بناء قائمة communities مرتبة
    communities = _build_communities(community, extra_communities)

    # قائمة IPs
    try:
        net     = ipaddress.ip_network(network, strict=False)
        all_ips = [str(ip) for ip in net.hosts()]
    except ValueError as e:
        return {"error": str(e), "switches": [], "total": 0}

    found = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:
        futures = {
            executor.submit(_probe_ip, ip, communities): ip
            for ip in all_ips
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result(timeout=3)
                if result:
                    found.append(result)
                    print(
                        f"[✔] {result['ip']:16} "
                        f"{result['hostname']:25} "
                        f"comm={result['community']:10} "
                        f"model={result['model']}"
                    )
            except Exception:
                pass 

    # ترتيب حسب IP
    found.sort(key=lambda x: [
        int(p) for p in x["ip"].split(".")
    ])

    print(f"\n[Discovery] Scanned {len(all_ips)} | Found {len(found)}")
    return {
        "switches"     : found,
        "total_scanned": len(all_ips),
        "total_found"  : len(found),
    }


def _build_communities(primary, extras):
    """يبني قائمة communities مرتبة بدون تكرار"""
    result = []
    # primary أولاً
    if primary and primary.strip():
        result.append(primary.strip())
    # extras ثانياً
    for c in (extras or []):
        c = str(c).strip()
        if c and c not in result:
            result.append(c)
    # defaults أخيراً
    for c in DEFAULT_COMMUNITIES:
        if c not in result:
            result.append(c)
    return result