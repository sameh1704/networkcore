"""
auto_discovery.py
────────────────────────────────────────────────────────
نفس منطق discovery.py لكن يحفظ في DB أيضاً.
يُستدعى من نفس صفحة /discovery/ عند الضغط على "Save to DB".
"""

import ipaddress
import re
import concurrent.futures

from .snmp import snmp_get, snmp_walk


OID_HOSTNAME  = "1.3.6.1.2.1.1.5.0"
OID_DESCR     = "1.3.6.1.2.1.1.1.0"
OID_LOCATION  = "1.3.6.1.2.1.1.6.0"
OID_ENT_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"
OID_ENT_SER   = "1.3.6.1.2.1.47.1.1.1.1.11"

DEFAULT_COMMUNITIES = [
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


def _probe_ip(ip_str, communities):
    from .snmp import snmp_get, snmp_walk, snmp_get_v3

    OID_HOSTNAME  = "1.3.6.1.2.1.1.5.0"
    OID_DESCR     = "1.3.6.1.2.1.1.1.0"
    OID_ENT_MODEL = "1.3.6.1.2.1.47.1.1.1.1.13"
    OID_ENT_SER   = "1.3.6.1.2.1.47.1.1.1.1.11"

    # SNMPv3
    hostname = snmp_get_v3(ip_str, "snmpuser", "authpass", "privpass", OID_HOSTNAME)
    if hostname:
        return {
            "ip": ip_str,
            "hostname": hostname,
            "community": "SNMPv3",
            "model": "",
            "serial": "",
        }

    # SNMPv2
    for community in communities:
        hostname = snmp_get(ip_str, community, OID_HOSTNAME)

        if not hostname:
            continue

        models = snmp_walk(ip_str, community, OID_ENT_MODEL) or []
        serials = snmp_walk(ip_str, community, OID_ENT_SER) or []

        model = " | ".join([str(m) for m in models if m][:3])
        serial = " | ".join([str(s) for s in serials if s][:3])

        return {
            "ip": ip_str,
            "hostname": hostname,
            "community": community,
            "model": model,
            "serial": serial,
        }

    return None


def _detect_device_type(descr, model):
    text = (descr + " " + model).lower()
    if any(x in text for x in ["router", "isr", "asr"]):
        return "router"
    if any(x in text for x in ["firewall", "asa", "ftd"]):
        return "firewall"
    if any(x in text for x in ["wireless", "wlc", "aironet"]):
        return "wireless"
    return "switch"


def _build_communities(primary, extras):
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


def discover_network(network, community=None, extra_communities=None,
                     max_workers=60):
    """
    يسكان الشبكة ويحفظ كل جهاز في DB.
    يُستدعى من views.py → auto_discovery_api
    """
    from core.models import Switch

    communities = _build_communities(community, extra_communities)

    try:
        net     = ipaddress.ip_network(network, strict=False)
        all_ips = [str(ip) for ip in net.hosts()]
    except ValueError as e:
        return {"error": str(e), "discovered": [], "total": 0}

    discovered = []

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
                if not result:
                    continue

                # حفظ أو تحديث في DB
                sw, created = Switch.objects.update_or_create(
                    ip_address=result["ip"],
                    defaults={
                        "hostname"      : result["hostname"],
                        "snmp_community": result["community"],
                        "model"         : result.get("model", ""),
                        "serial_number" : result.get("serial", ""),
                        "ios_version"   : result.get("ios", ""),
                    }
                )

                result["created"] = created
                result["db_id"]   = sw.id
                discovered.append(result)

                action = "NEW" if created else "UPD"
                print(
                    f"[{action}] {result['ip']:16} "
                    f"{result['hostname']:25} "
                    f"comm={result['community']:10} "
                    f"model={result['model']}"
                )

            except Exception as e:
                print(f"[✘] Error: {e}")

    # ترتيب حسب IP
    discovered.sort(key=lambda x: [
        int(p) for p in x["ip"].split(".")
    ])

    print(
        f"\n[Discovery] Scanned {len(all_ips)} | "
        f"Saved {len(discovered)} to DB"
    )

    return {
        "discovered"   : discovered,
        "total_scanned": len(all_ips),
        "total_found"  : len(discovered),
    }