# core/services/camera_vlan_analyzer.py - النسخة المصححة

"""
Camera VLAN 100 Analyzer — نسخة محسّنة وسريعة
"""

import re
import logging
import concurrent.futures
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from core.services.camera_identity_resolver import resolve_camera_identities

log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════
#  دالة آمنة لاستدعاءات SNMP
# ══════════════════════════════════════════════════════════════
def _safe_snmp_call(func, *args, **kwargs):
    """دالة آمنة لاستدعاء دوال SNMP مع معالجة الأخطاء"""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        log.warning(f"SNMP call failed for {func.__name__}: {e}")
        return None

# ── إعدادات الأداء ─────────────────────────────────────────
CACHE_TIMEOUT = 180   # 3 دقائق (مخفض للحصول على بيانات أحدث)
SNMP_TIMEOUT = 3      # ثوانٍ لكل استدعاء SNMP (مخفض للسرعة)
MAX_WORKERS = 6       # عدد threads للتوازي
MAX_IPS_PER_CAMERA = 2
MAX_MACS_PER_CAMERA = 2
CAMERA_VLAN_ID = 100

# ── OUI database للكاميرات ──────────────────────────────────
# ── OUI database للكاميرات (محدث مع Tiandy) ─────────────────
_OUI_MAP = {
    # Tiandy (Tiandy Technologies)
    "00:19:8C": "Tiandy",
    "00:23:8C": "Tiandy", 
    "00:50:C2": "Tiandy",
    "4C:0F:6E": "Tiandy",
    "8C:1F:64": "Tiandy",
    "B8:4D:43": "Tiandy",
    "DC:08:56": "Tiandy",
    "E4:71:85": "Tiandy",
    "F8:3E:6F": "Tiandy",
    
    # Axis
    "00:0C:43": "Axis", "AC:CC:8E": "Axis",
    
    # Hikvision
    "00:40:8C": "Hikvision", "4C:11:AE": "Hikvision",
    "CC:1A:FA": "Hikvision", "C0:56:E3": "Hikvision",
    
    # Dahua
    "7C:B5:9B": "Dahua", "9C:8E:CD": "Dahua",
    "E0:50:8B": "Dahua", "BC:32:5F": "Dahua",
    
    # Bosch
    "00:1C:F2": "Bosch",
    
    # Panasonic
    "00:1B:8F": "Panasonic",
    
    # Sony
    "00:06:5B": "Sony",
    
    # Samsung
    "00:0D:6D": "Samsung",
    
    # Vivotek
    "00:1A:A7": "Vivotek",
    
    # ACTi
    "00:0E:74": "ACTi",
    
    # Mobotix
    "00:19:6D": "Mobotix",
}


def analyze_camera_vlan(switch, hours: int = 24) -> dict:
    """
    تحليل كاميرات VLAN 100 لسويتش واحد.
    """
    # ✅ إصلاح 1: تضمين hours و switch.id في cache key
    cache_key = _analysis_cache_key(switch.id, hours)
    latest_key = _latest_cache_key(switch.id)
    
    cached = cache.get(cache_key)
    if cached:
        cached["from_cache"] = True
        return cached

    result = _build_empty_result(switch, hours)
    
    try:
        snapshot_state = _load_snapshot_state(switch)
        vlan_ports = snapshot_state["vlan_ports"]
        iface_map = snapshot_state["iface_map"]
        poe_map = snapshot_state["poe_map"]

        from core.services.switch_inspector import (
            get_interfaces_detail,
            get_vlans_full,
            get_poe_detail,
        )

        # جلب البيانات بالتوازي مع timeout محسن
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # أولوية للبيانات الأساسية
            future_vlans = executor.submit(_safe_snmp_call, get_vlans_full, switch.ip_address, switch.snmp_community)
            future_iface = executor.submit(_safe_snmp_call, get_interfaces_detail, switch.ip_address, switch.snmp_community)
            
            # بيانات ثانوية (يمكن أن تفشل بدون توقف العملية)
            future_poe = executor.submit(_safe_snmp_call, get_poe_detail, switch.ip_address, switch.snmp_community)
            future_mac = executor.submit(
                _safe_snmp_call,
                _get_camera_mac_table,
                switch.ip_address,
                switch.snmp_community,
            )
            
            # جمع النتائج مع timeout أقصر
            try:
                vlans = future_vlans.result(timeout=8) or []
                interfaces = future_iface.result(timeout=8) or []
                poe_data = future_poe.result(timeout=6) or {}
                mac_data = future_mac.result(timeout=6) or {}
            except concurrent.futures.TimeoutError:
                log.warning(f"Timeout gathering data for {switch.hostname} - using partial data")
                # استخدم أي نتيجة جاهزة، وحاول فقط انتظار ما لم يكتمل بعد.
                vlans = _future_result_or_default(future_vlans, [], timeout=2)
                interfaces = _future_result_or_default(future_iface, [], timeout=2)
                poe_data = _future_result_or_default(future_poe, {}, timeout=1)
                mac_data = _future_result_or_default(future_mac, {}, timeout=1)

        # استخراج المنافذ بعد جلب الـ VLANs بالتوازي
        if not vlan_ports:
            vlan_ports = _extract_vlan100_ports(vlans)
        if not vlan_ports:
            vlan_ports = _extract_vlan100_ports_from_mac_table(
                mac_data.get("mac_table", [])
            )
        
        if not vlan_ports:
            result["summary"]["message"] = "لم يتم العثور على منافذ في VLAN 100"
            cache.set(cache_key, result, 60)
            cache.set(latest_key, result, 60)
            return result
        
        # بناء الخرائط
        if not iface_map:
            iface_map = {i["name"]: i for i in interfaces}
        else:
            live_iface_map = {i["name"]: i for i in interfaces}
            iface_map.update({k: v for k, v in live_iface_map.items() if k not in iface_map})

        if not poe_map:
            poe_map = {p["port"]: p for p in poe_data.get("ports", [])}
        else:
            live_poe_map = {p["port"]: p for p in poe_data.get("ports", [])}
            poe_map.update({k: v for k, v in live_poe_map.items() if k not in poe_map})

        identity_result = resolve_camera_identities(switch, vlan_ports)
        identity_map = identity_result.get("identity_map", {})
        
        # تحليل كل منفذ
        cameras = []
        for port_name in vlan_ports:
            cam = _analyze_single_port(
                port_name, iface_map, poe_map, identity_map
            )
            cameras.append(cam)
        
        cameras.sort(key=lambda x: x["traffic_mbps"], reverse=True)
        
        summary = _build_summary(cameras)
        issues = _detect_issues(cameras)
        
        result.update({
            "cameras": cameras,
            "summary": summary,
            "issues": issues,
            "port_count": len(vlan_ports),
            "diagnostics": {
                "vlan_port_count": len(vlan_ports),
                **identity_result.get("diagnostics", {}),
            },
        })
        
    except Exception as e:
        log.error(f"analyze_camera_vlan({switch.hostname}): {e}", exc_info=True)
        result["error"] = str(e)
        result["summary"]["message"] = f"خطأ في التحليل: {e}"
    
    cache.set(cache_key, result, CACHE_TIMEOUT)
    cache.set(latest_key, result, CACHE_TIMEOUT)
    return result


# ══════════════════════════════════════════════════════════════
#  ARP Table (محسّن)
# ══════════════════════════════════════════════════════════════
def _get_arp_table(ip: str, community: str, interesting_macs=None) -> dict:
    """جلب جدول ARP: MAC → [IP list] - نسخة محسنة"""
    arp_map = _get_cached_arp_rows(interesting_macs)
    interesting_macs = set(interesting_macs or [])
    try:
        from core.services.snmp import snmp_walk_with_index
        
        # timeout أقصر للسرعة
        mac_rows = snmp_walk_with_index(ip, community, "1.3.6.1.2.1.4.22.1.2", timeout=1) or []
        ip_rows = snmp_walk_with_index(ip, community, "1.3.6.1.2.1.4.22.1.3", timeout=1) or []
        
        # تحسين معالجة البيانات
        ip_by_suffix = {}
        for sfx, val in ip_rows:
            ip_str = str(val).strip()
            if ip_str and not ip_str.startswith(("0.", "127.", "169.", "224.")):
                ip_by_suffix[sfx] = ip_str
        
        # معالجة أسرع للـ MAC addresses
        for suffix, mac_val in mac_rows[:300]:
            if suffix not in ip_by_suffix:
                continue
            mac = _format_mac(str(mac_val))
            if interesting_macs and mac not in interesting_macs:
                continue
            if mac and len(mac) == 17:  # تحقق سريع من طول MAC
                ip_addr = ip_by_suffix[suffix]
                arp_map.setdefault(mac, []).append(ip_addr)
                if len(arp_map[mac]) > MAX_IPS_PER_CAMERA:
                    arp_map[mac] = arp_map[mac][:MAX_IPS_PER_CAMERA]
                
    except Exception as e:
        log.debug(f"ARP table error ({ip}): {e}")
    return arp_map


# ══════════════════════════════════════════════════════════════
#  الدوال المساعدة
# ══════════════════════════════════════════════════════════════
def _extract_vlan100_ports(vlans: list) -> list:
    for v in vlans:
        if _safe_int(v.get("vlan_id", 0)) == CAMERA_VLAN_ID:
            ports = v.get("port_names", [])
            return [_canonical_port(p) for p in ports if re.match(r'^(Fa|Gi|Te|Eth|Gig)', p, re.I)]
    return []


def _load_snapshot_state(switch) -> dict:
    """
    يستخدم آخر لقطة محفوظة لكل منفذ كمصدر سريع وموثوق عندما تكون
    مهام Port History تعمل بشكل صحيح.
    """
    try:
        from core.models import PortSnapshot

        since = timezone.now() - timedelta(hours=12)
        snapshots = list(
            PortSnapshot.objects
            .filter(switch=switch, recorded_at__gte=since)
            .order_by("port_name", "-recorded_at")
            .distinct("port_name")
            .values(
                "port_name",
                "oper_status",
                "speed_bps",
                "in_octets",
                "out_octets",
                "in_errors",
                "out_errors",
                "in_discards",
                "out_discards",
                "poe_status",
                "poe_power_mw",
                "vlan_id",
            )
        )
    except Exception as e:
        log.debug(f"snapshot_state error ({switch.hostname}): {e}")
        snapshots = []

    iface_map = {}
    poe_map = {}
    vlan_ports = []

    for snap in snapshots:
        port_name = _canonical_port(snap["port_name"])
        vlan_id = _safe_int(snap.get("vlan_id"))
        iface_map[port_name] = {
            "name": port_name,
            "status": snap.get("oper_status", "notconnect"),
            "speed_bps": _safe_int(snap.get("speed_bps")),
            "speed_str": _fmt_speed(_safe_int(snap.get("speed_bps"))),
            "in_octets": _safe_int(snap.get("in_octets")),
            "out_octets": _safe_int(snap.get("out_octets")),
            "traffic_mbps": round(
                (_safe_int(snap.get("in_octets")) + _safe_int(snap.get("out_octets"))) / 1_000_000, 2
            ),
            "in_errors": _safe_int(snap.get("in_errors")),
            "out_errors": _safe_int(snap.get("out_errors")),
            "in_discards": _safe_int(snap.get("in_discards")),
            "out_discards": _safe_int(snap.get("out_discards")),
        }
        poe_map[port_name] = {
            "port": port_name,
            "status": snap.get("poe_status", ""),
            "power_mw": _safe_int(snap.get("poe_power_mw")),
            "power_w": round(_safe_int(snap.get("poe_power_mw")) / 1000, 1),
        }
        if vlan_id == CAMERA_VLAN_ID and re.match(r'^(Fa|Gi|Te|Eth|Gig)', port_name, re.I):
            vlan_ports.append(port_name)

    return {
        "vlan_ports": sorted(set(vlan_ports)),
        "iface_map": iface_map,
        "poe_map": poe_map,
    }


def _build_mac_port_map(mac_table: list, allowed_ports=None) -> dict:
    m = {}
    allowed_ports = {_canonical_port(port) for port in (allowed_ports or [])}
    for e in mac_table:
        port = _canonical_port(e.get("port", ""))
        mac = e.get("mac", "")
        if allowed_ports and port not in allowed_ports:
            continue
        if port and mac and mac != "00:00:00:00:00:00":
            m.setdefault(port, []).append(mac)
    for port, macs in m.items():
        m[port] = macs[:MAX_MACS_PER_CAMERA]
    return m


def _extract_vlan100_ports_from_mac_table(mac_table: list) -> list:
    ports = []
    seen = set()
    for entry in mac_table:
        port = _canonical_port(entry.get("port", ""))
        vlan_id = _safe_int(entry.get("vlan_id"))
        if vlan_id != CAMERA_VLAN_ID:
            continue
        if not port or not re.match(r'^(Fa|Gi|Te|Eth|Gig)', port, re.I):
            continue
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
    return ports


def _analysis_cache_key(switch_id: int, hours: int) -> str:
    return f"cam_vlan_{switch_id}_{hours}"


def _latest_cache_key(switch_id: int) -> str:
    return f"cam_vlan_latest_{switch_id}"


def invalidate_camera_cache(switch_id: int, hours: int | None = None) -> None:
    if hours is not None:
        cache.delete(_analysis_cache_key(switch_id, hours))
    else:
        for h in (1, 6, 12, 24, 48, 168):
            cache.delete(_analysis_cache_key(switch_id, h))
    cache.delete(_latest_cache_key(switch_id))


def _get_camera_mac_table(ip: str, community: str) -> dict:
    """
    يفضّل community@100 لتجنب مسح جداول MAC لكل VLAN.
    لو لم يدعم السويتش ذلك، يرجع للطريقة العامة.
    """
    from core.services.switch_inspector import get_mac_table

    vlan_community = f"{community}@{CAMERA_VLAN_ID}"
    vlan_scoped = _safe_snmp_call(get_mac_table, ip, vlan_community, limit=5000) or {"mac_table": []}
    global_data = _safe_snmp_call(get_mac_table, ip, community, limit=5000) or {"mac_table": []}

    merged = []
    seen = set()
    for dataset in (vlan_scoped.get("mac_table", []), global_data.get("mac_table", []), _get_cached_mac_rows()):
        for entry in dataset:
            mac = str(entry.get("mac", "")).lower()
            port = _canonical_port(entry.get("port", ""))
            vlan_id = _safe_int(entry.get("vlan_id"))
            key = (mac, port, vlan_id)
            if not mac or key in seen:
                continue
            seen.add(key)
            merged.append({
                "mac": mac,
                "port": port,
                "type": entry.get("type", "learned"),
                "vlan_id": vlan_id or entry.get("vlan_id"),
            })

    return {
        "mac_table": merged,
        "total": len(merged),
        "offset": 0,
        "limit": len(merged),
    }


def _get_cached_mac_rows() -> list:
    try:
        from core.models import MACTable

        rows = (
            MACTable.objects
            .filter(vlan=CAMERA_VLAN_ID)
            .values("mac_address", "interface", "vlan")
        )
        return [
            {
                "mac": str(row["mac_address"]).lower(),
                "port": _canonical_port(row["interface"]),
                "type": "cached",
                "vlan_id": row["vlan"],
            }
            for row in rows
        ]
    except Exception:
        return []


def _get_cached_arp_rows(interesting_macs=None) -> dict:
    interesting_macs = {str(mac).lower() for mac in (interesting_macs or [])}
    arp_map = {}
    try:
        from core.models import ARPTable

        qs = ARPTable.objects.all().values("mac_address", "ip_address")
        for row in qs:
            mac = str(row["mac_address"]).lower()
            if interesting_macs and mac not in interesting_macs:
                continue
            arp_map.setdefault(mac, []).append(str(row["ip_address"]))
            if len(arp_map[mac]) > MAX_IPS_PER_CAMERA:
                arp_map[mac] = arp_map[mac][:MAX_IPS_PER_CAMERA]
    except Exception:
        pass
    return arp_map


def _normalize_status(raw: str) -> str:
    s = str(raw).lower()
    if "connected" in s or s == "up": return "connected"
    if "notconnect" in s or "down" in s: return "notconnect"
    return s


def _canonical_port(port_name) -> str:
    s = str(port_name or "").strip()
    if not s:
        return ""
    s = re.sub(r'(?i)^gigabitethernet', 'Gi', s)
    s = re.sub(r'(?i)^fastethernet', 'Fa', s)
    s = re.sub(r'(?i)^tengigabitethernet', 'Te', s)
    s = re.sub(r'(?i)^ethernet', 'Eth', s)
    s = re.sub(r'\s+', '', s)
    return s


def _safe_int(value, default=0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _safe_float(value, default=0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _fmt_speed(bps: int) -> str:
    if not bps:
        return "—"
    if bps >= 1_000_000_000:
        return f"{bps//1_000_000_000}G"
    if bps >= 1_000_000:
        return f"{bps//1_000_000}M"
    if bps >= 1_000:
        return f"{bps//1_000}K"
    return str(bps)


def _future_result_or_default(future, default, timeout=0):
    try:
        if future.done():
            return future.result() or default
        return future.result(timeout=timeout) or default
    except Exception:
        return default


def _format_mac(raw: str) -> str:
    s = str(raw).strip()
    if re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', s, re.I):
        return s.lower()
    h = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(h) >= 12:
        return ":".join(h[i:i+2] for i in range(0, 12, 2)).lower()
    return ""


def _oui_lookup(mac: str) -> str:
    if not mac or len(mac) < 8:
        return "Unknown"
    oui = mac[:8].upper().replace(":", "")
    for prefix, name in _OUI_MAP.items():
        if oui.startswith(prefix.replace(":", "")):
            return name
    return "Generic IP Camera"


def _analyze_single_port(port_name, iface_map, poe_map, identity_map) -> dict:
    port_name = _canonical_port(port_name)
    ifc = iface_map.get(port_name, {})
    poe = poe_map.get(port_name, {})
    identity = identity_map.get(port_name, {})
    macs = identity.get("mac_addresses", [])
    ips = identity.get("ip_addresses", [])
    
    oper_status = _normalize_status(ifc.get("status", "notconnect"))
    traffic_mbps = _safe_float(ifc.get("traffic_mbps") or 0)
    in_errors = _safe_int(ifc.get("in_errors") or 0)
    in_discards = _safe_int(ifc.get("in_discards") or 0)
    
    # حالة الكاميرا
    if oper_status == "connected":
        cam_status = "silent" if traffic_mbps < 0.1 else "online"
    else:
        cam_status = "offline"
    
    # درجة الصحة
    health = 100
    health -= min(30, int(in_errors / 100) * 5)
    health -= min(20, int(in_discards / 50) * 5)
    if poe.get("status") in ("fault", "deny"):
        health -= 40
    if cam_status == "silent":
        health -= 25
    if cam_status == "offline":
        health = 0
    health = max(0, min(100, health))
    
    # جودة الفيديو
    if cam_status != "online":
        quality = "—"
    elif traffic_mbps >= 6:
        quality = "4K/High"
    elif traffic_mbps >= 3:
        quality = "1080p"
    elif traffic_mbps >= 1:
        quality = "720p"
    else:
        quality = "Low/CIF"
    
    return {
        "port": port_name,
        "status": cam_status,
        "health_score": health,
        "traffic_mbps": round(traffic_mbps, 2),
        "in_errors": in_errors,
        "out_errors": _safe_int(ifc.get("out_errors") or 0),
        "in_discards": in_discards,
        "speed": ifc.get("speed_str", "—"),
        "poe_status": poe.get("status", "—"),
        "poe_power_w": _safe_float(poe.get("power_w"), _safe_float(poe.get("power_mw"), 0) / 1000),
        "mac_addresses": macs[:MAX_MACS_PER_CAMERA],
        "ip_addresses": ips,
        "manufacturer": identity.get("manufacturer") or _oui_lookup(macs[0] if macs else ""),
        "estimated_quality": quality,
        "alias": ifc.get("alias", ""),
    }


def _build_summary(cameras: list) -> dict:
    if not cameras:
        return {"total_cameras": 0, "online_cameras": 0, "offline_cameras": 0,
                "silent_cameras": 0, "total_traffic_mbps": 0}
    
    total_cameras = len(cameras)
    online = sum(1 for c in cameras if c["status"] == "online")
    offline = sum(1 for c in cameras if c["status"] == "offline")
    silent = sum(1 for c in cameras if c["status"] == "silent")
    total_traffic = sum(c["traffic_mbps"] for c in cameras)
    avg_health = round(sum(c["health_score"] for c in cameras) / total_cameras)
    poe_faults = sum(1 for c in cameras if c["poe_status"] == "fault")
    
    return {
        "total_cameras": total_cameras,
        "online_cameras": online,
        "offline_cameras": offline,
        "silent_cameras": silent,
        "total_traffic_mbps": round(total_traffic, 1),
        "avg_traffic_mbps": round(total_traffic / total_cameras, 2) if total_cameras else 0,
        "max_traffic_mbps": round(max(c["traffic_mbps"] for c in cameras), 2) if cameras else 0,
        "avg_health_score": avg_health,
        "poe_faults": poe_faults,
    }


def _detect_issues(cameras: list) -> list:
    issues = []
    for c in cameras:
        if c["status"] == "offline":
            issues.append({
                "severity": "critical",
                "port": c["port"],
                "message": f"كاميرا offline على المنفذ {c['port']}",
                "recommendation": "تحقق من الكابل وطاقة PoE",
            })
        elif c["status"] == "silent":
            issues.append({
                "severity": "warning",
                "port": c["port"],
                "message": f"كاميرا صامتة على {c['port']} (متصلة لكن بلا ترافيك)",
                "recommendation": "الكاميرا قد تكون متجمدة — جرب إعادة تشغيل المنفذ",
            })
        if c["in_errors"] > 100:
            issues.append({
                "severity": "critical",
                "port": c["port"],
                "message": f"أخطاء CRC عالية على {c['port']}: {c['in_errors']}",
                "recommendation": "استبدل الكابل أو افحص التوصيلات",
            })
        if c["poe_status"] == "fault":
            issues.append({
                "severity": "critical",
                "port": c["port"],
                "message": f"عطل PoE على {c['port']}",
                "recommendation": "تحقق من استهلاك الكاميرا وجودة الكابل",
            })
    return sorted(issues, key=lambda x: 0 if x["severity"] == "critical" else 1)


def _build_empty_result(switch, hours: int) -> dict:
    return {
        "switch": {
            "id": switch.id,
            "hostname": switch.hostname,
            "ip": switch.ip_address,
            "location": switch.location.name if switch.location else "—",
        },
        "vlan_id": 100,
        "hours": hours,
        "cameras": [],
        "summary": {"total_cameras": 0, "online_cameras": 0,
                    "offline_cameras": 0, "silent_cameras": 0,
                    "total_traffic_mbps": 0,
                    "message": ""},
        "issues": [],
        "from_cache": False,
        "generated_at": timezone.now().isoformat(),
    }

# ══════════════════════════════════════════════════════════════
#  ملخص شامل لكل السويتشات (خفيف — يقرأ من cache فقط)
# ══════════════════════════════════════════════════════════════
def get_global_camera_summary() -> dict:
    """
    ملخص خفيف يقرأ فقط من cache المخزَّن.
    لا يُشغِّل أي استدعاء SNMP جديد.
    """
    from core.models import Switch

    total_cameras = 0
    total_traffic = 0
    total_issues  = 0
    switches_with_cameras = 0
    all_critical_issues   = []
    location_stats        = {}

    for sw in Switch.objects.select_related("location").all():
        cache_key = _latest_cache_key(sw.id)
        cached    = cache.get(cache_key)
        if not cached:
            continue   # لا نُشغِّل SNMP هنا — نقرأ فقط ما هو محزَّن

        cams = cached.get("cameras", [])
        if not cams:
            continue

        switches_with_cameras += 1
        total_cameras += len(cams)
        total_traffic += cached.get("summary", {}).get("total_traffic_mbps", 0)

        loc = sw.location.name if sw.location else "Unknown"
        if loc not in location_stats:
            location_stats[loc] = {"cameras": 0, "offline": 0, "silent": 0, "issues": 0}
        location_stats[loc]["cameras"]  += len(cams)
        location_stats[loc]["offline"]  += sum(1 for c in cams if c["status"] == "offline")
        location_stats[loc]["silent"]   += sum(1 for c in cams if c["status"] == "silent")

        for issue in cached.get("issues", []):
            if issue["severity"] == "critical":
                total_issues += 1
                all_critical_issues.append({
                    **issue,
                    "switch":   sw.hostname,
                    "location": loc,
                })

    return {
        "total_cameras":             total_cameras,
        "total_switches_with_data":  switches_with_cameras,
        "total_traffic_mbps":        round(total_traffic, 1),
        "total_critical_issues":     total_issues,
        "location_stats":            location_stats,
        "critical_issues":           all_critical_issues[:20],
        "generated_at":              timezone.now().isoformat(),
    }
