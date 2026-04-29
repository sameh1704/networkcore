
"""
switch_inspector.py  —  v4 (Hybrid - Fallback Mode)
─────────────────────────────────────────────────────────
- يحاول استخدام IEEE OIDs أولاً
- إذا فشل، يستخدم الطريقة القديمة (VTP) 
- يعيد ترتيب المنافذ بشكل صحيح
"""

from .snmp import snmp_get, snmp_walk, snmp_walk_with_index
import re
import time

# ═══════════════════════════════════════════════════════
#  OIDs
# ═══════════════════════════════════════════════════════

# System
OID_SYS_DESCR    = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME     = "1.3.6.1.2.1.1.5.0"
OID_SYS_UPTIME   = "1.3.6.1.2.1.1.3.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_SYS_CONTACT  = "1.3.6.1.2.1.1.4.0"

# Entity
OID_ENT_MODEL    = "1.3.6.1.2.1.47.1.1.1.1.13"
OID_ENT_SERIAL   = "1.3.6.1.2.1.47.1.1.1.1.11"

# Interfaces
OID_IF_NAME      = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_DESCR     = "1.3.6.1.2.1.2.2.1.2"
OID_IF_OPER      = "1.3.6.1.2.1.2.2.1.8"
OID_IF_ADMIN     = "1.3.6.1.2.1.2.2.1.7"
OID_IF_SPEED     = "1.3.6.1.2.1.2.2.1.5"
OID_IF_IN_OCT    = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT_OCT   = "1.3.6.1.2.1.2.2.1.16"
OID_IF_IN_ERR    = "1.3.6.1.2.1.2.2.1.14"
OID_IF_OUT_ERR   = "1.3.6.1.2.1.2.2.1.20"
OID_IF_IN_DISC   = "1.3.6.1.2.1.2.2.1.13"
OID_IF_OUT_DISC  = "1.3.6.1.2.1.2.2.1.19"
OID_IF_MTU       = "1.3.6.1.2.1.2.2.1.4"
OID_IF_ALIAS     = "1.3.6.1.2.1.31.1.1.1.18"

# VLAN - Multiple approaches
OID_VLAN_NAMES_VTP = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"   # VTP MIB
OID_VLAN_STATE_VTP = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"   # VTP State
OID_VLAN_PORTMAP   = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"   # vmVlan

# IEEE 802.1Q Alternative OIDs
OID_VLAN_NAMES_IEEE = "1.3.6.1.2.1.17.7.1.4.3.1.2"
OID_VLAN_STATE_IEEE = "1.3.6.1.2.1.17.7.1.4.3.1.5"
OID_VLAN_UNTAGGED   = "1.3.6.1.2.1.17.7.1.4.3.1.4"

# IP
OID_IP_IF_IDX    = "1.3.6.1.2.1.4.20.1.2"
OID_IP_MASK      = "1.3.6.1.2.1.4.20.1.3"

# CDP
OID_CDP_IF_IDX   = "1.3.6.1.4.1.9.9.23.1.2.1.1.1"
OID_CDP_DEV_ID   = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
OID_CDP_PORT     = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
OID_CDP_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
OID_CDP_IP       = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"

# PoE
OID_POE_OPER_STD = "1.3.6.1.2.1.105.1.1.1.3"
OID_POE_POWER    = "1.3.6.1.2.1.105.1.1.1.6"
OID_POE_CLASS    = "1.3.6.1.2.1.105.1.1.1.10"
OID_POE_TOTAL    = "1.3.6.1.4.1.9.9.402.1.2.1.7.1"
OID_POE_CONSUMED = "1.3.6.1.4.1.9.9.402.1.2.1.8.1"

# Port-security
OID_PSEC_STATUS  = "1.3.6.1.4.1.9.9.315.1.2.1.1.1"
OID_PSEC_MAX_MAC = "1.3.6.1.4.1.9.9.315.1.2.1.1.3"
OID_PSEC_CURR    = "1.3.6.1.4.1.9.9.315.1.2.1.1.6"
OID_PSEC_VIOL    = "1.3.6.1.4.1.9.9.315.1.2.1.1.9"

# MAC Table
OID_MAC_ADDR     = "1.3.6.1.2.1.17.4.3.1.1"
OID_MAC_PORT     = "1.3.6.1.2.1.17.4.3.1.2"
OID_MAC_TYPE     = "1.3.6.1.2.1.17.4.3.1.3"

# CPU / Memory
OID_CPU_5S       = "1.3.6.1.4.1.9.2.1.57.0"
OID_CPU_1M       = "1.3.6.1.4.1.9.2.1.58.0"
OID_CPU_5M       = "1.3.6.1.4.1.9.2.1.59.0"
OID_MEM_USED     = "1.3.6.1.4.1.9.9.48.1.1.1.5.1"
OID_MEM_FREE     = "1.3.6.1.4.1.9.9.48.1.1.1.6.1"

# TDR
OID_TDR_STATUS   = "1.3.6.1.4.1.9.9.119.1.4.1.1.3"
OID_TDR_LENGTH   = "1.3.6.1.4.1.9.9.119.1.4.1.1.4"

# STP
OID_STP_PORT_STATE = "1.3.6.1.2.1.17.2.15.1.3"
OID_STP_ROOT      = "1.3.6.1.2.1.17.2.5"

# Environment
OID_TEMP         = "1.3.6.1.4.1.9.9.13.1.3.1.3"
OID_FAN          = "1.3.6.1.4.1.9.9.13.1.4.1.3"
OID_PWR_SUPPLY   = "1.3.6.1.4.1.9.9.13.1.5.1.3"


# ═══════════════════════════════════════════════════════
#  Cache System
# ═══════════════════════════════════════════════════════
_CACHE = {}

def _cache_get(key):
    entry = _CACHE.get(key)
    if entry and time.time() - entry["ts"] < entry["ttl"]:
        return entry["val"]
    return None

def _cache_set(key, val, ttl=60):
    _CACHE[key] = {"val": val, "ts": time.time(), "ttl": ttl}


# ═══════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════
PHYSICAL_RE = re.compile(
    r'^(Fa|Gi|Te|Eth|Fast|Gig|Ten|ge-|xe-|et-)',
    re.IGNORECASE
)

def _i(val, default=0):
    try:
        return int(str(val).strip())
    except:
        return default

def _safe(lst, i, default=None):
    return lst[i] if 0 <= i < len(lst) else default

def _physical_offset(if_names):
    for idx, n in enumerate(if_names):
        if PHYSICAL_RE.match(str(n)):
            return idx
    return 0

def _fmt_speed(bps):
    if not bps:
        return "—"
    if bps >= 1_000_000_000:
        return f"{bps//1_000_000_000}G"
    if bps >= 1_000_000:
        return f"{bps//1_000_000}M"
    if bps >= 1_000:
        return f"{bps//1_000}K"
    return str(bps)

def _fmt_uptime(raw):
    try:
        s = str(raw)
        m = re.search(r'\((\d+)\)', s)
        ticks = int(m.group(1)) if m else int(s)
        secs = ticks // 100
        d, r = divmod(secs, 86400)
        h, r = divmod(r, 3600)
        mn, s = divmod(r, 60)
        parts = []
        if d:
            parts.append(f"{d}d")
        if h:
            parts.append(f"{h}h")
        if mn:
            parts.append(f"{mn}m")
        parts.append(f"{s}s")
        return " ".join(parts)
    except:
        return str(raw)

def _get_if_names(ip, community):
    key = f"ifnames:{ip}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    names = snmp_walk(ip, community, OID_IF_NAME) or []
    _cache_set(key, names, ttl=120)
    return names


# ═══════════════════════════════════════════════════════
#  1. System Info
# ═══════════════════════════════════════════════════════
def get_system_info(ip, community):
    key = f"sysinfo:{ip}"
    cached = _cache_get(key)
    if cached:
        return cached

    descr = snmp_get(ip, community, OID_SYS_DESCR) or ""
    hostname = snmp_get(ip, community, OID_SYS_NAME) or "Unknown"
    uptime = snmp_get(ip, community, OID_SYS_UPTIME) or "0"
    location = snmp_get(ip, community, OID_SYS_LOCATION) or ""
    contact = snmp_get(ip, community, OID_SYS_CONTACT) or ""

    models = snmp_walk(ip, community, OID_ENT_MODEL) or []
    serials = snmp_walk(ip, community, OID_ENT_SERIAL) or []
    model = next((m for m in models if str(m).strip() and str(m) not in ("", "0")), "")
    serial = next((s for s in serials if str(s).strip() and str(s) not in ("", "0")), "")

    ios = ""
    m = re.search(r'Version\s+([\d\w\.\(\)]+)', descr)
    if m:
        ios = m.group(1)

    if not model:
        m2 = re.search(r'([A-Z]{2,3}-[A-Z0-9\-]+)', descr)
        if m2:
            model = m2.group(1)

    cpu_5s = _i(snmp_get(ip, community, OID_CPU_5S) or 0)
    cpu_1m = _i(snmp_get(ip, community, OID_CPU_1M) or 0)
    cpu_5m = _i(snmp_get(ip, community, OID_CPU_5M) or 0)

    mem_used = _i(snmp_get(ip, community, OID_MEM_USED) or 0)
    mem_free = _i(snmp_get(ip, community, OID_MEM_FREE) or 0)
    mem_total = mem_used + mem_free
    mem_pct = round(mem_used / mem_total * 100) if mem_total else 0

    result = {
        "hostname": hostname, "model": model, "serial": serial,
        "ios": ios, "descr": descr[:120],
        "uptime": _fmt_uptime(uptime),
        "location": location, "contact": contact,
        "cpu_5s": cpu_5s, "cpu_1m": cpu_1m, "cpu_5m": cpu_5m,
        "mem_used": mem_used, "mem_free": mem_free, "mem_pct": mem_pct,
    }
    _cache_set(key, result, ttl=30)
    return result


# ═══════════════════════════════════════════════════════
#  2. Interfaces Detail
# ═══════════════════════════════════════════════════════
def get_interfaces_detail(ip, community):
    key = f"ifaces:{ip}"
    cached = _cache_get(key)
    if cached:
        return cached

    if_names = _get_if_names(ip, community)
    oper = snmp_walk(ip, community, OID_IF_OPER) or []
    admin = snmp_walk(ip, community, OID_IF_ADMIN) or []
    speed = snmp_walk(ip, community, OID_IF_SPEED) or []
    in_oct = snmp_walk(ip, community, OID_IF_IN_OCT) or []
    out_oct = snmp_walk(ip, community, OID_IF_OUT_OCT) or []
    in_err = snmp_walk(ip, community, OID_IF_IN_ERR) or []
    out_err = snmp_walk(ip, community, OID_IF_OUT_ERR) or []
    in_disc = snmp_walk(ip, community, OID_IF_IN_DISC) or []
    out_disc = snmp_walk(ip, community, OID_IF_OUT_DISC) or []
    aliases = snmp_walk(ip, community, OID_IF_ALIAS) or []
    mtu_list = snmp_walk(ip, community, OID_IF_MTU) or []

    result = []
    for i, name in enumerate(if_names):
        if not PHYSICAL_RE.match(str(name)):
            continue

        oper_v = _i(_safe(oper, i, 2))
        admin_v = _i(_safe(admin, i, 2))
        spd = _i(_safe(speed, i, 0))

        if admin_v == 2:
            status = "disabled"
        elif oper_v == 1:
            status = "connected"
        else:
            status = "notconnect"

        in_o = _i(_safe(in_oct, i, 0))
        out_o = _i(_safe(out_oct, i, 0))
        mbps = (in_o + out_o) // 1_000_000
        in_e = _i(_safe(in_err, i, 0))
        out_e = _i(_safe(out_err, i, 0))
        in_d = _i(_safe(in_disc, i, 0))
        out_d = _i(_safe(out_disc, i, 0))

        result.append({
            "if_idx": i,
            "name": str(name),
            "alias": str(_safe(aliases, i, "") or ""),
            "status": status,
            "speed_bps": spd,
            "speed_str": _fmt_speed(spd),
            "in_octets": in_o,
            "out_octets": out_o,
            "traffic_mbps": mbps,
            "in_errors": in_e,
            "out_errors": out_e,
            "in_discards": in_d,
            "out_discards": out_d,
            "mtu": _i(_safe(mtu_list, i, 1500)),
            "has_errors": (in_e + out_e + in_d + out_d) > 0,
        })

    _cache_set(key, result, ttl=30)
    return result


# ═══════════════════════════════════════════════════════
#  3. Error Analysis
# ═══════════════════════════════════════════════════════
def get_error_analysis(interfaces_detail):
    errors = []
    for ifc in interfaces_detail:
        total_err = ifc["in_errors"] + ifc["out_errors"]
        total_disc = ifc["in_discards"] + ifc["out_discards"]
        if total_err == 0 and total_disc == 0:
            continue

        causes, fixes = [], []
        if ifc["in_errors"] > 100:
            causes.append("CRC/FCS errors — كابل تالف أو duplex mismatch")
            fixes.append("استبدل الكابل أو تحقق من duplex/speed")
        if ifc["out_errors"] > 50:
            causes.append("Output errors — congestion أو MTU mismatch")
            fixes.append("فعّل QoS أو تحقق من MTU")
        if ifc["in_discards"] > 50:
            causes.append("Input drops — buffer overflow")
            fixes.append("قلل الـ traffic أو وسّع الـ buffer")
        if ifc["out_discards"] > 50:
            causes.append("Output drops — queue full")
            fixes.append("فعّل QoS أو upgrade الـ link")

        severity = (
            "critical" if total_err > 1000 or total_disc > 500 else
            "warning" if total_err > 100 or total_disc > 50 else
            "info"
        )
        errors.append({
            "name": ifc["name"],
            "in_errors": ifc["in_errors"],
            "out_errors": ifc["out_errors"],
            "in_discards": ifc["in_discards"],
            "out_discards": ifc["out_discards"],
            "severity": severity,
            "causes": causes,
            "fixes": fixes,
        })
    return sorted(errors, key=lambda x: x["in_errors"] + x["out_errors"], reverse=True)


# ═══════════════════════════════════════════════════════
#  4. VLANs - النسخة الهجينة (تعمل في كل الأحوال)
# ═══════════════════════════════════════════════════════
def get_vlans_full(ip, community):
    """
    نفس منطق monitoring.get_vlans() المُصلح مع cache.
    الإصلاح: استخدام snmp_walk_with_index لكل من
    IF_NAME و VM_VLAN و VLAN_NAMES للحصول على
    الـ ifIndex الحقيقي.
    """
    key = f"vlans:{ip}"
    cached = _cache_get(key)
    if cached:
        return cached

    # ── 1. ifIndex الحقيقي → اسم المنفذ ─────────────────
    if_name_idx = snmp_walk_with_index(
        ip, community, OID_IF_NAME
    ) or []

    ifidx2name = {suffix: str(name) for suffix, name in if_name_idx}

    # ── 2. VM_VLAN: ifIndex → vlan_id ───────────────────
    vm_vlan_idx = snmp_walk_with_index(
        ip, community, OID_VLAN_PORTMAP
    ) or []

    vlan_ports = {}
    for suffix, vlan_raw in vm_vlan_idx:
        vid = _i(vlan_raw)
        if not (1 <= vid <= 4094):
            continue
        port_name = ifidx2name.get(suffix, "")
        if port_name and PHYSICAL_RE.match(port_name):
            vlan_ports.setdefault(vid, []).append(port_name)

    # ── 2b. IEEE/Q-BRIDGE fallback: VLAN → port bitmap ─────
    # بعض السويتشات لا تُظهر منافذ VLAN 100 عبر vmVlan بشكل موثوق،
    # لذا نفكك الـ bitmap ونحوّل bridge-port → ifIndex → port name.
    if not vlan_ports:
        bp_ifidx_raw = snmp_walk_with_index(
            ip, community, OID_DOT1D_BASE_PORT_IFINDEX
        ) or []
        bp2ifidx = {}
        for suffix, ifidx_val in bp_ifidx_raw:
            bp = suffix.split(".")[-1]
            bp2ifidx[bp] = _i(ifidx_val)

        vlan_bitmap_idx = snmp_walk_with_index(
            ip, community, OID_VLAN_UNTAGGED
        ) or []

        for suffix, bitmap_raw in vlan_bitmap_idx:
            vid = _last_idx(suffix)
            if not (1 <= vid <= 4094):
                continue
            for bp in _decode_port_bitmap(bitmap_raw):
                ifidx = bp2ifidx.get(str(bp))
                if not ifidx:
                    continue
                port_name = ifidx2name.get(str(ifidx), "")
                if port_name and PHYSICAL_RE.match(port_name):
                    vlan_ports.setdefault(vid, []).append(port_name)

    # ── 3. VLAN_NAMES مع VLAN_ID الحقيقي ────────────────
    vlan_name_idx  = snmp_walk_with_index(
        ip, community, OID_VLAN_NAMES_VTP
    ) or []
    vlan_state_idx = snmp_walk_with_index(
        ip, community, OID_VLAN_STATE_VTP
    ) or []

    vlan_names  = {}
    vlan_states = {}

    for suffix, val in vlan_name_idx:
        vid = _last_idx(suffix)
        if vid and 1 <= vid <= 4094:
            vlan_names[vid] = str(val).strip() or f"VLAN{vid}"

    if not vlan_names:
        vlan_name_idx = snmp_walk_with_index(
            ip, community, OID_VLAN_NAMES_IEEE
        ) or []
        for suffix, val in vlan_name_idx:
            vid = _last_idx(suffix)
            if vid and 1 <= vid <= 4094:
                vlan_names[vid] = str(val).strip() or f"VLAN{vid}"

    for suffix, val in vlan_state_idx:
        vid = _last_idx(suffix)
        if vid:
            vlan_states[vid] = (str(val) == "1")

    # ── 4. القائمة النهائية ──────────────────────────────
    result = []
    all_vlan_ids = sorted(set(vlan_names.keys()) | set(vlan_ports.keys()))
    for vid in all_vlan_ids:
        name       = vlan_names.get(vid, f"VLAN{vid}")
        active     = vlan_states.get(vid, False)
        port_names = sorted(set(vlan_ports.get(vid, [])))
        result.append({
            "vlan_id"   : vid,
            "name"      : name,
            "active"    : active,
            "port_names": port_names,
            "port_count": len(port_names),
        })

    _cache_set(key, result, ttl=60)
    return result


def _last_idx(suffix: str) -> int:
    """آخر رقم موجب في OID suffix"""
    for p in reversed(str(suffix).split(".")):
        try:
            v = int(p)
            if v > 0:
                return v
        except ValueError:
            continue
    return 0 


def _decode_port_bitmap(raw) -> list[int]:
    """
    يفكك Q-BRIDGE port bitmap إلى أرقام bridge ports (1-based).
    يدعم 0xHEX, dot notation, bytes النصية, و OctetString المطبوعة.
    """
    if raw is None:
        return []

    s = str(raw).strip()
    data = b""

    if s.lower().startswith("0x"):
        hex_str = re.sub(r'[^0-9a-fA-F]', '', s[2:])
        if len(hex_str) % 2 == 1:
            hex_str = "0" + hex_str
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            data = b""
    elif "." in s and all(p.isdigit() for p in s.split(".")):
        try:
            data = bytes(int(p) for p in s.split(".") if 0 <= int(p) <= 255)
        except Exception:
            data = b""
    else:
        try:
            data = s.encode("latin-1", errors="ignore")
        except Exception:
            data = b""

    ports = []
    for byte_index, byte_val in enumerate(data):
        for bit in range(8):
            if byte_val & (1 << (7 - bit)):
                ports.append(byte_index * 8 + bit + 1)
    return ports

# ═══════════════════════════════════════════════════════
#  5. IP Interface Brief
# ═══════════════════════════════════════════════════════
def get_ip_interfaces(ip, community):
    key = f"ipbrief:{ip}"
    cached = _cache_get(key)
    if cached:
        return cached

    if_names = _get_if_names(ip, community)
    oper = snmp_walk(ip, community, OID_IF_OPER) or []

    oper_map = {i+1: _i(_safe(oper, i, 2)) for i in range(len(oper))}
    ifidx2name = {i+1: str(n) for i, n in enumerate(if_names)}

    ip_ifidx = snmp_walk_with_index(ip, community, OID_IP_IF_IDX) or []
    ip_mask = snmp_walk_with_index(ip, community, OID_IP_MASK) or []

    mask_map = {suffix: val for suffix, val in ip_mask}

    result = []
    for suffix, ifidx_raw in ip_ifidx:
        ip_addr = suffix
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_addr):
            continue
        if ip_addr.startswith("127."):
            continue

        ifidx = _i(ifidx_raw)
        if_name = ifidx2name.get(ifidx, f"If{ifidx}")
        oper_v = oper_map.get(ifidx, 2)
        raw_mask = mask_map.get(suffix, "")
        clean_mask = _clean_mask(raw_mask)

        result.append({
            "name": if_name,
            "ip": ip_addr,
            "mask": clean_mask,
            "status": "up" if oper_v == 1 else "down",
        })

    _cache_set(key, result, ttl=60)
    return sorted(result, key=lambda x: x["name"])


def _clean_mask(raw):
    if not raw:
        return "255.255.255.0"

    s = str(raw).strip()

    # ── 1. already dotted ─────────────────
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', s):
        return s

    # ── 2. Hex format (0xFFFFFF00) ───────
    if s.startswith("0x"):
        try:
            val = int(s, 16)
            return ".".join(str((val >> i) & 0xFF) for i in [24,16,8,0])
        except Exception:
            pass

    # ── 3. Binary / weird chars (ÿÿÿ) ─────
    try:
        b = s.encode('latin-1', errors='ignore')
        if len(b) == 4:
            return ".".join(str(x) for x in b)
    except Exception:
        pass

    # ── 4. \xFF\xFF\xFF\x00 ─────────────
    try:
        parts = re.findall(r'\\x([0-9a-fA-F]{2})', s)
        if len(parts) == 4:
            return ".".join(str(int(p, 16)) for p in parts)
    except Exception:
        pass

    return "255.255.255.0"


# ═══════════════════════════════════════════════════════
#  6. CDP Neighbors
# ═══════════════════════════════════════════════════════
def get_cdp_neighbors(ip, community):
    key = f"cdp:{ip}"
    cached = _cache_get(key)
    if cached:
        return cached

    if_names = _get_if_names(ip, community)
    dev_ids = snmp_walk(ip, community, OID_CDP_DEV_ID) or []
    cdp_ports = snmp_walk(ip, community, OID_CDP_PORT) or []
    platforms = snmp_walk(ip, community, OID_CDP_PLATFORM) or []
    cdp_ips = snmp_walk(ip, community, OID_CDP_IP) or []
    if_idxs = snmp_walk(ip, community, OID_CDP_IF_IDX) or []

    result = []
    for i in range(len(dev_ids)):
        if_idx = _i(_safe(if_idxs, i, 0))
        local_port = if_names[if_idx-1] if 0 < if_idx <= len(if_names) else f"If{if_idx}"
        raw_ip = _safe(cdp_ips, i, "")
        dev_ip = _parse_cdp_ip_advanced(str(raw_ip)) if raw_ip else ""

        result.append({
            "local_port": str(local_port),
            "device_id": str(_safe(dev_ids, i, "")),
            "remote_port": str(_safe(cdp_ports, i, "")),
            "platform": str(_safe(platforms, i, "")),
            "ip": dev_ip,
        })

    _cache_set(key, result, ttl=60)
    return result


def _parse_cdp_ip_advanced(raw):
    s = str(raw)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', s):
        return s
    numbers = re.findall(r'\d+', s)
    if len(numbers) >= 4:
        octets = [int(n) for n in numbers[:4] if 0 <= int(n) <= 255]
        if len(octets) == 4:
            return '.'.join(str(o) for o in octets)
    try:
        bytes_data = bytes([ord(c) for c in s if ord(c) < 256])
        if len(bytes_data) >= 4:
            octets = [str(b) for b in bytes_data[:4] if 0 <= b <= 255]
            if len(octets) == 4:
                return '.'.join(octets)
    except Exception:
        pass
    return s if s else ""


# ═══════════════════════════════════════════════════════
#  7. PoE Detail
# ═══════════════════════════════════════════════════════
def get_poe_detail(ip, community):
    key = f"poe:{ip}"
    cached = _cache_get(key)
    if cached:
        return cached

    if_names = _get_if_names(ip, community)
    offset = _physical_offset(if_names)

    oper = snmp_walk(ip, community, OID_POE_OPER_STD) or []
    power = snmp_walk(ip, community, OID_POE_POWER) or []
    poe_cls = snmp_walk(ip, community, OID_POE_CLASS) or []

    total_w = _i(snmp_get(ip, community, OID_POE_TOTAL) or 0)
    consumed_w = _i(snmp_get(ip, community, OID_POE_CONSUMED) or 0)

    STATUS_MAP = {"1": "on", "2": "off", "3": "fault",
                  "4": "deny", "5": "searching", "6": "delayedOn"}
    CLASS_MAP = {"1": "Class 0", "2": "Class 1", "3": "Class 2",
                 "4": "Class 3", "5": "Class 4", "6": "Class 0"}

    ports = []
    for i, st_raw in enumerate(oper):
        list_idx = offset + i
        name = if_names[list_idx] if list_idx < len(if_names) else f"Port{i+1}"
        if not PHYSICAL_RE.match(str(name)):
            continue

        st = STATUS_MAP.get(str(st_raw), "unknown")
        pwr_mw = _i(_safe(power, i, 0))
        cls = CLASS_MAP.get(str(_safe(poe_cls, i, "")), "—")

        ports.append({
            "port": str(name),
            "status": st,
            "power_mw": pwr_mw,
            "power_w": round(pwr_mw / 1000, 1),
            "class": cls,
            "faulty": st in ("fault", "deny"),
        })

    result = {
        "ports": ports,
        "total_w": total_w,
        "consumed_w": consumed_w,
        "available_w": max(0, total_w - consumed_w),
        "faulty": [p for p in ports if p["faulty"]],
    }
    _cache_set(key, result, ttl=30)
    return result


# ═══════════════════════════════════════════════════════
#  8. Port Security
# ═══════════════════════════════════════════════════════
def get_port_security(ip, community):
    key = f"psec:{ip}"
    cached = _cache_get(key)
    if cached:
        return cached

    if_names = _get_if_names(ip, community)
    ps_stat = snmp_walk(ip, community, OID_PSEC_STATUS) or []
    ps_max = snmp_walk(ip, community, OID_PSEC_MAX_MAC) or []
    ps_curr = snmp_walk(ip, community, OID_PSEC_CURR) or []
    ps_viol = snmp_walk(ip, community, OID_PSEC_VIOL) or []

    if not ps_stat:
        return {"enabled": False, "ports": [], "enabled_count": 0}

    offset = _physical_offset(if_names)
    S_MAP = {"1": "enabled", "2": "disabled"}
    V_MAP = {"1": "protect", "2": "restrict", "3": "shutdown"}

    ports = []
    for i, st in enumerate(ps_stat):
        list_idx = offset + i
        name = if_names[list_idx] if list_idx < len(if_names) else f"Port{i+1}"
        ports.append({
            "port": str(name),
            "status": S_MAP.get(str(st), "unknown"),
            "max_mac": _i(_safe(ps_max, i, 0)),
            "current_mac": _i(_safe(ps_curr, i, 0)),
            "violation": V_MAP.get(str(_safe(ps_viol, i, "")), "—"),
        })

    enabled = [p for p in ports if p["status"] == "enabled"]
    result = {
        "enabled": bool(enabled),
        "ports": ports,
        "enabled_count": len(enabled),
    }
    _cache_set(key, result, ttl=60)
    return result


# ═══════════════════════════════════════════════════════
#  9. MAC Table
# ═══════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════
#  9. MAC Table  ← الإصلاح الكامل
# ═══════════════════════════════════════════════════════

# OIDs
OID_MAC_ADDR = "1.3.6.1.2.1.17.4.3.1.1"   # dot1dTpFdbAddress
OID_MAC_PORT = "1.3.6.1.2.1.17.4.3.1.2"   # dot1dTpFdbPort
OID_MAC_TYPE = "1.3.6.1.2.1.17.4.3.1.3"   # dot1dTpFdbStatus
OID_DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # bridge port → ifIndex
OID_DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"    # vlan-aware MAC table
OID_DOT1Q_TP_FDB_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"


def get_mac_table(ip, community, limit=500, offset_n=0):
    """
    يجلب MAC address table مع تحويل bridge port → ifIndex → port name.

    المشكلة القديمة:
      dot1dTpFdbPort يُرجع bridge port number وليس ifIndex مباشرة.
      يجب تحويله عبر dot1dBasePortIfIndex أولاً.

    المشكلة الثانية:
      MAC address في OID INDEX (suffix) وليس في القيمة.
      1.3.6.1.2.1.17.4.3.1.1.A.B.C.D.E.F → suffix = A.B.C.D.E.F
    """
    key = f"mac:{ip}:{limit}:{offset_n}"
    cached = _cache_get(key)
    if cached:
        return cached

    if_names = _get_if_names(ip, community)
    ifidx2name, bp2ifidx = _build_mac_mappers(ip, community, if_names)

    all_macs = _collect_mac_entries(
        ip, community, if_names, ifidx2name, bp2ifidx
    )

    # على Cisco Catalyst أحيانًا يظهر الجدول العالمي فارغًا أو ناقصًا جدًا،
    # بينما الجدول الكامل متاح فقط عبر community@vlan.
    if len(all_macs) <= 2:
        vlan_entries = []
        for vlan_id in _candidate_mac_vlans(ip, community):
            vlan_community = f"{community}@{vlan_id}"
            vlan_entries.extend(
                _collect_mac_entries(
                    ip,
                    vlan_community,
                    if_names,
                    ifidx2name,
                    bp2ifidx,
                    forced_vlan_id=vlan_id,
                )
            )
        if len(vlan_entries) > len(all_macs):
            all_macs = vlan_entries

    # ترتيب حسب المنفذ ثم VLAN ثم MAC مع تفضيل learned أولاً
    all_macs.sort(key=lambda x: (x["port"], x.get("vlan_id") or 0, x["type"] != "learned", x["mac"]))

    total = len(all_macs)
    paged = all_macs[offset_n: offset_n + limit]

    result = {
        "mac_table": paged,
        "total"    : total,
        "offset"   : offset_n,
        "limit"    : limit,
    }
    _cache_set(key, result, ttl=30)
    return result


def _suffix_to_mac(suffix: str) -> str:
    """
    يحوّل OID suffix "A.B.C.D.E.F" (decimal) لـ MAC.
    مثال: "40.161.134.84.176.192" → "28:a1:86:54:b0:c0"
    """
    parts = str(suffix).split(".")
    if len(parts) == 6:
        try:
            octets = [int(p) for p in parts]
            if all(0 <= o <= 255 for o in octets):
                return ":".join(f"{o:02x}" for o in octets)
        except (ValueError, TypeError):
            pass
    return ""


def _parse_mac_suffix(suffix: str):
    """
    يدعم:
    - dot1dTpFdb*: A.B.C.D.E.F
    - dot1qTpFdb*: VLAN.A.B.C.D.E.F
    """
    parts = str(suffix).split(".")
    if len(parts) < 6:
        return (None, "")

    mac_suffix = ".".join(parts[-6:])
    vlan_id = None

    if len(parts) > 6:
        try:
            vlan_id = int(parts[0])
        except (TypeError, ValueError):
            vlan_id = None

    return (vlan_id, _suffix_to_mac(mac_suffix))


def _build_mac_mappers(ip, community, if_names):
    bp_ifidx_raw = snmp_walk_with_index(
        ip, community, OID_DOT1D_BASE_PORT_IFINDEX
    ) or []

    bp2ifidx = {}
    for suffix, ifidx_val in bp_ifidx_raw:
        bp = suffix.split(".")[-1]
        bp2ifidx[bp] = _i(ifidx_val)

    if_name_idx = snmp_walk_with_index(
        ip, community, OID_IF_NAME
    ) or []
    ifidx2name = {str(_i(s) if s.isdigit() else 0): str(n) for s, n in if_name_idx}

    for i, n in enumerate(if_names):
        ifidx2name.setdefault(str(i + 1), str(n))

    return ifidx2name, bp2ifidx


def _bridge_port_to_name(bp_str, if_names, ifidx2name, bp2ifidx):
    ifidx = bp2ifidx.get(bp_str)
    if ifidx:
        name = ifidx2name.get(str(ifidx))
        if name:
            return name

    try:
        bp_int = int(bp_str)
        if 0 < bp_int <= len(if_names):
            return str(if_names[bp_int - 1])
    except Exception:
        pass

    return f"port{bp_str}"


def _collect_mac_entries(ip, community, if_names, ifidx2name, bp2ifidx, forced_vlan_id=None):
    mac_port_raw = snmp_walk_with_index(ip, community, OID_MAC_PORT) or []
    mac_type_raw = snmp_walk_with_index(ip, community, OID_MAC_TYPE) or []

    if not mac_port_raw:
        mac_port_raw = snmp_walk_with_index(
            ip, community, OID_DOT1Q_TP_FDB_PORT
        ) or []
        mac_type_raw = snmp_walk_with_index(
            ip, community, OID_DOT1Q_TP_FDB_STATUS
        ) or []

    type_map_raw = {suffix: val for suffix, val in mac_type_raw}
    type_map = {
        "1": "other",
        "2": "invalid",
        "3": "learned",
        "4": "self",
        "5": "mgmt",
    }

    results = []
    seen = set()

    for suffix, bp_raw in mac_port_raw:
        vlan_id, mac_str = _parse_mac_suffix(suffix)
        vlan_id = forced_vlan_id if forced_vlan_id is not None else vlan_id
        if not mac_str:
            continue
        if not _is_valid_mac(mac_str):
            continue

        bp_str = str(_i(bp_raw))
        port_name = _bridge_port_to_name(bp_str, if_names, ifidx2name, bp2ifidx)
        entry_type = type_map.get(str(type_map_raw.get(suffix, "3")), "learned")

        if entry_type == "invalid":
            continue

        dedupe_key = (mac_str, port_name, vlan_id)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        results.append({
            "mac": mac_str,
            "port": port_name,
            "type": entry_type,
            "vlan_id": vlan_id,
        })

    return results


def _candidate_mac_vlans(ip, community):
    try:
        vlans = get_vlans_full(ip, community) or []
    except Exception:
        vlans = []

    candidates = []
    for vlan in vlans:
        vid = _i(vlan.get("vlan_id"))
        if not (1 <= vid <= 4094):
            continue
        if vid in (1002, 1003, 1004, 1005):
            continue
        candidates.append(vid)

    return candidates[:128]


def _format_mac(raw: str) -> str:
    """
    يحوّل أي صيغة MAC لـ xx:xx:xx:xx:xx:xx.
    يتعامل مع كل ما يُرجعه pysnmp.
    """
    s = str(raw).strip()

    # 1. 0x + 12 hex chars (pysnmp OctetString.__str__)
    if s.lower().startswith("0x"):
        h = s[2:].replace(":","").replace("-","").replace(".","").replace(" ","")
        if len(h) == 12:
            return ":".join(h[i:i+2] for i in range(0,12,2)).lower()

    # 2. Colon-separated (padded أو غير padded)
    # مثل "00:17:94:06:32:01" أو "0:17:94:6:32:1"
    colon_parts = s.split(":")
    if len(colon_parts) == 6:
        try:
            padded = [f"{int(p, 16):02x}" for p in colon_parts]
            return ":".join(padded)
        except (ValueError, TypeError):
            pass

    # 3. Dot notation: "0017.9406.3201" أو "FFFF.FFFF.FFFF"
    dot_parts = s.split(".")
    if len(dot_parts) == 3 and all(len(d) <= 4 for d in dot_parts):
        h = re.sub(r'[^0-9a-fA-F]', '', "".join(dot_parts))
        if len(h) == 12:
            return ":".join(h[i:i+2] for i in range(0,12,2)).lower()

    # 4. Plain 12 hex chars بدون separators
    h_only = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(h_only) == 12:
        return ":".join(h_only[i:i+2] for i in range(0,12,2)).lower()

    # 5. Escaped bytes: \xNN\xNN...
    esc_parts = re.findall(r'\\x([0-9a-fA-F]{2})', s)
    if len(esc_parts) == 6:
        return ":".join(esc_parts).lower()

    # 6. Raw 6-byte string (latin-1)
    try:
        b = s.encode('latin-1')
        if len(b) == 6:
            return ":".join(f"{x:02x}" for x in b)
    except Exception:
        pass

    return ""


def _is_valid_mac(mac: str) -> bool:
    """
    يتحقق من صلاحية MAC:
    - ليس all-zeros
    - ليس broadcast
    - تنسيق صحيح
    """
    if not mac:
        return False
    if not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac):
        return False
    if mac == "00:00:00:00:00:00":
        return False
    if mac == "ff:ff:ff:ff:ff:ff":
        return False
    return True


def _format_mac_advanced(raw):
    try:
        if raw.startswith("0x"):
            h = raw[2:].replace(":", "").replace("-", "").replace(".", "")
            if len(h) == 12:
                return ":".join(h[i:i+2] for i in range(0, 12, 2))

        hex_parts = re.findall(r'([0-9a-fA-F]{2})', raw)
        if len(hex_parts) >= 6:
            return ":".join(hex_parts[:6])

        cleaned = re.sub(r'[^0-9a-fA-F]', '', raw)
        if len(cleaned) >= 12:
            return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))
    except Exception:
        pass
    return ""


# ═══════════════════════════════════════════════════════
#  10. TDR Results
# ═══════════════════════════════════════════════════════
def get_tdr_results(ip, community):
    key = f"tdr:{ip}"
    cached = _cache_get(key)
    if cached: return cached

    if_names   = _get_if_names(ip, community)
    tdr_status = snmp_walk(ip, community, OID_TDR_STATUS) or []
    tdr_length = snmp_walk(ip, community, OID_TDR_LENGTH) or []

    if not tdr_status:
        _cache_set(key, [], ttl=120)
        return []

    STATUS_MAP = {
        "1":"ok","2":"open","3":"short",
        "4":"impedanceMismatch","5":"broken","6":"unknown",
    }
    offset = _physical_offset(if_names)
    result = []
    for i, st_raw in enumerate(tdr_status):
        list_idx = offset + i
        name     = if_names[list_idx] if list_idx < len(if_names) else f"Port{i+1}"
        st       = STATUS_MAP.get(str(st_raw), "unknown")
        length_m = _i(_safe(tdr_length, i, -1))
        result.append({
            "port"    : str(name),
            "status"  : st,
            "length_m": length_m,
            "healthy" : st == "ok",
        })

    _cache_set(key, result, ttl=120)
    return result



# ═══════════════════════════════════════════════════════
#  11. Environment
# ═══════════════════════════════════════════════════════
def get_environment(ip, community):
    key = f"env:{ip}"
    cached = _cache_get(key)
    if cached:
        return cached

    TEMP_STATE = {"1": "normal", "2": "warning", "3": "critical",
                  "4": "shutdown", "5": "notPresent", "6": "notFunctioning"}
    FAN_STATE = {"1": "normal", "2": "warning", "3": "critical",
                 "4": "shutdown", "5": "notPresent", "6": "notFunctioning"}
    PWR_STATE = {"1": "normal", "2": "warning", "3": "critical",
                 "4": "shutdown", "5": "notPresent", "6": "notFunctioning"}

    temps = snmp_walk(ip, community, OID_TEMP) or []
    fans = snmp_walk(ip, community, OID_FAN) or []
    pwrs = snmp_walk(ip, community, OID_PWR_SUPPLY) or []

    result = {
        "temperatures": [
            {"id": i+1, "status": TEMP_STATE.get(str(v), "unknown"), "alert": str(v) not in ("1", "5")}
            for i, v in enumerate(temps)
        ],
        "fans": [
            {"id": i+1, "status": FAN_STATE.get(str(v), "unknown"), "alert": str(v) not in ("1", "5")}
            for i, v in enumerate(fans)
        ],
        "power_supplies": [
            {"id": i+1, "status": PWR_STATE.get(str(v), "unknown"), "alert": str(v) not in ("1", "5")}
            for i, v in enumerate(pwrs)
        ],
    }
    _cache_set(key, result, ttl=60)
    return result


# ═══════════════════════════════════════════════════════
#  12. STP Info
# ═══════════════════════════════════════════════════════
def get_stp_info(ip, community):
    key = f"stp:{ip}"
    cached = _cache_get(key)
    if cached:
        return cached

    if_names = _get_if_names(ip, community)
    stp_states = snmp_walk(ip, community, OID_STP_PORT_STATE) or []
    root_raw = snmp_get(ip, community, OID_STP_ROOT) or ""

    PORT_STATE = {
        "1": "disabled", "2": "blocking", "3": "listening",
        "4": "learning", "5": "forwarding", "6": "broken",
    }

    offset = _physical_offset(if_names)
    ports = []
    for i, st in enumerate(stp_states):
        list_idx = offset + i
        name = if_names[list_idx] if list_idx < len(if_names) else f"Port{i+1}"
        if not PHYSICAL_RE.match(str(name)):
            continue
        state_str = PORT_STATE.get(str(st), "unknown")
        ports.append({
            "port": str(name),
            "stp_state": state_str,
            "blocking": state_str == "blocking",
            "forwarding": state_str == "forwarding",
        })

    result = {
        "root_bridge": root_raw,
        "ports": ports,
        "blocking_count": sum(1 for p in ports if p["blocking"]),
        "forwarding_count": sum(1 for p in ports if p["forwarding"]),
    }
    _cache_set(key, result, ttl=60)
    return result


