from .snmp import snmp_get, snmp_walk, snmp_walk_with_index
import re

OID_CPU_5SEC  = "1.3.6.1.4.1.9.2.1.57.0"
OID_IF_DESC   = "1.3.6.1.2.1.2.2.1.2"
OID_IF_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_IN     = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT    = "1.3.6.1.2.1.2.2.1.16"
OID_IF_NAME   = "1.3.6.1.2.1.31.1.1.1.1"
OID_VLAN_NAMES= "1.3.6.1.4.1.9.9.46.1.3.1.1.4"
OID_VLAN_STATE= "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
OID_VM_VLAN   = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"
OID_POE_STATUS= "1.3.6.1.2.1.105.1.1.1.3"
OID_POE_POWER = "1.3.6.1.2.1.105.1.1.1.6"

PHYSICAL_RE = re.compile(
    r'^(Fa|Gi|Te|Eth|Fast|Gig|Ten|ge-|xe-)',
    re.IGNORECASE
)

def safe_get(lst, i, default=0):
    return lst[i] if i < len(lst) else default

def _safe_int(val, default=0):
    try:    return int(str(val).strip())
    except: return default


def get_cpu_usage(ip, community):
    try:    return float(snmp_get(ip, community, OID_CPU_5SEC))
    except: return 0.0


def get_interfaces(ip, community):
    names  = snmp_walk(ip, community, OID_IF_NAME)   or []
    desc   = snmp_walk(ip, community, OID_IF_DESC)   or []
    status = snmp_walk(ip, community, OID_IF_STATUS) or []
    t_in   = snmp_walk(ip, community, OID_IF_IN)     or []
    t_out  = snmp_walk(ip, community, OID_IF_OUT)    or []
    if not names:
        return []
    result = []
    for i, name in enumerate(names):
        st = str(safe_get(status, i, "2"))
        result.append({
            "if_index": i + 1,
            "name"    : name,
            "desc"    : safe_get(desc, i, name),
            "status"  : "up" if st == "1" else "down",
            "in"      : int(safe_get(t_in,  i, 0)),
            "out"     : int(safe_get(t_out, i, 0)),
        })
    return result


def get_vlans(ip, community):
    """
    ══════════════════════════════════════════════════════════
    الإصلاح الجذري النهائي:

    المشكلة كانت:
      - snmp_walk(VM_VLAN) يُرجع القيم فقط [50, 100, 79, ...]
        بدون الـ ifIndex الحقيقي
      - على Catalyst stack السويتش ifIndex = 10101+ وليس 1, 2, 3

    الحل:
      1. snmp_walk_with_index(IF_NAME)
         → {ifIndex_real: "Gi1/0/1", ...}
         مثال: {"10101": "Gi1/0/1", "10102": "Gi1/0/2"}

      2. snmp_walk_with_index(VM_VLAN)
         → [(ifIndex_real, vlan_id), ...]
         مثال: [("10101", "50"), ("10102", "100")]

      3. snmp_walk_with_index(VLAN_NAMES)
         → [(suffix, name), ...]
         suffix يحتوي VLAN_ID الحقيقي في آخر رقم
         مثال: [("1.50", "MOAZ_COMPU"), ("1.100", "Camera")]

    ══════════════════════════════════════════════════════════
    """

    # ── 1. بناء ifIndex الحقيقي → اسم المنفذ ─────────────
    if_name_idx = snmp_walk_with_index(ip, community, OID_IF_NAME) or []

    # {ifIndex_str: port_name}
    ifidx2name = {}
    for suffix, name in if_name_idx:
        # suffix = ifIndex الحقيقي (مثل "10101" أو "6")
        ifidx2name[suffix] = str(name)

    # ── 2. Port membership: ifIndex → vlan_id ────────────
    vm_vlan_idx = snmp_walk_with_index(ip, community, OID_VM_VLAN) or []

    # {vlan_id: [port_names]}
    vlan_ports = {}
    for suffix, vlan_raw in vm_vlan_idx:
        vid = _safe_int(vlan_raw)
        if not (1 <= vid <= 4094):
            continue
        port_name = ifidx2name.get(suffix, "")
        if port_name and PHYSICAL_RE.match(port_name):
            vlan_ports.setdefault(vid, []).append(port_name)

    # ── 3. VLAN names مع الـ VLAN_ID الحقيقي ─────────────
    vlan_name_idx  = snmp_walk_with_index(ip, community, OID_VLAN_NAMES) or []
    vlan_state_idx = snmp_walk_with_index(ip, community, OID_VLAN_STATE) or []

    # {vlan_id: name}
    vlan_names  = {}
    vlan_states = {}

    for suffix, val in vlan_name_idx:
        # suffix مثل "1.50" أو "50"
        # VLAN_ID = آخر رقم في الـ suffix
        vid = _last_int(suffix)
        if vid and 1 <= vid <= 4094:
            vlan_names[vid] = str(val).strip() or f"VLAN{vid}"

    for suffix, val in vlan_state_idx:
        vid = _last_int(suffix)
        if vid:
            vlan_states[vid] = (str(val) == "1")

    # ── 4. بناء القائمة النهائية ──────────────────────────
    result = []
    for vid in sorted(vlan_names.keys()):
        name       = vlan_names[vid]
        active     = vlan_states.get(vid, False)
        port_names = vlan_ports.get(vid, [])

        result.append({
            "vlan_id"   : vid,
            "name"      : name,
            "active"    : active,
            "port_names": port_names,
            "port_count": len(port_names),
        })

    return result


def _last_int(suffix: str) -> int:
    """آخر رقم موجب في OID suffix"""
    for p in reversed(str(suffix).split(".")):
        try:
            v = int(p)
            if v > 0:
                return v
        except ValueError:
            continue
    return 0


def get_ports_status(ip, community):
    names  = snmp_walk(ip, community, OID_IF_NAME)   or []
    status = snmp_walk(ip, community, OID_IF_STATUS) or []
    if not names:
        return []
    return [
        {
            "name"  : names[i],
            "status": "up" if str(safe_get(status, i, "2")) == "1" else "down",
        }
        for i in range(len(names))
    ]


def get_poe_status(ip, community):
    status   = snmp_walk(ip, community, OID_POE_STATUS) or []
    power    = snmp_walk(ip, community, OID_POE_POWER)  or []
    if_names = snmp_walk(ip, community, OID_IF_NAME)    or []

    status_map = {
        "1":"on","2":"off","3":"fault","4":"deny","5":"searching"
    }

    offset = 0
    for idx, n in enumerate(if_names):
        if PHYSICAL_RE.match(str(n)):
            offset = idx
            break

    result = []
    for i in range(max(len(status), len(power), 1)):
        list_idx  = offset + i
        port_name = if_names[list_idx] if list_idx < len(if_names) else f"Port{i+1}"
        st        = str(safe_get(status, i, "2"))
        result.append({
            "port"        : port_name,
            "power_status": status_map.get(st, "unknown"),
            "power_mw"    : int(safe_get(power, i, 0)),
        })
    return result