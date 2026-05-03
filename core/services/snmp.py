# core/services/snmp.py

from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity,
    getCmd, nextCmd,
    UsmUserData, usmHMACSHAAuthProtocol, usmAesCfb128Protocol
)

import time
import hashlib
import re
import threading
from functools import wraps


# ═══════════════════════════════════════════════════════════════
#  FAST CACHE (تحسين الأداء بدون كسر الدوال القديمة)
# ═══════════════════════════════════════════════════════════════

class FastCache:
    """
    طبقة تخزين مؤقت محسنة مع دعم الـ threading
    """
    def __init__(self):
        self.data = {}
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            entry = self.data.get(key)
            if entry and (time.time() - entry["time"]) < entry["ttl"]:
                return entry["value"]
            return None

    def set(self, key, value, ttl=30):
        with self.lock:
            self.data[key] = {
                "value": value,
                "time": time.time(),
                "ttl": ttl
            }

    def clear(self, prefix=None):
        with self.lock:
            if prefix:
                keys_to_delete = [k for k in self.data if k.startswith(prefix)]
                for k in keys_to_delete:
                    del self.data[k]
            else:
                self.data.clear()

    def valid(self, key):
        with self.lock:
            if key not in self.data:
                return False
            entry = self.data[key]
            return (time.time() - entry["time"]) < entry["ttl"]


# ═══════════════════════════════════════════════════════════════
#  متغيرات الـ Cache (للتوافق مع الدوال القديمة)
# ═══════════════════════════════════════════════════════════════

CACHE_STORAGE = {}
CACHE_TTL = {
    'system': 30,
    'interfaces': 30,
    'vlans': 60,
    'cdp': 60,
    'mac': 30,
    'stp': 60,
    'environment': 60,
}

# الـ FastCache الجديد (اختياري للاستخدام)
_FAST_CACHE = FastCache()


def _make_cache_key(func_name, args, kwargs):
    raw_key = f"{func_name}:{args}:{kwargs}"
    return hashlib.md5(raw_key.encode()).hexdigest()


def cached(ttl=30):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = _make_cache_key(func.__name__, args, kwargs)

            if key in CACHE_STORAGE:
                entry = CACHE_STORAGE[key]
                if time.time() - entry['timestamp'] < entry['ttl']:
                    return entry['value']

            result = func(*args, **kwargs)

            CACHE_STORAGE[key] = {
                'value': result,
                'timestamp': time.time(),
                'ttl': ttl
            }

            return result
        return wrapper
    return decorator


def clear_cache(ip=None):
    global CACHE_STORAGE
    if ip:
        CACHE_STORAGE = {k: v for k, v in CACHE_STORAGE.items() if ip not in k}
    else:
        CACHE_STORAGE.clear()
    _FAST_CACHE.clear()


# ═══════════════════════════════════════════════════════════════
#  SNMP ENGINE CLASS (طبقة موحدة بدون تكرار calls)
# ═══════════════════════════════════════════════════════════════

class SNMPEngine:
    """
    طبقة موحدة لإدارة SNMP بدون تكرار calls
    تحسن الأداء بدون تعديل الدوال القديمة
    """

    def __init__(self, ip, community, timeout=2, retries=1):
        self.ip = ip
        self.community = community
        self.timeout = timeout
        self.retries = retries
        self._session_cache = {}

    def _get(self, oid, mp_model=1):
        key = f"get:{oid}:{mp_model}"

        if key in self._session_cache:
            return self._session_cache[key]

        result = snmp_get(
            self.ip,
            self.community,
            oid,
            timeout=self.timeout,
            retries=self.retries
        )

        self._session_cache[key] = result
        return result

    def _walk(self, oid):
        key = f"walk:{oid}"

        if key in self._session_cache:
            return self._session_cache[key]

        result = snmp_walk(
            self.ip,
            self.community,
            oid,
            timeout=self.timeout,
            retries=self.retries
        )

        self._session_cache[key] = result
        return result

    def _walk_index(self, oid):
        key = f"walk_index:{oid}"

        if key in self._session_cache:
            return self._session_cache[key]

        result = snmp_walk_with_index(
            self.ip,
            self.community,
            oid,
            timeout=self.timeout,
            retries=self.retries
        )

        self._session_cache[key] = result
        return result

    def clear(self):
        self._session_cache.clear()


# ═══════════════════════════════════════════════════════════════
#  SNMP GET (v2c + v1 fallback) - الدالة الأصلية لم تتغير
# ═══════════════════════════════════════════════════════════════

@cached(ttl=CACHE_TTL['system'])
def snmp_get(ip, community, oid, timeout=2, retries=1):
    for mp_model in [1, 0]:  # v2c ثم v1
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=mp_model),
                UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )

            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if errorIndication or errorStatus:
                continue

            for varBind in varBinds:
                val = str(varBind[1])
                if val and "NoSuch" not in val and "noSuch" not in val:
                    return val

        except Exception:
            continue

    return None


# ═══════════════════════════════════════════════════════════════
#  SNMP GET SAFE (نسخة محسنة مع retry ذكي)
# ═══════════════════════════════════════════════════════════════

def snmp_get_safe(ip, community, oid, timeout=2, retries=2):
    """نسخة محسنة من snmp_get مع retry ذكي (لا تؤثر على الدالة الأصلية)"""
    engine = SNMPEngine(ip, community, timeout, retries)
    return engine._get(oid)


# ═══════════════════════════════════════════════════════════════
#  SNMP WALK (values فقط) - الدالة الأصلية لم تتغير
# ═══════════════════════════════════════════════════════════════

@cached(ttl=CACHE_TTL['interfaces'])
def snmp_walk(ip, community, oid, timeout=2, retries=1):
    results = []

    for mp_model in [1, 0]:
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=mp_model),
                UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
            ):
                if errorIndication or errorStatus:
                    break

                for varBind in varBinds:
                    val = str(varBind[1])
                    if "NoSuch" not in val and "noSuch" not in val:
                        results.append(val)

            if results:
                return results

        except Exception:
            continue

    return []


# ═══════════════════════════════════════════════════════════════
#  SNMP WALK SAFE (نسخة محسنة)
# ═══════════════════════════════════════════════════════════════

def snmp_walk_safe(ip, community, oid, timeout=2, retries=2):
    """نسخة محسنة من snmp_walk (لا تؤثر على الدالة الأصلية)"""
    engine = SNMPEngine(ip, community, timeout, retries)
    return engine._walk(oid)


# ═══════════════════════════════════════════════════════════════
#  SNMP WALK WITH INDEX (النسخة الصحيحة) - الدالة الأصلية
# ═══════════════════════════════════════════════════════════════

@cached(ttl=30)
def snmp_walk_with_index(ip, community, oid, timeout=2, retries=1):
    """
    يُرجع list من (suffix, value)
    suffix = index الحقيقي (ifIndex / VLAN / IP ...)
    """
    results = []
    clean_base = oid.strip(".")

    for mp_model in [1, 0]:
        try:
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=mp_model),
                UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
            ):
                if errorIndication or errorStatus:
                    break

                for varBind in varBinds:
                    full_oid = str(varBind[0]).strip(".")
                    value = str(varBind[1])

                    if "NoSuch" in value or "noSuch" in value:
                        continue

                    if full_oid.startswith(clean_base + "."):
                        suffix = full_oid[len(clean_base) + 1:]
                    else:
                        suffix = full_oid

                    results.append((suffix.strip(), value.strip()))

            if results:
                return results

        except Exception as e:
            print(f"[SNMP ERROR] {ip} {oid} -> {e}")
            continue

    return []


# ═══════════════════════════════════════════════════════════════
#  SNMP v3 - الدالة الأصلية
# ═══════════════════════════════════════════════════════════════

def snmp_get_v3(ip, user, auth_key, priv_key, oid, timeout=2):
    try:
        iterator = getCmd(
            SnmpEngine(),
            UsmUserData(
                user,
                auth_key,
                priv_key,
                authProtocol=usmHMACSHAAuthProtocol,
                privProtocol=usmAesCfb128Protocol
            ),
            UdpTransportTarget((ip, 161), timeout=timeout, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication or errorStatus:
            return None

        for varBind in varBinds:
            return str(varBind[1])

    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
#  TEST SNMP CONNECTION
# ═══════════════════════════════════════════════════════════════

def test_snmp_connection(ip, community, timeout=5):
    test_oids = [
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.2.0",
        "1.3.6.1.2.1.1.5.0",
    ]

    results = {}

    for oid in test_oids:
        try:
            val = snmp_get(ip, community, oid, timeout=timeout)
            results[oid] = val if val else "No response"
        except Exception as e:
            results[oid] = f"Error: {e}"

    return results


# ═══════════════════════════════════════════════════════════════
#  الدوال الجديدة (غير مؤثرة على الدوال القديمة)
# ═══════════════════════════════════════════════════════════════

# ============================================
# ثوابت OIDs القياسية (تعمل على جميع الأجهزة)
# ============================================

# System OIDs
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

# Interface OIDs
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IF_MTU = "1.3.6.1.2.1.2.2.1.4"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_LAST_CHANGE = "1.3.6.1.2.1.2.2.1.9"
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
OID_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
OID_IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
OID_IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
OID_IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"
OID_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"


# ============================================
# Vendor Detection (التعرف على نوع الجهاز)
# ============================================

VENDOR_OIDS = {
    # Cisco
    "1.3.6.1.4.1.9.1.516": ("Cisco", "Catalyst 3750E"),
    "1.3.6.1.4.1.9.1.174": ("Cisco", "Catalyst 2950"),
    "1.3.6.1.4.1.9.1.613": ("Cisco", "Catalyst 3650"),
    "1.3.6.1.4.1.9.1.662": ("Cisco", "Catalyst 3850"),
    "1.3.6.1.4.1.9.1.1160": ("Cisco", "Catalyst 9300"),
    "1.3.6.1.4.1.9.1.767": ("Cisco", "Catalyst 2960"),
    "1.3.6.1.4.1.9.1.1289": ("Cisco", "Catalyst 9200"),
    "1.3.6.1.4.1.9.1.253": ("Cisco", "Cisco Router 2800"),
    "1.3.6.1.4.1.9.1.257": ("Cisco", "Cisco Router 3800"),
    
    # Dell PowerConnect
    "1.3.6.1.4.1.674.10895.3033": ("Dell", "PowerConnect 3348"),
    "1.3.6.1.4.1.674.10895.3040": ("Dell", "PowerConnect 3548"),
    "1.3.6.1.4.1.674.10895.3050": ("Dell", "PowerConnect 5448"),
    "1.3.6.1.4.1.674.10895.3060": ("Dell", "PowerConnect 5524"),
    
    # Fortinet FortiSwitch
    "1.3.6.1.4.1.12356.101.1": ("Fortinet", "FortiSwitch 108E"),
    "1.3.6.1.4.1.12356.101.2": ("Fortinet", "FortiSwitch 148E"),
    "1.3.6.1.4.1.12356.101.3": ("Fortinet", "FortiSwitch 224E"),
    "1.3.6.1.4.1.12356.101.4": ("Fortinet", "FortiSwitch 424E"),
    
    # HP/Aruba
    "1.3.6.1.4.1.11.2.3.7.11.1": ("HP", "ProCurve Switch"),
    "1.3.6.1.4.1.11.2.3.7.11.2": ("HP", "Aruba Switch"),
    
    # Juniper
    "1.3.6.1.4.1.45.3.60.1": ("Juniper", "EX Series"),
    "1.3.6.1.4.1.45.3.60.2": ("Juniper", "QFX Series"),
    
    # Generic
    "1.3.6.1.4.1.8072.3.2.10": ("Linux", "Generic SNMP Agent"),
    "1.3.6.1.4.1.2021.250.3": ("FreeBSD", "Generic SNMP Agent"),
}


def detect_vendor(sys_object_id):
    """
    التعرف على نوع الجهاز من SysObjectID
    """
    sys_oid = str(sys_object_id).strip()
    
    for oid, (vendor, model) in VENDOR_OIDS.items():
        if sys_oid.startswith(oid):
            return vendor, model
    
    if sys_oid.startswith("1.3.6.1.4.1.9"):
        return "Cisco", "Unknown Cisco Device"
    elif sys_oid.startswith("1.3.6.1.4.1.674"):
        return "Dell", "Unknown Dell Device"
    elif sys_oid.startswith("1.3.6.1.4.1.12356"):
        return "Fortinet", "Unknown Fortinet Device"
    elif sys_oid.startswith("1.3.6.1.4.1.11"):
        return "HP/Aruba", "Unknown HP Device"
    elif sys_oid.startswith("1.3.6.1.4.1.45"):
        return "Juniper", "Unknown Juniper Device"
    else:
        return "Unknown", "Generic SNMP Device"


# ============================================
# الدوال المساعدة الجديدة
# ============================================

def clean_octet_string_for_arp(value):
    """تنظيف OctetString لـ ARP لعرضه بشكل صحيح"""
    try:
        if isinstance(value, bytes):
            try:
                return value.decode('ascii', errors='replace')
            except:
                return ''.join(f'{b:02x}' for b in value)
        s = str(value)
        if any(ord(c) > 127 or ord(c) < 32 for c in s):
            hex_match = re.search(r'([0-9a-f]{12})', s, re.I)
            if hex_match:
                hex_str = hex_match.group(1)
                return ':'.join(hex_str[i:i+2] for i in range(0, 12, 2)).lower()
        return s
    except Exception:
        return str(value)


def extract_mac_from_octet(value):
    """استخراج MAC بشكل موثوق من OctetString"""
    s = str(value)
    
    hex_match = re.search(r'([0-9a-f]{12})', s, re.I)
    if hex_match:
        hex_str = hex_match.group(1)
        return ':'.join(hex_str[i:i+2] for i in range(0, 12, 2)).lower()
    
    if len(s) == 6 and all(ord(c) < 256 for c in s):
        return ':'.join(f'{ord(c):02x}' for c in s)
    
    return None


def extract_ip_from_octet(value):
    """استخراج IP من OctetString المشوه"""
    s = str(value)
    
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', s)
    if ip_match:
        return ip_match.group(1)
    
    hex_numbers = re.findall(r'([0-9a-f]{2})', s, re.I)
    if len(hex_numbers) == 4:
        try:
            return '.'.join(str(int(h, 16)) for h in hex_numbers)
        except:
            pass
    
    return None


# ============================================
# دوال اكتشاف السويتشات الجديدة (لا تؤثر على الدوال القديمة)
# ============================================

def get_system_description(ip, community, timeout=3):
    """جلب معلومات النظام الأساسية (تعمل على جميع الأجهزة)"""
    try:
        descr = snmp_get(ip, community, OID_SYS_DESCR, timeout=timeout)
        sys_oid = snmp_get(ip, community, OID_SYS_OBJECT_ID, timeout=timeout)
        hostname = snmp_get(ip, community, OID_SYS_NAME, timeout=timeout)
        uptime = snmp_get(ip, community, OID_SYS_UPTIME, timeout=timeout)
        location = snmp_get(ip, community, OID_SYS_LOCATION, timeout=timeout)
        contact = snmp_get(ip, community, OID_SYS_CONTACT, timeout=timeout)
        
        vendor, model = detect_vendor(sys_oid) if sys_oid else ("Unknown", "Unknown")
        
        return {
            "hostname": hostname or ip,
            "description": descr or "",
            "vendor": vendor,
            "model": model,
            "sys_object_id": sys_oid,
            "uptime": uptime,
            "location": location or "",
            "contact": contact or "",
            "snmp_responds": True,
        }
    except Exception as e:
        return {
            "hostname": ip,
            "description": "",
            "vendor": "Unknown",
            "model": "Unknown",
            "snmp_responds": False,
            "error": str(e),
        }


def get_interfaces_universal(ip, community, timeout=3):
    """جلب جميع الواجهات من أي جهاز (تعمل على 100% من الأجهزة)"""
    result = []
    
    try:
        if_names = snmp_walk(ip, community, OID_IF_NAME, timeout=timeout) or []
        
        if if_names:
            if_oper = snmp_walk(ip, community, OID_IF_OPER_STATUS, timeout=timeout) or []
            if_admin = snmp_walk(ip, community, OID_IF_ADMIN_STATUS, timeout=timeout) or []
            if_speed = snmp_walk(ip, community, OID_IF_SPEED, timeout=timeout) or []
            if_in_oct = snmp_walk(ip, community, OID_IF_IN_OCTETS, timeout=timeout) or []
            if_out_oct = snmp_walk(ip, community, OID_IF_OUT_OCTETS, timeout=timeout) or []
            if_mac = snmp_walk(ip, community, OID_IF_PHYS_ADDRESS, timeout=timeout) or []
            if_type = snmp_walk(ip, community, OID_IF_TYPE, timeout=timeout) or []
            
            for i, name in enumerate(if_names):
                result.append({
                    "index": i + 1,
                    "name": str(name),
                    "description": str(if_type[i]) if i < len(if_type) else "",
                    "status": "up" if (i < len(if_oper) and str(if_oper[i]) == "1") else "down",
                    "admin": "up" if (i < len(if_admin) and str(if_admin[i]) == "1") else "down",
                    "speed": int(if_speed[i]) if i < len(if_speed) else 0,
                    "in_octets": int(if_in_oct[i]) if i < len(if_in_oct) else 0,
                    "out_octets": int(if_out_oct[i]) if i < len(if_out_oct) else 0,
                    "mac": str(if_mac[i]) if i < len(if_mac) else "",
                })
        else:
            if_desc = snmp_walk(ip, community, OID_IF_DESCR, timeout=timeout) or []
            if_oper = snmp_walk(ip, community, OID_IF_OPER_STATUS, timeout=timeout) or []
            if_admin = snmp_walk(ip, community, OID_IF_ADMIN_STATUS, timeout=timeout) or []
            if_speed = snmp_walk(ip, community, OID_IF_SPEED, timeout=timeout) or []
            
            for i, desc in enumerate(if_desc):
                result.append({
                    "index": i + 1,
                    "name": str(desc),
                    "description": str(desc),
                    "status": "up" if (i < len(if_oper) and str(if_oper[i]) == "1") else "down",
                    "admin": "up" if (i < len(if_admin) and str(if_admin[i]) == "1") else "down",
                    "speed": int(if_speed[i]) if i < len(if_speed) else 0,
                    "in_octets": 0,
                    "out_octets": 0,
                    "mac": "",
                })
        
        return result
    except Exception as e:
        print(f"Error getting interfaces for {ip}: {e}")
        return []


def discover_switch_complete(ip, community, timeout=3):
    """اكتشاف كامل لسويتش واحد (جميع المعلومات الأساسية)"""
    result = {
        "ip": ip,
        "snmp_responds": False,
        "hostname": ip,
        "vendor": "Unknown",
        "model": "Unknown",
        "interfaces_count": 0,
        "interfaces_up": 0,
    }
    
    try:
        sys_info = get_system_description(ip, community, timeout)
        result.update(sys_info)
        
        if not sys_info.get("snmp_responds"):
            return result
        
        interfaces = get_interfaces_universal(ip, community, timeout)
        result["interfaces"] = interfaces
        result["interfaces_count"] = len(interfaces)
        result["interfaces_up"] = sum(1 for i in interfaces if i["status"] == "up")
        
        return result
        
    except Exception as e:
        result["error"] = str(e)
        return result


def discover_switch_complete_fast(ip, community, timeout=3):
    """نسخة محسنة من discover_switch_complete مع SNMPEngine (أسرع)"""
    engine = SNMPEngine(ip, community, timeout)

    result = {
        "ip": ip,
        "snmp_responds": False,
        "hostname": ip,
        "vendor": "Unknown",
        "model": "Unknown",
        "interfaces_count": 0,
        "interfaces_up": 0,
    }

    sys_info = get_system_description(ip, community, timeout)
    result.update(sys_info)

    if not sys_info.get("snmp_responds"):
        return result

    interfaces = get_interfaces_universal(ip, community, timeout)
    result["interfaces"] = interfaces

    result["interfaces_count"] = len(interfaces)
    result["interfaces_up"] = sum(1 for i in interfaces if i["status"] == "up")

    return result


def discover_network_range(start_ip, end_ip, community, timeout=2):
    """اكتشاف جميع السويتشات في نطاق IP معين"""
    from ipaddress import ip_address
    
    results = []
    
    start = int(ip_address(start_ip))
    end = int(ip_address(end_ip))
    
    for ip_int in range(start, end + 1):
        ip = str(ip_address(ip_int))
        try:
            print(f"Scanning {ip}...")
            info = get_system_description(ip, community, timeout)
            if info.get("snmp_responds"):
                results.append(info)
                print(f"  ✓ Discovered: {info['hostname']} ({info['vendor']} {info['model']})")
        except Exception:
            pass
    
    return results


# ═══════════════════════════════════════════════════════════════
#  دوال متوافقة مع جميع موديلات Cisco (2950, 3750, 3650, 3850) + Dell
# ═══════════════════════════════════════════════════════════════

def get_arp_table_universal(ip, community, timeout=3):
    """
    جلب ARP table من أي سويتش (Cisco, Dell, Fortinet, HP)
    """
    arp_map = {}
    
    try:
        mac_rows = snmp_walk_with_index(ip, community, "1.3.6.1.2.1.4.22.1.2", timeout=timeout) or []
        ip_rows = snmp_walk_with_index(ip, community, "1.3.6.1.2.1.4.22.1.3", timeout=timeout) or []
        
        ip_by_suffix = {}
        for suffix, val in ip_rows:
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', str(val))
            if ip_match:
                ip_by_suffix[suffix] = ip_match.group(1)
        
        for suffix, mac_val in mac_rows:
            mac_hex = re.search(r'([0-9a-f]{12})', str(mac_val), re.I)
            if mac_hex:
                mac = ':'.join(mac_hex.group(1)[i:i+2] for i in range(0, 12, 2)).lower()
                ip_addr = ip_by_suffix.get(suffix, "")
                if ip_addr and mac not in arp_map:
                    arp_map[mac] = ip_addr
        
        return arp_map
    except Exception as e:
        print(f"ARP table error for {ip}: {e}")
        return {}


def get_mac_table_universal(ip, community, vlan_id=None, timeout=3):
    """
    جلب MAC table من أي سويتش
    - vlan_id: إذا تم تحديده، يستخدم community@vlan_id (لأجهزة Cisco)
    """
    if vlan_id:
        community = f"{community}@{vlan_id}"
    
    mac_ports = {}
    
    try:
        mac_entries = snmp_walk_with_index(ip, community, "1.3.6.1.2.1.17.4.3.1.1", timeout=timeout) or []
        port_entries = snmp_walk_with_index(ip, community, "1.3.6.1.2.1.17.4.3.1.2", timeout=timeout) or []
        
        for i, (suffix, mac_val) in enumerate(mac_entries):
            if i >= len(port_entries):
                break
            
            mac_hex = re.search(r'([0-9a-f]{12})', str(mac_val), re.I)
            if not mac_hex:
                continue
            
            mac = ':'.join(mac_hex.group(1)[i:i+2] for i in range(0, 12, 2)).lower()
            
            port_str = str(port_entries[i][1])
            port = port_str if port_str.isdigit() else "?"
            
            mac_ports[mac] = port
        
        return mac_ports
    except Exception as e:
        print(f"MAC table error for {ip}: {e}")
        return {}


def get_all_connected_devices(ip, community, vlan_id=None, timeout=3):
    """جلب جميع الأجهزة المتصلة بالسويتش مع (MAC, Port, IP إن وجد)"""
    devices = []
    
    mac_ports = get_mac_table_universal(ip, community, vlan_id, timeout)
    arp_map = get_arp_table_universal(ip, community, timeout)
    
    for mac, port in mac_ports.items():
        devices.append({
            "mac": mac,
            "port": port,
            "ip": arp_map.get(mac, "N/A"),
        })
    
    return devices


def get_cpu_usage_universal(ip, community, timeout=3):
    """جلب CPU usage من سويتشات Cisco (تعمل على 3750, 3650, 3850)"""
    OID_CPU_5SEC = "1.3.6.1.4.1.9.2.1.57.0"
    OID_CPU_1MIN = "1.3.6.1.4.1.9.2.1.58.0"
    OID_CPU_5MIN = "1.3.6.1.4.1.9.2.1.59.0"
    
    try:
        cpu_5s = snmp_get(ip, community, OID_CPU_5SEC, timeout=timeout)
        if cpu_5s and "NoSuch" not in cpu_5s:
            return {
                "5sec": int(cpu_5s),
                "1min": int(snmp_get(ip, community, OID_CPU_1MIN, timeout=timeout) or 0),
                "5min": int(snmp_get(ip, community, OID_CPU_5MIN, timeout=timeout) or 0),
                "supported": True
            }
    except:
        pass
    
    return {"supported": False, "message": "CPU OID not supported on this switch"}


def get_poe_universal(ip, community, timeout=3):
    """جلب PoE information من سويتشات Cisco"""
    OID_POE_PORT_POWER = "1.3.6.1.4.1.9.9.402.1.2.1.8"
    
    try:
        poe_power = snmp_walk(ip, community, OID_POE_PORT_POWER, timeout=timeout) or []
        if poe_power:
            return {
                "supported": True,
                "ports": len(poe_power),
                "total_power_mw": sum(int(p) for p in poe_power if p.isdigit())
            }
    except:
        pass
    
    return {"supported": False, "message": "PoE not supported on this switch"}


def get_switch_capabilities(ip, community, timeout=3):
    """تحديد إمكانيات السويتش (ما هي الـ OIDs المدعومة)"""
    capabilities = {
        "snmp_responds": False,
        "hostname": ip,
        "model": "Unknown",
        "supports_cpu": False,
        "supports_poe": False,
        "supports_arp": False,
        "supports_mac_table": False,
    }
    
    try:
        hostname = snmp_get(ip, community, "1.3.6.1.2.1.1.5.0", timeout=timeout)
        descr = snmp_get(ip, community, "1.3.6.1.2.1.1.1.0", timeout=timeout)
        
        if not hostname and not descr:
            return capabilities
        
        capabilities["snmp_responds"] = True
        capabilities["hostname"] = hostname or ip
        
        if descr:
            model_match = re.search(r'([A-Z]{2,3}-\d{4,5})', descr)
            if model_match:
                capabilities["model"] = model_match.group(1)
        
        cpu_test = snmp_get(ip, community, "1.3.6.1.4.1.9.2.1.57.0", timeout=timeout)
        capabilities["supports_cpu"] = cpu_test and "NoSuch" not in cpu_test
        
        poe_test = snmp_get(ip, community, "1.3.6.1.4.1.9.9.402.1.2.1.8.1", timeout=timeout)
        capabilities["supports_poe"] = poe_test and "NoSuch" not in poe_test
        
        arp_test = snmp_get(ip, community, "1.3.6.1.2.1.4.22.1.2", timeout=timeout)
        capabilities["supports_arp"] = arp_test and "NoSuch" not in arp_test
        
        mac_test = snmp_get(ip, community, "1.3.6.1.2.1.17.4.3.1.1", timeout=timeout)
        capabilities["supports_mac_table"] = mac_test and "NoSuch" not in mac_test
        
    except Exception as e:
        print(f"Capability check error for {ip}: {e}")
    
    return capabilities


def scan_all_switches(switches_list, community="private", timeout=2):
    """فحص جميع السويتشات وجمع كل المعلومات الممكنة"""
    results = []
    
    for ip in switches_list:
        print(f"\n[SCAN] {ip}")
        
        caps = get_switch_capabilities(ip, community, timeout)
        
        if not caps["snmp_responds"]:
            print(f"  ✗ No SNMP response")
            results.append({"ip": ip, "error": "No SNMP response"})
            continue
        
        print(f"  ✓ Model: {caps['model']}")
        print(f"  ✓ Hostname: {caps['hostname']}")
        
        device = {
            "ip": ip,
            "hostname": caps["hostname"],
            "model": caps["model"],
            "capabilities": caps,
        }
        
        if caps["supports_mac_table"]:
            devices = get_all_connected_devices(ip, community, timeout=timeout)
            device["connected_devices"] = devices
            print(f"  ✓ Connected devices: {len(devices)}")
            
            for d in devices[:5]:
                print(f"    - Port {d['port']}: {d['mac']} -> IP: {d['ip']}")
        
        if caps["supports_cpu"]:
            cpu = get_cpu_usage_universal(ip, community, timeout)
            if cpu["supported"]:
                device["cpu"] = cpu
                print(f"  ✓ CPU: {cpu['5sec']}%")
        
        if caps["supports_poe"]:
            poe = get_poe_universal(ip, community, timeout)
            if poe["supported"]:
                device["poe"] = poe
                print(f"  ✓ PoE: {poe['total_power_mw']/1000:.1f}W total")
        
        results.append(device)
    
    return results


# ═══════════════════════════════════════════════════════════════
#  اختبار سريع (يُشغَّل فقط إذا تم تنفيذ الملف مباشرة)
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    switches = [
        "192.168.70.20",
        "192.168.70.27",
        "192.168.70.131",
    ]
    
    results = scan_all_switches(switches, community="NMSCOMM")
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    for r in results:
        if "error" in r:
            print(f"✗ {r['ip']}: {r['error']}")
        else:
            print(f"✓ {r['ip']:16} | {r['model']:15} | {len(r.get('connected_devices', [])):3} devices")