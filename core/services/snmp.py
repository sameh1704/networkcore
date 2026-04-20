# core/services/snmp.py

from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity,
    getCmd, nextCmd,
    UsmUserData, usmHMACSHAAuthProtocol, usmAesCfb128Protocol
)

import time
import hashlib
from functools import wraps

# ============================================
# Cache System
# ============================================
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


# ============================================
# SNMP GET (v2c + v1 fallback)
# ============================================
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


# ============================================
# SNMP WALK (values فقط)
# ============================================
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


# ============================================
# SNMP WALK WITH INDEX (🔥 النسخة الصحيحة)
# ============================================
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

                    # استخراج suffix بدقة (مهم جدًا للـ MAC & VLAN)
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


# ============================================
# SNMP v3
# ============================================
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


# ============================================
# TEST SNMP CONNECTION
# ============================================
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