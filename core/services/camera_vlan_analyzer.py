# core/services/camera_vlan_analyzer.py - نسخة خفيفة

"""
Camera VLAN Analyzer - نسخة محسنة للأداء
"""

import re
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache

from core.services.switch_inspector import get_interfaces_detail, get_vlans_full
from core.services.snmp import snmp_get, snmp_walk


def analyze_camera_vlan(switch, hours: int = 24) -> dict:
    """
    تحليل كاميرات VLAN 100 - نسخة محسنة للأداء
    """
    cache_key = f"camera_vlan_{switch.id}_{hours}"
    
    # محاولة القراءة من cache أولاً
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    result = {
        "switch": {
            "id": switch.id,
            "hostname": switch.hostname,
            "ip": switch.ip_address,
            "location": switch.location.name if switch.location else "Unknown"
        },
        "vlan_id": 100,
        "hours": hours,
        "cameras": [],
        "summary": {
            "total_cameras": 0,
            "online_cameras": 0,
            "offline_cameras": 0,
            "total_traffic_mbps": 0,
        },
        "top_traffic": [],
        "issues": [],
    }
    
    try:
        # 1. جلب VLAN 100 (مع timeout قصير)
        vlan_ports = _get_vlan_100_ports_fast(switch)
        if not vlan_ports:
            cache.set(cache_key, result, 60)
            return result
        
        # 2. جلب تفاصيل المنافذ (مع timeout)
        interfaces = get_interfaces_detail(switch.ip_address, switch.snmp_community) or []
        iface_map = {ifc["name"]: ifc for ifc in interfaces}
        
        # 3. تحليل كل منفذ
        cameras = []
        total_traffic = 0
        
        for port_name in vlan_ports:
            ifc = iface_map.get(port_name, {})
            traffic_mbps = ifc.get("traffic_mbps", 0)
            total_traffic += traffic_mbps
            
            status = "online" if ifc.get("status") == "connected" else "offline"
            
            cameras.append({
                "port": port_name,
                "status": status,
                "traffic_mbps": traffic_mbps,
                "in_errors": ifc.get("in_errors", 0),
                "out_errors": ifc.get("out_errors", 0),
                "ip_addresses": [],  # تبسيط: لا نجلب ARP حالياً
                "manufacturer": "Unknown",
            })
        
        # ترتيب حسب الترافيك
        cameras.sort(key=lambda x: x["traffic_mbps"], reverse=True)
        
        online_count = sum(1 for c in cameras if c["status"] == "online")
        offline_count = sum(1 for c in cameras if c["status"] == "offline")
        
        result.update({
            "cameras": cameras,
            "top_traffic": cameras[:10],
            "summary": {
                "total_cameras": len(cameras),
                "online_cameras": online_count,
                "offline_cameras": offline_count,
                "total_traffic_mbps": round(total_traffic, 1),
            },
        })
        
        # تخزين في cache لمدة 30 ثانية (ليس 60 ثانية)
        cache.set(cache_key, result, 30)
        
    except Exception as e:
        result["error"] = str(e)
        cache.set(cache_key, result, 10)  # cache قصير في حالة الخطأ
    
    return result


def _get_vlan_100_ports_fast(switch):
    """جلب منافذ VLAN 100 بسرعة"""
    try:
        vlans = get_vlans_full(switch.ip_address, switch.snmp_community) or []
        for vlan in vlans:
            if vlan.get("vlan_id") == 100:
                return vlan.get("port_names", [])[:24]  # حد أقصى 24 منفذ
        return []
    except Exception as e:
        print(f"VLAN 100 error: {e}")
        return []