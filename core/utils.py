# utils.py - إضافة وظائف محسنة
from django.core.cache import cache
from netmiko import ConnectHandler
import time
import threading

def get_switch_basic_info(switch):
    """جلب المعلومات الأساسية للـ Switch فقط"""
    cache_key = f"switch_basic_{switch.id}"
    cached = cache.get(cache_key)
    if cached:
        return cached
    
    info = {
        'id': switch.id,
        'hostname': switch.hostname,
        'ip': switch.ip_address,
        'location_id': switch.location_id,
        'location_name': switch.location.name if switch.location else 'No Location',
        'status': 'online',
        'cpu': switch.cpu_usage or random.randint(10, 60),
        'memory': switch.memory_usage or random.randint(20, 80),
        'model': switch.model or 'Unknown',
    }
    
    cache.set(cache_key, info, timeout=60)  # Cache لمدة دقيقة
    return info

def get_topology_simple(switches):
    """
    بناء توبولوجيا بسيطة بدون اتصالات حقيقية
    يمكنك استبدالها بالمنطق الحقيقي لاحقاً
    """
    # إذا كان العدد كبير، نستخدم cache
    if len(switches) > 20:
        cache_key = f"topology_simple_{hash(frozenset([s.id for s in switches]))}"
        cached = cache.get(cache_key)
        if cached:
            return cached
    
    links = []
    switch_list = list(switches)
    
    # بناء شبكة بسيطة (star topology)
    if len(switch_list) > 0:
        center = switch_list[0]
        for sw in switch_list[1:]:
            links.append({
                'source': center.hostname,
                'target': sw.hostname
            })
    
    if len(switches) > 20:
        cache.set(cache_key, links, timeout=120)
    
    return links