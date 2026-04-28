# core/views.py
"""
Views for Cisco NMS Django Application
═══════════════════════════════════════════════════════════════
يحتوي على:
  1. Page Views (الصفحات الرئيسية)
  2. Dashboard APIs
  3. Discovery APIs
  4. Network Map APIs
  5. Switch Inspector APIs (لصفحة تفاصيل السويتش)
  6. Switch Inspector APIs (لصفحة MAC Tracker)
  7. Port History APIs (للجدول الزمني وتشخيص المنافذ)
  8. AI & Predictive APIs
  9. Port Flapping APIs
═══════════════════════════════════════════════════════════════
"""

# ============================================================
# 1. Imports (منظمة)
# ============================================================
import json
import logging
import random
import subprocess
import platform
from functools import wraps
from datetime import timedelta

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.core.cache import cache
from django.views.decorators.cache import cache_page
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count, Q
from rest_framework.decorators import api_view
from rest_framework.response import Response

# Models
from core.models import Switch, Interface, Location

# Services - Discovery
from core.services.auto_discovery import discover_network
from core.services.smart_discovery import smart_discovery
from core.services.topology_discovery import generate_topology, build_topology

# Services - Monitoring & Inspector
from core.services.switch_inspector import (
    get_system_info,
    get_interfaces_detail,
    get_error_analysis,
    get_cdp_neighbors,
    get_poe_detail,
    get_port_security,
    get_mac_table,
    get_ip_interfaces,
    get_tdr_results,
    get_vlans_full,
    get_environment,
    get_stp_info,
)
from core.services.monitoring import get_vlans, get_ports_status

# Services - Predictive & AI
from core.services.predictive import (
    estimate_cable_length,
    detect_network_loops,
    check_stp_consistency,
    FailurePredictor,
    detect_duplex_mismatch,
)
from core.services.predictive_ai import predict_cpu_crash

# Services - Port History
from core.services.port_history import (
    get_port_timeline,
    get_switch_events,
    get_flap_report,
    get_port_diagnostics,
    get_all_ports_health,
    get_anomaly_report,
    get_error_trend,
    get_traffic_baseline,
)

# Services - SNMP
from core.services.snmp import clear_cache, snmp_walk_with_index

logger = logging.getLogger(__name__)


# ============================================================
# 2. Helpers & Decorators
# ============================================================

def api_cache(timeout=30):
    """
    ديكوراتور للتخزين المؤقت لواجهات API
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            cache_key = f"api:{request.path}:{request.GET.urlencode()}:{kwargs.get('hostname', '')}"
            cached_response = cache.get(cache_key)
            if cached_response:
                return cached_response
            response = view_func(request, *args, **kwargs)
            if response.status_code == 200:
                cache.set(cache_key, response, timeout)
            return response
        return wrapper
    return decorator


def _json(data, status=200):
    """إرجاع JSON response"""
    return JsonResponse(data, status=status, safe=False)


def _get_switch_by_hostname(hostname):
    """جلب السويتش بواسطة hostname"""
    return get_object_or_404(Switch, hostname=hostname)


def _get_switch_by_id(switch_id):
    """جلب السويتش بواسطة ID"""
    return get_object_or_404(Switch, id=switch_id)


# ============================================================
# 3. Page Views (الصفحات الرئيسية)
# ============================================================

@login_required
def dashboard_page(request):
    """
    الصفحة الرئيسية — تعرض كروت المواقع فقط.
    لا تُحمِّل بيانات SNMP هنا، كلها تأتي عبر WebSocket.
    """
    locations = Location.objects.annotate(
        total_switches=Count("switch")
    ).order_by("name")
    
    return render(request, "dashboard/dashboard.html", {
        "locations": locations,
    })


@login_required
def location_switches_page(request, location_id):
    """
    صفحة سويتشات مكان واحد.
    تمرر الـ location_id للـ template حتى يفلتر WS feed.
    """
    location = get_object_or_404(Location, id=location_id)
    switches = Switch.objects.filter(location=location).order_by("hostname")
    
    # تحويل السويتشات إلى JSON للعرض الأولي
    switches_data = []
    for sw in switches:
        switches_data.append({
            'hostname': sw.hostname,
            'ip_address': sw.ip_address,
            'cpu_usage': sw.cpu_usage,
        })
    
    return render(request, "dashboard/location_switches.html", {
        "location": location,
        "switches": switches,
        "switches_data": json.dumps(switches_data),
    })


@login_required
def switches_page(request):
    """صفحة عرض جميع السويتشات"""
    switches = Switch.objects.all()
    return render(request, "dashboard/switches.html", {
        "switches": switches
    })


@login_required
def topology_page(request, location_id=None):
    """صفحة التوبولوجيا المحسنة"""
    # تحسين استعلام المواقع
    locations = Location.objects.filter(
        switch__isnull=False
    ).annotate(
        switches_count=Count('switch')
    ).distinct()
    
    current_location = None
    if location_id:
        try:
            current_location = locations.get(id=location_id)
        except Location.DoesNotExist:
            pass
    elif locations.exists():
        current_location = locations.first()
    
    # Pre-fetch أول 10 سويتشات فقط للعرض السريع
    initial_switches = []
    if current_location:
        initial_switches = list(Switch.objects.filter(
            location=current_location
        ).values('id', 'hostname', 'ip_address')[:10])
    
    context = {
        'locations': locations,
        'current_location': current_location,
        'initial_switches': json.dumps(initial_switches),
        'location_id': location_id or '',
    }
    return render(request, "dashboard/topology.html", context)


@login_required
def discovery_page(request):
    """صفحة اكتشاف الأجهزة"""
    return render(request, "dashboard/discovery.html")


@login_required
def switch_details(request, hostname):
    """صفحة تفاصيل سويتش واحد (FULL DETAILS)"""
    sw = get_object_or_404(Switch, hostname=hostname)
    return render(request, "dashboard/switch_details.html", {
        "switch": sw
    })


@login_required
def mac_tracker_page(request):
    """صفحة MAC Tracker الرئيسية"""
    switches = Switch.objects.select_related("location").order_by("location__name", "hostname")
    locations = Location.objects.order_by("name")
    return render(request, "dashboard/mac_tracker.html", {
        "switches": switches,
        "locations": locations,
    })


@login_required
def port_flapping_page(request):
    """صفحة مراقبة تقلب المنافذ (Port Flapping)"""
    return render(request, "dashboard/port_flapping.html")


# ============================================================
# 4. Dashboard & Topology APIs
# ============================================================

@api_view(["GET"])
def dashboard_api(request):
    """API للإحصائيات العامة للداشبورد"""
    switches = Switch.objects.count()
    interfaces = Interface.objects.count()
    return Response({
        "switches": switches,
        "interfaces": interfaces
    })


from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.core.cache import cache
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_headers
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.decorators import login_required
from .models import Location, Switch
from .utils import get_switch_basic_info, get_topology_simple
import json
from django.db.models import Count, Q
from django.db import connection
@api_view(["GET"])
def locations_api(request):
    """API سريع للمواقع"""
    cache_key = "locations_api_data"
    cached = cache.get(cache_key)
    
    if cached:
        return Response(cached)
    
    locations = Location.objects.filter(
        switch__isnull=False
    ).annotate(
        switches_count=Count('switch'),
        online_count=Count('switch', filter=Q(switch__cpu_usage__isnull=False))
    ).values('id', 'name', 'switches_count', 'online_count')
    
    data = list(locations)
    cache.set(cache_key, data, timeout=300)  # Cache 5 دقائق
    return Response(data)



@api_view(["GET"])
def switches_api(request):
    """API مجزأ للسويتشات - تحميل تدريجي"""
    location_id = request.GET.get('location_id')
    offset = int(request.GET.get('offset', 0))
    limit = int(request.GET.get('limit', 20))
    
    # بناء الاستعلام
    queryset = Switch.objects.select_related('location')
    if location_id and location_id != 'all':
        queryset = queryset.filter(location_id=location_id)
    
    # جلب العدد الكلي
    total = queryset.count()
    
    # جلب البيانات المجزأة
    switches = queryset[offset:offset+limit]
    
    # تجهيز البيانات للعرض
    switches_data = []
    for sw in switches:
        switches_data.append({
            'id': sw.id,
            'hostname': sw.hostname,
            'ip': sw.ip_address,
            'location_name': sw.location.name if sw.location else 'No Location',
            'status': 'online',
            'cpu': sw.cpu_usage or 0,
            'memory': sw.memory_usage or 0,
            'model': sw.model or 'N/A',
            'last_seen': sw.last_seen.strftime('%Y-%m-%d %H:%M:%S') if sw.last_seen else 'Never'
        })
    
    return Response({
        'switches': switches_data,
        'total': total,
        'offset': offset,
        'limit': limit,
        'has_more': offset + limit < total
    })

@api_view(["GET"])
def topology_links_api(request):
    """API للروابط فقط - يتم تحميلها بشكل منفصل"""
    location_id = request.GET.get('location_id')
    
    cache_key = f"topology_links_{location_id or 'all'}"
    cached = cache.get(cache_key)
    
    if cached:
        return Response({'links': cached})
    
    # جلب السويتشات للموقع
    if location_id and location_id != 'all':
        switches = Switch.objects.filter(location_id=location_id)
    else:
        switches = Switch.objects.all()
    
    # بناء الروابط (يمكن أن يكون ثقيلاً لكنه يحدث مرة واحدة)
    links = get_topology_simple(switches)
    
    # تجهيز الروابط بالـ IDs
    links_data = []
    node_map = {sw.hostname: sw.id for sw in switches}
    
    for link in links:
        if link['source'] in node_map and link['target'] in node_map:
            links_data.append({
                'source': node_map[link['source']],
                'target': node_map[link['target']]
            })
    
    cache.set(cache_key, links_data, timeout=300)
    return Response({'links': links_data})



@api_view(["GET"])
def topology_api(request):
    """API محسنة لجلب بيانات التوبولوجيا مع Cache"""
    loc_id = request.GET.get("location_id")
    
    # Cache لمدة 30 ثانية فقط للبيانات الثقيلة
    cache_key = f"topology_data_{loc_id or 'all'}"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return Response(cached_data)
    
    # تحسين الاستعلامات باستخدام select_related و prefetch_related
    if loc_id:
        switches = Switch.objects.filter(location_id=loc_id).select_related('location')
    else:
        switches = Switch.objects.select_related('location').all()
    
    # تجهيز البيانات بشكل أخف
    nodes = []
    node_ids = set()
    
    for sw in switches:
        nodes.append({
            "id": sw.id,  # استخدام ID بدلاً من hostname
            "hostname": sw.hostname,
            "ip": sw.ip_address,
            "location_id": sw.location_id,
            "location_name": sw.location.name if sw.location else "No Location",
            "status": "online",  # يمكن تعديله حسب حالة الجهاز الفعلية
            "cpu": random.randint(10, 60),  # مثال مؤقت
            "memory": random.randint(20, 80)  # مثال مؤقت
        })
        node_ids.add(sw.id)
    
    # بناء الروابط (تحسين الأداء)
    links = []
    link_set = set()
    
    for sw in switches:
        topo = build_topology([sw])
        for link in topo:
            src_id = None
            dst_id = None
            
            # البحث عن ID السويتشات
            for node in nodes:
                if node["hostname"] == link["source"]:
                    src_id = node["id"]
                if node["hostname"] == link["target"]:
                    dst_id = node["id"]
            
            if src_id and dst_id and dst_id in node_ids:
                key = tuple(sorted([src_id, dst_id]))
                if key not in link_set:
                    links.append({
                        "source": src_id,
                        "target": dst_id,
                        "traffic": random.randint(10, 100)
                    })
                    link_set.add(key)
    
    data = {
        "nodes": nodes,
        "links": links,
        "total_switches": len(nodes),
        "total_links": len(links)
    }
    
    # تخزين في cache لمدة 30 ثانية
    cache.set(cache_key, data, timeout=30)
    return Response(data)


@api_view(["GET"])
def network_map_api(request):
    """
    API لخريطة الشبكة (Nodes + Links)
    مع cache لمدة 30 ثانية
    """
    loc_id = request.GET.get("location_id")
    cache_key = f"network_map_{loc_id or 'all'}"
    cached = cache.get(cache_key)
    if cached:
        return Response(cached)

    switches = Switch.objects.filter(location_id=loc_id) if loc_id else Switch.objects.all()

    nodes = []
    links = []
    node_ids = set()

    # بناء العقد (Nodes)
    for sw in switches:
        status = "online"
        try:
            vlans = get_vlans(sw.ip_address, sw.snmp_community)
            vlan_ids = [v["vlan_id"] for v in vlans]
        except:
            vlan_ids = []

        nodes.append({
            "id": sw.hostname,
            "ip": sw.ip_address,
            "status": status,
            "vlans": vlan_ids
        })
        node_ids.add(sw.hostname)

    # بناء الروابط (Links)
    link_set = set()
    for sw in switches:
        topo = build_topology([sw])
        for link in topo:
            src = link["source"]
            dst = link["target"]
            if dst not in node_ids:
                continue
            key = tuple(sorted([src, dst]))
            if key not in link_set:
                links.append({
                    "source": src,
                    "target": dst,
                    "traffic": random.randint(10, 100)
                })
                link_set.add(key)

    # Fallback إذا لم توجد روابط
    if not links and len(nodes) > 1:
        for i in range(len(nodes) - 1):
            links.append({
                "source": nodes[i]["id"],
                "target": nodes[i+1]["id"],
                "traffic": random.randint(10, 100)
            })

    data = {"nodes": nodes, "links": links}
    cache.set(cache_key, data, timeout=30)
    return Response(data)


@api_view(["GET"])
def switch_ports_api(request, ip):
    """API لجلب حالة منافذ سويتش معين"""
    ports = get_ports_status(ip, "public")
    return Response(ports)


# ============================================================
# 5. Discovery APIs
# ============================================================

@api_view(["GET", "POST"])
def auto_discovery_api(request):
    """
    يسكان الشبكة ويحفظ الأجهزة المكتشفة في قاعدة البيانات.
    POST body:
        network           : "192.168.70.0/24"
        community         : "private"
        extra_communities : ["public", "cisco"]
    """
    if request.method == "POST":
        network = request.data.get("network", "192.168.70.0/24")
        community = request.data.get("community", "private")
        extra_communities = request.data.get("extra_communities", [])
    else:
        network = request.GET.get("network", "192.168.70.0/24")
        community = request.GET.get("community", "private")
        extra_communities = request.GET.getlist("extra_communities", [])

    logger.info(f"[Discovery] network={network} community={community} extras={extra_communities}")

    result = discover_network(
        network,
        community=community,
        extra_communities=extra_communities,
    )

    logger.info(f"[Discovery] found={result.get('total_found', 0)}")
    return Response(result)


@api_view(["GET", "POST"])
def smart_discovery_api(request):
    """
    Smart discovery من seed IP.
    يُجرب communities متعددة تلقائياً.
    """
    if request.method == "POST":
        seed_ip = request.data.get("seed_ip", "192.168.70.1")
        community = request.data.get("community", "private")
        extra_communities = request.data.get("extra_communities", [])
    else:
        seed_ip = request.GET.get("seed_ip", "192.168.70.1")
        community = request.GET.get("community", "private")
        extra_communities = request.GET.getlist("extra_communities", [])

    result = smart_discovery(seed_ip, community)
    return Response({"discovered": result})


# ============================================================
# 6. AI & Predictive APIs
# ============================================================

@api_view(["GET"])
def ai_insights(request):
    """API للتنبؤات الذكية باستخدام AI"""
    cpu_data = [20, 40, 60, 85, 90]
    result = predict_cpu_crash(cpu_data)
    return Response({
        "ai": result
    })


# ============================================================
# 7. Switch Inspector APIs (لصفحة تفاصيل السويتش)
# ============================================================

@api_cache(timeout=30)
def api_switch_system(request, hostname):
    """API لمعلومات النظام الأساسية للسويتش"""
    sw = _get_switch_by_hostname(hostname)
    try:
        data = get_system_info(sw.ip_address, sw.snmp_community)
    except Exception as e:
        data = {"error": str(e)}
    return JsonResponse(data)


@api_cache(timeout=30)
def api_switch_interfaces(request, hostname):
    """API لجلب تفاصيل المنافذ (Interfaces)"""
    sw = _get_switch_by_hostname(hostname)
    status_filter = request.GET.get("status", "all")
    try:
        ifaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)
        if status_filter == "connected":
            ifaces = [i for i in ifaces if i["status"] == "connected"]
        elif status_filter == "notconnect":
            ifaces = [i for i in ifaces if i["status"] == "notconnect"]
        elif status_filter == "disabled":
            ifaces = [i for i in ifaces if i["status"] == "disabled"]
        elif status_filter == "err":
            ifaces = [i for i in ifaces if i["has_errors"]]
    except Exception:
        ifaces = []
    return JsonResponse({"interfaces": ifaces})


@api_cache(timeout=30)
def api_switch_errors(request, hostname):
    """API لتحليل أخطاء المنافذ"""
    sw = _get_switch_by_hostname(hostname)
    try:
        ifaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)
        errors = get_error_analysis(ifaces)
    except Exception:
        errors = []
    return JsonResponse({"errors": errors})


@api_cache(timeout=60)
def api_switch_cdp(request, hostname):
    """API لجيران CDP"""
    sw = _get_switch_by_hostname(hostname)
    try:
        data = get_cdp_neighbors(sw.ip_address, sw.snmp_community)
    except Exception:
        data = []
    return JsonResponse({"neighbors": data})


@api_cache(timeout=30)
def api_switch_poe(request, hostname):
    """API لمعلومات PoE"""
    sw = _get_switch_by_hostname(hostname)
    try:
        data = get_poe_detail(sw.ip_address, sw.snmp_community)
    except Exception:
        data = {"ports": [], "total_w": 0, "consumed_w": 0, "available_w": 0, "faulty": []}
    return JsonResponse(data)


@api_cache(timeout=60)
def api_switch_portsec(request, hostname):
    """API لمعلومات Port Security"""
    sw = _get_switch_by_hostname(hostname)
    try:
        data = get_port_security(sw.ip_address, sw.snmp_community)
    except Exception:
        data = {"enabled": False, "ports": [], "enabled_count": 0}
    return JsonResponse(data)


@api_cache(timeout=30)
def api_switch_mac(request, hostname):
    """API لجدول MAC addresses"""
    sw = _get_switch_by_hostname(hostname)
    port = request.GET.get("port", "").strip()
    page = max(0, int(request.GET.get("page", "0")))
    limit = min(500, max(10, int(request.GET.get("limit", "200"))))
    show_all = request.GET.get("all", "0") == "1"

    try:
        if show_all:
            limit = 5000
        data = get_mac_table(
            sw.ip_address,
            sw.snmp_community,
            limit=limit,
            offset_n=page * limit,
        )
        if port:
            data["mac_table"] = [
                m for m in data["mac_table"]
                if port.lower() in m["port"].lower()
            ]
            data["filtered_total"] = len(data["mac_table"])
    except Exception as e:
        data = {"mac_table": [], "total": 0, "offset": 0, "limit": limit, "error": str(e)}

    return JsonResponse(data)


@api_cache(timeout=60)
def api_switch_ipbrief(request, hostname):
    """API لـ IP Interface Brief"""
    sw = _get_switch_by_hostname(hostname)
    try:
        data = get_ip_interfaces(sw.ip_address, sw.snmp_community)
    except Exception:
        data = []
    return JsonResponse({"ip_interfaces": data})


@api_cache(timeout=120)
def api_switch_tdr(request, hostname):
    """API لنتائج TDR (اختبار الكابلات)"""
    sw = _get_switch_by_hostname(hostname)
    try:
        data = get_tdr_results(sw.ip_address, sw.snmp_community)
    except Exception:
        data = []
    return JsonResponse({"tdr": data})


@api_cache(timeout=60)
def api_switch_vlans(request, hostname):
    """API لـ VLANs"""
    sw = _get_switch_by_hostname(hostname)
    try:
        data = get_vlans_full(sw.ip_address, sw.snmp_community)
        data = [v for v in data if v["port_count"] > 0 or v["active"]]
    except Exception:
        data = []
    return JsonResponse({"vlans": data})


@api_cache(timeout=60)
def api_switch_env(request, hostname):
    """API لمعلومات البيئة (حرارة، مراوح، إمدادات طاقة)"""
    sw = _get_switch_by_hostname(hostname)
    try:
        data = get_environment(sw.ip_address, sw.snmp_community)
    except Exception:
        data = {"temperatures": [], "fans": [], "power_supplies": []}
    return JsonResponse(data)


@api_cache(timeout=60)
def api_switch_stp(request, hostname):
    """API لمعلومات Spanning Tree Protocol"""
    sw = _get_switch_by_hostname(hostname)
    try:
        data = get_stp_info(sw.ip_address, sw.snmp_community)
    except Exception:
        data = {"root_bridge": "", "ports": [], "blocking_count": 0, "forwarding_count": 0}
    return JsonResponse(data)


@api_cache(timeout=30)
def api_switch_cable_estimate(request, hostname):
    """تقدير طول الكابل بدون TDR"""
    sw = _get_switch_by_hostname(hostname)
    try:
        estimates = estimate_cable_length(sw.ip_address, sw.snmp_community)
        poor_cables = [e for e in estimates if e['quality'] == 'poor']
        return JsonResponse({
            'estimates': estimates,
            'poor_cables_count': len(poor_cables),
            'poor_cables': poor_cables,
            'message': f'تم تقدير طول {len(estimates)} كابل' if estimates else 'لا توجد بيانات كافية'
        })
    except Exception as e:
        return JsonResponse({'error': str(e), 'estimates': []})


@api_cache(timeout=60)
def api_switch_loops(request, hostname):
    """اكتشاف حلقات (Loops) في الشبكة"""
    sw = _get_switch_by_hostname(hostname)
    try:
        mac_data = get_mac_table(sw.ip_address, sw.snmp_community, limit=5000)
        loops = detect_network_loops(sw.ip_address, sw.snmp_community, mac_data)
        stp_status = check_stp_consistency(sw.ip_address, sw.snmp_community)
        return JsonResponse({
            'loops': loops,
            'stp_status': stp_status,
            'has_issue': loops['has_loop'] or not stp_status.get('stp_healthy', True)
        })
    except Exception as e:
        return JsonResponse({'error': str(e), 'loops': {'has_loop': False, 'loops': []}})


@api_cache(timeout=60)
def api_switch_duplex(request, hostname):
    """اكتشاف Duplex Mismatch"""
    sw = _get_switch_by_hostname(hostname)
    try:
        mismatches = detect_duplex_mismatch(sw.ip_address, sw.snmp_community)
        return JsonResponse(mismatches)
    except Exception as e:
        return JsonResponse({'error': str(e), 'has_mismatch': False, 'mismatches': []})


@api_cache(timeout=60)
def api_switch_predictions(request, hostname):
    """توقع الأعطال (Failure Prediction)"""
    sw = _get_switch_by_hostname(hostname)
    try:
        predictor = FailurePredictor(sw.ip_address, sw.snmp_community)
        try:
            from core.models import Errors
            predictor.load_history(Errors, days=30)
        except Exception:
            pass
        
        predictions = predictor.get_full_prediction()
        cable_estimates = estimate_cable_length(sw.ip_address, sw.snmp_community)
        
        # حساب درجة الخطر الإجمالية
        risk_score = 0
        if predictions['cable'].get('risk_percent', 0) > 50:
            risk_score += 30
        if predictions['cpu'].get('risk_percent', 0) > 50:
            risk_score += 40
        if predictions['ports'].get('has_overload', False):
            risk_score += 20
        if predictions['broadcast'].get('has_storm_risk', False):
            risk_score += 30
        
        risk_level = 'critical' if risk_score > 70 else 'warning' if risk_score > 30 else 'good'
        
        return JsonResponse({
            'predictions': predictions,
            'cable_estimates': cable_estimates[:10],
            'risk_score': min(100, risk_score),
            'risk_level': risk_level,
            'timestamp': predictions['timestamp']
        })
    except Exception as e:
        return JsonResponse({'error': str(e), 'predictions': {}})


@api_cache(timeout=60)
def api_switch_health_report(request, hostname):
    """تقرير صحي شامل للسويتش"""
    sw = _get_switch_by_hostname(hostname)
    try:
        system = get_system_info(sw.ip_address, sw.snmp_community)
        interfaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)
        errors = get_error_analysis(interfaces)
        poe = get_poe_detail(sw.ip_address, sw.snmp_community)
        loops = detect_network_loops(sw.ip_address, sw.snmp_community)
        duplex = detect_duplex_mismatch(sw.ip_address, sw.snmp_community)
        
        total_ports = len(interfaces)
        up_ports = len([i for i in interfaces if i['status'] == 'connected'])
        error_ports = len([i for i in interfaces if i['has_errors']])
        
        if system.get('cpu_5s', 0) > 90 or error_ports > 5 or loops.get('has_loop'):
            overall_status = 'critical'
        elif system.get('cpu_5s', 0) > 70 or error_ports > 0 or poe.get('faulty'):
            overall_status = 'warning'
        else:
            overall_status = 'healthy'
        
        return JsonResponse({
            'overall_status': overall_status,
            'system': {
                'hostname': system.get('hostname'),
                'model': system.get('model'),
                'ios': system.get('ios'),
                'uptime': system.get('uptime'),
                'cpu': system.get('cpu_5s'),
                'memory_percent': system.get('mem_pct')
            },
            'ports_summary': {
                'total': total_ports,
                'up': up_ports,
                'down': total_ports - up_ports,
                'with_errors': error_ports
            },
            'poe_summary': {
                'total_w': poe.get('total_w', 0),
                'consumed_w': poe.get('consumed_w', 0),
                'faulty_ports': len(poe.get('faulty', []))
            },
            'issues': {
                'critical_errors': len([e for e in errors if e['severity'] == 'critical']),
                'warning_errors': len([e for e in errors if e['severity'] == 'warning']),
                'has_loop': loops.get('has_loop', False),
                'has_duplex_mismatch': duplex.get('has_mismatch', False),
                'loop_count': loops.get('loop_count', 0),
                'duplex_mismatch_count': duplex.get('count', 0)
            },
            'recommendations': _generate_recommendations(system, errors, loops, duplex, poe)
        })
    except Exception as e:
        return JsonResponse({'error': str(e), 'overall_status': 'unknown'})


@api_cache(timeout=30)
def api_switch_clear_cache(request, hostname):
    """مسح التخزين المؤقت لسويتش معين (للتحديث اليدوي)"""
    sw = _get_switch_by_hostname(hostname)
    clear_cache(sw.ip_address)
    cache.clear()
    return JsonResponse({'status': 'success', 'message': f'Cache cleared for {hostname}'})


def api_switch_vlans_debug(request, hostname):
    """
    endpoint مؤقت للتشخيص — يعرض البيانات الخام لـ VLANs.
    يمكن إزالته بعد التأكد من عمل كل شيء بشكل صحيح.
    """
    from core.services.monitoring import get_vlans
    
    sw = get_object_or_404(Switch, hostname=hostname)
    
    result = {
        "switch": sw.hostname,
        "ip": sw.ip_address,
    }
    
    # جلب VLANات من switch_inspector
    try:
        vlans_full = get_vlans_full(sw.ip_address, sw.snmp_community)
        result["vlans_full"] = vlans_full
        result["vlans_full_count"] = len(vlans_full)
    except Exception as e:
        result["vlans_full_error"] = str(e)
        result["vlans_full"] = []
    
    # جلب VLANات من monitoring
    try:
        vlans_mon = get_vlans(sw.ip_address, sw.snmp_community)
        result["vlans_monitoring"] = vlans_mon
        result["vlans_monitoring_count"] = len(vlans_mon)
    except Exception as e:
        result["vlans_monitoring_error"] = str(e)
        result["vlans_monitoring"] = []
    
    # جلب أسماء المنافذ
    try:
        from core.services.switch_inspector import _get_if_names
        if_names = _get_if_names(sw.ip_address, sw.snmp_community)
        result["if_names"] = if_names[:20]
    except Exception as e:
        result["if_names_error"] = str(e)
    
    # اختبار OID_PORTMAP مباشرة
    try:
        portmap_raw = snmp_walk_with_index(sw.ip_address, sw.snmp_community, "1.3.6.1.4.1.9.9.68.1.2.2.1.2")
        result["portmap_raw"] = portmap_raw[:20]
    except Exception as e:
        result["portmap_raw_error"] = str(e)
    
    return JsonResponse(result)


def _generate_recommendations(system, errors, loops, duplex, poe):
    """توليد توصيات بناءً على التحليلات (دالة مساعدة)"""
    recommendations = []
    
    if system.get('cpu_5s', 0) > 85:
        recommendations.append({
            'severity': 'critical',
            'title': '⚠️ ارتفاع حاد في CPU',
            'description': f'CPU عند {system["cpu_5s"]}%',
            'action': 'افحص وجود Broadcast Storm أو Loop في الشبكة'
        })
    elif system.get('cpu_5s', 0) > 70:
        recommendations.append({
            'severity': 'warning',
            'title': '⚠️ ارتفاع في CPU',
            'description': f'CPU عند {system["cpu_5s"]}%',
            'action': 'راقب الـ traffic وراجع تكوين STP'
        })
    
    critical_errors = [e for e in errors if e['severity'] == 'critical']
    if critical_errors:
        recommendations.append({
            'severity': 'critical',
            'title': '🔴 أخطاء حرجة في المنافذ',
            'description': f'{len(critical_errors)} منفذ يعاني من أخطاء',
            'action': 'افحص الكابلات وإعدادات Duplex على المنافذ: ' + 
                      ', '.join([e['name'] for e in critical_errors[:3]])
        })
    
    if loops.get('has_loop'):
        recommendations.append({
            'severity': 'critical',
            'title': '🔄 وجود Loop في الشبكة',
            'description': f'تم اكتشاف {loops.get("loop_count", 0)} حلقة محتملة',
            'action': 'افحص الكابلات المتكررة أو الأجهزة المتصلة بمنفذين'
        })
    
    if duplex.get('has_mismatch'):
        recommendations.append({
            'severity': 'warning',
            'title': '⚡ Duplex Mismatch',
            'description': f'{duplex.get("count", 0)} منفذ يعمل بـ Half Duplex',
            'action': 'غيّر إعدادات الـ duplex إلى Auto أو Full على الطرفين'
        })
    
    if poe.get('faulty'):
        recommendations.append({
            'severity': 'warning',
            'title': '🔌 مشاكل في PoE',
            'description': f'{len(poe.get("faulty", []))} منفذ يعاني من مشاكل في الطاقة',
            'action': 'افحص الأجهزة المتصلة واستهلاك الطاقة'
        })
    
    if not recommendations:
        recommendations.append({
            'severity': 'good',
            'title': '✅ السويتش بحالة جيدة',
            'description': 'جميع المقاييس ضمن الحدود الطبيعية',
            'action': 'استمر في المراقبة الدورية'
        })
    
    return recommendations


# ============================================================
# 8. Switch Inspector APIs (لصفحة MAC Tracker)
# ============================================================

@require_GET
def api_mac_table(request, switch_id):
    """
    GET /api/mac/<switch_id>/
    params: ?limit=500&offset=0&search=xx:xx:xx
    يُرجع MAC table مع فلترة اختيارية.
    """
    sw = _get_switch_by_id(switch_id)
    limit = int(request.GET.get("limit", 500))
    offset = int(request.GET.get("offset", 0))
    search = request.GET.get("search", "").strip().lower()

    data = get_mac_table(sw.ip_address, sw.snmp_community, limit=limit, offset_n=offset)

    if search:
        filtered = [e for e in data["mac_table"] if search in e["mac"].lower() or search in (e["port"] or "").lower()]
        data["mac_table"] = filtered
        data["total"] = len(filtered)

    for entry in data["mac_table"]:
        entry["switch_hostname"] = sw.hostname
        entry["switch_id"] = sw.id

    return _json(data)


@require_GET
def api_mac_search_global(request):
    """
    GET /api/mac/search/?q=xx:xx:xx
    يبحث في كل السويتشات المتاحة عن MAC معين.
    """
    query = request.GET.get("q", "").strip().lower()
    if len(query) < 4:
        return _json({"error": "يجب أن يكون البحث 4 أحرف على الأقل"}, 400)

    results = []
    switches = Switch.objects.all()

    for sw in switches:
        try:
            data = get_mac_table(sw.ip_address, sw.snmp_community, limit=2000)
            for entry in data.get("mac_table", []):
                if query in entry["mac"].lower() or query in (entry["port"] or "").lower():
                    results.append({
                        "mac": entry["mac"],
                        "port": entry["port"],
                        "vlan_id": entry.get("vlan_id"),
                        "type": entry.get("type", "learned"),
                        "switch_hostname": sw.hostname,
                        "switch_ip": sw.ip_address,
                        "switch_id": sw.id,
                        "location": sw.location.name if sw.location else "—",
                    })
        except Exception:
            pass

    return _json({"results": results, "count": len(results), "query": query})


@require_GET
def api_system_info(request, switch_id):
    """API لمعلومات النظام الأساسية (لـ MAC Tracker)"""
    sw = _get_switch_by_id(switch_id)
    data = get_system_info(sw.ip_address, sw.snmp_community)
    return _json(data)


@require_GET
def api_interfaces(request, switch_id):
    """API لتفاصيل المنافذ (لـ MAC Tracker)"""
    sw = _get_switch_by_id(switch_id)
    ifaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)
    errors = get_error_analysis(ifaces)
    return _json({"interfaces": ifaces, "errors": errors})


@require_GET
def api_vlans(request, switch_id):
    """API لـ VLANs (لـ MAC Tracker)"""
    sw = _get_switch_by_id(switch_id)
    vlans = get_vlans_full(sw.ip_address, sw.snmp_community)

    CAMERA_KEYWORDS = ["camera", "cam", "cctv", "vlan100", "surveillance"]
    AP_KEYWORDS = ["ap", "wifi", "wireless", "wlan", "access_point", "accesspoint"]

    for v in vlans:
        name_lower = v["name"].lower()
        v["is_camera"] = any(k in name_lower for k in CAMERA_KEYWORDS) or v["vlan_id"] == 100
        v["is_ap"] = any(k in name_lower for k in AP_KEYWORDS)

    return _json(vlans)


@require_GET
def api_stp(request, switch_id):
    """API لمعلومات STP (لـ MAC Tracker)"""
    sw = _get_switch_by_id(switch_id)
    data = get_stp_info(sw.ip_address, sw.snmp_community)

    blocking = [p for p in data["ports"] if p["blocking"]]
    loops = []
    if data["blocking_count"] > 10:
        loops.append({
            "severity": "warning",
            "msg": f"{data['blocking_count']} ports in blocking state — قد يكون هناك loop أو misconfiguration",
        })
    if not data["root_bridge"]:
        loops.append({
            "severity": "critical",
            "msg": "لم يتم العثور على Root Bridge — تحقق من STP configuration",
        })

    data["analysis"] = loops
    data["blocking_ports"] = blocking
    return _json(data)


@require_GET
def api_poe(request, switch_id):
    """API لمعلومات PoE (لـ MAC Tracker)"""
    sw = _get_switch_by_id(switch_id)
    data = get_poe_detail(sw.ip_address, sw.snmp_community)
    return _json(data)


@require_GET
def api_cdp(request, switch_id):
    """API لجيران CDP (لـ MAC Tracker)"""
    sw = _get_switch_by_id(switch_id)
    data = get_cdp_neighbors(sw.ip_address, sw.snmp_community)
    return _json(data)


@require_GET
def api_port_security(request, switch_id):
    """API لمعلومات Port Security (لـ MAC Tracker)"""
    sw = _get_switch_by_id(switch_id)
    data = get_port_security(sw.ip_address, sw.snmp_community)
    return _json(data)


@require_GET
def api_environment(request, switch_id):
    """API لمعلومات البيئة (لـ MAC Tracker)"""
    sw = _get_switch_by_id(switch_id)
    data = get_environment(sw.ip_address, sw.snmp_community)
    return _json(data)


@require_GET
def api_tdr(request, switch_id):
    """API لنتائج TDR (لـ MAC Tracker)"""
    sw = _get_switch_by_id(switch_id)
    data = get_tdr_results(sw.ip_address, sw.snmp_community)
    return _json(data)


@require_GET
def api_ip_brief(request, switch_id):
    """API لـ IP Interface Brief (لـ MAC Tracker)"""
    sw = _get_switch_by_id(switch_id)
    data = get_ip_interfaces(sw.ip_address, sw.snmp_community)
    return _json(data)


@require_GET
def api_connectivity(request, switch_id):
    """API لفحص اتصالية السويتش (SNMP + Ping)"""
    sw = _get_switch_by_id(switch_id)
    result = {"switch_id": sw.id, "hostname": sw.hostname, "ip": sw.ip_address}

    # SNMP check
    try:
        info = get_system_info(sw.ip_address, sw.snmp_community)
        result["snmp_ok"] = bool(info.get("hostname"))
        result["snmp_name"] = info.get("hostname", "")
        result["uptime"] = info.get("uptime", "")
    except Exception as e:
        result["snmp_ok"] = False
        result["snmp_error"] = str(e)

    # Ping check
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "2", sw.ip_address]
        else:
            cmd = ["ping", "-c", "2", "-W", "2", sw.ip_address]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        result["ping_ok"] = r.returncode == 0
        result["ping_out"] = (r.stdout + r.stderr)[:300]
    except Exception as e:
        result["ping_ok"] = False
        result["ping_error"] = str(e)

    result["status"] = (
        "online" if result.get("snmp_ok") and result.get("ping_ok") else
        "degraded" if result.get("snmp_ok") or result.get("ping_ok") else
        "offline"
    )
    return _json(result)


@csrf_exempt
@require_POST
def api_ping(request):
    """
    POST /api/ping/
    body: {"target": "192.168.1.1", "count": 4}
    يُشغِّل ping من السيرفر ويُرجع النتائج.
    """
    try:
        body = json.loads(request.body)
        target = body.get("target", "").strip()
        count = min(int(body.get("count", 4)), 10)

        if not target:
            return _json({"error": "target مطلوب"}, 400)

        import ipaddress
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return _json({"error": "IP address غير صالح"}, 400)

        is_windows = platform.system().lower() == "windows"
        cmd = (
            ["ping", "-n", str(count), target]
            if is_windows else
            ["ping", "-c", str(count), "-W", "2", target]
        )

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        stats = _parse_ping_stats(output)

        return _json({
            "target": target,
            "success": result.returncode == 0,
            "output": output,
            "stats": stats,
        })

    except subprocess.TimeoutExpired:
        return _json({"error": "timeout — الجهاز لا يستجيب", "success": False})
    except Exception as e:
        return _json({"error": str(e), "success": False}, 500)


def _parse_ping_stats(output: str) -> dict:
    """يستخرج packet loss وزمن الاستجابة من ping output (دالة مساعدة)"""
    import re
    stats = {"sent": 0, "received": 0, "loss_pct": 100, "avg_ms": None}

    m = re.search(r'(\d+) packets transmitted, (\d+) received', output)
    if m:
        stats["sent"] = int(m.group(1))
        stats["received"] = int(m.group(2))
        if stats["sent"] > 0:
            stats["loss_pct"] = round((stats["sent"] - stats["received"]) / stats["sent"] * 100)

    m = re.search(r'Sent = (\d+), Received = (\d+)', output)
    if m:
        stats["sent"] = int(m.group(1))
        stats["received"] = int(m.group(2))
        if stats["sent"] > 0:
            stats["loss_pct"] = round((stats["sent"] - stats["received"]) / stats["sent"] * 100)

    m = re.search(r'rtt \S+ = [\d.]+/([\d.]+)/', output)
    if m:
        stats["avg_ms"] = float(m.group(1))

    m = re.search(r'Average = (\d+)ms', output)
    if m:
        stats["avg_ms"] = float(m.group(1))

    return stats


@require_GET
def api_duplex_analysis(request, switch_id):
    """
    GET /api/duplex/<switch_id>/
    يكتشف مشاكل Duplex/Speed mismatch.
    """
    sw = _get_switch_by_id(switch_id)
    ifaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)

    issues = []
    for ifc in ifaces:
        if ifc["status"] != "connected":
            continue

        err_total = ifc["in_errors"] + ifc["out_errors"]
        if err_total > 100:
            severity = "critical" if err_total > 1000 else "warning"
            issues.append({
                "port": ifc["name"],
                "speed": ifc["speed_str"],
                "in_errors": ifc["in_errors"],
                "out_errors": ifc["out_errors"],
                "in_discards": ifc["in_discards"],
                "out_discards": ifc["out_discards"],
                "severity": severity,
                "diagnosis": _diagnose_duplex(ifc),
                "fix": _fix_duplex(ifc),
            })

    return _json({
        "issues": issues,
        "total_issues": len(issues),
        "clean": len(issues) == 0,
    })


def _diagnose_duplex(ifc):
    """تشخيص مشكلة Duplex (دالة مساعدة)"""
    parts = []
    if ifc["in_errors"] > 100:
        parts.append("CRC errors مرتفعة — احتمال duplex mismatch أو كابل تالف")
    if ifc["out_errors"] > 50:
        parts.append("Output errors — احتمال congestion أو MTU mismatch")
    if ifc["in_discards"] > 50:
        parts.append("Input drops — buffer overflow أو traffic burst")
    return " | ".join(parts) if parts else "مشكلة غير محددة"


def _fix_duplex(ifc):
    """حلول مقترحة لمشكلة Duplex (دالة مساعدة)"""
    fixes = []
    if ifc["in_errors"] > 100:
        fixes.append("تحقق من duplex/speed على الطرفين (auto-auto أو full-full)")
        fixes.append("استبدل الكابل إذا استمرت المشكلة")
    if ifc["out_errors"] > 50:
        fixes.append("تحقق من MTU على الطرفين")
        fixes.append("فعّل QoS إذا كان الـ link مشغولاً")
    return fixes


@require_GET
def api_vlan_troubleshoot(request, switch_id):
    """
    GET /api/vlan/troubleshoot/<switch_id>/
    يحلل حالة VLANs الكاميرات والـ AP ويبين المشاكل.
    """
    sw = _get_switch_by_id(switch_id)
    vlans = get_vlans_full(sw.ip_address, sw.snmp_community)
    ifaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)

    port_traffic = {ifc["name"]: ifc for ifc in ifaces}

    CAMERA_KEYWORDS = ["camera", "cam", "cctv", "surveillance"]
    AP_KEYWORDS = ["ap", "wifi", "wireless", "wlan"]

    issues = []
    camera_vl = []
    ap_vl = []

    for v in vlans:
        name_lower = v["name"].lower()
        is_cam = any(k in name_lower for k in CAMERA_KEYWORDS) or v["vlan_id"] == 100
        is_ap = any(k in name_lower for k in AP_KEYWORDS)

        if is_cam:
            camera_vl.append(v)
        if is_ap:
            ap_vl.append(v)

        if not v["active"]:
            issues.append({
                "vlan_id": v["vlan_id"],
                "name": v["name"],
                "severity": "warning",
                "msg": f"VLAN {v['vlan_id']} ({v['name']}) غير نشط",
                "fix": "تأكد من تفعيل الـ VLAN: no shutdown على السويتش",
            })

        if v["port_count"] == 0:
            issues.append({
                "vlan_id": v["vlan_id"],
                "name": v["name"],
                "severity": "info",
                "msg": f"VLAN {v['vlan_id']} ({v['name']}) لا توجد منافذ مرتبطة",
                "fix": "تحقق من إعدادات access/trunk على المنافذ",
            })

        for port_name in v.get("port_names", []):
            ifc = port_traffic.get(port_name)
            if ifc and (ifc["in_errors"] + ifc["out_errors"]) > 100:
                issues.append({
                    "vlan_id": v["vlan_id"],
                    "name": v["name"],
                    "severity": "warning",
                    "msg": f"Port {port_name} (VLAN {v['vlan_id']}) — أخطاء عالية: in={ifc['in_errors']}, out={ifc['out_errors']}",
                    "fix": "تحقق من الكابل والـ duplex على هذا المنفذ",
                })

    return _json({
        "issues": issues,
        "camera_vlans": camera_vl,
        "ap_vlans": ap_vl,
        "total_issues": len(issues),
    })


# ============================================================
# 9. Port History APIs
# ============================================================

@require_GET
def api_port_timeline(request, switch_id, port_name):
    """جدول زمني لمنفذ واحد"""
    sw = get_object_or_404(Switch, id=switch_id)
    hours = int(request.GET.get("hours", 24))
    data = get_port_timeline(sw, port_name, hours)
    return JsonResponse(data, safe=False)


@require_GET
def api_switch_events(request, switch_id):
    """
    GET /api/history/events/<sw_id>/
    params: ?hours=24&severity=critical&event_type=link_down
    كل أحداث سويتش في نطاق زمني مع إمكانية الفلترة.
    """
    hours = int(request.GET.get("hours", 24))
    severity = request.GET.get("severity")
    event_type = request.GET.get("event_type")
    data = get_switch_events(_get_switch_by_id(switch_id), hours, severity, event_type)
    return _json(data)


@require_GET
def api_flap_report(request, switch_id):
    """
    GET /api/history/flaps/<sw_id>/
    params: ?hours=24
    تقرير المنافذ الأكثر flap مرتبة تنازلياً.
    """
    hours = int(request.GET.get("hours", 24))
    data = get_flap_report(_get_switch_by_id(switch_id), hours)
    return _json(data)


from core.services.port_history import (
    get_port_diagnostics,
    get_port_timeline,
)

def api_port_diagnostics(request, switch_id, port_name):
    """تشخيص شامل لمنفذ واحد"""
    sw = get_object_or_404(Switch, id=switch_id)
    data = get_port_diagnostics(sw, port_name)
    return JsonResponse(data, safe=False)


@require_GET
def api_all_ports_health(request, switch_id):
    """
    GET /api/history/health/<sw_id>/
    params: ?hours=24
    درجة صحة كل منافذ السويتش.
    """
    hours = int(request.GET.get("hours", 24))
    data = get_all_ports_health(_get_switch_by_id(switch_id), hours)
    return _json(data)


@require_GET
def api_anomaly(request, switch_id, port_name):
    """
    GET /api/history/anomaly/<sw_id>/<port>/
    params: ?hours=24
    يكتشف الشواذ الإحصائية في بيانات المنفذ.
    """
    hours = int(request.GET.get("hours", 24))
    data = get_anomaly_report(_get_switch_by_id(switch_id), port_name, hours)
    return _json(data)


@require_GET
def api_error_trend(request, switch_id, port_name):
    """
    GET /api/history/trend/<sw_id>/<port>/
    يحسب اتجاه الأخطاء: هل يزداد أم يقل؟
    """
    hours = int(request.GET.get("hours", 24))
    data = get_error_trend(_get_switch_by_id(switch_id), port_name, hours)
    return _json(data)


@require_GET
def api_traffic_baseline(request, switch_id, port_name):
    """
    GET /api/history/baseline/<sw_id>/<port>/
    params: ?days=7
    يحسب خط قاعدة الترافيك لآخر N أيام.
    """
    days = int(request.GET.get("days", 7))
    data = get_traffic_baseline(_get_switch_by_id(switch_id), port_name, days)
    return _json(data)


@require_GET
def api_history_summary(request, switch_id):
    """
    GET /api/history/summary/<sw_id>/
    ملخص شامل للوحة التشخيص الرئيسية.
    """
    sw = _get_switch_by_id(switch_id)
    hours = int(request.GET.get("hours", 24))

    events = get_switch_events(sw, hours)
    flaps = get_flap_report(sw, hours)
    health = get_all_ports_health(sw, hours)

    critical_ports = [p for p in health if p["severity"] == "critical"]
    warning_ports = [p for p in health if p["severity"] == "warning"]

    top_event = max(events["by_type"].items(), key=lambda x: x[1], default=("none", 0))

    return _json({
        "switch": sw.hostname,
        "hours": hours,
        "total_events": events["total"],
        "by_severity": events["by_severity"],
        "top_event_type": top_event[0],
        "top_event_count": top_event[1],
        "critical_ports": critical_ports[:5],
        "warning_ports": warning_ports[:5],
        "flapping_ports": flaps[:5],
        "top_ports": events["top_ports"][:5],
        "health_summary": {
            "critical": len(critical_ports),
            "warning": len(warning_ports),
            "ok": len([p for p in health if p["severity"] == "ok"]),
        },
    })
    
    
    
    
    
    ######################################################################
# core/views.py - أضف هذه الدوال في نهاية الملف

# ============================================================
# 10. Camera VLAN Analysis (VLAN 100 - Cameras)
# ============================================================

from core.services.camera_vlan_analyzer import analyze_camera_vlan


def camera_vlan_page(request):
    """
    صفحة تحليل كاميرات VLAN 100
    """
    from core.models import Switch, Location
    
    locations = Location.objects.annotate(
        switch_count=Count("switch")
    ).order_by("name")
    
    # جلب جميع السويتشات مع مواقعها للـ JavaScript
    switches = Switch.objects.select_related("location").order_by("location__name", "hostname")
    
    switches_data = []
    for sw in switches:
        switches_data.append({
            "id": sw.id,
            "hostname": sw.hostname,
            "ip_address": sw.ip_address,
            "location_id": sw.location.id if sw.location else None,
            "location_name": sw.location.name if sw.location else "Unknown",
        })
    
    return render(request, "dashboard/camera_vlan.html", {
        "locations": locations,
        "switches": switches,
        "switches_data": json.dumps(switches_data),
    })


@api_cache(timeout=30)
def api_camera_vlan_analysis(request, switch_id):
    """
    API لتحليل كاميرات VLAN 100
    
    GET /api/camera-vlan/<switch_id>/?hours=24
    
    Returns:
        {
            "switch": {...},
            "vlan_id": 100,
            "hours": 24,
            "cameras": [...],
            "summary": {...},
            "top_traffic": [...],
            "issues": [...]
        }
    """
    sw = get_object_or_404(Switch, id=switch_id)
    hours = int(request.GET.get("hours", 24))
    
    try:
        result = analyze_camera_vlan(sw, hours)
        return JsonResponse(result)
    except Exception as e:
        logger.error(f"Camera VLAN analysis failed for {sw.hostname}: {e}")
        return JsonResponse({"error": str(e)}, status=500)


@api_cache(timeout=60)
def api_camera_vlan_summary(request):
    """
    API لملخص كاميرات VLAN 100 عبر جميع السويتشات
    
    GET /api/camera-vlan/summary/
    
    Returns:
        {
            "total_cameras": 0,
            "total_switches_with_cameras": 0,
            "top_locations": [...],
            "global_issues": [...]
        }
    """
    from core.models import Switch
    from core.services.camera_vlan_analyzer import analyze_camera_vlan
    
    switches = Switch.objects.select_related("location").all()
    
    total_cameras = 0
    total_traffic = 0
    switches_with_cameras = 0
    all_issues = []
    location_stats = {}
    
    for sw in switches:
        try:
            result = analyze_camera_vlan(sw, hours=24)
            cameras = result.get("cameras", [])
            if cameras:
                switches_with_cameras += 1
                total_cameras += len(cameras)
                total_traffic += result.get("summary", {}).get("total_traffic_mbps", 0)
                
                # إحصائيات لكل موقع
                loc_name = sw.location.name if sw.location else "Unknown"
                if loc_name not in location_stats:
                    location_stats[loc_name] = {"cameras": 0, "issues": 0}
                location_stats[loc_name]["cameras"] += len(cameras)
                
                # جمع المشاكل
                for issue in result.get("issues", []):
                    issue["switch_hostname"] = sw.hostname
                    issue["location"] = loc_name
                    all_issues.append(issue)
                    location_stats[loc_name]["issues"] += 1
                    
        except Exception as e:
            logger.error(f"Summary failed for {sw.hostname}: {e}")
    
    # ترتيب المواقع حسب عدد الكاميرات
    top_locations = sorted(
        [{"name": k, "cameras": v["cameras"], "issues": v["issues"]} 
         for k, v in location_stats.items()],
        key=lambda x: x["cameras"],
        reverse=True
    )[:5]
    
    return JsonResponse({
        "total_cameras": total_cameras,
        "total_switches_with_cameras": switches_with_cameras,
        "total_traffic_mbps": round(total_traffic, 1),
        "top_locations": top_locations,
        "global_issues": all_issues[:20],  # آخر 20 مشكلة
        "generated_at": timezone.now().isoformat(),
    })


@api_cache(timeout=30)
def api_camera_vlan_export(request, switch_id):
    """
    تصدير بيانات كاميرات VLAN 100 بصيغة CSV
    
    GET /api/camera-vlan/export/<switch_id>/
    """
    import csv
    from django.http import HttpResponse
    
    sw = get_object_or_404(Switch, id=switch_id)
    hours = int(request.GET.get("hours", 24))
    
    result = analyze_camera_vlan(sw, hours)
    cameras = result.get("cameras", [])
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="camera_vlan_{sw.hostname}_{timezone.now().date()}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Port', 'Status', 'Health Score', 'Traffic (Mbps)', 
                     'In Errors', 'Out Errors', 'PoE Status', 'PoE Power (W)',
                     'IP Addresses', 'Manufacturer', 'Last Seen'])
    
    for cam in cameras:
        writer.writerow([
            cam.get('port', ''),
            cam.get('status', ''),
            cam.get('health_score', 0),
            cam.get('traffic_mbps', 0),
            cam.get('in_errors', 0),
            cam.get('out_errors', 0),
            cam.get('poe_status', ''),
            cam.get('poe_power_w', 0),
            ', '.join(cam.get('ip_addresses', [])),
            cam.get('manufacturer', ''),
            cam.get('last_seen', ''),
        ])
    
    return response



from core.services.camera_vlan_analyzer import analyze_camera_vlan

@api_cache(timeout=30)
def api_camera_vlan_analysis(request, switch_id):
    """
    API لتحليل كاميرات VLAN 100
    
    GET /api/camera-vlan/<switch_id>/?hours=24
    """
    sw = get_object_or_404(Switch, id=switch_id)
    hours = int(request.GET.get("hours", 24))
    
    try:
        result = analyze_camera_vlan(sw, hours)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)