from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Switch, Interface, Location
from .services.auto_discovery import discover_network
from .services.smart_discovery import smart_discovery
from .services.topology_discovery import generate_topology


# ----------------------------
# Web Pages
# ----------------------------


from django.db.models import Count

from django.shortcuts import render, get_object_or_404
from django.db.models import Count
from core.models import Location, Switch
 
 
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
 
 
def location_switches_page(request, location_id):
    from django.core.serializers import serialize
    import json
    
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
        "switches_data": json.dumps(switches_data),  # ← أضف هذا
    })



def switches_page(request):

    switches = Switch.objects.all()

    return render(request, "dashboard/switches.html", {
        "switches": switches
    })


def topology_page(request):

    return render(request, "dashboard/topology.html")


# ----------------------------
# API
# ----------------------------

@api_view(["GET"])
def dashboard_api(request):

    switches = Switch.objects.count()
    interfaces = Interface.objects.count()

    return Response({
        "switches": switches,
        "interfaces": interfaces
    })


@api_view(["GET"])
def topology_api(request):

    switches = Switch.objects.all()

    path = generate_topology(switches)

    return Response({
        "topology_image": path
    })


# core/views.py
from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from core.services.auto_discovery import discover_network
from core.services.smart_discovery import smart_discovery
import logging

logger = logging.getLogger(__name__)

def discovery_page(request):
    return render(request, "dashboard/discovery.html")

import logging
logger = logging.getLogger(__name__)

@api_view(["GET", "POST"])
def auto_discovery_api(request):
    """
    يسكان ويحفظ في DB.
    POST body:
        network           : "192.168.70.0/24"
        community         : "private"
        extra_communities : ["public", "cisco"]   ← اختياري
    """
    from core.services.auto_discovery import discover_network

    if request.method == "POST":
        network           = request.data.get("network",   "192.168.70.0/24")
        community         = request.data.get("community", "private")
        extra_communities = request.data.get("extra_communities", [])
    else:
        network           = request.GET.get("network",   "192.168.70.0/24")
        community         = request.GET.get("community", "private")
        extra_communities = request.GET.getlist("extra_communities", [])

    logger.info(
        f"[Discovery] network={network} "
        f"community={community} "
        f"extras={extra_communities}"
    )

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
    from core.services.smart_discovery import smart_discovery

    if request.method == "POST":
        seed_ip           = request.data.get("seed_ip",   "192.168.70.1")
        community         = request.data.get("community", "private")
        extra_communities = request.data.get("extra_communities", [])
    else:
        seed_ip           = request.GET.get("seed_ip",   "192.168.70.1")
        community         = request.GET.get("community", "private")
        extra_communities = request.GET.getlist("extra_communities", [])

    result = smart_discovery(seed_ip, community)
    return Response({"discovered": result})

    
from .services.monitoring import get_interfaces
from .services.packet_loss import check_packet_loss
from .services.topology_discovery import build_topology


from django.core.cache import cache

from django.core.cache import cache
import random

import random
from django.db.models import Count

from django.core.cache import cache
import random

from django.core.cache import cache
import random
from .services.monitoring import get_vlans
from .services.topology_discovery import build_topology
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import Switch


@api_view(["GET"])
def network_map_api(request):

    # 🔥 cache لمدة 30 ثانية
    cached = cache.get("network_map")
    if cached:
        return Response(cached)

    switches = Switch.objects.all()

    nodes = []
    links = []
    node_ids = set()

    # -------------------------
    # Nodes
    # -------------------------
    for sw in switches:

        status = "online"

        # 🔥 VLANs
        try:
            vlans = get_vlans(sw.ip_address, sw.snmp_community)
            vlan_ids = [v["vlan_id"] for v in vlans]
        except:
            vlan_ids = []

        nodes.append({
            "id": sw.hostname,
            "ip": sw.ip_address,
            "status": status,
            "vlans": vlan_ids   # ✅ الجديد
        })

        node_ids.add(sw.hostname)

    # -------------------------
    # Links
    # -------------------------
    link_set = set()

    for sw in switches:

        topo = build_topology([sw])

        for link in topo:

            src = link["source"]
            dst = link["target"]

            # ❌ تجاهل أي جهاز ليس Switch
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

    # fallback
    if not links and len(nodes) > 1:
        for i in range(len(nodes) - 1):
            links.append({
                "source": nodes[i]["id"],
                "target": nodes[i+1]["id"],
                "traffic": random.randint(10, 100)
            })

    data = {"nodes": nodes, "links": links}

    cache.set("network_map", data, timeout=30)

    return Response(data)
    
from .services.predictive_ai import predict_cpu_crash

@api_view(["GET"])
def ai_insights(request):

    cpu_data = [20, 40, 60, 85, 90]

    result = predict_cpu_crash(cpu_data)

    return Response({
        "ai": result
    }) 

from .services.monitoring import get_ports_status

@api_view(["GET"])
def switch_ports_api(request, ip):

    ports = get_ports_status(ip, "public")

    return Response(ports)


from django.shortcuts import render, get_object_or_404
from core.models import Switch

def switch_details(request, hostname):
    sw = get_object_or_404(Switch, hostname=hostname)

    return render(request, "dashboard/switch_details.html", {
        "switch": sw
    })




# ══════════════════════════════════════════════════════════════
#  Switch Inspector API Views
#  كل دالة تُرجع JSON مباشرة للـ AJAX calls في صفحة التفاصيل
# ══════════════════════════════════════════════════════════════
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404

# core/views.py - النسخة الكاملة مع جميع الإضافات

import json
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_headers
from django.core.cache import cache
from functools import wraps

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
from core.services.predictive import (
    estimate_cable_length,
    detect_network_loops,
    check_stp_consistency,
    FailurePredictor,
    detect_duplex_mismatch,
)
from core.services.ai_engine import build_ai_diagnosis
from core.services.snmp import clear_cache

# core/views.py - أضف هذه الدالة

def api_switch_vlans_debug(request, hostname):
    """
    API لاختبار VLANات وعرض البيانات الخام للتشخيص
    """
    from core.models import Switch
    from core.services.switch_inspector import get_vlans_full
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
        result["if_names"] = if_names[:20]  # أول 20 منفذ
    except Exception as e:
        result["if_names_error"] = str(e)
    
    # اختبار OID_PORTMAP مباشرة
    try:
        from core.services.snmp import snmp_walk_with_index
        portmap_raw = snmp_walk_with_index(sw.ip_address, sw.snmp_community, "1.3.6.1.4.1.9.9.68.1.2.2.1.2")
        result["portmap_raw"] = portmap_raw[:20]  # أول 20 نتيجة
    except Exception as e:
        result["portmap_raw_error"] = str(e)
    
    return JsonResponse(result)
# ============================================
# Decorator للتخزين المؤقت في Django
# ============================================
def api_cache(timeout=30):
    """
    ديكوراتور للتخزين المؤقت لواجهات API
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # بناء مفتاح فريد لكل طلب
            cache_key = f"api:{request.path}:{request.GET.urlencode()}:{kwargs.get('hostname', '')}"
            
            # محاولة القراءة من cache
            cached_response = cache.get(cache_key)
            if cached_response:
                return cached_response
            
            # تنفيذ الـ view
            response = view_func(request, *args, **kwargs)
            
            # تخزين النتيجة في cache
            if response.status_code == 200:
                cache.set(cache_key, response, timeout)
            
            return response
        return wrapper
    return decorator


def _sw(hostname):
    from core.models import Switch
    return get_object_or_404(Switch, hostname=hostname)


def switch_details(request, hostname):
    from core.models import Switch
    sw = get_object_or_404(Switch, hostname=hostname)
    return render(request, "dashboard/switch_details.html", {"switch": sw})


# ============================================
# APIs الأساسية
# ============================================

@api_cache(timeout=30)
def api_switch_system(request, hostname):
    sw = _sw(hostname)
    try:
        d = get_system_info(sw.ip_address, sw.snmp_community)
    except Exception as e:
        d = {"error": str(e)}
    return JsonResponse(d)


@api_cache(timeout=30)
def api_switch_interfaces(request, hostname):
    sw = _sw(hostname)
    f = request.GET.get("status", "all")
    try:
        ifaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)
        if f == "connected":
            ifaces = [i for i in ifaces if i["status"] == "connected"]
        elif f == "notconnect":
            ifaces = [i for i in ifaces if i["status"] == "notconnect"]
        elif f == "disabled":
            ifaces = [i for i in ifaces if i["status"] == "disabled"]
        elif f == "err":
            ifaces = [i for i in ifaces if i["has_errors"]]
    except Exception as e:
        ifaces = []
    return JsonResponse({"interfaces": ifaces})


@api_cache(timeout=30)
def api_switch_errors(request, hostname):
    sw = _sw(hostname)
    try:
        ifaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)
        errors = get_error_analysis(ifaces)
    except Exception as e:
        errors = []
    return JsonResponse({"errors": errors})


@api_cache(timeout=60)
def api_switch_cdp(request, hostname):
    sw = _sw(hostname)
    try:
        d = get_cdp_neighbors(sw.ip_address, sw.snmp_community)
    except:
        d = []
    return JsonResponse({"neighbors": d})


@api_cache(timeout=30)
def api_switch_poe(request, hostname):
    sw = _sw(hostname)
    try:
        d = get_poe_detail(sw.ip_address, sw.snmp_community)
    except:
        d = {"ports": [], "total_w": 0, "consumed_w": 0, "available_w": 0, "faulty": []}
    return JsonResponse(d)


@api_cache(timeout=60)
def api_switch_portsec(request, hostname):
    sw = _sw(hostname)
    try:
        d = get_port_security(sw.ip_address, sw.snmp_community)
    except:
        d = {"enabled": False, "ports": [], "enabled_count": 0}
    return JsonResponse(d)


@api_cache(timeout=30)
def api_switch_mac(request, hostname):
    sw      = _sw(hostname)
    port    = request.GET.get("port", "").strip()
    page    = max(0, int(request.GET.get("page", "0")))
    limit   = min(500, max(10, int(request.GET.get("limit", "200"))))
    show_all= request.GET.get("all", "0") == "1"

    try:
        if show_all:
            limit = 5000
        d = get_mac_table(
            sw.ip_address,
            sw.snmp_community,
            limit=limit,
            offset_n=page * limit,
        )
        # فلتر بالمنفذ
        if port:
            d["mac_table"] = [
                m for m in d["mac_table"]
                if port.lower() in m["port"].lower()
            ]
            d["filtered_total"] = len(d["mac_table"])
    except Exception as e:
        d = {"mac_table": [], "total": 0,
             "offset": 0, "limit": limit, "error": str(e)}

    return JsonResponse(d)


@api_cache(timeout=60)
def api_switch_ipbrief(request, hostname):
    sw = _sw(hostname)
    try:
        d = get_ip_interfaces(sw.ip_address, sw.snmp_community)
    except:
        d = []
    return JsonResponse({"ip_interfaces": d})


@api_cache(timeout=120)
def api_switch_tdr(request, hostname):
    sw = _sw(hostname)
    try:
        d = get_tdr_results(sw.ip_address, sw.snmp_community)
    except:
        d = []
    return JsonResponse({"tdr": d})


@api_cache(timeout=60)
def api_switch_vlans(request, hostname):
    sw = _sw(hostname)
    try:
        d = get_vlans_full(sw.ip_address, sw.snmp_community)
        d = [v for v in d if v["port_count"] > 0 or v["active"]]
    except:
        d = []
    return JsonResponse({"vlans": d})


@api_cache(timeout=60)
def api_switch_env(request, hostname):
    sw = _sw(hostname)
    try:
        d = get_environment(sw.ip_address, sw.snmp_community)
    except:
        d = {"temperatures": [], "fans": [], "power_supplies": []}
    return JsonResponse(d)


@api_cache(timeout=60)
def api_switch_stp(request, hostname):
    sw = _sw(hostname)
    try:
        d = get_stp_info(sw.ip_address, sw.snmp_community)
    except:
        d = {"root_bridge": "", "ports": [], "blocking_count": 0, "forwarding_count": 0}
    return JsonResponse(d)


# ============================================
# APIs الجديدة: الميزات المتقدمة
# ============================================

@api_cache(timeout=30)
def api_switch_cable_estimate(request, hostname):
    """
    تقدير طول الكابل بدون TDR
    """
    sw = _sw(hostname)
    try:
        estimates = estimate_cable_length(sw.ip_address, sw.snmp_community)
        
        # إضافة تحليل صحة الكابلات
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
    """
    اكتشاف حلقات (Loops) في الشبكة
    """
    sw = _sw(hostname)
    try:
        # جلب جدول MAC للتحليل
        mac_data = get_mac_table(sw.ip_address, sw.snmp_community, limit=5000)
        
        # اكتشاف الـ Loops
        loops = detect_network_loops(sw.ip_address, sw.snmp_community, mac_data)
        
        # التحقق من STP
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
    """
    اكتشاف Duplex Mismatch
    """
    sw = _sw(hostname)
    try:
        mismatches = detect_duplex_mismatch(sw.ip_address, sw.snmp_community)
        return JsonResponse(mismatches)
    except Exception as e:
        return JsonResponse({'error': str(e), 'has_mismatch': False, 'mismatches': []})


@api_cache(timeout=60)
def api_switch_predictions(request, hostname):
    """
    توقع الأعطال (Failure Prediction)
    """
    sw = _sw(hostname)
    try:
        predictor = FailurePredictor(sw.ip_address, sw.snmp_community)
        
        # محاولة تحميل البيانات التاريخية
        try:
            from core.models import Errors
            predictor.load_history(Errors, days=30)
        except:
            pass
        
        predictions = predictor.get_full_prediction()
        
        # إضافة تقدير طول الكابل
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
            'cable_estimates': cable_estimates[:10],  # أول 10 منافذ فقط
            'risk_score': min(100, risk_score),
            'risk_level': risk_level,
            'timestamp': predictions['timestamp']
        })
    except Exception as e:
        return JsonResponse({'error': str(e), 'predictions': {}})


@api_cache(timeout=30)
def api_switch_ai_diagnosis(request, hostname):
    """
    تشخيص موحد للواجهة مع fallback بدل الاعتماد على الـ WebSocket فقط.
    """
    sw = _sw(hostname)
    try:
        system = get_system_info(sw.ip_address, sw.snmp_community)
        interfaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)
        errors = get_error_analysis(interfaces)
        poe = get_poe_detail(sw.ip_address, sw.snmp_community)
        loops = detect_network_loops(sw.ip_address, sw.snmp_community)
        duplex = detect_duplex_mismatch(sw.ip_address, sw.snmp_community)

        try:
            from core.models import Errors
            predictor = FailurePredictor(sw.ip_address, sw.snmp_community)
            predictor.load_history(Errors, days=30)
            predictions = predictor.get_full_prediction()
        except Exception:
            predictions = {}

        diagnosis = build_ai_diagnosis(
            system=system,
            interfaces=interfaces,
            errors=errors,
            loops=loops,
            duplex=duplex,
            poe=poe,
            predictions=predictions,
        )

        diagnosis.update({
            "hostname": sw.hostname,
            "timestamp": predictions.get("timestamp"),
        })
        return JsonResponse(diagnosis)
    except Exception as e:
        return JsonResponse({
            "error": str(e),
            "severity": "unknown",
            "root_cause": "تعذر إكمال التشخيص حالياً",
            "issues": [],
            "recommendations": [],
            "network_issues": [],
            "prediction_items": [],
        })


@api_cache(timeout=60)
def api_switch_health_report(request, hostname):
    """
    تقرير صحي شامل للسويتش
    """
    sw = _sw(hostname)
    try:
        # جمع جميع التحليلات
        system = get_system_info(sw.ip_address, sw.snmp_community)
        interfaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)
        errors = get_error_analysis(interfaces)
        poe = get_poe_detail(sw.ip_address, sw.snmp_community)
        loops = detect_network_loops(sw.ip_address, sw.snmp_community)
        duplex = detect_duplex_mismatch(sw.ip_address, sw.snmp_community)
        
        # إحصاءات سريعة
        total_ports = len(interfaces)
        up_ports = len([i for i in interfaces if i['status'] == 'connected'])
        error_ports = len([i for i in interfaces if i['has_errors']])
        
        # الحالة العامة
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
            'recommendations': generate_recommendations(system, errors, loops, duplex, poe)
        })
    except Exception as e:
        return JsonResponse({'error': str(e), 'overall_status': 'unknown'})


def generate_recommendations(system, errors, loops, duplex, poe):
    """
    توليد توصيات بناءً على التحليلات
    """
    recommendations = []
    
    # توصيات CPU
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
    
    # توصيات الأخطاء
    critical_errors = [e for e in errors if e['severity'] == 'critical']
    if critical_errors:
        recommendations.append({
            'severity': 'critical',
            'title': '🔴 أخطاء حرجة في المنافذ',
            'description': f'{len(critical_errors)} منفذ يعاني من أخطاء',
            'action': 'افحص الكابلات وإعدادات Duplex على المنافذ: ' + 
                      ', '.join([e['name'] for e in critical_errors[:3]])
        })
    
    # توصيات الـ Loops
    if loops.get('has_loop'):
        recommendations.append({
            'severity': 'critical',
            'title': '🔄 وجود Loop في الشبكة',
            'description': f'تم اكتشاف {loops.get("loop_count", 0)} حلقة محتملة',
            'action': 'افحص الكابلات المتكررة أو الأجهزة المتصلة بمنفذين'
        })
    
    # توصيات Duplex
    if duplex.get('has_mismatch'):
        recommendations.append({
            'severity': 'warning',
            'title': '⚡ Duplex Mismatch',
            'description': f'{duplex.get("count", 0)} منفذ يعمل بـ Half Duplex',
            'action': 'غيّر إعدادات الـ duplex إلى Auto أو Full على الطرفين'
        })
    
    # توصيات PoE
    if poe.get('faulty'):
        recommendations.append({
            'severity': 'warning',
            'title': '🔌 مشاكل في PoE',
            'description': f'{len(poe.get("faulty", []))} منفذ يعاني من مشاكل في الطاقة',
            'action': 'افحص الأجهزة المتصلة واستهلاك الطاقة'
        })
    
    # توصيات عامة
    if not recommendations:
        recommendations.append({
            'severity': 'good',
            'title': '✅ السويتش بحالة جيدة',
            'description': 'جميع المقاييس ضمن الحدود الطبيعية',
            'action': 'استمر في المراقبة الدورية'
        })
    
    return recommendations


@api_cache(timeout=30)
def api_switch_clear_cache(request, hostname):
    """
    مسح التخزين المؤقت لسويتش معين (للتحديث اليدوي)
    """
    sw = _sw(hostname)
    clear_cache(sw.ip_address)
    cache.clear()  # مسح cache Django أيضاً
    return JsonResponse({'status': 'success', 'message': f'Cache cleared for {hostname}'})



def api_switch_vlans_debug(request, hostname):
    """endpoint مؤقت للتشخيص"""
    from core.models import Switch
    from core.services.snmp import snmp_walk_with_index
    sw = get_object_or_404(Switch, hostname=hostname)

    # IF_NAME مع ifIndex الحقيقي
    if_name_idx = snmp_walk_with_index(
        sw.ip_address, sw.snmp_community,
        "1.3.6.1.2.1.31.1.1.1.1"
    ) or []

    # VM_VLAN مع ifIndex
    vm_vlan_idx = snmp_walk_with_index(
        sw.ip_address, sw.snmp_community,
        "1.3.6.1.4.1.9.9.68.1.2.2.1.2"
    ) or []

    # بناء الـ mapping
    ifidx2name = {s: v for s, v in if_name_idx}

    # أول 20 نتيجة لكل منهم
    return JsonResponse({
        "if_name_sample" : if_name_idx[:20],
        "vm_vlan_sample" : vm_vlan_idx[:20],
        "ifidx_mapping"  : {
            s: ifidx2name.get(s, "?")
            for s, _ in vm_vlan_idx[:20]
        },
    })
