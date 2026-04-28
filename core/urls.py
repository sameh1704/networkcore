# core/urls.py
"""
ملف تعريف المسارات (URLs) لتطبيق NOC Monitor
═══════════════════════════════════════════════════════════════

يحتوي على جميع مسارات التطبيق مقسمة حسب الوظيفة:
  1. صفحات الواجهة (Pages)
  2. واجهات API للداشبورد والتوبولوجيا
  3. واجهات API لاكتشاف الأجهزة
  4. واجهات API لتفاصيل السويتش (Switch Inspector)
  5. واجهات API للميزات المتقدمة
  6. واجهات API لـ MAC Tracker
  7. واجهات API لتاريخ المنافذ (Port History)
"""

from django.urls import path
from django.contrib.auth import views as auth_views
from . import views


# ═══════════════════════════════════════════════════════════════
# 1. صفحات الواجهة (Pages)
# ═══════════════════════════════════════════════════════════════

urlpatterns = [
    path("login/", auth_views.LoginView.as_view(template_name="dashboard/login.html", redirect_authenticated_user=True), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    # الصفحة الرئيسية للداشبورد
    path("", views.dashboard_page, name="dashboard"),
    path("dashboard/", views.dashboard_page, name="dashboard_alt"),
    path("topology/",  views.topology_page),
    path('topology/<int:location_id>/', views.topology_page, name='topology_location'),
    path('api/locations/', views.locations_api, name='locations_api'),
    path('api/switches/', views.switches_api, name='switches_api'),
    path('api/topology-links/', views.topology_links_api, name='topology_links_api'),
    # صفحة سويتشات موقع معين (باستخدام ID الموقع)
    path('location/<int:location_id>/', views.location_switches_page, name='location_switches'),
    
    # صفحة قائمة جميع السويتشات
    path("switches/", views.switches_page, name="switches"),
    
    # صفحة اكتشاف الأجهزة
    path("discovery/", views.discovery_page, name="discovery"),
    
    # صفحة تفاصيل سويتش واحد (FULL DETAILS)
    path("network/switch/<str:hostname>/", views.switch_details, name="switch_details"),
    
    # صفحة MAC Tracker (تتبع عناوين MAC)
    path('mac-tracker/', views.mac_tracker_page, name='mac_tracker_page'),
]

# ═══════════════════════════════════════════════════════════════
# 2. واجهات API للداشبورد والتوبولوجيا
# ═══════════════════════════════════════════════════════════════

urlpatterns += [
    # API لإحصائيات الداشبورد (عدد السويتشات والواجهات)
    path("api/dashboard/", views.dashboard_api, name="dashboard_api"),
    
    # API لإنشاء صورة التوبولوجيا
    path("api/topology/", views.topology_api, name="topology_api"),
    
    # API لخريطة الشبكة (Nodes + Links للرسم البياني)
    path("api/network-map/", views.network_map_api, name="network_map_api"),
    
    # API لحالة منافذ سويتش معين (باستخدام IP)
    path("api/switch-ports/<str:ip>/", views.switch_ports_api, name="switch_ports_api"),
    
    # API للتنبؤات الذكية باستخدام AI
    path("api/ai/", views.ai_insights, name="ai_insights"),
]

# ═══════════════════════════════════════════════════════════════
# 3. واجهات API لاكتشاف الأجهزة (Discovery)
# ═══════════════════════════════════════════════════════════════

urlpatterns += [
    # API للاكتشاف التلقائي (Auto Discovery) - يدعم GET و POST
    path("api/discover/", views.auto_discovery_api, name="auto_discovery_api"),
    
    # API للاكتشاف الذكي (Smart Discovery) - يبدأ من Seed IP
    path("api/smart-discovery/", views.smart_discovery_api, name="smart_discovery_api"),
]

# ═══════════════════════════════════════════════════════════════
# 4. واجهات API لتفاصيل السويتش (Switch Inspector)
#    تستخدم hostname كمعرّف
# ═══════════════════════════════════════════════════════════════

urlpatterns += [
    # معلومات النظام الأساسية (موديل، IOS، uptime، CPU، Memory)
    path("api/switch/<str:hostname>/system/", views.api_switch_system, name="api_switch_system"),
    
    # تفاصيل المنافذ (Interfaces) مع فلترة حسب الحالة
    path("api/switch/<str:hostname>/interfaces/", views.api_switch_interfaces, name="api_switch_interfaces"),
    
    # تحليل أخطاء المنافذ (CRC, Drops) مع توصيات
    path("api/switch/<str:hostname>/errors/", views.api_switch_errors, name="api_switch_errors"),
    
    # جيران CDP (Cisco Discovery Protocol)
    path("api/switch/<str:hostname>/cdp/", views.api_switch_cdp, name="api_switch_cdp"),
    
    # معلومات PoE (Power over Ethernet)
    path("api/switch/<str:hostname>/poe/", views.api_switch_poe, name="api_switch_poe"),
    
    # معلومات Port Security (أمان المنافذ)
    path("api/switch/<str:hostname>/portsec/", views.api_switch_portsec, name="api_switch_portsec"),
    
    # جدول MAC Addresses (مع دعم Pagination والفلترة)
    path("api/switch/<str:hostname>/mac/", views.api_switch_mac, name="api_switch_mac"),
    
    # IP Interface Brief (عناوين IP على الواجهات)
    path("api/switch/<str:hostname>/ipbrief/", views.api_switch_ipbrief, name="api_switch_ipbrief"),
    
    # نتائج TDR (اختبار كابلات)
    path("api/switch/<str:hostname>/tdr/", views.api_switch_tdr, name="api_switch_tdr"),
    
    # قائمة VLANs مع المنافذ المرتبطة
    path("api/switch/<str:hostname>/vlans/", views.api_switch_vlans, name="api_switch_vlans"),
    
    # معلومات البيئة (حرارة، مراوح، إمدادات طاقة)
    path("api/switch/<str:hostname>/env/", views.api_switch_env, name="api_switch_env"),
    
    # معلومات Spanning Tree Protocol (STP)
    path("api/switch/<str:hostname>/stp/", views.api_switch_stp, name="api_switch_stp"),
]

# ═══════════════════════════════════════════════════════════════
# 5. واجهات API للميزات المتقدمة (Advanced Features)
# ═══════════════════════════════════════════════════════════════

urlpatterns += [
    # تقدير طول الكابل بدون TDR (باستخدام قوة الإشارة)
    path('api/switch/<str:hostname>/cable-estimate/', views.api_switch_cable_estimate, name='api_cable_estimate'),
    
    # اكتشاف حلقات (Loops) في الشبكة عبر جدول MAC
    path('api/switch/<str:hostname>/loops/', views.api_switch_loops, name='api_loops'),
    
    # اكتشاف Duplex Mismatch (تضارب إعدادات duplex)
    path('api/switch/<str:hostname>/duplex/', views.api_switch_duplex, name='api_duplex'),
    
    # توقع الأعطال (Predictive Failure Analysis)
    path('api/switch/<str:hostname>/predictions/', views.api_switch_predictions, name='api_predictions'),
    
    # تقرير صحي شامل للسويتش
    path('api/switch/<str:hostname>/health-report/', views.api_switch_health_report, name='api_health_report'),
    
    # مسح التخزين المؤقت (Cache) لسويتش معين
    path('api/switch/<str:hostname>/clear-cache/', views.api_switch_clear_cache, name='api_clear_cache'),
    
    # نقطة تشخيص VLANs (تعرض البيانات الخام للتطوير والاختبار)
    path("api/switch/<str:hostname>/vlans-debug/", views.api_switch_vlans_debug, name="api_vlans_debug"),
]

# ═══════════════════════════════════════════════════════════════
# 6. واجهات API لـ MAC Tracker (تتبع عناوين MAC)
#    تستخدم switch_id كمعرّف (رقم)
# ═══════════════════════════════════════════════════════════════

urlpatterns += [
    # MAC Table لسويتش معين (مع Pagination والبحث)
    path('api/mac/<int:switch_id>/', views.api_mac_table, name='api_mac_table'),
    
    # بحث MAC في جميع السويتشات (Global Search)
    path('api/mac/search/', views.api_mac_search_global, name='api_mac_search_global'),
    
    # معلومات النظام الأساسية (لـ MAC Tracker)
    path('api/system/<int:switch_id>/', views.api_system_info, name='api_system_info'),
    
    # تفاصيل المنافذ (لـ MAC Tracker)
    path('api/interfaces/<int:switch_id>/', views.api_interfaces, name='api_interfaces'),
    
    # قائمة VLANs (لـ MAC Tracker)
    path('api/vlans/<int:switch_id>/', views.api_vlans, name='api_vlans'),
    
    # معلومات STP (لـ MAC Tracker)
    path('api/stp/<int:switch_id>/', views.api_stp, name='api_stp'),
    
    # معلومات PoE (لـ MAC Tracker)
    path('api/poe/<int:switch_id>/', views.api_poe, name='api_poe'),
    
    # جيران CDP (لـ MAC Tracker)
    path('api/cdp/<int:switch_id>/', views.api_cdp, name='api_cdp'),
    
    # معلومات Port Security (لـ MAC Tracker)
    path('api/port-security/<int:switch_id>/', views.api_port_security, name='api_port_security'),
    
    # معلومات البيئة (لـ MAC Tracker)
    path('api/environment/<int:switch_id>/', views.api_environment, name='api_environment'),
    
    # نتائج TDR (لـ MAC Tracker)
    path('api/tdr/<int:switch_id>/', views.api_tdr, name='api_tdr'),
    
    # IP Interface Brief (لـ MAC Tracker)
    path('api/ip/<int:switch_id>/', views.api_ip_brief, name='api_ip_brief'),
    
    # اختبار Ping (من السيرفر إلى أي IP)
    path('api/ping/', views.api_ping, name='api_ping'),
    
    # فحص اتصالية السويتش (SNMP + Ping)
    path('api/connectivity/<int:switch_id>/', views.api_connectivity, name='api_connectivity'),
    
    # تحليل Duplex/Speed (لـ MAC Tracker)
    path('api/duplex/<int:switch_id>/', views.api_duplex_analysis, name='api_duplex'),
    
    # استكشاف أخطاء VLANs (كاميرات - AP)
    path('api/vlan/troubleshoot/<int:switch_id>/', views.api_vlan_troubleshoot, name='api_vlan_troubleshoot'),
]

# ═══════════════════════════════════════════════════════════════
# 7. واجهات API لتاريخ المنافذ (Port History)
#    تستخدم switch_id كمعرّف و port_name كاسم المنفذ
# ═══════════════════════════════════════════════════════════════

urlpatterns += [
    # ملخص شامل للوحة التشخيص (إحصائيات عامة)
    path('api/history/summary/<int:switch_id>/', views.api_history_summary, name='api_history_summary'),
    
    # درجة صحة كل منافذ السويتش (Health Score 0-100)
    path('api/history/health/<int:switch_id>/', views.api_all_ports_health, name='api_all_ports_health'),
    
    # تقرير المنافذ الأكثر تقلباً (Flapping)
    path('api/history/flaps/<int:switch_id>/', views.api_flap_report, name='api_flap_report'),
    
    # قائمة أحداث السويتش (Link Down, CRC Spike, PoE Faults, etc.)
    path('api/history/events/<int:switch_id>/', views.api_switch_events, name='api_switch_events'),
    
    # جدول زمني لمنفذ واحد (Timeline with chart data)
    path('api/history/timeline/<int:switch_id>/<path:port_name>/', views.api_port_timeline, name='api_port_timeline'),
    # تشخيص شامل لمنفذ واحد (مشاكل + حلول مقترحة)
    path('api/history/diagnose/<int:switch_id>/<path:port_name>/', views.api_port_diagnostics, name='api_port_diagnostics'),
    
    
    

    
    # ============================================================
    # 8. Camera VLAN Analysis (صفحة مستقلة)
    # ============================================================
    
    # صفحة تحليل كاميرات VLAN 100
    path("camera-vlan/", views.camera_vlan_page, name="camera_vlan_page"),
    
    # API لتحليل كاميرات سويتش معين
    path("api/camera-vlan/<int:switch_id>/", views.api_camera_vlan_analysis, name="api_camera_vlan_analysis"),
    
    # API لملخص عام (اختياري)
    path("api/camera-vlan/summary/", views.api_camera_vlan_summary, name="api_camera_vlan_summary"),
    
    # API لتصدير البيانات (اختياري)
    path("api/camera-vlan/export/<int:switch_id>/", views.api_camera_vlan_export, name="api_camera_vlan_export"),

]