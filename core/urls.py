from django.urls import path
from . import views




from django.urls import path
from . import views

from django.urls import path
from . import views

urlpatterns = [
    # Pages
    path("", views.dashboard_page, name="dashboard"),
    path("dashboard/", views.dashboard_page),
    path('location/<int:location_id>/', views.location_switches_page, name='location_switches'),
    path("switches/",  views.switches_page),
    path("topology/",  views.topology_page),
    path("switches/",  views.switches_page),
    path("topology/",  views.topology_page),
    path("discovery/", views.discovery_page, name="discovery"),

    # Switch detail
    path("network/switch/<str:hostname>/",
         views.switch_details, name="switch_details"),

    # Switch Inspector APIs
    path("api/switch/<str:hostname>/system/",     views.api_switch_system),
    path("api/switch/<str:hostname>/interfaces/", views.api_switch_interfaces),
    path("api/switch/<str:hostname>/errors/",     views.api_switch_errors),
    path("api/switch/<str:hostname>/cdp/",        views.api_switch_cdp),
    path("api/switch/<str:hostname>/poe/",        views.api_switch_poe),
    path("api/switch/<str:hostname>/portsec/",    views.api_switch_portsec),
    path("api/switch/<str:hostname>/mac/",        views.api_switch_mac),
    path("api/switch/<str:hostname>/ipbrief/",    views.api_switch_ipbrief),
    path("api/switch/<str:hostname>/tdr/",        views.api_switch_tdr),
    path("api/switch/<str:hostname>/vlans/",      views.api_switch_vlans),
    path("api/switch/<str:hostname>/env/",        views.api_switch_env),
    path("api/switch/<str:hostname>/stp/",        views.api_switch_stp),

    # Existing
    path("api/dashboard/",              views.dashboard_api),
    path("api/topology/",               views.topology_api),
    path("api/discover/",               views.auto_discovery_api),
    path("api/smart-discovery/",        views.smart_discovery_api),
    path("api/network-map/",            views.network_map_api),
    path("api/ai/",                     views.ai_insights),
    path("api/switch-ports/<str:ip>/",  views.switch_ports_api),



    # المسارات الجديدة للميزات المتقدمة
    path('api/switch/<str:hostname>/cable-estimate/', views.api_switch_cable_estimate, name='api_cable_estimate'),
    path('api/switch/<str:hostname>/loops/', views.api_switch_loops, name='api_loops'),
    path('api/switch/<str:hostname>/duplex/', views.api_switch_duplex, name='api_duplex'),
    path('api/switch/<str:hostname>/ai-diagnosis/', views.api_switch_ai_diagnosis, name='api_ai_diagnosis'),
    path('api/switch/<str:hostname>/predictions/', views.api_switch_predictions, name='api_predictions'),
    path('api/switch/<str:hostname>/health-report/', views.api_switch_health_report, name='api_health_report'),
    path('api/switch/<str:hostname>/clear-cache/', views.api_switch_clear_cache, name='api_clear_cache'),

   # أضف هذا السطر مع باقي مسارات API
    path("api/switch/<str:hostname>/vlans-debug/", views.api_switch_vlans_debug, name="api_vlans_debug"),

    path("api/switch/<str:hostname>/vlans-debug2/",
     views.api_switch_vlans_debug),
]
