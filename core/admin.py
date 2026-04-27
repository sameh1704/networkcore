from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import *

admin.site.register(Switch)
admin.site.register(Interface)
admin.site.register(VLAN)
admin.site.register(Traffic)
admin.site.register(Errors)
admin.site.register(MACTable)
admin.site.register(ARPTable)
admin.site.register(Event)
admin.site.register(Alert)
admin.site.register(Location)
admin.site.register(PortSnapshot)
admin.site.register(PortEvent)
admin.site.register(PortFlapCounter)

# Port Flapping Admin
@admin.register(PortFlapEvent)
class PortFlapEventAdmin(admin.ModelAdmin):
    list_display = ['switch', 'interface', 'from_status', 'to_status', 'timestamp', 'duration_seconds']
    list_filter = ['switch', 'interface', 'from_status', 'to_status']
    search_fields = ['switch__hostname', 'interface__name']
    date_hierarchy = 'timestamp'
    readonly_fields = ['timestamp']

@admin.register(PortFlapSummary)
class PortFlapSummaryAdmin(admin.ModelAdmin):
    list_display = ['switch', 'interface', 'period_start', 'period_end', 'flap_count', 'total_down_time', 'last_flap_time']
    list_filter = ['switch', 'interface']
    search_fields = ['switch__hostname', 'interface__name']
    date_hierarchy = 'period_end'
    readonly_fields = ['period_start', 'period_end']
