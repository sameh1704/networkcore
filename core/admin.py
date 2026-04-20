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