from django.db import models






class Location(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name
    
class Switch(models.Model):

    hostname = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(unique=True)
    location = models.ForeignKey(Location, on_delete=models.CASCADE, null=True, blank=True)

    model = models.CharField(max_length=100, blank=True)
    ios_version = models.CharField(max_length=100, blank=True)
    serial_number = models.CharField(max_length=100, blank=True)

    snmp_community = models.CharField(max_length=50, default="public")

    total_poe_power = models.FloatField(default=0)

    cpu_usage = models.FloatField(default=0)
    memory_usage = models.FloatField(default=0)

    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.hostname


class VLAN(models.Model):

    switch = models.ForeignKey(Switch, on_delete=models.CASCADE)
    vlan_id = models.IntegerField()
    name = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.vlan_id} - {self.name}"


class Interface(models.Model):

    switch = models.ForeignKey(Switch, on_delete=models.CASCADE)

    name = models.CharField(max_length=50)

    status = models.BooleanField(default=False)

    speed = models.IntegerField(default=0)

    duplex = models.CharField(max_length=20, blank=True)

    vlan = models.IntegerField(default=1)

    poe_power = models.FloatField(default=0)

    def __str__(self):
        return f"{self.switch.hostname} {self.name}"


class Traffic(models.Model):

    interface = models.ForeignKey(Interface, on_delete=models.CASCADE)

    in_octets = models.BigIntegerField(default=0)

    out_octets = models.BigIntegerField(default=0)

    timestamp = models.DateTimeField(auto_now_add=True)


class Errors(models.Model):

    interface = models.ForeignKey(Interface, on_delete=models.CASCADE)

    crc_errors = models.IntegerField(default=0)

    input_errors = models.IntegerField(default=0)

    output_drops = models.IntegerField(default=0)

    timestamp = models.DateTimeField(auto_now_add=True)


class MACTable(models.Model):

    switch = models.ForeignKey(Switch, on_delete=models.CASCADE)

    mac_address = models.CharField(max_length=20)

    interface = models.CharField(max_length=50)

    vlan = models.IntegerField()


class ARPTable(models.Model):

    switch = models.ForeignKey(Switch, on_delete=models.CASCADE)

    ip_address = models.GenericIPAddressField()

    mac_address = models.CharField(max_length=20)

    vlan = models.IntegerField()


class Event(models.Model):

    switch = models.ForeignKey(Switch, on_delete=models.CASCADE)

    event_type = models.CharField(max_length=100)

    message = models.TextField()

    timestamp = models.DateTimeField(auto_now_add=True)


class Alert(models.Model):

    switch = models.ForeignKey(Switch, on_delete=models.CASCADE)

    severity = models.CharField(max_length=20)

    message = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)


# Port Flapping Models
class PortFlapEvent(models.Model):
    """تسجيل أحداث تغير حالة المنفذ (Up/Down)"""
    switch = models.ForeignKey(Switch, on_delete=models.CASCADE)
    interface = models.ForeignKey(Interface, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    from_status = models.CharField(max_length=10)  # up/down
    to_status = models.CharField(max_length=10)    # up/down
    duration_seconds = models.IntegerField(default=0)  # مدة الحالة السابقة
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['switch', 'interface', '-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.switch.hostname} {self.interface.name}: {self.from_status} -> {self.to_status}"


class PortFlapSummary(models.Model):
    """ملخص تغيرات المنفذ خلال فترة زمنية"""
    switch = models.ForeignKey(Switch, on_delete=models.CASCADE)
    interface = models.ForeignKey(Interface, on_delete=models.CASCADE)
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    flap_count = models.IntegerField(default=0)
    total_down_time = models.IntegerField(default=0)  # بالثواني
    last_flap_time = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        unique_together = ['switch', 'interface', 'period_start', 'period_end']
        ordering = ['-period_end']
    
    def __str__(self):
        return f"{self.switch.hostname} {self.interface.name}: {self.flap_count} flaps"
#######################################################################################
# أضف هذه النماذج في core/models.py
# ═══════════════════════════════════════════════════════════════
#  Port Event Models  — سجل أحداث المنافذ
# ═══════════════════════════════════════════════════════════════

from django.db import models
from django.utils import timezone


class PortSnapshot(models.Model):
    """
    لقطة دورية لحالة كل منفذ — تُحفظ كل N دقائق عبر Celery.
    هي الأساس الذي يُبنى عليه كل التحليل التاريخي.
    """
    switch      = models.ForeignKey("Switch", on_delete=models.CASCADE, related_name="port_snapshots")
    port_name   = models.CharField(max_length=64, db_index=True)
    recorded_at = models.DateTimeField(default=timezone.now, db_index=True)

    # حالة المنفذ
    oper_status  = models.CharField(max_length=16)   # connected / notconnect / disabled
    admin_status = models.CharField(max_length=16)   # enabled / disabled
    speed_bps    = models.BigIntegerField(default=0)

    # حركة البيانات
    in_octets    = models.BigIntegerField(default=0)
    out_octets   = models.BigIntegerField(default=0)
    in_errors    = models.BigIntegerField(default=0)
    out_errors   = models.BigIntegerField(default=0)
    in_discards  = models.BigIntegerField(default=0)
    out_discards = models.BigIntegerField(default=0)

    # PoE
    poe_status   = models.CharField(max_length=16, blank=True)
    poe_power_mw = models.IntegerField(default=0)

    # VLAN
    vlan_id      = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ["-recorded_at"]
        indexes  = [
            models.Index(fields=["switch", "port_name", "recorded_at"]),
        ]

    def __str__(self):
        return f"{self.switch.hostname}/{self.port_name} @ {self.recorded_at:%H:%M:%S}"


class PortEvent(models.Model):
    """
    حدث محدد على منفذ: flap، خطأ، تغيير VLAN، PoE fault …
    يُولَّد تلقائياً من مقارنة اللقطات المتتالية.
    """

    EVENT_TYPES = [
        # الاتصال
        ("link_down",       "Link Down"),
        ("link_up",         "Link Up"),
        ("flap",            "Port Flap (down+up)"),
        # الأخطاء
        ("crc_spike",       "CRC Error Spike"),
        ("drop_spike",      "Drop Spike"),
        ("error_clear",     "Errors Cleared"),
        # الأداء
        ("traffic_surge",   "Traffic Surge"),
        ("traffic_drop",    "Traffic Drop"),
        ("speed_change",    "Speed Change"),
        # PoE
        ("poe_fault",       "PoE Fault"),
        ("poe_recovered",   "PoE Recovered"),
        ("poe_overload",    "PoE Overload"),
        # VLAN
        ("vlan_change",     "VLAN Change"),
        ("vlan_mismatch",   "VLAN Mismatch"),
        # STP
        ("stp_blocking",    "STP Blocking"),
        ("stp_forwarding",  "STP Forwarding"),
        # إدارية
        ("admin_down",      "Admin Shutdown"),
        ("admin_up",        "Admin Enabled"),
    ]

    SEVERITY = [
        ("critical", "Critical"),
        ("warning",  "Warning"),
        ("info",     "Info"),
        ("ok",       "OK / Recovered"),
    ]

    switch      = models.ForeignKey("Switch", on_delete=models.CASCADE, related_name="port_events")
    port_name   = models.CharField(max_length=64, db_index=True)
    event_type  = models.CharField(max_length=32, choices=EVENT_TYPES, db_index=True)
    severity    = models.CharField(max_length=16, choices=SEVERITY, default="info")
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)

    # تفاصيل الحدث
    description  = models.TextField(blank=True)
    old_value    = models.CharField(max_length=128, blank=True)
    new_value    = models.CharField(max_length=128, blank=True)

    # بيانات إضافية (JSON)
    extra        = models.JSONField(default=dict, blank=True)

    # تم إرسال تنبيه؟
    alerted      = models.BooleanField(default=False)

    class Meta:
        ordering = ["-occurred_at"]
        indexes  = [
            models.Index(fields=["switch", "port_name", "occurred_at"]),
            models.Index(fields=["switch", "event_type", "occurred_at"]),
            models.Index(fields=["severity", "occurred_at"]),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.switch.hostname}/{self.port_name}: {self.event_type}"


class PortFlapCounter(models.Model):
    """
    عداد مُجمَّع لعدد مرات flap كل منفذ خلال فترة زمنية.
    يُحدَّث تلقائياً عند كل flap event.
    """
    switch      = models.ForeignKey("Switch", on_delete=models.CASCADE, related_name="flap_counters")
    port_name   = models.CharField(max_length=64)
    window_start= models.DateTimeField(db_index=True)   # بداية الفترة (أول كل ساعة)
    window_end  = models.DateTimeField()
    flap_count  = models.IntegerField(default=0)
    down_count  = models.IntegerField(default=0)

    class Meta:
        unique_together = ["switch", "port_name", "window_start"]
        ordering = ["-window_start"]

