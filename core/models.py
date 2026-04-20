from django.db import models

# Create your models here.
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