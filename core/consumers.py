# core/consumers.py

import json
import asyncio
import re
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from core.services.monitoring import (
    get_cpu_usage,
    get_interfaces,
    get_vlans,
    get_poe_status,
)
from core.services.ai_engine import analyze_network


class NetworkConsumer(AsyncWebsocketConsumer):

    async def connect(self): 
        await self.accept()
        while True:
            try:
                data = await self.get_data()
                await self.send(text_data=json.dumps({"data": data}))
            except Exception as e:
                await self.send(text_data=json.dumps({
                    "data": [], "error": str(e)
                }))
            await asyncio.sleep(5)

    async def disconnect(self, close_code):
        pass

    @sync_to_async
    def get_data(self):
        from core.models import Switch, Errors

        try:
            switches = list(Switch.objects.select_related('location').all())
        except Exception:
            return []

        result = []

        for sw in switches:

            try:
                cpu = get_cpu_usage(sw.ip_address, sw.snmp_community)
            except Exception:
                cpu = 0.0

            try:
                interfaces = get_interfaces(
                    sw.ip_address, sw.snmp_community
                ) or []
            except Exception:
                interfaces = []

            try:
                vlans = get_vlans(
                    sw.ip_address, sw.snmp_community
                ) or []
            except Exception:
                vlans = []

            try:
                poe_ports = get_poe_status(
                    sw.ip_address, sw.snmp_community
                ) or []
            except Exception:
                poe_ports = []

            poe_faults = [
                p for p in poe_ports
                if p.get("power_status") in ("fault", "deny")
            ]

            total_in  = sum(i.get("in",  0) for i in interfaces)
            total_out = sum(i.get("out", 0) for i in interfaces)
            traffic   = (total_in + total_out) // 1_000_000

            sorted_ifaces = sorted(
                interfaces,
                key=lambda x: x.get("in", 0) + x.get("out", 0),
                reverse=True
            )[:6]

            top_interfaces = [
                {
                    "name"        : i.get("name", ""),
                    "traffic_mbps": (
                        i.get("in", 0) + i.get("out", 0)
                    ) // 1_000_000,
                    "status"      : i.get("status", "down"),
                }
                for i in sorted_ifaces
            ]

            sw_status = (
                "critical" if cpu >= 90 else
                "warning"  if cpu >= 70 else
                "online"
            )

            # بناء all_ports بالأسماء الفعلية
            all_ports = _build_all_ports(
                interfaces, poe_ports, vlans, sw_status
            )

            try:
                errors_qs   = Errors.objects.filter(
                    interface__switch=sw
                ).order_by("-timestamp")[:20]
                crc_total   = sum(e.crc_errors   for e in errors_qs)
                drops_total = sum(e.output_drops for e in errors_qs)
            except Exception:
                crc_total   = 0
                drops_total = 0

            try:
                ai = analyze_network(
                    crc=crc_total, cpu=cpu,
                    traffic_mbps=traffic, drops=drops_total,
                    interfaces=interfaces, poe_faults=poe_faults,
                )
            except Exception:
                ai = {
                    "severity": "ok",
                    "root_cause": "لا يوجد مشاكل",
                    "issues": [], "recommendations": [],
                    "alert": False,
                }

            # ═══════════════════════════════════════════════════════════
            # 🔥 إضافة location و location_id (المطلوب لفلترة المواقع)
            # ═══════════════════════════════════════════════════════════
            result.append({
                "hostname"      : sw.hostname,
                "ip"            : sw.ip_address,
                "location"      : sw.location.name if sw.location else "Unknown",
                "location_id"   : sw.location.id if sw.location else None,
                "cpu"           : cpu,
                "status"        : sw_status,
                "traffic"       : traffic,
                "crc"           : crc_total,
                "drops"         : drops_total,
                "top_interfaces": top_interfaces,
                "all_ports"     : all_ports,
                "vlans"         : vlans,
                "poe_ports"     : poe_ports,
                "poe_faults"    : poe_faults,
                "ai"            : ai,
            })

        return result


# ══════════════════════════════════════════════════════════════
# _build_all_ports - بناء قائمة المنافذ مع ربط VLAN الصحيح
# ══════════════════════════════════════════════════════════════

def _build_all_ports(interfaces, poe_ports, vlans, sw_status="online"):
    """
    بناء قائمة المنافذ الفعلية فقط (Fa/Gi/Te) مرتبة.
    يربط كل منفذ بالـ VLAN الخاص به عبر port_names.
    """
    PHYSICAL_RE = re.compile(r'^(Fa|Gi|Te|Eth|Fast|Gig|Ten)', re.IGNORECASE)
    
    # فلتر المنافذ الفعلية
    physical = [
        ifc for ifc in interfaces
        if PHYSICAL_RE.match(str(ifc.get("name", "")))
    ]
    
    # بناء port_name → vlan info
    name2vlan = {}
    for v in vlans:
        for pname in v.get("port_names", []):
            if pname not in name2vlan:  # أول VLAN فقط (access port)
                name2vlan[pname] = {
                    "id": v["vlan_id"],
                    "name": v["name"],
                }
    
    # PoE faults
    poe_fault_names = set()
    for p in poe_ports:
        if p.get("power_status") in ("fault", "deny"):
            poe_fault_names.add(str(p.get("port", "")))
    
    result = []
    for i, ifc in enumerate(physical):
        name = ifc.get("name", f"Port{i+1}")
        
        # تحديد الحالة
        if sw_status == "offline":
            status = "down"
        elif name in poe_fault_names:
            status = "err"
        elif ifc.get("status") == "up":
            mbps = (ifc.get("in", 0) + ifc.get("out", 0)) // 1_000_000
            if mbps > 800:
                status = "err"
            elif mbps > 300:
                status = "wrn"
            else:
                status = "up"
        else:
            status = "down"
        
        mbps = (ifc.get("in", 0) + ifc.get("out", 0)) // 1_000_000
        vlan_info = name2vlan.get(name, {})
        
        result.append({
            "port": i + 1,
            "name": name,
            "status": status,
            "traffic_mbps": mbps,
            "in_octets": ifc.get("in", 0),
            "out_octets": ifc.get("out", 0),
            "vlan_id": vlan_info.get("id"),
            "vlan_name": vlan_info.get("name"),
        })
    
    return result[:48]