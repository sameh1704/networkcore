from celery import shared_task
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from core.models import Switch
from core.services.monitoring import get_cpu_usage
from core.services.ai_engine import analyze_network


@shared_task
def broadcast_network():

    channel_layer = get_channel_layer()

    switches = Switch.objects.all()

    data = []

    for sw in switches:

        cpu = get_cpu_usage(sw.ip_address, sw.snmp_community)

        # 🔥 AI Analysis
        issues = analyze_network(
            crc=120,        # لاحقاً من DB
            cpu=cpu,
            broadcast=6000  # لاحقاً من SNMP
        )

        data.append({
            "hostname": sw.hostname,
            "ip": sw.ip_address,
            "cpu": cpu,
            "status": "online" if cpu < 90 else "warning",
            "ai": issues   # ✅ الجديد
        })

    async_to_sync(channel_layer.group_send)(
        "network",
        {
            "type": "send_network_update",
            "data": data
        }
    )