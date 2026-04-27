# core/tasks.py

from celery import shared_task
from celery.utils.log import get_task_logger
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone
from datetime import timedelta

from core.models import Switch
from core.services.monitoring import get_cpu_usage
from core.services.ai_engine import analyze_network
from core.services.port_history import collect_port_snapshot, cleanup_old_data

log = get_task_logger(__name__)


# ═══════════════════════════════════════════════════════════
#  المهمة الأصلية (WebSocket broadcast) - مصححة
# ═══════════════════════════════════════════════════════════
@shared_task
def broadcast_network():
    """بث بيانات الشبكة عبر WebSocket"""
    channel_layer = get_channel_layer()
    switches = Switch.objects.all()
    data = []

    for sw in switches:
        try:
            cpu = get_cpu_usage(sw.ip_address, sw.snmp_community)
        except Exception:
            cpu = 0.0

        # ✅ تصحيح: analyze_network لا تقبل broadcast
        # تمرر القيم الصحيحة فقط
        issues = analyze_network(
            crc=120,
            cpu=cpu,
            traffic_mbps=0,
            drops=0,
            interfaces=[],
            poe_faults=[],
        )

        data.append({
            "hostname": sw.hostname,
            "ip": sw.ip_address,
            "cpu": cpu,
            "status": "online" if cpu < 90 else "warning",
            "ai": issues
        })

    async_to_sync(channel_layer.group_send)(
        "network",
        {
            "type": "send_network_update",
            "data": data
        }
    )
    return f"Broadcasted {len(data)} switches"


# ═══════════════════════════════════════════════════════════
#  مهام Port History
# ═══════════════════════════════════════════════════════════
@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def task_collect_port_snapshot(self, switch_id: int):
    """يُجمع لقطة لسويتش واحد — يُجدول كل 5 دقائق."""
    try:
        sw = Switch.objects.get(id=switch_id)
        count = collect_port_snapshot(sw)
        log.info(f"Snapshot collected: {sw.hostname} — {count} ports")
        return {"switch": sw.hostname, "ports": count, "status": "success"}
    except Switch.DoesNotExist:
        log.error(f"Switch {switch_id} not found")
        return {"error": f"Switch {switch_id} not found", "status": "failed"}
    except Exception as exc:
        log.error(f"Snapshot failed for {switch_id}: {exc}")
        raise self.retry(exc=exc)


@shared_task
def task_collect_all_snapshots():
    """يُجمع لقطات لكل السويتشات — يُجدول كل 5 دقائق."""
    switches = Switch.objects.all()
    if not switches:
        log.warning("No switches found to collect snapshots")
        return "No switches found"
    
    for sw in switches:
        task_collect_port_snapshot.delay(sw.id)
    
    log.info(f"Dispatched {switches.count()} snapshot tasks")
    return f"Dispatched {switches.count()} snapshot tasks"


@shared_task
def task_cleanup_history():
    """تنظيف البيانات القديمة — يُشغَّل يومياً."""
    result = cleanup_old_data()
    log.info(f"Cleanup done: {result}")
    return result


# ═══════════════════════════════════════════════════════════
#  مهمة اختيارية: تشغيل يدوي لملء البيانات الأولية
# ═══════════════════════════════════════════════════════════
@shared_task
def task_initial_history_populate():
    """تشغيل لمرة واحدة لملء البيانات التاريخية للمنافذ."""
    switches = Switch.objects.all()
    results = []
    
    for sw in switches:
        try:
            count = collect_port_snapshot(sw)
            results.append({"switch": sw.hostname, "ports": count, "status": "success"})
            log.info(f"Initial snapshot for {sw.hostname}: {count} ports")
        except Exception as e:
            results.append({"switch": sw.hostname, "error": str(e), "status": "failed"})
            log.error(f"Initial snapshot failed for {sw.hostname}: {e}")
    
    return {"results": results, "total": len(results)}