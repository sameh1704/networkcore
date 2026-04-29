# core/tasks.py - النسخة النهائية (تجمع الأفضل من الملفين)

from celery import shared_task
from celery.utils.log import get_task_logger
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone
from django.db import connection
from datetime import timedelta
import shutil
from django.conf import settings
from core.models import Switch
from core.services.monitoring import get_cpu_usage
from core.services.ai_engine import analyze_network
from core.services.port_history import collect_port_snapshot

log = get_task_logger(__name__)

# ═══════════════════════════════════════════════════════════
#  إعدادات إدارة المساحة (قابلة للتعديل)
# ═══════════════════════════════════════════════════════════


# مراحل التخفيف
SNAPSHOT_FULL_HOURS   = getattr(settings, 'PORT_HISTORY_FULL_HOURS', 6)      # 6 ساعات تفصيل كامل
SNAPSHOT_MEDIUM_HOURS = getattr(settings, 'PORT_HISTORY_MEDIUM_HOURS', 24)   # 24 ساعة لقطة/30د
SNAPSHOT_LOW_DAYS     = getattr(settings, 'PORT_HISTORY_LOW_DAYS', 7)         # 7 أيام لقطة/ساعة
EVENTS_ONLY_DAYS      = getattr(settings, 'PORT_HISTORY_EVENTS_DAYS', 30)     # 30 يوم أحداث فقط

# حدود القرص
DISK_EMERGENCY_PCT = getattr(settings, 'PORT_HISTORY_DISK_EMERGENCY', 85)
DISK_PAUSE_PCT     = getattr(settings, 'PORT_HISTORY_DISK_PAUSE', 90)


def _get_disk_usage_pct(path: str = "/") -> float:
    """نسبة امتلاء القرص"""
    try:
        total, used, free = shutil.disk_usage(path)
        return (used / total) * 100
    except Exception:
        return 0.0


# ═══════════════════════════════════════════════════════════
#  1. WebSocket Broadcast (يعمل بشكل صحيح)
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
        {"type": "send_network_update", "data": data}
    )
    return f"Broadcasted {len(data)} switches"


# ═══════════════════════════════════════════════════════════
#  2. جمع لقطة سويتش واحد (مع فحص المساحة)
# ═══════════════════════════════════════════════════════════
@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def task_collect_port_snapshot(self, switch_id: int):
    """يُجمع لقطة لسويتش مع فحص المساحة أولاً"""
    
    disk_pct = _get_disk_usage_pct()
    
    # إذا كان القرص ممتلئاً، لا تجمع لقطات جديدة
    if disk_pct >= DISK_PAUSE_PCT:
        log.error(f"DISK FULL ({disk_pct:.1f}%) — Skipping snapshot")
        return {"status": "skipped", "reason": f"Disk {disk_pct:.1f}% full"}

    try:
        sw = Switch.objects.get(id=switch_id)
        count = collect_port_snapshot(sw)
        log.info(f"Snapshot: {sw.hostname} — {count} ports | disk {disk_pct:.1f}%")
        return {"switch": sw.hostname, "ports": count, "status": "success"}
    except Switch.DoesNotExist:
        log.error(f"Switch {switch_id} not found")
        return {"error": f"Switch {switch_id} not found", "status": "failed"}
    except Exception as exc:
        log.error(f"Snapshot failed for {switch_id}: {exc}")
        raise self.retry(exc=exc)


# ═══════════════════════════════════════════════════════════
#  3. جمع لقطات كل السويتشات
# ═══════════════════════════════════════════════════════════
@shared_task
def task_collect_all_snapshots():
    """جمع لقطات لكل السويتشات"""
    disk_pct = _get_disk_usage_pct()
    
    if disk_pct >= DISK_PAUSE_PCT:
        log.error(f"Disk {disk_pct:.1f}% — Snapshot collection PAUSED")
        return {"status": "paused", "disk_pct": disk_pct}

    switches = Switch.objects.all()
    if not switches:
        return {"status": "no_switches"}

    for sw in switches:
        task_collect_port_snapshot.delay(sw.id)

    log.info(f"Dispatched {switches.count()} snapshot tasks")
    return {"status": "dispatched", "count": switches.count(), "disk_pct": round(disk_pct, 1)}


# ═══════════════════════════════════════════════════════════
#  4. التنظيف الذكي (يمنع امتلاء المساحة)
# ═══════════════════════════════════════════════════════════
@shared_task
def cleanup_port_history_task():
    """
    تنظيف ذكي متعدد المراحل:
    - 6 ساعات: كل اللقطات (تفصيل كامل)
    - 6-24 ساعة: لقطة كل 30 دقيقة
    - 24 ساعة - 7 أيام: لقطة كل ساعة
    - أكثر من 7 أيام: حذف اللقطات (يبقى الأحداث)
    - أكثر من 30 يوم: حذف الأحداث
    """
    from core.models import PortSnapshot, PortEvent

    log.info("═══ Starting Smart Cleanup ═══")
    now = timezone.now()
    results = {}
    disk_before = _get_disk_usage_pct()

    # ── المرحلة 1: لقطات أقدم من 6 ساعات (تخفيف إلى لقطة/30د) ──
    older_than_6h = now - timedelta(hours=SNAPSHOT_FULL_HOURS)
    older_than_24h = now - timedelta(hours=SNAPSHOT_MEDIUM_HOURS)
    
    p1_deleted = _thin_snapshots(
        older_than=older_than_6h,
        newer_than=older_than_24h,
        keep_interval_minutes=30,
    )
    results["thinned_30min"] = p1_deleted
    log.info(f"Deleted {p1_deleted} snapshots (thinned to 30min resolution)")

    # ── المرحلة 2: لقطات أقدم من 24 ساعة (تخفيف إلى لقطة/ساعة) ──
    older_than_24h = now - timedelta(hours=SNAPSHOT_MEDIUM_HOURS)
    older_than_7d = now - timedelta(days=SNAPSHOT_LOW_DAYS)
    
    p2_deleted = _thin_snapshots(
        older_than=older_than_24h,
        newer_than=older_than_7d,
        keep_interval_minutes=60,
    )
    results["thinned_1hour"] = p2_deleted
    log.info(f"Deleted {p2_deleted} snapshots (thinned to 1hour resolution)")

    # ── المرحلة 3: حذف اللقطات الأقدم من 7 أيام ───────────────
    cutoff_7d = now - timedelta(days=SNAPSHOT_LOW_DAYS)
    p3_deleted = PortSnapshot.objects.filter(recorded_at__lt=cutoff_7d).delete()[0]
    results["snapshots_deleted_7d"] = p3_deleted
    log.info(f"Deleted {p3_deleted} snapshots older than 7 days")

    # ── المرحلة 4: حذف الأحداث الأقدم من 30 يوماً ─────────────
    cutoff_30d = now - timedelta(days=EVENTS_ONLY_DAYS)
    p4_deleted = PortEvent.objects.filter(occurred_at__lt=cutoff_30d).delete()[0]
    results["events_deleted_30d"] = p4_deleted
    log.info(f"Deleted {p4_deleted} events older than 30 days")

    # ── المرحلة الطارئة: إذا كان القرص لا يزال ممتلئاً ────────
    disk_after = _get_disk_usage_pct()
    if disk_after >= DISK_EMERGENCY_PCT:
        log.warning(f"Disk still {disk_after:.1f}% — running emergency cleanup")
        cutoff_48h = now - timedelta(hours=48)
        emergency_deleted = PortSnapshot.objects.filter(recorded_at__lt=cutoff_48h).delete()[0]
        results["emergency_deleted"] = emergency_deleted
        disk_after = _get_disk_usage_pct()

    results["disk_before"] = round(disk_before, 1)
    results["disk_after"] = round(disk_after, 1)
    results["total_deleted"] = sum(v for v in results.values() if isinstance(v, int))

    log.info(f"═══ Cleanup Done: {results['total_deleted']} deleted | "
             f"Disk: {disk_before:.1f}% → {disk_after:.1f}% ═══")
    return results


def _thin_snapshots(older_than, newer_than, keep_interval_minutes: int) -> int:
    """تخفيف اللقطات بين نطاقين زمنيين"""
    from core.models import PortSnapshot

    total_deleted = 0
    
    ports = PortSnapshot.objects.filter(
        recorded_at__range=(newer_than, older_than)
    ).values_list("switch_id", "port_name").distinct()

    for switch_id, port_name in ports:
        snaps = list(PortSnapshot.objects.filter(
            switch_id=switch_id,
            port_name=port_name,
            recorded_at__range=(newer_than, older_than),
        ).order_by("recorded_at").values("id", "recorded_at"))

        if len(snaps) <= 1:
            continue

        # تحديد اللقطات المراد الاحتفاظ بها
        ids_to_keep = set()
        last_kept_time = None

        for snap in snaps:
            if last_kept_time is None:
                ids_to_keep.add(snap["id"])
                last_kept_time = snap["recorded_at"]
            else:
                diff = (snap["recorded_at"] - last_kept_time).total_seconds() / 60
                if diff >= keep_interval_minutes:
                    ids_to_keep.add(snap["id"])
                    last_kept_time = snap["recorded_at"]

        to_delete = {s["id"] for s in snaps} - ids_to_keep
        if to_delete:
            deleted, _ = PortSnapshot.objects.filter(id__in=to_delete).delete()
            total_deleted += deleted

    return total_deleted


# ═══════════════════════════════════════════════════════════
#  5. مهمة احتياطية لمرة واحدة (اختيارية)
# ═══════════════════════════════════════════════════════════
@shared_task
def task_initial_history_populate():
    """ملء أولي للبيانات (للاستخدام عند التثبيت لأول مرة فقط)"""
    switches = Switch.objects.all()
    results = []
    
    for sw in switches:
        try:
            count = collect_port_snapshot(sw)
            results.append({"switch": sw.hostname, "ports": count, "status": "success"})
        except Exception as e:
            results.append({"switch": sw.hostname, "error": str(e), "status": "failed"})
    
    return {"results": results, "total": len(results)}