# core/services/port_history.py
"""
Port History & Diagnostics Service — النسخة المحسنة
═══════════════════════════════════════════════════════════════
المهام:
  1. collect_port_snapshot()  — يُشغَّل كل 5 دقائق عبر Celery
  2. detect_events()          — يقارن لقطتين ويُنشئ أحداث
  3. get_port_timeline()      — جدول زمني لمنفذ واحد
  4. get_switch_events()      — كل أحداث سويتش في نطاق زمني
  5. get_flap_report()        — تقرير المنافذ الأكثر flap
  6. get_port_diagnostics()   — تشخيص شامل لمنفذ واحد
  7. get_all_ports_health()   — درجة صحة كل المنافذ
  8. get_anomaly_report()     — كشف الشواذ الإحصائية
  9. get_error_trend()        — اتجاه الأخطاء عبر الزمن
  10. get_traffic_baseline()  — خط قاعدة الترافيك الطبيعي
  11. cleanup_old_snapshots() — تنظيف البيانات القديمة
  12. get_ifindex_mapping()   — دعم السويتشات الـ Stack
"""

from __future__ import annotations
import statistics
import logging
from datetime import timedelta, datetime
from django.utils import timezone
from django.db.models import Avg, Max, Min, Sum, Count, Q, F
from django.core.cache import cache

from core.models import Switch, PortSnapshot, PortEvent, PortFlapCounter
from core.services.switch_inspector import (
    get_interfaces_detail,
    get_poe_detail,
    get_vlans_full,
    get_stp_info,
    _get_if_names,  # للحصول على ifIndex الحقيقي
)

log = logging.getLogger(__name__)

# ── Constants (قابلة للتخصيص عبر Django settings) ───────────
from django.conf import settings

SNAPSHOT_TTL_DAYS  = getattr(settings, 'PORT_HISTORY_SNAPSHOT_TTL_DAYS', 30)
EVENT_TTL_DAYS     = getattr(settings, 'PORT_HISTORY_EVENT_TTL_DAYS', 90)
FLAP_THRESHOLD     = getattr(settings, 'PORT_HISTORY_FLAP_THRESHOLD', 3)
FLAP_CRITICAL      = getattr(settings, 'PORT_HISTORY_FLAP_CRITICAL', 10)
CRC_SPIKE_DELTA    = getattr(settings, 'PORT_HISTORY_CRC_SPIKE_DELTA', 100)
DROP_SPIKE_DELTA   = getattr(settings, 'PORT_HISTORY_DROP_SPIKE_DELTA', 50)
TRAFFIC_SURGE_PCT  = getattr(settings, 'PORT_HISTORY_TRAFFIC_SURGE_PCT', 200)
TRAFFIC_DROP_PCT   = getattr(settings, 'PORT_HISTORY_TRAFFIC_DROP_PCT', 80)
MIN_SAMPLES        = getattr(settings, 'PORT_HISTORY_MIN_SAMPLES', 4)


# ═══════════════════════════════════════════════════════════
#  0. Helper: ifIndex Mapping (للسويتشات الـ Stack)
# ═══════════════════════════════════════════════════════════
def _get_ifindex_to_port_name(switch: Switch) -> dict:
    """
    يُعيد mapping من ifIndex الحقيقي إلى اسم المنفذ.
    مهم جداً للسويتشات الـ Stack (ifIndex يبدأ من 10101).
    """
    cache_key = f"ifindex_map_{switch.id}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    try:
        if_names = _get_if_names(switch.ip_address, switch.snmp_community)
        result = {str(idx + 1): name for idx, name in enumerate(if_names)}
        cache.set(cache_key, result, timeout=300)  # 5 دقائق
        return result
    except Exception as e:
        log.warning(f"ifIndex mapping failed for {switch.hostname}: {e}")
        return {}


# ═══════════════════════════════════════════════════════════
#  1. Collect Snapshot (محسن لدعم ifIndex)
# ═══════════════════════════════════════════════════════════
def collect_port_snapshot(switch: Switch) -> int:
    """يجمع لقطة حالية لجميع منافذ السويتش ويحفظها."""
    try:
        ip = switch.ip_address
        com = switch.snmp_community
        now = timezone.now()

        ifaces = get_interfaces_detail(ip, com) or []
        if not ifaces:
            log.warning(f"No interfaces found for {switch.hostname}")
            return 0

        poe_d = get_poe_detail(ip, com) or {}
        vlan_d = get_vlans_full(ip, com) or []

        # بناء خرائط سريعة
        poe_map = {p["port"]: p for p in poe_d.get("ports", [])}
        vlan_map = {}
        for v in vlan_d:
            for pname in v.get("port_names", []):
                vlan_map[pname] = v["vlan_id"]

        snapshots = []
        for ifc in ifaces:
            port_name = ifc["name"]
            poe = poe_map.get(port_name, {})

            snapshots.append(PortSnapshot(
                switch=switch,
                port_name=port_name,
                recorded_at=now,
                oper_status=ifc["status"],
                admin_status="enabled" if ifc.get("admin", 1) == 1 else "disabled",
                speed_bps=ifc.get("speed_bps", 0),
                in_octets=ifc.get("in_octets", 0),
                out_octets=ifc.get("out_octets", 0),
                in_errors=ifc.get("in_errors", 0),
                out_errors=ifc.get("out_errors", 0),
                in_discards=ifc.get("in_discards", 0),
                out_discards=ifc.get("out_discards", 0),
                poe_status=poe.get("status", ""),
                poe_power_mw=poe.get("power_mw", 0),
                vlan_id=vlan_map.get(port_name),
            ))

        if snapshots:
            PortSnapshot.objects.bulk_create(snapshots)
            # تشغيل كشف الأحداث مقارنةً باللقطة السابقة
            _detect_events_for_switch(switch, now)

        return len(snapshots)

    except Exception as e:
        log.error(f"collect_port_snapshot({switch.hostname}): {e}")
        return 0


# ═══════════════════════════════════════════════════════════
#  2. Event Detection (محسن بمنع التكرار وحساب الـ traffic rate)
# ═══════════════════════════════════════════════════════════
def _detect_events_for_switch(switch: Switch, now: datetime):
    """يقارن آخر لقطتين لكل منفذ ويُنشئ أحداث PortEvent مع منع التكرار."""

    # الحصول على آخر لقطة قبل هذه للحصول على الـ time delta
    previous_snapshot = (
        PortSnapshot.objects
        .filter(switch=switch, recorded_at__lt=now)
        .order_by("-recorded_at")
        .first()
    )

    if not previous_snapshot:
        return

    time_delta_seconds = (now - previous_snapshot.recorded_at).total_seconds()
    if time_delta_seconds <= 0:
        time_delta_seconds = 300  # افتراضي 5 دقائق

    # آخر لقطتين لكل منفذ
    recent = (
        PortSnapshot.objects
        .filter(switch=switch, recorded_at__gte=now - timedelta(minutes=20))
        .order_by("port_name", "-recorded_at")
    )

    # تجميع آخر لقطتين لكل منفذ
    port_pairs: dict[str, list[PortSnapshot]] = {}
    for snap in recent:
        lst = port_pairs.setdefault(snap.port_name, [])
        if len(lst) < 2:
            lst.append(snap)

    # التحقق من الأحداث المسجلة حديثاً لتجنب التكرار
    last_event_time = {}
    last_event = (
        PortEvent.objects
        .filter(switch=switch)
        .order_by("-occurred_at")
        .first()
    )
    if last_event:
        last_event_time = {last_event.port_name: last_event.occurred_at}

    events_to_create = []
    flap_updates = {}

    for port_name, pair in port_pairs.items():
        if len(pair) < 2:
            continue

        curr, prev = pair[0], pair[1]  # curr = أحدث

        # منع التكرار في نفس الثانية
        skip = False
        if port_name in last_event_time:
            diff = (curr.recorded_at - last_event_time[port_name]).total_seconds()
            if diff < 30:  # نفس الحدث خلال 30 ثانية
                skip = True

        if skip:
            continue

        # ── Link Down ────────────────────────────────────────
        if prev.oper_status == "connected" and curr.oper_status == "notconnect":
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="link_down", severity="warning",
                occurred_at=curr.recorded_at,
                description=f"المنفذ {port_name} انقطع عن الشبكة",
                old_value="connected", new_value="notconnect",
            ))
            flap_updates[port_name] = flap_updates.get(port_name, 0) + 1

        # ── Link Up ──────────────────────────────────────────
        elif prev.oper_status != "connected" and curr.oper_status == "connected":
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="link_up", severity="ok",
                occurred_at=curr.recorded_at,
                description=f"المنفذ {port_name} عاد للعمل",
                old_value=prev.oper_status, new_value="connected",
            ))

        # ── Admin Down ───────────────────────────────────────
        if prev.admin_status == "enabled" and curr.admin_status == "disabled":
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="admin_down", severity="info",
                occurred_at=curr.recorded_at,
                description=f"تم إيقاف المنفذ {port_name} يدوياً (shutdown)",
                old_value="enabled", new_value="disabled",
            ))
        elif prev.admin_status == "disabled" and curr.admin_status == "enabled":
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="admin_up", severity="info",
                occurred_at=curr.recorded_at,
                description=f"تم تفعيل المنفذ {port_name} (no shutdown)",
                old_value="disabled", new_value="enabled",
            ))

        # ── CRC Spike (محسوب كنسبة زيادة) ────────────────────
        crc_delta = (curr.in_errors - prev.in_errors) + (curr.out_errors - prev.out_errors)
        if crc_delta > CRC_SPIKE_DELTA:
            crc_rate = crc_delta / time_delta_seconds
            sev = "critical" if crc_delta > 1000 else "warning"
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="crc_spike", severity=sev,
                occurred_at=curr.recorded_at,
                description=f"ارتفاع مفاجئ في أخطاء CRC: +{crc_delta} خطأ ({crc_rate:.1f}/sec)",
                new_value=str(crc_delta),
                extra={
                    "in_err": curr.in_errors,
                    "out_err": curr.out_errors,
                    "delta": crc_delta,
                    "rate_per_sec": round(crc_rate, 2),
                },
            ))

        # ── Drop Spike ───────────────────────────────────────
        drop_delta = (curr.in_discards - prev.in_discards) + (curr.out_discards - prev.out_discards)
        if drop_delta > DROP_SPIKE_DELTA:
            drop_rate = drop_delta / time_delta_seconds
            sev = "critical" if drop_delta > 500 else "warning"
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="drop_spike", severity=sev,
                occurred_at=curr.recorded_at,
                description=f"ارتفاع في الـ Drops: +{drop_delta} ({drop_rate:.1f}/sec)",
                new_value=str(drop_delta),
                extra={
                    "in_disc": curr.in_discards,
                    "out_disc": curr.out_discards,
                    "delta": drop_delta,
                    "rate_per_sec": round(drop_rate, 2),
                },
            ))

        # ── Traffic Rate و Surge/Drop ────────────────────────
        prev_traffic = prev.in_octets + prev.out_octets
        curr_traffic = curr.in_octets + curr.out_octets

        if prev_traffic > 0:
            traffic_rate = (curr_traffic - prev_traffic) / time_delta_seconds / 1_000_000  # Mbps
            change_pct = (curr_traffic - prev_traffic) / prev_traffic * 100

            if change_pct > TRAFFIC_SURGE_PCT and curr_traffic > 10_000_000:
                events_to_create.append(PortEvent(
                    switch=switch, port_name=port_name,
                    event_type="traffic_surge", severity="warning",
                    occurred_at=curr.recorded_at,
                    description=f"ارتفاع مفاجئ في الترافيك: +{change_pct:.0f}% ({traffic_rate:.1f} Mbps)",
                    extra={"change_pct": round(change_pct, 1), "rate_mbps": round(traffic_rate, 1)},
                ))
            elif change_pct < -TRAFFIC_DROP_PCT and prev_traffic > 1_000_000:
                events_to_create.append(PortEvent(
                    switch=switch, port_name=port_name,
                    event_type="traffic_drop", severity="info",
                    occurred_at=curr.recorded_at,
                    description=f"انخفاض حاد في الترافيك: {change_pct:.0f}%",
                    extra={"change_pct": round(change_pct, 1)},
                ))

        # ── Speed Change ─────────────────────────────────────
        if prev.speed_bps and curr.speed_bps and prev.speed_bps != curr.speed_bps:
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="speed_change", severity="warning",
                occurred_at=curr.recorded_at,
                description=f"تغير سرعة المنفذ: {_fmt_speed(prev.speed_bps)} → {_fmt_speed(curr.speed_bps)}",
                old_value=_fmt_speed(prev.speed_bps),
                new_value=_fmt_speed(curr.speed_bps),
            ))

        # ── VLAN Change ──────────────────────────────────────
        if prev.vlan_id != curr.vlan_id:
            if prev.vlan_id is None or curr.vlan_id is None:
                continue
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="vlan_change", severity="warning",
                occurred_at=curr.recorded_at,
                description=f"تغير VLAN من {prev.vlan_id} إلى {curr.vlan_id}",
                old_value=str(prev.vlan_id),
                new_value=str(curr.vlan_id),
            ))

        # ── PoE Fault ────────────────────────────────────────
        prev_bad = prev.poe_status in ("fault", "deny")
        curr_bad = curr.poe_status in ("fault", "deny")

        if not prev_bad and curr_bad:
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="poe_fault", severity="critical",
                occurred_at=curr.recorded_at,
                description=f"عطل PoE على المنفذ {port_name}: {curr.poe_status}",
                new_value=curr.poe_status,
                extra={"power_mw": curr.poe_power_mw},
            ))
        elif prev_bad and not curr_bad and curr.poe_status == "on":
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="poe_recovered", severity="ok",
                occurred_at=curr.recorded_at,
                description=f"استعاد المنفذ {port_name} طاقة PoE",
                old_value=prev.poe_status,
                new_value=curr.poe_status,
            ))

        # ── PoE Overload ─────────────────────────────────────
        if curr.poe_power_mw > 30000:  # أكثر من 30W
            events_to_create.append(PortEvent(
                switch=switch, port_name=port_name,
                event_type="poe_overload", severity="warning",
                occurred_at=curr.recorded_at,
                description=f"استهلاك PoE مرتفع: {curr.poe_power_mw/1000:.1f}W",
                extra={"power_mw": curr.poe_power_mw},
            ))

    # حفظ دفعة
    if events_to_create:
        PortEvent.objects.bulk_create(events_to_create)

    # تحديث عدادات flap
    _update_flap_counters(switch, flap_updates, now)


def _update_flap_counters(switch: Switch, flap_map: dict, now: datetime):
    """تحديث عدادات الـ flap لكل منفذ."""
    window_start = now.replace(minute=0, second=0, microsecond=0)
    window_end = window_start + timedelta(hours=1)

    for port_name, count in flap_map.items():
        obj, _ = PortFlapCounter.objects.get_or_create(
            switch=switch, port_name=port_name, window_start=window_start,
            defaults={"window_end": window_end, "flap_count": 0, "down_count": 0},
        )
        obj.down_count += count
        obj.flap_count += count
        obj.save(update_fields=["down_count", "flap_count"])


def _fmt_speed(bps: int) -> str:
    """تنسيق السرعة (bps) إلى نص مقروء."""
    if not bps:
        return "—"
    if bps >= 1_000_000_000:
        return f"{bps // 1_000_000_000}G"
    if bps >= 1_000_000:
        return f"{bps // 1_000_000}M"
    if bps >= 1_000:
        return f"{bps // 1_000}K"
    return str(bps)


# ═══════════════════════════════════════════════════════════
#  3. Port Timeline
# ═══════════════════════════════════════════════════════════
def get_port_timeline(switch: Switch, port_name: str, hours: int = 24) -> dict:
    """جدول زمني كامل لمنفذ واحد خلال الـ N ساعة الماضية."""
    since = timezone.now() - timedelta(hours=hours)

    events = (
        PortEvent.objects
        .filter(switch=switch, port_name=port_name, occurred_at__gte=since)
        .order_by("-occurred_at")
        .values("event_type", "severity", "occurred_at",
                "description", "old_value", "new_value", "extra")
    )

    snapshots = (
        PortSnapshot.objects
        .filter(switch=switch, port_name=port_name, recorded_at__gte=since)
        .order_by("recorded_at")
        .values("recorded_at", "oper_status", "in_errors", "out_errors",
                "in_discards", "out_discards", "in_octets", "out_octets",
                "poe_power_mw", "poe_status", "vlan_id", "speed_bps")
    )

    snap_list = list(snapshots)
    chart_data = _build_chart_series(snap_list)

    total_flaps = PortFlapCounter.objects.filter(
        switch=switch, port_name=port_name, window_start__gte=since
    ).aggregate(total=Sum("flap_count"))["total"] or 0

    ev_list = list(events)
    crc_events = sum(1 for e in ev_list if e["event_type"] == "crc_spike")
    drop_events = sum(1 for e in ev_list if e["event_type"] == "drop_spike")
    poe_faults = sum(1 for e in ev_list if e["event_type"] == "poe_fault")

    return {
        "port_name": port_name,
        "switch": switch.hostname,
        "hours": hours,
        "events": ev_list,
        "event_count": len(ev_list),
        "flap_count": total_flaps,
        "crc_events": crc_events,
        "drop_events": drop_events,
        "poe_faults": poe_faults,
        "chart": chart_data,
        "health_score": _calc_port_health(ev_list, total_flaps, snap_list),
    }


def _build_chart_series(snapshots: list) -> dict:
    """يبني سلاسل بيانية للمخططات."""
    labels, errors, drops, traffic, poe_power = [], [], [], [], []

    for i, s in enumerate(snapshots):
        labels.append(s["recorded_at"].strftime("%H:%M"))

        if i > 0:
            prev = snapshots[i - 1]
            err_delta = max(0, (s["in_errors"] + s["out_errors"]) -
                               (prev["in_errors"] + prev["out_errors"]))
            drop_delta = max(0, (s["in_discards"] + s["out_discards"]) -
                                 (prev["in_discards"] + prev["out_discards"]))
            tr_delta = max(0, (s["in_octets"] + s["out_octets"]) -
                               (prev["in_octets"] + prev["out_octets"]))
        else:
            err_delta = drop_delta = tr_delta = 0

        errors.append(err_delta)
        drops.append(drop_delta)
        traffic.append(tr_delta // 1_000_000)  # → Mbps
        poe_power.append(s["poe_power_mw"] / 1000)  # → Watts

    return {
        "labels": labels,
        "errors": errors,
        "drops": drops,
        "traffic": traffic,
        "poe_power": poe_power,
    }


# ═══════════════════════════════════════════════════════════
#  4. Switch Events Summary
# ═══════════════════════════════════════════════════════════
def get_switch_events(switch: Switch, hours: int = 24,
                      severity: str = None, event_type: str = None) -> dict:
    """كل أحداث سويتش في نطاق زمني مع إمكانية الفلترة."""
    since = timezone.now() - timedelta(hours=hours)
    qs = PortEvent.objects.filter(switch=switch, occurred_at__gte=since)

    if severity:
        qs = qs.filter(severity=severity)
    if event_type:
        qs = qs.filter(event_type=event_type)

    qs = qs.order_by("-occurred_at")

    events = list(qs.values(
        "port_name", "event_type", "severity",
        "occurred_at", "description", "old_value", "new_value", "extra",
    ))

    # إحصاءات
    by_type = {}
    by_severity = {}
    by_port = {}
    for e in events:
        by_type[e["event_type"]] = by_type.get(e["event_type"], 0) + 1
        by_severity[e["severity"]] = by_severity.get(e["severity"], 0) + 1
        by_port[e["port_name"]] = by_port.get(e["port_name"], 0) + 1

    top_ports = sorted(by_port.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "switch": switch.hostname,
        "hours": hours,
        "events": events,
        "total": len(events),
        "by_type": by_type,
        "by_severity": by_severity,
        "top_ports": top_ports,
    }


# ═══════════════════════════════════════════════════════════
#  5. Flap Report
# ═══════════════════════════════════════════════════════════
def get_flap_report(switch: Switch, hours: int = 24) -> list:
    """تقرير المنافذ الأكثر flap مرتبة تنازلياً."""
    since = timezone.now() - timedelta(hours=hours)

    # استخدام جدول PortEvent كمصدر أساسي لضمان دقة التقارير التاريخية
    event_stats = (
        PortEvent.objects
        .filter(switch=switch, event_type="link_down", occurred_at__gte=since)
        .values("port_name")
        .annotate(
            total_flaps=Count("id"),
            total_downs=Count("id"),
            last_flap=Max("occurred_at")
        )
        .order_by("-total_flaps")
    )

    result = []
    for r in event_stats:
        severity = (
            "critical" if r["total_flaps"] >= FLAP_CRITICAL else
            "warning" if r["total_flaps"] >= FLAP_THRESHOLD else
            "info"
        )
        hourly_rate = r["total_flaps"] / max(hours, 1)
        result.append({
            "port_name": r["port_name"],
            "total_flaps": r["total_flaps"],
            "total_downs": r["total_downs"],
            "last_flap": r["last_flap"],
            "severity": severity,
            "hourly_rate": round(hourly_rate, 2),
            "diagnosis": _diagnose_flap(r["total_flaps"], hourly_rate),
            "fix": _fix_flap(r["total_flaps"]),
        })

    return result


def _diagnose_flap(count: int, rate: float) -> str:
    """تشخيص سبب الـ flapping."""
    if rate > 5:
        return "Flapping شديد — كابل معطوب أو SFP فاشل أو مشكلة في الجهاز المتصل"
    if rate > 1:
        return "Flapping متوسط — تحقق من جودة الكابل أو إعدادات STP أو PoE"
    return "حالات انقطاع متفرقة — قد تكون بسبب صيانة أو إعادة تشغيل"


def _fix_flap(count: int) -> list:
    """حلول مقترحة لمشكلة الـ flapping."""
    fixes = ["🔌 تحقق من الكابل جسدياً واستبدله إذا كان قديماً أو مكسوراً"]
    if count > 5:
        fixes.append("🔧 افحص SFP/Transceiver وتأكد من نظافة الموصلات")
        fixes.append("⏱ فعّل 'carrier-delay' لتأخير حالات الـ flap السريعة")
    fixes.append("🌳 تحقق من Spanning Tree — قد يكون هناك Loop أو تكوين خاطئ")
    fixes.append("⚡ افحص الجهاز المتصل وتأكد من سلامة مصدر الطاقة (PoE أو محول)")
    return fixes


# ═══════════════════════════════════════════════════════════
#  6. Port Diagnostics (الشامل)
# ═══════════════════════════════════════════════════════════
def get_port_diagnostics(switch: Switch, port_name: str) -> dict:
    """تشخيص شامل لمنفذ واحد يجمع كل المعلومات."""
    now = timezone.now()
    h1 = now - timedelta(hours=1)
    h24 = now - timedelta(hours=24)
    h168 = now - timedelta(hours=168)  # 7 days

    def events_in(since, ev_type=None):
        qs = PortEvent.objects.filter(switch=switch, port_name=port_name, occurred_at__gte=since)
        if ev_type:
            qs = qs.filter(event_type=ev_type)
        return qs.count()

    flaps_1h = _flaps_in(switch, port_name, h1)
    flaps_24h = _flaps_in(switch, port_name, h24)
    flaps_7d = _flaps_in(switch, port_name, h168)

    crc_1h = events_in(h1, "crc_spike")
    crc_24h = events_in(h24, "crc_spike")
    drop_1h = events_in(h1, "drop_spike")
    drop_24h = events_in(h24, "drop_spike")
    poe_f = events_in(h24, "poe_fault")

    # آخر لقطة
    last_snap = (
        PortSnapshot.objects
        .filter(switch=switch, port_name=port_name)
        .order_by("-recorded_at").first()
    )

    calculations = {"total_time_seconds": 0}
    if last_snap:
        first_snap = (
            PortSnapshot.objects
            .filter(switch=switch, port_name=port_name)
            .order_by("recorded_at")
            .first()
        )
        if first_snap:
            calculations["total_time_seconds"] = (now - first_snap.recorded_at).total_seconds()

    diagnoses = _run_diagnostics(
        flaps_1h=flaps_1h, flaps_24h=flaps_24h,
        crc_1h=crc_1h, crc_24h=crc_24h,
        drop_1h=drop_1h, drop_24h=drop_24h,
        poe_faults=poe_f, last_snap=last_snap,
        calculations=calculations,
    )

    health = _calc_health_from_counters(flaps_24h, crc_24h, drop_24h, poe_f)

    recent_events = list(
        PortEvent.objects
        .filter(switch=switch, port_name=port_name, occurred_at__gte=h24)
        .order_by("-occurred_at")[:20]
        .values("event_type", "severity", "occurred_at", "description",
                "old_value", "new_value", "extra")
    )

    return {
        "port": port_name,
        "switch": switch.hostname,
        "health": health,
        "last_status": last_snap.oper_status if last_snap else "unknown",
        "last_seen": last_snap.recorded_at if last_snap else None,
        "counters": {
            "flaps_1h": flaps_1h, "flaps_24h": flaps_24h, "flaps_7d": flaps_7d,
            "crc_1h": crc_1h, "crc_24h": crc_24h,
            "drops_1h": drop_1h, "drops_24h": drop_24h,
            "poe_faults_24h": poe_f,
        },
        "diagnoses": diagnoses,
        "recent_events": recent_events,
    }


def _flaps_in(switch: Switch, port_name: str, since: datetime) -> int:
    """عدد مرات الـ flap في فترة زمنية."""
    return (
        PortFlapCounter.objects
        .filter(switch=switch, port_name=port_name, window_start__gte=since)
        .aggregate(total=Sum("flap_count"))["total"] or 0
    )


def _run_diagnostics(flaps_1h, flaps_24h, crc_1h, crc_24h,
                     drop_1h, drop_24h, poe_faults, last_snap, calculations) -> list:
    """يشغِّل مجموعة من القواعد التشخيصية ويُرجع قائمة النتائج."""
    results = []

    # ── قاعدة 1: Flapping متكرر ──────────────────────────
    if flaps_1h >= FLAP_CRITICAL:
        results.append({
            "severity": "critical",
            "category": "Link Stability",
            "title": f"⚠️ Flapping حرج: {flaps_1h} مرة في آخر ساعة",
            "detail": "المنفذ يفقد الاتصال بشكل متكرر جداً مما يؤثر على الخدمة",
            "causes": [
                "🔌 كابل تالف أو موصل مفكوك",
                "📡 SFP/Transceiver معطوب",
                "⚡ مشكلة في power supply الجهاز المتصل",
                "🌳 Spanning Tree Loop أو تكوين خاطئ",
            ],
            "fixes": _fix_flap(flaps_1h),
        })
    elif flaps_24h >= FLAP_THRESHOLD:
        results.append({
            "severity": "warning",
            "category": "Link Stability",
            "title": f"⚠️ Flapping متكرر: {flaps_24h} مرة في 24 ساعة",
            "detail": "المنفذ غير مستقر خلال اليوم الماضي، قد يؤثر على الأداء",
            "causes": [
                "🔌 كابل رديء الجودة أو طويل جداً (>80m)",
                "🔄 إعادة تشغيل متكررة للجهاز المتصل",
                "🌳 إعدادات STP غير صحيحة",
            ],
            "fixes": [
                "🔌 افحص الكابل وجرب استبداله بآخر معتمد Cat6",
                "🔧 تحقق من إعدادات STP: 'show spanning-tree interface'",
                "📋 راجع سجل الجهاز المتصل بحثاً عن أخطاء",
            ],
        })

    # ── قاعدة 2: CRC Errors ──────────────────────────────
    if crc_1h >= 3:
        results.append({
            "severity": "critical",
            "category": "Signal Quality",
            "title": f"⚠️ أخطاء CRC متكررة: {crc_1h} spike في آخر ساعة",
            "detail": "إشارة ضعيفة أو ضجيج كهربائي — يؤدي إلى إعادة إرسال البيانات وبطء الشبكة",
            "causes": [
                "📏 كابل طويل أو منهك (يتجاوز 100m للـ Cat5e/6)",
                "🔄 Duplex Mismatch — طرف على Full وآخر على Half",
                "⚡ تداخل كهرومغناطيسي (EMI) من مصادر طاقة قريبة",
                "🔌 SFP / Transceiver معطوب أو متسخ",
                "📎 موصل RJ45 تالف أو غير ثابت",
            ],
            "fixes": [
                "📏 تحقق من طول الكابل وحالته الفيزيائية",
                "🔧 اضبط duplex يدوياً: 'duplex full' و 'speed 1000'",
                "🧹 نظّف موصل SFP بإيثانول وأعد تركيبه",
                "🔌 استبدل الكابل بآخر معتمد Cat6",
                "📡 ابعد الكابل عن مصادر التيار الكهربائي",
            ],
        })
    elif crc_24h >= 5:
        results.append({
            "severity": "warning",
            "category": "Signal Quality",
            "title": f"⚠️ أخطاء CRC متراكمة: {crc_24h} spike في 24 ساعة",
            "detail": "جودة الإشارة تحتاج مراجعة — قد تتفاقم مع الوقت",
            "causes": ["🔌 كابل رديء الجودة", "🔄 احتمال Duplex Mismatch"],
            "fixes": [
                "🔌 افحص الكابل جسدياً وتأكد من سلامة الموصلات",
                "🔧 جرب 'auto-negotiate' على الطرفين أو حدد duplex يدوياً",
            ],
        })

    # ── قاعدة 3: Drop Spike ──────────────────────────────
    if drop_1h >= 3:
        results.append({
            "severity": "warning",
            "category": "Congestion",
            "title": f"⚠️ ازدحام شبكي: {drop_1h} drop-spike في آخر ساعة",
            "detail": "الـ buffer ممتلئ — حزم تُفقد بسبب الضغط الزائد على المنفذ",
            "causes": [
                "📡 bandwidth غير كافٍ للتطبيقات الجارية",
                "🎯 لا يوجد QoS — حركة المرور غير مُصنَّفة",
                "📹 جهاز متصل يُرسل burst كبير (كاميرا 4K بدون compression)",
                "📡 multicast flooding بسبب IGMP snooping غير مُفعَّل",
            ],
            "fixes": [
                "🎯 فعّل QoS وصنّف حركة المرور حسب الأولوية",
                "📡 فعّل IGMP Snooping لتقليل multicast flood",
                "🔌 رفع سرعة الـ uplink إذا كان الخط مشغولاً",
                "📹 راجع إعدادات الكاميرا وقلل البث إلى H.265",
                "🌪 فعّل 'storm-control' على المنفذ",
            ],
        })

    # ── قاعدة 4: Port Down مستمر ─────────────────────────
    if last_snap and last_snap.oper_status == "notconnect":
        results.append({
            "severity": "info",
            "category": "Connectivity",
            "title": "ℹ️ المنفذ غير متصل حالياً",
            "detail": "لا يوجد جهاز متصل أو الكابل مفصول أو الطرف الآخر مغلق",
            "causes": [
                "💻 لا يوجد جهاز متصل بهذا المنفذ",
                "🔌 كابل مفصول من أحد الطرفين",
                "🚫 المنفذ disabled من الجهاز الآخر (admin down)",
            ],
            "fixes": [
                "💻 تحقق من وجود جهاز متصل بهذا المنفذ",
                "🔌 اختبر الكابل بأداة cable tester",
                "🔧 تأكد من تفعيل المنفذ على الجهاز الآخر (no shutdown)",
            ],
        })

    # ── قاعدة 5: PoE Faults ──────────────────────────────
    if poe_faults >= 2:
        results.append({
            "severity": "critical" if poe_faults >= 5 else "warning",
            "category": "Power over Ethernet",
            "title": f"⚠️ أعطال PoE متكررة: {poe_faults} مرة في 24 ساعة",
            "detail": "الجهاز المتصل يعاني من مشاكل في الطاقة الكهربائية عبر PoE",
            "causes": [
                "⚡ تجاوز PoE budget للسويتش",
                "📡 جهاز PD (Powered Device) معطوب أو يستهلك أكثر من Class المحدد",
                "🔌 كابل غير معتمد للـ PoE (يحتاج الأزواج 4/5 و 7/8)",
                "🌡 درجة الحرارة العالية تُسبب thermal shutdown للمنفذ",
            ],
            "fixes": [
                "⚡ تحقق من PoE budget المتبقي: 'show power inline'",
                "🔧 حدد الـ Class المسموح: 'power inline max milli-watts 15400'",
                "🔌 استبدل الكابل بآخر معتمد PoE+",
                "🔌 وزّع الأحمال على PSU إضافي أو سويتش آخر",
            ],
        })

    # ── قاعدة 6: الحالة ممتازة ───────────────────────────
    if not results and last_snap and last_snap.oper_status == "connected":
        results.append({
            "severity": "ok",
            "category": "Health",
            "title": "✅ المنفذ يعمل بشكل طبيعي",
            "detail": "لم يتم اكتشاف أي مشاكل خلال الفترة المحددة",
            "causes": [],
            "fixes": [],
        })

    return results


def _calc_health_from_counters(flaps: int, crcs: int, drops: int, poe_faults: int) -> int:
    """درجة صحة المنفذ من 0 إلى 100."""
    score = 100
    score -= min(40, flaps * 5)
    score -= min(25, crcs * 5)
    score -= min(20, drops * 3)
    score -= min(15, poe_faults * 5)
    return max(0, score)


def _calc_port_health(events: list, flaps: int, snapshots: list) -> int:
    """درجة صحة المنفذ من الأحداث المجمعة."""
    crcs = sum(1 for e in events if e.get("event_type") == "crc_spike")
    drops = sum(1 for e in events if e.get("event_type") == "drop_spike")
    poe = sum(1 for e in events if e.get("event_type") == "poe_fault")
    return _calc_health_from_counters(flaps, crcs, drops, poe)


# ═══════════════════════════════════════════════════════════
#  7. All Ports Health
# ═══════════════════════════════════════════════════════════
def get_all_ports_health(switch: Switch, hours: int = 24) -> list:
    """يُعيد درجة صحة لكل منفذ في السويتش."""
    since = timezone.now() - timedelta(hours=hours)

    # جلب كل الأحداث دفعة واحدة
    events = list(
        PortEvent.objects
        .filter(switch=switch, occurred_at__gte=since)
        .values("port_name", "event_type")
    )
    flaps = list(
        PortFlapCounter.objects
        .filter(switch=switch, window_start__gte=since)
        .values("port_name")
        .annotate(total=Sum("flap_count"))
    )
    flap_map = {r["port_name"]: r["total"] for r in flaps}

    # تجميع حسب المنفذ
    by_port: dict[str, dict] = {}
    for e in events:
        p = e["port_name"]
        d = by_port.setdefault(p, {"crc": 0, "drops": 0, "poe": 0, "flaps": flap_map.get(p, 0)})
        if e["event_type"] == "crc_spike":
            d["crc"] += 1
        if e["event_type"] == "drop_spike":
            d["drops"] += 1
        if e["event_type"] == "poe_fault":
            d["poe"] += 1

    # آخر حالة لكل منفذ
    last_snaps = {}
    for snap in PortSnapshot.objects.filter(switch=switch).order_by("-recorded_at")[:200]:
        if snap.port_name not in last_snaps:
            last_snaps[snap.port_name] = snap

    result = []
    for port_name, d in by_port.items():
        health = _calc_health_from_counters(d["flaps"], d["crc"], d["drops"], d["poe"])
        snap = last_snaps.get(port_name)
        result.append({
            "port": port_name,
            "health": health,
            "status": snap.oper_status if snap else "unknown",
            "flaps": d["flaps"],
            "crc_events": d["crc"],
            "drop_events": d["drops"],
            "poe_faults": d["poe"],
            "severity": (
                "critical" if health < 40 else
                "warning" if health < 70 else
                "ok"
            ),
        })

    return sorted(result, key=lambda x: x["health"])


# ═══════════════════════════════════════════════════════════
#  8. Anomaly Detection
# ═══════════════════════════════════════════════════════════
def get_anomaly_report(switch: Switch, port_name: str, hours: int = 24) -> dict:
    """يكتشف الشواذ الإحصائية في بيانات المنفذ."""
    now = timezone.now()
    since = now - timedelta(hours=hours)
    prev = since - timedelta(hours=hours)

    def get_metrics(start, end):
        snaps = list(
            PortSnapshot.objects
            .filter(switch=switch, port_name=port_name,
                    recorded_at__range=(start, end))
            .values("in_errors", "out_errors", "in_discards", "out_discards",
                    "in_octets", "out_octets")
        )
        if not snaps or len(snaps) < MIN_SAMPLES:
            return None
        return {
            "avg_errors": statistics.mean(s["in_errors"] + s["out_errors"] for s in snaps),
            "avg_drops": statistics.mean(s["in_discards"] + s["out_discards"] for s in snaps),
            "avg_traffic": statistics.mean((s["in_octets"] + s["out_octets"]) // 1_000_000 for s in snaps),
            "max_errors": max(s["in_errors"] + s["out_errors"] for s in snaps),
            "samples": len(snaps),
        }

    current = get_metrics(since, now)
    baseline = get_metrics(prev, since)

    anomalies = []
    if current and baseline:
        if baseline["avg_errors"] > 0:
            ratio = current["avg_errors"] / baseline["avg_errors"]
            if ratio > 3:
                anomalies.append({
                    "type": "error_anomaly",
                    "severity": "critical" if ratio > 10 else "warning",
                    "msg": f"📈 أخطاء أعلى من المعتاد بمقدار {ratio:.1f}x",
                    "current": round(current["avg_errors"], 1),
                    "baseline": round(baseline["avg_errors"], 1),
                })

        if baseline["avg_traffic"] > 0:
            ratio = current["avg_traffic"] / baseline["avg_traffic"]
            if ratio > 3:
                anomalies.append({
                    "type": "traffic_anomaly",
                    "severity": "warning",
                    "msg": f"📊 ترافيك أعلى من المعتاد بمقدار {ratio:.1f}x",
                    "current": round(current["avg_traffic"], 1),
                    "baseline": round(baseline["avg_traffic"], 1),
                })
            elif ratio < 0.1 and baseline["avg_traffic"] > 10:
                anomalies.append({
                    "type": "traffic_absent",
                    "severity": "info",
                    "msg": "📉 انخفاض حاد في الترافيك — الجهاز قد يكون متوقفاً",
                    "current": round(current["avg_traffic"], 1),
                    "baseline": round(baseline["avg_traffic"], 1),
                })

    return {
        "port": port_name,
        "current": current,
        "baseline": baseline,
        "anomalies": anomalies,
        "has_anomaly": len(anomalies) > 0,
    }


# ═══════════════════════════════════════════════════════════
#  9. Error Trend
# ═══════════════════════════════════════════════════════════
def get_error_trend(switch: Switch, port_name: str, hours: int = 24) -> dict:
    """يحسب اتجاه الأخطاء: هل يزداد أم يقل؟"""
    since = timezone.now() - timedelta(hours=hours)
    snaps = list(
        PortSnapshot.objects
        .filter(switch=switch, port_name=port_name, recorded_at__gte=since)
        .order_by("recorded_at")
        .values("recorded_at", "in_errors", "out_errors", "in_discards", "out_discards")
    )

    if len(snaps) < MIN_SAMPLES:
        return {"trend": "insufficient_data", "direction": "unknown", "min_samples": MIN_SAMPLES}

    # حساب الفروقات
    deltas = []
    for i in range(1, len(snaps)):
        d = ((snaps[i]["in_errors"] + snaps[i]["out_errors"]) -
             (snaps[i - 1]["in_errors"] + snaps[i - 1]["out_errors"]))
        deltas.append(max(0, d))

    if not deltas:
        return {"trend": "no_data", "direction": "unknown"}

    # تحليل الاتجاه بمقارنة النصف الأول بالثاني
    mid = len(deltas) // 2
    first = statistics.mean(deltas[:mid]) if mid > 0 else 0
    last = statistics.mean(deltas[mid:]) if deltas[mid:] else 0

    if last > first * 1.5:
        direction, label = "increasing", "📈 متزايد ⚠️"
    elif last < first * 0.5:
        direction, label = "decreasing", "📉 متراجع ✓"
    else:
        direction, label = "stable", "➡️ مستقر"

    return {
        "trend": label,
        "direction": direction,
        "first_half_avg": round(first, 2),
        "last_half_avg": round(last, 2),
        "total_deltas": deltas,
        "peak": max(deltas),
        "avg": round(statistics.mean(deltas), 2),
    }


# ═══════════════════════════════════════════════════════════
#  10. Traffic Baseline
# ═══════════════════════════════════════════════════════════
def get_traffic_baseline(switch: Switch, port_name: str, days: int = 7) -> dict:
    """يحسب خط قاعدة الترافيك لآخر N أيام."""
    since = timezone.now() - timedelta(days=days)
    snaps = list(
        PortSnapshot.objects
        .filter(switch=switch, port_name=port_name, recorded_at__gte=since)
        .order_by("recorded_at")
        .values("recorded_at", "in_octets", "out_octets")
    )

    if len(snaps) < 2:
        return {"status": "insufficient_data", "samples": len(snaps)}

    mbps_vals = []
    for i in range(1, len(snaps)):
        delta = max(0, (snaps[i]["in_octets"] + snaps[i]["out_octets"]) -
                       (snaps[i - 1]["in_octets"] + snaps[i - 1]["out_octets"]))
        mbps_vals.append(delta // 1_000_000)

    if not mbps_vals:
        return {"status": "no_data"}

    return {
        "status": "ok",
        "avg_mbps": round(statistics.mean(mbps_vals), 2),
        "max_mbps": max(mbps_vals),
        "min_mbps": min(mbps_vals),
        "p95_mbps": round(sorted(mbps_vals)[int(len(mbps_vals) * 0.95)], 2),
        "samples": len(mbps_vals),
        "days": days,
    }


# ═══════════════════════════════════════════════════════════
#  11. Cleanup
# ═══════════════════════════════════════════════════════════
def cleanup_old_data() -> dict:
    """تنظيف البيانات القديمة حسب الـ TTL المحدد."""
    snap_cutoff = timezone.now() - timedelta(days=SNAPSHOT_TTL_DAYS)
    event_cutoff = timezone.now() - timedelta(days=EVENT_TTL_DAYS)
    s = PortSnapshot.objects.filter(recorded_at__lt=snap_cutoff).delete()[0]
    e = PortEvent.objects.filter(occurred_at__lt=event_cutoff).delete()[0]
    log.info(f"Cleanup: deleted {s} snapshots, {e} events")
    return {"snapshots_deleted": s, "events_deleted": e}


# ═══════════════════════════════════════════════════════════
#  12. Summary Dashboard
# ═══════════════════════════════════════════════════════════
def get_history_summary(switch: Switch, hours: int = 24) -> dict:
    """ملخص شامل للوحة التشخيص الرئيسية."""
    events = get_switch_events(switch, hours)
    flaps = get_flap_report(switch, hours)
    health = get_all_ports_health(switch, hours)

    critical_ports = [p for p in health if p["severity"] == "critical"]
    warning_ports = [p for p in health if p["severity"] == "warning"]

    top_event = max(events["by_type"].items(), key=lambda x: x[1], default=("none", 0))

    return {
        "switch": switch.hostname,
        "hours": hours,
        "total_events": events["total"],
        "by_severity": events["by_severity"],
        "top_event_type": top_event[0],
        "top_event_count": top_event[1],
        "critical_ports": critical_ports[:5],
        "warning_ports": warning_ports[:5],
        "flapping_ports": flaps[:5],
        "top_ports": events["top_ports"][:5],
        "health_summary": {
            "critical": len(critical_ports),
            "warning": len(warning_ports),
            "ok": len([p for p in health if p["severity"] == "ok"]),
        },
    }
    
    
