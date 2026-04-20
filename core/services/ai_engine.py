def _severity_rank(level):
    return {"ok": 0, "good": 0, "info": 1, "warning": 2, "critical": 3}.get(level, 0)


def _max_severity(*levels):
    return max(levels, key=_severity_rank, default="ok")


def _dedupe_keep_order(items):
    seen = set()
    result = []
    for item in items:
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def analyze_network(
    crc: int,
    cpu: float,
    traffic_mbps: int,
    drops: int,
    interfaces: list,
    poe_faults: list,
) -> dict:
    """
    تحليل سريع وخفيف للاستخدام في الـ WebSocket.
    يعتمد على أقل قدر من البيانات ليبقى سريعاً، لكنه يحاول استنتاج
    السبب المرجح بدل الاكتفاء بمؤشر واحد.
    """
    interfaces = interfaces or []
    poe_faults = poe_faults or []

    issues = []
    recommendations = []
    severity = "ok"

    connected_ports = [i for i in interfaces if i.get("status") == "up"]
    busy_ports = [
        i for i in interfaces
        if ((i.get("in", 0) + i.get("out", 0)) // 1_000_000) > 300
    ]
    error_ports = []
    for iface in interfaces:
        total_errors = (
            int(iface.get("in_errors", 0) or 0) +
            int(iface.get("out_errors", 0) or 0) +
            int(iface.get("in_discards", 0) or 0) +
            int(iface.get("out_discards", 0) or 0)
        )
        if total_errors > 0:
            error_ports.append({
                "name": iface.get("name", "?"),
                "total_errors": total_errors,
            })

    if cpu >= 90:
        issues.append({"type": "cpu", "severity": "critical", "msg": f"CPU حرج: {cpu:.0f}%"})
        recommendations.append("افحص وجود Loop أو Broadcast Storm أو عملية SNMP ثقيلة")
        severity = _max_severity(severity, "critical")
    elif cpu >= 70:
        issues.append({"type": "cpu", "severity": "warning", "msg": f"CPU مرتفع: {cpu:.0f}%"})
        recommendations.append("راجع STP والـ traffic على المنافذ الأعلى استخداماً")
        severity = _max_severity(severity, "warning")

    if crc > 500:
        issues.append({"type": "crc", "severity": "critical", "msg": f"CRC حرج: {crc}"})
        recommendations.append("افحص الكابل أو الـ SFP أو إعدادات speed/duplex")
        severity = _max_severity(severity, "critical")
    elif crc > 100:
        issues.append({"type": "crc", "severity": "warning", "msg": f"CRC مرتفع: {crc}"})
        recommendations.append("تحقق من وجود duplex mismatch أو كابل منخفض الجودة")
        severity = _max_severity(severity, "warning")

    if drops > 500:
        issues.append({"type": "drops", "severity": "critical", "msg": f"Drops حرجة: {drops}"})
        recommendations.append("فعّل QoS أو راقب broadcast/unknown-unicast")
        severity = _max_severity(severity, "critical")
    elif drops > 100:
        issues.append({"type": "drops", "severity": "warning", "msg": f"Drops مرتفعة: {drops}"})
        recommendations.append("افحص الازدحام وامتلاء الـ queues على المنافذ")
        severity = _max_severity(severity, "warning")

    if traffic_mbps > 800:
        issues.append({"type": "traffic", "severity": "critical", "msg": f"ضغط عالي: {traffic_mbps} Mbps"})
        recommendations.append("راجع المنافذ الأعلى استخداماً ووازن الحمل إن أمكن")
        severity = _max_severity(severity, "critical")
    elif traffic_mbps > 500:
        issues.append({"type": "traffic", "severity": "warning", "msg": f"ضغط مرتفع: {traffic_mbps} Mbps"})
        severity = _max_severity(severity, "warning")

    if len(error_ports) >= 3:
        bad_ports = ", ".join(p["name"] for p in error_ports[:3])
        issues.append({
            "type": "port_errors",
            "severity": "warning",
            "msg": f"عدة منافذ بها أخطاء: {bad_ports}",
        })
        recommendations.append("ابدأ بفحص المنافذ المتأثرة أولاً لتحديد إن كانت المشكلة محصورة أم عامة")
        severity = _max_severity(severity, "warning")

    if len(busy_ports) >= 4 and drops > 0:
        issues.append({
            "type": "congestion",
            "severity": "warning",
            "msg": f"ازدحام محتمل: {len(busy_ports)} منافذ فوق 300 Mbps",
        })
        recommendations.append("راقب الـ uplinks والمنافذ كثيرة الاستخدام")
        severity = _max_severity(severity, "warning")

    for fault in poe_faults[:5]:
        issues.append({
            "type": "poe",
            "severity": "warning",
            "msg": f"PoE fault على {fault.get('port', '?')}",
        })
        severity = _max_severity(severity, "warning")
    if poe_faults:
        recommendations.append("تحقق من استهلاك الطاقة للأجهزة المتصلة على منافذ PoE")

    root_cause = derive_root_cause(
        issues=issues,
        cpu=cpu,
        traffic_mbps=traffic_mbps,
        drops=drops,
        crc=crc,
        error_port_count=len(error_ports),
        poe_fault_count=len(poe_faults),
        busy_port_count=len(busy_ports),
    )

    return {
        "severity": severity,
        "root_cause": root_cause,
        "issues": issues[:6],
        "recommendations": _dedupe_keep_order(recommendations)[:4],
        "alert": severity in ("warning", "critical"),
        "facts": {
            "connected_ports": len(connected_ports),
            "error_ports": len(error_ports),
            "busy_ports": len(busy_ports),
            "poe_faults": len(poe_faults),
        },
    }


def derive_root_cause(
    issues,
    cpu=0,
    traffic_mbps=0,
    drops=0,
    crc=0,
    error_port_count=0,
    poe_fault_count=0,
    busy_port_count=0,
):
    types = {issue.get("type") for issue in (issues or [])}

    if "cpu" in types and ("traffic" in types or "drops" in types):
        return "احتمال Loop أو Broadcast Storm يسبب ضغطاً على المعالج والشبكة"
    if "crc" in types and ("drops" in types or error_port_count > 0):
        return "احتمال Duplex mismatch أو كابل/وحدة uplink بها مشكلة"
    if "congestion" in types or (busy_port_count >= 4 and drops > 0):
        return "ازدحام على الـ uplink أو توزيع حمل غير متوازن"
    if "poe" in types and poe_fault_count > 0:
        return "مشكلة طاقة PoE أو جهاز يستهلك أكثر من المسموح"
    if crc > 0:
        return "أخطاء طبقة فيزيائية مرجحة على بعض المنافذ"
    if cpu >= 70:
        return "ضغط مرتفع على المعالج يحتاج تتبع مصدر الـ traffic"
    if traffic_mbps >= 500:
        return "الشبكة نشطة بشدة لكن دون مؤشر قاطع على عطل محدد"
    return "لا توجد مؤشرات قوية على عطل فعلي حالياً"


def build_ai_diagnosis(system, interfaces, errors, loops, duplex, poe, predictions):
    """
    تشخيص أعمق للاستخدام في الـ API والواجهة.
    """
    system = system or {}
    interfaces = interfaces or []
    errors = errors or []
    loops = loops or {}
    duplex = duplex or {}
    poe = poe or {}
    predictions = predictions or {}

    critical_errors = [e for e in errors if e.get("severity") == "critical"]
    warning_errors = [e for e in errors if e.get("severity") == "warning"]
    poe_faults = poe.get("faulty", []) or []

    total_crc = sum((e.get("in_errors", 0) or 0) for e in errors)
    total_drops = sum(
        (e.get("in_discards", 0) or 0) + (e.get("out_discards", 0) or 0)
        for e in errors
    )
    total_traffic = sum((i.get("traffic_mbps", 0) or 0) for i in interfaces)

    ai = analyze_network(
        crc=total_crc,
        cpu=float(system.get("cpu_5s", 0) or 0),
        traffic_mbps=int(total_traffic),
        drops=int(total_drops),
        interfaces=interfaces,
        poe_faults=poe_faults,
    )

    severity = ai.get("severity", "ok")
    severity = _max_severity(
        severity,
        "critical" if loops.get("has_loop") else "ok",
        "warning" if duplex.get("has_mismatch") else "ok",
        "warning" if warning_errors else "ok",
        "critical" if critical_errors else "ok",
    )

    network_issues = []
    if loops.get("has_loop"):
        network_issues.append({
            "severity": "critical",
            "title": "Loop محتمل",
            "message": f"تم اكتشاف {loops.get('loop_count', 0)} حالة محتملة في جدول الـ MAC",
            "action": "افحص الكابلات المكررة والأجهزة المتصلة بأكثر من منفذ",
        })
    if duplex.get("has_mismatch"):
        network_issues.append({
            "severity": "warning",
            "title": "Duplex Mismatch",
            "message": f"{duplex.get('count', 0)} منفذ يعمل على Half Duplex",
            "action": "اجعل الـ duplex على Auto أو Full على الطرفين",
        })
    if critical_errors:
        bad_ports = ", ".join(e.get("name", "?") for e in critical_errors[:3])
        network_issues.append({
            "severity": "critical",
            "title": "أخطاء منافذ حرجة",
            "message": f"{len(critical_errors)} منفذ متأثر، أبرزها: {bad_ports}",
            "action": "افحص الكابلات والـ SFP والـ duplex للمنافذ المتأثرة",
        })
    elif warning_errors:
        warn_ports = ", ".join(e.get("name", "?") for e in warning_errors[:3])
        network_issues.append({
            "severity": "warning",
            "title": "أخطاء واجهات متوسطة",
            "message": f"{len(warning_errors)} منفذ به أخطاء أو discards، أبرزها: {warn_ports}",
            "action": "راقب الزيادة مع الزمن وراجع جودة الكابلات",
        })
    if poe_faults:
        network_issues.append({
            "severity": "warning",
            "title": "مشكلة PoE",
            "message": f"{len(poe_faults)} منفذ PoE به fault أو deny",
            "action": "تحقق من استهلاك الطاقة للأجهزة المتصلة",
        })
    if not network_issues:
        network_issues.append({
            "severity": "good",
            "title": "لا توجد مشاكل شبكة حرجة",
            "message": "لم تظهر مؤشرات Loop أو Duplex mismatch أو أخطاء جسيمة حالياً",
            "action": "استمر في المراقبة الدورية",
        })

    prediction_items = []
    cable = predictions.get("cable", {})
    cpu_pred = predictions.get("cpu", {})
    broadcast = predictions.get("broadcast", {})
    ports = predictions.get("ports", {})

    if cable:
        prediction_items.append({
            "severity": cable.get("status", "good"),
            "title": "الكابل",
            "message": cable.get("message", "لا توجد بيانات"),
        })
    if cpu_pred:
        prediction_items.append({
            "severity": cpu_pred.get("status", "good"),
            "title": "CPU",
            "message": cpu_pred.get("message", "لا توجد بيانات"),
        })
    prediction_items.append({
        "severity": "critical" if broadcast.get("has_storm_risk") else "good",
        "title": "Broadcast Storm",
        "message": broadcast.get("warnings", [{}])[0].get("message", "لا توجد مؤشرات لعاصفة بث") if broadcast.get("warnings") else "لا توجد مؤشرات لعاصفة بث",
    })
    prediction_items.append({
        "severity": "warning" if ports.get("count", 0) else "good",
        "title": "ازدحام المنافذ",
        "message": f"{ports.get('count', 0)} منفذ لديه استخدام مرتفع" if ports.get("count", 0) else "لا توجد مؤشرات ازدحام حرجة",
    })

    root_cause = ai.get("root_cause", "لا توجد مؤشرات قوية على عطل فعلي حالياً")
    if loops.get("has_loop"):
        root_cause = "Loop محتمل في الشبكة وهو السبب الأقرب للأعراض الحالية"
    elif duplex.get("has_mismatch") and critical_errors:
        root_cause = "Duplex mismatch أو خلل فيزيائي على المنافذ المتأثرة"
    elif critical_errors and len(critical_errors) <= 2:
        root_cause = "العطل يبدو محصوراً في منافذ أو كابلات محددة أكثر من كونه مشكلة عامة"

    recommendations = _dedupe_keep_order(
        ai.get("recommendations", []) +
        [item.get("action") for item in network_issues if item.get("action")]
    )[:6]

    return {
        "severity": severity,
        "root_cause": root_cause,
        "issues": ai.get("issues", []),
        "recommendations": recommendations,
        "network_issues": network_issues,
        "prediction_items": prediction_items,
        "facts": {
            "cpu": system.get("cpu_5s", 0),
            "memory": system.get("mem_pct", 0),
            "error_ports": len(critical_errors) + len(warning_errors),
            "loop_count": loops.get("loop_count", 0),
            "duplex_count": duplex.get("count", 0),
            "poe_faults": len(poe_faults),
        },
    }
