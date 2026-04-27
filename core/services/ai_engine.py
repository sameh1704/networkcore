def analyze_network(
    crc: int,
    cpu: float,
    traffic_mbps: int,
    drops: int,
    interfaces: list,
    poe_faults: list,
) -> dict:

    issues = []
    recommendations = []
    severity = "ok"

    # CPU
    if cpu >= 90:
        issues.append({"type": "cpu", "msg": f"CPU حرج: {cpu:.0f}%"})
        recommendations.append("تحقق من routing loop أو broadcast storm")
        severity = "critical"

    elif cpu >= 70:
        issues.append({"type": "cpu", "msg": f"CPU مرتفع: {cpu:.0f}%"})
        recommendations.append("راجع spanning-tree")
        severity = "warning"

    # CRC
    if crc > 500:
        issues.append({"type": "crc", "msg": f"CRC حرج: {crc}"})
        recommendations.append("استبدل الكابل أو SFP")
        severity = "critical"

    elif crc > 100:
        issues.append({"type": "crc", "msg": f"CRC مرتفع: {crc}"})
        recommendations.append("تحقق من duplex mismatch")
        if severity == "ok":
            severity = "warning"

    # Drops
    if drops > 500:
        issues.append({"type": "drops", "msg": f"Drops حرجة: {drops}"})
        recommendations.append("فعّل QoS")
        severity = "critical"

    elif drops > 100:
        issues.append({"type": "drops", "msg": f"Drops مرتفعة: {drops}"})
        if severity == "ok":
            severity = "warning"

    # Traffic
    if traffic_mbps > 800:
        issues.append({"type": "traffic", "msg": f"ضغط عالي: {traffic_mbps} Mbps"})
        severity = "critical"

    elif traffic_mbps > 500:
        issues.append({"type": "traffic", "msg": f"ضغط متوسط: {traffic_mbps} Mbps"})
        if severity == "ok":
            severity = "warning"

    # PoE
    for f in poe_faults:
        issues.append({
            "type": "poe",
            "msg": f"PoE fault على {f['port']}"
        })
        if severity == "ok":
            severity = "warning"

    root_cause = derive_root_cause(issues)

    has_real_issue = severity in ["warning", "critical"]

    return {
        "severity": severity,
        "root_cause": root_cause,
        "issues": issues,
        "recommendations": recommendations,
        "alert": has_real_issue   # 🔥 مهم
    }

def derive_root_cause(issues):

    types = [i["type"] for i in issues]

    if "crc" in types and "drops" in types:
        return "Duplex mismatch أو كابل تالف"

    if "cpu" in types and "traffic" in types:
        return "Broadcast storm أو Loop"

    if "crc" in types:
        return "مشكلة كابل"

    if "cpu" in types:
        return "CPU overload"

    if "poe" in types:
        return "PoE overload"

    return "لا يوجد مشاكل"
