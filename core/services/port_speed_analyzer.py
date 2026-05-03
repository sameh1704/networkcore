"""
Port speed analysis built on switch snapshots and live SNMP counters.
"""

from __future__ import annotations

import statistics
from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone

from core.models import PortSnapshot


class PortSpeedAnalyzer:
    SPEED_THRESHOLDS = [
        (100_000_000_000, "100G"),
        (40_000_000_000, "40G"),
        (25_000_000_000, "25G"),
        (10_000_000_000, "10G"),
        (5_000_000_000, "5G"),
        (2_500_000_000, "2.5G"),
        (1_000_000_000, "1G"),
        (100_000_000, "100M"),
        (10_000_000, "10M"),
    ]

    UTILIZATION_THRESHOLDS = {
        "critical": 90,
        "warning": 70,
        "info": 50,
    }

    def __init__(self, switch, community="private", timeout=3):
        self.switch = switch
        self.community = community
        self.timeout = timeout
        self.ip = switch.ip_address
        self._vlan_map = None

    def analyze_port(self, port_name: str, hours: int = 24) -> dict:
        cache_key = f"port_speed_analysis:{self.switch.id}:{port_name}:{hours}"
        cached = cache.get(cache_key)
        if cached:
            return cached

        result = {
            "port": port_name,
            "switch": {
                "id": self.switch.id,
                "hostname": self.switch.hostname,
                "ip": self.ip,
            },
            "analysis_hours": hours,
            "current_status": {},
            "historical": {},
            "throughput_analysis": {},
            "utilization_analysis": {},
            "error_analysis": {},
            "queue_analysis": {},
            "diagnosis": [],
            "recommendations": [],
            "health_score": {"score": 0, "level": "critical"},
            "timestamp": timezone.now().isoformat(),
        }

        try:
            current = self._get_current_port_status(port_name)
            historical = self._get_historical_data(port_name, hours)
            self._merge_recent_traffic(current, historical)

            throughput = self._analyze_throughput(current, historical)
            utilization = self._analyze_utilization(current, historical)
            errors = self._analyze_errors(current, historical)
            queue = self._analyze_queue(current, historical)
            diagnosis = self._diagnose_issue(current, throughput, errors, queue)
            recommendations = self._generate_recommendations(diagnosis, current)
            health_score = self._calculate_health_score(current, throughput, errors)

            result.update({
                "current_status": current,
                "historical": historical,
                "throughput_analysis": throughput,
                "utilization_analysis": utilization,
                "error_analysis": errors,
                "queue_analysis": queue,
                "diagnosis": diagnosis,
                "recommendations": recommendations,
                "health_score": health_score,
            })
        except Exception as exc:
            result["error"] = str(exc)
            result["diagnosis"] = [{
                "severity": "critical",
                "category": "analysis",
                "message": f"Failed to analyze port: {exc}",
                "detail": None,
                "cause": "Unexpected service error",
            }]

        cache.set(cache_key, result, 30)
        return result

    def _get_current_port_status(self, port_name: str) -> dict:
        from core.services.switch_inspector import get_interfaces_detail

        interfaces = get_interfaces_detail(self.ip, self.community) or []
        for ifc in interfaces:
            if ifc.get("name") != port_name:
                continue

            speed_bps = int(ifc.get("speed_bps") or 0)
            return {
                "name": ifc.get("name"),
                "alias": ifc.get("alias") or "",
                "status": ifc.get("status"),
                "speed_bps": speed_bps,
                "speed_human": self._format_speed(speed_bps),
                "vlan_id": self._get_vlan_for_port(ifc.get("name")),
                "traffic_mbps": round(float(ifc.get("traffic_mbps") or 0), 2),
                "in_octets": int(ifc.get("in_octets") or 0),
                "out_octets": int(ifc.get("out_octets") or 0),
                "in_errors": int(ifc.get("in_errors") or 0),
                "out_errors": int(ifc.get("out_errors") or 0),
                "in_discards": int(ifc.get("in_discards") or 0),
                "out_discards": int(ifc.get("out_discards") or 0),
                "mtu": int(ifc.get("mtu") or 1500),
                "utilization_percent": 0,
            }

        return {"error": f"Port {port_name} not found", "name": port_name}

    def _get_vlan_for_port(self, port_name: str):
        if self._vlan_map is None:
            self._vlan_map = {}

            try:
                from core.services.switch_inspector import get_vlans_full

                for vlan in get_vlans_full(self.ip, self.community) or []:
                    vlan_id = vlan.get("vlan_id")
                    for member in vlan.get("port_names", []):
                        self._vlan_map.setdefault(member, vlan_id)
            except Exception:
                self._vlan_map = {}

            if not self._vlan_map:
                latest = (
                    PortSnapshot.objects.filter(switch=self.switch)
                    .order_by("port_name", "-recorded_at")
                )
                latest_by_port = {}
                for snapshot in latest[:500]:
                    latest_by_port.setdefault(snapshot.port_name, snapshot.vlan_id)
                self._vlan_map.update(latest_by_port)

        return self._vlan_map.get(port_name)

    def _get_historical_data(self, port_name: str, hours: int) -> dict:
        since = timezone.now() - timedelta(hours=hours)
        snapshots = list(
            PortSnapshot.objects.filter(
                switch=self.switch,
                port_name=port_name,
                recorded_at__gte=since,
            ).order_by("recorded_at")
        )

        if len(snapshots) < 2:
            return {
                "hours": hours,
                "snapshots_count": len(snapshots),
                "samples": [],
                "avg_traffic_mbps": 0,
                "max_traffic_mbps": 0,
                "min_traffic_mbps": 0,
                "p95_traffic_mbps": 0,
                "current_traffic_mbps": 0,
                "latest_in_mbps": 0,
                "latest_out_mbps": 0,
                "total_errors": sum((s.in_errors + s.out_errors) for s in snapshots),
                "total_discards": sum((s.in_discards + s.out_discards) for s in snapshots),
                "trend": "stable",
                "has_history": False,
            }

        samples = self._build_traffic_series(snapshots)
        totals = [sample["traffic_mbps"] for sample in samples]

        return {
            "hours": hours,
            "snapshots_count": len(snapshots),
            "samples": samples[-180:],
            "avg_traffic_mbps": round(statistics.mean(totals), 2) if totals else 0,
            "max_traffic_mbps": round(max(totals), 2) if totals else 0,
            "min_traffic_mbps": round(min(totals), 2) if totals else 0,
            "p95_traffic_mbps": round(self._percentile(totals, 95), 2) if totals else 0,
            "current_traffic_mbps": round(samples[-1]["traffic_mbps"], 2) if samples else 0,
            "latest_in_mbps": round(samples[-1]["in_mbps"], 2) if samples else 0,
            "latest_out_mbps": round(samples[-1]["out_mbps"], 2) if samples else 0,
            "total_errors": sum((s.in_errors + s.out_errors) for s in snapshots),
            "total_discards": sum((s.in_discards + s.out_discards) for s in snapshots),
            "trend": self._calculate_trend(totals),
            "has_history": True,
        }

    def _build_traffic_series(self, snapshots: list[PortSnapshot]) -> list[dict]:
        samples = []

        for previous, current in zip(snapshots, snapshots[1:]):
            seconds = max((current.recorded_at - previous.recorded_at).total_seconds(), 1)
            in_delta = max(current.in_octets - previous.in_octets, 0)
            out_delta = max(current.out_octets - previous.out_octets, 0)
            in_mbps = (in_delta * 8) / seconds / 1_000_000
            out_mbps = (out_delta * 8) / seconds / 1_000_000
            total_mbps = in_mbps + out_mbps

            samples.append({
                "time": current.recorded_at.isoformat(),
                "in_mbps": round(in_mbps, 2),
                "out_mbps": round(out_mbps, 2),
                "traffic_mbps": round(total_mbps, 2),
                "errors": (current.in_errors + current.out_errors),
                "discards": (current.in_discards + current.out_discards),
            })

        return samples

    def _merge_recent_traffic(self, current: dict, historical: dict) -> None:
        recent_mbps = historical.get("current_traffic_mbps", 0)
        if recent_mbps:
            current["traffic_mbps"] = recent_mbps
            current["in_mbps"] = historical.get("latest_in_mbps", 0)
            current["out_mbps"] = historical.get("latest_out_mbps", 0)
        else:
            current["in_mbps"] = 0
            current["out_mbps"] = 0

        current["utilization_percent"] = self._calculate_utilization(
            current.get("speed_bps", 0),
            current.get("traffic_mbps", 0),
        )

    def _analyze_throughput(self, current: dict, historical: dict) -> dict:
        current_mbps = float(current.get("traffic_mbps") or 0)
        speed_bps = int(current.get("speed_bps") or 0)
        max_possible_mbps = round(speed_bps / 1_000_000, 2) if speed_bps else 0

        return {
            "current_mbps": round(current_mbps, 2),
            "max_possible_mbps": max_possible_mbps,
            "avg_mbps_historical": historical.get("avg_traffic_mbps", 0),
            "peak_mbps": historical.get("max_traffic_mbps", 0),
            "p95_mbps": historical.get("p95_traffic_mbps", 0),
            "is_saturated": bool(max_possible_mbps and current_mbps >= max_possible_mbps * 0.95),
            "is_underutilized": bool(max_possible_mbps and current_mbps <= max_possible_mbps * 0.05),
        }

    def _analyze_utilization(self, current: dict, historical: dict) -> dict:
        current_util = float(current.get("utilization_percent") or 0)
        avg_util = self._calculate_utilization_from_traffic(
            current.get("speed_bps", 0),
            historical.get("avg_traffic_mbps", 0),
        )
        peak_util = self._calculate_utilization_from_traffic(
            current.get("speed_bps", 0),
            historical.get("max_traffic_mbps", 0),
        )

        severity = "ok"
        if current_util >= self.UTILIZATION_THRESHOLDS["critical"]:
            severity = "critical"
        elif current_util >= self.UTILIZATION_THRESHOLDS["warning"]:
            severity = "warning"
        elif current_util >= self.UTILIZATION_THRESHOLDS["info"]:
            severity = "info"

        return {
            "current_percent": round(current_util, 1),
            "average_percent": avg_util,
            "peak_percent": peak_util,
            "severity": severity,
            "level": self._get_utilization_level(current_util),
        }

    def _analyze_errors(self, current: dict, historical: dict) -> dict:
        in_errors = int(current.get("in_errors") or 0)
        out_errors = int(current.get("out_errors") or 0)
        in_discards = int(current.get("in_discards") or 0)
        out_discards = int(current.get("out_discards") or 0)

        total_errors = in_errors + out_errors
        total_discards = in_discards + out_discards
        error_type = None

        if total_errors > 100:
            error_type = "crc"
        elif total_discards > 100:
            error_type = "congestion"
        elif in_errors > 50 and out_errors == 0:
            error_type = "input_noise"
        elif out_errors > 50 and in_errors == 0:
            error_type = "output_queue"

        return {
            "in_errors": in_errors,
            "out_errors": out_errors,
            "in_discards": in_discards,
            "out_discards": out_discards,
            "total_errors": total_errors,
            "total_discards": total_discards,
            "error_type": error_type,
            "historical_errors": historical.get("total_errors", 0),
            "historical_discards": historical.get("total_discards", 0),
            "error_rate_per_second": self._calculate_error_rate(current),
        }

    def _analyze_queue(self, current: dict, historical: dict) -> dict:
        total_traffic = max(float(current.get("traffic_mbps") or 0), 0.01)
        discard_rate = float(current.get("out_discards") or 0) / max(total_traffic, 1)

        status = "normal"
        if discard_rate > 0.01:
            status = "congested"
        elif discard_rate > 0.001:
            status = "busy"

        return {
            "status": status,
            "discard_rate_percent": round(discard_rate * 100, 3),
            "possible_backlog": int(current.get("out_discards") or 0) > 50,
            "is_uplink_saturated": self._check_uplink_saturation(current, historical),
        }

    def _diagnose_issue(self, current: dict, throughput: dict, errors: dict, queue: dict) -> list[dict]:
        diagnoses = []

        if throughput.get("is_saturated"):
            diagnoses.append({
                "severity": "critical",
                "category": "bandwidth",
                "message": "Port is saturated",
                "detail": f"Current utilization is {current.get('utilization_percent', 0)}% of interface capacity",
                "cause": "Traffic demand is exceeding the available port bandwidth",
            })

        if errors.get("error_type") == "crc":
            diagnoses.append({
                "severity": "critical",
                "category": "physical",
                "message": "High CRC/error count detected",
                "detail": f"{errors['total_errors']} errors recorded on the interface",
                "cause": "Likely cable, optic, duplex, or physical layer problem",
            })
        elif errors.get("error_type") == "congestion":
            diagnoses.append({
                "severity": "warning",
                "category": "congestion",
                "message": "Packets are being discarded on the port",
                "detail": f"{errors['total_discards']} discards recorded",
                "cause": "Queue pressure or microbursts are exceeding interface buffering",
            })

        util = float(current.get("utilization_percent") or 0)
        if util > 80:
            diagnoses.append({
                "severity": "warning" if util < 90 else "critical",
                "category": "utilization",
                "message": f"High utilization ({util:.1f}%)",
                "detail": f"Historical average over {throughput.get('avg_mbps_historical', 0)} Mbps",
                "cause": "Sustained load or bursty endpoint traffic",
            })

        if queue.get("is_uplink_saturated"):
            diagnoses.append({
                "severity": "critical",
                "category": "uplink",
                "message": "Likely uplink saturation",
                "detail": "Historical peaks are close to interface capacity",
                "cause": "The uplink no longer matches the active workload",
            })

        if not diagnoses:
            diagnoses.append({
                "severity": "ok",
                "category": "health",
                "message": "Port is operating within normal limits",
                "detail": "Traffic, errors, and discards are inside expected thresholds",
                "cause": None,
            })

        return diagnoses

    def _generate_recommendations(self, diagnoses: list[dict], current: dict) -> list[dict]:
        recommendations = []

        for diagnosis in diagnoses:
            if diagnosis["severity"] == "ok":
                continue

            category = diagnosis.get("category")
            if category == "bandwidth":
                recommendations.append({
                    "priority": 1,
                    "action": "Upgrade the link or add LACP members",
                    "details": "Current demand is too close to the port ceiling.",
                })
            elif category == "physical":
                recommendations.append({
                    "priority": 1,
                    "action": "Check cable/transceiver and duplex settings",
                    "details": f"Validate optics or copper on {current.get('name')}.",
                })
            elif category == "congestion":
                recommendations.append({
                    "priority": 1,
                    "action": "Review queueing and QoS",
                    "details": "Discards indicate the egress buffer is under pressure.",
                })
            elif category == "uplink":
                recommendations.append({
                    "priority": 1,
                    "action": "Review uplink capacity",
                    "details": "Consider a higher-speed uplink or load balancing.",
                })
            elif category == "utilization":
                recommendations.append({
                    "priority": 2,
                    "action": "Inspect top talkers",
                    "details": "Use flow telemetry or packet analysis to identify heavy senders.",
                })

        return recommendations

    def _calculate_health_score(self, current: dict, throughput: dict, errors: dict) -> dict:
        score = 100

        util = float(current.get("utilization_percent") or 0)
        if util > 90:
            score -= 30
        elif util > 70:
            score -= 15
        elif util > 50:
            score -= 5

        total_errors = int(errors.get("total_errors") or 0)
        if total_errors > 1000:
            score -= 40
        elif total_errors > 100:
            score -= 20
        elif total_errors > 10:
            score -= 5

        total_discards = int(errors.get("total_discards") or 0)
        if total_discards > 500:
            score -= 25
        elif total_discards > 50:
            score -= 10

        if throughput.get("is_saturated"):
            score -= 15

        score = max(0, min(100, score))

        level = "good"
        if score < 40:
            level = "critical"
        elif score < 70:
            level = "warning"

        return {"score": score, "level": level}

    def _format_speed(self, bps: int) -> str:
        for threshold, label in self.SPEED_THRESHOLDS:
            if bps >= threshold:
                return label
        return "0M" if bps <= 0 else f"{round(bps / 1_000_000, 1)}M"

    def _calculate_utilization(self, speed_bps: int, traffic_mbps: float) -> float:
        if speed_bps <= 0:
            return 0
        return round((float(traffic_mbps or 0) / (speed_bps / 1_000_000)) * 100, 1)

    def _calculate_utilization_from_traffic(self, speed_bps: int, traffic_mbps: float) -> float:
        return self._calculate_utilization(speed_bps, traffic_mbps)

    def _calculate_trend(self, values: list[float]) -> str:
        if len(values) < 4:
            return "stable"

        midpoint = len(values) // 2
        first_half = statistics.mean(values[:midpoint])
        second_half = statistics.mean(values[midpoint:])

        if second_half > first_half * 1.2:
            return "increasing"
        if second_half < first_half * 0.8:
            return "decreasing"
        return "stable"

    def _calculate_error_rate(self, current: dict) -> float:
        total_octets = int(current.get("in_octets") or 0) + int(current.get("out_octets") or 0)
        total_errors = int(current.get("in_errors") or 0) + int(current.get("out_errors") or 0)
        if total_octets <= 0:
            return 0
        return round(total_errors / max(total_octets / 1_000_000, 1), 4)

    def _get_utilization_level(self, percent: float) -> str:
        if percent >= 90:
            return "Oversaturated"
        if percent >= 70:
            return "High"
        if percent >= 40:
            return "Moderate"
        if percent >= 10:
            return "Low"
        return "Idle"

    def _check_uplink_saturation(self, current: dict, historical: dict) -> bool:
        util = float(current.get("utilization_percent") or 0)
        peak = float(historical.get("max_traffic_mbps") or 0)
        speed = int(current.get("speed_bps") or 0)
        max_mbps = speed / 1_000_000 if speed else 0
        return util > 80 or bool(max_mbps and peak > max_mbps * 0.95)

    def _percentile(self, values: list[float], percentile: int) -> float:
        if not values:
            return 0
        ordered = sorted(values)
        index = min(int(len(ordered) * percentile / 100), len(ordered) - 1)
        return ordered[index]


def analyze_port_speed(switch, port_name: str, hours: int = 24) -> dict:
    analyzer = PortSpeedAnalyzer(switch, switch.snmp_community)
    return analyzer.analyze_port(port_name, hours)


def analyze_all_ports(switch, hours: int = 24) -> list[dict]:
    from core.services.switch_inspector import get_interfaces_detail

    analyzer = PortSpeedAnalyzer(switch, switch.snmp_community)
    interfaces = get_interfaces_detail(switch.ip_address, switch.snmp_community) or []

    results = []
    for interface in interfaces:
        if interface.get("status") == "disabled":
            continue
        results.append(analyzer.analyze_port(interface.get("name"), hours))

    results.sort(key=lambda item: item.get("health_score", {}).get("score", 100))
    return results
