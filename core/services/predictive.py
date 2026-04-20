# core/services/predictive.py

import statistics
import time
from collections import defaultdict
from .snmp import snmp_get, snmp_walk, cached

# ============================================
# Cable Length Estimation (بدون TDR)
# ============================================

def estimate_cable_length(ip, community, port_name=None):
    """
    تقدير طول الكابل باستخدام قوة الإشارة (Attenuation)
    يعمل على معظم السويتشات حتى القديمة
    
    المبدأ: كلما زاد الطول، ضعفت الإشارة
    """
    # OID لقوة الإشارة (يعمل على معظم الأجهزة)
    OID_SIGNAL_STRENGTH = "1.3.6.1.2.1.10.7.2.1.4"  # dot3StatsIndex
    
    try:
        signal_raw = snmp_walk(ip, community, OID_SIGNAL_STRENGTH) or []
        
        results = []
        for i, signal in enumerate(signal_raw):
            try:
                signal_val = int(str(signal).strip())
                # تقدير الطول: الإشارة تضعف حوالي 0.2dB لكل متر
                # القيمة 100 تعني كابل مثالي
                if signal_val > 0 and signal_val <= 100:
                    estimated_length = max(0, (100 - signal_val) * 1.5)
                    results.append({
                        'port_index': i + 1,
                        'signal_strength': signal_val,
                        'estimated_length_m': round(estimated_length, 1),
                        'quality': 'good' if estimated_length < 50 else 'fair' if estimated_length < 80 else 'poor'
                    })
            except:
                continue
        
        if port_name:
            # فلتر حسب اسم المنفذ إذا مطلوب
            return [r for r in results if str(r['port_index']) in port_name]
        
        return results
    except Exception as e:
        return []


# ============================================
# Loop Detection
# ============================================

def detect_network_loops(ip, community, mac_table_data=None):
    """
    اكتشاف حلقات (Loops) في الشبكة باستخدام جدول MAC
    
    المبدأ: نفس الـ MAC على منفذين مختلفين = Loop محتمل
    """
    if not mac_table_data:
        from .switch_inspector import get_mac_table
        mac_table_data = get_mac_table(ip, community, limit=5000)
    
    mac_entries = mac_table_data.get('mac_table', []) if isinstance(mac_table_data, dict) else mac_table_data
    
    mac_locations = {}
    loops = []
    
    for entry in mac_entries:
        mac = entry.get('mac', '')
        port = entry.get('port', '')
        
        if not mac or not port:
            continue
        
        if mac in mac_locations:
            if mac_locations[mac] != port:
                loops.append({
                    'mac': mac,
                    'port1': mac_locations[mac],
                    'port2': port,
                    'severity': 'critical',
                    'issue': 'نفس الـ MAC ظهر على منفذين مختلفين',
                    'fix': 'افحص وجود كابل Loop أو جهاز متصل بمنفذين (STP可能 معطل)'
                })
        else:
            mac_locations[mac] = port
    
    return {
        'has_loop': len(loops) > 0,
        'loops': loops,
        'loop_count': len(loops)
    }


def check_stp_consistency(ip, community):
    """
    التحقق من تناسق STP عبر الجيران
    """
    from .switch_inspector import get_stp_info, get_cdp_neighbors
    
    try:
        stp_info = get_stp_info(ip, community)
        cdp_neighbors = get_cdp_neighbors(ip, community)
        
        warnings = []
        
        # التحقق من وجود منافذ في حالة blocking (طبيعي ولكن قد يكون Loop)
        if stp_info.get('blocking_count', 0) > 0:
            warnings.append({
                'type': 'stp_blocking',
                'message': f"{stp_info['blocking_count']} منافذ في حالة Blocking",
                'severity': 'info',
                'fix': 'طبيعي في شبكات STP، ولكن تأكد من عدم وجود Loops'
            })
        
        # التحقق من root bridge
        root = stp_info.get('root_bridge', '')
        if root and 'not' in root.lower():
            warnings.append({
                'type': 'stp_root',
                'message': 'قد يكون هناك مشكلة في تحديد Root Bridge',
                'severity': 'warning',
                'fix': 'تأكد من تكوين STP بشكل صحيح'
            })
        
        return {
            'stp_healthy': len([w for w in warnings if w['severity'] == 'critical']) == 0,
            'warnings': warnings
        }
    except Exception as e:
        return {'stp_healthy': True, 'warnings': [], 'error': str(e)}


# ============================================
# Failure Prediction
# ============================================

class FailurePredictor:
    """
    توقع الأعطال بناءً على البيانات التاريخية والاتجاهات
    """
    
    def __init__(self, ip, community):
        self.ip = ip
        self.community = community
        self.history = {}  # سيتم تحميلها من قاعدة البيانات
    
    def load_history(self, model_class, days=30):
        """
        تحميل البيانات التاريخية من قاعدة البيانات
        """
        from django.utils import timezone
        from datetime import timedelta
        
        cutoff = timezone.now() - timedelta(days=days)
        
        try:
            history = model_class.objects.filter(
                switch__ip_address=self.ip,
                timestamp__gte=cutoff
            ).order_by('timestamp')
            
            self.history = {
                'crc_errors': [h.crc_errors for h in history if h.crc_errors],
                'cpu_usage': [h.cpu_usage for h in history if h.cpu_usage],
                'temperature': [h.temperature for h in history if h.temperature],
                'drops': [h.output_drops for h in history if h.output_drops],
            }
        except Exception:
            self.history = {}
    
    def analyze_trend(self, data_list):
        """
        تحليل اتجاه البيانات (زيادة أو نقصان)
        """
        if len(data_list) < 5:
            return 0, 'insufficient_data'
        
        # حساب الميل باستخدام الانحدار الخطي البسيط
        n = len(data_list)
        x = list(range(n))
        y = data_list
        
        mean_x = sum(x) / n
        mean_y = sum(y) / n
        
        numerator = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
        denominator = sum((x[i] - mean_x) ** 2 for i in range(n))
        
        slope = numerator / denominator if denominator != 0 else 0
        
        # نسبة التغير
        if mean_y > 0:
            change_percent = (slope * n) / mean_y * 100
        else:
            change_percent = 0
        
        return change_percent, 'increasing' if slope > 0 else 'decreasing'
    
    def predict_cable_failure(self):
        """
        توقع فشل الكابل بناءً على أخطاء CRC
        """
        crc_history = self.history.get('crc_errors', [])
        
        if len(crc_history) < 5:
            return {
                'status': 'unknown',
                'message': 'بيانات غير كافية للتنبؤ (يلزم 5 أيام على الأقل)',
                'risk_percent': 0
            }
        
        trend, direction = self.analyze_trend(crc_history)
        last_value = crc_history[-1] if crc_history else 0
        avg_value = sum(crc_history) / len(crc_history)
        
        if trend > 20 and last_value > 100:
            return {
                'status': 'critical',
                'message': f'⚠️ زيادة حادة في أخطاء CRC ({trend:.0f}%) - استبدل الكابل فوراً',
                'risk_percent': min(95, trend),
                'expected_days': max(1, int((500 - last_value) / max(1, (last_value - crc_history[-2]))) if len(crc_history) > 1 else 7)
            }
        elif trend > 10 and last_value > 50:
            return {
                'status': 'warning',
                'message': f'⚠️ تدهور ملحوظ في جودة الكابل ({trend:.0f}%)',
                'risk_percent': min(70, trend),
                'expected_days': 14
            }
        elif trend > 5:
            return {
                'status': 'info',
                'message': f'تدهور بطيء في جودة الكابل ({trend:.0f}%) - راقب الحالة',
                'risk_percent': min(40, trend),
                'expected_days': 30
            }
        else:
            return {
                'status': 'good',
                'message': '✅ الكابل بحالة جيدة',
                'risk_percent': 0
            }
    
    def predict_cpu_crash(self):
        """
        توقع ارتفاع CPU للحد الخطير
        """
        cpu_history = self.history.get('cpu_usage', [])
        
        if len(cpu_history) < 5:
            return {'status': 'unknown', 'message': 'بيانات غير كافية', 'risk_percent': 0}
        
        trend, direction = self.analyze_trend(cpu_history)
        last_cpu = cpu_history[-1]
        
        if last_cpu > 90:
            return {
                'status': 'critical',
                'message': f'🔥 CPU حرج ({last_cpu:.0f}%) - خطر تعطل وشيك',
                'risk_percent': 90,
                'action': 'قم بتحليل الـ traffic وإعادة تشغيل السويتش إذا لزم'
            }
        elif last_cpu > 75 and trend > 5:
            return {
                'status': 'warning',
                'message': f'⚠️ CPU مرتفع ({last_cpu:.0f}%) ويتزايد ({trend:.0f}%)',
                'risk_percent': 60,
                'action': 'افحص وجود Broadcast Storm أو Loop'
            }
        elif last_cpu > 60 and trend > 0:
            return {
                'status': 'info',
                'message': f'📈 CPU في ارتفاع ({last_cpu:.0f}%) - راقب الحالة',
                'risk_percent': 30
            }
        else:
            return {
                'status': 'good',
                'message': f'✅ CPU مستقر ({last_cpu:.0f}%)',
                'risk_percent': 0
            }
    
    def predict_port_overload(self, port_stats=None):
        """
        توقع ازدحام المنافذ
        """
        # استخدام بيانات من interfaces
        from .switch_inspector import get_interfaces_detail
        
        try:
            interfaces = get_interfaces_detail(self.ip, self.community)
            
            overloaded_ports = []
            for iface in interfaces:
                traffic_mbps = iface.get('traffic_mbps', 0)
                speed_bps = iface.get('speed_bps', 1000000000)
                
                # حساب نسبة الاستخدام
                if speed_bps > 0:
                    utilization = (traffic_mbps * 1_000_000) / speed_bps * 100
                else:
                    utilization = 0
                
                if utilization > 80:
                    overloaded_ports.append({
                        'port': iface['name'],
                        'utilization': round(utilization, 1),
                        'severity': 'critical' if utilization > 95 else 'warning',
                        'message': f'ازدحام شديد - استخدم {utilization:.0f}% من السعة',
                        'fix': 'قم بترقية الـ link أو توزيع الحمل'
                    })
                elif utilization > 60:
                    overloaded_ports.append({
                        'port': iface['name'],
                        'utilization': round(utilization, 1),
                        'severity': 'info',
                        'message': f'استخدام عالي ({utilization:.0f}%) - قم بالتخطيط للترقية',
                        'fix': 'راقب الـ traffic وخطط للترقية'
                    })
            
            return {
                'has_overload': len([p for p in overloaded_ports if p['severity'] == 'critical']) > 0,
                'overloaded_ports': overloaded_ports,
                'count': len(overloaded_ports)
            }
        except Exception as e:
            return {'has_overload': False, 'overloaded_ports': [], 'error': str(e)}
    
    def predict_broadcast_storm(self):
        """
        توقع عواصف البث (Broadcast Storms)
        """
        from .switch_inspector import get_interfaces_detail
        
        try:
            interfaces = get_interfaces_detail(self.ip, self.community)
            
            # حساب نسبة البث مقابل البيانات العادية
            # (تقديرية بناءً على drops و errors)
            warnings = []
            
            for iface in interfaces:
                in_discards = iface.get('in_discards', 0)
                in_errors = iface.get('in_errors', 0)
                
                # زيادة مفاجئة في الـ discards قد تشير إلى Broadcast Storm
                if in_discards > 500:
                    warnings.append({
                        'port': iface['name'],
                        'severity': 'critical',
                        'message': f'⚠️ احتمال وجود Broadcast Storm - {in_discards} dropped packets',
                        'fix': 'افحص وجود Loop في الشبكة أو جهاز مصاب بفيروس'
                    })
                elif in_discards > 100:
                    warnings.append({
                        'port': iface['name'],
                        'severity': 'warning',
                        'message': f'عدد كبير من الـ drops ({in_discards}) - راقب الوضع',
                        'fix': 'افحص الـ traffic باستخدام wireshark'
                    })
            
            return {
                'has_storm_risk': len([w for w in warnings if w['severity'] == 'critical']) > 0,
                'warnings': warnings,
                'count': len(warnings)
            }
        except Exception as e:
            return {'has_storm_risk': False, 'warnings': [], 'error': str(e)}
    
    def get_full_prediction(self):
        """
        الحصول على توقع كامل لجميع المخاطر
        """
        return {
            'cable': self.predict_cable_failure(),
            'cpu': self.predict_cpu_crash(),
            'ports': self.predict_port_overload(),
            'broadcast': self.predict_broadcast_storm(),
            'timestamp': time.time()
        }


# ============================================
# Duplex Mismatch Detection
# ============================================

def detect_duplex_mismatch(ip, community):
    """
    اكتشاف عدم تطابق الـ Duplex بين السويتش والجهاز المتصل
    """
    from .switch_inspector import get_interfaces_detail, get_cdp_neighbors
    
    OID_DUPLEX = "1.3.6.1.2.1.10.7.2.1.19"  # dot3StatsDuplex
    # 1 = Half, 2 = Full
    
    try:
        duplex_values = snmp_walk(ip, community, OID_DUPLEX) or []
        interfaces = get_interfaces_detail(ip, community)
        cdp_neighbors = get_cdp_neighbors(ip, community)
        
        # بناء mapping للمنافذ من CDP
        cdp_port_map = {}
        for nbr in cdp_neighbors:
            cdp_port_map[nbr.get('local_port', '')] = nbr
        
        mismatches = []
        
        for i, iface in enumerate(interfaces):
            if i < len(duplex_values):
                duplex_val = int(str(duplex_values[i]).strip()) if duplex_values[i] else 2
                
                # Half duplex قد يشير إلى مشكلة
                if duplex_val == 1:
                    local_port = iface['name']
                    neighbor = cdp_port_map.get(local_port, {})
                    
                    mismatches.append({
                        'port': local_port,
                        'local_duplex': 'Half',
                        'remote_device': neighbor.get('device_id', 'Unknown'),
                        'severity': 'critical',
                        'issue': 'المنفذ يعمل بـ Half Duplex مما يسبب تصادمات (Collisions)',
                        'fix': 'غيّر إعدادات الـ duplex إلى Auto أو Full على كلا الطرفين'
                    })
        
        return {
            'has_mismatch': len(mismatches) > 0,
            'mismatches': mismatches,
            'count': len(mismatches)
        }
    except Exception as e:
        return {'has_mismatch': False, 'mismatches': [], 'error': str(e)}