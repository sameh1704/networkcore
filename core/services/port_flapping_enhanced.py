# core/services/port_flapping_enhanced.py
"""
Port Flapping Detection Service — Enhanced Version
═══════════════════════════════════════════════════════════════
المميزات:
  1. اكتشاف المنافذ التي تتغير حالتها (Up/Down) بشكل متكرر
  2. عرض عدد مرات التغيير في آخر ساعة / يوم
  3. اقتراح حلول (استبدال الكابل، تغيير الـ Duplex، فحص الجهاز المتصل)
  4. تحليل أسباب الـ Flapping
═══════════════════════════════════════════════════════════════
"""

from datetime import timedelta
from django.db.models import Count, Q
from django.utils import timezone
from collections import defaultdict

from core.models import Switch, PortSnapshot, PortEvent


# ═══════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════
FLAP_THRESHOLDS = {
    'hour': {'warning': 3, 'critical': 5},      #flaps per hour
    'day': {'warning': 10, 'critical': 20},     #flaps per day
}


# ═══════════════════════════════════════════════════════════
# 1. Get Flap Count for Time Period
# ═══════════════════════════════════════════════════════════
def get_flap_count(switch_id, interface_name=None, hours=1):
    """
    الحصول على عدد مرات الـ Flapping في آخر N ساعة
    
    Args:
        switch_id: معرف السويتش
        interface_name: اسم المنفذ (اختياري)
        hours: عدد الساعات
    
    Returns:
        dict: {port_name: flap_count}
    """
    since = timezone.now() - timedelta(hours=hours)
    
    #flap events = link_down events
    events = PortEvent.objects.filter(
        switch_id=switch_id,
        event_type='link_down',
        occurred_at__gte=since
    )
    
    if interface_name:
        events = events.filter(port_name=interface_name)
    
    flap_counts = events.values('port_name').annotate(
        count=Count('id')
    ).order_by('-count')
    
    return {item['port_name']: item['count'] for item in flap_counts}


# ═══════════════════════════════════════════════════════════
# 2. Get Flap Report (Hour/Day)
# ═══════════════════════════════════════════════════════════
def get_flap_report(switch_id=None, period='hour'):
    """
    تقرير شامل للـ Port Flapping
    
    Args:
        switch_id: معرف السويتش (اختياري، None = كل السويتشات)
        period: 'hour' أو 'day'
    
    Returns:
        list: قائمة المنافذ مع معلومات الـ Flapping
    """
    hours = 1 if period == 'hour' else 24
    since = timezone.now() - timedelta(hours=hours)
    
    # الحصول على كل أحداث الـ link_down
    events_query = PortEvent.objects.filter(
        event_type='link_down',
        occurred_at__gte=since
    )
    
    if switch_id:
        events_query = events_query.filter(switch_id=switch_id)
    
    # تجميع حسب السويتش والمنفذ
    flap_data = events_query.values(
        'switch__hostname', 'switch__ip_address', 'port_name'
    ).annotate(
        flap_count=Count('id'),
        first_flap=Min('occurred_at'),
        last_flap=Max('occurred_at')
    ).order_by('-flap_count')
    
    results = []
    thresholds = FLAP_THRESHOLDS.get(period, FLAP_THRESHOLDS['hour'])
    
    for item in flap_data:
        flap_count = item['flap_count']
        
        # تحديد الخطورة
        if flap_count >= thresholds['critical']:
            severity = 'critical'
        elif flap_count >= thresholds['warning']:
            severity = 'warning'
        else:
            severity = 'ok'
        
        # حساب وقت التوقف الإجمالي (تقريبي)
        # نفترض أن كل flap يعني انقطاع 1-5 دقائق
        total_down_time = flap_count * 180  # 3 دقائق متوسط
        
        results.append({
            'switch_hostname': item['switch__hostname'],
            'switch_ip': item['switch__ip_address'],
            'port_name': item['port_name'],
            'flap_count': flap_count,
            'severity': severity,
            'first_flap': item['first_flap'],
            'last_flap': item['last_flap'],
            'total_down_time_seconds': total_down_time,
            'suggestions': get_flap_suggestions(item['port_name'], flap_count)
        })
    
    return results


# ═══════════════════════════════════════════════════════════
# 3. Flap Suggestions (AI-powered recommendations)
# ═══════════════════════════════════════════════════════════
def get_flap_suggestions(port_name, flap_count):
    """
    اقتراح حلول بناءً على عدد الـ Flaps
    
    Args:
        port_name: اسم المنفذ
        flap_count: عدد مرات الـ Flapping
    
    Returns:
        list: قائمة الاقتراحات
    """
    suggestions = []
    port_type = port_name.lower()
    
    # تحليل نوع المنفذ
    is_access_port = any(x in port_type for x in ['fa', 'gi', 'et'])  # FastEthernet, GigabitEthernet, Ethernet
    
    if flap_count >= 10:
        # حالة حرجة
        suggestions.extend([
            {
                'priority': 'high',
                'title': 'استبدل الكابل',
                'description': 'الكابل قد يكون تالفاً أو هناك مشكلة في التوصيل',
                'action': 'استبدل كابل Ethernet واختبر مرة أخرى'
            },
            {
                'priority': 'high',
                'title': 'افحص المنافذ على الجانب الآخر',
                'description': 'المنفذ على الجهاز المتصل قد يكون تالفاً',
                'action': 'جرب منفذاً آخر على الجهاز المتصل'
            },
            {
                'priority': 'medium',
                'title': 'تحقق من مصدر الطاقة PoE',
                'description': 'إذا كان المنفذ يدعم PoE، قد يكون هناك مشكلة في الطاقة',
                'action': 'افحص طاقة PoE على المنفذ'
            }
        ])
    elif flap_count >= 5:
        # حالة تحذير
        suggestions.extend([
            {
                'priority': 'medium',
                'title': 'افحص جودة الكابل',
                'description': 'قد يكون الكابل قديماً أو غير مناسب',
                'action': 'استبدل الكابل بكابل جديد Category 6 أو أعلى'
            },
            {
                'priority': 'medium',
                'title': 'تحقق من إعدادات الـ Duplex',
                'description': 'قد يكون هناك عدم توافق في إعدادات الـ Duplex',
                'action': 'تأكد من أن إعدادات الـ Duplex متطابقة على كلا الجانبين'
            },
            {
                'priority': 'low',
                'title': 'افحص البيئة المحيطة',
                'description': 'التداخل الكهرومغناطيسي قد يسبب المشكلة',
                'action': 'تحقق من وجود مصادر تداخل قريبة'
            }
        ])
    else:
        # حالة خفيفة
        suggestions.append({
            'priority': 'low',
            'title': 'مراقبة مستمرة',
            'description': 'المنفذ يحتاج لمراقبة إضافية',
            'action': 'تابع حالة المنفذ خلال الـ 24 ساعة القادمة'
        })
    
    # اقتراحات خاصة بمنافذ معينة
    if 'poe' in port_type:
        suggestions.append({
            'priority': 'high',
            'title': 'فحص أجهزة PoE',
            'description': 'أجهزة PoE قد تستهلك طاقة زائدة',
            'action': 'تحقق من استهلاك طاقة أجهزة PoE المتصلة'
        })
    
    return suggestions


# ═══════════════════════════════════════════════════════════
# 4. Analyze Flap Pattern
# ═══════════════════════════════════════════════════════════
def analyze_flap_pattern(switch_id, port_name, days=7):
    """
    تحليل نمط الـ Flapping لتحديد السبب المحتمل
    
    Args:
        switch_id: معرف السويتش
        port_name: اسم المنفذ
        days: عدد الأيام للتحليل
    
    Returns:
        dict: تحليل النمط
    """
    since = timezone.now() - timedelta(days=days)
    
    events = PortEvent.objects.filter(
        switch_id=switch_id,
        port_name=port_name,
        event_type='link_down',
        occurred_at__gte=since
    ).order_by('occurred_at')
    
    if not events.exists():
        return {'pattern': 'no_data', 'message': 'لا توجد بيانات كافية'}
    
    # حساب الفترات بين الـ Flaps
    event_times = [e.occurred_at for e in events]
    intervals = []
    for i in range(1, len(event_times)):
        interval = (event_times[i-1] - event_times[i]).total_seconds()
        intervals.append(interval)
    
    if not intervals:
        return {'pattern': 'single', 'message': 'حدث واحد فقط'}
    
    avg_interval = sum(intervals) / len(intervals)
    min_interval = min(intervals)
    max_interval = max(intervals)
    
    # تحديد النمط
    if avg_interval < 300:  # أقل من 5 دقائق
        pattern = 'rapid'
        description = 'تذبذب سريع - احتمال مشكلة في الكابل أو المنافذ'
    elif avg_interval < 3600:  # أقل من ساعة
        pattern = 'intermittent'
        description = 'تقطع متقطع - احتمال تداخل أو مشكلة في التوصيل'
    elif max_interval - min_interval < 600:  # كل الـ intervals متقاربة
        pattern = 'periodic'
        description = 'تقطع دوري - احتمال وجود جهاز يتسبب في إعادة التشغيل'
    else:
        pattern = 'random'
        description = 'تقطع عشوائي - يحتاج لمراقبة إضافية'
    
    return {
        'pattern': pattern,
        'description': description,
        'total_events': len(event_times),
        'avg_interval_seconds': round(avg_interval, 1),
        'min_interval_seconds': round(min_interval, 1),
        'max_interval_seconds': round(max_interval, 1),
        'events': [
            {'time': e.occurred_at.isoformat(), 'description': e.description}
            for e in events[:10]  # آخر 10 أحداث
        ]
    }


# ═══════════════════════════════════════════════════════════
# 5. Get Port Health Score
# ═══════════════════════════════════════════════════════════
def get_port_health_score(switch_id, port_name, days=7):
    """
    حساب درجة صحة المنفذ بناءً على سجل الـ Flapping
    
    Args:
        switch_id: معرف السويتش
        port_name: اسم المنفذ
        days: عدد الأيام
    
    Returns:
        dict: درجة الصحة والسبب
    """
    since = timezone.now() - timedelta(days=days)
    
    #flap events
    flap_count = PortEvent.objects.filter(
        switch_id=switch_id,
        port_name=port_name,
        event_type='link_down',
        occurred_at__gte=since
    ).count()
    
    # CRC errors
    snapshots = PortSnapshot.objects.filter(
        switch_id=switch_id,
        port_name=port_name,
        recorded_at__gte=since
    ).order_by('-recorded_at')[:100]
    
    total_errors = sum(s.in_errors + s.out_errors for s in snapshots)
    
    # حساب الدرجة (100 = ممتاز، 0 = سيء)
    health_score = 100
    
    # خصم نقاط لكل flap
    health_score -= min(flap_count * 5, 50)  # max 50 points for flaps
    
    # خصم نقاط للأخطاء
    error_factor = min(total_errors / 1000, 30)  # max 30 points for errors
    health_score -= error_factor
    
    health_score = max(0, min(100, health_score))
    
    # تحديد الحالة
    if health_score >= 80:
        status = 'excellent'
    elif health_score >= 60:
        status = 'good'
    elif health_score >= 40:
        status = 'fair'
    else:
        status = 'poor'
    
    return {
        'score': round(health_score, 1),
        'status': status,
        'flap_count': flap_count,
        'total_errors': total_errors,
        'period_days': days
    }