# إضافات Port Events & Diagnostics

## 1. إضافة الزر في القائمة اليسرى (بعد Port Security)

```html
<button class="tool-btn" onclick="showTool('portevents')" id="btn-portevents">
  <span class="tb-icon">📊</span> Port Events
  <span class="tb-badge warn" id="portevents-badge" style="display:none">!</span>
</button>
```

## 2. إضافة View جديد في main-area (قبل </div><!-- /main-area -->)

```html
<!-- ── PORT EVENTS & DIAGNOSTICS ── -->
<div id="view-portevents" style="display:none">
  <div class="st">◈ PORT EVENTS & DIAGNOSTICS</div>
  
  <!-- Time range selector -->
  <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;align-items:center">
    <span style="font-family:var(--mono);font-size:10px;color:var(--dim)">الفترة الزمنية:</span>
    <button class="tab active" onclick="peSetRange(1,this)">آخر ساعة</button>
    <button class="tab" onclick="peSetRange(6,this)">6 ساعات</button>
    <button class="tab" onclick="peSetRange(24,this)">24 ساعة</button>
    <button class="tab" onclick="peSetRange(168,this)">7 أيام</button>
    <button class="search-btn" onclick="loadPortEvents()" 
      style="background:var(--bg3);color:var(--accent);border:1px solid var(--accent);margin-left:auto">↻ تحديث</button>
  </div>
  
  <!-- Summary cards -->
  <div id="pe-cards" class="cards-grid" style="margin-bottom:14px"></div>
  
  <!-- Tabs -->
  <div class="tab-bar" style="margin-bottom:12px">
    <button class="tab active" onclick="peTab('flaps',this)">🔄 Flaps (فصل/وصل)</button>
    <button class="tab" onclick="peTab('errors',this)">⚠ أخطاء المنافذ</button>
    <button class="tab" onclick="peTab('down',this)">🔴 منافذ Down</button>
    <button class="tab" onclick="peTab('diag',this)">🔬 تشخيص شامل</button>
  </div>
  
  <div id="pe-content"></div>
</div>
```

## 3. تحديث showTool function

استبدل السطر:
```javascript
['welcome','mac','ping','ifaces','vlans','stp','duplex','poe','cdp','vlan-ts','env','psec']
```

بـ:
```javascript
['welcome','mac','ping','ifaces','vlans','stp','duplex','poe','cdp','vlan-ts','env','psec','portevents']
```

## 4. تحديث loaders object

أضف:
```javascript
portevents: loadPortEvents,
```

## 5. إضافة JavaScript functions (قبل </script>)

```javascript
// ════════════════════════════════════════════════════════
//  PORT EVENTS & DIAGNOSTICS
// ════════════════════════════════════════════════════════
let _peHours = 1;
let _peTab   = 'flaps';
let _peData  = null;

function peSetRange(h, btn){
  _peHours = h;
  document.querySelectorAll('#view-portevents > div:first-of-type .tab')
    .forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  loadPortEvents();
}

function peTab(t, btn){
  _peTab = t;
  document.querySelectorAll('#view-portevents .tab-bar .tab')
    .forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  if(_peData) renderPeTab();
}

async function loadPortEvents(){
  if(!CURRENT_SW) return;
  const content = $('pe-content'), cards = $('pe-cards');
  spin(content); cards.innerHTML='';
  try{
    const d = await API(`port-events/${CURRENT_SW.id}/?hours=${_peHours}`);
    _peData = d;
    
    // Update badge
    const badge = $('portevents-badge');
    if(d.summary.critical_ports > 0){
      badge.style.display='inline'; 
      badge.textContent=d.summary.critical_ports;
    } else badge.style.display='none';
    
    // Render cards
    cards.innerHTML=`
      <div class="info-card">
        <div class="ic-label">إجمالي الأحداث</div>
        <div class="ic-value" style="color:var(--accent)">${d.summary.total_events}</div>
        <div class="ic-sub">آخر ${_peHours}h</div>
      </div>
      <div class="info-card">
        <div class="ic-label">منافذ فصلت</div>
        <div class="ic-value" style="color:${d.summary.flapped_ports>0?'var(--warn)':'var(--ok)'}">${d.summary.flapped_ports}</div>
        <div class="ic-sub">port flaps</div>
      </div>
      <div class="info-card">
        <div class="ic-label">منافذ حرجة</div>
        <div class="ic-value" style="color:${d.summary.critical_ports>0?'var(--danger)':'var(--ok)'}">${d.summary.critical_ports}</div>
        <div class="ic-sub">≥5 flaps أو أخطاء عالية</div>
      </div>
      <div class="info-card">
        <div class="ic-label">إجمالي Downtime</div>
        <div class="ic-value" style="font-size:14px">${fmtSec(d.summary.total_down_sec)}</div>
        <div class="ic-sub">وقت الانقطاع</div>
      </div>
      <div class="info-card">
        <div class="ic-label">منافذ بأخطاء</div>
        <div class="ic-value" style="color:${d.summary.error_ports>0?'var(--warn)':'var(--ok)'}">${d.summary.error_ports}</div>
        <div class="ic-sub">CRC / Input errors</div>
      </div>
      <div class="info-card">
        <div class="ic-label">منافذ Down الآن</div>
        <div class="ic-value" style="color:${d.summary.down_now>0?'var(--danger)':'var(--ok)'}">${d.summary.down_now}</div>
        <div class="ic-sub">notconnect</div>
      </div>`;
    
    renderPeTab();
  }catch(e){ 
    err(content,'خطأ في تحميل البيانات: '+e.message); 
  }
}

function fmtSec(s){
  if(!s) return '0s';
  if(s<60) return s+'s';
  if(s<3600) return Math.floor(s/60)+'m '+(s%60)+'s';
  return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
}

function renderPeTab(){
  const d = _peData;
  const content = $('pe-content');
  if(_peTab==='flaps')   renderPeFlaps(d, content);
  if(_peTab==='errors')  renderPeErrors(d, content);
  if(_peTab==='down')    renderPeDown(d, content);
  if(_peTab==='diag')    renderPeDiag(d, content);
}

function renderPeFlaps(d, wrap){
  const ports = d.flap_ports || [];
  if(!ports.length){
    wrap.innerHTML='<div class="empty-state" style="color:var(--ok)">✓ لا توجد أحداث فصل/وصل في هذه الفترة</div>';
    return;
  }
  
  wrap.innerHTML=`
    <div style="font-family:var(--mono);font-size:10px;color:var(--dim);margin-bottom:8px">
      ${ports.length} منفذ سُجِّل له أحداث فصل/وصل
    </div>
    <table class="data-table">
      <thead><tr>
        <th>المنفذ</th><th>عدد الفصل</th><th>إجمالي Downtime</th>
        <th>متوسط مدة الفصل</th><th>آخر حدث</th><th>الحالة</th><th>التشخيص</th>
      </tr></thead>
      <tbody>${ports.map(p=>{
        const sev = p.flap_count>=10?'critical':p.flap_count>=5?'warning':'info';
        return`<tr>
          <td style="font-family:var(--mono);color:var(--accent)">${p.interface}</td>
          <td style="color:${p.flap_count>=5?'var(--danger)':'var(--warn)'};
              font-family:var(--mono);font-weight:700">${p.flap_count}x</td>
          <td style="font-family:var(--mono)">${fmtSec(p.total_down_sec)}</td>
          <td style="font-family:var(--mono);color:var(--dim)">${fmtSec(p.avg_down_sec)}</td>
          <td style="font-size:10px;color:var(--dim)">${p.last_event?new Date(p.last_event).toLocaleString('ar-EG'):'—'}</td>
          <td>${badge(sev==='critical'?'حرج':sev==='warning'?'تحذير':'معلومة',sev)}</td>
          <td style="font-size:10px;color:var(--dim)">${(p.diagnoses||[]).join(' | ')||'—'}</td>
        </tr>`;
      }).join('')}</tbody>
    </table>
    ${ports.filter(p=>p.flap_count>=5).length?`
    <div class="st" style="margin:14px 0 8px">⚠ توصيات للمنافذ الحرجة</div>`+
    ports.filter(p=>p.flap_count>=5).map(p=>`
      <div class="issue-item ${p.flap_count>=10?'critical':'warning'}">
        <div class="issue-sev ${p.flap_count>=10?'critical':'warning'}"></div>
        <div class="issue-body">
          <div class="issue-msg"><strong>${p.interface}</strong> — فصل ${p.flap_count} مرة، downtime: ${fmtSec(p.total_down_sec)}</div>
          ${(p.fixes||[]).map(f=>`<div class="issue-fix" style="color:var(--accent2)">→ ${f}</div>`).join('')}
        </div>
      </div>`).join(''):''}`;  
}

function renderPeErrors(d, wrap){
  const ports = d.error_ports || [];
  if(!ports.length){
    wrap.innerHTML='<div class="empty-state" style="color:var(--ok)">✓ لا توجد منافذ بأخطاء مرتفعة</div>';
    return;
  }
  
  wrap.innerHTML=`
    <table class="data-table">
      <thead><tr>
        <th>المنفذ</th><th>In Errors</th><th>Out Errors</th><th>CRC</th>
        <th>Discards</th><th>السرعة</th><th>التشخيص</th>
      </tr></thead>
      <tbody>${ports.map(p=>`<tr>
        <td style="font-family:var(--mono);color:var(--accent)">${p.name}</td>
        <td style="color:${p.in_errors>1000?'var(--danger)':p.in_errors>100?'var(--warn)':'var(--dim)'}">${p.in_errors}</td>
        <td style="color:${p.out_errors>500?'var(--danger)':p.out_errors>50?'var(--warn)':'var(--dim)'}">${p.out_errors}</td>
        <td style="color:${p.crc>100?'var(--danger)':'var(--dim)'}">${p.crc||0}</td>
        <td style="color:${(p.in_discards+p.out_discards)>100?'var(--warn)':'var(--dim)'}">${p.in_discards+p.out_discards}</td>
        <td style="font-family:var(--mono)">${p.speed_str}</td>
        <td style="font-size:10px;color:var(--dim)">${p.diagnosis||'—'}</td>
      </tr>`).join('')}</tbody>
    </table>`;
}

function renderPeDown(d, wrap){
  const ports = d.down_ports || [];
  if(!ports.length){
    wrap.innerHTML='<div class="empty-state" style="color:var(--ok)">✓ جميع المنافذ المتوقع اتصالها تعمل</div>';
    return;
  }
  
  wrap.innerHTML=`
    <div style="font-family:var(--mono);font-size:10px;color:var(--dim);margin-bottom:8px">
      ${ports.length} منفذ في حالة Down
    </div>
    <table class="data-table">
      <thead><tr>
        <th>المنفذ</th><th>الحالة</th><th>آخر MAC</th><th>VLAN</th><th>PoE</th><th>ملاحظة</th>
      </tr></thead>
      <tbody>${ports.map(p=>`<tr>
        <td style="font-family:var(--mono);color:var(--accent)">${p.name}</td>
        <td>${badge(p.status==='disabled'?'معطل':'غير متصل',p.status==='disabled'?'off':'critical')}</td>
        <td style="font-family:var(--mono);font-size:10px;color:var(--dim)">${p.last_mac||'—'}</td>
        <td>${p.vlan?badge('VLAN '+p.vlan,'info'):'—'}</td>
        <td style="color:${p.poe_fault?'var(--danger)':'var(--dim)'}">${p.poe_fault?'⚠ خطأ PoE':'—'}</td>
        <td style="font-size:10px;color:var(--dim)">${p.note||'—'}</td>
      </tr>`).join('')}</tbody>
    </table>`;
}

function renderPeDiag(d, wrap){
  const diags = d.diagnostics || [];
  if(!diags.length){
    wrap.innerHTML='<div class="empty-state" style="color:var(--ok)">✓ لا توجد مشاكل مكتشفة</div>';
    return;
  }
  
  wrap.innerHTML = diags.map(item=>`
    <div class="issue-item ${item.severity}" style="margin-bottom:6px">
      <div class="issue-sev ${item.severity}"></div>
      <div class="issue-body">
        <div class="issue-msg">
          <strong>${item.port}</strong>
          <span style="font-size:9px;color:var(--dim);margin-left:8px">${item.category}</span>
        </div>
        <div class="issue-fix" style="color:var(--warn);margin-top:2px">▸ ${item.problem}</div>
        ${(item.fixes||[]).map(f=>`<div class="issue-fix" style="color:var(--accent2)">→ ${f}</div>`).join('')}
        ${item.metrics?`<div style="font-size:9px;color:var(--dim);margin-top:3px;font-family:var(--mono)">${item.metrics}</div>`:''}
      </div>
    </div>`).join('');
}
```

## 6. API Endpoint في views.py

أضف هذه الدالة:

```python
@require_GET
def api_port_events(request, switch_id):
    """
    GET /api/port-events/<switch_id>/?hours=24
    تحليل شامل لأحداث المنافذ والمشاكل
    """
    from django.utils import timezone
    from datetime import timedelta
    from django.db.models import Count, Sum, Max
    
    sw = _sw(switch_id)
    hours = int(request.GET.get('hours', 24))
    start_time = timezone.now() - timedelta(hours=hours)
    
    # جلب بيانات المنافذ الحالية
    ifaces = get_interfaces_detail(sw.ip_address, sw.snmp_community)
    
    # Port Flapping Events
    flap_events = PortFlapEvent.objects.filter(
        switch=sw,
        timestamp__gte=start_time
    ).values('interface__name').annotate(
        flap_count=Count('id'),
        total_down=Sum('duration_seconds'),
        last_event=Max('timestamp')
    ).order_by('-flap_count')
    
    flap_ports = []
    for fe in flap_events:
        avg_down = fe['total_down'] / fe['flap_count'] if fe['flap_count'] > 0 else 0
        
        # تشخيص السبب
        diagnoses = []
        fixes = []
        
        if fe['flap_count'] >= 10:
            diagnoses.append('كابل تالف')
            fixes.append('استبدال الكابل فوراً')
        elif fe['flap_count'] >= 5:
            diagnoses.append('مشكلة في الاتصال')
            fixes.append('فحص الكابل والموصلات')
        
        if fe['total_down'] > 600:
            diagnoses.append('انقطاع طويل')
            fixes.append('فحص الجهاز المتصل')
        
        if fe['flap_count'] > 0:
            fixes.append('تغيير Duplex إلى Auto')
            fixes.append('فحص وجود Loop')
        
        flap_ports.append({
            'interface': fe['interface__name'],
            'flap_count': fe['flap_count'],
            'total_down_sec': fe['total_down'] or 0,
            'avg_down_sec': int(avg_down),
            'last_event': fe['last_event'].isoformat() if fe['last_event'] else None,
            'diagnoses': diagnoses,
            'fixes': fixes
        })
    
    # Error Ports
    error_ports = []
    for ifc in ifaces:
        if ifc['status'] == 'connected' and (ifc['in_errors'] > 100 or ifc['out_errors'] > 50):
            diagnosis = []
            if ifc['in_errors'] > 1000:
                diagnosis.append('CRC errors حرجة')
            elif ifc['in_errors'] > 100:
                diagnosis.append('Duplex mismatch محتمل')
            
            if ifc['out_errors'] > 500:
                diagnosis.append('Congestion')
            
            error_ports.append({
                'name': ifc['name'],
                'in_errors': ifc['in_errors'],
                'out_errors': ifc['out_errors'],
                'crc': ifc.get('crc_errors', 0),
                'in_discards': ifc['in_discards'],
                'out_discards': ifc['out_discards'],
                'speed_str': ifc['speed_str'],
                'diagnosis': ' | '.join(diagnosis) if diagnosis else 'أخطاء عالية'
            })
    
    # Down Ports
    down_ports = []
    for ifc in ifaces:
        if ifc['status'] in ['notconnect', 'disabled']:
            down_ports.append({
                'name': ifc['name'],
                'status': ifc['status'],
                'last_mac': None,  # يمكن جلبه من MAC table
                'vlan': ifc.get('vlan'),
                'poe_fault': False,  # يمكن جلبه من PoE data
                'note': 'تحقق من الجهاز المتصل' if ifc['status'] == 'notconnect' else 'المنفذ معطل'
            })
    
    # Comprehensive Diagnostics
    diagnostics = []
    
    # منافذ بـ flaps عالية
    for fp in flap_ports:
        if fp['flap_count'] >= 5:
            diagnostics.append({
                'port': fp['interface'],
                'category': 'Port Flapping',
                'severity': 'critical' if fp['flap_count'] >= 10 else 'warning',
                'problem': f'فصل {fp["flap_count"]} مرة خلال {hours} ساعة',
                'fixes': fp['fixes'],
                'metrics': f'Downtime: {fp["total_down_sec"]}s, Avg: {fp["avg_down_sec"]}s'
            })
    
    # منافذ بأخطاء عالية
    for ep in error_ports[:10]:  # أول 10 فقط
        if ep['in_errors'] > 1000 or ep['out_errors'] > 500:
            diagnostics.append({
                'port': ep['name'],
                'category': 'High Errors',
                'severity': 'critical' if ep['in_errors'] > 1000 else 'warning',
                'problem': ep['diagnosis'],
                'fixes': [
                    'فحص الكابل',
                    'تحقق من Duplex/Speed',
                    'استبدل الكابل إذا استمرت المشكلة'
                ],
                'metrics': f'In: {ep["in_errors"]}, Out: {ep["out_errors"]}, CRC: {ep["crc"]}'
            })
    
    # Summary
    summary = {
        'total_events': len(flap_events) + len(error_ports),
        'flapped_ports': len(flap_ports),
        'critical_ports': len([p for p in flap_ports if p['flap_count'] >= 5]) + 
                         len([p for p in error_ports if p['in_errors'] > 1000]),
        'total_down_sec': sum(p['total_down_sec'] for p in flap_ports),
        'error_ports': len(error_ports),
        'down_now': len(down_ports)
    }
    
    return _json({
        'summary': summary,
        'flap_ports': flap_ports,
        'error_ports': error_ports,
        'down_ports': down_ports[:20],  # أول 20 فقط
        'diagnostics': diagnostics
    })
```

## 7. إضافة URL في urls.py

```python
path('api/port-events/<int:switch_id>/', views.api_port_events, name='api_port_events'),
```

