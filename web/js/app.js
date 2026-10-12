/**
 * RouterPilot Control Plane v1.0
 * Frontend Orchestrator & State Manager
 */

const state = {
  activeTab: 'dashboard',
  router: null,
  discovery: null,
  currentPlan: null,
  wans: [],
  profiles: [],
  proxyEnabled: false,
  pollTimer: null,
};

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initEventListeners();
  loadInitialData();
  startHealthPolling();
});

// Navigation Handling
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const targetTab = item.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });
}

function switchTab(tabId) {
  state.activeTab = tabId;

  // Update nav item active classes
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-tab') === tabId);
  });

  // Update tab pane active classes
  document.querySelectorAll('.tab-pane').forEach(el => {
    el.classList.toggle('active', el.id === `tab-${tabId}`);
  });

  // Refresh tab-specific data if needed
  if (tabId === 'discovery') loadDiscoveryData();
  if (tabId === 'profiles') loadProfiles();
  if (tabId === 'audit') loadAuditLogs();
  if (tabId === 'ai') runAIAnalysis();
}

// Event Listeners for actions
function initEventListeners() {
  // Emergency Backup Button
  document.getElementById('btn-quick-backup')?.addEventListener('click', triggerQuickBackup);

  // Manual Failover Button
  document.getElementById('btn-manual-failover')?.addEventListener('click', toggleManualFailover);

  // Plan Dry-Run & Apply Buttons
  document.getElementById('btn-dry-run')?.addEventListener('click', executeDryRun);
  document.getElementById('btn-apply-plan')?.addEventListener('click', executeApplyPlan);

  // AI Chat send
  document.getElementById('btn-ai-send')?.addEventListener('click', sendAIMessage);
  document.getElementById('input-ai-prompt')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendAIMessage();
  });
}

// Initial Data Fetch
async function loadInitialData() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    updateConnectionBadge(data.connected);

    // Initial Discovery
    await loadDiscoveryData();
  } catch (err) {
    console.error('Failed to load status:', err);
  }
}

// Discovery Data Loader
async function loadDiscoveryData() {
  try {
    const res = await fetch('/api/discovery');
    if (!res.ok) return;
    const data = await res.json();
    state.discovery = data;
    renderDiscoveryView(data);
    renderDashboardOverview(data);
  } catch (err) {
    console.error('Discovery load failed:', err);
  }
}

// Health Polling (Every 3 seconds)
function startHealthPolling() {
  state.pollTimer = setInterval(async () => {
    try {
      const res = await fetch('/api/wan/health');
      if (!res.ok) return;
      const report = await res.json();
      updateWANHealthUI(report);
    } catch (err) {
      // Ignore network errors in polling
    }
  }, 3000);
}

// Update Topbar and Status
function updateConnectionBadge(connected) {
  const badge = document.getElementById('router-status-badge');
  if (!badge) return;
  if (connected) {
    badge.innerHTML = `<span class="status-dot"></span><span>روتر متصل (ROS 7.15)</span>`;
  } else {
    badge.innerHTML = `<span class="status-dot" style="background:#ef4444;box-shadow:0 0 10px #ef4444;"></span><span>قطع ارتباط</span>`;
  }
}

// Render Dashboard Overview Cards
function renderDashboardOverview(disc) {
  if (!disc || !disc.router) return;

  const r = disc.router;
  document.getElementById('val-router-model').innerText = r.Model || 'RB5009UG+S+IN';
  document.getElementById('val-router-arch').innerText = `${r.Architecture} (${r.CPUCount} Cores)`;
  document.getElementById('val-cpu-load').innerText = `${r.CPULoadPercent}%`;
  
  const ramFreeMB = Math.round(r.RAMFreeBytes / (1024 * 1024));
  const ramTotalMB = Math.round(r.RAMTotalBytes / (1024 * 1024));
  document.getElementById('val-ram-usage').innerText = `${ramFreeMB} MB آزاد از ${ramTotalMB} MB`;

  document.getElementById('val-uptime').innerText = r.Uptime || '14d 06:42:19';
}

// Render WAN Health UI
function updateWANHealthUI(report) {
  if (!report || !report.WANProbes) return;

  const probes = report.WANProbes;
  if (probes.length >= 2) {
    const wan1 = probes[0];
    const wan2 = probes[1];

    // WAN 1 (MobinNet)
    const elWan1 = document.getElementById('wan1-card');
    if (elWan1) {
      elWan1.classList.toggle('active-wan', wan1.IsDefaultRoute);
      document.getElementById('wan1-latency').innerText = `${wan1.LatencyMs} ms`;
      document.getElementById('wan1-badge').className = `wan-card-badge ${wan1.IsDefaultRoute ? 'badge-active' : 'badge-standby'}`;
      document.getElementById('wan1-badge').innerText = wan1.IsDefaultRoute ? 'فعال (Default Route)' : 'آماده‌باش (Standby)';
    }

    // WAN 2 (TCT)
    const elWan2 = document.getElementById('wan2-card');
    if (elWan2) {
      elWan2.classList.toggle('active-wan', wan2.IsDefaultRoute);
      document.getElementById('wan2-latency').innerText = `${wan2.LatencyMs} ms`;
      document.getElementById('wan2-badge').className = `wan-card-badge ${wan2.IsDefaultRoute ? 'badge-active' : 'badge-standby'}`;
      document.getElementById('wan2-badge').innerText = wan2.IsDefaultRoute ? 'فعال (Default Route)' : 'آماده‌باش (Standby)';
    }

    document.getElementById('val-active-wan').innerText = report.ActiveWAN;
  }
}

// Quick Failover Action
async function toggleManualFailover() {
  const currentActive = document.getElementById('val-active-wan')?.innerText || '';
  const newTarget = currentActive.includes('MobinNet') ? 'WAN-2 (TCT)' : 'WAN-1 (MobinNet)';

  if (!confirm(`آیا از سوئیچ دستی خط اینترنت به «${newTarget}» اطمینان دارید؟`)) return;

  try {
    const res = await fetch('/api/wan/failover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_wan: newTarget }),
    });
    const data = await res.json();
    if (data.success) {
      alert(`✅ سوئیچ با موفقیت انجام شد. گیت‌وی فعال اکنون: ${newTarget}`);
    }
  } catch (err) {
    alert('خطا در سوئیچ خط: ' + err.message);
  }
}

// Quick Backup Action
async function triggerQuickBackup() {
  try {
    const res = await fetch('/api/backup', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alert(`🛡️ فایل بک‌آپ اضطراری با نام «${data.name}» با موفقیت روی روتر ذخیره شد.`);
    }
  } catch (err) {
    alert('خطا در ایجاد بک‌آپ: ' + err.message);
  }
}

// Render Discovery View
function renderDiscoveryView(disc) {
  const tableBody = document.getElementById('interfaces-table-body');
  if (!tableBody || !disc.Interfaces) return;

  tableBody.innerHTML = disc.Interfaces.map(iface => `
    <tr>
      <td class="font-mono"><strong>${iface.Name}</strong></td>
      <td><span class="status-badge">${iface.Type}</span></td>
      <td>
        <span class="status-dot" style="background:${iface.Running ? '#10b981' : '#64748b'};box-shadow:none;"></span>
        ${iface.Running ? 'متصل' : 'قطع'}
      </td>
      <td class="font-mono">${iface.IPAddresses && iface.IPAddresses.length ? iface.IPAddresses.join(', ') : '-'}</td>
      <td class="font-mono">${iface.MAC}</td>
      <td style="color:var(--text-muted);">${iface.Comment || '-'}</td>
    </tr>
  `).join('');

  // Container Info card
  const cont = disc.Container;
  const contEl = document.getElementById('container-status-box');
  if (contEl && cont) {
    contEl.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <h4>وضعیت کانتینر: <span style="color:#10b981;">${cont.Status || 'در حال اجرا (Running)'}</span></h4>
          <p style="color:var(--text-muted); font-size:0.85rem; margin-top:4px;">ایمیج: ${cont.Image || 'metacubex/mihomo:latest'} | مسیر: ${cont.RootDir || 'usb1/mihomo'}</p>
        </div>
        <a href="http://172.16.20.1:9090/ui" target="_blank" class="btn btn-outline" style="font-size:0.8rem;">
          🚀 باز کردن پنل MetaCubeX
        </a>
      </div>
    `;
  }
}

// Load Profiles & Render
async function loadProfiles() {
  try {
    const res = await fetch('/api/profiles');
    const profiles = await res.json();
    state.profiles = profiles;

    const grid = document.getElementById('profiles-grid');
    if (!grid) return;

    grid.innerHTML = profiles.map(p => `
      <div class="glass-panel stat-card" style="display:flex; flex-direction:column; justify-content:space-between;">
        <div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <span class="status-badge" style="color:var(--primary);">${p.Category}</span>
            <span style="font-size:0.75rem; color:var(--text-muted);">v${p.Version}</span>
          </div>
          <h3 style="margin-bottom:8px; font-size:1.1rem; color:#fff;">${p.TitleFa}</h3>
          <p style="color:var(--text-muted); font-size:0.86rem; line-height:1.5; margin-bottom:16px;">${p.Description}</p>
        </div>
        <button class="btn btn-primary" onclick="compileProfileToPlan('${p.ID}')" style="width:100%;">
          ⚡ ساخت Plan اجرایی
        </button>
      </div>
    `).join('');
  } catch (err) {
    console.error('Error loading profiles:', err);
  }
}

// Compile Profile into Plan
async function compileProfileToPlan(profileId) {
  try {
    const res = await fetch('/api/plan/compile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: profileId }),
    });
    const plan = await res.json();
    state.currentPlan = plan;
    switchTab('plan');
    renderPlanView(plan);
  } catch (err) {
    alert('خطا در تولید Plan: ' + err.message);
  }
}

// Render Plan in Plan Builder
function renderPlanView(plan) {
  if (!plan) return;

  document.getElementById('plan-title').innerText = plan.Name;
  document.getElementById('plan-status-badge').innerText = `وضعیت: ${plan.Status}`;

  const tbody = document.getElementById('plan-steps-table-body');
  if (!tbody || !plan.Steps) return;

  tbody.innerHTML = plan.Steps.map((step, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td>
        <span class="status-badge diff-${step.Action}">${step.Action.toUpperCase()}</span>
      </td>
      <td class="font-mono">${step.TargetResource}</td>
      <td class="font-mono" style="font-size:0.82rem; color:#38bdf8;">${step.NativeCommand}</td>
      <td>${step.Description}</td>
      <td>
        <span class="${step.RiskLevel === 'critical' ? 'risk-critical' : 'risk-low'}">
          ${step.RiskLevel === 'critical' ? '⚠️ حیاتی' : 'عادی'}
        </span>
      </td>
      <td>
        <span class="status-dot" style="background:${step.Applied ? '#10b981' : '#64748b'};box-shadow:none;"></span>
      </td>
    </tr>
  `).join('');
}

// Execute Dry Run
async function executeDryRun() {
  if (!state.currentPlan) {
    alert('لطفاً ابتدا یک پروفایل برای تولید Plan انتخاب کنید.');
    return;
  }

  try {
    const res = await fetch('/api/plan/dry-run', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alert('✅ شبیه‌سازی Dry-Run با موفقیت انجام شد. تمام چک‌های ایمنی و Zero-Lockout تأیید شدند.');
      renderPlanView(data.plan);
    }
  } catch (err) {
    alert('خطا در Dry-Run: ' + err.message);
  }
}

// Execute Apply Plan
async function executeApplyPlan() {
  if (!state.currentPlan) return;

  if (!confirm('آیا از اعمال این تغییرات روی روتر اطمینان دارید؟ سیستم قبل از اجرا یک بک‌آپ کامل تهیه خواهد کرد.')) {
    return;
  }

  try {
    const res = await fetch('/api/plan/apply', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alert('🎉 تمام مراحل Plan با موفقیت روی روتر اجرا و ثبت شدند!');
      renderPlanView(data.plan);
    } else {
      alert('❌ خطا در اجرا: ' + data.error);
    }
  } catch (err) {
    alert('خطا در اجرای تغییرات: ' + err.message);
  }
}

// AI Advisor Analysis
async function runAIAnalysis() {
  try {
    const res = await fetch('/api/ai/analyze', { method: 'POST' });
    const data = await res.json();
    
    document.getElementById('ai-health-score').innerText = `${data.HealthScore} / 100`;
    document.getElementById('ai-summary-text').innerText = data.Summary;

    const findingsContainer = document.getElementById('ai-findings-list');
    if (findingsContainer && data.Findings) {
      findingsContainer.innerHTML = data.Findings.map(f => `
        <div class="glass-panel" style="padding:14px 18px; margin-bottom:12px; border-right:4px solid ${f.Level === 'warning' ? '#f59e0b' : '#06b6d4'};">
          <h4 style="color:#fff; margin-bottom:4px;">${f.Title}</h4>
          <p style="color:var(--text-muted); font-size:0.88rem; margin-bottom:6px;">${f.Description}</p>
          <div style="font-size:0.84rem; color:#38bdf8;"><strong>💡 راه‌حل پیشنهادی:</strong> ${f.Solution}</div>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error('AI Analysis failed:', err);
  }
}

// AI Message Sender
async function sendAIMessage() {
  const input = document.getElementById('input-ai-prompt');
  const prompt = input.value.trim();
  if (!prompt) return;

  const chatContainer = document.getElementById('chat-messages');
  chatContainer.innerHTML += `
    <div class="chat-bubble user">${prompt}</div>
  `;
  input.value = '';
  chatContainer.scrollTop = chatContainer.scrollHeight;

  try {
    const res = await fetch('/api/ai/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt }),
    });
    const data = await res.json();
    chatContainer.innerHTML += `
      <div class="chat-bubble bot">${data.answer}</div>
    `;
    chatContainer.scrollTop = chatContainer.scrollHeight;
  } catch (err) {
    chatContainer.innerHTML += `
      <div class="chat-bubble bot" style="color:#ef4444;">خطا در دریافت پاسخ: ${err.message}</div>
    `;
  }
}

// Audit Logs Loader
async function loadAuditLogs() {
  try {
    const res = await fetch('/api/audit/logs');
    const logs = await res.json();
    const tbody = document.getElementById('audit-table-body');
    if (!tbody) return;

    tbody.innerHTML = logs.map(l => `
      <tr>
        <td class="font-mono" style="font-size:0.8rem;">${new Date(l.Timestamp).toLocaleTimeString('fa-IR')}</td>
        <td><span class="status-badge">${l.Category}</span></td>
        <td><span class="status-badge" style="color:${l.Level === 'error' ? '#ef4444' : l.Level === 'warning' ? '#f59e0b' : '#10b981'};">${l.Level}</span></td>
        <td>${l.Message}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load logs:', err);
  }
}
