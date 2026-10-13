/**
 * RouterPilot Control Plane v1.1
 * Modern Glass UI Orchestrator & State Manager
 */

const state = {
  activeTab: 'dashboard',
  router: null,
  discovery: null,
  currentPlan: null,
  wans: [
    { id: 'wan1', name: 'WAN-1', custom_name: 'اینترنت اول (اصلی)', interface: 'ether2', type: 'DHCP', latency_ms: 31, packet_loss: 0, is_default: true },
    { id: 'wan2', name: 'WAN-2', custom_name: 'اینترنت دوم (پشتیبان)', interface: 'ether1', type: 'DHCP', latency_ms: 18, packet_loss: 0, is_default: false },
  ],
  profiles: [],
  pollTimer: null,
};

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initEventListeners();
  loadInitialData();
  startHealthPolling();
  renderDynamicWANsTable();
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

  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-tab') === tabId);
  });

  document.querySelectorAll('.tab-pane').forEach(el => {
    el.classList.toggle('active', el.id === `tab-${tabId}`);
  });

  if (tabId === 'discovery') loadDiscoveryData();
  if (tabId === 'audit') loadAuditLogs();
}

function initEventListeners() {
  document.getElementById('btn-quick-backup')?.addEventListener('click', triggerQuickBackup);
  document.getElementById('btn-manual-failover')?.addEventListener('click', toggleManualFailover);
  document.getElementById('btn-dry-run')?.addEventListener('click', executeDryRun);
  document.getElementById('btn-apply-plan')?.addEventListener('click', executeApplyPlan);

  // Global Search Filter
  document.getElementById('global-search')?.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    filterContentBySearch(query);
  });

  // Theme Toggle
  document.getElementById('btn-theme-toggle')?.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
  });

  // AI Chat send
  document.getElementById('btn-ai-send')?.addEventListener('click', sendAIMessage);
  document.getElementById('input-ai-prompt')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendAIMessage();
  });
}

async function loadInitialData() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    updateConnectionBadge(data.connected);
    await loadDiscoveryData();
  } catch (err) {
    console.error('Failed to load status:', err);
  }
}

async function loadDiscoveryData() {
  try {
    const res = await fetch('/api/discovery');
    if (!res.ok) return;
    const data = await res.json();
    state.discovery = data;
    renderDiscoveryView(data);
  } catch (err) {
    console.error('Discovery load failed:', err);
  }
}

function startHealthPolling() {
  state.pollTimer = setInterval(async () => {
    try {
      const res = await fetch('/api/wan/health');
      if (!res.ok) return;
      const report = await res.json();
      updateDashboardTelemetry(report);
    } catch (err) {
      // Ignore network errors in polling
    }
  }, 3000);
}

function updateConnectionBadge(connected, simulatorMode = true) {
  const badge = document.getElementById('router-status-badge');
  const footerStatus = document.getElementById('sidebar-system-status');
  if (!badge) return;

  if (simulatorMode) {
    badge.style.color = 'var(--warning)';
    badge.innerHTML = `<span class="status-dot" style="background:#f59e0b; box-shadow:0 0 8px rgba(245,158,11,0.5);"></span><span>شبیه‌ساز امن (آفلاین)</span>`;
    if (footerStatus) footerStatus.innerText = 'حالت شبیه‌ساز آفلاین (امن)';
  } else if (connected) {
    badge.style.color = 'var(--success)';
    badge.innerHTML = `<span class="status-dot"></span><span>روتر متصل (آنلاین)</span>`;
    if (footerStatus) footerStatus.innerText = 'روتر متصل و پایدار';
  } else {
    badge.style.color = 'var(--danger)';
    badge.innerHTML = `<span class="status-dot" style="background:#ef4444; box-shadow:0 0 8px #ef4444;"></span><span>قطع ارتباط</span>`;
    if (footerStatus) footerStatus.innerText = 'عدم اتصال به روتر';
  }
}

function updateDashboardTelemetry(report) {
  if (!report) return;

  const kpiWan = document.getElementById('kpi-active-wan');
  if (kpiWan) kpiWan.innerText = report.ActiveWAN;

  const kpiLatency = document.getElementById('kpi-latency');
  if (kpiLatency && report.WANProbes && report.WANProbes.length > 0) {
    kpiLatency.innerHTML = `${report.WANProbes[0].LatencyMs || 24} <span style="font-size:0.8rem; font-weight:500;">ms</span>`;
  }

  // Update dynamic WAN table
  if (report.WANProbes && report.WANProbes.length >= 2) {
    state.wans[0].latency_ms = report.WANProbes[0].LatencyMs;
    state.wans[0].is_default = report.WANProbes[0].IsDefaultRoute;
    state.wans[1].latency_ms = report.WANProbes[1].LatencyMs;
    state.wans[1].is_default = report.WANProbes[1].IsDefaultRoute;
    renderDynamicWANsTable();
  }
}

// Render Dynamic WAN Table with in-line renaming
function renderDynamicWANsTable() {
  const tbody = document.getElementById('dynamic-wans-table-body');
  if (!tbody) return;

  tbody.innerHTML = state.wans.map((w, idx) => `
    <tr>
      <td>
        <strong style="color:#fff;">${w.custom_name}</strong>
        <button class="btn btn-outline" style="padding:2px 6px; font-size:0.7rem; margin-right:6px;" onclick="renameWAN(${idx})" title="تغییر نام اپراتور">
          ✏️
        </button>
      </td>
      <td class="font-mono">${w.interface}</td>
      <td><span class="status-badge">${w.type}</span></td>
      <td class="font-mono" style="color:${w.latency_ms < 40 ? '#10b981' : '#f59e0b'}; font-weight:700;">${w.latency_ms} ms</td>
      <td>۰٪</td>
      <td>
        <span class="status-badge" style="${w.is_default ? 'background:rgba(16,185,129,0.15); color:#10b981;' : 'background:rgba(245,158,11,0.15); color:#f59e0b;'}">
          ${w.is_default ? 'فعال (Default)' : 'پشتیبان (Standby)'}
        </span>
      </td>
    </tr>
  `).join('');
}

// Rename WAN function
function renameWAN(idx) {
  const current = state.wans[idx].custom_name;
  const newName = prompt(`نام دلخواه جدید برای این خط اینترنت را وارد کنید:`, current);
  if (newName && newName.trim() !== '') {
    state.wans[idx].custom_name = newName.trim();
    renderDynamicWANsTable();
  }
}

// Toggle Failover
async function toggleManualFailover() {
  const activeWan = state.wans.find(w => w.is_default);
  const targetWan = state.wans.find(w => !w.is_default);

  if (!targetWan) return;

  if (!confirm(`آیا از سوئیچ دستی مسیر اصلی اینترنت به «${targetWan.custom_name}» اطمینان دارید؟`)) return;

  try {
    const res = await fetch('/api/wan/failover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_wan: targetWan.name }),
    });
    const data = await res.json();
    if (data.success) {
      state.wans.forEach(w => w.is_default = (w.name === targetWan.name));
      renderDynamicWANsTable();
      alert(`✅ مسیر اصلی با موفقیت به «${targetWan.custom_name}» منتقل شد.`);
    }
  } catch (err) {
    alert('خطا در سوئیچ: ' + err.message);
  }
}

// Quick Backup
async function triggerQuickBackup() {
  try {
    const res = await fetch('/api/backup', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alert(`🛡️ فایل پشتیبان اضطراری با نام «${data.name}» روی روتر ذخیره شد.`);
    }
  } catch (err) {
    alert('خطا در بک‌آپ: ' + err.message);
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

  const cont = disc.Container;
  const contEl = document.getElementById('container-status-box');
  if (contEl && cont) {
    contEl.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <h4>وضعیت کانتینر: <span style="color:#10b981;">${cont.Status || 'Active (Running)'}</span></h4>
          <p style="color:var(--text-muted); font-size:0.85rem; margin-top:4px;">ایمیج: ${cont.Image || 'metacubex/mihomo:latest'} | ذخیره‌سازی: ${cont.RootDir || 'usb1/mihomo'}</p>
        </div>
        <a href="http://172.16.20.1:9090/ui" target="_blank" class="btn btn-outline" style="font-size:0.8rem;">
          🚀 باز کردن پنل MetaCubeX
        </a>
      </div>
    `;
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

// Render Plan
function renderPlanView(plan) {
  if (!plan) return;

  document.getElementById('plan-title').innerText = plan.Name;
  document.getElementById('plan-status-badge').innerText = `وضعیت: ${plan.Status}`;

  const cardLastPlan = document.getElementById('card-last-plan-title');
  if (cardLastPlan) cardLastPlan.innerText = plan.Name;

  const tbody = document.getElementById('plan-steps-table-body');
  if (!tbody || !plan.Steps) return;

  tbody.innerHTML = plan.Steps.map((step, idx) => `
    <tr>
      <td>${idx + 1}</td>
      <td>
        <span class="status-badge" style="color:#10b981;">${step.Action.toUpperCase()}</span>
      </td>
      <td class="font-mono">${step.TargetResource}</td>
      <td class="font-mono" style="font-size:0.82rem; color:#38bdf8;">${step.NativeCommand}</td>
      <td>${step.Description}</td>
      <td>
        <span class="status-badge" style="${step.RiskLevel === 'critical' ? 'color:#ef4444;' : 'color:#10b981;'}">
          ${step.RiskLevel === 'critical' ? '⚠️ حیاتی' : 'عادی'}
        </span>
      </td>
      <td>
        <span class="status-dot" style="background:${step.Applied ? '#10b981' : '#64748b'};box-shadow:none;"></span>
      </td>
    </tr>
  `).join('');
}

// Dry Run
async function executeDryRun() {
  if (!state.currentPlan) {
    alert('لطفاً ابتدا یک پلن تولید کنید.');
    return;
  }

  try {
    const res = await fetch('/api/plan/dry-run', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alert('✅ تست شبیه‌سازی Dry-Run بدون هیچ تداخل و خطایی تأیید شد.');
      renderPlanView(data.plan);
    }
  } catch (err) {
    alert('خطا در Dry-Run: ' + err.message);
  }
}

// Apply Plan
async function executeApplyPlan() {
  if (!state.currentPlan) return;

  if (!confirm('آیا از اعمال این تغییرات روی روتر اطمینان دارید؟ سیستم قبل از اجرا یک بک‌آپ کامل تهیه خواهد کرد.')) return;

  try {
    const res = await fetch('/api/plan/apply', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      alert('🎉 تمام مراحل Plan با موفقیت روی روتر اجرا و ثبت شدند!');
      renderPlanView(data.plan);
    } else {
      alert('❌ خطا در اجرا و بازگردانی خودکار: ' + data.error);
    }
  } catch (err) {
    alert('خطا در اجرا: ' + err.message);
  }
}

// AI Message Sender (Prompt-to-Plan)
async function sendAIMessage() {
  const input = document.getElementById('input-ai-prompt');
  const prompt = input.value.trim();
  if (!prompt) return;

  const chatContainer = document.getElementById('chat-messages');
  chatContainer.innerHTML += `<div class="chat-bubble user">${prompt}</div>`;
  input.value = '';
  chatContainer.scrollTop = chatContainer.scrollHeight;

  const provider = document.getElementById('cfg-ai-provider')?.value || 'rule_engine';
  const aiUrl = document.getElementById('cfg-ai-url')?.value || '';
  const aiKey = document.getElementById('cfg-ai-key')?.value || '';
  const aiModel = document.getElementById('cfg-ai-model')?.value || '';

  try {
    const res = await fetch('/api/ai/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt,
        provider,
        base_url: aiUrl,
        api_key: aiKey,
        model: aiModel
      }),
    });
    const data = await res.json();
    chatContainer.innerHTML += `
      <div class="chat-bubble bot">
        ${data.answer}
        <div style="margin-top:10px;">
          <button class="btn btn-primary" style="font-size:0.78rem; padding:6px 12px;" onclick="loadAIPlanDirectly('${encodeURIComponent(prompt)}')">
            ⚡ انتقال به Plan Builder و پیش‌نمایش
          </button>
        </div>
      </div>
    `;
    chatContainer.scrollTop = chatContainer.scrollHeight;
  } catch (err) {
    chatContainer.innerHTML += `<div class="chat-bubble bot" style="color:#ef4444;">خطا: ${err.message}</div>`;
  }
}

function setAndSendAIPrompt(text) {
  const input = document.getElementById('input-ai-prompt');
  if (input) {
    input.value = text;
    sendAIMessage();
  }
}

async function loadAIPlanDirectly(promptEncoded) {
  const prompt = decodeURIComponent(promptEncoded);
  await compileProfileToPlan('Generic-Dual-WAN-Failover');
}

// Global Search Filter
function filterContentBySearch(q) {
  if (!q) return;
  const rows = document.querySelectorAll('table.data-table tbody tr');
  rows.forEach(r => {
    const text = r.innerText.toLowerCase();
    r.style.display = text.includes(q) ? '' : 'none';
  });
}

// Load Audit Logs
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

// Save Settings function
function saveSettings() {
  const settings = {
    host: document.getElementById('cfg-host')?.value || '',
    user: document.getElementById('cfg-user')?.value || '',
    mode: document.getElementById('cfg-mode')?.value || 'simulator',
    socks: document.getElementById('cfg-socks')?.value || '127.0.0.1:7890',
    ai_provider: document.getElementById('cfg-ai-provider')?.value || 'rule_engine',
    ai_url: document.getElementById('cfg-ai-url')?.value || '',
    ai_key: document.getElementById('cfg-ai-key')?.value || '',
    ai_model: document.getElementById('cfg-ai-model')?.value || ''
  };

  localStorage.setItem('rp_settings', JSON.stringify(settings));

  const isSim = (settings.mode === 'simulator');
  updateConnectionBadge(!isSim, isSim);

  alert('💾 تنظیمات با موفقیت ذخیره شد. حالت فعال: ' + (isSim ? 'شبیه‌ساز امن (آفلاین)' : 'اتصال واقعی به روتر'));
}
