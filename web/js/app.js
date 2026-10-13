/**
 * RouterPilot Control Plane v1.1
 * Modern Glass UI Orchestrator & State Manager
 */

const state = {
  activeTab: 'dashboard',
  router: null,
  discovery: null,
  currentPlan: null,
  routers: [],
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
  initRoutersFleet();
  loadSettings();
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

  if (tabId === 'routers') renderRoutersFleet();
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

  // AI Provider change listener
  document.getElementById('cfg-ai-provider')?.addEventListener('change', (e) => {
    handleAIProviderChange(e.target.value);
  });

  // SOCKS5 Checkbox synchronization
  document.getElementById('cfg-socks-enabled')?.addEventListener('change', (e) => {
    const checked = e.target.checked;
    const chatToggle = document.getElementById('chat-socks-toggle');
    if (chatToggle) chatToggle.checked = checked;
    updateSocksUI(checked);
    autoSaveSettings();
  });

  document.getElementById('chat-socks-toggle')?.addEventListener('change', (e) => {
    const checked = e.target.checked;
    const cfgToggle = document.getElementById('cfg-socks-enabled');
    if (cfgToggle) cfgToggle.checked = checked;
    updateSocksUI(checked);
    autoSaveSettings();
  });

  // Router Dropdown Toggler
  const btnRouterDropdown = document.getElementById('btn-router-dropdown');
  const routerDropdownMenu = document.getElementById('router-dropdown-menu');
  if (btnRouterDropdown && routerDropdownMenu) {
    btnRouterDropdown.addEventListener('click', (e) => {
      e.stopPropagation();
      routerDropdownMenu.classList.toggle('show');
    });

    document.addEventListener('click', (e) => {
      if (!btnRouterDropdown.contains(e.target) && !routerDropdownMenu.contains(e.target)) {
        routerDropdownMenu.classList.remove('show');
      }
    });
  }

  // Close modal when clicking on dark backdrop
  const modalAddRouter = document.getElementById('modal-add-router');
  if (modalAddRouter) {
    modalAddRouter.addEventListener('click', (e) => {
      if (e.target === modalAddRouter) closeAddRouterModal();
    });
  }
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
    if (!okStatus(res)) return;
    const data = await res.json();
    state.discovery = data;
    renderDiscoveryView(data);
  } catch (err) {
    console.error('Discovery load failed:', err);
  }
}

function okStatus(res) {
  return res && res.ok;
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
  const activeDot = document.getElementById('active-router-dot');
  const footerStatus = document.getElementById('sidebar-system-status');
  const activeRouter = state.routers ? state.routers.find(r => r.is_active) : null;
  const isSim = activeRouter ? (activeRouter.os === 'simulator') : simulatorMode;

  if (isSim) {
    if (activeDot) {
      activeDot.style.background = '#f59e0b';
      activeDot.style.boxShadow = '0 0 8px rgba(245,158,11,0.5)';
    }
    if (footerStatus) footerStatus.innerText = 'حالت شبیه‌ساز آفلاین (امن)';
  } else if (connected) {
    if (activeDot) {
      activeDot.style.background = '#10b981';
      activeDot.style.boxShadow = '0 0 8px rgba(16,185,129,0.5)';
    }
    if (footerStatus) footerStatus.innerText = 'روتر متصل و پایدار';
  } else {
    if (activeDot) {
      activeDot.style.background = '#ef4444';
      activeDot.style.boxShadow = '0 0 8px #ef4444';
    }
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

// AI Message Sender (Prompt-to-Plan with Google Gemini & SOCKS support)
async function sendAIMessage() {
  const input = document.getElementById('input-ai-prompt');
  const prompt = input.value.trim();
  if (!prompt) return;

  const chatContainer = document.getElementById('chat-messages');
  chatContainer.innerHTML += `<div class="chat-bubble user">${prompt}</div>`;
  input.value = '';
  chatContainer.scrollTop = chatContainer.scrollHeight;

  const provider = document.getElementById('cfg-ai-provider')?.value || 'gemini';
  const aiUrl = document.getElementById('cfg-ai-url')?.value || '';
  const aiKey = document.getElementById('cfg-ai-key')?.value || '';
  const aiModel = document.getElementById('cfg-ai-model')?.value || '';
  const socksEnabled = document.getElementById('chat-socks-toggle')?.checked ?? (document.getElementById('cfg-socks-enabled')?.checked ?? true);
  const socksAddr = document.getElementById('cfg-socks')?.value || '127.0.0.1:7890';

  // Temporary thinking bubble
  const thinkingId = 'thinking-' + Date.now();
  chatContainer.innerHTML += `<div id="${thinkingId}" class="chat-bubble bot" style="opacity:0.75;">در حال اتصال و ارسال به ${provider === 'gemini' ? 'Google Gemini' : (provider === 'ollama' ? 'Ollama' : 'مشاور هوشمند')} ${socksEnabled ? '(با ساکس)' : '(بدون ساکس)'}... ⏳</div>`;
  chatContainer.scrollTop = chatContainer.scrollHeight;

  try {
    const res = await fetch('/api/ai/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prompt,
        provider,
        base_url: aiUrl,
        api_key: aiKey,
        model: aiModel,
        socks_enabled: socksEnabled,
        socks_addr: socksAddr
      }),
    });
    const data = await res.json();
    const thinkingEl = document.getElementById(thinkingId);
    if (thinkingEl) thinkingEl.remove();

    const sourceBadge = data.source ? `<div style="font-size:0.72rem; color:var(--text-muted); margin-bottom:6px;">پاسخ دریافتی از: <span style="color:var(--primary); font-weight:600;">${data.source}</span> ${socksEnabled ? '🛡️ (SOCKS5)' : '🌐 (Direct)'}</div>` : '';

    chatContainer.innerHTML += `
      <div class="chat-bubble bot">
        ${sourceBadge}
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
    const thinkingEl = document.getElementById(thinkingId);
    if (thinkingEl) thinkingEl.remove();
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
    socks_enabled: document.getElementById('cfg-socks-enabled')?.checked ?? true,
    socks: document.getElementById('cfg-socks')?.value || '127.0.0.1:7890',
    ai_provider: document.getElementById('cfg-ai-provider')?.value || 'gemini',
    ai_url: document.getElementById('cfg-ai-url')?.value || '',
    ai_key: document.getElementById('cfg-ai-key')?.value || '',
    ai_model: document.getElementById('cfg-ai-model')?.value || ''
  };

  localStorage.setItem('rp_settings', JSON.stringify(settings));

  const isSim = (settings.mode === 'simulator');
  updateConnectionBadge(!isSim, isSim);
  updateAIProviderBadge(settings.ai_provider);
  updateSocksUI(settings.socks_enabled);

  alert('💾 تنظیمات با موفقیت ذخیره شد. حالت هوش مصنوعی: ' + settings.ai_provider + ' (' + (settings.socks_enabled ? 'با ساکس پروکسی' : 'مستقیم بدون ساکس') + ')');
}

function autoSaveSettings() {
  const saved = localStorage.getItem('rp_settings');
  const current = saved ? JSON.parse(saved) : {};
  current.socks_enabled = document.getElementById('cfg-socks-enabled')?.checked ?? true;
  current.socks = document.getElementById('cfg-socks')?.value || '127.0.0.1:7890';
  localStorage.setItem('rp_settings', JSON.stringify(current));
}

function loadSettings() {
  const saved = localStorage.getItem('rp_settings');
  if (!saved) {
    // Defaults for Gemini
    handleAIProviderChange('gemini');
    return;
  }
  try {
    const s = JSON.parse(saved);
    if (s.host && document.getElementById('cfg-host')) document.getElementById('cfg-host').value = s.host;
    if (s.user && document.getElementById('cfg-user')) document.getElementById('cfg-user').value = s.user;
    if (s.mode && document.getElementById('cfg-mode')) document.getElementById('cfg-mode').value = s.mode;
    if (s.ai_provider && document.getElementById('cfg-ai-provider')) {
      document.getElementById('cfg-ai-provider').value = s.ai_provider;
    }
    if (s.ai_url && document.getElementById('cfg-ai-url')) document.getElementById('cfg-ai-url').value = s.ai_url;
    if (s.ai_key && document.getElementById('cfg-ai-key')) document.getElementById('cfg-ai-key').value = s.ai_key;
    if (s.ai_model && document.getElementById('cfg-ai-model')) document.getElementById('cfg-ai-model').value = s.ai_model;
    if (s.socks && document.getElementById('cfg-socks')) document.getElementById('cfg-socks').value = s.socks;

    const socksEnabled = (s.socks_enabled !== false);
    if (document.getElementById('cfg-socks-enabled')) document.getElementById('cfg-socks-enabled').checked = socksEnabled;
    if (document.getElementById('chat-socks-toggle')) document.getElementById('chat-socks-toggle').checked = socksEnabled;
    updateSocksUI(socksEnabled);
    updateAIProviderBadge(s.ai_provider || 'gemini');
  } catch (e) {
    console.error('Failed to load settings:', e);
  }
}

function handleAIProviderChange(provider) {
  const urlInput = document.getElementById('cfg-ai-url');
  const keyInput = document.getElementById('cfg-ai-key');
  const modelInput = document.getElementById('cfg-ai-model');

  if (provider === 'gemini') {
    if (urlInput) urlInput.value = 'https://generativelanguage.googleapis.com';
    if (modelInput) modelInput.value = 'gemini-1.5-flash';
    if (keyInput) keyInput.placeholder = 'کلید Google Gemini خود را وارد کنید (AIzaSy...)';
  } else if (provider === 'ollama') {
    if (urlInput) urlInput.value = 'http://localhost:11434/v1';
    if (modelInput) modelInput.value = 'qwen2.5:7b';
    if (keyInput) keyInput.placeholder = 'برای Ollama خالی بگذارید...';
  } else if (provider === 'groq') {
    if (urlInput) urlInput.value = 'https://api.groq.com/openai/v1';
    if (modelInput) modelInput.value = 'llama-3.3-70b-versatile';
    if (keyInput) keyInput.placeholder = 'کلید Groq API (gsk_...)';
  } else if (provider === 'openai') {
    if (urlInput) urlInput.value = 'https://api.openai.com/v1';
    if (modelInput) modelInput.value = 'gpt-4o-mini';
    if (keyInput) keyInput.placeholder = 'کلید OpenAI (sk-...)';
  }

  updateAIProviderBadge(provider);
}

function updateAIProviderBadge(provider) {
  const badge = document.getElementById('chat-provider-badge');
  if (!badge) return;
  switch (provider) {
    case 'gemini':
      badge.innerText = 'Google Gemini API';
      badge.style.color = 'var(--primary)';
      break;
    case 'ollama':
      badge.innerText = 'Ollama (محلی)';
      badge.style.color = 'var(--success)';
      break;
    case 'groq':
      badge.innerText = 'Groq Cloud (Llama 3.3)';
      badge.style.color = '#a855f7';
      break;
    case 'openai':
      badge.innerText = 'OpenAI API';
      badge.style.color = '#38bdf8';
      break;
    default:
      badge.innerText = 'موتور قوانین آفلاین (Rule Engine)';
      badge.style.color = '#f59e0b';
  }
}

function updateSocksUI(enabled) {
  const dot = document.getElementById('chat-socks-status-dot');
  if (dot) {
    dot.style.background = enabled ? '#10b981' : '#64748b';
    dot.style.boxShadow = enabled ? '0 0 8px rgba(16,185,129,0.5)' : 'none';
    dot.title = enabled ? 'ساکس پروکسی فعال' : 'اتصال مستقیم بدون پروکسی';
  }
  const addrCont = document.getElementById('socks-addr-container');
  if (addrCont) {
    addrCont.style.opacity = enabled ? '1' : '0.6';
  }
}

async function testProxyConnection() {
  const resultEl = document.getElementById('socks-test-result');
  const socksEnabled = document.getElementById('cfg-socks-enabled')?.checked ?? true;
  const socksAddr = document.getElementById('cfg-socks')?.value || '127.0.0.1:7890';

  if (resultEl) {
    resultEl.innerHTML = '<span style="color:var(--primary);">در حال آزمون اتصال اینترنت به سرورهای گوگل... ⏳</span>';
  }

  try {
    const res = await fetch('/api/proxy/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        socks_enabled: socksEnabled,
        socks_addr: socksAddr
      })
    });
    const data = await res.json();
    if (resultEl) {
      if (data.success) {
        resultEl.innerHTML = `<span style="color:var(--success); font-weight:600;">✅ ${data.message}</span>`;
      } else {
        resultEl.innerHTML = `<span style="color:#ef4444; font-weight:600;">❌ ${data.message}</span>`;
      }
    }
  } catch (err) {
    if (resultEl) {
      resultEl.innerHTML = `<span style="color:#ef4444;">خطای شبکه: ${err.message}</span>`;
    }
  }
}

// ==========================================
// Multi-Router Fleet & Switcher Engine (v1.2)
// ==========================================

function getOSDetails(os) {
  switch (os) {
    case 'mikrotik_ros7':
      return { label: 'MikroTik RouterOS 7', color: '#06b6d4', icon: '📶', desc: 'پشتیبانی کامل کانتینر، REST API و فایروال مدرن' };
    case 'mikrotik_ros6':
      return { label: 'MikroTik RouterOS 6', color: '#3b82f6', icon: '📻', desc: 'پشتیبانی SSH و API سنتی' };
    case 'openwrt':
      return { label: 'OpenWrt Linux', color: '#10b981', icon: '🌐', desc: 'پشتیبانی ubus و iptables/nftables' };
    case 'linux':
      return { label: 'Linux Router / VyOS', color: '#a855f7', icon: '🐧', desc: 'مسیریابی پیشرفته کرنل لینوکس و nftables' };
    default:
      return { label: 'Simulator Mode', color: '#f59e0b', icon: '🧪', desc: 'محیط مجازی و ایزوله آفلاین جهت تست و آزمایش' };
  }
}

function initRoutersFleet() {
  const saved = localStorage.getItem('rp_routers');
  if (saved) {
    try {
      state.routers = JSON.parse(saved);
    } catch (e) {
      console.error('Failed to parse saved routers:', e);
    }
  }

  // Provide initial fleet if empty
  if (!state.routers || state.routers.length === 0) {
    state.routers = [
      {
        id: 'r-sim',
        name: 'شبیه‌ساز امن (Simulator)',
        os: 'simulator',
        host: '127.0.0.1 (Sandbox)',
        port: 8080,
        user: 'local-admin',
        auth: 'none',
        status: 'online',
        is_active: true,
        wan_count: 2,
        container_supported: true
      },
      {
        id: 'r-rb5009',
        name: 'روتر دفتر مرکزی (RB5009)',
        os: 'mikrotik_ros7',
        host: '172.16.20.1',
        port: 443,
        user: 'admin',
        auth: 'password',
        status: 'standby',
        is_active: false,
        wan_count: 2,
        container_supported: true
      },
      {
        id: 'r-openwrt',
        name: 'شعبه ۲ (OpenWrt Gateway)',
        os: 'openwrt',
        host: '192.168.10.1',
        port: 80,
        user: 'root',
        auth: 'ssh_key',
        status: 'standby',
        is_active: false,
        wan_count: 1,
        container_supported: false
      }
    ];
    localStorage.setItem('rp_routers', JSON.stringify(state.routers));
  }

  // Ensure one router is active
  let active = state.routers.find(r => r.is_active);
  if (!active) {
    state.routers[0].is_active = true;
    active = state.routers[0];
    localStorage.setItem('rp_routers', JSON.stringify(state.routers));
  }

  updateActiveRouterUI(active);
  renderRouterDropdown();
  renderRoutersFleet();
}

function updateActiveRouterUI(active) {
  if (!active) return;
  const nameEl = document.getElementById('topbar-router-name');
  const typeEl = document.getElementById('topbar-router-type');
  const dotEl = document.getElementById('active-router-dot');
  const osInfo = getOSDetails(active.os);

  if (nameEl) nameEl.innerText = active.name;
  if (typeEl) typeEl.innerText = `${osInfo.label} • ${active.host}`;
  if (dotEl) {
    dotEl.style.background = active.os === 'simulator' ? '#f59e0b' : '#10b981';
    dotEl.style.boxShadow = active.os === 'simulator' ? '0 0 8px rgba(245,158,11,0.6)' : '0 0 8px rgba(16,185,129,0.6)';
  }

  const footerStatus = document.getElementById('sidebar-system-status');
  if (footerStatus) {
    footerStatus.innerText = active.os === 'simulator' ? 'شبیه‌ساز امن (آفلاین)' : `متصل به ${active.name}`;
  }
}

function renderRouterDropdown() {
  const listEl = document.getElementById('router-dropdown-list');
  if (!listEl) return;

  listEl.innerHTML = state.routers.map(r => {
    const osInfo = getOSDetails(r.os);
    const dotColor = r.is_active ? '#10b981' : (r.os === 'simulator' ? '#f59e0b' : '#64748b');
    return `
      <div class="router-dropdown-item ${r.is_active ? 'active' : ''}" onclick="switchActiveRouter('${r.id}')">
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="status-dot" style="background:${dotColor};"></span>
          <div>
            <div style="font-weight:600; font-size:0.85rem; color:#fff;">${r.name}</div>
            <div style="font-size:0.72rem; color:var(--text-muted);">${osInfo.label} • ${r.host}</div>
          </div>
        </div>
        ${r.is_active ? '<span style="color:var(--primary); font-size:0.75rem; font-weight:600;">فعال ✓</span>' : ''}
      </div>
    `;
  }).join('');
}

function renderRoutersFleet() {
  const gridEl = document.getElementById('routers-fleet-grid');
  if (!gridEl) return;

  gridEl.innerHTML = state.routers.map(r => {
    const osInfo = getOSDetails(r.os);
    const isActive = r.is_active;
    return `
      <div class="glass-panel stat-card" style="border-right: 4px solid ${isActive ? 'var(--success)' : osInfo.color}; display:flex; flex-direction:column; justify-content:space-between; min-height:220px;">
        <div>
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
            <div>
              <div style="font-size:0.78rem; color:${osInfo.color}; font-weight:600; margin-bottom:2px;">${osInfo.icon} ${osInfo.label}</div>
              <h3 style="margin:0; font-size:1.05rem; color:#fff;">${r.name}</h3>
            </div>
            <span class="status-badge" style="color:${isActive ? 'var(--success)' : 'var(--text-muted)'}; background:${isActive ? 'rgba(16,185,129,0.15)' : 'rgba(255,255,255,0.05)'};">
              ${isActive ? '● روتر فعال' : 'آماده اتصال'}
            </span>
          </div>

          <p class="font-mono" style="color:var(--text-muted); font-size:0.84rem; margin:6px 0;" dir="ltr">
            ${r.user}@${r.host}:${r.port}
          </p>
          <p style="font-size:0.78rem; color:var(--text-muted); margin-bottom:12px;">
            ${osInfo.desc}
          </p>

          <div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:14px;">
            <span class="status-badge" style="font-size:0.72rem; padding:3px 8px;">📶 ${r.wan_count || 1} خط WAN</span>
            <span class="status-badge" style="font-size:0.72rem; padding:3px 8px; color:${r.container_supported ? 'var(--primary)' : 'var(--text-muted)'};">
              ${r.container_supported ? '🚀 پشتیبانی کانتینر' : '✕ بدون کانتینر'}
            </span>
          </div>
        </div>

        <div style="display:flex; gap:8px; align-items:center; padding-top:10px; border-top:1px solid rgba(255,255,255,0.06);">
          ${isActive ? `
            <button class="btn btn-primary" style="font-size:0.78rem; padding:6px 12px; flex:1;" disabled>
              ✓ روتر فعال فعلی
            </button>
          ` : `
            <button class="btn btn-outline" style="font-size:0.78rem; padding:6px 12px; flex:1;" onclick="switchActiveRouter('${r.id}')">
              🔄 سوئیچ به این روتر
            </button>
          `}
          <button class="btn btn-outline" style="font-size:0.78rem; padding:6px 10px;" onclick="switchTab('discovery')" title="اسکن و Discovery روتر">
            🔍 کشف
          </button>
          ${r.os !== 'simulator' ? `
            <button class="btn btn-outline" style="font-size:0.78rem; padding:6px 10px; color:#ef4444;" onclick="deleteRouter('${r.id}')" title="حذف روتر از فهرست">
              🗑️
            </button>
          ` : ''}
        </div>
      </div>
    `;
  }).join('');
}

function switchActiveRouter(routerId) {
  const target = state.routers.find(r => r.id === routerId);
  if (!target) return;

  state.routers.forEach(r => {
    r.is_active = (r.id === routerId);
  });

  localStorage.setItem('rp_routers', JSON.stringify(state.routers));
  updateActiveRouterUI(target);
  renderRouterDropdown();
  renderRoutersFleet();

  // Close dropdown if open
  document.getElementById('router-dropdown-menu')?.classList.remove('show');

  // Trigger discovery reload for newly selected router
  loadDiscoveryData();

  // Notify backend API
  fetch('/api/routers/switch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: target.id, name: target.name })
  }).catch(() => {});

  // Log in Audit table if active
  const auditBody = document.getElementById('audit-table-body');
  if (auditBody) {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="font-mono" style="font-size:0.8rem;">${new Date().toLocaleTimeString('fa-IR')}</td>
      <td><span class="status-badge">Fleet</span></td>
      <td><span class="status-badge" style="color:#10b981;">info</span></td>
      <td>سوئیچ موفق به روتر: ${target.name} (${target.host})</td>
    `;
    auditBody.prepend(row);
  }
}

function openAddRouterModal() {
  const modal = document.getElementById('modal-add-router');
  if (!modal) return;
  document.getElementById('form-add-router')?.reset();
  modal.classList.add('show');
}

function closeAddRouterModal() {
  const modal = document.getElementById('modal-add-router');
  if (modal) modal.classList.remove('show');
}

function saveNewRouter() {
  const name = document.getElementById('new-router-name')?.value.trim();
  const os = document.getElementById('new-router-os')?.value || 'mikrotik_ros7';
  const host = document.getElementById('new-router-host')?.value.trim();
  const port = parseInt(document.getElementById('new-router-port')?.value || '443', 10);
  const authtype = document.getElementById('new-router-authtype')?.value || 'password';
  const user = document.getElementById('new-router-user')?.value.trim() || 'admin';
  const pass = document.getElementById('new-router-pass')?.value || '';

  if (!name || !host) {
    alert('لطفاً نام روتر و آدرس IP را وارد کنید.');
    return;
  }

  const newId = 'r-' + Date.now();
  const newRouter = {
    id: newId,
    name,
    os,
    host,
    port,
    user,
    auth: authtype,
    status: 'online',
    is_active: false,
    wan_count: 2,
    container_supported: (os === 'mikrotik_ros7' || os === 'linux')
  };

  // Add to state and persist
  state.routers.push(newRouter);
  localStorage.setItem('rp_routers', JSON.stringify(state.routers));

  closeAddRouterModal();

  // Switch to the newly created router
  switchActiveRouter(newId);

  alert(`✅ روتر «${name}» با موفقیت اضافه و به عنوان روتر فعال انتخاب شد.`);
}

function deleteRouter(routerId) {
  const target = state.routers.find(r => r.id === routerId);
  if (!target) return;

  if (target.os === 'simulator') {
    alert('شبیه‌ساز پیش‌فرض سیستم قابل حذف نیست.');
    return;
  }

  if (!confirm(`آیا از حذف روتر «${target.name}» مطمئن هستید؟`)) {
    return;
  }

  state.routers = state.routers.filter(r => r.id !== routerId);

  // If deleted router was active, switch to first available
  if (target.is_active && state.routers.length > 0) {
    state.routers[0].is_active = true;
    updateActiveRouterUI(state.routers[0]);
  }

  localStorage.setItem('rp_routers', JSON.stringify(state.routers));
  renderRouterDropdown();
  renderRoutersFleet();
}
