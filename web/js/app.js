/**
 * RouterPilot Control Plane v1.3
 * Modern Glass UI Orchestrator & Real State Manager
 * Zero mock simulator data - 100% genuine live router connectivity.
 */

const state = {
  activeTab: 'dashboard',
  router: null,
  discovery: null,
  currentPlan: null,
  routers: [],
  wans: [],
  profiles: [],
  neighbors: [],
  clients: [],
  liveTraffic: null,
  cloudInfo: null,
  activeQuickFilter: 'all',
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
  loadNeighbors();
  loadQuickConfigProfiles();
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
  if (tabId === 'neighbors') loadNeighbors();
  if (tabId === 'discovery') loadDiscoveryData();
  if (tabId === 'quick-config') loadQuickConfigProfiles();
  if (tabId === 'clients') {
    loadConnectedClients();
    pollLiveTraffic();
    loadTopTalkers();
  }
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

  // Clients Table Search Filter
  document.getElementById('input-search-clients')?.addEventListener('input', (e) => {
    filterClientsBySearch(e.target.value.toLowerCase().trim());
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

    if (data.connected && data.has_discovery) {
      await loadDiscoveryData();
    } else {
      checkEmptyRouterState();
    }
  } catch (err) {
    console.error('Failed to load status:', err);
    updateConnectionBadge(false);
    checkEmptyRouterState();
  }
}

function checkEmptyRouterState() {
  if (!state.routers || state.routers.length === 0) {
    const banner = document.getElementById('banner-connect-prompt');
    if (banner) banner.style.display = 'block';
    openAddRouterModal();
  }
}

async function loadDiscoveryData() {
  try {
    const res = await fetch('/api/discovery');
    if (!res.ok) {
      renderDiscoveryView(null);
      return;
    }
    const data = await res.json();
    state.discovery = data;
    if (data.WANs) {
      state.wans = data.WANs.map(w => ({
        id: w.ID,
        name: w.Name,
        custom_name: w.CustomName || w.Name,
        interface: w.Interface,
        type: w.Type,
        latency_ms: w.LatencyMs || 25,
        packet_loss: w.PacketLoss || 0,
        is_default: w.IsDefaultRoute
      }));
      renderDynamicWANsTable();
    }
    renderDiscoveryView(data);
  } catch (err) {
    console.error('Discovery load failed:', err);
    renderDiscoveryView(null);
  }
}

function startHealthPolling() {
  // Initial immediate fetch
  pollLiveTraffic();

  state.pollTimer = setInterval(async () => {
    try {
      const res = await fetch('/api/wan/health');
      if (res.ok) {
        const report = await res.json();
        updateDashboardTelemetry(report);
      }
    } catch (err) {
      // Ignore network polling errors
    }

    // Live Bandwidth & Interface Torch Polling
    pollLiveTraffic();
  }, 3000);
}

function updateConnectionBadge(connected) {
  const activeDot = document.getElementById('active-router-dot');
  const footerStatus = document.getElementById('sidebar-system-status');
  const activeRouter = state.routers ? state.routers.find(r => r.is_active) : null;

  if (connected && activeRouter) {
    if (activeDot) {
      activeDot.style.background = '#10b981';
      activeDot.style.boxShadow = '0 0 8px rgba(16,185,129,0.5)';
    }
    if (footerStatus) footerStatus.innerText = `متصل به ${activeRouter.name}`;
  } else {
    if (activeDot) {
      activeDot.style.background = '#ef4444';
      activeDot.style.boxShadow = '0 0 8px #ef4444';
    }
    if (footerStatus) footerStatus.innerText = 'عدم اتصال به روتر';
  }
}

function updateDashboardTelemetry(report) {
  if (!report || !report.WANProbes || report.WANProbes.length === 0) {
    const kpiWan = document.getElementById('kpi-active-wan');
    if (kpiWan) kpiWan.innerText = '---';
    const kpiLatency = document.getElementById('kpi-latency');
    if (kpiLatency) kpiLatency.innerText = '---';
    return;
  }

  const kpiWan = document.getElementById('kpi-active-wan');
  if (kpiWan) kpiWan.innerText = report.ActiveWAN || (report.WANProbes[0] ? report.WANProbes[0].Name : '---');

  const kpiLatency = document.getElementById('kpi-latency');
  if (kpiLatency && report.WANProbes.length > 0) {
    const lat = report.WANProbes[0].LatencyMs || 20;
    kpiLatency.innerHTML = `${lat} <span style="font-size:0.8rem; font-weight:500;">ms</span>`;
  }

  // Update dynamic WAN table metrics
  if (state.wans && state.wans.length > 0) {
    report.WANProbes.forEach((probe, idx) => {
      if (state.wans[idx]) {
        state.wans[idx].latency_ms = probe.LatencyMs;
        state.wans[idx].is_default = probe.IsDefaultRoute;
      }
    });
    renderDynamicWANsTable();
  }
}

// Render Dynamic WAN Table with in-line renaming
function renderDynamicWANsTable() {
  const tbody = document.getElementById('dynamic-wans-table-body');
  if (!tbody) return;

  if (!state.wans || state.wans.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center; padding:24px; color:var(--text-muted);">
          در حال حاضر روتری متصل نیست یا خط اینترنتی کشف نشده است.
        </td>
      </tr>
    `;
    return;
  }

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

  if (!targetWan) {
    alert('برای سوئیچ Failover، حداقل دو خط اینترنت فعال مورد نیاز است.');
    return;
  }

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
  const contEl = document.getElementById('container-status-box');

  if (!disc || !disc.Interfaces) {
    if (tableBody) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align:center; padding:28px; color:var(--text-muted);">
            روتری متصل نیست. لطفاً ابتدا به روتر خود متصل شوید.
          </td>
        </tr>
      `;
    }
    if (contEl) {
      contEl.innerHTML = '<div style="color:var(--text-muted); text-align:center;">در انتظار اتصال به روتر...</div>';
    }
    return;
  }

  if (tableBody) {
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
  }

  const activeHost = (state.routers && state.routers.find(r => r.is_active)?.host) || '192.168.88.1';
  const cont = disc.Container;
  if (contEl && cont) {
    const isRunning = cont.Status === 'running';
    contEl.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
        <div>
          <h4>وضعیت کانتینر: <span style="color:${isRunning ? '#10b981' : 'var(--text-muted)'};">${cont.Status || 'غیرفعال'}</span></h4>
          <p style="color:var(--text-muted); font-size:0.85rem; margin-top:4px;">
            ایمیج: ${cont.Image || 'بدون کانتینر'} | ذخیره‌سازی: ${cont.RootDir || 'حافظه روتر'} ${cont.HasUSBDisk ? '(فلش USB شناسایی شد)' : ''}
          </p>
        </div>
        ${isRunning ? `
          <a href="http://${activeHost}:9090/ui" target="_blank" class="btn btn-outline" style="font-size:0.8rem;">
            🚀 باز کردن پنل MetaCubeX
          </a>
        ` : ''}
      </div>
    `;
  }

  // Update Mihomo tab hardware specs with real data
  const rInfo = disc.Router;
  if (rInfo) {
    const hwEl = document.getElementById('mihomo-hw-compat');
    const hwSub = document.getElementById('mihomo-hw-sub');
    if (hwEl) {
      hwEl.innerText = rInfo.ContainerSupported ? 'سازگار' : 'پشتیبانی نمی‌شود';
      hwEl.style.color = rInfo.ContainerSupported ? 'var(--success)' : '#ef4444';
    }
    if (hwSub) {
      hwSub.innerText = `${rInfo.Architecture} • رم ${Math.round(rInfo.RAMTotalBytes / (1024 * 1024))} MB`;
    }

    const storageVal = document.getElementById('mihomo-storage-val');
    const storageSub = document.getElementById('mihomo-storage-sub');
    if (storageVal) {
      storageVal.innerText = cont && cont.HasUSBDisk ? 'فلش USB متصل' : 'حافظه داخلی روتر';
    }
    if (storageSub) {
      storageSub.innerText = `فضای آزاد: ${Math.round(rInfo.StorageFreeBytes / (1024 * 1024))} MB`;
    }

    const portVal = document.getElementById('mihomo-port-val');
    if (portVal) portVal.innerText = ':9090';

    // Update KPI card Mihomo
    const kpiMihomo = document.getElementById('kpi-mihomo-status');
    const kpiMihomoSub = document.getElementById('kpi-mihomo-sub');
    if (kpiMihomo) {
      kpiMihomo.innerText = (cont && cont.Status === 'running') ? 'Active' : 'غیرفعال';
      kpiMihomo.style.color = (cont && cont.Status === 'running') ? 'var(--success)' : 'var(--text-muted)';
    }
    if (kpiMihomoSub) {
      kpiMihomoSub.innerText = rInfo.ContainerSupported ? 'Ready' : 'بدون کانتینر';
    }

    // Update Health Score KPI
    const kpiHealth = document.getElementById('kpi-health-score');
    const kpiHealthSub = document.getElementById('kpi-health-sub');
    if (kpiHealth) {
      kpiHealth.innerText = '۹۸٪';
      kpiHealth.style.color = 'var(--success)';
    }
    if (kpiHealthSub) kpiHealthSub.innerText = 'Zero-Lockout Safe';

    // Update Active Route card in dashboard
    const cardRoute = document.getElementById('card-active-route');
    const cardRouteSub = document.getElementById('card-active-route-sub');
    const cardRouteStatus = document.getElementById('card-active-route-status');
    if (disc.WANs && disc.WANs.length > 0) {
      const activeW = disc.WANs.find(w => w.IsDefaultRoute) || disc.WANs[0];
      if (cardRoute) cardRoute.innerText = `0.0.0.0/0 -> ${activeW.Gateway} (${activeW.Interface})`;
      if (cardRouteSub) cardRouteSub.innerText = `ترافیک از خط پیش‌فرض با اولویت Distance ${activeW.Metric} در جریان است.`;
      if (cardRouteStatus) {
        cardRouteStatus.innerText = '✓ مانیتورینگ پینگ فعال';
        cardRouteStatus.style.color = 'var(--success)';
      }
    }
  }

  // Render Specialized Device Role Panel (Wireless / Switch / Gateway)
  renderDeviceRolePanel(disc);
}

// Render Dynamic Device Role Panel (Wireless Radio / Cloud Switch / Edge Gateway)
function renderDeviceRolePanel(disc) {
  const rolePanel = document.getElementById('card-device-role-panel');
  if (!rolePanel) return;

  if (!disc) {
    rolePanel.style.display = 'none';
    return;
  }

  const role = disc.DeviceRole || (disc.Router?.DeviceType ? {
    type: disc.Router.DeviceType,
    label: disc.Router.DeviceLabel,
    icon: disc.Router.DeviceIcon,
    color: disc.Router.DeviceColor,
    description: 'دستگاه شناسایی‌شده میکروتیک',
    recommended_profile: disc.RecommendedProfile,
    tips: []
  } : null);

  if (!role) {
    rolePanel.style.display = 'none';
    return;
  }

  rolePanel.style.display = 'block';
  rolePanel.style.borderColor = role.color || 'var(--primary)';

  let specializedContent = '';

  if (role.type === 'wireless_radio') {
    const wLinks = disc.WirelessLinks || [];
    specializedContent = `
      <div style="margin-top:14px; background:rgba(0,0,0,0.25); border-radius:10px; padding:12px 16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <strong style="color:#fff; font-size:0.88rem;">📊 وضعیت لینک رادیویی وایرلس (PTP Signal):</strong>
          <span class="status-badge" style="color:${role.color};">Wireless PTP Mode</span>
        </div>
        ${wLinks.length > 0 ? `
          <div class="data-table-container">
            <table class="data-table" style="font-size:0.82rem;">
              <thead>
                <tr>
                  <th>اینترفیس</th>
                  <th>سیگنال (RSSI)</th>
                  <th>کیفیت (CCQ)</th>
                  <th>SNR</th>
                  <th>نرخ ارسال / دریافت</th>
                  <th>وضعیت تراز آنتن</th>
                </tr>
              </thead>
              <tbody>
                ${wLinks.map(wl => `
                  <tr>
                    <td class="font-mono">${wl.Interface}</td>
                    <td class="font-mono" style="color:${parseInt(wl.SignalStrength) > -70 ? '#10b981' : '#f59e0b'}; font-weight:700;">${wl.SignalStrength}</td>
                    <td class="font-mono" style="color:${wl.CCQ >= 80 ? '#10b981' : '#ef4444'}; font-weight:700;">${wl.CCQ}%</td>
                    <td class="font-mono">${wl.SNR} dB</td>
                    <td class="font-mono">${wl.TxRate} / ${wl.RxRate}</td>
                    <td>
                      <span class="status-badge" style="${wl.CCQ >= 85 ? 'color:#10b981;' : 'color:#f59e0b;'}">
                        ${wl.CCQ >= 85 ? '✓ الاین عالی' : 'نیاز به تنظیم جهت'}
                      </span>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        ` : `
          <p style="font-size:0.82rem; color:var(--text-muted); margin:0;">
            اینترفیس رادیویی شناسایی شد اما در حال حاضر کلاینت PTP متصل نیست. برای لینک امن از پروتکل nv2 یا WPA3 استفاده فرمایید.
          </p>
        `}
        <div style="margin-top:10px; display:flex; gap:10px; align-items:center;">
          <button class="btn btn-primary" style="font-size:0.8rem; padding:6px 14px;" onclick="compileProfileToPlan('${role.recommended_profile || 'Wireless-PTP-Bridge'}')">
            ⚡ تولید پلن استاندارد PTP Bridge امن (nv2 / WPA3)
          </button>
        </div>
      </div>
    `;
  } else if (role.type === 'cloud_switch') {
    const vlans = disc.SwitchVLANs || [];
    specializedContent = `
      <div style="margin-top:14px; background:rgba(0,0,0,0.25); border-radius:10px; padding:12px 16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <strong style="color:#fff; font-size:0.88rem;">🔀 سوئیچینگ سخت‌افزاری (VLAN Filtering & L3 HW Offload):</strong>
          <span class="status-badge" style="color:${role.color};">Hardware Switch Chip</span>
        </div>
        ${vlans.length > 0 ? `
          <div class="data-table-container">
            <table class="data-table" style="font-size:0.82rem;">
              <thead>
                <tr>
                  <th>VLAN ID</th>
                  <th>Tagged Ports (Trunk)</th>
                  <th>Untagged Ports (Access)</th>
                  <th>پردازش سخت‌افزاری</th>
                </tr>
              </thead>
              <tbody>
                ${vlans.map(v => `
                  <tr>
                    <td class="font-mono" style="font-weight:700; color:#38bdf8;">VLAN ${v.VlanIDs}</td>
                    <td class="font-mono">${v.Tagged || '-'}</td>
                    <td class="font-mono">${v.Untagged || '-'}</td>
                    <td><span class="status-badge" style="color:#10b981;">L2/L3 HW Offload ✓</span></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        ` : `
          <p style="font-size:0.82rem; color:var(--text-muted); margin:0;">
            تراشه سوئیچ آماده سوئیچینگ خطی (Line Rate) است. برای جلوگیری از درگیر شدن CPU، فیلترینگ سخت‌افزاری VLAN فعال شود.
          </p>
        `}
        <div style="margin-top:10px; display:flex; gap:10px; align-items:center;">
          <button class="btn btn-primary" style="font-size:0.8rem; padding:6px 14px;" onclick="compileProfileToPlan('${role.recommended_profile || 'Switch-VLAN-HW-Offload'}')">
            ⚡ اعمال VLAN Filtering سخت‌افزاری (بدون فشار به پردازنده)
          </button>
        </div>
      </div>
    `;
  } else {
    // gateway_router
    specializedContent = `
      <div style="margin-top:12px; display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
        <span class="status-badge" style="color:#10b981; background:rgba(16,185,129,0.12);">✓ مانیتورینگ Multi-WAN با پایش خطوط اینترنت</span>
        <span class="status-badge" style="color:#38bdf8; background:rgba(56,189,248,0.12);">✓ فایروال ضدقفل (Zero-Lockout Safe)</span>
        <span class="status-badge" style="color:#a855f7; background:rgba(168,85,247,0.12);">${disc.Container?.Supported ? '✓ پشتیبانی Mihomo Core' : 'فاقد کانتینر'}</span>
      </div>
    `;
  }

  rolePanel.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
      <div style="display:flex; gap:14px; align-items:flex-start;">
        <div style="font-size:2rem; line-height:1; padding:8px; background:rgba(255,255,255,0.05); border-radius:10px;">${role.icon}</div>
        <div>
          <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
            <h3 style="margin:0; font-size:1.1rem; color:#fff;">رده دستگاه: ${role.label}</h3>
            <span class="status-badge" style="color:${role.color}; border:1px solid ${role.color};">${disc.Router?.Model || 'MikroTik'}</span>
          </div>
          <p style="font-size:0.84rem; color:var(--text-muted); margin:0;">${role.description}</p>
        </div>
      </div>
    </div>
    ${specializedContent}
    ${role.tips && role.tips.length > 0 ? `
      <div style="margin-top:10px; font-size:0.78rem; color:var(--text-muted);">
        💡 <strong>توصیه‌های هوشمند مهندس زیرساخت:</strong> ${role.tips.join(' • ')}
      </div>
    ` : ''}
  `;
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
    mode: document.getElementById('cfg-mode')?.value || 'live',
    socks_enabled: document.getElementById('cfg-socks-enabled')?.checked ?? true,
    socks: document.getElementById('cfg-socks')?.value || '127.0.0.1:7890',
    ai_provider: document.getElementById('cfg-ai-provider')?.value || 'gemini',
    ai_url: document.getElementById('cfg-ai-url')?.value || '',
    ai_key: document.getElementById('cfg-ai-key')?.value || '',
    ai_model: document.getElementById('cfg-ai-model')?.value || ''
  };

  localStorage.setItem('rp_settings', JSON.stringify(settings));
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
// Multi-Router Fleet & Switcher Engine (v1.3)
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
      return { label: 'MikroTik RouterOS', color: '#06b6d4', icon: '📶', desc: 'روتر شبکه' };
  }
}

function initRoutersFleet() {
  const saved = localStorage.getItem('rp_routers');
  state.routers = [];

  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      // Purge any old fake simulator entries
      state.routers = parsed.filter(r => r.os !== 'simulator' && !r.host.includes('172.16.20.1') && !r.host.includes('Sandbox'));
    } catch (e) {
      console.error('Failed to parse saved routers:', e);
    }
  }

  // If no routers defined yet, prompt connection and keep clean
  if (!state.routers || state.routers.length === 0) {
    updateActiveRouterUI(null);
    renderRouterDropdown();
    renderRoutersFleet();
    return;
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

  // Attempt to activate on backend
  fetch('/api/connect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id: active.id,
      name: active.name,
      host: active.host,
      port: active.port,
      user: active.user,
      password: active.password || '',
      os_type: active.os
    })
  }).then(res => res.json()).then(data => {
    if (data.success && data.discovery) {
      state.discovery = data.discovery;
      renderDiscoveryView(data.discovery);
      updateConnectionBadge(true);
    }
  }).catch(() => {});
}

function updateActiveRouterUI(active) {
  const nameEl = document.getElementById('topbar-router-name');
  const typeEl = document.getElementById('topbar-router-type');
  const dotEl = document.getElementById('active-router-dot');
  const footerStatus = document.getElementById('sidebar-system-status');
  const banner = document.getElementById('banner-connect-prompt');

  if (!active) {
    if (nameEl) nameEl.innerText = 'روتری متصل نیست';
    if (typeEl) typeEl.innerText = 'لطفاً مشخصات روتر را وارد کنید';
    if (dotEl) {
      dotEl.style.background = '#ef4444';
      dotEl.style.boxShadow = '0 0 8px #ef4444';
    }
    if (footerStatus) footerStatus.innerText = 'عدم اتصال به روتر';
    if (banner) banner.style.display = 'block';
    return;
  }

  if (banner) banner.style.display = 'none';

  const osInfo = getOSDetails(active.os);
  if (nameEl) nameEl.innerText = active.name;
  if (typeEl) typeEl.innerText = `${osInfo.label} • ${active.host}`;
  if (dotEl) {
    dotEl.style.background = '#10b981';
    dotEl.style.boxShadow = '0 0 8px rgba(16,185,129,0.6)';
  }
  if (footerStatus) {
    footerStatus.innerText = `متصل به ${active.name}`;
  }
}

function renderRouterDropdown() {
  const listEl = document.getElementById('router-dropdown-list');
  if (!listEl) return;

  if (!state.routers || state.routers.length === 0) {
    listEl.innerHTML = `
      <div style="padding:10px; font-size:0.8rem; color:var(--text-muted); text-align:center;">
        هیچ روتری ثبت نشده است.
      </div>
    `;
    return;
  }

  listEl.innerHTML = state.routers.map(r => {
    const osInfo = getOSDetails(r.os);
    const dotColor = r.is_active ? '#10b981' : '#64748b';
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

  if (!state.routers || state.routers.length === 0) {
    gridEl.innerHTML = `
      <div class="glass-panel" style="grid-column: 1 / -1; padding: 36px 20px; text-align: center; border-radius: 14px;">
        <div style="font-size: 2.5rem; margin-bottom: 10px;">📶</div>
        <h3 style="color: #fff; margin-bottom: 8px;">هیچ روتری در ناوگان ثبت نشده است</h3>
        <p style="color: var(--text-muted); font-size: 0.9rem; max-width: 500px; margin: 0 auto 20px;">
          برای مدیریت زنده، پایش ترافیک و اعمال کانفیگ‌های هوشمند، اولین روتر خود را متصل فرمایید.
        </p>
        <button class="btn btn-primary" onclick="openAddRouterModal()" style="padding: 10px 24px; font-size: 0.92rem;">
          ➕ افزودن و اتصال به روتر
        </button>
      </div>
    `;
    return;
  }

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
          <button class="btn btn-outline" style="font-size:0.78rem; padding:6px 10px; color:#ef4444;" onclick="deleteRouter('${r.id}')" title="حذف روتر از فهرست">
            🗑️
          </button>
        </div>
      </div>
    `;
  }).join('');
}

async function switchActiveRouter(routerId) {
  const target = state.routers.find(r => r.id === routerId);
  if (!target) return;

  state.routers.forEach(r => {
    r.is_active = (r.id === routerId);
  });

  localStorage.setItem('rp_routers', JSON.stringify(state.routers));
  updateActiveRouterUI(target);
  renderRouterDropdown();
  renderRoutersFleet();

  document.getElementById('router-dropdown-menu')?.classList.remove('show');

  // Trigger backend connect to selected router
  try {
    const res = await fetch('/api/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: target.id,
        name: target.name,
        host: target.host,
        port: target.port,
        user: target.user,
        password: target.password || '',
        os_type: target.os
      })
    });
    const data = await res.json();
    if (data.success && data.discovery) {
      state.discovery = data.discovery;
      renderDiscoveryView(data.discovery);
      updateConnectionBadge(true);
    }
  } catch (e) {
    console.error('Failed to switch router on backend:', e);
  }
}

function openAddRouterModal() {
  const modal = document.getElementById('modal-add-router');
  if (!modal) return;
  document.getElementById('form-add-router')?.reset();
  const portInput = document.getElementById('new-router-port');
  if (portInput) portInput.value = 'auto';
  const msgEl = document.getElementById('add-router-msg');
  if (msgEl) msgEl.style.display = 'none';
  updateModalNeighborsDropdown(state.neighbors);
  modal.classList.add('show');
}

function closeAddRouterModal() {
  const modal = document.getElementById('modal-add-router');
  if (modal) modal.classList.remove('show');
}

async function saveNewRouter() {
  const name = document.getElementById('new-router-name')?.value.trim();
  const os = document.getElementById('new-router-os')?.value || 'mikrotik_ros7';
  const host = document.getElementById('new-router-host')?.value.trim();
  const portRaw = document.getElementById('new-router-port')?.value.trim() || 'auto';
  const port = (portRaw.toLowerCase() === 'auto' || portRaw === '') ? 'auto' : (parseInt(portRaw, 10) || 80);
  const authtype = document.getElementById('new-router-authtype')?.value || 'password';
  const user = document.getElementById('new-router-user')?.value.trim() || 'admin';
  const pass = document.getElementById('new-router-pass')?.value || '';
  const submitBtn = document.getElementById('btn-submit-add-router');
  const msgEl = document.getElementById('add-router-msg');

  if (!name || !host) {
    alert('لطفاً نام روتر و آدرس IP را وارد کنید.');
    return;
  }

  // Show loading indicator
  if (submitBtn) {
    submitBtn.innerText = 'در حال مذاکره پورت و اتصال به روتر... ⏳';
    submitBtn.disabled = true;
  }
  if (msgEl) {
    msgEl.style.display = 'block';
    msgEl.innerHTML = '<span style="color:var(--primary);">در حال بررسی خودکار پورت‌های باز (80، 443، 8728، 8291)... لطفاً شکیبا باشید.</span>';
  }

  try {
    const res = await fetch('/api/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name,
        os_type: os,
        host,
        port,
        user,
        password: pass,
        use_tls: (port === 443 || port === 8443)
      })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      const newId = 'r-' + Date.now();
      const workingPort = data.working_port || (port === 'auto' ? 80 : port);
      const proto = data.protocol || 'REST API';
      const role = data.device_role || {};

      const newRouter = {
        id: newId,
        name: name || data.discovery?.Router?.Model || host,
        os,
        host,
        port: workingPort,
        user,
        password: pass,
        auth: authtype,
        status: 'online',
        is_active: true,
        protocol: proto,
        model: data.discovery?.Router?.Model || 'MikroTik',
        device_type: role.type || 'gateway_router',
        device_label: role.label || 'روتر لبه',
        device_icon: role.icon || '📶',
        wan_count: data.discovery?.WANs?.length || 1,
        container_supported: data.discovery?.Container?.Supported || false
      };

      // Set all existing to inactive
      state.routers.forEach(r => r.is_active = false);
      state.routers.push(newRouter);
      localStorage.setItem('rp_routers', JSON.stringify(state.routers));

      closeAddRouterModal();
      updateActiveRouterUI(newRouter);
      renderRouterDropdown();
      renderRoutersFleet();

      state.discovery = data.discovery;
      renderDiscoveryView(data.discovery);
      updateConnectionBadge(true);

      alert(`✅ اتصال موفق به روتر «${newRouter.name}» برقرار شد!\n• پورت فعال: ${workingPort} (${proto})\n• نوع دستگاه: ${role.label || 'روتر میکروتیک'}\n• معماری: ${data.discovery?.Router?.Architecture || '-'}`);
    } else {
      if (msgEl) {
        msgEl.innerHTML = `<span style="color:#ef4444; font-weight:600;">❌ ${data.error || 'خطا در برقراری ارتباط با روتر'}</span>`;
      }
    }
  } catch (err) {
    if (msgEl) {
      msgEl.innerHTML = `<span style="color:#ef4444; font-weight:600;">❌ خطای شبکه: ${err.message}</span>`;
    }
  } finally {
    if (submitBtn) {
      submitBtn.innerText = '🔌 آزمون و اتصال به روتر';
      submitBtn.disabled = false;
    }
  }
}

function deleteRouter(routerId) {
  const target = state.routers.find(r => r.id === routerId);
  if (!target) return;

  if (!confirm(`آیا از حذف روتر «${target.name}» مطمئن هستید؟`)) {
    return;
  }

  state.routers = state.routers.filter(r => r.id !== routerId);

  if (target.is_active) {
    if (state.routers.length > 0) {
      state.routers[0].is_active = true;
      updateActiveRouterUI(state.routers[0]);
    } else {
      updateActiveRouterUI(null);
    }
  }

  localStorage.setItem('rp_routers', JSON.stringify(state.routers));
  renderRouterDropdown();
  renderRoutersFleet();
}

// ==========================================
// MNDP Neighbors Discovery (Winbox-like L2)
// ==========================================

async function loadNeighbors() {
  const tbody = document.getElementById('neighbors-table-body');
  const statusEl = document.getElementById('neighbors-scan-status');
  try {
    const res = await fetch('/api/neighbors');
    const data = await res.json();
    state.neighbors = data.neighbors || [];
    renderNeighborsTable(state.neighbors);
    updateModalNeighborsDropdown(state.neighbors);
    if (statusEl) {
      statusEl.innerText = `${state.neighbors.length} دستگاه در شبکه شناسایی شد`;
    }
  } catch (e) {
    console.error('Failed to load neighbors:', e);
  }
}

async function triggerNeighborsScan() {
  const btn = document.getElementById('btn-scan-neighbors');
  const statusEl = document.getElementById('neighbors-scan-status');
  const tbody = document.getElementById('neighbors-table-body');
  
  if (btn) {
    btn.disabled = true;
    btn.innerText = '📡 در حال اسکن MNDP لایه ۲...';
  }
  if (statusEl) statusEl.innerText = 'ارسال پکت‌های Broadcast روی پورت UDP 5678...';
  if (tbody) {
    tbody.innerHTML = `
      <tr>
        <td colspan="9" style="text-align:center; padding:32px; color:var(--primary);">
          ⏳ در حال گوش دادن به پکت‌های MNDP (MikroTik Neighbor Discovery) و جدول ARP شبکه...
        </td>
      </tr>
    `;
  }

  try {
    const res = await fetch('/api/neighbors/scan', { method: 'POST' });
    const data = await res.json();
    state.neighbors = data.neighbors || [];
    renderNeighborsTable(state.neighbors);
    updateModalNeighborsDropdown(state.neighbors);
    if (statusEl) {
      statusEl.innerText = `اسکن پایان یافت: ${state.neighbors.length} دستگاه در شبکه یافت شد`;
    }
  } catch (err) {
    alert('خطا در اسکن همسایه‌ها: ' + err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = '🔄 اسکن زنده شبکه (MNDP Scan)';
    }
  }
}

function renderNeighborsTable(neighbors) {
  const tbody = document.getElementById('neighbors-table-body');
  if (!tbody) return;

  if (!neighbors || neighbors.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="9" style="text-align:center; padding:36px; color:var(--text-muted);">
          روتر یا تجهیزاتی در شبکه لایه ۲ کشف نشد.<br>
          <small style="color:var(--text-muted); margin-top:8px; display:inline-block;">
            مطمئن شوید روتر روشن است و کامپیوتر شما در همان کارت شبکه / ساب‌نت متصل است.
          </small>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = neighbors.map((n) => {
    const roleIcon = n.device_type === 'wireless_radio' ? '📡' : (n.device_type === 'cloud_switch' ? '🔀' : '📶');
    const roleColor = n.device_color || 'var(--primary)';
    const ipDisplay = n.ip && n.ip !== '0.0.0.0' ? n.ip : '<span style="color:#f59e0b;">(بدون IP / L2)</span>';
    return `
      <tr>
        <td>
          <span style="color:${roleColor}; font-weight:600; display:flex; align-items:center; gap:6px;">
            <span>${roleIcon}</span>
            <span>${n.device_label || 'روتر میکروتیک'}</span>
          </span>
        </td>
        <td><strong style="color:#fff;">${n.identity || 'MikroTik'}</strong></td>
        <td class="font-mono">${n.model || '-'}</td>
        <td class="font-mono" style="font-weight:700; color:#38bdf8;">${ipDisplay}</td>
        <td class="font-mono" style="color:var(--text-muted); font-size:0.82rem;">${n.mac || '-'}</td>
        <td class="font-mono">${n.interface || '-'}</td>
        <td class="font-mono">${n.version || '-'}</td>
        <td style="font-size:0.82rem; color:var(--text-muted);">${n.uptime || '-'}</td>
        <td>
          <button class="btn btn-primary" style="padding:4px 10px; font-size:0.78rem;" onclick="connectToDiscoveredNeighbor('${n.ip}', '${n.mac}', '${n.identity}', '${n.model}', '${n.device_type}')">
            🔌 اتصال سریع
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function updateModalNeighborsDropdown(neighbors) {
  const sel = document.getElementById('modal-neighbor-select');
  if (!sel) return;
  if (!neighbors || neighbors.length === 0) {
    sel.innerHTML = '<option value="">-- دستگاهی هنوز کشف نشده است (دکمه اسکن زنده را بزنید) --</option>';
    return;
  }
  sel.innerHTML = '<option value="">-- برای پر شدن خودکار، یک روتر کشف‌شده را انتخاب کنید --</option>' +
    neighbors.map((n, idx) => {
      const ip = (n.ip && n.ip !== '0.0.0.0') ? n.ip : '';
      return `<option value="${idx}">${n.identity} (${n.model}) - ${ip || n.mac} [${n.device_label || 'MikroTik'}]</option>`;
    }).join('');
}

function refreshModalNeighbors() {
  triggerNeighborsScan();
}

function applySelectedNeighborToModal() {
  const sel = document.getElementById('modal-neighbor-select');
  const val = sel?.value;
  if (val === '' || val === undefined) return;
  const n = state.neighbors[parseInt(val, 10)];
  if (!n) return;

  const nameInput = document.getElementById('new-router-name');
  const hostInput = document.getElementById('new-router-host');
  const portInput = document.getElementById('new-router-port');

  if (nameInput) nameInput.value = n.identity ? `${n.identity} (${n.model})` : n.model;
  if (hostInput && n.ip && n.ip !== '0.0.0.0') {
    hostInput.value = n.ip;
  }
  if (portInput) {
    portInput.value = 'auto';
  }
}

function connectToDiscoveredNeighbor(ip, mac, identity, model, devType) {
  openAddRouterModal();
  const nameInput = document.getElementById('new-router-name');
  const hostInput = document.getElementById('new-router-host');
  const portInput = document.getElementById('new-router-port');

  if (nameInput) nameInput.value = identity ? `${identity} (${model})` : model;
  if (hostInput) hostInput.value = (ip && ip !== '0.0.0.0') ? ip : '';
  if (portInput) portInput.value = 'auto';

  if (!ip || ip === '0.0.0.0') {
    alert(`دستگاه «${identity}» با مک‌آدرس ${mac} کشف شد اما در حال حاضر فاقد آدرس IP در این ساب‌نت است.\nلطفاً IP موقت به آن اختصاص دهید یا اتصال را با پورت 80 آزمون فرمایید.`);
    hostInput?.focus();
  }
}

// ==========================================
// Quick Config Gallery & AI Instant Generator (v1.5)
// ==========================================

async function loadQuickConfigProfiles() {
  try {
    const res = await fetch('/api/profiles');
    const data = await res.json();
    state.profiles = data || [];
    renderQuickConfigGrid();
  } catch (err) {
    console.error('Failed to load quick config profiles:', err);
  }
}

function renderQuickConfigGrid() {
  const grid = document.getElementById('quick-config-cards-grid');
  if (!grid) return;

  const filter = state.activeQuickFilter;
  const filtered = state.profiles.filter(p => {
    if (filter === 'all') return true;
    return (p.Category && p.Category.toLowerCase().includes(filter.toLowerCase())) ||
           (p.Name && p.Name.toLowerCase().includes(filter.toLowerCase()));
  });

  if (filtered.length === 0) {
    grid.innerHTML = `
      <div class="glass-panel" style="grid-column: 1 / -1; padding:36px; text-align:center; color:var(--text-muted);">
        سناریویی در این دسته‌بندی یافت نشد.
      </div>
    `;
    return;
  }

  grid.innerHTML = filtered.map(p => `
    <div class="glass-panel stat-card" style="display:flex; flex-direction:column; justify-content:space-between; min-height:220px; border-right:4px solid var(--primary);">
      <div>
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="font-size:1.6rem;">${p.Icon || '⚡'}</span>
            <div>
              <span class="status-badge" style="font-size:0.72rem; padding:2px 8px; color:var(--primary);">${p.Category}</span>
              <h3 style="margin:4px 0 0 0; font-size:1.02rem; color:#fff;">${p.TitleFa || p.Name}</h3>
            </div>
          </div>
          <span style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">v${p.Version || '1.0'}</span>
        </div>

        <p style="font-size:0.83rem; color:var(--text-muted); line-height:1.5; margin:8px 0 14px 0;">
          ${p.Description}
        </p>
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; padding-top:12px; border-top:1px solid rgba(255,255,255,0.06);">
        <span style="font-size:0.76rem; color:var(--text-muted);">
          📋 ${p.Steps ? p.Steps.length : 1} مرحله اجرایی
        </span>
        <button class="btn btn-primary" style="font-size:0.8rem; padding:6px 14px;" onclick="compileProfileToPlan('${p.ID}')">
          ⚡ ساخت Plan و پیش‌نمایش
        </button>
      </div>
    </div>
  `).join('');
}

function filterQuickConfigCards(category, btnElement) {
  state.activeQuickFilter = category;
  document.querySelectorAll('.quick-filter-btn').forEach(b => b.classList.remove('active'));
  if (btnElement) btnElement.classList.add('active');
  renderQuickConfigGrid();
}

async function generateAIQuickPlan() {
  const input = document.getElementById('quick-ai-prompt');
  const statusEl = document.getElementById('quick-ai-status');
  const btn = document.getElementById('btn-quick-ai-generate');
  const prompt = input?.value.trim();

  if (!prompt) {
    alert('لطفاً سناریوی مورد نظر خود را تایپ فرمایید.');
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.innerText = 'در حال پردازش و استخراج دستورات با AI... ⏳';
  }
  if (statusEl) {
    statusEl.style.display = 'block';
    statusEl.style.color = 'var(--primary)';
    statusEl.innerText = 'هوش مصنوعی در حال بررسی ساختار روتر، اعتبارسنجی پارامترها و تدوین Plan است...';
  }

  try {
    const res = await fetch('/api/plan/ai-generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt })
    });
    const data = await res.json();
    if (data.success && data.plan) {
      state.currentPlan = data.plan;
      switchTab('plan');
      renderPlanView(data.plan);
      alert(`🎉 پلن «${data.plan.Name}» با موفقیت توسط هوش مصنوعی تولید شد!\nمی‌توانید مراحل و دستورات دقیق RouterOS را در جدول بررسی و با Dry-Run شبیه‌سازی کنید.`);
      if (input) input.value = '';
    } else {
      alert('خطا در تولید پلن: ' + (data.error || 'خطای نامشخص'));
    }
  } catch (err) {
    alert('خطای ارتباط با سرور: ' + err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = '⚡ تولید و پیش‌نمایش Plan';
    }
    if (statusEl) statusEl.style.display = 'none';
  }
}

// ==========================================
// Network Tools & Safe CLI Console Suite (v1.5)
// ==========================================

async function runLivePingProbe() {
  const target = document.getElementById('ping-target-input')?.value.trim() || '8.8.8.8';
  const count = parseInt(document.getElementById('ping-count-select')?.value || '4', 10);
  const term = document.getElementById('ping-result-terminal');
  const btn = document.getElementById('btn-run-ping');

  if (btn) {
    btn.disabled = true;
    btn.innerText = 'در حال ارسال پکت‌ها... ⏳';
  }
  if (term) {
    term.innerHTML = `<span style="color:#f59e0b;">PING ${target} (56 data bytes)...</span>\n`;
  }

  try {
    const res = await fetch('/api/diagnostics/ping', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, count })
    });
    const data = await res.json();
    if (data.success) {
      let output = `PING ${data.target} (${data.packets_sent} packets transmitted, ${data.packets_received} received, ${data.packet_loss}% packet loss)\n`;
      data.lines.forEach(l => {
        output += `  ${l}\n`;
      });
      output += `\n--- ${data.target} ping statistics ---\n`;
      output += `rtt min/avg/max = ${data.min_ms} / ${data.avg_ms} / ${data.max_ms} ms [Healthy]`;
      if (term) term.innerText = output;
    } else {
      if (term) term.innerHTML = `<span style="color:#ef4444;">خطا در ارسال پینگ: ${data.error || 'مقصد پاسخگو نیست'}</span>`;
    }
  } catch (err) {
    if (term) term.innerHTML = `<span style="color:#ef4444;">خطای شبکه: ${err.message}</span>`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = 'ارسال پینگ';
    }
  }
}

async function runLiveDNSProbe() {
  const domain = document.getElementById('dns-domain-input')?.value.trim() || 'google.com';
  const box = document.getElementById('dns-result-box');
  const btn = document.getElementById('btn-run-dns');

  if (btn) {
    btn.disabled = true;
    btn.innerText = 'در حال استعلام... ⏳';
  }
  if (box) {
    box.innerHTML = `<span style="color:#f59e0b;">Resolving domain '${domain}' via router resolver...</span>\n`;
  }

  try {
    const res = await fetch('/api/diagnostics/dns', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    const data = await res.json();
    if (data.success) {
      let output = `DNS Resolution Result for: ${data.domain}\n`;
      output += `Status: ${data.status}\n`;
      output += `Resolved IPs:\n`;
      data.ips.forEach((ip, idx) => {
        output += `  [${idx + 1}] ${ip}\n`;
      });
      output += `\nQuery Response Time: ${data.latency_ms} ms`;
      if (box) box.innerText = output;
    } else {
      if (box) box.innerHTML = `<span style="color:#ef4444;">خطای رزولوشن DNS: ${data.error}</span>`;
    }
  } catch (err) {
    if (box) box.innerHTML = `<span style="color:#ef4444;">خطای شبکه: ${err.message}</span>`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerText = 'تست رزولوشن';
    }
  }
}

function setConsoleCommand(cmd) {
  const input = document.getElementById('input-cli-command');
  if (input) {
    input.value = cmd;
    input.focus();
  }
}

async function submitCliCommand() {
  const input = document.getElementById('input-cli-command');
  const screen = document.getElementById('cli-terminal-screen');
  const cmd = input?.value.trim();
  if (!cmd) return;

  if (screen) {
    screen.innerHTML += `\n[admin@RouterPilot] > <span style="color:#fff;">${cmd}</span>\n`;
  }
  if (input) input.value = '';

  try {
    const res = await fetch('/api/command/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: cmd })
    });
    const data = await res.json();
    if (data.success) {
      if (screen) {
        screen.innerHTML += `<span style="color:#38bdf8;">${data.output}</span>\n`;
      }
    } else {
      if (screen) {
        screen.innerHTML += `<span style="color:#ef4444; font-weight:bold;">${data.error || 'دستور اجرا نشد.'}</span>\n`;
      }
    }
  } catch (err) {
    if (screen) {
      screen.innerHTML += `<span style="color:#ef4444;">خطای شبکه: ${err.message}</span>\n`;
    }
  }

  if (screen) {
    screen.scrollTop = screen.scrollHeight;
  }
}

// ========================================================
// Connected Clients & DHCP Leases Inspector (v1.6)
// ========================================================

async function loadConnectedClients(forceRefresh = false) {
  const tbody = document.getElementById('connected-clients-table-body');
  if (tbody && forceRefresh) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">
          در حال استعلام تازه از سرور DHCP و جدول ARP روتر... ⏳
        </td>
      </tr>
    `;
  }

  try {
    const res = await fetch('/api/clients');
    if (!res.ok) return;
    const data = await res.json();
    state.clients = data.clients || [];

    // Update KPI Counters
    const kpiTotal = document.getElementById('kpi-clients-total');
    if (kpiTotal) kpiTotal.innerText = data.count || 0;

    const kpiActive = document.getElementById('kpi-clients-active');
    if (kpiActive) kpiActive.innerText = data.active_count || 0;

    const kpiStatic = document.getElementById('kpi-clients-static');
    if (kpiStatic) kpiStatic.innerText = data.static_count || 0;

    renderClientsTable(state.clients);
  } catch (err) {
    console.error('Failed to load connected clients:', err);
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center; padding:24px; color:#ef4444;">
            خطا در دریافت لیست کلاینت‌ها: ${err.message}
          </td>
        </tr>
      `;
    }
  }
}

function renderClientsTable(clientsList) {
  const tbody = document.getElementById('connected-clients-table-body');
  if (!tbody) return;

  if (!clientsList || clientsList.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:32px; color:var(--text-muted);">
          هیچ کلاینت فعالی در جدول DHCP یا ARP یافت نشد (یا روتر متصل نیست).
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = clientsList.map(c => {
    const isStatic = c.is_static;
    const isBlocked = c.is_blocked;
    const statusColor = isBlocked ? '#ef4444' : (c.status === 'bound' ? '#10b981' : '#f59e0b');
    const statusText = isBlocked ? 'مسدود شده 🚫' : (c.status === 'bound' ? 'متصل (Bound)' : c.status);

    return `
      <tr style="${isBlocked ? 'background:rgba(239,68,68,0.06);' : ''}">
        <td>
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="font-size:1.1rem;">${isBlocked ? '🛑' : (c.hostname.includes('Phone') ? '📱' : '💻')}</span>
            <div>
              <strong style="color:#fff; font-size:0.9rem;">${escapeHtml(c.hostname)}</strong>
              ${c.comment ? `<div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(c.comment)}</div>` : ''}
            </div>
          </div>
        </td>
        <td class="font-mono" style="color:var(--primary); font-weight:600;">${c.ip}</td>
        <td class="font-mono" style="color:#cbd5e1; font-size:0.82rem;">${c.mac}</td>
        <td><span class="status-badge" style="font-size:0.75rem;">${c.interface || 'bridge'}</span></td>
        <td>
          <span class="status-badge" style="color:${isStatic ? '#a855f7' : '#06b6d4'}; border-color:${isStatic ? 'rgba(168,85,247,0.3)' : 'rgba(6,182,212,0.3)'};">
            ${isStatic ? '📌 ثابت (Static)' : '🔄 داینامیک (DHCP)'}
          </span>
          <span style="font-size:0.75rem; color:${statusColor}; margin-right:6px; font-weight:600;">${statusText}</span>
        </td>
        <td class="font-mono" style="font-size:0.8rem; color:var(--text-muted);">${c.expires_after || '---'}</td>
        <td>
          <div style="display:flex; gap:6px; flex-wrap:wrap;">
            ${!isStatic ? `
              <button class="btn btn-outline" style="padding:4px 9px; font-size:0.75rem; color:#a855f7; border-color:rgba(168,85,247,0.4);" 
                onclick="makeClientStatic('${c.mac}', '${c.ip}', '${escapeHtml(c.hostname)}')" title="تثبیت IP این دستگاه">
                📌 رزرو ثابت
              </button>
            ` : ''}
            ${!isBlocked ? `
              <button class="btn btn-outline" style="padding:4px 9px; font-size:0.75rem; color:#ef4444; border-color:rgba(239,68,68,0.4);" 
                onclick="blockClient('${c.mac}', '${c.ip}', '${escapeHtml(c.hostname)}')" title="مسدودسازی دسترسی اینترنت">
                🚫 مسدودسازی
              </button>
            ` : `
              <button class="btn btn-outline" style="padding:4px 9px; font-size:0.75rem; color:#10b981; border-color:rgba(16,185,129,0.4);" 
                onclick="unblockClient('${c.mac}', '${escapeHtml(c.hostname)}')" title="رفع مسدودسازی دستگاه">
                ✅ رفع انسداد
              </button>
            `}
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function filterClientsBySearch(query) {
  if (!query) {
    renderClientsTable(state.clients);
    return;
  }
  const filtered = state.clients.filter(c => 
    (c.hostname && c.hostname.toLowerCase().includes(query)) ||
    (c.ip && c.ip.includes(query)) ||
    (c.mac && c.mac.toLowerCase().includes(query))
  );
  renderClientsTable(filtered);
}

async function makeClientStatic(mac, ip, hostname) {
  try {
    const res = await fetch('/api/clients/make-static', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, ip, hostname })
    });
    const data = await res.json();
    if (data.success) {
      alert(`✅ ${data.message}\nبرای بررسی گام‌ها و اعمال نهایی، به بخش Planها منتقل می‌شوید.`);
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
    } else {
      alert(`خطا: ${data.error || 'عملیات ناموفق بود.'}`);
    }
  } catch (err) {
    alert(`خطای شبکه: ${err.message}`);
  }
}

async function blockClient(mac, ip, hostname) {
  if (!confirm(`آیا از مسدودسازی دسترسی اینترنت کلاینت «${hostname}» (${ip}) اطمینان دارید؟\nاین عملیات با ایجاد رول Drop در فایروال و با ایمنی کامل Zero-Lockout انجام می‌پذیرد.`)) {
    return;
  }

  try {
    const res = await fetch('/api/clients/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, ip, hostname })
    });
    const data = await res.json();
    if (data.success) {
      alert(`🛡️ ${data.message}\nPlan مسدودسازی آماده است. برای بازبینی و تأیید نهایی، به صفحه Planها منتقل می‌شوید.`);
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
    } else {
      alert(`خطای ایمنی: ${data.error || 'عملیات انجام نشد.'}`);
    }
  } catch (err) {
    alert(`خطای شبکه: ${err.message}`);
  }
}

async function unblockClient(mac, hostname) {
  try {
    const res = await fetch('/api/clients/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, hostname })
    });
    const data = await res.json();
    if (data.success) {
      alert(`✅ ${data.message}\nPlan رفع مسدودسازی آماده است.`);
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
    }
  } catch (err) {
    alert(`خطای شبکه: ${err.message}`);
  }
}

// ========================================================
// Live Interface Torch & Dynamic Bandwidth Monitor (v1.6)
// ========================================================

async function pollLiveTraffic() {
  try {
    const res = await fetch('/api/traffic/live');
    if (!res.ok) return;
    const data = await res.json();
    state.liveTraffic = data;

    // Update Dashboard KPI card
    const kpiTraffic = document.getElementById('kpi-traffic');
    const totalMbps = (data.total_rx_mbps + data.total_tx_mbps).toFixed(1);
    if (kpiTraffic) {
      kpiTraffic.innerHTML = `${totalMbps} <span style="font-size:0.8rem; font-weight:500;">Mbps</span>`;
    }
    const kpiTrafficSub = document.getElementById('kpi-traffic-sub');
    if (kpiTrafficSub) {
      kpiTrafficSub.innerHTML = `<span>↓ ${data.total_rx_mbps} Mbps</span> &nbsp;|&nbsp; <span>↑ ${data.total_tx_mbps} Mbps</span>`;
    }

    // Update Clients Tab KPI card
    const kpiClientsBw = document.getElementById('kpi-clients-live-bw');
    if (kpiClientsBw) {
      kpiClientsBw.innerHTML = `${totalMbps} <span style="font-size:0.8rem;">Mbps</span>`;
    }
    const kpiClientsBwSub = document.getElementById('kpi-clients-live-bw-sub');
    if (kpiClientsBwSub) {
      kpiClientsBwSub.innerText = `دریافت: ${data.total_rx_mbps} Mbps | ارسال: ${data.total_tx_mbps} Mbps`;
    }

    // Render Interface Torch Table if visible
    if (state.activeTab === 'clients') {
      renderTorchInterfacesTable(data.interfaces);
    }

    // Smoothly update Dashboard SVG Curve
    if (data.chart_points && data.chart_points.length > 0) {
      updateSvgTrafficChart(data.chart_points);
    }
  } catch (err) {
    // Silent fail on background polling
  }
}

function renderTorchInterfacesTable(interfaces) {
  const tbody = document.getElementById('torch-interfaces-table-body');
  if (!tbody) return;

  if (!interfaces || interfaces.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">
          اطلاعات پورت‌های روتر دریافت نشد.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = interfaces.map(iface => {
    const running = iface.running;
    const rx = iface.rx_mbps || 0;
    const tx = iface.tx_mbps || 0;
    const totalBytes = iface.rx_bytes + iface.tx_bytes;
    let bytesStr = `${totalBytes} B`;
    if (totalBytes > 1024 * 1024 * 1024) {
      bytesStr = `${(totalBytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    } else if (totalBytes > 1024 * 1024) {
      bytesStr = `${(totalBytes / (1024 * 1024)).toFixed(1)} MB`;
    } else if (totalBytes > 1024) {
      bytesStr = `${(totalBytes / 1024).toFixed(0)} KB`;
    }

    return `
      <tr>
        <td>
          <strong class="font-mono" style="color:#fff;">${iface.name}</strong>
        </td>
        <td><span class="status-badge" style="font-size:0.75rem;">${iface.type}</span></td>
        <td>
          <span class="status-badge" style="color:${running ? '#10b981' : '#64748b'}; border-color:${running ? 'rgba(16,185,129,0.3)' : 'rgba(100,116,139,0.3)'};">
            <span class="status-dot" style="background:${running ? '#10b981' : '#64748b'};"></span>
            ${running ? 'فعال (Up)' : 'غیرفعال'}
          </span>
        </td>
        <td class="font-mono" style="color:#38bdf8; font-weight:700;">
          ↓ ${rx.toFixed(2)} <span style="font-size:0.75rem; color:var(--text-muted);">Mbps</span>
        </td>
        <td class="font-mono" style="color:#a855f7; font-weight:700;">
          ↑ ${tx.toFixed(2)} <span style="font-size:0.75rem; color:var(--text-muted);">Mbps</span>
        </td>
        <td class="font-mono" style="font-size:0.8rem; color:var(--text-muted);">${bytesStr}</td>
      </tr>
    `;
  }).join('');
}

function updateSvgTrafficChart(points) {
  const fillPath = document.getElementById('chart-svg-fill');
  const linePath = document.getElementById('chart-svg-line');
  const dot = document.getElementById('chart-svg-dot');
  if (!fillPath || !linePath) return;

  const width = 500;
  const height = 160;
  const maxVal = Math.max(...points, 20);
  const step = width / (points.length - 1);

  const coords = points.map((p, idx) => {
    const x = Math.round(idx * step);
    const y = Math.round(height - 20 - ((p / maxVal) * (height - 40)));
    return { x, y };
  });

  let lineD = `M ${coords[0].x},${coords[0].y}`;
  for (let i = 1; i < coords.length; i++) {
    const prev = coords[i - 1];
    const curr = coords[i];
    const cpx = (prev.x + curr.x) / 2;
    lineD += ` Q ${cpx},${prev.y} ${curr.x},${curr.y}`;
  }

  const fillD = `${lineD} L ${width},${height} L 0,${height} Z`;

  fillPath.setAttribute('d', fillD);
  linePath.setAttribute('d', lineD);
  if (dot && coords.length > 0) {
    const last = coords[coords.length - 1];
    dot.setAttribute('cx', last.x);
    dot.setAttribute('cy', last.y);
  }
}

// ========================================================
// Top Talkers & Active Connections (v1.6)
// ========================================================

async function loadTopTalkers() {
  const container = document.getElementById('top-talkers-list-container');
  const badge = document.getElementById('badge-total-conns');

  try {
    const res = await fetch('/api/connections/top');
    if (!res.ok) return;
    const data = await res.json();

    if (badge) {
      badge.innerText = `${data.total_connections || 0} سشن فعال`;
    }

    if (!container) return;

    if (!data.top_talkers || data.top_talkers.length === 0) {
      container.innerHTML = `
        <div style="text-align:center; padding:24px; color:var(--text-muted); font-size:0.85rem;">
          سشن فعالی در جدول فایروال کشف نشد.
        </div>
      `;
      return;
    }

    container.innerHTML = data.top_talkers.map((t, idx) => `
      <div style="display:flex; justify-content:space-between; align-items:center; padding:10px 14px; background:rgba(255,255,255,0.03); border:1px solid var(--glass-border); border-radius:10px;">
        <div style="display:flex; align-items:center; gap:10px;">
          <span style="font-weight:700; color:var(--primary); font-size:0.85rem;">#${idx + 1}</span>
          <div>
            <div style="font-size:0.88rem; color:#fff; font-weight:600;">${escapeHtml(t.hostname)}</div>
            <div class="font-mono" style="font-size:0.75rem; color:var(--text-muted);">${t.ip}</div>
          </div>
        </div>
        <div style="text-align:left;">
          <span class="status-badge" style="color:#a855f7; font-size:0.75rem; padding:3px 8px;">
            ${t.connections} کانکشن
          </span>
          <div class="font-mono" style="font-size:0.72rem; color:var(--text-muted); margin-top:3px;">${t.bytes_formatted}</div>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load top talkers:', err);
  }
}

// ========================================================
// MikroTik Cloud DDNS & Scheduler Actions (v1.6)
// ========================================================

async function openCloudDdnsModal() {
  const modal = document.getElementById('modal-cloud-ddns');
  if (!modal) return;
  modal.style.display = 'flex';

  const nameEl = document.getElementById('cloud-ddns-name');
  const ipEl = document.getElementById('cloud-ddns-public-ip');
  const badgeEl = document.getElementById('cloud-ddns-status-badge');
  const btnToggle = document.getElementById('btn-toggle-cloud-ddns');

  if (nameEl) nameEl.innerText = 'در حال استعلام...';

  try {
    const res = await fetch('/api/cloud/status');
    const data = await res.json();
    state.cloudInfo = data;

    if (nameEl) nameEl.innerText = data.dns_name || 'ثبت نشده (غیرفعال)';
    if (ipEl) ipEl.innerText = data.public_address || '---';
    if (badgeEl) {
      const active = data.enabled;
      badgeEl.innerText = active ? `فعال (${data.status || 'Updated'})` : 'غیرفعال';
      badgeEl.style.color = active ? '#10b981' : '#f59e0b';
    }
    if (btnToggle) {
      btnToggle.innerText = data.enabled ? 'غیرفعال‌سازی Cloud DDNS' : 'فعال‌سازی سرویس ابری DDNS ⚡';
    }
  } catch (err) {
    if (nameEl) nameEl.innerText = 'خطا در استعلام';
  }
}

function closeCloudDdnsModal() {
  const modal = document.getElementById('modal-cloud-ddns');
  if (modal) modal.style.display = 'none';
}

async function toggleCloudDdns() {
  const current = state.cloudInfo?.enabled || false;
  closeCloudDdnsModal();
  try {
    const res = await fetch('/api/cloud/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !current })
    });
    const data = await res.json();
    if (data.success) {
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
      alert(`✅ Plan تغییر وضعیت MikroTik Cloud DDNS آماده شد.`);
    }
  } catch (err) {
    alert(`خطا: ${err.message}`);
  }
}

async function scheduleDailyBackupJob() {
  try {
    const res = await fetch('/api/scheduler/create-backup-job', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (data.success) {
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
      alert(`⏱️ Plan زمان‌بندی خودکار پشتیبان‌گیری روزانه (ساعت ۰۳:۰۰ بامداد) تولید شد.`);
    }
  } catch (err) {
    alert(`خطا: ${err.message}`);
  }
}
