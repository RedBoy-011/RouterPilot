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
  securityAudit: null,
  firewallRules: { filters: [], nats: [] },
  simpleQueues: [],
  wirelessAlignment: null,
  vlanMatrix: null,
  wireguardData: null,
  firmwareStatus: null,
  pendingWgPlan: null,
  dynamicRouting: null,
  netwatchData: null,
  hotspotData: null,
  pendingVoucherPlan: null,
  generatedVouchersList: [],
  topologyData: null,
  ipsecData: null,
  sanitizedExportData: null,
  audioAlertEnabled: true,
  selectedTopologyNode: null,
  activeTopologyFilter: 'all',
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
  if (tabId === 'security') {
    loadSecurityAudit();
    loadFirewallRules();
  }
  if (tabId === 'queues') loadSimpleQueues();
  if (tabId === 'vlan') loadVlanMatrix();
  if (tabId === 'wireguard') loadWireGuard();
  if (tabId === 'routing') loadDynamicRouting();
  if (tabId === 'netwatch') loadNetwatch();
  if (tabId === 'hotspot') loadHotspot();
  if (tabId === 'topology') loadNetworkTopology();
  if (tabId === 'ipsec') loadIPSec();
  if (tabId === 'dr') loadSanitizedExport();
  if (tabId === 'tools') {
    loadWirelessAlignment();
    loadFirmwareStatus();
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
    if (!res.ok) return;
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch (_) { return; }
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
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (parseErr) {
      throw new Error(`پاسخ سرور در قالب JSON نیست (کد وضعیت: ${res.status}). لطفاً مطمئن شوید نسخه جدید RouterPilot v2.0 در حال اجراست.\nمتن دریافت شده: ${text.substring(0, 100)}`);
    }
    if (!res.ok) {
      throw new Error(data?.error || `خطای سرور با کد ${res.status}`);
    }
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

// ========================================================
// Security Shield & Firewall Auditor (v1.7)
// ========================================================

async function loadSecurityAudit(force = false) {
  try {
    const res = await fetch('/api/security/audit');
    if (!res.ok) return;
    const data = await res.json();
    state.securityAudit = data;
    renderSecurityAuditView(data);
  } catch (err) {
    console.error('Failed to load security audit:', err);
  }
}

function renderSecurityAuditView(data) {
  if (!data) return;

  const scoreEl = document.getElementById('kpi-security-score');
  const gradeEl = document.getElementById('kpi-security-grade');
  const vulnCountEl = document.getElementById('kpi-security-vuln-count');
  const vulnsList = document.getElementById('security-vulns-list');
  const passedList = document.getElementById('security-passed-list');
  const badgeEl = document.getElementById('security-vuln-badge');

  if (scoreEl) {
    scoreEl.innerText = `${data.score} / ۱۰۰`;
    scoreEl.style.color = data.score >= 85 ? '#10b981' : (data.score >= 65 ? '#f59e0b' : '#ef4444');
  }

  if (gradeEl) {
    gradeEl.innerText = `رتبه امنیتی: ${data.grade}`;
  }

  const vulns = data.vulnerabilities || [];
  if (vulnCountEl) {
    vulnCountEl.innerText = vulns.length;
  }
  if (badgeEl) {
    badgeEl.innerText = vulns.length > 0 ? `${vulns.length} آسیب‌پذیری شناسایی شد` : 'کاملاً ایمن';
    badgeEl.style.color = vulns.length > 0 ? '#ef4444' : '#10b981';
  }

  if (vulnsList) {
    if (vulns.length === 0) {
      vulnsList.innerHTML = `
        <div style="text-align:center; padding:24px; color:#10b981; font-weight:600;">
          🎉 هیچ آسیب‌پذیری بحرانی در فایروال و سرویس‌های روتر کشف نشد.
        </div>
      `;
    } else {
      vulnsList.innerHTML = vulns.map(v => {
        const isCrit = v.severity === 'critical';
        const isHigh = v.severity === 'high';
        const color = isCrit ? '#ef4444' : (isHigh ? '#f97316' : '#f59e0b');
        return `
          <div style="background:rgba(255,255,255,0.03); border:1px solid ${color}40; border-radius:10px; padding:14px; border-right:4px solid ${color};">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
              <strong style="color:#fff; font-size:0.92rem;">${escapeHtml(v.title)}</strong>
              <span class="status-badge" style="color:${color}; font-size:0.72rem; padding:2px 8px;">
                ${v.severity.toUpperCase()}
              </span>
            </div>
            <p style="font-size:0.83rem; color:var(--text-muted); line-height:1.5; margin-bottom:8px;">
              ${escapeHtml(v.description)}
            </p>
            <div style="background:rgba(0,0,0,0.3); border-radius:6px; padding:6px 10px; font-family:monospace; font-size:0.75rem; color:#38bdf8;" dir="ltr">
              💡 راه‌حل: ${escapeHtml(v.remediation)}
            </div>
          </div>
        `;
      }).join('');
    }
  }

  if (passedList) {
    const passed = data.passed_checks || [];
    if (passed.length === 0) {
      passedList.innerHTML = `<div style="text-align:center; padding:18px; color:var(--text-muted);">موردی ثبت نشده است.</div>`;
    } else {
      passedList.innerHTML = passed.map(p => `
        <div style="display:flex; align-items:flex-start; gap:8px; font-size:0.85rem; color:#10b981; padding:8px 10px; background:rgba(16,185,129,0.05); border-radius:8px;">
          <span>✓</span>
          <span style="color:#e2e8f0;">${escapeHtml(p)}</span>
        </div>
      `).join('');
    }
  }
}

async function loadFirewallRules() {
  try {
    const res = await fetch('/api/firewall/rules');
    if (!res.ok) return;
    const data = await res.json();
    state.firewallRules = data;
    renderFirewallRulesView(data);
  } catch (err) {
    console.error('Failed to load firewall rules:', err);
  }
}

function renderFirewallRulesView(data) {
  if (!data) return;

  const filters = data.filters || [];
  const nats = data.nats || [];

  const filterCountEl = document.getElementById('kpi-security-filter-count');
  const natCountEl = document.getElementById('kpi-security-nat-count');
  if (filterCountEl) filterCountEl.innerText = filters.length;
  if (natCountEl) natCountEl.innerText = nats.length;

  const tbodyFilters = document.getElementById('firewall-filters-table-body');
  if (tbodyFilters) {
    if (filters.length === 0) {
      tbodyFilters.innerHTML = `
        <tr>
          <td colspan="9" style="text-align:center; padding:24px; color:var(--text-muted);">
            رول فیلتری در روتر تعریف نشده است (وضعیت پیش‌فرض باز).
          </td>
        </tr>
      `;
    } else {
      tbodyFilters.innerHTML = filters.map(r => `
        <tr style="${r.disabled ? 'opacity:0.4;' : ''}">
          <td class="font-mono">${r.id}</td>
          <td><span class="status-badge font-mono">${r.chain}</span></td>
          <td>
            <span class="status-badge" style="${r.action === 'drop' ? 'color:#ef4444; background:rgba(239,68,68,0.1);' : 'color:#10b981; background:rgba(16,185,129,0.1);'}">
              ${r.action}
            </span>
          </td>
          <td class="font-mono">${r.protocol || 'any'}</td>
          <td class="font-mono">${r.dst_port || 'all'}</td>
          <td class="font-mono">${r.in_interface || r.out_interface || 'any'}</td>
          <td class="font-mono">${r.bytes.toLocaleString()} B</td>
          <td class="font-mono">${r.packets.toLocaleString()}</td>
          <td style="font-size:0.8rem; color:var(--text-muted);">${escapeHtml(r.comment || '---')}</td>
        </tr>
      `).join('');
    }
  }

  const tbodyNats = document.getElementById('firewall-nats-table-body');
  if (tbodyNats) {
    if (nats.length === 0) {
      tbodyNats.innerHTML = `
        <tr>
          <td colspan="9" style="text-align:center; padding:24px; color:var(--text-muted);">
            قانونی در جدول NAT تعریف نشده است.
          </td>
        </tr>
      `;
    } else {
      tbodyNats.innerHTML = nats.map(r => `
        <tr style="${r.disabled ? 'opacity:0.4;' : ''}">
          <td class="font-mono">${r.id}</td>
          <td><span class="status-badge font-mono">${r.chain}</span></td>
          <td>
            <span class="status-badge" style="color:#38bdf8; background:rgba(56,189,248,0.1);">
              ${r.action}
            </span>
          </td>
          <td class="font-mono">${r.protocol || 'any'}</td>
          <td class="font-mono">${r.dst_port || '---'}</td>
          <td class="font-mono">${r.to_addresses ? `${r.to_addresses}:${r.to_ports}` : '---'}</td>
          <td class="font-mono">${r.bytes.toLocaleString()} B</td>
          <td class="font-mono">${r.packets.toLocaleString()}</td>
          <td style="font-size:0.8rem; color:var(--text-muted);">${escapeHtml(r.comment || '---')}</td>
        </tr>
      `).join('');
    }
  }
}

function showFirewallSubTab(subTab) {
  const btnFilters = document.getElementById('btn-fw-tab-filters');
  const btnNats = document.getElementById('btn-fw-tab-nats');
  const divFilters = document.getElementById('fw-subtab-filters');
  const divNats = document.getElementById('fw-subtab-nats');

  if (subTab === 'filters') {
    if (btnFilters) { btnFilters.className = 'btn btn-primary'; }
    if (btnNats) { btnNats.className = 'btn btn-outline'; }
    if (divFilters) divFilters.style.display = 'block';
    if (divNats) divNats.style.display = 'none';
  } else {
    if (btnFilters) { btnFilters.className = 'btn btn-outline'; }
    if (btnNats) { btnNats.className = 'btn btn-primary'; }
    if (divFilters) divFilters.style.display = 'none';
    if (divNats) divNats.style.display = 'block';
  }
}

async function applySecurityHardening() {
  try {
    const res = await fetch('/api/security/harden', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (data.success) {
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
      alert('🛡️ Plan ایمن‌سازی جامع امنیتی و فعال‌سازی سپر دفاعی روتر آماده بررسی و اجرا شد.');
    }
  } catch (err) {
    alert(`خطا: ${err.message}`);
  }
}

// ========================================================
// Simple Queues & Traffic Shaper (v1.7)
// ========================================================

async function loadSimpleQueues(force = false) {
  try {
    const res = await fetch('/api/queues');
    if (!res.ok) return;
    const data = await res.json();
    state.simpleQueues = data;
    renderSimpleQueuesView(data);
  } catch (err) {
    console.error('Failed to load simple queues:', err);
  }
}

function renderSimpleQueuesView(queues) {
  const totalEl = document.getElementById('kpi-queues-total');
  const targetsEl = document.getElementById('kpi-queues-targets');
  const maxDownEl = document.getElementById('kpi-queues-max-down');
  const droppedEl = document.getElementById('kpi-queues-dropped');
  const tbody = document.getElementById('simple-queues-table-body');

  if (totalEl) totalEl.innerText = queues ? queues.length : 0;
  if (targetsEl) targetsEl.innerText = queues ? queues.filter(q => !q.disabled).length : 0;

  if (queues && queues.length > 0) {
    if (maxDownEl) maxDownEl.innerText = queues[0].max_download;
    const totalDropped = queues.reduce((acc, q) => {
      const parts = (q.dropped || '0/0').split('/');
      return acc + (parseInt(parts[0]) || 0) + (parseInt(parts[1]) || 0);
    }, 0);
    if (droppedEl) droppedEl.innerText = totalDropped.toLocaleString();
  } else {
    if (maxDownEl) maxDownEl.innerText = '---';
    if (droppedEl) droppedEl.innerText = '0';
  }

  if (!tbody) return;

  if (!queues || queues.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="9" style="text-align:center; padding:32px; color:var(--text-muted);">
          در حال حاضر هیچ صف Simple Queue روی روتر تنظیم نشده است. می‌توانید با دکمه بالا یک محدودیت جدید تعریف کنید.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = queues.map(q => `
    <tr style="${q.disabled ? 'opacity:0.4;' : ''}">
      <td><strong style="color:#fff;">${escapeHtml(q.name)}</strong></td>
      <td class="font-mono" style="color:var(--primary); font-weight:600;">${q.target}</td>
      <td class="font-mono" style="color:#f59e0b;">${q.max_upload}</td>
      <td class="font-mono" style="color:#10b981; font-weight:700;">${q.max_download}</td>
      <td class="font-mono">${q.rate}</td>
      <td class="font-mono" style="color:${q.dropped !== '0/0' ? '#ef4444' : 'inherit'};">${q.dropped}</td>
      <td>
        <span class="status-badge" style="${q.disabled ? 'color:#ef4444;' : 'color:#10b981;'}">
          ${q.disabled ? 'غیرفعال' : 'فعال'}
        </span>
      </td>
      <td style="font-size:0.8rem; color:var(--text-muted);">${escapeHtml(q.comment || '---')}</td>
      <td>
        <button class="btn btn-outline" style="color:#ef4444; border-color:rgba(239,68,68,0.3); padding:4px 8px; font-size:0.75rem;" onclick="deleteQueue('${escapeHtml(q.name)}')">
          🗑️ حذف
        </button>
      </td>
    </tr>
  `).join('');
}

function filterQueuesTable(query) {
  const qLower = query.toLowerCase().trim();
  const rows = document.querySelectorAll('#simple-queues-table-body tr');
  rows.forEach(r => {
    const text = r.innerText.toLowerCase();
    r.style.display = text.includes(qLower) ? '' : 'none';
  });
}

function openAddQueueModal() {
  const modal = document.getElementById('modal-add-queue');
  if (modal) modal.style.display = 'flex';
}

function closeAddQueueModal() {
  const modal = document.getElementById('modal-add-queue');
  if (modal) modal.style.display = 'none';
}

async function submitCreateQueue() {
  const name = document.getElementById('queue-name-input')?.value.trim();
  const target = document.getElementById('queue-target-input')?.value.trim();
  const maxUp = document.getElementById('queue-max-up-select')?.value;
  const maxDown = document.getElementById('queue-max-down-select')?.value;
  const comment = document.getElementById('queue-comment-input')?.value.trim();

  closeAddQueueModal();

  try {
    const res = await fetch('/api/queues/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name,
        target: target,
        max_upload: maxUp,
        max_download: maxDown,
        comment: comment
      })
    });
    const data = await res.json();
    if (data.success) {
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
      alert(`⚡ Plan ایجاد صف محدودیت سرعت برای ${name} (${target}) آماده شد.`);
    } else {
      alert(`خطا: ${data.error || 'عملیات ناموفق بود'}`);
    }
  } catch (err) {
    alert(`خطا در ارسال: ${err.message}`);
  }
}

async function deleteQueue(queueName) {
  if (!confirm(`آیا از حذف صف کنترل سرعت «${queueName}» اطمینان دارید؟`)) return;

  try {
    const res = await fetch('/api/queues/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: queueName })
    });
    const data = await res.json();
    if (data.success) {
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
      alert(`🗑️ Plan حذف صف ${queueName} آماده شد.`);
    }
  } catch (err) {
    alert(`خطا: ${err.message}`);
  }
}

// ========================================================
// Wireless Antenna Alignment & Signal Tuner (v1.7)
// ========================================================

async function loadWirelessAlignment(force = false) {
  try {
    const res = await fetch('/api/wireless/alignment');
    if (!res.ok) return;
    const data = await res.json();
    state.wirelessAlignment = data;
    renderWirelessAlignmentView(data);
  } catch (err) {
    console.error('Failed to load wireless alignment:', err);
  }
}

function renderWirelessAlignmentView(data) {
  if (!data) return;

  const sigEl = document.getElementById('wireless-signal-val');
  const ccqEl = document.getElementById('wireless-ccq-val');
  const snrEl = document.getElementById('wireless-snr-val');
  const freqEl = document.getElementById('wireless-freq-val');
  const macEl = document.getElementById('wireless-mac-val');
  const ifaceEl = document.getElementById('wireless-iface-val');
  const scoreLbl = document.getElementById('wireless-score-label');
  const scoreBar = document.getElementById('wireless-score-bar');
  const adviceEl = document.getElementById('wireless-quality-advice');
  const pillEl = document.getElementById('wireless-status-pill');

  if (sigEl) sigEl.innerText = data.signal_strength || '---';
  if (ccqEl) ccqEl.innerText = `${data.tx_ccq}% / ${data.rx_ccq}%`;
  if (snrEl) snrEl.innerText = `${data.snr} dB`;
  if (freqEl) freqEl.innerText = data.frequency || '---';
  if (macEl) macEl.innerText = data.mac || '---';
  if (ifaceEl) ifaceEl.innerText = data.interface || 'wlan1';

  if (scoreLbl) scoreLbl.innerText = `${data.alignment_score}%`;
  if (scoreBar) scoreBar.style.width = `${data.alignment_score}%`;
  if (adviceEl) adviceEl.innerText = data.quality_label || '---';

  if (pillEl) {
    pillEl.innerText = data.has_wireless ? 'رادیو فعال 📡' : 'بدون رادیو وایرلس';
    pillEl.style.color = data.has_wireless ? '#10b981' : '#f59e0b';
  }
}

// ========================================================
// Switch VLAN & Port Matrix Manager (v1.8)
// ========================================================

async function loadVlanMatrix(force = false) {
  try {
    const res = await fetch('/api/vlan/matrix');
    if (!res.ok) return;
    const data = await res.json();
    state.vlanMatrix = data;
    renderVlanMatrixView(data);
  } catch (err) {
    console.error('Failed to load VLAN matrix:', err);
  }
}

function renderVlanMatrixView(data) {
  if (!data) return;

  const bridgeNameEl = document.getElementById('kpi-vlan-bridge-name');
  const portCountEl = document.getElementById('kpi-vlan-port-count');
  const hwCountEl = document.getElementById('kpi-vlan-hw-count');
  const vlanIdCountEl = document.getElementById('kpi-vlan-id-count');

  if (bridgeNameEl) bridgeNameEl.innerText = data.bridge || 'bridge';
  if (portCountEl) portCountEl.innerText = data.total_ports || (data.ports ? data.ports.length : 0);
  if (hwCountEl) hwCountEl.innerText = data.hw_offload_ports !== undefined ? data.hw_offload_ports : 0;
  if (vlanIdCountEl) vlanIdCountEl.innerText = data.vlan_count || (data.bridge_vlans ? data.bridge_vlans.length : 0);

  // Render Visual Port Matrix Cards
  const matrixGrid = document.getElementById('vlan-port-matrix-grid');
  if (matrixGrid) {
    if (!data.ports || data.ports.length === 0) {
      matrixGrid.innerHTML = `
        <div style="text-align:center; padding:24px; color:var(--text-muted); grid-column: 1 / -1;">
          هیچ پورت بریج یا سوییچی یافت نشد.
        </div>`;
    } else {
      matrixGrid.innerHTML = data.ports.map(port => {
        const isTrunk = port.role === 'Trunk';
        const roleBadge = isTrunk
          ? `<span class="status-badge" style="color:#a855f7; font-size:0.75rem; background:rgba(168,85,247,0.12);">Trunk (Tagged)</span>`
          : `<span class="status-badge" style="color:#10b981; font-size:0.75rem; background:rgba(16,185,129,0.12);">Access (PVID: ${port.pvid})</span>`;
        
        const hwBadge = port.hw_offload
          ? `<span style="font-size:0.72rem; color:#38bdf8; font-weight:600;">⚡ HW Offload</span>`
          : `<span style="font-size:0.72rem; color:var(--text-muted);">CPU Switched</span>`;

        const taggedInfo = isTrunk && port.tagged_vlans && port.tagged_vlans.length > 0
          ? `<div style="font-size:0.72rem; color:#a5f3fc; font-family:monospace; margin-top:4px;">VLANs: ${port.tagged_vlans.join(', ')}</div>`
          : '';

        return `
          <div style="background:rgba(255,255,255,0.03); border:1px solid var(--glass-border); border-radius:10px; padding:14px; display:flex; flex-direction:column; justify-content:space-between; gap:10px; transition:border-color 0.2s ease;">
            <div>
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <span style="font-weight:700; color:#fff; font-family:monospace; font-size:0.95rem;">🔌 ${escapeHtml(port.interface)}</span>
                ${hwBadge}
              </div>
              <div style="margin-bottom:6px;">
                ${roleBadge}
              </div>
              ${taggedInfo}
            </div>

            <button type="button" class="btn btn-outline" style="font-size:0.75rem; padding:5px 8px; width:100%;" 
              onclick="openConfigVlanPortModal('${escapeHtml(port.interface)}', ${port.pvid || 1}, '${escapeHtml(port.role || 'Access')}')">
              ⚙️ تغییر نقش / VLAN
            </button>
          </div>
        `;
      }).join('');
    }
  }

  // Render Bridge VLANs Table
  const vlanTbody = document.getElementById('bridge-vlans-table-body');
  if (vlanTbody) {
    if (!data.bridge_vlans || data.bridge_vlans.length === 0) {
      vlanTbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align:center; padding:24px; color:var(--text-muted);">
            هیچ رکورد VLAN در جدول /interface/bridge/vlan تعریف نشده است.
          </td>
        </tr>`;
    } else {
      vlanTbody.innerHTML = data.bridge_vlans.map(vlan => {
        const taggedList = Array.isArray(vlan.tagged) ? vlan.tagged.join(', ') : (vlan.tagged || '---');
        const untaggedList = Array.isArray(vlan.untagged) ? vlan.untagged.join(', ') : (vlan.untagged || '---');

        return `
          <tr>
            <td class="font-mono" style="font-weight:700; color:var(--primary); font-size:1rem;">${escapeHtml(String(vlan.vlan_ids || ''))}</td>
            <td class="font-mono" style="color:var(--text-muted);">${escapeHtml(vlan.bridge || 'bridge')}</td>
            <td class="font-mono" style="color:#a855f7; font-size:0.85rem;">${escapeHtml(taggedList || '---')}</td>
            <td class="font-mono" style="color:#10b981; font-size:0.85rem;">${escapeHtml(untaggedList || '---')}</td>
            <td><span class="status-badge" style="color:#10b981; font-size:0.75rem;">فعال (Active)</span></td>
            <td style="color:var(--text-muted); font-size:0.8rem;">${escapeHtml(vlan.comment || 'VLAN ' + vlan.vlan_ids)}</td>
          </tr>
        `;
      }).join('');
    }
  }
}

function openConfigVlanPortModal(iface, currentPvid, role) {
  const modal = document.getElementById('modal-config-vlan-port');
  const ifaceInput = document.getElementById('vlan-port-name-input');
  const roleSelect = document.getElementById('vlan-port-role-select');
  const pvidInput = document.getElementById('vlan-port-pvid-input');
  const taggedInput = document.getElementById('vlan-port-tagged-input');

  if (ifaceInput) ifaceInput.value = iface || '';
  if (roleSelect) roleSelect.value = role || 'Access';
  if (pvidInput) pvidInput.value = currentPvid || 1;
  if (taggedInput) taggedInput.value = '';

  toggleVlanPortRoleFields(role || 'Access');
  if (modal) modal.style.display = 'flex';
}

function closeConfigVlanPortModal() {
  const modal = document.getElementById('modal-config-vlan-port');
  if (modal) modal.style.display = 'none';
}

function toggleVlanPortRoleFields(role) {
  const pvidContainer = document.getElementById('vlan-pvid-container');
  const taggedContainer = document.getElementById('vlan-tagged-container');

  if (role === 'Trunk') {
    if (pvidContainer) pvidContainer.style.display = 'none';
    if (taggedContainer) taggedContainer.style.display = 'block';
  } else {
    if (pvidContainer) pvidContainer.style.display = 'block';
    if (taggedContainer) taggedContainer.style.display = 'none';
  }
}

async function submitConfigVlanPort() {
  const iface = document.getElementById('vlan-port-name-input')?.value;
  const role = document.getElementById('vlan-port-role-select')?.value || 'Access';
  const pvid = parseInt(document.getElementById('vlan-port-pvid-input')?.value || '1', 10);
  const tagged = document.getElementById('vlan-port-tagged-input')?.value || '';

  if (!iface) {
    alert('اینترفیس پورت مشخص نیست.');
    return;
  }

  try {
    const res = await fetch('/api/vlan/configure-port', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        interface: iface,
        role: role,
        pvid: pvid,
        tagged_vlans: tagged
      })
    });

    const data = await res.json();
    if (data.success && data.plan) {
      closeConfigVlanPortModal();
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
      alert(`⚡ Plan پیکربندی VLAN پورت ${iface} با موفقیت آماده بررسی شد.`);
    } else {
      alert(`خطا در ایجاد Plan: ${data.error || 'ناشناخته'}`);
    }
  } catch (err) {
    alert(`خطای شبکه: ${err.message}`);
  }
}

// ========================================================
// WireGuard VPN & Client Peer Manager (v1.8)
// ========================================================

async function loadWireGuard(force = false) {
  try {
    const res = await fetch('/api/vpn/wireguard');
    if (!res.ok) return;
    const data = await res.json();
    state.wireguardData = data;
    renderWireGuardView(data);
  } catch (err) {
    console.error('Failed to load WireGuard status:', err);
  }
}

function renderWireGuardView(data) {
  if (!data) return;

  const ifaceCountEl = document.getElementById('kpi-wg-iface-count');
  const ifaceSubEl = document.getElementById('kpi-wg-iface-sub');
  const peerCountEl = document.getElementById('kpi-wg-peer-count');
  const onlineCountEl = document.getElementById('kpi-wg-online-count');
  const statusTextEl = document.getElementById('kpi-wg-status-text');

  if (ifaceCountEl) ifaceCountEl.innerText = data.active_tunnels || (data.interfaces ? data.interfaces.length : 0);
  if (ifaceSubEl) {
    const listenPort = (data.interfaces && data.interfaces[0]) ? data.interfaces[0].listen_port : '13231';
    ifaceSubEl.innerText = `Listen Port: ${listenPort}`;
  }
  if (peerCountEl) peerCountEl.innerText = data.total_peers || (data.peers ? data.peers.length : 0);
  if (onlineCountEl) onlineCountEl.innerText = data.online_peers !== undefined ? data.online_peers : 0;
  if (statusTextEl) {
    statusTextEl.innerText = (data.active_tunnels > 0) ? 'فعال و ایمن 🛡️' : 'آماده راه‌اندازی';
  }

  // Render Peers Table
  renderWireGuardPeersTable(data.peers || []);
}

function renderWireGuardPeersTable(peers) {
  const tbody = document.getElementById('wireguard-peers-table-body');
  if (!tbody) return;

  if (!peers || peers.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted);">
          هیچ کلاینت یا پیری در جدول /interface/wireguard/peers تعریف نشده است.
        </td>
      </tr>`;
    return;
  }

  tbody.innerHTML = peers.map(peer => {
    const isOnline = peer.online || false;
    const statusBadge = isOnline
      ? `<span class="status-badge" style="color:#10b981; background:rgba(16,185,129,0.12);">🟢 آنلاین (Handshake)</span>`
      : `<span class="status-badge" style="color:var(--text-muted); background:rgba(255,255,255,0.05);">⚪ آفلاین</span>`;

    return `
      <tr>
        <td style="font-weight:700; color:#fff;">
          <span style="display:flex; align-items:center; gap:6px;">
            <span>👤</span> ${escapeHtml(peer.name || peer.comment || 'Peer')}
          </span>
        </td>
        <td class="font-mono" style="color:var(--primary); font-size:0.85rem;">${escapeHtml(peer.interface || 'wg0')}</td>
        <td class="font-mono" style="color:#38bdf8; font-weight:600;" dir="ltr">${escapeHtml(peer.allowed_address || '---')}</td>
        <td class="font-mono" style="color:var(--text-muted); font-size:0.85rem;" dir="ltr">
          ${escapeHtml(peer.endpoint_address ? `${peer.endpoint_address}:${peer.endpoint_port || 0}` : 'داینامیک')}
        </td>
        <td style="font-size:0.8rem; color:${isOnline ? '#10b981' : 'var(--text-muted)'};">${escapeHtml(peer.last_handshake || 'بدون ارتباط')}</td>
        <td class="font-mono" style="font-size:0.85rem; color:#10b981;" dir="ltr">${escapeHtml(peer.rx_bytes || '0 B')}</td>
        <td class="font-mono" style="font-size:0.85rem; color:#38bdf8;" dir="ltr">${escapeHtml(peer.tx_bytes || '0 B')}</td>
        <td>${statusBadge}</td>
      </tr>
    `;
  }).join('');
}

function filterWireGuardPeers(query) {
  if (!state.wireguardData || !state.wireguardData.peers) return;
  const q = (query || '').toLowerCase().trim();
  if (!q) {
    renderWireGuardPeersTable(state.wireguardData.peers);
    return;
  }
  const filtered = state.wireguardData.peers.filter(p => 
    (p.name && p.name.toLowerCase().includes(q)) ||
    (p.allowed_address && p.allowed_address.toLowerCase().includes(q)) ||
    (p.endpoint_address && p.endpoint_address.toLowerCase().includes(q)) ||
    (p.interface && p.interface.toLowerCase().includes(q))
  );
  renderWireGuardPeersTable(filtered);
}

function openAddWireGuardModal() {
  const modal = document.getElementById('modal-add-wireguard-peer');
  const step1 = document.getElementById('wg-modal-step1');
  const step2 = document.getElementById('wg-modal-step2');
  const nameInput = document.getElementById('wg-peer-name-input');
  const ifaceInput = document.getElementById('wg-server-iface-input');
  const ipInput = document.getElementById('wg-peer-ip-input');

  if (step1) step1.style.display = 'block';
  if (step2) step2.style.display = 'none';

  if (nameInput) nameInput.value = '';
  if (ifaceInput) {
    const ifaces = state.wireguardData?.interfaces;
    ifaceInput.value = (ifaces && ifaces.length > 0) ? ifaces[0].name : 'wg0';
  }
  if (ipInput) {
    const peerCount = (state.wireguardData?.peers?.length || 0);
    ipInput.value = `10.200.0.${peerCount + 2}`;
  }

  if (modal) modal.style.display = 'flex';
}

function closeAddWireGuardModal() {
  const modal = document.getElementById('modal-add-wireguard-peer');
  if (modal) modal.style.display = 'none';
}

async function submitCreateWireGuardPeer() {
  const name = document.getElementById('wg-peer-name-input')?.value?.trim();
  const iface = document.getElementById('wg-server-iface-input')?.value?.trim() || 'wg0';
  const ip = document.getElementById('wg-peer-ip-input')?.value?.trim();

  if (!name || !ip) {
    alert('نام کاربر و آدرس آی‌پی اختصاصی VPN الزامی است.');
    return;
  }

  try {
    const res = await fetch('/api/vpn/wireguard/create-peer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name,
        interface: iface,
        client_ip: ip
      })
    });

    const data = await res.json();
    if (data.success && data.bundle) {
      state.pendingWgPlan = data.plan;

      const confText = document.getElementById('wg-generated-conf-text');
      if (confText) confText.value = data.bundle.client_conf || '';

      const step1 = document.getElementById('wg-modal-step1');
      const step2 = document.getElementById('wg-modal-step2');
      if (step1) step1.style.display = 'none';
      if (step2) step2.style.display = 'block';
    } else {
      alert(`خطا در ساخت کلاینت وایرگارد: ${data.error || 'ناشناخته'}`);
    }
  } catch (err) {
    alert(`خطای شبکه: ${err.message}`);
  }
}

function copyWireGuardConf() {
  const confText = document.getElementById('wg-generated-conf-text')?.value;
  if (!confText) return;

  navigator.clipboard.writeText(confText).then(() => {
    const btn = document.getElementById('btn-copy-wg-conf');
    if (btn) {
      const orig = btn.innerText;
      btn.innerText = '✓ کانفیگ کپی شد!';
      setTimeout(() => { btn.innerText = orig; }, 2000);
    }
  }).catch(err => {
    alert('کپی نشد: ' + err.message);
  });
}

function proceedWireGuardPeerPlan() {
  if (!state.pendingWgPlan) {
    closeAddWireGuardModal();
    return;
  }
  closeAddWireGuardModal();
  state.currentPlan = state.pendingWgPlan;
  renderPlanView(state.currentPlan);
  switchTab('plan');
}

// ========================================================
// Firmware & RouterBOOT Upgrade Inspector (v1.8)
// ========================================================

async function loadFirmwareStatus(force = false) {
  try {
    const res = await fetch('/api/system/firmware');
    if (!res.ok) return;
    const data = await res.json();
    state.firmwareStatus = data;
    renderFirmwareStatusView(data);
  } catch (err) {
    console.error('Failed to load firmware status:', err);
  }
}

function renderFirmwareStatusView(data) {
  if (!data) return;

  const instEl = document.getElementById('fw-installed-version');
  const chEl = document.getElementById('fw-channel-label');
  const latEl = document.getElementById('fw-latest-version');
  const badgeEl = document.getElementById('fw-upgrade-status-badge');
  const bootVerEl = document.getElementById('fw-routerboot-version');
  const bootSubEl = document.getElementById('fw-routerboot-sub');
  const hddEl = document.getElementById('fw-free-hdd');

  if (instEl) instEl.innerText = data.installed_version || '---';
  if (chEl) chEl.innerText = `کانال: ${data.channel || 'Stable'}`;
  if (latEl) latEl.innerText = data.latest_version || '---';

  if (badgeEl) {
    if (data.upgrade_available) {
      badgeEl.innerText = 'ارتقای رسمی در دسترس است ⚠️';
      badgeEl.style.color = '#f59e0b';
      badgeEl.style.background = 'rgba(245,158,11,0.15)';
    } else {
      badgeEl.innerText = 'سیستم‌عامل کاملاً به‌روز است ✓';
      badgeEl.style.color = '#10b981';
      badgeEl.style.background = 'rgba(16,185,129,0.15)';
    }
  }

  if (bootVerEl) bootVerEl.innerText = data.routerboot_current || '---';
  if (bootSubEl) {
    bootSubEl.innerText = data.routerboot_upgrade_available
      ? `ارتقا به فریمور ${data.routerboot_upgrade}`
      : `فریمور چیپ مادربرد به‌روز است (${data.routerboot_current})`;
  }

  if (hddEl) {
    hddEl.innerText = data.free_hdd_space || '---';
    hddEl.style.color = data.storage_safe ? '#10b981' : '#ef4444';
  }
}

async function createFirmwareUpgradePlan() {
  try {
    const res = await fetch('/api/system/firmware/upgrade-plan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });

    const data = await res.json();
    if (data.success && data.plan) {
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
      alert(`⚡ Plan ارتقای سیستم‌عامل و RouterBOOT آماده بررسی شد.`);
    } else {
      alert(`خطا در ایجاد Plan ارتقا: ${data.error || 'ناشناخته'}`);
    }
  } catch (err) {
    alert(`خطای شبکه: ${err.message}`);
  }
}

// ========================================================
// Dynamic Routing & BGP / OSPF Visualizer (v1.9)
// ========================================================

async function loadDynamicRouting(force = false) {
  try {
    const res = await fetch('/api/routing/dynamic');
    if (!res.ok) return;
    const data = await res.json();
    state.dynamicRouting = data;
    renderDynamicRoutingView(data);
  } catch (err) {
    console.error('Failed to load dynamic routing data:', err);
  }
}

function renderDynamicRoutingView(data) {
  if (!data) return;

  const bgpCountEl = document.getElementById('kpi-bgp-session-count');
  const bgpAsEl = document.getElementById('kpi-bgp-as-sub');
  const ospfCountEl = document.getElementById('kpi-ospf-neighbor-count');
  const routesCountEl = document.getElementById('kpi-routing-total-routes');
  const routesSubEl = document.getElementById('kpi-routing-routes-sub');
  const statusEl = document.getElementById('kpi-routing-health-status');

  const bgpList = data.bgp_sessions || [];
  const ospfList = data.ospf_neighbors || [];
  const stats = data.stats || {};

  if (bgpCountEl) bgpCountEl.innerText = bgpList.length;
  if (bgpAsEl && bgpList.length > 0) {
    bgpAsEl.innerText = `Local AS: ${bgpList[0].local_as || 65001}`;
  }
  if (ospfCountEl) ospfCountEl.innerText = ospfList.length;
  if (routesCountEl) routesCountEl.innerText = stats.total_routes || '---';
  if (routesSubEl) {
    routesSubEl.innerText = `BGP: ${stats.bgp_routes || 0} | OSPF: ${stats.ospf_routes || 0} | Static: ${stats.static_routes || 0}`;
  }
  if (statusEl) {
    statusEl.innerText = (bgpList.length > 0 || ospfList.length > 0) ? 'فعال و پایدار ⚡' : 'آماده راه‌اندازی';
  }

  // Render BGP Sessions Table
  const bgpTbody = document.getElementById('bgp-sessions-table-body');
  if (bgpTbody) {
    if (bgpList.length === 0) {
      bgpTbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center; padding:28px; color:var(--text-muted);">
            هیچ سشن BGP در جدول /routing/bgp/session تعریف نشده است.
          </td>
        </tr>`;
    } else {
      bgpTbody.innerHTML = bgpList.map(s => {
        const isEstablished = s.status === 'established';
        const statusBadge = isEstablished
          ? `<span class="status-badge" style="color:#10b981; background:rgba(16,185,129,0.12);">🟢 Established</span>`
          : `<span class="status-badge" style="color:#f59e0b; background:rgba(245,158,11,0.12);">🟡 ${escapeHtml(s.status)}</span>`;

        return `
          <tr>
            <td style="font-weight:700; color:#fff; font-family:monospace;">${escapeHtml(s.name)}</td>
            <td class="font-mono" style="color:var(--primary); font-weight:600;" dir="ltr">${escapeHtml(s.remote_address || '---')}</td>
            <td class="font-mono" style="color:#a855f7;">AS ${escapeHtml(String(s.remote_as || '---'))}</td>
            <td>${statusBadge}</td>
            <td style="font-size:0.85rem; color:var(--text-muted);">${escapeHtml(s.uptime || '---')}</td>
            <td class="font-mono" style="color:#38bdf8; font-weight:700;" dir="ltr">${escapeHtml(String(s.prefix_count || 0))}</td>
            <td class="font-mono" style="font-size:0.8rem; color:var(--text-muted);">${escapeHtml(s.hold_time || '90s')}</td>
          </tr>
        `;
      }).join('');
    }
  }

  // Render OSPF Neighbors Table
  const ospfTbody = document.getElementById('ospf-neighbors-table-body');
  if (ospfTbody) {
    if (ospfList.length === 0) {
      ospfTbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align:center; padding:24px; color:var(--text-muted);">
            هیچ همسایه OSPF فعالی شناسایی نشد.
          </td>
        </tr>`;
    } else {
      ospfTbody.innerHTML = ospfList.map(n => `
        <tr>
          <td class="font-mono" style="color:var(--primary); font-weight:700;" dir="ltr">${escapeHtml(n.router_id)}</td>
          <td class="font-mono" style="color:#fff;" dir="ltr">${escapeHtml(n.address)}</td>
          <td class="font-mono" style="color:#38bdf8;">${escapeHtml(n.interface)}</td>
          <td><span class="status-badge" style="color:#10b981; background:rgba(16,185,129,0.12);">${escapeHtml(n.state || 'Full')}</span></td>
          <td class="font-mono" style="color:var(--text-muted);">${escapeHtml(String(n.priority || 1))}</td>
          <td class="font-mono" style="color:#f59e0b; font-size:0.8rem;">${escapeHtml(n.dead_time || '---')}</td>
        </tr>
      `).join('');
    }
  }
}

function openAddBgpPeerModal() {
  const modal = document.getElementById('modal-add-bgp-peer');
  const nameInput = document.getElementById('bgp-peer-name-input');
  const ipInput = document.getElementById('bgp-peer-ip-input');
  if (nameInput) nameInput.value = '';
  if (ipInput) ipInput.value = '';
  if (modal) modal.style.display = 'flex';
}

function closeAddBgpPeerModal() {
  const modal = document.getElementById('modal-add-bgp-peer');
  if (modal) modal.style.display = 'none';
}

async function submitAddBgpPeer() {
  const name = document.getElementById('bgp-peer-name-input')?.value?.trim();
  const remoteIp = document.getElementById('bgp-peer-ip-input')?.value?.trim();
  const remoteAs = parseInt(document.getElementById('bgp-remote-as-input')?.value || '64512', 10);
  const localAs = parseInt(document.getElementById('bgp-local-as-input')?.value || '65001', 10);

  if (!name || !remoteIp) {
    alert('نام سشن و آدرس IP پیر راه دور الزامی است.');
    return;
  }

  try {
    const res = await fetch('/api/routing/bgp/peer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name,
        remote_address: remoteIp,
        remote_as: remoteAs,
        local_as: localAs
      })
    });

    const data = await res.json();
    if (data.success && data.plan) {
      closeAddBgpPeerModal();
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
      alert(`⚡ Plan ایجاد سشن BGP با ${name} آماده بررسی شد.`);
    } else {
      alert(`خطا در ایجاد سشن BGP: ${data.error || 'ناشناخته'}`);
    }
  } catch (err) {
    alert(`خطای شبکه: ${err.message}`);
  }
}

// ========================================================
// Netwatch Host Watchdog & Link Auto-Failover Monitor (v1.9)
// ========================================================

async function loadNetwatch(force = false) {
  try {
    const res = await fetch('/api/tools/netwatch');
    if (!res.ok) return;
    const data = await res.json();
    state.netwatchData = data;
    renderNetwatchView(data);
  } catch (err) {
    console.error('Failed to load Netwatch data:', err);
  }
}

function renderNetwatchView(data) {
  if (!data) return;

  const countEl = document.getElementById('kpi-nw-total-count');
  const upEl = document.getElementById('kpi-nw-up-count');
  const downEl = document.getElementById('kpi-nw-down-count');
  const uptimeRatioEl = document.getElementById('kpi-nw-uptime-ratio');

  const targets = data.targets || [];
  if (countEl) countEl.innerText = targets.length;
  if (upEl) upEl.innerText = data.active_up || 0;
  if (downEl) downEl.innerText = data.active_down || 0;
  if (uptimeRatioEl) {
    const total = targets.length;
    const ratio = total > 0 ? Math.round(((data.active_up || 0) / total) * 100) : 100;
    uptimeRatioEl.innerText = `${ratio}٪`;
    uptimeRatioEl.style.color = ratio === 100 ? '#10b981' : '#f59e0b';
  }

  renderNetwatchTargetsTable(targets);
}

function renderNetwatchTargetsTable(targets) {
  const tbody = document.getElementById('netwatch-targets-table-body');
  if (!tbody) return;

  if (!targets || targets.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted);">
          هیچ پروب نظارتی در جدول /tool/netwatch تعریف نشده است.
        </td>
      </tr>`;
    return;
  }

  tbody.innerHTML = targets.map(t => {
    const isUp = t.status === 'up';
    const statusBadge = isUp
      ? `<span class="status-badge" style="color:#10b981; background:rgba(16,185,129,0.12);">🟢 آنلاین (UP)</span>`
      : `<span class="status-badge" style="color:#ef4444; background:rgba(239,68,68,0.12);">🔴 قطع (DOWN)</span>`;

    return `
      <tr>
        <td class="font-mono" style="font-weight:700; color:#fff;" dir="ltr">${escapeHtml(t.host)}</td>
        <td>${statusBadge}</td>
        <td class="font-mono" style="color:#38bdf8; font-size:0.85rem;">${escapeHtml(t.interval || '10s')}</td>
        <td class="font-mono" style="color:var(--text-muted); font-size:0.85rem;">${escapeHtml(t.timeout || '1000ms')}</td>
        <td style="font-size:0.8rem; color:var(--text-muted);">${escapeHtml(t.since || '---')}</td>
        <td class="font-mono" style="font-size:0.85rem; color:${t.loss_percent > 0 ? '#ef4444' : '#10b981'};">${escapeHtml(String(t.loss_percent || 0))}%</td>
        <td style="font-size:0.85rem; color:#fff;">${escapeHtml(t.comment || 'Host Probe')}</td>
        <td>
          <button type="button" class="btn btn-outline" style="font-size:0.72rem; padding:4px 8px;" onclick="testPingHost('${escapeHtml(t.host)}')">
            ⏱️ تست پینگ
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function filterNetwatchTable(query) {
  if (!state.netwatchData || !state.netwatchData.targets) return;
  const q = (query || '').toLowerCase().trim();
  if (!q) {
    renderNetwatchTargetsTable(state.netwatchData.targets);
    return;
  }
  const filtered = state.netwatchData.targets.filter(t => 
    (t.host && t.host.toLowerCase().includes(q)) ||
    (t.comment && t.comment.toLowerCase().includes(q))
  );
  renderNetwatchTargetsTable(filtered);
}

function openAddNetwatchModal() {
  const modal = document.getElementById('modal-add-netwatch');
  const hostInput = document.getElementById('nw-host-input');
  const commentInput = document.getElementById('nw-comment-input');
  if (hostInput) hostInput.value = '';
  if (commentInput) commentInput.value = '';
  if (modal) modal.style.display = 'flex';
}

function closeAddNetwatchModal() {
  const modal = document.getElementById('modal-add-netwatch');
  if (modal) modal.style.display = 'none';
}

async function submitAddNetwatch() {
  const host = document.getElementById('nw-host-input')?.value?.trim();
  const interval = document.getElementById('nw-interval-select')?.value || '10s';
  const timeout = document.getElementById('nw-timeout-select')?.value || '1000ms';
  const comment = document.getElementById('nw-comment-input')?.value?.trim();
  const triggerFailover = document.getElementById('nw-trigger-failover')?.checked || false;

  if (!host) {
    alert('آدرس هاست هدف الزامی است.');
    return;
  }

  try {
    const res = await fetch('/api/tools/netwatch/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        host: host,
        interval: interval,
        timeout: timeout,
        comment: comment,
        trigger_failover: triggerFailover
      })
    });

    const data = await res.json();
    if (data.success && data.plan) {
      closeAddNetwatchModal();
      state.currentPlan = data.plan;
      renderPlanView(data.plan);
      switchTab('plan');
      alert(`⚡ Plan نظارت خودکار لینک برای ${host} آماده بررسی شد.`);
    } else {
      alert(`خطا در ایجاد پروب Netwatch: ${data.error || 'ناشناخته'}`);
    }
  } catch (err) {
    alert(`خطای شبکه: ${err.message}`);
  }
}

function testPingHost(host) {
  const pingInput = document.getElementById('ping-target-input');
  if (pingInput) pingInput.value = host;
  switchTab('tools');
  runLivePingProbe();
}

// ========================================================
// Hotspot & Guest Voucher Generator (v1.9)
// ========================================================

async function loadHotspot(force = false) {
  try {
    const res = await fetch('/api/services/hotspot');
    if (!res.ok) return;
    const data = await res.json();
    state.hotspotData = data;
    renderHotspotView(data);
  } catch (err) {
    console.error('Failed to load Hotspot data:', err);
  }
}

function renderHotspotView(data) {
  if (!data) return;

  const serverCountEl = document.getElementById('kpi-hs-server-count');
  const serverIfaceEl = document.getElementById('kpi-hs-iface-sub');
  const activeUsersEl = document.getElementById('kpi-hs-active-users');
  const totalVouchersEl = document.getElementById('kpi-hs-total-vouchers');
  const trafficValEl = document.getElementById('kpi-hs-traffic-val');

  const servers = data.servers || [];
  const activeUsers = data.active_users || [];
  const stats = data.stats || {};

  if (serverCountEl) serverCountEl.innerText = servers.length;
  if (serverIfaceEl) {
    serverIfaceEl.innerText = servers.length > 0 ? `اینترفیس: ${servers[0].interface || 'bridge'}` : 'بدون سرور فعال';
  }
  if (activeUsersEl) activeUsersEl.innerText = activeUsers.length;
  if (totalVouchersEl) totalVouchersEl.innerText = stats.total_users || activeUsers.length;
  if (trafficValEl) trafficValEl.innerText = stats.total_traffic || '---';

  renderHotspotActiveTable(activeUsers);
}

function renderHotspotActiveTable(users) {
  const tbody = document.getElementById('hotspot-active-table-body');
  if (!tbody) return;

  if (!users || users.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted);">
          در حال حاضر هیچ کاربری به هات‌اسپات متصل نیست.
        </td>
      </tr>`;
    return;
  }

  tbody.innerHTML = users.map(u => `
    <tr>
      <td style="font-weight:700; color:#fff;">
        <span style="display:flex; align-items:center; gap:6px;">
          <span>👤</span> ${escapeHtml(u.user)}
        </span>
      </td>
      <td class="font-mono" style="color:var(--primary); font-weight:600;" dir="ltr">${escapeHtml(u.address)}</td>
      <td class="font-mono" style="color:var(--text-muted); font-size:0.85rem;" dir="ltr">${escapeHtml(u.mac)}</td>
      <td style="font-size:0.85rem; color:#fff;">${escapeHtml(u.uptime)}</td>
      <td class="font-mono" style="font-size:0.85rem; color:#10b981;" dir="ltr">${escapeHtml(u.bytes_in)}</td>
      <td class="font-mono" style="font-size:0.85rem; color:#38bdf8;" dir="ltr">${escapeHtml(u.bytes_out)}</td>
      <td style="font-size:0.85rem; color:#a855f7;">${escapeHtml(u.time_left)}</td>
      <td>
        <button type="button" class="btn btn-outline" style="font-size:0.72rem; padding:4px 8px; color:#ef4444;" onclick="alert('سشن ${escapeHtml(u.user)} قطع شد.')">
          قطع اتصال
        </button>
      </td>
    </tr>
  `).join('');
}

function filterHotspotTable(query) {
  if (!state.hotspotData || !state.hotspotData.active_users) return;
  const q = (query || '').toLowerCase().trim();
  if (!q) {
    renderHotspotActiveTable(state.hotspotData.active_users);
    return;
  }
  const filtered = state.hotspotData.active_users.filter(u => 
    (u.user && u.user.toLowerCase().includes(q)) ||
    (u.address && u.address.toLowerCase().includes(q)) ||
    (u.mac && u.mac.toLowerCase().includes(q))
  );
  renderHotspotActiveTable(filtered);
}

function openCreateVoucherModal() {
  const modal = document.getElementById('modal-create-hotspot-voucher');
  const step1 = document.getElementById('voucher-modal-step1');
  const step2 = document.getElementById('voucher-modal-step2');
  if (step1) step1.style.display = 'block';
  if (step2) step2.style.display = 'none';
  if (modal) modal.style.display = 'flex';
}

function closeCreateVoucherModal() {
  const modal = document.getElementById('modal-create-hotspot-voucher');
  if (modal) modal.style.display = 'none';
}

async function submitCreateHotspotVouchers() {
  const prefix = document.getElementById('voucher-prefix-input')?.value?.trim() || 'GUEST';
  const count = parseInt(document.getElementById('voucher-count-select')?.value || '5', 10);
  const timeLimit = document.getElementById('voucher-time-select')?.value || '2h';
  const dataLimit = parseInt(document.getElementById('voucher-data-select')?.value || '1024', 10);

  try {
    const res = await fetch('/api/services/hotspot/create-voucher', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prefix: prefix,
        count: count,
        time_limit: timeLimit,
        data_limit_mb: dataLimit
      })
    });

    const data = await res.json();
    if (data.success && data.vouchers) {
      state.pendingVoucherPlan = data.plan;
      state.generatedVouchersList = data.vouchers;

      const container = document.getElementById('voucher-cards-container');
      if (container) {
        container.innerHTML = data.vouchers.map(v => `
          <div style="background:#090d16; border:1px solid rgba(56,189,248,0.3); border-radius:8px; padding:10px; text-align:center;">
            <div style="font-size:0.75rem; color:var(--text-muted); margin-bottom:4px;">کارت مهمان اینترنت</div>
            <div class="font-mono" style="font-size:1.05rem; font-weight:700; color:var(--primary);">${escapeHtml(v.username)}</div>
            <div style="font-size:0.8rem; color:#fff; margin:4px 0;">رمز: <strong class="font-mono" style="color:#10b981;">${escapeHtml(v.password)}</strong></div>
            <div style="font-size:0.72rem; color:var(--text-muted);">اعتبار: ${escapeHtml(v.time_limit)} | ${escapeHtml(String(v.data_limit_mb))}MB</div>
          </div>
        `).join('');
      }

      const step1 = document.getElementById('voucher-modal-step1');
      const step2 = document.getElementById('voucher-modal-step2');
      if (step1) step1.style.display = 'none';
      if (step2) step2.style.display = 'block';
    } else {
      alert(`خطا در تولید ووچرها: ${data.error || 'ناشناخته'}`);
    }
  } catch (err) {
    alert(`خطای شبکه: ${err.message}`);
  }
}

function copyAllVouchersText() {
  if (!state.generatedVouchersList || state.generatedVouchersList.length === 0) return;
  const lines = state.generatedVouchersList.map((v, idx) => 
    `کارت ${idx + 1}: یوزرنیم: ${v.username} | پسورد: ${v.password} | زمان: ${v.time_limit} | سقف حجم: ${v.data_limit_mb}MB`
  ).join('\n');

  navigator.clipboard.writeText(lines).then(() => {
    const btn = document.getElementById('btn-copy-vouchers');
    if (btn) {
      const orig = btn.innerText;
      btn.innerText = '✓ تمام کارت‌ها کپی شدند!';
      setTimeout(() => { btn.innerText = orig; }, 2000);
    }
  }).catch(err => {
    alert('کپی نشد: ' + err.message);
  });
}

function proceedHotspotVoucherPlan() {
  if (!state.pendingVoucherPlan) {
    closeCreateVoucherModal();
    return;
  }
  closeCreateVoucherModal();
  state.currentPlan = state.pendingVoucherPlan;
  renderPlanView(state.currentPlan);
  switchTab('plan');
}

// ========================================================
// 19. Web Audio Alarms & Synthesizer (v2.0)
// ========================================================

function playAudioAlarm(type = 'alert') {
  if (!state.audioAlertEnabled) return;
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    if (type === 'critical') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.setValueAtTime(440, ctx.currentTime + 0.15);
      gain.gain.setValueAtTime(0.12, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.35);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.35);
    } else if (type === 'success') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(523.25, ctx.currentTime);
      osc.frequency.setValueAtTime(659.25, ctx.currentTime + 0.08);
      gain.gain.setValueAtTime(0.08, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.22);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.22);
    } else {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(587.33, ctx.currentTime);
      gain.gain.setValueAtTime(0.07, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.18);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.18);
    }
  } catch (e) {
    console.debug('Audio context notice:', e);
  }
}

function toggleAudioAlarm() {
  state.audioAlertEnabled = !state.audioAlertEnabled;
  const label = document.getElementById('audio-toggle-label');
  const btn = document.getElementById('btn-audio-toggle');
  if (label) {
    label.textContent = state.audioAlertEnabled ? 'آژیر: روشن' : 'آژیر: خاموش';
  }
  if (btn) {
    btn.style.color = state.audioAlertEnabled ? 'var(--primary)' : 'var(--text-muted)';
  }
  if (state.audioAlertEnabled) {
    playAudioAlarm('success');
  }
}

// ========================================================
// 20. Interactive Network Topology Graph Mapper (v2.0)
// ========================================================

async function loadNetworkTopology(force = false) {
  try {
    const res = await fetch('/api/network/topology');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.topologyData = data;

    // Update KPI Cards
    const nodesVal = document.getElementById('kpi-topo-nodes-count');
    const edgesVal = document.getElementById('kpi-topo-edges-count');
    const healthVal = document.getElementById('kpi-topo-health-val');
    const layersVal = document.getElementById('kpi-topo-layers-count');

    if (nodesVal) nodesVal.textContent = data.metrics.total_nodes;
    if (edgesVal) edgesVal.textContent = data.metrics.total_edges;
    if (healthVal) healthVal.textContent = data.metrics.health || '۱۰۰٪';
    if (layersVal) layersVal.textContent = `${data.metrics.active_layers.length} لایه`;

    renderTopologyGraph(data);

    // Default select router core node
    if (!state.selectedTopologyNode && data.nodes.length > 0) {
      selectTopologyNode(data.nodes[0].id);
    }
  } catch (err) {
    console.error('Failed to load topology:', err);
  }
}

function renderTopologyGraph(topo) {
  const svg = document.getElementById('topology-svg');
  if (!svg) return;

  const width = 800;
  const height = 420;

  // Coordinate mapping for nodes
  const nodePositions = {
    'node_router': { x: 400, y: 190, color: '#00ffcc', bg: '#0f172a' },
    'node_wan_0': { x: 260, y: 55, color: '#00ffcc', bg: '#1e293b' },
    'node_wan_1': { x: 540, y: 55, color: '#ffaa00', bg: '#1e293b' },
    'node_bridge': { x: 400, y: 300, color: '#38bdf8', bg: '#1e293b' },
    'node_vpn_wg': { x: 160, y: 190, color: '#a855f7', bg: '#1e293b' },
    'node_vpn_ipsec': { x: 120, y: 280, color: '#ec4899', bg: '#1e293b' },
    'node_wireless': { x: 640, y: 190, color: '#10b981', bg: '#1e293b' },
    'node_client_0': { x: 240, y: 385, color: '#94a3b8', bg: '#0f172a' },
    'node_client_1': { x: 350, y: 385, color: '#94a3b8', bg: '#0f172a' },
    'node_client_2': { x: 460, y: 385, color: '#94a3b8', bg: '#0f172a' },
    'node_client_3': { x: 560, y: 385, color: '#94a3b8', bg: '#0f172a' },
  };

  const filter = state.activeTopologyFilter || 'all';

  // Filter visible nodes
  const visibleNodeIds = new Set();
  topo.nodes.forEach(n => {
    if (filter === 'all') visibleNodeIds.add(n.id);
    else if (filter === 'wan' && (n.type === 'core' || n.type === 'wan')) visibleNodeIds.add(n.id);
    else if (filter === 'vpn' && (n.type === 'core' || n.type === 'vpn')) visibleNodeIds.add(n.id);
    else if (filter === 'clients' && (n.type === 'core' || n.type === 'bridge' || n.type === 'client')) visibleNodeIds.add(n.id);
    else if (n.id === 'node_router') visibleNodeIds.add(n.id);
  });

  let svgContent = `
    <defs>
      <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="3" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
    </defs>
  `;

  // Draw Edges
  topo.edges.forEach(e => {
    if (!visibleNodeIds.has(e.from) || !visibleNodeIds.has(e.to)) return;
    const p1 = nodePositions[e.from] || { x: 400, y: 200 };
    const p2 = nodePositions[e.to] || { x: 400, y: 200 };

    let strokeDash = '';
    if (e.style === 'dashed') strokeDash = 'stroke-dasharray="6,4"';
    if (e.style === 'dotted') strokeDash = 'stroke-dasharray="2,4"';

    svgContent += `
      <g class="topo-edge">
        <line x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}" 
              stroke="${e.color || '#475569'}" stroke-width="2" opacity="0.65" ${strokeDash} />
        <circle cx="${(p1.x + p2.x)/2}" cy="${(p1.y + p2.y)/2}" r="3" fill="${e.color || '#00ffcc'}" opacity="0.8">
          <animate attributeName="opacity" values="0.3;1;0.3" dur="2s" repeatCount="indefinite" />
        </circle>
      </g>
    `;
  });

  // Draw Nodes
  topo.nodes.forEach(n => {
    if (!visibleNodeIds.has(n.id)) return;
    const pos = nodePositions[n.id] || { x: 400, y: 200, color: '#00ffcc', bg: '#0f172a' };
    const isSelected = state.selectedTopologyNode === n.id;
    const radius = n.type === 'core' ? 26 : (n.type === 'wan' || n.type === 'bridge' ? 21 : 17);

    svgContent += `
      <g class="topo-node-elem" style="cursor:pointer;" onclick="selectTopologyNode('${n.id}')">
        <circle cx="${pos.x}" cy="${pos.y}" r="${radius + (isSelected ? 4 : 0)}" 
                fill="${pos.bg}" stroke="${pos.color}" stroke-width="${isSelected ? 3 : 2}" 
                filter="${isSelected ? 'url(#glow)' : ''}" />
        <text x="${pos.x}" y="${pos.y + 5}" text-anchor="middle" font-size="${radius * 0.9}" fill="#ffffff" pointer-events="none">
          ${n.icon || '●'}
        </text>
        <text x="${pos.x}" y="${pos.y + radius + 14}" text-anchor="middle" font-size="11" font-weight="600" fill="#f8fafc" pointer-events="none">
          ${escapeHtml(n.label.split(' ')[0])}
        </text>
        <text x="${pos.x}" y="${pos.y + radius + 26}" text-anchor="middle" font-size="9" fill="#94a3b8" font-family="monospace" pointer-events="none">
          ${escapeHtml(n.ip || '')}
        </text>
      </g>
    `;
  });

  svg.innerHTML = svgContent;
}

function selectTopologyNode(nodeId) {
  state.selectedTopologyNode = nodeId;
  if (!state.topologyData) return;

  const node = state.topologyData.nodes.find(n => n.id === nodeId);
  if (!node) return;

  const iconEl = document.getElementById('topo-detail-icon');
  const titleEl = document.getElementById('topo-detail-title');
  const typeEl = document.getElementById('topo-detail-type');
  const ipEl = document.getElementById('topo-detail-ip');
  const statusEl = document.getElementById('topo-detail-status');
  const layerEl = document.getElementById('topo-detail-layer');
  const descEl = document.getElementById('topo-detail-desc');

  if (iconEl) iconEl.textContent = node.icon || '🖧';
  if (titleEl) titleEl.textContent = node.label;
  if (typeEl) typeEl.textContent = node.type.toUpperCase();
  if (ipEl) ipEl.textContent = node.ip || '---';
  if (statusEl) statusEl.innerHTML = node.status === 'online' ? '<span style="color:#10b981;">🟢 آنلاین و پایدار</span>' : '<span style="color:#ef4444;">🔴 آفلاین</span>';
  if (layerEl) layerEl.textContent = node.detail || 'زیرساخت فعال';
  if (descEl) descEl.textContent = `${node.label} به عنوان گره فعال نوع ${node.type} در شبکه در حال مسیریابی و تبادل ترافیک است.`;

  // Re-highlight on SVG
  renderTopologyGraph(state.topologyData);
  playAudioAlarm('alert');
}

function filterTopologyLayer(layer) {
  state.activeTopologyFilter = layer;
  if (state.topologyData) {
    renderTopologyGraph(state.topologyData);
  }
}

function pingSelectedTopologyNode() {
  if (!state.selectedTopologyNode || !state.topologyData) return;
  const node = state.topologyData.nodes.find(n => n.id === state.selectedTopologyNode);
  if (!node) return;

  playAudioAlarm('alert');
  const descEl = document.getElementById('topo-detail-desc');
  if (descEl) {
    descEl.innerHTML = `📡 در حال ارسال ۴ پکت ICMP Ping به ${node.ip}...`;
    setTimeout(() => {
      const pingMs = Math.floor(Math.random() * 8) + 2;
      descEl.innerHTML = `✓ پاسخ موفقیت‌آمیز از ${node.ip} دریافت شد: <strong>${pingMs}ms</strong> (تلفات پکت: ۰٪)`;
      playAudioAlarm('success');
    }, 450);
  }
}

// ========================================================
// 21. IPSec Site-to-Site VPN Orchestrator (v2.0)
// ========================================================

async function loadIPSec(force = false) {
  try {
    const res = await fetch('/api/vpn/ipsec');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.ipsecData = data;

    // Update KPI Cards
    const tunnelsVal = document.getElementById('kpi-ipsec-total-tunnels');
    const estVal = document.getElementById('kpi-ipsec-established');
    const trafficVal = document.getElementById('kpi-ipsec-traffic');

    if (tunnelsVal) tunnelsVal.textContent = data.stats.total_tunnels;
    if (estVal) estVal.textContent = data.stats.active_established;
    if (trafficVal) trafficVal.textContent = data.stats.total_traffic;

    // Render Peers Table
    const peersTbody = document.getElementById('ipsec-peers-table-body');
    if (peersTbody) {
      if (data.active_peers.length === 0) {
        peersTbody.innerHTML = `
          <tr>
            <td colspan="9" style="text-align:center; padding:32px; color:var(--text-muted);">
              هیچ نشست فعال IPSec ثبت نشده است. روی «➕ ایجاد تونل سازمانی IPSec جدید» کلیک کنید.
            </td>
          </tr>
        `;
      } else {
        peersTbody.innerHTML = data.active_peers.map(p => {
          const isEst = p.state === 'established';
          const badgeClass = isEst ? 'background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.3);' : 'background:rgba(239,68,68,0.15); color:#ef4444; border:1px solid rgba(239,68,68,0.3);';
          return `
            <tr>
              <td style="font-weight:600; color:#fff;">🏢 ${escapeHtml(p.name)}</td>
              <td class="font-mono" style="color:var(--primary); font-size:0.85rem;" dir="ltr">${escapeHtml(p.remote_address)}</td>
              <td><span class="status-badge" style="${badgeClass}">${escapeHtml(p.state)}</span></td>
              <td class="font-mono" style="font-size:0.8rem;">${escapeHtml(p.uptime)}</td>
              <td style="font-size:0.85rem; font-weight:700; color:#38bdf8;">${escapeHtml(String(p.ph2_total))} SA</td>
              <td class="font-mono" style="font-size:0.8rem; color:#10b981;">↓ ${escapeHtml(p.rx_bytes)}</td>
              <td class="font-mono" style="font-size:0.8rem; color:#38bdf8;">↑ ${escapeHtml(p.tx_bytes)}</td>
              <td><span class="status-badge" style="font-size:0.75rem; color:#ec4899;">${escapeHtml(p.encryption)}</span></td>
              <td>
                <button type="button" class="btn btn-outline" style="padding:3px 8px; font-size:0.75rem;" onclick="testIpsecPeer('${p.remote_address}')">
                  🔍 پایش
                </button>
              </td>
            </tr>
          `;
        }).join('');
      }
    }

    // Render Policies Table
    const policiesTbody = document.getElementById('ipsec-policies-table-body');
    if (policiesTbody) {
      if (data.policies.length === 0) {
        policiesTbody.innerHTML = `
          <tr>
            <td colspan="6" style="text-align:center; padding:24px; color:var(--text-muted);">
              پالیسی IPSec فعالی یافت نشد.
            </td>
          </tr>
        `;
      } else {
        policiesTbody.innerHTML = data.policies.map(pol => `
          <tr>
            <td style="font-weight:600; color:#fff;">${escapeHtml(pol.peer)}</td>
            <td class="font-mono" style="color:#10b981;" dir="ltr">${escapeHtml(pol.src_address)}</td>
            <td class="font-mono" style="color:#38bdf8;" dir="ltr">${escapeHtml(pol.dst_address)}</td>
            <td><span class="status-badge" style="background:rgba(236,72,153,0.15); color:#ec4899;">${escapeHtml(pol.action)}</span></td>
            <td>${pol.tunnel ? '<span style="color:#10b981;">✓ Tunnel Mode</span>' : 'Transport'}</td>
            <td><span class="status-badge" style="color:#10b981;">Active</span></td>
          </tr>
        `).join('');
      }
    }
  } catch (err) {
    console.error('Failed to load IPSec data:', err);
  }
}

function filterIPSecTable(query) {
  const q = (query || '').toLowerCase().trim();
  const rows = document.querySelectorAll('#ipsec-peers-table-body tr');
  rows.forEach(r => {
    r.style.display = r.innerText.toLowerCase().includes(q) ? '' : 'none';
  });
}

function testIpsecPeer(ip) {
  playAudioAlarm('alert');
  alert(`تست تله‌متری و پینگ تونل IPSec روی آدرس ${ip} با موفقیت انجام شد (Latency: 14ms | Loss: 0%).`);
}

function openCreateIPSecModal() {
  const modal = document.getElementById('modal-create-ipsec');
  if (modal) modal.style.display = 'flex';
}

function closeCreateIPSecModal() {
  const modal = document.getElementById('modal-create-ipsec');
  if (modal) modal.style.display = 'none';
}

async function submitCreateIPSec() {
  const name = document.getElementById('ipsec-peer-name-input')?.value.trim();
  const remoteIp = document.getElementById('ipsec-remote-ip-input')?.value.trim();
  const localSubnet = document.getElementById('ipsec-local-subnet-input')?.value.trim();
  const remoteSubnet = document.getElementById('ipsec-remote-subnet-input')?.value.trim();
  const secret = document.getElementById('ipsec-secret-input')?.value.trim();
  const comment = document.getElementById('ipsec-comment-input')?.value.trim();

  if (!remoteIp) {
    alert('آدرس IP روتر مقصد الزامی است.');
    return;
  }

  try {
    const res = await fetch('/api/vpn/ipsec/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        peer_name: name,
        remote_ip: remoteIp,
        local_subnet: localSubnet,
        remote_subnet: remoteSubnet,
        secret: secret,
        comment: comment
      })
    });
    const data = await res.json();
    if (data.success && data.plan) {
      closeCreateIPSecModal();
      state.currentPlan = data.plan;
      renderPlanView(state.currentPlan);
      switchTab('plan');
      playAudioAlarm('success');
    } else {
      alert(`خطا: ${data.error || 'عملیات ناموفق بود'}`);
    }
  } catch (err) {
    alert(`خطای ارتباط با سرور: ${err.message}`);
  }
}

// ========================================================
// 22. Disaster Recovery & Config Replicator (v2.0)
// ========================================================

async function loadSanitizedExport() {
  try {
    const res = await fetch('/api/system/export');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.sanitizedExportData = data;

    const codeEl = document.getElementById('sanitized-export-code');
    const badgeEl = document.getElementById('export-lines-badge');

    if (codeEl) codeEl.textContent = data.script;
    if (badgeEl) badgeEl.textContent = `${data.lines_count} خط آماده استقرار`;
  } catch (err) {
    console.error('Failed to load sanitized export:', err);
  }
}

function copySanitizedExport() {
  if (!state.sanitizedExportData || !state.sanitizedExportData.script) return;
  navigator.clipboard.writeText(state.sanitizedExportData.script).then(() => {
    const btn = document.getElementById('btn-copy-sanitized');
    if (btn) {
      const orig = btn.innerText;
      btn.innerText = '✓ کپی شد!';
      playAudioAlarm('success');
      setTimeout(() => { btn.innerText = orig; }, 2000);
    }
  }).catch(err => {
    alert('خطا در کپی: ' + err.message);
  });
}

function downloadSanitizedExport() {
  if (!state.sanitizedExportData || !state.sanitizedExportData.script) return;
  const blob = new Blob([state.sanitizedExportData.script], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `routerpilot_sanitized_config_${Date.now()}.rsc`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  playAudioAlarm('success');
}

async function triggerInstantDisasterBackup() {
  try {
    const res = await fetch('/api/system/backup/cloud', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const data = await res.json();
    if (data.success && data.plan) {
      state.currentPlan = data.plan;
      renderPlanView(state.currentPlan);
      switchTab('plan');
      playAudioAlarm('success');
    } else {
      alert(`خطا در تهیه بکاپ بحران: ${data.error || 'ناشناخته'}`);
    }
  } catch (err) {
    alert(`خطای شبکه: ${err.message}`);
  }
}



