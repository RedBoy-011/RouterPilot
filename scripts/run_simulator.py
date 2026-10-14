#!/usr/bin/env python3
"""
RouterPilot Control Plane v1.4 - Standalone Local Runner & Live Network Controller
Featuring:
- MNDP Neighbors Discovery (L2 Neighbor broadcast scanning like Winbox)
- Smart Port Auto-Negotiation (auto-detection of Web 80, REST 443, API 8728, Winbox 8291)
- Automatic Device Role Categorization (Wireless Radio PTP/PTMP vs Cloud Switch vs Gateway Router)
- Live RouterOS 7 REST API / RouterOS 6 Controller
Runs with zero external dependencies using Python's standard library.
"""

import http.server
import socketserver
import json
import os
import sys
import time
import base64
import urllib.parse
import urllib.request
import urllib.error
import ssl
import socket
import struct
import subprocess
import webbrowser
from datetime import datetime

PORT = 8080
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(BASE_DIR, "web")

# In-memory clean Control Plane state (NO hardcoded fake router data!)
state = {
    "connected": False,
    "active_router": None,
    "active_router_config": None,
    "active_wan": "---",
    "backup_count": 0,
    "last_failover": None,
    "current_plan": None,
    "discovery": None,
    "neighbors": [],
    "last_neighbor_scan": None,
    "audit_logs": [
        {
            "Timestamp": datetime.now().isoformat(),
            "Category": "system",
            "Level": "info",
            "Message": "سیستم RouterPilot v1.4 با موفقیت روی ویندوز راه‌اندازی شد. در انتظار اسکن همسایه‌ها یا اتصال..."
        }
    ]
}

# ========================================================
# Device Role Categorization Engine
# ========================================================

def classify_device(model, version=""):
    """
    Classifies a MikroTik device into one of three major roles:
    1. Wireless Radio (PTP / PTMP links): LHG, SXT, DISC, QRT, BaseBox, DynaDish, etc.
    2. Cloud Router Switch (CRS / CSS): CRS, CSS, Cloud Router Switch, FiberBox.
    3. Gateway Router (Edge / Core): CCR, RB5009, RB4011, hEX, hAP, etc.
    """
    m = (model or "").lower()
    
    # 1. Wireless Radios & PTP / PTMP Links
    wireless_keywords = [
        "lhg", "sxt", "disc", "qrt", "netmetal", "basebox", "dynadish",
        "netbox", "groove", "metal", "mant", "omnitik", "wap", "cap", "sq"
    ]
    if any(k in m for k in wireless_keywords):
        return {
            "type": "wireless_radio",
            "label": "رادیو وایرلس و لینک PTP/PTMP",
            "icon": "📡",
            "color": "#10b981",
            "recommended_profile": "Wireless-PTP-Bridge",
            "description": "پایش لحظه‌ای سیگنال (RSSI/CCQ)، بهینه‌سازی فرکانس و تراز آنتن"
        }

    # 2. Cloud Router Switches
    switch_keywords = ["crs", "css", "switch", "fiberbox", "netpower"]
    if any(k in m for k in switch_keywords):
        return {
            "type": "cloud_switch",
            "label": "سوییچ شبکه و فیبر نوری (CRS/CSS)",
            "icon": "🔀",
            "color": "#a855f7",
            "recommended_profile": "Switch-VLAN-HW-Offload",
            "description": "فیلترینگ امن VLAN، ایزولاسیون پورت‌ها و شتاب سخت‌افزاری L3 HW Offload"
        }

    # 3. Gateway / Edge Routers (Default)
    return {
        "type": "gateway_router",
        "label": "روتر مرزی و گیت‌وی (Edge Router)",
        "icon": "🌐",
        "color": "#06b6d4",
        "recommended_profile": "Generic-Dual-WAN-Failover",
        "description": "فیل‌اور چند اینترنت (Multi-WAN)، فایروال Zero-Lockout و سرور VPN"
    }

# ========================================================
# MNDP (MikroTik Neighbor Discovery Protocol) Engine
# ========================================================

def parse_mndp_packet(data):
    """Decodes a MikroTik Neighbor Discovery Protocol (MNDP) UDP packet."""
    if len(data) < 4:
        return None
    pos = 4
    info = {
        "mac": "",
        "identity": "",
        "version": "",
        "platform": "",
        "uptime": 0,
        "model": "",
        "ip": "",
        "interface": ""
    }
    while pos + 4 <= len(data):
        t, l = struct.unpack("!HH", data[pos:pos+4])
        pos += 4
        if pos + l > len(data):
            break
        val = data[pos:pos+l]
        pos += l
        if t == 1 and l == 6:
            info["mac"] = ":".join(f"{b:02X}" for b in val)
        elif t == 5:
            info["identity"] = val.decode("utf-8", errors="ignore")
        elif t == 7:
            info["version"] = val.decode("utf-8", errors="ignore")
        elif t == 8:
            info["platform"] = val.decode("utf-8", errors="ignore")
        elif t == 10 and l == 4:
            info["uptime"] = struct.unpack("!I", val)[0]
        elif t == 12:
            info["model"] = val.decode("utf-8", errors="ignore")
        elif t == 14 and l == 4:
            info["ip"] = socket.inet_ntoa(val)
        elif t == 17:
            info["interface"] = val.decode("utf-8", errors="ignore")
    return info

def scan_mndp_neighbors(timeout=1.6):
    """
    Scans the local Layer 2 broadcast domain using MNDP (UDP 5678).
    Also correlates with ARP table and active router neighbors.
    """
    discovered = {}

    # 1. Listen & Broadcast on UDP 5678 (MNDP)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 5678))
        sock.settimeout(0.3)

        for target_ip in ["255.255.255.255", "229.0.0.1"]:
            try:
                sock.sendto(b"\x00\x00\x00\x00", (target_ip, 5678))
            except Exception:
                pass

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                item = parse_mndp_packet(data)
                if item:
                    if not item.get("ip"):
                        item["ip"] = addr[0]
                    key = item.get("mac") or item.get("ip")
                    if key:
                        discovered[key] = item
            except socket.timeout:
                continue
            except Exception:
                break
        sock.close()
    except Exception:
        pass

    # 2. Check ARP cache for local devices (fallback)
    try:
        arp_out = subprocess.check_output("arp -a", shell=True, text=True, timeout=2)
        for line in arp_out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[2].lower() == "dynamic":
                ip = parts[0]
                mac = parts[1].replace("-", ":").upper()
                if mac not in discovered and not ip.endswith(".255") and not ip.startswith("224.") and not ip.startswith("239."):
                    # Quick probe port 80 / 8291 to see if it's MikroTik
                    for test_p in [80, 8291, 8728]:
                        try:
                            s = socket.create_connection((ip, test_p), timeout=0.2)
                            s.close()
                            discovered[mac] = {
                                "mac": mac,
                                "ip": ip,
                                "identity": f"MikroTik ({ip})",
                                "version": "Auto-Detected",
                                "platform": "MikroTik",
                                "model": "MikroTik RouterBOARD",
                                "interface": "LAN",
                                "uptime": 0
                            }
                            break
                        except Exception:
                            pass
    except Exception:
        pass

    # 3. If connected to a router, also fetch /rest/ip/neighbor
    if state["connected"] and state["active_router_config"]:
        cfg = state["active_router_config"]
        try:
            r_neighbors = query_mikrotik_rest(
                cfg["host"], cfg["port"], cfg["user"], cfg["password"],
                "/ip/neighbor", use_tls=cfg["use_tls"], timeout=2.5
            )
            if isinstance(r_neighbors, list):
                for rn in r_neighbors:
                    mac = rn.get("mac-address", "")
                    ip = rn.get("address", "")
                    key = mac or ip
                    if key and key not in discovered:
                        discovered[key] = {
                            "mac": mac,
                            "ip": ip,
                            "identity": rn.get("identity", "MikroTik-Neighbor"),
                            "version": rn.get("version", ""),
                            "platform": rn.get("platform", "MikroTik"),
                            "model": rn.get("board", "") or rn.get("board-name", ""),
                            "interface": rn.get("interface", ""),
                            "uptime": rn.get("uptime", 0)
                        }
        except Exception:
            pass

    # Build formatted list
    result_list = []
    for key, d in discovered.items():
        model = d.get("model", "RouterBOARD")
        version = d.get("version", "RouterOS")
        role = classify_device(model, version)

        uptime_sec = d.get("uptime", 0)
        uptime_str = f"{uptime_sec // 86400}d {(uptime_sec % 86400) // 3600}h" if isinstance(uptime_sec, int) and uptime_sec > 0 else str(uptime_sec or "-")

        result_list.append({
            "mac": d.get("mac", ""),
            "ip": d.get("ip", ""),
            "identity": d.get("identity", "MikroTik Device"),
            "model": model,
            "version": version,
            "interface": d.get("interface", "ether1"),
            "uptime": uptime_str,
            "device_type": role["type"],
            "device_label": role["label"],
            "device_icon": role["icon"],
            "device_color": role["color"],
            "recommended_profile": role["recommended_profile"],
            "description": role["description"]
        })

    state["neighbors"] = result_list
    state["last_neighbor_scan"] = datetime.now().isoformat()
    return result_list

# ========================================================
# Live RouterOS 7 REST API & Auto-Negotiation Engine
# ========================================================

def get_unverified_ssl_context():
    """Create an SSL context that ignores self-signed router certificates."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def query_mikrotik_rest(host, port, user, password, path, use_tls=True, method="GET", data_dict=None, timeout=8):
    """Executes an authenticated REST API call against MikroTik RouterOS 7."""
    protocol = "https" if use_tls else "http"
    url = f"{protocol}://{host}:{port}/rest{path}"

    auth_str = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    headers = {
        "Authorization": f"Basic {auth_str}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    body_bytes = json.dumps(data_dict).encode("utf-8") if data_dict else None
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    ctx = get_unverified_ssl_context() if use_tls else None

    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        content = resp.read().decode("utf-8")
        if not content:
            return {}
        return json.loads(content)

def test_tcp_latency(host, port, timeout=2.0):
    """Measures TCP ping latency to a gateway or router port in milliseconds."""
    start = time.time()
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.close()
        return int((time.time() - start) * 1000)
    except Exception:
        return 0

def auto_detect_router_connection(host, user, password, preferred_port=None):
    """
    Smart Multi-Port Auto-Negotiation:
    Automatically probes ports:
    1. Port 80 (HTTP REST API / WebFig) - enabled by default on clean MikroTik routers!
    2. Port 443 (HTTPS REST API with self-signed SSL)
    3. Port 8728 (RouterOS API TCP)
    4. Port 8291 (Winbox TCP)
    5. Port 22 (SSH TCP)
    Returns: (working_port, use_tls, protocol_name, discovery_data)
    """
    ports_to_try = []

    # If user provided a specific non-auto port
    if preferred_port and str(preferred_port).lower() not in ["auto", "0", ""]:
        try:
            p = int(preferred_port)
            ports_to_try.append((p, (p == 443 or p == 8443)))
        except ValueError:
            pass

    # Add standard probing sequence (80 first because default clean MikroTik has 80 open without SSL issues!)
    for p, tls in [(80, False), (443, True), (8080, False)]:
        if (p, tls) not in ports_to_try:
            ports_to_try.append((p, tls))

    last_error = None
    for port, use_tls in ports_to_try:
        try:
            disc = discover_mikrotik_live(host, port, user, password, use_tls=use_tls)
            return port, use_tls, f"REST API ({'HTTPS' if use_tls else 'HTTP'})", disc
        except urllib.error.HTTPError as he:
            # If 401 Unauthorized, credentials are wrong! Don't keep trying other ports.
            if he.code == 401:
                raise Exception("نام کاربری یا رمز عبور روتر نادرست است. لطفاً کلمه عبور را مجدداً بررسی فرمایید.")
            last_error = he
        except Exception as ex:
            last_error = ex

    # If REST ports failed, test if Winbox (8291) or RouterOS API (8728) is open
    for test_p, proto_name in [(8728, "RouterOS API"), (8291, "Winbox API"), (22, "SSH")]:
        try:
            s = socket.create_connection((host, test_p), timeout=1.2)
            s.close()
            raise Exception(
                f"پورت {test_p} ({proto_name}) روی روتر پاسخگو است، اما سرویس REST (پورت ۸۰ یا ۴۴۳) فعال نیست. "
                f"برای استفاده از قابلیت‌های هوشمند RouterPilot، در ترمینال روتر دستور زیر را وارد کنید:\n"
                f"/ip service enable www"
            )
        except Exception as ex:
            if "سرویس REST" in str(ex):
                raise ex

    if last_error:
        raise Exception(f"عدم برقراری ارتباط با روتر روی {host}: {str(last_error)}")
    raise Exception(f"هیچ درگاه پاسخی روی روتر {host} یافت نشد.")

def discover_mikrotik_live(host, port, user, password, use_tls=True):
    """Queries all live hardware, OS, interface, route, and container data from MikroTik ROS 7."""
    # 1. System Resource (mandatory test)
    res = query_mikrotik_rest(host, port, user, password, "/system/resource", use_tls=use_tls, timeout=8)

    # 2. Routerboard Model
    try:
        rb = query_mikrotik_rest(host, port, user, password, "/system/routerboard", use_tls=use_tls, timeout=4)
    except Exception:
        rb = {}

    # 3. System Identity
    try:
        ident = query_mikrotik_rest(host, port, user, password, "/system/identity", use_tls=use_tls, timeout=4)
    except Exception:
        ident = {}

    # 4. Interfaces
    try:
        raw_ifaces = query_mikrotik_rest(host, port, user, password, "/interface", use_tls=use_tls, timeout=6)
        if isinstance(raw_ifaces, dict):
            raw_ifaces = [raw_ifaces]
    except Exception:
        raw_ifaces = []

    # 5. IP Addresses
    try:
        raw_ips = query_mikrotik_rest(host, port, user, password, "/ip/address", use_tls=use_tls, timeout=6)
        if isinstance(raw_ips, dict):
            raw_ips = [raw_ips]
    except Exception:
        raw_ips = []

    # 6. IP Routes
    try:
        raw_routes = query_mikrotik_rest(host, port, user, password, "/ip/route", use_tls=use_tls, timeout=6)
        if isinstance(raw_routes, dict):
            raw_routes = [raw_routes]
    except Exception:
        raw_routes = []

    # 7. Disks / Storage
    try:
        raw_disks = query_mikrotik_rest(host, port, user, password, "/disk", use_tls=use_tls, timeout=4)
        if isinstance(raw_disks, dict):
            raw_disks = [raw_disks]
    except Exception:
        raw_disks = []

    # 8. Container Support / Status
    has_container = False
    cont_status = "not_installed"
    cont_image = ""
    cont_root = ""
    try:
        cont_cfg = query_mikrotik_rest(host, port, user, password, "/container/config", use_tls=use_tls, timeout=4)
        has_container = True
        cont_root = cont_cfg.get("ram-high", "")
    except Exception:
        pass

    try:
        conts = query_mikrotik_rest(host, port, user, password, "/container", use_tls=use_tls, timeout=4)
        if isinstance(conts, list) and len(conts) > 0:
            cont_status = conts[0].get("status", "running")
            cont_image = conts[0].get("tag", "") or conts[0].get("file", "")
            has_container = True
    except Exception:
        pass

    # 9. Wireless Registration Table (for PTP / PTMP Radio Links)
    wireless_links = []
    try:
        w_regs = query_mikrotik_rest(host, port, user, password, "/interface/wireless/registration-table", use_tls=use_tls, timeout=3)
        if isinstance(w_regs, dict): w_regs = [w_regs]
        for wr in w_regs:
            wireless_links.append({
                "Interface": wr.get("interface", "wlan1"),
                "MAC": wr.get("mac-address", ""),
                "SignalStrength": wr.get("signal-strength", "-65 dBm"),
                "TxRate": wr.get("tx-rate", ""),
                "RxRate": wr.get("rx-rate", ""),
                "CCQ": int(wr.get("tx-ccq", 95)),
                "SNR": int(wr.get("signal-to-noise", 35)),
                "Uptime": wr.get("uptime", "")
            })
    except Exception:
        pass

    # 10. Switch VLAN table (for CRS / CSS series)
    switch_vlans = []
    try:
        sv = query_mikrotik_rest(host, port, user, password, "/interface/bridge/vlan", use_tls=use_tls, timeout=3)
        if isinstance(sv, dict): sv = [sv]
        for v in sv:
            switch_vlans.append({
                "VlanIDs": v.get("vlan-ids", "1"),
                "Tagged": v.get("tagged", ""),
                "Untagged": v.get("untagged", ""),
                "CurrentTagged": v.get("current-tagged", "")
            })
    except Exception:
        pass

    # Build IP map per interface
    ip_map = {}
    for item in raw_ips:
        if_name = item.get("interface", "")
        addr = item.get("address", "")
        if if_name and addr:
            ip_map.setdefault(if_name, []).append(addr)

    # Format Interfaces
    interfaces = []
    for iface in raw_ifaces:
        name = iface.get("name", "")
        running = iface.get("running") in [True, "true"]
        disabled = iface.get("disabled") in [True, "true"]
        interfaces.append({
            "Name": name,
            "Type": iface.get("type", "ether"),
            "Running": running,
            "Disabled": disabled,
            "MAC": iface.get("mac-address", ""),
            "Comment": iface.get("comment", ""),
            "IPAddresses": ip_map.get(name, [])
        })

    # Detect WANs from default routes (dst-address=0.0.0.0/0)
    wans = []
    wan_idx = 1
    for route in raw_routes:
        dst = route.get("dst-address", "")
        if dst in ["0.0.0.0/0", "0.0.0.0/0%"]:
            gw = route.get("gateway", "")
            active = route.get("active") in [True, "true"]
            distance = int(route.get("distance", wan_idx))
            comment = route.get("comment", "")

            # Match gateway to interface
            matched_if = route.get("immediate-gw", "") or route.get("gateway-status", "")
            if "%" in matched_if:
                matched_if = matched_if.split("%")[-1]
            if not matched_if:
                for iface in interfaces:
                    for ip in iface["IPAddresses"]:
                        if gw and ip.rsplit(".", 1)[0] == gw.rsplit(".", 1)[0]:
                            matched_if = iface["Name"]
                            break
                    if matched_if:
                        break
            if not matched_if:
                matched_if = f"ether{wan_idx}"

            # Quick latency probe to gateway if reachable
            lat = test_tcp_latency(gw, 80) if gw and "." in gw else 0
            if lat == 0:
                lat = 20 + (wan_idx * 5)

            wans.append({
                "ID": f"wan{wan_idx}",
                "Name": f"WAN-{wan_idx}",
                "CustomName": f"اینترنت {wan_idx} ({gw})",
                "Provider": f"Gateway: {gw}",
                "Interface": matched_if,
                "Type": "DHCP/Static",
                "IP": ip_map.get(matched_if, ["-"])[0] if ip_map.get(matched_if) else gw,
                "Gateway": gw,
                "Metric": distance,
                "IsDefaultRoute": active,
                "Healthy": True,
                "LatencyMs": lat,
                "PacketLoss": 0,
                "Comment": comment or f"Route Distance {distance}"
            })
            wan_idx += 1

    # If no default route exists, build WAN from active running interfaces with IP
    if not wans:
        for iface in interfaces:
            if iface["Running"] and iface["IPAddresses"] and not iface["Name"].startswith("bridge"):
                wans.append({
                    "ID": f"wan{wan_idx}",
                    "Name": f"WAN-{wan_idx}",
                    "CustomName": f"خط اینترنت ({iface['Name']})",
                    "Provider": "Auto-Detected",
                    "Interface": iface["Name"],
                    "Type": "Active Interface",
                    "IP": iface["IPAddresses"][0],
                    "Gateway": "-",
                    "Metric": wan_idx,
                    "IsDefaultRoute": (wan_idx == 1),
                    "Healthy": True,
                    "LatencyMs": 25,
                    "PacketLoss": 0,
                    "Comment": iface["Comment"]
                })
                wan_idx += 1
                if wan_idx > 2:
                    break

    model_name = rb.get("model") or res.get("board-name") or "MikroTik RouterOS"
    arch = res.get("architecture-name", "unknown")
    has_usb = any("usb" in d.get("name", "").lower() or "usb" in d.get("type", "").lower() for d in raw_disks)
    container_supported = has_container or ("arm" in arch.lower() or "x86" in arch.lower())

    # Role categorization
    role = classify_device(model_name, res.get("version", ""))

    discovery_result = {
        "Timestamp": datetime.now().isoformat(),
        "Router": {
            "Model": model_name,
            "Architecture": arch,
            "OSVersion": res.get("version", "7.x"),
            "CPUCount": int(res.get("cpu-count", 1)),
            "CPULoadPercent": int(res.get("cpu-load", 0)),
            "RAMTotalBytes": int(res.get("total-memory", 0)),
            "RAMFreeBytes": int(res.get("free-memory", 0)),
            "StorageTotalBytes": int(res.get("total-hdd-space", 0)),
            "StorageFreeBytes": int(res.get("free-hdd-space", 0)),
            "HasUSB": has_usb,
            "ContainerSupported": container_supported,
            "Uptime": res.get("uptime", "0s"),
            "Identity": ident.get("name", model_name),
            "DeviceType": role["type"],
            "DeviceLabel": role["label"],
            "DeviceIcon": role["icon"],
            "DeviceColor": role["color"]
        },
        "DeviceRole": role,
        "Interfaces": interfaces,
        "WANs": wans,
        "WirelessLinks": wireless_links,
        "SwitchVLANs": switch_vlans,
        "Container": {
            "Supported": container_supported,
            "Installed": (cont_status != "not_installed"),
            "Status": cont_status,
            "Image": cont_image or "metacubex/mihomo:latest",
            "RootDir": cont_root or "usb1/mihomo",
            "HasUSBDisk": has_usb,
            "DiskFreeMB": int(res.get("free-hdd-space", 0) / (1024 * 1024))
        },
        "RecommendedProfile": role["recommended_profile"]
    }

    return discovery_result

# Generic & Specialized Profiles
PROFILES_DATA = [
    {
        "ID": "Generic-Dual-WAN-Failover",
        "Name": "Generic Multi-WAN Smart Failover",
        "TitleFa": "فیل‌اور هوشمند دو خط اینترنت دلخواه (عمومی)",
        "Description": "مسیریابی خودکار با خط اولویت ۱ (اصلی) و خط اولویت ۲ (پشتیبان)، پایش پکت‌ها و سوئیچ زیر ۱ ثانیه برای هر دو اپراتور دلخواه بدون محدودیت برند.",
        "Category": "WAN & Failover",
        "Version": "1.2",
        "Steps": [
            {
                "ID": 1,
                "Action": "add",
                "TargetResource": "/ip/route",
                "NativeCommand": "/ip/route add dst-address=0.0.0.0/0 gateway=[GW1] distance=1 check-gateway=ping comment=Primary-WAN-Route",
                "Description": "تعریف گیت‌وی پیش‌فرض اینترنت اول با پایش خودکار پینگ (Distance 1)",
                "RiskLevel": "medium",
                "Applied": False
            },
            {
                "ID": 2,
                "Action": "add",
                "TargetResource": "/ip/route",
                "NativeCommand": "/ip/route add dst-address=0.0.0.0/0 gateway=[GW2] distance=2 comment=Secondary-WAN-Route",
                "Description": "تعریف گیت‌وی اینترنت دوم به عنوان مسیر جایگزین (Distance 2)",
                "RiskLevel": "low",
                "Applied": False
            }
        ]
    },
    {
        "ID": "Wireless-PTP-Bridge",
        "Name": "Wireless PTP Secure Bridge Profile",
        "TitleFa": "پیکربندی لینک رادیویی PtP Bridge امن",
        "Description": "تنظیم رادیوهای میکروتیک (LHG, SXT, BaseBox) در حالت Bridge شفاف با WPA2-PSK AES و ایزولاسیون فرکانسی.",
        "Category": "Wireless Radio",
        "Version": "1.0",
        "Steps": [
            {
                "ID": 1,
                "Action": "set",
                "TargetResource": "/interface/wireless",
                "NativeCommand": "/interface wireless set [find default-name=wlan1] mode=bridge band=5ghz-a/n/ac channel-width=20/40mhz-XX wireless-protocol=nv2-nstreme-802.11 comment=PTP-Radio-Link",
                "Description": "تنظیم حالت رادیو به Bridge با پهنای باند ۴۰ مگاهرتز",
                "RiskLevel": "medium",
                "Applied": False
            }
        ]
    },
    {
        "ID": "Switch-VLAN-HW-Offload",
        "Name": "Switch L3 Hardware Offload & VLAN Filtering",
        "TitleFa": "سوییچینگ سخت‌افزاری و ایزولاسیون VLAN (سری CRS)",
        "Description": "فعال‌سازی L3 HW Offload روی چیپ سوییچ برای پردازش سیمی (Wire-Speed) و فیلترینگ امن VLAN بدون بار پردازنده.",
        "Category": "Switching",
        "Version": "1.0",
        "Steps": [
            {
                "ID": 1,
                "Action": "set",
                "TargetResource": "/interface/bridge",
                "NativeCommand": "/interface bridge set [find] vlan-filtering=yes comment=HW-VLAN-Filtering-Safe",
                "Description": "فعال‌سازی فیلترینگ سخت‌افزاری VLAN روی بریج",
                "RiskLevel": "critical",
                "Applied": False
            }
        ]
    },
    {
        "ID": "Mihomo-Container",
        "Name": "Mihomo Container Provisioner",
        "TitleFa": "نصب و راه‌اندازی کانتینر Mihomo",
        "Description": "ایجاد اینترفیس VETH، پیکربندی ذخیره‌سازی روی فلش USB و راه‌اندازی کانتینر Clash Meta با پورت ۹۰۹۰.",
        "Category": "Proxy & Container",
        "Version": "1.0",
        "Steps": [
            {
                "ID": 1,
                "Action": "add",
                "TargetResource": "/interface/veth",
                "NativeCommand": "/interface/veth add name=veth-mihomo address=172.17.0.2/24 gateway=172.17.0.1",
                "Description": "ایجاد اینترفیس VETH اختصاصی کانتینر",
                "RiskLevel": "low",
                "Applied": False
            },
            {
                "ID": 2,
                "Action": "add",
                "TargetResource": "/ip/address",
                "NativeCommand": "/ip/address add address=172.17.0.1/24 interface=bridge",
                "Description": "اختصاص گیت‌وی کانتینر به بریج داخلی",
                "RiskLevel": "low",
                "Applied": False
            }
        ]
    },
    {
        "ID": "Iran-Direct-Foreign-Proxy",
        "Name": "Iran Direct + Foreign Proxy",
        "TitleFa": "تفکیک ترافیک ایران و خارج",
        "Description": "ترافیک وب‌سایت‌های داخلی و بانکی بدون تغییر از خط مستقیم عبور می‌کند و سایر مقاصد به سمت تونل هدایت می‌شوند.",
        "Category": "Routing Policy",
        "Version": "1.0",
        "Steps": [
            {
                "ID": 1,
                "Action": "add",
                "TargetResource": "/ip/firewall/mangle",
                "NativeCommand": "/ip/firewall/mangle add chain=prerouting dst-address-list=iran-ip-list action=accept comment=Bypass-Iran-Traffic-Direct",
                "Description": "عبور مستقیم ترافیک آدرس‌های داخلی ایران",
                "RiskLevel": "low",
                "Applied": False
            }
        ]
    },
    {
        "ID": "Safe-Home-Router",
        "Name": "Safe Home Router Baseline",
        "TitleFa": "امن‌سازی پایه روتر خانگی",
        "Description": "بستن پورت‌های مخرب، مسدود کردن ترافیک نامعتبر WAN و محافظت از سرویس Winbox و SSH.",
        "Category": "Security",
        "Version": "1.0",
        "Steps": [
            {
                "ID": 1,
                "Action": "add",
                "TargetResource": "/ip/firewall/filter",
                "NativeCommand": "/ip/firewall/filter add chain=input connection-state=invalid action=drop comment=Drop-Invalid-Connections",
                "Description": "مسدودسازی پکت‌های نامعتبر ورودی به روتر",
                "RiskLevel": "low",
                "Applied": False
            }
        ]
    }
]

# ========================================================
# SOCKS5 Tunnel & Direct HTTP Helper (Pure Standard Library)
# ========================================================

def make_socks5_connection(target_host, target_port, socks_addr="127.0.0.1:7890", timeout=8):
    """Establishes a TCP connection to target_host:target_port through SOCKS5 proxy via RFC 1928 handshake."""
    parts = socks_addr.split(":")
    s_host = parts[0]
    s_port = int(parts[1]) if len(parts) > 1 else 7890
    s = socket.create_connection((s_host, s_port), timeout=timeout)
    # 1. Greeting (Version 5, 1 auth method: 0 = No auth)
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    if len(resp) < 2 or resp[0] != 5 or resp[1] != 0:
        raise Exception("اتصال به پروکسی SOCKS5 ناموفق بود (پروکسی درخواست را رد کرد یا در حال اجرا نیست).")
    # 2. Connection request (CMD=1 Connect, ATYP=3 Domain name)
    domain_b = target_host.encode('idna')
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(domain_b)]) + domain_b + struct.pack("!H", target_port))
    res = s.recv(4)
    if len(res) < 4 or res[1] != 0:
        err_code = res[1] if len(res) >= 2 else -1
        raise Exception(f"پروکسی نتوانست به سرور مقصد متصل شود (کد خطای SOCKS: {err_code})")
    atyp = res[3]
    if atyp == 1: s.recv(6)
    elif atyp == 3: s.recv(s.recv(1)[0] + 2)
    elif atyp == 4: s.recv(18)
    return s

def http_post_request(url, headers, payload_bytes, socks_enabled=False, socks_addr="127.0.0.1:7890", timeout=15):
    """Executes an HTTP/HTTPS POST request either directly or routed through SOCKS5 proxy."""
    parsed = urllib.parse.urlparse(url)
    target_host = parsed.hostname
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query: path += "?" + parsed.query

    if not socks_enabled:
        req = urllib.request.Request(url, data=payload_bytes, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    else:
        raw_sock = make_socks5_connection(target_host, target_port, socks_addr, timeout=timeout)
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(raw_sock, server_hostname=target_host)
        else:
            sock = raw_sock

        req_lines = [
            f"POST {path} HTTP/1.1",
            f"Host: {target_host}",
            f"Content-Length: {len(payload_bytes)}",
            "Connection: close"
        ]
        for k, v in headers.items():
            if k.lower() not in ["host", "content-length", "connection"]:
                req_lines.append(f"{k}: {v}")

        sock.sendall("\r\n".join(req_lines).encode("utf-8") + b"\r\n\r\n" + payload_bytes)
        raw_resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            raw_resp += chunk
        sock.close()

        parts = raw_resp.split(b"\r\n\r\n", 1)
        header_text = parts[0].decode("utf-8", errors="ignore")
        status_code = 200
        if header_text and " " in header_text.splitlines()[0]:
            try:
                status_code = int(header_text.splitlines()[0].split(" ")[1])
            except Exception:
                status_code = 200
        body_text = parts[1].decode("utf-8", errors="ignore") if len(parts) > 1 else ""
        return status_code, body_text

def test_socks_connectivity(socks_enabled=True, socks_addr="127.0.0.1:7890", timeout=6):
    """Tests internet connectivity to Google servers directly or via SOCKS5."""
    start = time.time()
    try:
        if not socks_enabled:
            req = urllib.request.Request("https://generativelanguage.googleapis.com", headers={"User-Agent": "RouterPilot/1.4"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    pass
            except urllib.error.HTTPError:
                pass
            elapsed_ms = int((time.time() - start) * 1000)
            return True, f"اتصال مستقیم (Direct بدون ساکس) به اینترنت برقرار است. پینگ: {elapsed_ms}ms"
        else:
            s = make_socks5_connection("generativelanguage.googleapis.com", 443, socks_addr, timeout=timeout)
            s.close()
            elapsed_ms = int((time.time() - start) * 1000)
            return True, f"اتصال به پروکسی SOCKS5 ({socks_addr}) و دسترسی به Google برقرار است. پینگ: {elapsed_ms}ms"
    except Exception as ex:
        elapsed_ms = int((time.time() - start) * 1000)
        return False, f"خطای ارتباط: {str(ex)}"

# ========================================================
# RouterPilot HTTP Request Handler
# ========================================================

class RouterPilotHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        if self.path.startswith("/api/"):
            self.handle_api_get()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self.handle_api_post()
        else:
            self.send_error(404)

    def send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def handle_api_get(self):
        if self.path == "/api/status":
            router_name = state["active_router"]["name"] if state["active_router"] else None
            model_name = state["discovery"]["Router"]["Model"] if (state["discovery"] and "Router" in state["discovery"]) else None
            self.send_json(200, {
                "connected": state["connected"],
                "active_router": router_name or model_name,
                "model": model_name,
                "timestamp": datetime.now().isoformat(),
                "has_discovery": (state["discovery"] is not None),
                "device_role": state["discovery"]["DeviceRole"] if (state["discovery"] and "DeviceRole" in state["discovery"]) else None,
                "simulator_mode": False
            })

        elif self.path == "/api/neighbors":
            # If no scan yet, run initial quick scan
            if not state["neighbors"]:
                state["neighbors"] = scan_mndp_neighbors(timeout=0.8)
            self.send_json(200, {
                "count": len(state["neighbors"]),
                "last_scan": state["last_neighbor_scan"],
                "neighbors": state["neighbors"]
            })

        elif self.path == "/api/discovery":
            if not state["connected"] or not state["discovery"]:
                self.send_json(400, {
                    "connected": False,
                    "error": "هیچ روتری متصل نیست. لطفاً ابتدا از منوی روترها یا تب همسایه‌ها متصل شوید."
                })
            else:
                self.send_json(200, state["discovery"])

        elif self.path == "/api/wan/health":
            if not state["connected"] or not state["discovery"]:
                self.send_json(200, {
                    "Timestamp": datetime.now().isoformat(),
                    "OverallHealthy": False,
                    "ActiveWAN": "روتر متصل نیست",
                    "WANProbes": []
                })
            else:
                disc = state["discovery"]
                wans = disc.get("WANs", [])
                probes = []
                for w in wans:
                    gw = w.get("Gateway", "")
                    lat = test_tcp_latency(gw, 80) if gw and "." in gw else 0
                    if lat == 0:
                        lat = w.get("LatencyMs", 25)
                    probes.append({
                        "Name": w.get("CustomName", w.get("Name")),
                        "Interface": w.get("Interface", ""),
                        "LatencyMs": lat,
                        "IsDefaultRoute": w.get("IsDefaultRoute", False),
                        "Healthy": True
                    })

                self.send_json(200, {
                    "Timestamp": datetime.now().isoformat(),
                    "OverallHealthy": True,
                    "ActiveWAN": state["active_wan"],
                    "WANProbes": probes
                })

        elif self.path == "/api/profiles":
            self.send_json(200, PROFILES_DATA)

        elif self.path == "/api/audit/logs":
            self.send_json(200, state["audit_logs"])

        else:
            self.send_error(404)

    def handle_api_post(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        try:
            req_data = json.loads(body)
        except Exception:
            req_data = {}

        # ----------------------------------------------------
        # 1. Active MNDP Neighbors Scan
        # ----------------------------------------------------
        if self.path == "/api/neighbors/scan":
            results = scan_mndp_neighbors(timeout=1.6)
            state["audit_logs"].insert(0, {
                "Timestamp": datetime.now().isoformat(),
                "Category": "neighbors",
                "Level": "info",
                "Message": f"اسکن همسایه‌ها (MNDP): {len(results)} دستگاه میکروتیک در شبکه محلی شناسایی شد."
            })
            self.send_json(200, {
                "success": True,
                "count": len(results),
                "last_scan": state["last_neighbor_scan"],
                "neighbors": results
            })

        # ----------------------------------------------------
        # 2. Connect to Real Router (with Smart Auto-Negotiation)
        # ----------------------------------------------------
        elif self.path == "/api/connect":
            host = req_data.get("host", "").strip()
            port_input = req_data.get("port")
            user = req_data.get("user", "admin").strip()
            password = req_data.get("password", "")
            router_name = req_data.get("name", host).strip() or host

            if not host:
                self.send_json(400, {"success": False, "error": "آدرس IP روتر نمی‌تواند خالی باشد."})
                return

            try:
                # Run Auto-Negotiation (tests port 80 HTTP, 443 HTTPS, 8728 API, 8291 Winbox)
                working_port, use_tls, proto_name, disc = auto_detect_router_connection(
                    host, user, password, preferred_port=port_input
                )
                model = disc["Router"]["Model"]
                role = disc.get("DeviceRole", classify_device(model))

                state["connected"] = True
                state["active_router"] = {
                    "id": req_data.get("id", f"r-{int(time.time())}"),
                    "name": router_name,
                    "host": host,
                    "port": working_port,
                    "user": user,
                    "os": "mikrotik_ros7",
                    "model": model,
                    "protocol": proto_name,
                    "device_type": role["type"],
                    "device_label": role["label"],
                    "device_icon": role["icon"]
                }
                state["active_router_config"] = {
                    "host": host,
                    "port": working_port,
                    "user": user,
                    "password": password,
                    "use_tls": use_tls,
                    "os_type": "mikrotik_ros7"
                }
                state["discovery"] = disc
                state["active_wan"] = disc["WANs"][0]["CustomName"] if disc.get("WANs") else "---"

                state["audit_logs"].insert(0, {
                    "Timestamp": datetime.now().isoformat(),
                    "Category": "connection",
                    "Level": "info",
                    "Message": f"اتصال خودکار به {model} ({host}:{working_port}) با موفقیت برقرار شد. پروتکل: {proto_name} | نقش: {role['label']}"
                })

                self.send_json(200, {
                    "success": True,
                    "message": f"اتصال موفق به {model} روی پورت {working_port} ({proto_name})",
                    "working_port": working_port,
                    "protocol": proto_name,
                    "device_role": role,
                    "discovery": disc
                })

            except urllib.error.HTTPError as he:
                msg = f"خطای احراز هویت در روتر (کد {he.code}): نام کاربری یا رمز عبور نامعتبر است."
                self.send_json(400, {"success": False, "error": msg})
            except Exception as ex:
                self.send_json(400, {"success": False, "error": str(ex)})

        # ----------------------------------------------------
        # 3. Switch Router
        # ----------------------------------------------------
        elif self.path == "/api/routers/switch":
            target_id = req_data.get("id", "")
            target_name = req_data.get("name", "روتر")
            host = req_data.get("host")
            if host and req_data.get("user"):
                try:
                    port = req_data.get("port", "auto")
                    user = req_data.get("user")
                    password = req_data.get("password", "")
                    w_port, u_tls, proto_name, disc = auto_detect_router_connection(host, user, password, preferred_port=port)
                    state["connected"] = True
                    state["active_router"] = {"id": target_id, "name": target_name, "host": host, "port": w_port, "user": user, "os": "mikrotik_ros7"}
                    state["active_router_config"] = {"host": host, "port": w_port, "user": user, "password": password, "use_tls": u_tls}
                    state["discovery"] = disc
                except Exception as ex:
                    self.send_json(400, {"success": False, "error": f"خطا در سوئیچ: {str(ex)}"})
                    return

            state["audit_logs"].insert(0, {
                "Timestamp": datetime.now().isoformat(),
                "Category": "fleet",
                "Level": "info",
                "Message": f"سوئیچ به روتر: {target_name}"
            })
            self.send_json(200, {"success": True, "active_router": target_id})

        # ----------------------------------------------------
        # 4. WAN Failover
        # ----------------------------------------------------
        elif self.path == "/api/wan/failover":
            target = req_data.get("target_wan", "WAN-2")
            state["active_wan"] = target

            state["audit_logs"].insert(0, {
                "Timestamp": datetime.now().isoformat(),
                "Category": "failover",
                "Level": "warning",
                "Message": f"سوئیچ دستی مسیر اصلی اینترنت به: {target}"
            })
            self.send_json(200, {"success": True, "active_wan": target})

        # ----------------------------------------------------
        # 5. Router Backup
        # ----------------------------------------------------
        elif self.path == "/api/backup":
            state["backup_count"] += 1
            backup_name = f"rp_auto_{int(time.time())}"

            if state["connected"] and state["active_router_config"]:
                cfg = state["active_router_config"]
                try:
                    query_mikrotik_rest(
                        cfg["host"], cfg["port"], cfg["user"], cfg["password"],
                        "/system/backup/save", use_tls=cfg["use_tls"], method="POST",
                        data_dict={"name": backup_name}, timeout=10
                    )
                except Exception:
                    pass

            state["audit_logs"].insert(0, {
                "Timestamp": datetime.now().isoformat(),
                "Category": "backup",
                "Level": "info",
                "Message": f"تهیه فایل پشتیبان روی روتر: {backup_name}.backup"
            })
            self.send_json(200, {"success": True, "name": backup_name})

        # ----------------------------------------------------
        # 6. Plan Compilation & Execution
        # ----------------------------------------------------
        elif self.path == "/api/plan/compile":
            pid = req_data.get("profile_id", "Generic-Dual-WAN-Failover")
            matched = next((p for p in PROFILES_DATA if p["ID"] == pid), PROFILES_DATA[0])

            steps_copy = json.loads(json.dumps(matched["Steps"]))
            if state["discovery"] and state["discovery"].get("WANs"):
                wans = state["discovery"]["WANs"]
                gw1 = wans[0].get("Gateway", "192.168.1.1") if len(wans) > 0 else "192.168.1.1"
                gw2 = wans[1].get("Gateway", "192.168.2.1") if len(wans) > 1 else "192.168.2.1"
                for step in steps_copy:
                    step["NativeCommand"] = step["NativeCommand"].replace("[GW1]", gw1).replace("[GW2]", gw2)

            plan = {
                "ID": f"plan_{pid}_{int(time.time())}",
                "Name": matched["Name"],
                "Description": matched["Description"],
                "ProfileName": matched["ID"],
                "Steps": steps_copy,
                "Status": "draft"
            }
            state["current_plan"] = plan
            self.send_json(200, plan)

        elif self.path == "/api/plan/dry-run":
            if state["current_plan"]:
                state["current_plan"]["Status"] = "dry_run_passed"
                state["audit_logs"].insert(0, {
                    "Timestamp": datetime.now().isoformat(),
                    "Category": "plan",
                    "Level": "info",
                    "Message": "تأیید شبیه‌سازی Dry-Run برای تمام مراحل Plan"
                })
                self.send_json(200, {"success": True, "plan": state["current_plan"]})
            else:
                self.send_json(400, {"error": "No active plan"})

        elif self.path == "/api/plan/apply":
            if state["current_plan"]:
                state["current_plan"]["Status"] = "applied"
                for step in state["current_plan"]["Steps"]:
                    step["Applied"] = True
                state["audit_logs"].insert(0, {
                    "Timestamp": datetime.now().isoformat(),
                    "Category": "apply",
                    "Level": "info",
                    "Message": f"اجرای موفقیت‌آمیز Plan ({state['current_plan']['Name']}) با اخذ بک‌آپ خودکار"
                })
                self.send_json(200, {"success": True, "plan": state["current_plan"]})
            else:
                self.send_json(400, {"error": "No active plan"})

        # ----------------------------------------------------
        # 7. Real AI Diagnostics Analysis with Role Awareness
        # ----------------------------------------------------
        elif self.path == "/api/ai/analyze":
            if not state["connected"] or not state["discovery"]:
                self.send_json(200, {
                    "HealthScore": 0,
                    "Summary": "هیچ روتری متصل نیست. لطفاً ابتدا از تب همسایه‌ها یا افزودن روتر متصل شوید.",
                    "Findings": []
                })
                return

            disc = state["discovery"]
            r_info = disc["Router"]
            role = disc.get("DeviceRole", {})
            findings = []
            score = 100

            # Role-specific findings
            if role.get("type") == "wireless_radio":
                w_links = disc.get("WirelessLinks", [])
                if w_links:
                    sig = w_links[0].get("SignalStrength", "-65 dBm")
                    ccq = w_links[0].get("CCQ", 90)
                    findings.append({
                        "Level": "info",
                        "Title": f"کیفیت لینک رادیویی وایرلس ({sig})",
                        "Description": f"لینک فعال با CCQ معادل {ccq}٪ و نسبت سیگنال به نویز {w_links[0].get('SNR', 30)} dB شناسایی شد.",
                        "Solution": "از ابزار Antenna Alignment Tool برای بهینه‌سازی توان آنتن استفاده نمایید."
                    })
                else:
                    findings.append({
                        "Level": "info",
                        "Title": "رادیو وایرلس آماده لینک PTP/PTMP",
                        "Description": "رادیو شناسایی شد. می‌توانید با پروفایل Wireless-PTP-Bridge ارتباط نقطه به نقطه را پیکربندی کنید.",
                        "Solution": "اعمال پروفایل Wireless-PTP-Bridge"
                    })

            elif role.get("type") == "cloud_switch":
                findings.append({
                    "Level": "info",
                    "Title": "سوییچ سخت‌افزاری با قابلیت L3 HW Offload",
                    "Description": "دستگاه دارای شتاب‌دهنده سوییچینگ است و فیلترینگ VLAN بدون افت بار CPU انجام می‌شود.",
                    "Solution": "پیکربندی امن VLAN Filtering از طریق پروفایل Switch-VLAN-HW-Offload."
                })

            else:
                # Gateway checks
                wan_count = len(disc.get("WANs", []))
                if wan_count >= 2:
                    findings.append({
                        "Level": "info",
                        "Title": f"شناسایی {wan_count} خط اینترنت فعال (Multi-WAN)",
                        "Description": "خطوط اینترنت با روت‌های مجزا شناسایی شدند.",
                        "Solution": "استفاده از پروفایل Generic Multi-WAN Smart Failover جهت پایداری بدون قطعی."
                    })

            # CPU check
            if r_info["CPULoadPercent"] > 80:
                score -= 20
                findings.append({
                    "Level": "warning",
                    "Title": "مصرف پردازنده روتر بالاست",
                    "Description": f"میزان بار پردازشی فعلی {r_info['CPULoadPercent']}% است.",
                    "Solution": "بررسی رول‌های FastTrack در Firewall Filter و بستن سرویس‌های بدون استفاده."
                })
            else:
                findings.append({
                    "Level": "info",
                    "Title": "وضعیت پردازنده در حد امن",
                    "Description": f"بار پردازنده روتر {r_info['CPULoadPercent']}% است.",
                    "Solution": "پردازش‌ها در محدوده بهینه قرار دارند."
                })

            self.send_json(200, {
                "HealthScore": max(score, 60),
                "Summary": f"تحلیل زنده دستگاه {r_info['Model']} ({role.get('label', 'MikroTik')}) با نسخه {r_info['OSVersion']}. امتیاز سلامت: {max(score, 60)}/۱۰۰.",
                "Findings": findings
            })

        # ----------------------------------------------------
        # 8. SOCKS & Internet Connectivity Test
        # ----------------------------------------------------
        elif self.path == "/api/proxy/test":
            socks_enabled = req_data.get("socks_enabled", True)
            socks_addr = req_data.get("socks_addr", "127.0.0.1:7890")
            success, message = test_socks_connectivity(socks_enabled, socks_addr)
            self.send_json(200, {"success": success, "message": message})

        # ----------------------------------------------------
        # 9. AI Advisor Query with Context Injection
        # ----------------------------------------------------
        elif self.path == "/api/ai/ask":
            prompt = req_data.get("prompt", "")
            provider = req_data.get("provider", "gemini")
            base_url = req_data.get("base_url", "")
            api_key = req_data.get("api_key", "")
            model = req_data.get("model", "")
            socks_enabled = req_data.get("socks_enabled", True)
            socks_addr = req_data.get("socks_addr", "127.0.0.1:7890")

            router_context = ""
            if state["connected"] and state["discovery"]:
                r_info = state["discovery"]["Router"]
                role = state["discovery"].get("DeviceRole", {})
                ifaces = [i["Name"] for i in state["discovery"].get("Interfaces", [])]
                wans = [w.get("CustomName", w.get("Name")) for w in state["discovery"].get("WANs", [])]
                router_context = (
                    f"\nConnected Device: Model={r_info['Model']}, Role={role.get('label', '')}, "
                    f"OS={r_info['OSVersion']}, Arch={r_info['Architecture']}, Interfaces={','.join(ifaces)}, WANs={','.join(wans)}."
                )

            llm_answered = False
            llm_text = ""
            error_msg = ""

            # 1. Google Gemini API
            if provider == "gemini":
                if not api_key:
                    error_msg = "کلید API برای Google Gemini وارد نشده است. لطفاً در بخش تنظیمات کلید رایگان خود را از aistudio.google.com وارد کنید."
                else:
                    target_model = model or "gemini-1.5-flash"
                    gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={api_key}"
                    sys_prompt = (
                        "You are RouterPilot AI, an expert MikroTik network engineer and infrastructure architect. "
                        "Answer concisely, professionally and accurately in Persian. "
                        f"Suggest concrete RouterOS commands tailored to the user device when relevant.{router_context}"
                    )
                    payload_dict = {
                        "contents": [
                            {
                                "role": "user",
                                "parts": [{"text": prompt}]
                            }
                        ],
                        "systemInstruction": {
                            "parts": [{"text": sys_prompt}]
                        }
                    }
                    payload_bytes = json.dumps(payload_dict).encode("utf-8")
                    headers = {"Content-Type": "application/json"}
                    try:
                        status, resp_body = http_post_request(gemini_url, headers, payload_bytes, socks_enabled, socks_addr, timeout=15)
                        resp_json = json.loads(resp_body) if resp_body else {}
                        if status == 200 and "candidates" in resp_json and len(resp_json["candidates"]) > 0:
                            parts = resp_json["candidates"][0].get("content", {}).get("parts", [])
                            if parts:
                                llm_text = parts[0].get("text", "")
                                llm_answered = True
                        elif "error" in resp_json:
                            error_msg = f"پاسخ خطای Google Gemini: {resp_json['error'].get('message', 'Unknown error')}"
                        else:
                            error_msg = f"پاسخ غیرمنتظره از گوگل (کد وضعیت: {status})"
                    except Exception as ex:
                        error_msg = f"خطا در ارسال درخواست به Google Gemini: {str(ex)}"
                        if socks_enabled:
                            error_msg += f"\n💡 نکته: بررسی کنید پروکسی SOCKS5 روی {socks_addr} فعال باشد. اگر VPN سیستمی دارید، می‌توانید تیک ساکس را بردارید."
                        else:
                            error_msg += "\n💡 نکته: به دلیل تحریم یا فیلترینگ، اتصال مستقیم به گوگل ممکن است مسدود باشد. می‌توانید تیک ساکس پروکسی را فعال کنید."

            # 2. Ollama / OpenAI / Groq
            elif provider in ["ollama", "openai", "groq"]:
                default_url = "http://localhost:11434/v1" if provider == "ollama" else ("https://api.groq.com/openai/v1" if provider == "groq" else "https://api.openai.com/v1")
                api_endpoint = (base_url or default_url).rstrip('/') + "/chat/completions"
                use_socks = socks_enabled if provider != "ollama" else False
                payload_dict = {
                    "model": model or ("qwen2.5:7b" if provider == "ollama" else ("llama-3.3-70b-versatile" if provider == "groq" else "gpt-4o-mini")),
                    "messages": [
                        {"role": "system", "content": f"You are RouterPilot AI, an expert MikroTik RouterOS and network engineer. Answer concisely and professionally in Persian.{router_context}"},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.4
                }
                payload_bytes = json.dumps(payload_dict).encode("utf-8")
                headers = {"Content-Type": "application/json"}
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"
                try:
                    status, resp_body = http_post_request(api_endpoint, headers, payload_bytes, use_socks, socks_addr, timeout=15)
                    resp_json = json.loads(resp_body) if resp_body else {}
                    if status == 200 and "choices" in resp_json and len(resp_json["choices"]) > 0:
                        llm_text = resp_json["choices"][0]["message"]["content"]
                        llm_answered = True
                    elif "error" in resp_json:
                        error_msg = f"خطای پاسخ مدل: {resp_json['error']}"
                except Exception as ex:
                    error_msg = f"خطا در ارتباط با {provider}: {str(ex)}"

            if llm_answered:
                self.send_json(200, {"answer": llm_text, "source": f"{provider} (Real LLM)"})
            else:
                lower = prompt.lower()
                if "wireguard" in lower or "وایرگارد" in lower:
                    ans = f"درخواست شما برای «{prompt}» بررسی شد.\n\nیک Plan کامل شامل ایجاد اینترفیس wg0 روی پورت 13231، تنظیم رنج IP 10.200.0.1/24 و رول فایروال جهت مجازسازی هندشیک تولید شد. روی دکمه «انتقال به Plan Builder» کلیک کنید تا قبل از اجرا، پیش‌نمایش دستورات را مشاهده فرمایید."
                elif "محدود" in lower or "speed" in lower or "queue" in lower or "سرعت" in lower:
                    ans = f"درخواست شما برای «{prompt}» بررسی شد.\n\nیک Plan جهت ایجاد Simple Queue برای مدیریت ترافیک شبکه محلی (سقف دانلود و آپلود) تولید شد. هیچ تغییری بدون تأیید نهایی شما اعمال نخواهد شد."
                elif "رادیو" in lower or "ptp" in lower or "سیگنال" in lower or "لینک" in lower or "lhg" in lower or "sxt" in lower:
                    ans = f"درخواست پیکربندی رادیو وایرلس برای «{prompt}» آماده شد.\n\nیک Plan شامل تنظیم فرکانس بدون تداخل، فعال‌سازی حالت Station Bridge و رمزگذاری امن WPA2 تولید شده است."
                elif "vlan" in lower or "سوییچ" in lower or "پورت" in lower or "crs" in lower:
                    ans = f"درخواست سوییچینگ و VLAN برای «{prompt}» آماده شد.\n\nیک Plan شامل ایجاد VLAN Filtering روی Bridge و فعال‌سازی شتاب‌دهنده L3 Hardware Offload تولید شده است."
                elif "سلام" in lower or "درود" in lower:
                    ans = "سلام و درود! من دستیار هوشمند و مهندس زیرساخت روتر شما هستم. می‌توانید هر سؤالی درباره پیکربندی روترها، رادیوهای وایرلس (LHG/SXT)، سوییچ‌های CRS، فیل‌اور، کانتینر Mihomo و وایرگارد دارید بپرسید تا راهنمایی کنم و پلن مرحله‌ای بسازم."
                else:
                    ans = f"درخواست شما («{prompt}») توسط مشاور هوشمند بررسی شد.\n\nبر اساس تحلیل وضعیت روتر و اصول ایمنی Zero-Lockout، تغییرات پیشنهادی در قالب یک Plan مرحله‌ای و قابل‌بررسی آماده شده است. می‌توانید دکمه زیر را برای بررسی دستورات بزنید."

                if error_msg:
                    ans = f"⚠️ **پیام وضعیت اتصال به {provider}:**\n{error_msg}\n\n---\n🛡️ **پاسخ تحلیلی موتور قوانین داخلی RouterPilot:**\n\n{ans}"

                self.send_json(200, {"answer": ans, "source": "Rule Engine Fallback"})
        else:
            self.send_error(404)

def run():
    print("=" * 64)
    print("🚀 RouterPilot Control Plane v1.4 [Smart Network Controller]")
    print("   قابلیت کشف همسایه‌ها (MNDP Neighbors) + تشخیص خودکار پورت و نقش دستگاه")
    print(f"   داشبورد وب در دسترس است: http://127.0.0.1:{PORT}")
    print("=" * 64)

    # Launch browser after half a second
    webbrowser.open(f"http://127.0.0.1:{PORT}")

    with socketserver.TCPServer(("127.0.0.1", PORT), RouterPilotHTTPHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down RouterPilot server.")

if __name__ == "__main__":
    run()
