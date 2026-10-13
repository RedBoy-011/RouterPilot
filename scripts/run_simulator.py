#!/usr/bin/env python3
"""
RouterPilot Control Plane v1.0 - Standalone Local Runner & Simulator
Provides immediate HTTP API & serves the Modern Glass UI.
Runs with zero external dependencies using Python's standard library.
"""

import http.server
import socketserver
import json
import os
import sys
import time
import webbrowser
from datetime import datetime

PORT = 8080
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(BASE_DIR, "web")

# In-memory simulator state
state = {
    "active_wan": "WAN-1 (MobinNet)",
    "backup_count": 0,
    "last_failover": None,
    "current_plan": None,
    "audit_logs": [
        {
            "Timestamp": datetime.now().isoformat(),
            "Category": "system",
            "Level": "info",
            "Message": "سیستم RouterPilot v1.0 با موفقیت روی ویندوز راه‌اندازی شد."
        },
        {
            "Timestamp": datetime.now().isoformat(),
            "Category": "discovery",
            "Level": "info",
            "Message": "شناسایی خودکار روتر مرجع (RB5009UG+S+IN) با موفقیت انجام شد."
        }
    ]
}

DISCOVERY_DATA = {
    "Timestamp": datetime.now().isoformat(),
    "Router": {
        "Model": "RB5009UG+S+IN",
        "Architecture": "arm64",
        "OSVersion": "7.15.3 (stable)",
        "CPUCount": 4,
        "CPULoadPercent": 12,
        "RAMTotalBytes": 1073741824,
        "RAMFreeBytes": 825229312,
        "StorageTotalBytes": 1073741824,
        "StorageFreeBytes": 891289600,
        "HasUSB": True,
        "ContainerSupported": True,
        "Uptime": "14d 06:42:19",
        "Identity": "RouterPilot-Reference"
    },
    "Interfaces": [
        {"Name": "ether1", "Type": "ether", "Running": True, "Disabled": False, "MAC": "48:8F:5A:11:22:33", "Comment": "WAN2-TCT", "IPAddresses": ["192.168.2.80/24"]},
        {"Name": "ether2", "Type": "ether", "Running": True, "Disabled": False, "MAC": "48:8F:5A:11:22:34", "Comment": "WAN1-MobinNet", "IPAddresses": ["192.168.1.150/24"]},
        {"Name": "ether3", "Type": "ether", "Running": False, "Disabled": False, "MAC": "48:8F:5A:11:22:35", "Comment": "LAN-Port3", "IPAddresses": []},
        {"Name": "ether4", "Type": "ether", "Running": True, "Disabled": False, "MAC": "48:8F:5A:11:22:36", "Comment": "LAN-Port4", "IPAddresses": []},
        {"Name": "bridge", "Type": "bridge", "Running": True, "Disabled": False, "MAC": "48:8F:5A:11:22:30", "Comment": "LAN-Bridge", "IPAddresses": ["172.16.20.1/24"]},
        {"Name": "veth-mihomo", "Type": "veth", "Running": True, "Disabled": False, "MAC": "02:00:00:AA:BB:CC", "Comment": "Container-VETH", "IPAddresses": ["172.17.0.2/24"]}
    ],
    "WANs": [
        {
            "ID": "wan1",
            "Name": "WAN-1",
            "CustomName": "اینترنت اول (اصلی)",
            "Provider": "Primary ISP (LTE/DHCP)",
            "Interface": "ether2",
            "Type": "DHCP",
            "IP": "192.168.1.150/24",
            "Gateway": "192.168.1.1",
            "Metric": 1,
            "IsDefaultRoute": True,
            "Healthy": True,
            "LatencyMs": 32,
            "PacketLoss": 0,
            "Comment": "Primary Internet"
        },
        {
            "ID": "wan2",
            "Name": "WAN-2",
            "CustomName": "اینترنت دوم (پشتیبان)",
            "Provider": "Secondary ISP (VDSL/DHCP)",
            "Interface": "ether1",
            "Type": "DHCP",
            "IP": "192.168.2.80/24",
            "Gateway": "192.168.2.1",
            "Metric": 2,
            "IsDefaultRoute": False,
            "Healthy": True,
            "LatencyMs": 18,
            "PacketLoss": 0,
            "Comment": "Backup Internet"
        }
    ],
    "Container": {
        "Supported": True,
        "Installed": True,
        "Name": "mihomo-core",
        "Status": "running",
        "Image": "metacubex/mihomo:latest",
        "RootDir": "usb1/mihomo",
        "HasUSBDisk": True,
        "DiskFreeMB": 14336
    },
    "RecommendedProfile": "Generic-Dual-WAN-Failover"
}

PROFILES_DATA = [
    {
        "ID": "Generic-Dual-WAN-Failover",
        "Name": "Generic Multi-WAN Smart Failover",
        "TitleFa": "فیل‌اور هوشمند دو خط اینترنت دلخواه (عمومی)",
        "Description": "مسیریابی خودکار با خط اولویت ۱ (اصلی) و خط اولویت ۲ (پشتیبان)، پایش پکت‌ها و سوئیچ زیر ۱ ثانیه برای هر دو اپراتور دلخواه (شاتل، زیتل، ایرانسل، همراه اول، استارلینک و ...).",
        "Category": "WAN & Failover",
        "Version": "1.1",
        "Steps": [
            {
                "ID": 1,
                "Action": "add",
                "TargetResource": "/ip/route",
                "NativeCommand": "/ip/route add dst-address=0.0.0.0/0 gateway=192.168.1.1 distance=1 check-gateway=ping comment=Primary-WAN-Route",
                "Description": "تعریف گیت‌وی پیش‌فرض اینترنت اول با پایش خودکار پینگ (Distance 1)",
                "RiskLevel": "medium",
                "Applied": False
            },
            {
                "ID": 2,
                "Action": "add",
                "TargetResource": "/ip/route",
                "NativeCommand": "/ip/route add dst-address=0.0.0.0/0 gateway=192.168.2.1 distance=2 comment=Secondary-WAN-Route",
                "Description": "تعریف گیت‌وی اینترنت دوم به عنوان مسیر جایگزین (Distance 2)",
                "RiskLevel": "low",
                "Applied": False
            }
        ]
    },
    {
        "ID": "MobinNet-TCT-Failover",
        "Name": "MobinNet + TCT Smart Failover",
        "TitleFa": "فیل‌اور هوشمند مبین‌نت و مخابرات",
        "Description": "مسیریابی خودکار با خط اولویت ۱ مبین‌نت و خط پشتیبان مخابرات، همراه با پایش مداوم پکت‌ها و سوئیچ زیر ۱ ثانیه.",
        "Category": "WAN & Failover",
        "Version": "1.0",
        "Steps": [
            {
                "ID": 1,
                "Action": "add",
                "TargetResource": "/ip/route",
                "NativeCommand": "/ip/route add dst-address=0.0.0.0/0 gateway=192.168.1.1 distance=1 check-gateway=ping comment=WAN1-MobinNet-Primary",
                "Description": "تعریف گیت‌وی پیش‌فرض مبین‌نت با مانیتورینگ خودکار پینگ (Distance 1)",
                "RiskLevel": "medium",
                "Applied": False
            },
            {
                "ID": 2,
                "Action": "add",
                "TargetResource": "/ip/route",
                "NativeCommand": "/ip/route add dst-address=0.0.0.0/0 gateway=192.168.2.1 distance=2 comment=WAN2-TCT-Backup",
                "Description": "تعریف گیت‌وی پشتیبان مخابرات به عنوان مسیر جایگزین (Distance 2)",
                "RiskLevel": "low",
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
    import socket, struct
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
    import urllib.parse, urllib.request, ssl
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
    import time
    start = time.time()
    try:
        if not socks_enabled:
            import urllib.request, urllib.error
            req = urllib.request.Request("https://generativelanguage.googleapis.com", headers={"User-Agent": "RouterPilot/1.2"})
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
            self.send_json(200, {
                "connected": True,
                "active_router": "MikroTik RouterOS 7",
                "timestamp": datetime.now().isoformat(),
                "has_discovery": True,
                "simulator_mode": True
            })
        elif self.path == "/api/discovery":
            self.send_json(200, DISCOVERY_DATA)
        elif self.path == "/api/wan/health":
            import random
            w1_is_default = (state["active_wan"] == "WAN-1 (MobinNet)")
            report = {
                "Timestamp": datetime.now().isoformat(),
                "OverallHealthy": True,
                "ActiveWAN": state["active_wan"],
                "WANProbes": [
                    {
                        "Name": "MobinNet (LTE/DHCP)",
                        "Interface": "ether2",
                        "LatencyMs": 30 + random.randint(0, 5),
                        "IsDefaultRoute": w1_is_default,
                        "Healthy": True
                    },
                    {
                        "Name": "TCT (VDSL/DHCP)",
                        "Interface": "ether1",
                        "LatencyMs": 17 + random.randint(0, 4),
                        "IsDefaultRoute": not w1_is_default,
                        "Healthy": True
                    }
                ]
            }
            self.send_json(200, report)
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

        if self.path == "/api/routers/switch":
            target_id = req_data.get("id", "r-sim")
            target_name = req_data.get("name", "روتر")
            state["audit_logs"].insert(0, {
                "Timestamp": datetime.now().isoformat(),
                "Category": "fleet",
                "Level": "info",
                "Message": f"سوئیچ به روتر فعال: {target_name} ({target_id})"
            })
            self.send_json(200, {"success": True, "active_router": target_id})

        elif self.path == "/api/wan/failover":
            target = req_data.get("target_wan", "WAN-2 (TCT)")
            state["active_wan"] = target
            state["audit_logs"].insert(0, {
                "Timestamp": datetime.now().isoformat(),
                "Category": "failover",
                "Level": "warning",
                "Message": f"سوئیچ دستی خط اینترنت به: {target}"
            })
            self.send_json(200, {"success": True, "active_wan": target})

        elif self.path == "/api/backup":
            state["backup_count"] += 1
            backup_name = f"rp_manual_{int(time.time())}"
            state["audit_logs"].insert(0, {
                "Timestamp": datetime.now().isoformat(),
                "Category": "backup",
                "Level": "info",
                "Message": f"تهیه فایل بک‌آپ اضطراری: {backup_name}"
            })
            self.send_json(200, {"success": True, "name": backup_name})

        elif self.path == "/api/plan/compile":
            pid = req_data.get("profile_id", "MobinNet-TCT-Failover")
            matched = next((p for p in PROFILES_DATA if p["ID"] == pid), PROFILES_DATA[0])
            plan = {
                "ID": f"plan_{pid}_{int(time.time())}",
                "Name": matched["Name"],
                "Description": matched["Description"],
                "ProfileName": matched["ID"],
                "Steps": matched["Steps"],
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

        elif self.path == "/api/ai/analyze":
            self.send_json(200, {
                "HealthScore": 95,
                "Summary": "تحلیل هوشمند وضعیت روتر انجام شد. امتیاز سلامت روتر: ۹۵/۱۰۰. پیکربندی سخت‌افزاری کاملاً سالم است.",
                "Findings": [
                    {
                        "Level": "info",
                        "Title": "تنظیم صحیح Multi-WAN",
                        "Description": "دو اینترفیس WAN مجزا (مبین‌نت و مخابرات) شناسایی شد.",
                        "Solution": "استفاده از پروفایل MobinNet-TCT-Failover برای تضمین پایداری اتصال."
                    },
                    {
                        "Level": "info",
                        "Title": "پشتیبانی کانتینر روی حافظه خارجی USB",
                        "Description": "دیسک فلش USB با ظرفیت ۱۴ گیگابایت متصل است و کانتینر Mihomo بدون آسیب به حافظه داخلی اجرا می‌شود.",
                        "Solution": "پروفایل Mihomo-Container فعال است."
                    },
                    {
                        "Level": "info",
                        "Title": "سلامت مسیرهای شبکه و امنیت Zero-Lockout",
                        "Description": "آدرس مدیریت روتر روی بریج داخلی کاملاً محافظت شده است.",
                        "Solution": "هیچ اقدام اصلاحی فوری نیاز نیست."
                    }
                ]
            })

        elif self.path == "/api/proxy/test":
            socks_enabled = req_data.get("socks_enabled", True)
            socks_addr = req_data.get("socks_addr", "127.0.0.1:7890")
            success, message = test_socks_connectivity(socks_enabled, socks_addr)
            self.send_json(200, {"success": success, "message": message})

        elif self.path == "/api/ai/ask":
            prompt = req_data.get("prompt", "")
            provider = req_data.get("provider", "rule_engine")
            base_url = req_data.get("base_url", "")
            api_key = req_data.get("api_key", "")
            model = req_data.get("model", "")
            socks_enabled = req_data.get("socks_enabled", True)
            socks_addr = req_data.get("socks_addr", "127.0.0.1:7890")

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
                    payload_dict = {
                        "contents": [
                            {
                                "role": "user",
                                "parts": [{"text": prompt}]
                            }
                        ],
                        "systemInstruction": {
                            "parts": [{"text": "You are RouterPilot AI, an expert MikroTik RouterOS and network engineer. Answer concisely and professionally in Persian. Suggest concrete RouterOS commands when relevant."}]
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
                        {"role": "system", "content": "You are RouterPilot AI, an expert MikroTik RouterOS and network engineer. Answer concisely and professionally in Persian."},
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
                elif "port" in lower or "forward" in lower or "پورت" in lower or "دوربین" in lower:
                    ans = f"درخواست انتقال پورت (Port Forwarding / DST-NAT) برای «{prompt}» آماده شد.\n\nرول فایروال برای هدایت درخواست‌های خارجی به سمت سرور یا دوربین محلی تنظیم گردیده است."
                elif "سلام" in lower or "درود" in lower:
                    ans = "سلام و درود! من دستیار هوشمند روتر شما هستم. می‌توانید هر سؤالی درباره پیکربندی میکروتیک، Failover، کانتینر Mihomo، وایرگارد و مدیریت روت‌ها دارید بپرسید تا راهنمایی کنم و پلن مرحله‌ای بسازم."
                else:
                    ans = f"درخواست شما («{prompt}») توسط مشاور هوشمند بررسی شد.\n\nبر اساس تحلیل وضعیت روتر و اصول ایمنی Zero-Lockout، تغییرات پیشنهادی در قالب یک Plan مرحله‌ای و قابل‌بررسی آماده شده است. می‌توانید دکمه زیر را برای بررسی دستورات بزنید."

                if error_msg:
                    ans = f"⚠️ **پیام وضعیت اتصال به {provider}:**\n{error_msg}\n\n---\n🛡️ **پاسخ تحلیلی موتور قوانین داخلی RouterPilot:**\n\n{ans}"

                self.send_json(200, {"answer": ans, "source": "Rule Engine Fallback"})
        else:
            self.send_error(404)

def run():
    print("=" * 64)
    print("🚀 RouterPilot Control Plane v1.0 [Windows Standalone]")
    print("   معماری ایمن، هوشمند و تراکنشی مدیریت روترهای میکروتیک")
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
