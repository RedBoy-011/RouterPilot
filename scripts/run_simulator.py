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

        if self.path == "/api/wan/failover":
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

        elif self.path == "/api/ai/ask":
            prompt = req_data.get("prompt", "")
            self.send_json(200, {
                "answer": f"بر اساس بررسی پیکربندی روتر مرجع شما و سؤال «{prompt}»:\n\nبرای این منظور می‌توانید از قابلیت Policy Routing در تب پروفایل‌ها استفاده کنید. ترافیک‌های حساس به صورت مستقیم از لینک مبین‌نت عبور داده شده و ترافیک بین‌الملل به سمت پروکسی هدایت خواهد شد. برای اجرای این تغییرات کافیست Plan مربوطه را تولید و پس از بررسی دستورات تأیید نمایید."
            })
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
