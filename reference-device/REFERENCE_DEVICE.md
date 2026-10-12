# 📋 مستند روتر مرجع (Reference Device Specification)

> **دستگاه مرجع پروژه RouterPilot:** روتر سخت‌افزاری مرجع جهت استانداردسازی، اعتبارسنجی الگوریتم‌های Failover، تثبیت کانتینر Mihomo، اتصال L2TP و اجرای آزمون‌های خودکار.

---

## ۱. مشخصات سخت‌افزاری و سیستم‌عامل

| مشخصه | مقدار مرجع | توضیحات |
| :--- | :--- | :--- |
| **Model** | `MikroTik RB5009UG+S+IN` (یا معادل Cloud Router) | پردازنده ۴ هسته‌ای قدرتمند |
| **Architecture** | `arm64` | سازگاری کامل با کانتینرهای Docker/Linux |
| **RouterOS Version** | `7.15.3 (Stable)` | پشتیبانی کامل از REST API و Routing Tables v7 |
| **RAM Total / Free** | `1024 MB / ~780 MB` | حافظه کافی برای اجرای کانتینر بدون OOM |
| **Storage / Flash** | `1024 MB NAND` | حافظه اصلی روتر |
| **External USB** | `14+ GB USB 3.0 (ext4)` | **الزامی:** محل ذخیره‌سازی کانتینر برای جلوگیری از فرسودگی NAND |
| **LAN Management IP** | `172.16.20.1/24` | اینترفیس Bridge داخلی و حفاظت‌شده (Zero-Lockout) |

---

## ۲. استاندارد نام‌گذاری و کامنت‌ها (Naming Convention)

برای جلوگیری از سردرگمی و خوانایی خودکار توسط موتور Discovery، تمام المان‌های شبکه باید از الگوی زیر پیروی کنند:

### ۲.۱ اینترفیس‌ها و پورت‌ها:
- `WAN-1` یا `WAN-Primary`: پورت متصل به اینترنت اول (مثلاً مبین‌نت / شاتل / همراه اول)
- `WAN-2` یا `WAN-Backup`: پورت متصل به اینترنت دوم (مثلاً مخابرات / آسیاتک / زیتل)
- `LAN-Bridge`: اینترفیس بریج متصل به پورت‌های داخلی
- `veth-mihomo`: اینترفیس شبکه مجازی اختصاصی کانتینر Mihomo

### ۲.۲ روت‌ها و جداول روتینگ (Routing Tables):
- روت اصلی اینترنت اول:
  ```routeros
  /ip route add dst-address=0.0.0.0/0 gateway=192.168.1.1 distance=1 check-gateway=ping comment="WAN1-Primary-Internet"
  ```
- روت پشتیبان اینترنت دوم:
  ```routeros
  /ip route add dst-address=0.0.0.0/0 gateway=192.168.2.1 distance=2 comment="WAN2-Backup-Internet"
  ```
- جدول اختصاصی Policy Routing:
  ```routeros
  /routing table add name=to_WAN2 fib
  /ip route add dst-address=0.0.0.0/0 gateway=192.168.2.1 routing-table=to_WAN2 comment="Policy-Routing-WAN2"
  ```

---

## ۳. تثبیت ماژول‌های حیاتی

### ۳.۱ ماژول Failover:
- **پایش پیوسته سلامت:** استفاده از مکانیزم `check-gateway=ping` یا اسکریپت Netwatch با پایش IPهای عمومی (`1.1.1.1` و `8.8.8.8`).
- **زمان سوئیچ:** زیر ۱ ثانیه هنگام قطعی لینک فیزیکی یا عدم پاسخ پکت‌ها.
- **بازگشت خودکار:** به محض برقراری مجدد لینک اصلی، ترافیک بدون قطع ارتباط دستی به مسیر اولویت ۱ بازمی‌گردد.

### ۳.۲ ماژول L2TP Client:
- اتصال خودکار با گزینه `add-default-route=no` جهت جلوگیری از تصاحب مسیر اصلی اینترنت.
- هدایت گزینشی ترافیک از طریق Mangle و Routing Mark به جدول VPN.

### ۳.۳ کانتینر Mihomo (Clash Meta):
- **مسیر روت کانتینر:** اکیداً روی `usb1/mihomo` (برای صفر کردن استهلاک حافظه داخلی روتر).
- **پورت‌های ارتباطی:**
  - `7890`: پورت پروکسی مختلط (HTTP / SOCKS5)
  - `9090`: پورت REST API کنترل پنل MetaCubeX
  - `1053`: پورت DNS داخلی (Fake-IP / DoH)

---

## ۴. مجموعه تست‌های خودکار (Test Suite)

اسکریپت اعتبارسنجی خودکار در مسیر `reference-device/tests/test_suite.py` قرار دارد و سناریوهای زیر را تست می‌کند:

1. **Test 01 - Management Connectivity:** پینگ و تست باز بودن پورت‌های 80، 8728، 22 روی `172.16.20.1`.
2. **Test 02 - WAN 1 Gateway Health:** تست زمان پاسخگویی گیت‌وی اول.
3. **Test 03 - WAN 2 Gateway Health:** تست زمان پاسخگویی گیت‌وی دوم.
4. **Test 04 - DNS Resolution Test:** تست تفکیک دامنه‌های داخلی و خارجی.
5. **Test 05 - Failover Simulation:** شبیه‌سازی قطعی گیت‌وی اول و تأیید برقراری ارتباط از مسیر دوم.
6. **Test 06 - Mihomo Container Health:** استعلام وضعیت سلامت REST API کانتینر روی پورت ۹۰۹۰.
7. **Test 07 - Zero-Lockout Verification:** بررسی عدم تغییر رنج IP مدیریت در جدول روتینگ.
