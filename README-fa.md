

<div align="center">

# 🔥 CMLF - فایروال ماژولار و قابل تنظیم لینوکس

### *تنها فایروالی که خودش یاد می‌گیره و هوشمندانه از شبکه محافظت می‌کنه*

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=for-the-badge&logo=go)](https://golang.org)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/Mlauncher6/CMLF?style=for-the-badge&logo=github)](https://github.com/Mlauncher6/CMLF/stargazers)
[![Release](https://img.shields.io/github/v/release/Mlauncher6/CMLF?style=for-the-badge&logo=github)](https://github.com/Mlauncher6/CMLF/releases)

**[English](README.md) | [فارسی](README-fa.md)**

</div>

---

## 🎯 **CMLF چیه و چرا باید بهش اهمیت بدی؟**

CMLF یه فایروال نسل جدیده که از **هوش مصنوعی** و **یادگیری ماشین** برای شناسایی و مسدود کردن تهدیدات استفاده می‌کنه. برخلاف فایروال‌های سنتی که فقط به قوانین دستی تکیه دارن، CMLF **خودکار یاد می‌گیره** که ترافیک عادی شبکه چطوره و هر چی غیرعادی باشه رو بلاک می‌کنه.

### 📊 **مقایسه با دیگر فایروال‌ها**

| ویژگی | CMLF | iptables | UFW | pfSense |
|--------|------|----------|-----|---------|
| 🧠 **حالت یادگیری خودکار** | ✅ | ❌ | ❌ | ❌ |
| 🎨 **رابط کاربری TUI** | ✅ | ❌ | ❌ | ✅ |
| 🕵️ **تشخیص اسکن پورت** | ✅ | ❌ | ❌ | ❌ |
| 🔒 **محافظت SSH Brute Force** | ✅ | ❌ | ❌ | ✅ |
| 📤 **تشخیص خروج اطلاعات** | ✅ | ❌ | ❌ | ❌ |
| ⚡ **محدودسازی نرخ هوشمند** | ✅ | ✅ | ❌ | ✅ |
| 🔌 **API و متدیکس** | ✅ | ❌ | ❌ | ✅ |
| 💾 **مصرف حافظه** | ~50MB | ~10MB | ~20MB | ~1GB+ |
| 💰 **قیمت** | رایگان | رایگان | رایگان | رایگان |
| 🐧 **اجرا روی Raspberry Pi** | ✅ | ✅ | ✅ | ❌ |

---

## ✨ **ویژگی‌هایی که CMLF رو خاص می‌کنه**

### 🛡️ **امنیت هوشمند لایه‌ای**

| قابلیت | توضیح | کاربرد |
|--------|-------|--------|
| **تشخیص اسکن پورت** | اسکنرها رو بعد از چند ثانیه شناسایی می‌کنه | جلوگیری از حملات کاوشگری |
| **محافظت SSH** | حملات دیکشنری و بروت فورس رو بلاک می‌کنه | امنیت سرورهای لینوکس |
| **تشخیص خروج اطلاعات** | بسته‌های خروجی بزرگ رو رصد می‌کنه | جلوگیری از سرقت داده |
| **محدودسازی نرخ** | Token Bucket برای هر کلاینت | مقابله با DDoS |

### 🎮 **رابط کاربری حرفه‌ای**

```

┌─────────────────────────────────────────────────────────────┐
│  CMLF Firewall    Uptime: 2h 15m    Packets: 1,234,567    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  📡 Active Connections (last 10):                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 192.168.1.100:54321 → 8.8.8.8:443 (tcp, 2m)        │   │
│  │ 10.0.0.50:12345 → 1.1.1.1:53 (udp, 5m)            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  🚫 Blocked IPs:                                           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ 45.155.205.33 (Port scan, 8m remaining)           │   │
│  │ 185.130.5.67 (SSH brute force, 25m remaining)     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  📊 Traffic Rate: 1,234 pps [████████░░░░░░░░]            │
│                                                             │
│  💬 Last: IP 192.168.1.100 blocked for port scan          │
│                                                             │
│  [q] quit  [b] blacklist  [r] reload  [l] learning mode  │
└─────────────────────────────────────────────────────────────┘

```

### 🧠 **حالت یادگیری (Learning Mode)**

CMLF می‌تونه تا ۲۴ ساعت ترافیک شبکه رو یاد بگیره و بعدش بهت بگه:

- چه پورت‌هایی بیشتر استفاده می‌شن
- چه IPهایی بیشترین ترافیک رو دارن
- نرخ نرمال بسته‌ها چنده
- الگوهای غیرعادی کدامند

---

## 📦 **نصب سریع (۳ دقیقه‌ای)**

### روش اول: دانلود باینری آماده

```bash
# دانلود آخرین نسخه
wget https://github.com/Mlauncher6/CMLF/releases/latest/download/cmlf-linux-amd64

# قابل اجرا کردن
chmod +x cmlf-linux-amd64

# اجرا
sudo ./cmlf-linux-amd64 --tui
```

روش دوم: کامپایل از سورس

```bash
# کلون کردن
git clone https://github.com/Mlauncher6/CMLF.git
cd CMLF

# نصب وابستگی‌ها
sudo apt install -y libpcap-dev iptables

# کامپایل
go build -ldflags="-s -w" -o cmlf cmd/cmlf/main.go

# اجرا
sudo ./cmlf --tui
```

روش سوم: با Makefile (حرفه‌ای‌تر)

```bash
make build          # فقط کامپایل
make run            # کامپایل + اجرا با TUI
make install        # نصب در سیستم (/usr/local/bin)
make clean          # پاک کردن فایل‌های موقت
```

---

🎮 راهنمای کامل استفاده

دستورات پایه

```bash
# اجرای اصلی با رابط کاربری
sudo cmlf --tui

# اجرا به عنوان سرویس پس‌زمینه
sudo cmlf --daemon

# فعال‌سازی حالت یادگیری (۱ ساعت)
sudo cmlf --learn --duration=3600

# تست خشک (هیچ چیزی واقعاً بلاک نمیشه)
sudo cmlf --dry-run --tui

# استفاده از اینترفیس خاص
sudo cmlf --tui --interface=ens33
```

مدیریت لیست سیاه

```bash
# اضافه کردن IP
sudo cmlf --block-add=1.2.3.4 --reason="حمله SSH"

# حذف IP
sudo cmlf --block-remove=1.2.3.4

# مشاهده همه IPهای بلاک شده
sudo cmlf --block-list

# مشاهده وضعیت کلی
sudo cmlf --status
```

کلیدهای میانبر در TUI

کلید عمل توضیح
q خروج خارج شدن از برنامه
b لیست سیاه نمایش IPهای بلاک شده
r بارگذاری مجدد اعمال تغییرات فایل قوانین
l یادگیری فعال‌سازی حالت یادگیری
↑/↓ حرکت اسکرول در لیست‌ها

---

📝 نوشتن قوانین (قدرتمند و ساده)

فایل قوانین در /etc/cmlf/rules.conf:

```apache
# ============================================
# قوانین فایروال CMLF
# ============================================

# اجازه دادن به شبکه داخلی
allow src 192.168.0.0/16
allow src 10.0.0.0/8
allow src 172.16.0.0/12

# محدودسازی وب (۵۰ درخواست در ثانیه)
ratelimit dst port 80 rate 50/sec burst 100
ratelimit dst port 443 rate 50/sec burst 100

# بلاک کردن IPهای بد
deny src 185.130.5.0/24
deny src 45.155.205.0/24
deny src 103.115.17.0/24

# لیست سفید برای سرویس‌های حیاتی
whitelist ip 8.8.8.8
whitelist ip 1.1.1.1
whitelist ip 208.67.222.222

# محافظت از SSH (فقط از شبکه داخلی)
allow dst port 22 src 192.168.0.0/16
deny dst port 22

# اجازه PING
allow proto icmp

# لاگ کردن اتصالات عجیب (اختیاری)
# log src 0.0.0.0/0

# پیش‌فرض: اجازه همه چیز
```

اولویت اجرای قوانین:

```
1️⃣ whitelist   (بالاترین اولویت - اینا هیچوقت بلاک نمی‌شن)
2️⃣ blacklist   (IPهای بلاک شده)
3️⃣ deny        (منع صریح)
4️⃣ ratelimit   (محدودسازی نرخ)
5️⃣ allow       (اجازه صریح)
6️⃣ default     (پیش‌فرض: اجازه)
```

---

📊 مانیتورینگ و Metrixها

APIهای HTTP

```bash
# دریافت وضعیت JSON
curl http://localhost:9090/status

# دریافت لیست سیاه
curl http://localhost:9090/blacklist

# دریافت متدیکس پرومتئوس
curl http://localhost:9090/metrics
```

خروجی نمونه

```json
{
  "uptime": 86400.5,
  "packets_processed": 15234567,
  "packets_dropped": 1234,
  "active_connections": 42,
  "blacklisted_ips": 8
}
```

ادغام با Grafana + Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'cmlf'
    static_configs:
      - targets: ['localhost:9090']
```

---

🐳 اجرا با Docker

```bash
# ساخت image
docker build -t cmlf:latest .

# اجرای کانتینر
docker run --cap-add=NET_ADMIN --cap-add=NET_RAW \
    --network host \
    -v /etc/cmlf:/etc/cmlf \
    -p 9090:9090 \
    cmlf:latest --tui
```

---

🔧 عیب‌یابی سریع

مشکل: خطای Permission denied

```bash
# راه‌حل: با sudo اجرا کن
sudo cmlf --tui

# یا تنظیم capabilities
sudo setcap cap_net_raw,cap_net_admin+eip cmlf
```

مشکل: بسته‌ای دریافت نمی‌شه

```bash
# بررسی اینترفیس
ip link show

# فعال کردن promiscuous mode
sudo ip link set eth0 promisc on

# تست با اینترفیس خاص
sudo cmlf --tui --interface=ens33
```

مشکل: iptables کار نمی‌کنه

```bash
# نصب iptables
sudo apt install iptables

# بررسی ماژول‌ها
lsmod | grep iptable

# خاموش کردن حالت dry-run (اگه روشن بوده)
# --dry-run رو از دستور حذف کن
```

---

🏢 استقرار در محیط تولید

سرویس Systemd

```bash
# ایجاد فایل سرویس
sudo nano /etc/systemd/system/cmlf.service
```

```ini
[Unit]
Description=CMLF Enterprise Firewall
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/cmlf --daemon --interface=eth0
Restart=always
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
# فعال‌سازی و شروع
sudo systemctl enable cmlf
sudo systemctl start cmlf
sudo systemctl status cmlf
```

---

📈 عملکرد و منابع مصرفی

معیار مقدار
پردازش بسته در ثانیه ~۱۵۰,۰۰۰ بسته
مصرف RAM ۵۰-۱۰۰ مگابایت
مصرف CPU (بی‌کاری) <۱٪
تاخیر پردازش <۱۰۰ میکروثانیه
اتصال همزمان تا ۶۵,۵۳۵

---

❓ سوالات متداول

س: تفاوت CMLF با iptables چیه؟
ج: iptables یه ابزار فیلترینگ پایه‌ست، ولی CMLF هوشمنده، یاد می‌گیره، تشخیص ناهنجاری داره و TUI جذابی داره.

س: روی Raspberry Pi کار می‌کنه؟
ج: بله! هم روی معماری ARM و هم x86_64 عالی کار می‌کنه.

س: چطور یه IP رو آنبلاک کنم؟
ج: sudo cmlf --block-remove=1.2.3.4

س: IPv6 پشتیبانی میشه؟
ج: تا حدی بله. ضبط بسته کار می‌کنه، ولی تشخیص ناهنجاری فعلاً IPv4 هست. برنامه داریم.

س: چطور می‌تونم کمک کنم؟
ج: با زدن ⭐، گزارش باگ، نوشتن کد، ترجمه یا معرفی به دیگران!

---

🤝 چطور مشارکت کنیم؟

1. ⭐ به پروژه ستاره بده
2. 🐛 باگ پیدا کردی؟ Issue باز کن
3. 💡 ایده داری؟ تو Discussions بگو
4. 🔧 کد می‌نویسی؟ Pull Request بفرست
5. 📝 مستندات رو بهبود بده
6. 🌍 ترجمه به زبان‌های دیگه

---

📜 مجوز

این پروژه تحت مجوز MIT منتشر شده - کاملاً رایگان برای استفاده شخصی و تجاری.

---

⭐ حمایت کردن

اگه CMLF برات مفید بوده:

· ⭐ یه ستاره بده تا خوشحال شم
·

---

<div align="center">

ساخته شده با 💜 و Go
