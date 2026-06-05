


<div align="center">

# 🔥 CMLF - فایروال ماژولار و قابل تنظیم لینوکس

### *فایروال هوشمند با تشخیص تهدیدات سطح بالا و رابط کاربری حرفه‌ای*

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=for-the-badge&logo=go)](https://golang.org)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

</div>

---

## 🎯 **چرا CMLF؟**

CMLF فقط یه فایروال معمولی نیست - یه سیستم امنیتی هوشمنده که **یاد می‌گیره**، **تطبیق پیدا می‌کنه** و **در لحظه محافظت می‌کنه**.

| فایروال‌های سنتی | CMLF |
|-----------------|------|
| ❌ فقط بر پایه قوانین ایستا | ✅ **تشخیص ناهنجاری پویا** |
| ❌ قابلیت یادگیری ندارد | ✅ **پروفایلینگ خودکار ترافیک** |
| ❌ رابط کاربری ساده | ✅ **داشبورد TUI مدرن** |
| ❌ لیست سیاه دستی | ✅ **بلاک خودکار با زمان انقضا** |
| ❌ API ندارد | ✅ **REST + متدیکس Prometheus** |

---

## ✨ **ویژگی‌های برجسته**

### 🛡️ **تشخیص هوشمند تهدیدات**
- **تشخیص اسکن پورت** - بلاک خودکار اسکنرها بعد از آستانه تعیین شده
- **محافظت در برابر حمله SSH** - لیست سیاه پویای IP‌ها
- **تشخیص خروج اطلاعات** - نظارت بر بسته‌های بزرگ
- **محدودسازی نرخ** - الگوریتم Token Bucket برای هر کلاینت

### 🎨 **رابط کاربری مدرن**
- **TUI بلادرنگ** - مشاهده لحظه‌ای اتصالات و آمار
- **API HTTP** - خروجی JSON و متدیکس Prometheus
- **داشبورد رنگی** - نمایش بصری و جذاب

### 🧠 **ویژگی‌های هوشمند**
- **حالت یادگیری** - پروفایل‌سازی ترافیک نرمال
- **بررسی وضعیت اتصالات** - ردیابی کامل TCP
- **لیست سیاه پایدار** - ذخیره در فایل JSON
- **حالت آزمایشی** - تست قوانین بدون بلاک کردن

### 🔧 **آماده برای محیط تولید**
- **ادغام با iptables** - فیلترینگ در سطح کرنل
- **پشتیبانی از Systemd** - اجرا به عنوان سرویس پس‌زمینه
- **بدون وابستگی** - یک فایل باینری ایستا
- **مصرف منابع کم** - معمولاً ۵۰ مگابایت رم

---

## 📋 **راهنمای سریع نصب**

### **مرحله ۱: نصب پیش‌نیازها**

```bash
# اوبونتو/دبیان
sudo apt-get update && sudo apt-get install -y \
    libpcap-dev \
    iptables \
    build-essential

# RHEL/CentOS/Fedora
sudo yum install -y \
    libpcap-devel \
    iptables \
    gcc
```

### **مرحله ۲: نصب Go**

```bash
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### **مرحله ۳: دریافت CMLF**

```bash
git clone https://github.com/yourusername/cmlf.git
cd cmlf

# نصب وابستگی‌ها
go mod init cmlf
go get github.com/google/gopacket
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss

# ساخت فایل باینری
go build -ldflags="-s -w" -o cmlf CMLF.go
```

### **مرحله ۴: تنظیمات اولیه**

```bash
# ساخت پوشه تنظیمات
sudo mkdir -p /etc/cmlf

# ساخت فایل قوانین پیش‌فرض
sudo tee /etc/cmlf/rules.conf << 'EOF'
# ============================================
# تنظیمات فایروال CMLF
# ============================================

# اجازه دادن به شبکه داخلی
allow src 192.168.0.0/16
allow src 10.0.0.0/8

# محدودسازی نرخ برای وب (۵۰ درخواست در ثانیه)
ratelimit dst port 80 rate 50/sec burst 100

# محافظت از SSH
deny dst port 22 src 0.0.0.0/0

# لیست سفید برای سرورهای DNS
whitelist ip 8.8.8.8
whitelist ip 1.1.1.1

# اجازه ICMP (پینگ)
allow proto icmp

# پیش‌فرض: اجازه همه چیز
EOF
```

### **مرحله ۵: اجرای CMLF**

```bash
# اجرا با رابط کاربری TUI (پیشنهادی)
sudo ./cmlf --tui

# اجرا به عنوان سرویس پس‌زمینه
sudo ./cmlf --daemon

# حالت یادگیری - ابتدا ترافیک شبکه را یاد بگیر!
sudo ./cmlf --learn --duration=3600
```

---

## 🎮 **راهنمای کامل استفاده**

### **گزینه‌های خط فرمان**

```bash
CMLF v1.0.0 - فایروال ماژولار لینوکس

طرز استفاده:
  sudo ./cmlf [گزینه‌ها]

گزینه‌ها:
  --tui                     اجرای رابط کاربری TUI
  --daemon                  اجرا به عنوان سرویس پس‌زمینه
  --learn                   فعال‌سازی حالت یادگیری
  --duration=3600           مدت زمان یادگیری (ثانیه)
  --interface=eth0          رابط شبکه برای نظارت
  --config=/etc/cmlf/rules.conf
  --dry-run                 آزمایش بدون بلاک کردن
  --disable-http            غیرفعال کردن سرور متدیکس
  
مدیریت لیست سیاه:
  --block-add=1.2.3.4       اضافه کردن IP به لیست سیاه
  --reason="اسکن پورت"      دلیل بلاک
  --block-remove=1.2.3.4    حذف IP از لیست سیاه
  --block-list              نمایش همه IPهای بلاک شده
  --status                  نمایش وضعیت فایروال

مثال‌ها:
  sudo ./cmlf --tui --interface=ens33
  sudo ./cmlf --learn --duration=1800
  sudo ./cmlf --block-add=192.168.1.100 --reason="حمله SSH"
```

### **کلیدهای میانبر در TUI**

| کلید | عمل |
|------|------|
| `q` یا `Ctrl+C` | خروج از CMLF |
| `b` | مشاهده IPهای بلاک شده |
| `r` | بارگذاری مجدد قوانین |
| `l` | فعال‌سازی حالت یادگیری |
| `↑` `↓` | اسکرول در لیست‌ها |

---

## 📊 **نظارت و متدیکس‌ها**

### **نقاط پایانی API**

```bash
# دریافت وضعیت به صورت JSON
curl http://localhost:9090/status

# مشاهده لیست سیاه
curl http://localhost:9090/blacklist

# متدیکس‌های Prometheus
curl http://localhost:9090/metrics
```

### **مثال خروجی**

```json
{
  "uptime": 86400.5,
  "packets_processed": 15234567,
  "packets_dropped": 1234,
  "active_connections": 42,
  "blacklisted_ips": 8
}
```

### **ادغام با Prometheus**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'cmlf'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
```

---

## 🧪 **تست فایروال**

### **تست تشخیص اسکن پورت**

```bash
# از ماشین دیگر (هشدار: IP شما بلاک می‌شود!)
nmap -p 1-1000 آدرس_فایروال

# بررسی بلاک شدن
sudo ./cmlf --block-list
```

### **تست محافظت SSH**

```bash
# استفاده از hydra (فقط برای تست!)
hydra -l root -p passwords.txt ssh://آدرس_فایروال

# بررسی قوانین iptables
sudo iptables -L INPUT -n -v | grep DROP
```

### **تست محدودسازی نرخ**

```bash
# ارسال درخواست‌های سریع HTTP
for i in {1..200}; do
    curl -s http://سرور_شما > /dev/null &
done

# مشاهده بسته‌های dropped در TUI
```

---

## 🏗️ **استقرار در محیط تولید**

### **گزینه ۱: سرویس Systemd**

```bash
# ساخت فایل سرویس
sudo tee /etc/systemd/system/cmlf.service << 'EOF'
[Unit]
Description=CMLF Enterprise Firewall
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/cmlf --daemon --interface=eth0
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# نصب باینری
sudo cp cmlf /usr/local/bin/
sudo chmod 755 /usr/local/bin/cmlf

# فعال‌سازی و شروع
sudo systemctl daemon-reload
sudo systemctl enable cmlf
sudo systemctl start cmlf

# بررسی وضعیت
sudo systemctl status cmlf
sudo journalctl -u cmlf -f
```

### **گزینه ۲: داکر**

```dockerfile
# Dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    iptables \
    ca-certificates

COPY cmlf /usr/local/bin/cmlf
COPY rules.conf /etc/cmlf/rules.conf

ENTRYPOINT ["/usr/local/bin/cmlf"]
CMD ["--daemon", "--interface=eth0"]
```

```bash
# ساخت و اجرا
docker build -t cmlf:latest .
docker run --cap-add=NET_ADMIN --cap-add=NET_RAW \
    --network host \
    -v /etc/cmlf:/etc/cmlf \
    cmlf:latest
```

---

## 📁 **ساختار فایل‌ها**

CMLF فایل‌های زیر را خودکار می‌سازد:

| مسیر | خودکار ساخته می‌شود؟ | زمان |
|------|---------------------|------|
| `/etc/cmlf/` | ❌ دستی | یک بار بسازید |
| `/etc/cmlf/rules.conf` | ❌ دستی | برای قوانین سفارشی لازم است |
| `./blacklist.json` | ✅ بله | بعد از اولین بلاک |
| `./profile.json` | ✅ بله | بعد از حالت یادگیری |

**راه‌اندازی سریع:**
```bash
# راه‌اندازی یک بار
sudo mkdir -p /etc/cmlf
sudo tee /etc/cmlf/rules.conf << 'EOF'
allow src 0.0.0.0/0
EOF

# اجرا - blacklist.json خودکار ساخته می‌شود
sudo ./cmlf --tui

# حالت یادگیری - profile.json خودکار ساخته می‌شود
sudo ./cmlf --learn --duration=3600
```

---

## 🚨 **راهنمای عیب‌یابی**

### **خطای "Permission denied"**

```bash
# راه‌حل ۱: همیشه با sudo اجرا کنید
sudo ./cmlf --tui

# راه‌حل ۲: تنظیم capabilities (پیشرفته)
sudo setcap cap_net_raw,cap_net_admin+eip ./cmlf
./cmlf --tui  # الان بدون sudo کار می‌کند
```

### **هیچ بسته‌ای دریافت نمی‌شود**

```bash
# لیست رابط‌های موجود
ip link show

# فعال‌سازی حالت promiscuous
sudo ip link set eth0 promisc on

# تست با رابط خاص
sudo ./cmlf --tui --interface=ens33
```

### **قوانین iptables اعمال نمی‌شوند**

```bash
# بررسی نصب iptables
which iptables

# بررسی حالت dry-run
./cmlf --dry-run  # این گزینه را بردارید!
```

### **مشکل در نمایش TUI**

```bash
# تنظیم ترمینال صحیح
export TERM=xterm-256color

# افزایش بافر
stty rows 50 cols 120
```

---

## 📈 **عملکرد سیستم**

| معیار | مقدار |
|-------|-------|
| **توان پردازش بسته** | ~۱۵۰,۰۰۰ بسته در ثانیه |
| **مصرف حافظه** | ۵۰-۱۰۰ مگابایت |
| **مصرف CPU (در حالت بیکاری)** | <۱٪ |
| **ردیابی اتصالات همزمان** | تا ۶۵,۵۳۵ اتصال |

---

## 🔐 **بهترین روش‌های امنیتی**

1. **همیشه اول از حالت یادگیری استفاده کنید**
   ```bash
   sudo ./cmlf --learn --duration=86400  # ۲۴ ساعت
   ```

2. **در محیط تولید از حالت خشک استفاده کنید**
   ```bash
   sudo ./cmlf --daemon --dry-run
   # قبل از اجرای واقعی، نتایج را بررسی کنید
   ```

3. **بررسی منظم لیست سیاه**
   ```bash
   # کرون جاب روزانه
   0 0 * * * /usr/local/bin/cmlf --block-list > /var/log/cmlf-blacklist.log
   ```

4. **پشتیبان‌گیری از تنظیمات**
   ```bash
   tar czf cmlf-backup-$(date +%Y%m%d).tar.gz /etc/cmlf/ blacklist.json
   ```

---

## ❓ **سوالات متداول**

**س: آیا CMLF می‌تواند جایگزین کامل iptables شود؟**  
ج: خیر - CMLF با iptables کار می‌کند و از آن برای فیلترینگ در سطح کرنل استفاده می‌کند.

**س: آیا از IPv6 پشتیبانی می‌کند؟**  
ج: تا حدی - ضبط بسته کار می‌کند، اما تشخیص ناهنجاری روی IPv4 تمرکز دارد.

**س: چگونه یک IP را از لیست سیاه خارج کنم؟**  
ج: `sudo ./cmlf --block-remove=1.2.3.4`

**س: آیا می‌توانم روی Raspberry Pi استفاده کنم؟**  
ج: بله! روی هر دستگاه لینوکسی کار می‌کند.

---

## 📄 **مجوز**

**مجوز MIT** - رایگان برای استفاده شخصی و تجاری.

---

## ⚖️ **سلب مسئولیت حقوقی**

این نرم‌افزار فقط برای اهداف قانونی امنیتی طراحی شده است. کاربران مسئول رعایت قوانین محلی هستند.

---

<div align="center">

**ساخته شده با 💜 و Go**
