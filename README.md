# Ramin VPN

> یک ابزار VPN و مدیریت اتصال برای Termux با تمرکز بر پیدا کردن و آزمایش اتصال‌های مناسب.

---

## فارسی

### معرفی

**Ramin VPN** یک پروژه برای اجرای مدیریت و آزمایش اتصال‌های VPN در محیط Termux است.

این پروژه امکاناتی مانند جست‌وجوی اتصال، تست اتصال، انتخاب سرور، تنظیمات خودکار، IPv6، Fragment و AI Engine را در اختیار کاربر قرار می‌دهد.

### نصب در Termux

دستور زیر را اجرا کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/raminsepehr96/Ramin_VPN/main/install.sh | sh
```

پس از نصب، برنامه را با یکی از این دستورات اجرا کنید:

```bash
Ramin
```

یا:

```bash
ramin
```

### به‌روزرسانی

برای به‌روزرسانی، دوباره دستور نصب را اجرا کنید:

```bash
curl -fsSL https://raw.githubusercontent.com/raminsepehr96/Ramin_VPN/main/install.sh | sh
```

تنظیمات و فایل‌های شخصی داخل پوشه `Jason/` نباید در مخزن عمومی GitHub قرار بگیرند.

### Local Proxy

پروژه از اتصال‌های محلی روی دستگاه استفاده می‌کند.

پروکسی اصلی:

```text
Host: 127.0.0.1
Port: 64808
```

پورت‌های داخلی مورد استفاده پروژه شامل موارد زیر هستند:

```text
64808
3000
60000
50000
10808
```

نقش دقیق هر پورت ممکن است بسته به بخش استفاده‌کننده متفاوت باشد؛ شماره پورت به‌تنهایی نوع پروتکل را مشخص نمی‌کند.

### استفاده با RethinkDNS

در صورت پشتیبانی تنظیمات دستگاه و RethinkDNS، می‌توانید پروکسی محلی را به شکل زیر وارد کنید:

```text
Host: 127.0.0.1
Port: 64808
```

`127.0.0.1` به همان دستگاه اشاره می‌کند. بنابراین این تنظیم به‌صورت خودکار پروکسی را برای دستگاه‌های دیگر شبکه Wi-Fi قابل دسترس نمی‌کند.

### دستورات اصلی

| دستور | عملکرد |
|---|---|
| `FC` | Fast Connect |
| `AS` | Auto Setting |
| `FV` | Free Vless |
| `PC` | نمایش پروتکل |
| `SW` | Search Web |
| `AI` | AI Engine |
| `IP6` | IPv6 |
| `R` | Reload |
| `B1` | Speed Boost 1 |
| `B2` | Speed Boost 2 |

### Fragment

پروفایل‌های Fragment:

```text
F1
F2
F3
F4
```

خاموش کردن Fragment:

```text
F
```

### AI Engine

دستور:

```text
AI
```

AI Engine برای بررسی اتصال‌های موجود، استفاده از نتایج اندازه‌گیری‌شده و اطلاعات یادگرفته‌شده طراحی شده است.

### تست اتصال

پروژه می‌تواند اتصال‌های مختلف را آزمایش کند و از نتایج اندازه‌گیری‌شده برای انتخاب و ارزیابی اتصال استفاده کند.

### Source Memory

نتایج منابع می‌توانند در حافظه محلی پروژه ذخیره شوند تا اطلاعات قبلی در اجرای بعدی قابل استفاده باشد.

### Gemini API

قابلیت AI از Gemini API استفاده می‌کند.

کلید API نباید داخل GitHub قرار داده شود. کلید از طریق متغیر محیطی یا فایل محلی خوانده می‌شود.

نمونه متغیر محیطی:

```bash
export RAMIN_GEMINI_API_KEY="YOUR_API_KEY"
```

### ساختار پروژه

```text
Ramin_VPN/
├── Ramin_VPN.py
├── core.py
├── parser.py
├── source_memory.py
├── install.sh
├── .gitignore
└── README.md
```

فایل‌ها و اطلاعات حساس مانند API Key، فایل‌های session و فایل‌های شخصی نباید در مخزن عمومی قرار بگیرند.

---

## English

### Introduction

**Ramin VPN** is a Termux-based VPN connection management and testing project.

It provides features such as connection discovery, connection testing, server selection, automatic settings, IPv6, Fragment, and AI Engine.

### Installation

Run:

```bash
pkg update
pkg install -y curl
curl -fsSL https://raw.githubusercontent.com/raminsepehr96/Ramin_VPN/main/install.sh | sh
```

After installation, run:

```bash
Ramin
```

or:

```bash
ramin
```

### Updating

Run the installer again:

```bash
curl -fsSL https://raw.githubusercontent.com/raminsepehr96/Ramin_VPN/main/install.sh | sh
```

Personal settings and files stored in `Jason/` should not be uploaded to the public repository.

### Local Proxy

The project uses local connections on the device.

Main local proxy:

```text
Host: 127.0.0.1
Port: 64808
```

Internal ports used by the project include:

```text
64808
3000
60000
50000
10808
```

The exact role of each port may depend on the component using it. A port number alone does not define its protocol.

### RethinkDNS

If supported by your device and RethinkDNS configuration, use:

```text
Host: 127.0.0.1
Port: 64808
```

`127.0.0.1` refers to the same device. This does not automatically expose the proxy to other devices on the Wi-Fi network.

### Main Commands

| Command | Function |
|---|---|
| `FC` | Fast Connect |
| `AS` | Auto Setting |
| `FV` | Free Vless |
| `PC` | Show Protocol |
| `SW` | Search Web |
| `AI` | AI Engine |
| `IP6` | IPv6 |
| `R` | Reload |
| `B1` | Speed Boost 1 |
| `B2` | Speed Boost 2 |

### Fragment

Fragment presets:

```text
F1
F2
F3
F4
```

Disable Fragment:

```text
F
```

### AI Engine

Command:

```text
AI
```

The AI Engine is designed to evaluate available connections using measured results and previously learned information.

### Connection Testing

The project can test different connections and use measured results to evaluate available candidates.

### Source Memory

Source results can be stored locally so previously collected information can be reused in later runs.

### Gemini API

The AI functionality uses the Gemini API.

API keys should never be committed to the public GitHub repository. The key is read from an environment variable or a local file.

Example:

```bash
export RAMIN_GEMINI_API_KEY="YOUR_API_KEY"
```

### Project Structure

```text
Ramin_VPN/
├── Ramin_VPN.py
├── core.py
├── parser.py
├── source_memory.py
├── install.sh
├── .gitignore
└── README.md
```

Sensitive files such as API keys, session files, and personal data should not be uploaded to the public repository.

---

## License

This project is licensed under the MIT License. See the "LICENSE" (LICENSE) file for details.
