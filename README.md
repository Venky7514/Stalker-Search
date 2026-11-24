# Stalker Search

A 100% free, open-source, zero-telemetry, local-first personal privacy & self OSINT desktop application with a Firefox-based companion browser extension.

**Why Stalker Search exists:** Before a stalker, doxxer, or malicious actor can piece together your digital life using Open-Source Intelligence (OSINT), Stalker Search helps **you** see what is publicly exposed under your name, email, or phone number (including 10-digit, 11-digit, and `+91` / country-code formats)—so you can find and remove exposed documents, public calendars, profiles, and contact leaks early.

> **Disclaimer:** This software is strictly intended for defensive privacy awareness and authorized use. **Use it only for personal self-audits, authorized criminal investigations, authorized penetration testing, or open-source security projects.** Do not use this tool for harassment, stalking, or unauthorized surveillance.

![Stalker Search Interface](docs/preview.jpg)

---

## Supported Browsers (Firefox-Based Only · LibreWolf Recommended)

Stalker Search's browser companion works exclusively with **Firefox-based browsers** because privacy-hardened Gecko browsers are far better suited for OSINT:
- **LibreWolf** *(specifically used & recommended by me)*
- **Mozilla Firefox**, **Zen Browser**, **Floorp**, **Waterfox**, **Mullvad Browser**

*(Chromium browsers are intentionally not used for the companion extension.)*

---

## Quick Start (Recommended — No Coding or Build Tools Needed)

### 1. Download & Unblock the Release Files
Go to **[GitHub Releases](https://github.com/Venky7514/Stalker-Search/releases)** and download:
1. **`stalker-search.exe`** *(Standalone Windows 10/11 64-bit desktop app)*
2. **`stalker-search-companion.zip`** *(Firefox/LibreWolf companion extension)*

> **Important — Unblock the `.exe` on Windows:** Because this is a 100% free, zero-telemetry open-source binary without a paid commercial code-signing certificate, Windows may mark the downloaded file as blocked:
> - **Right-click `stalker-search-v9.exe` → Properties → check `Unblock` at the bottom → click Apply / OK** *(or if Windows SmartScreen appears, click **More info** → **Run anyway**)*, **OR**
> - In PowerShell, run: `Unblock-File .\stalker-search-v9.exe`

---

### 2. Add the Companion Extension (Temporary Mode Preferred)
You can install the add-on directly or load it as a **Temporary Add-on**. **Loading it as a Temporary Add-on is preferred** because the extension only stays in memory for your active OSINT session and is automatically removed as soon as you close your browser:

1. In **LibreWolf** or **Firefox**, open a tab and go to:
   ```text
   about:debugging#/runtime/this-firefox
   ```
2. Click **"Load Temporary Add-on..."**.
3. Select **`stalker-search-companion-v9.zip`** directly *(or unzip it and select `manifest.json`)*.
4. **Required if you want to use `Incognito Search (Private)` mode:**
   - Open a tab to **`about:addons`** → click **Stalker Search Companion** → scroll down to **Run in Private Windows** and set it to **`Allow`**.
   - *(Note: Firefox resets "Run in Private Windows" to "Don't Allow" every time you load a temporary add-on, and the Stalker Search app will show a live green indicator as soon as you switch it to **Allow**.)*

---

### 3. Run Your Scan
1. Double-click **`stalker-search-v9.exe`** — it opens in its own desktop software window.
2. Enter at least **one** of **Name**, **Email**, or **Phone Number** *(add comma-separated **Context** like college, city, or company to narrow common names)*.
3. Choose a Search Mode and click **Search Footprint**:
   - **Open Google Search (Faster)**: Uses your active Firefox/LibreWolf window to avoid CAPTCHAs, crawls up to 10 pages of Google results per query, automatically deletes the searched query URLs from your browser history, and **auto-closes the tabs** once synced.
   - **Incognito Search (Private)**: Launches Google searches in a Private window with zero saved history. **If Google prompts "Verify you are human" (CAPTCHA) inside the Private tab, complete the human verification directly in that tab** (keep the tab open while verifying)—once verified, it will scan all pages and **auto-close the tabs** automatically.
   - **Background APIs Only**: Silently queries 18 public datasets (GitHub, Reddit, News RSS, arXiv, OpenAlex, ORCID, Google Calendar `.ics`, Gravatar, OpenPGP, etc.) without opening any browser tabs.
4. Keep the opened Google tabs open while the on-page badge says **`DO NOT CLOSE TAB`**. As soon as syncing finishes, the badge turns green (**`CLOSE TAB NOW ✕`**) and the tabs close themselves automatically.

---

## Build From Source (Optional — For Developers)

- **Prerequisites**: [Rust (`1.75+`)](https://rustup.rs/) + a C linker (MinGW-w64 `stable-x86_64-pc-windows-gnu` or Visual Studio C++ Build Tools on Windows).

```bash
git clone https://github.com/Venky7514/Stalker-Search.git
cd Stalker-Search
cargo run --release
```

---

## Privacy & Credits

- **100% Free & Zero Telemetry**: Everything runs locally on `127.0.0.1`. Zero cookies, credentials, geolocation, analytics, or external servers are ever contacted by Stalker Search.
- **Inspiration**: Inspired in part by **[mxrch/GHunt](https://github.com/mxrch/GHunt)** for local browser companion architecture and public email/calendar pivoting techniques.
