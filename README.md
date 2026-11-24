# Stalker Search

A free, open source, zero telemetry, local personal privacy and OSINT desktop application with a companion browser extension for Firefox based browsers. Built and personally tested on **Windows** and **Arch Linux**.

**Why Stalker Search exists:** Before a stalker, doxxer, or malicious actor can piece together your digital life using Open Source Intelligence (OSINT), Stalker Search helps **you** see what is publicly exposed under your name, email, or phone number (including 10 digit, 11 digit, and `+91` or international country code formats) so you can find and remove exposed documents, public calendars, profiles, and contact leaks early.

> **Disclaimer:** This software is strictly intended for defensive privacy awareness and authorized use. **Use it only for personal self audits, authorized criminal investigations, authorized penetration testing, or open source security projects.** Do not use this tool for harassment, stalking, or unauthorized surveillance.

![Stalker Search Interface](docs/preview.jpg)

---

## Supported Browsers (Firefox Based Only · LibreWolf Recommended)

Stalker Search works exclusively with **Firefox based browsers** because privacy hardened Gecko browsers are far better suited for OSINT:
- **LibreWolf** *(personally used and tested by me on both Windows and Arch Linux)*
- **Mozilla Firefox**, **Zen Browser**, **Floorp**, **Waterfox**, **Mullvad Browser**

> **Important: Keep ONLY the browser where you loaded the companion addon open (close any other browsers before scanning) so Stalker Search does not accidentally catch and open scan tabs in a different browser.**

*(Chromium browsers are intentionally not used for the companion extension.)*

---

## Step 1: Get Stalker Search (Windows & Linux)

### On Linux (Personally Tested on Arch Linux · Also Supports Fedora, Ubuntu, Debian, Kali, Mint)

1. **Install Rust and OpenSSL headers**:
   - **Arch Linux / Manjaro / EndeavourOS**:
     ```bash
     sudo pacman -S --needed base-devel pkgconf openssl rust
     ```
   - **Fedora / RHEL**:
     ```bash
     sudo dnf install -y gcc pkg-config openssl-devel rust cargo
     ```
   - **Ubuntu / Debian / Mint / Kali**:
     ```bash
     sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev
     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
     ```
2. **Clone and run**:
   ```bash
   git clone https://github.com/Venky7514/Stalker-Search.git
   cd Stalker-Search
   cargo run --release
   ```

### On Windows (10 / 11)

1. Go to **[GitHub Releases](https://github.com/Venky7514/Stalker-Search/releases)** and download:
   - **`stalker-search.exe`** *(Windows 64 bit standalone desktop app)*
   - **`stalker-search-companion.zip`** *(Companion extension for LibreWolf / Firefox)*
2. **Unblock the `.exe` on Windows:** Because this is a free, zero telemetry open source binary without a paid commercial signing certificate, Windows may mark the downloaded file as blocked:
   - Right click `stalker-search.exe` → **Properties** → check **Unblock** at the bottom → click **Apply / OK** *(or if Windows SmartScreen appears, click **More info** → **Run anyway**)*, **OR**
   - In PowerShell, run: `Unblock-File .\stalker-search.exe`

---

## Step 2: Add the Companion Extension (Temporary Mode Preferred)

You can install the addon directly or load it as a **Temporary Addon**. **Loading it as a Temporary Addon is preferred** because the extension only stays in memory for your active OSINT session and is automatically removed as soon as you close your browser:

1. In **LibreWolf** or **Firefox**, open a tab and go to:
   ```text
   about:debugging#/runtime/this-firefox
   ```
2. Click **"Load Temporary Addon..."**.
3. Select **`companion_extension/manifest.json`** *(on Linux / source)* or **`stalker-search-companion.zip`** *(from Releases)*.
4. **Required if you want to use `Incognito Search (Private)` mode:**
   - Open a tab to **`about:addons`** → click **Stalker Search Companion** → scroll down to **Run in Private Windows** and set it to **`Allow`**.
   - *(Note: Firefox resets "Run in Private Windows" to "Don't Allow" every time you load a temporary addon, and the Stalker Search app will show a live green indicator as soon as you switch it to **Allow**.)*

---

## Step 3: Run Your Scan

1. **Make sure only the browser with the companion addon loaded is open (close other browsers so Stalker Search does not accidentally open tabs in another browser).**
2. Launch Stalker Search (`cargo run --release` on Linux, or open `stalker-search.exe` on Windows).
3. Enter at least **one** of **Name**, **Email**, or **Phone Number** *(add comma separated **Context** like college, city, or company to narrow common names)*.
4. Choose a Search Mode and click **Search Footprint**:
   - **Open Google Search (Faster)**: Uses your active Firefox or LibreWolf window to avoid CAPTCHAs, crawls up to 10 pages of Google results per query, automatically deletes the searched query URLs from your browser history, and **auto closes the tabs** once synced.
   - **Incognito Search (Private)**: Launches Google searches in a Private window with zero saved history. **If Google prompts "Verify you are human" (CAPTCHA) inside the Private tab, complete the human verification directly in that tab** (keep the tab open while verifying). Once verified, it will scan all pages and **auto close the tabs** automatically.
   - **Background APIs Only**: Silently queries 18 public datasets (GitHub, Reddit, News RSS, arXiv, OpenAlex, ORCID, Google Calendar `.ics`, Gravatar, OpenPGP, etc.) without opening any browser tabs.
5. Keep the opened Google tabs open while the on page badge says **`DO NOT CLOSE TAB`**. As soon as syncing finishes, the badge turns green (**`CLOSE TAB NOW ✕`**) and the tabs close themselves automatically.

---

## Privacy & Credits

- **100% Free & Zero Telemetry**: Everything runs locally on `127.0.0.1`. Zero cookies, credentials, geolocation, analytics, or external servers are ever contacted by Stalker Search.
- **Inspiration**: Inspired in part by **[mxrch/GHunt](https://github.com/mxrch/GHunt)** for local browser companion architecture and public email and calendar pivoting techniques.
