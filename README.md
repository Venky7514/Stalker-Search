# Stalker Search

A free, open source, zero telemetry, local personal privacy and OSINT desktop application with a companion extension for Firefox based browsers. Built and personally tested on **Arch Linux**, **Kali Linux**, and **Windows**.

**Why Stalker Search exists:** Before a stalker or malicious actor can piece together your digital life using Open Source Intelligence (OSINT), Stalker Search helps **you** see what is publicly exposed under your name, email, or phone number (including 10 digit, 11 digit, and `+91` or international country code formats) so you can find and remove leaked documents, public calendars, profiles, and contact details early.

> **Disclaimer:** Strictly for defensive privacy awareness and authorized use (**personal self audits, authorized criminal investigations, authorized penetration testing, or open source security projects**). Do not use for harassment, stalking, or unauthorized surveillance.

![Stalker Search Interface](docs/preview.jpg)

---

## Supported Browsers (Firefox Based Only · LibreWolf Recommended)

Works exclusively with **Firefox based browsers** because privacy hardened Gecko browsers are far better suited for OSINT:
- **LibreWolf** *(personally used and recommended by me on Linux and Windows)*
- **Mozilla Firefox**, **Zen Browser**, **Floorp**, **Waterfox**, **Mullvad Browser**

> **Important: Keep ONLY the browser where you loaded the companion addon open (close any other browsers before scanning) so Stalker Search does not accidentally open scan tabs in a different browser.**

---

## Step 1: Install & Launch (Linux & Windows)

### On Linux (Tested on Arch Linux & Kali Linux · Also Supports Fedora, Ubuntu, Debian, Mint)

1. **Install prerequisites**:
   - **Arch Linux**: `sudo pacman -S --needed base-devel pkgconf openssl rust`
   - **Kali / Ubuntu / Debian / Mint**: `sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev rustc cargo`
   - **Fedora**: `sudo dnf install -y gcc pkg-config openssl-devel rust cargo`
2. **Clone and run**:
   ```bash
   git clone https://github.com/Venky7514/Stalker-Search.git
   cd Stalker-Search
   cargo run --release
   ```
   *(If the interface does not pop up automatically, such as when running the terminal as `root` on Kali Linux, manually open **`http://127.0.0.1:7878`** in your browser.)*

### On Windows (10 / 11)

1. Download **`stalker-search.exe`** and **`stalker-search-companion.zip`** from **[GitHub Releases](https://github.com/Venky7514/Stalker-Search/releases)**.
2. **Unblock the `.exe`**: Because this is a free, zero telemetry open source binary without a paid commercial certificate, right click `stalker-search.exe` → **Properties** → check **Unblock** → **Apply** *(or run `Unblock-File .\stalker-search.exe` in PowerShell, or click **More info** → **Run anyway**)*, then open `stalker-search.exe`.

---

## Step 2: Add the Companion Extension (Temporary Mode Preferred)

Loading the addon as a **Temporary Addon** is preferred because it only stays in memory for your active OSINT session and is removed automatically when you close your browser:

1. In **LibreWolf** or **Firefox**, go to:
   ```text
   about:debugging#/runtime/this-firefox
   ```
2. Click **"Load Temporary Addon..."** and select **`companion_extension/manifest.json`** *(Linux / source)* or **`stalker-search-companion.zip`** *(Releases)*.
3. **For `Incognito Search (Private)` mode:** Open **`about:addons`** → click **Stalker Search Companion** → set **Run in Private Windows** to **`Allow`** *(Firefox resets this to "Don't Allow" each time you reload a temporary addon)*.

---

## Step 3: Run Your Scan

1. **Keep only your companion browser open** and open Stalker Search (`cargo run --release` on Linux or `stalker-search.exe` on Windows, or visit **`http://127.0.0.1:7878`**).
2. Enter at least **one** of **Name**, **Email**, or **Phone Number** *(add comma separated **Context** like college, city, or company to narrow common names)*.
3. Select a Search Mode and click **Search Footprint**:
   - **Open Google Search (Faster)**: Uses your active browser to avoid CAPTCHAs, crawls up to 10 Google pages per query, deletes the searched URLs from browser history, and **auto closes the tabs** once synced.
   - **Incognito Search (Private)**: Opens searches in a Private window with zero saved history. **If Google prompts "Verify you are human" (CAPTCHA) in the Private tab, complete the verification directly inside that tab** (keep the tab open while verifying) and it will scan all pages and **auto close the tabs** automatically.
   - **Background APIs Only**: Silently queries 18 public datasets (GitHub, Reddit, News RSS, arXiv, OpenAlex, ORCID, Google Calendar `.ics`, Gravatar, OpenPGP, etc.) without opening browser tabs.

---

## Privacy & Credits

- **100% Free & Zero Telemetry**: Runs purely on `127.0.0.1` with zero cookies, analytics, or external servers.
- **Inspiration**: Inspired in part by **[mxrch/GHunt](https://github.com/mxrch/GHunt)** for local browser companion architecture and public email and calendar pivoting techniques.
