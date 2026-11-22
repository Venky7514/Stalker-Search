# Stalker Search

An open-source, local-first personal privacy & self-OSINT scanner built in Rust with a Firefox-based companion browser extension.

**Why Stalker Search exists:** Before a stalker, doxxer, or malicious actor can piece together your digital life using Open-Source Intelligence (OSINT), Stalker Search helps **you** see what is publicly exposed under your name, email, or phone number—so you don't get caught off guard and can remove exposed documents, public calendars, profiles, and contact leaks early.

> **Disclaimer:** This software is strictly intended for defensive privacy awareness and authorized use. **Use it only for personal self-audits, authorized criminal investigations, authorized penetration testing, or open-source security projects.** Do not use this tool for harassment, stalking, or unauthorized surveillance.

![Stalker Search Interface](docs/preview.jpg)

---

## Supported Browsers

Works with **Firefox-based browsers**:
- **Mozilla Firefox**, **LibreWolf**, **Zen Browser**, **Floorp**, **Waterfox**, **Mullvad Browser**

*(Chromium browsers such as Chrome are not supported.)*

---

## Option 1: Quick Start (Recommended — No Coding or Build Tools Needed)

### 1. Download the Release Files
Go to **[GitHub Releases](https://github.com/Venky7514/Stalker-Search/releases)** and download:
1. **`stalker-search.exe`** *(Windows 10/11 64-bit)*
2. **`stalker-search-companion.zip`** *(unzip this into a folder)*

### 2. Add the Companion Extension to Your Browser
In **Firefox / LibreWolf / Zen / Floorp / Waterfox**:
1. Open a new tab and go to:
   ```text
   about:debugging#/runtime/this-firefox
   ```
2. Click **"Load Temporary Add-on..."**.
3. Open the unzipped companion folder and select **`manifest.json`**.
4. *(If you want to use **Incognito Search (Private)**)*:
   - Open **`about:addons`** → click **Stalker Search Companion** → set **Run in Private Windows** to **Allow**.

*(Note: Temporary add-ons stay loaded until you close the browser; repeat Step 2 if you restart the browser, or install directly from Mozilla Add-ons once published.)*

### 3. Run Your First Scan
1. Double-click **`stalker-search.exe`** — the dashboard will open automatically in your browser.
2. Enter at least **one** of **Name**, **Email**, or **Phone Number** *(add comma-separated **Context** like college, city, or company to narrow common names)*.
3. Pick a search mode and click **Search Footprint**:
   - **Open Google Search (Faster)**: Opens Google tabs in your active browser to avoid CAPTCHAs, scans all result pages, and automatically deletes temporary scan URLs from local browser history.
   - **Incognito Search (Private)**: Opens Google tabs in a Private window with zero saved history *(complete any "Verify you are human" check directly inside the Incognito tab if prompted)*.
   - **Background APIs Only**: Silently scans 18 public datasets (GitHub, Reddit, News RSS, arXiv, OpenAlex, ORCID, Google Calendar `.ics`, Gravatar, OpenPGP, etc.) without opening Google tabs.
4. **Keep the opened Google tabs open** while the on-page banner shows **`DO NOT CLOSE TAB`**. Once it turns green (**`SAFE TO CLOSE TAB`**), your dashboard displays all findings and opt-out/removal links.

---

## Option 2: Build From Source (Developers)

- **Prerequisites**: [Rust (`1.75+`)](https://rustup.rs/) + a Windows C linker (**MinGW-w64** `stable-x86_64-pc-windows-gnu` *or* Visual Studio C++ Build Tools; `xcode-select --install` on macOS; `build-essential pkg-config libssl-dev` on Linux). The extension needs zero build tools.

```bash
git clone https://github.com/Venky7514/Stalker-Search.git
cd Stalker-Search
cargo run --release
```

Then follow **Step 2** above using `companion_extension/manifest.json`.

### CLI Usage
```bash
cargo run -- dorks --name "Jane Doe" --context "MIT, Boston"
cargo run -- scan --name "Jane Doe" --context "MIT, Boston" --open-google --listen
cargo run -- scan --email "jane@example.com" --phone "+1 555-019-2834"
cargo run -- clean
```

---

## Privacy & Credits

- **100% Local**: Zero cookies, credentials, geolocation, telemetry, or saved search history on disk.
- **Inspiration**: Inspired in part by **[mxrch/GHunt](https://github.com/mxrch/GHunt)** for local browser companion architecture and public email/calendar pivoting techniques.
