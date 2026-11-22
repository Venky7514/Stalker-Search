# Stalker Search

An open-source, local-first digital footprint & personal OSINT privacy scanner written in Rust with a companion browser extension.

Stalker Search helps you discover public web references, social profiles, indexed documents (`.pdf`, `.docx`, `.xlsx`), public Google Calendars (`.ics`), and exposed contact details (emails, phone numbers) tied to a name, email, or phone number so you can lock down your online privacy.

---

## Prerequisites

- **Rust & Cargo** (`1.75+`): Install via [rustup.rs](https://rustup.rs/).
  - **Windows**: `rustup` requires a C linker (**Visual Studio C++ Build Tools** OR **MinGW-w64** with `x86_64-pc-windows-gnu`).
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`).
  - **Linux (Debian/Ubuntu)**: `build-essential pkg-config libssl-dev`.
- **Browser Extension Build Tools**: **None required!** The extension in [`companion_extension/`](./companion_extension) uses plain JavaScript/HTML/SVG (no Node.js, npm, webpack, or bundler).
- **Supported Browsers**: LibreWolf, Firefox, Brave, Chrome, Edge, Zen, Floorp, Vivaldi, or Opera.

---

## Step-by-Step Setup & Usage

### Step 1: Clone & Start the Application

```bash
git clone https://github.com/Venky7514/Stalker-Search.git
cd Stalker-Search
cargo run
```

- On startup, Stalker Search starts a private local web server strictly on `http://127.0.0.1:7878` (loopback only — zero external telemetry, zero disk search history) and opens the dashboard automatically in your active browser.
- *(Optional)* Launch without auto-opening a browser tab via `cargo run -- ui --no-open`.

---

### Step 2: Load the Temporary Browser Companion Extension

Until you install the signed version from Mozilla Add-ons, load the extension manually in under 15 seconds:

#### For Firefox / LibreWolf (`about:debugging`)
1. Open a new tab and go to:
   ```text
   about:debugging#/runtime/this-firefox
   ```
2. Click **"Load Temporary Add-on..."**.
3. Browse to the cloned `Stalker-Search/companion_extension/` folder and select **`manifest.json`**.
4. *(If you plan to use **Incognito Search (Private)**)*:
   - Open **`about:addons`** → find **Stalker Search Companion** → click it → set **Run in Private Windows** to **Allow**.

*(Note: Temporary add-ons loaded via `about:debugging` stay active until you close and restart the browser.)*

#### For Chrome / Brave / Edge
1. Open `chrome://extensions` (`brave://extensions` or `edge://extensions`).
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `Stalker-Search/companion_extension/` folder.

---

### Step 3: Run a Privacy Scan

1. **Enter Target Identity** (at least **one** of Name, Email, or Phone Number is required):
   - **Name**: Checks both `"First Last"` and `"Last First"`, plus compound name variations.
   - **Email**: Checks web leaks, GitHub commits, Gravatar, OpenPGP keys, and Public Google Calendar `.ics` feeds.
   - **Phone Number**: Checks normalized phone digit formats across directories and documents.
   - **Context** *(optional)*: Comma-separated keywords (e.g., college, city, company) to narrow common names. Enable **Strict Context Match Only** to hide results belonging to other people with the same name.
2. **Choose Search Mode**:
   - **Open Google Search (Faster)**: Opens targeted Google Search tabs in your active browser window to avoid CAPTCHAs, crawls up to 10 result pages (`Page 1 -> Page 2 -> ...`), syncs everything to `127.0.0.1:60067`, and automatically deletes the temporary scan query URLs from local browser history.
   - **Incognito Search (Private)**: Opens searches in a Private / Incognito browser window so zero history is stored. If Google prompts for human verification in an Incognito tab, complete it directly inside that tab without closing it.
   - **Background APIs Only**: Silently sweeps 18 public datasets (GitHub, GitLab, StackOverflow, NPM, Crates.io, Docker Hub, Hacker News, Reddit, Google News RSS, arXiv, OpenAlex, ORCID, Semantic Scholar, Crossref, Internet Archive, Wikipedia/Wikidata, Keybase, OpenPGP) without opening browser tabs.
3. **Wait for the On-Page Overlay**:
   - **Do NOT close** the opened Google Search browser tabs while the floating banner says **`DO NOT CLOSE TAB`**.
   - Once it switches to **`SAFE TO CLOSE TAB`**, your dashboard on `http://127.0.0.1:7878` updates automatically with risk-scored findings, discovered emails/phones, and direct remediation/opt-out links.
4. **Export or Wipe**:
   - Click **Export Markdown** or **Export JSON** to save a report locally, or **Clear Cache** in the header to wipe temporary state.

---

## Command-Line Interface (CLI) Usage

```bash
# Launch the Web Dashboard (default)
cargo run

# Preview generated dork queries without running a scan
cargo run -- dorks --name "Jane Doe" --context "MIT, Boston"

# Scan via CLI + Multi-Page Browser Companion Sync
cargo run -- scan --name "Jane Doe" --context "MIT, Boston" --open-google --listen

# Scan in Private / Incognito Browser Window
cargo run -- scan --name "Jane Doe" --incognito --listen

# Scan by Email or Phone Number only
cargo run -- scan --email "jane@example.com" --phone "+1 555-019-2834"

# Wipe any local cache files from disk
cargo run -- clean
```

---

## Privacy & Security Architecture

- **100% Local Loopback**: Both the Web UI (`127.0.0.1:7878`) and Companion Bridge (`127.0.0.1:60067`) bind exclusively to `127.0.0.1`.
- **Zero Cookies or Telemetry**: The browser extension only reads visible public search result cards (`div[data-snc]`, `div.MjjYud`, `div.g`) and sends them to `127.0.0.1`. It never accesses `document.cookie`, credentials, geolocation, or external analytics.
- **Zero Disk Search History**: Search queries and findings stay strictly in memory during scans and are never written to disk unless you explicitly click Export.
