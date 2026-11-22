# Stalker Search

An open-source, self-OSINT digital footprint and personal privacy scanner written in Rust.

Stalker Search helps you discover public references, social profiles, indexed documents (`.pdf`, `.docx`, `.xlsx`), public Google Calendars (`.ics`), and exposed contact details (emails, phone numbers) tied to a name, email, or phone number so you can lock down your online privacy.

---

## Quick Start (Graphical Web Application Interface)

Launch the local web application interface (binds strictly to `127.0.0.1:7878` and opens in your active browser):

```powershell
cargo run
```

Or explicitly:

```powershell
cargo run -- ui
```

### Interface Features
- **Target Identity & Context Inputs**:
  - **Full Name**: Automatically searches both `"First Last"` and `"Last First"`, plus compound name variations.
  - **Email Address**: Checks public pastes, commits, Gravatar profiles, OpenPGP keys, and public Google Calendar `.ics` endpoints.
  - **Phone Number**: Checks normalized phone digit formats across directories and documents.
  - **Context Keywords**: Comma-separated keywords (e.g., college, city, company) to isolate one specific person among many people with the same name.
  - *Validation*: Requires at least one of **Full Name**, **Email Address**, or **Phone Number** before scanning.
- **Google Browser Search Modes**:
  - **Open Google Search (Faster)**: Opens targeted Google Search tabs in your active browser window (uses your existing browser session to avoid CAPTCHAs) and automatically crawls **every Google result page** (`Page 1 -> Page 2 -> ... -> Last Page`) via the Companion Extension.
  - **Incognito Search (Private)**: Opens targeted Google Search tabs in a Private / Incognito browser window (`-private-window` / `--incognito`) so queries are never saved to browser history.
  - **Background Scan Only (No Browser Tabs)**: Silently sweeps 18 keyless public datasets (GitHub, GitLab, StackOverflow, NPM, Crates.io, Docker Hub, Hacker News, Reddit, Google News RSS, arXiv, OpenAlex, ORCID, Semantic Scholar, Crossref, Internet Archive, Wikipedia/Wikidata, Keybase, OpenPGP) and search engines.
- **Zero-Retention Privacy Mode**:
  - Binds exclusively to `127.0.0.1` (loopback only — never exposed to LAN/Wi-Fi).
  - Never saves search queries or results to disk. Includes a 1-click **Wipe Local Cache** button (`cargo run -- clean`).

---

## Browser Companion Extension

The browser extension in [`companion_extension/`](./companion_extension) crawls all pages of a Google Search tab and syncs the extracted results to `http://127.0.0.1:60067/stalker_feed` (zero cookies, credentials, or external telemetry are ever accessed or transmitted).

### Installing Locally
- **Firefox / LibreWolf**: Open `about:debugging#/runtime/this-firefox` -> **Load Temporary Add-on** -> select [`companion_extension/manifest.json`](./companion_extension/manifest.json) (or install the signed extension from Mozilla Add-ons).
- **Chrome / Brave / Edge**: Open `chrome://extensions`, enable **Developer Mode**, and click **Load unpacked** -> select [`companion_extension/`](./companion_extension).

---

## Command-Line Interface (CLI) Usage

```powershell
# Scan by Name + Context + Multi-Page Google Companion Sync
cargo run -- scan --name "Jane Doe" --context "MIT, Boston" --open-google --listen

# Scan in Private / Incognito Browser Window
cargo run -- scan --name "Jane Doe" --incognito --listen

# Scan by Email or Phone Number only
cargo run -- scan --email "jane@example.com" --phone "+1 555-019-2834"

# Purge any local cached files
cargo run -- clean
```
