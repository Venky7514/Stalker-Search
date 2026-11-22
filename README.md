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

## Browser Companion Extension & Mozilla Add-ons (AMO) Publishing

The extension in [`companion_extension/`](./companion_extension) crawls all pages of a Google Search tab and syncs the extracted results to `http://127.0.0.1:60067/stalker_feed` (zero cookies or credentials are ever read or transmitted).

### Publishing or Signing on Mozilla Add-ons (`addons.mozilla.org`)
A pre-packaged, Mozilla AMO-compliant archive is located at:
- `companion_extension/stalker-search-companion-mozilla.zip`

1. Go to the [Mozilla Add-on Developer Hub](https://addons.mozilla.org/en-US/developers/addon/submit/distribution).
2. Choose your distribution mode:
   - **"On your own" (Self-Distribution — Fastest, Automated Signing in ~2 minutes)**: Mozilla automatically signs the `.zip` into an official `.xpi` file that you can install permanently in Firefox or LibreWolf without `about:debugging`, while keeping it private to you.
   - **"On this site" (Public Mozilla Add-ons Store)**: Publishes the extension publicly on `addons.mozilla.org` for anyone to install.
3. Upload `companion_extension/stalker-search-companion-mozilla.zip`.

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
