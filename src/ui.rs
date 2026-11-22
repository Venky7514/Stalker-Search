use crate::analyzer::analyze_results;
use crate::cache::QueryCache;
use crate::config::AppConfig;
use crate::dorks::{generate_dorks, ScanTarget};
use crate::engines::build_engine;
use crate::engines::free::{run_direct_osint_sweep, run_second_stage_email_pivot};
use crate::listener::{
    accept_companion_results, bind_companion_listener, get_scan_live_state, mark_scan_finished,
    read_full_http_request, set_scan_live_state, DEFAULT_COMPANION_PORT,
};
use crate::models::{AnalyzedFinding, DorkQuery, RawSearchResult, RiskLevel};
use crate::open_urls_in_active_browser;
use anyhow::{Context, Result};
use console::style;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

pub const DEFAULT_UI_PORT: u16 = 7878;

#[derive(Debug, Deserialize)]
struct UiScanRequest {
    #[serde(default)]
    name: String,
    #[serde(default)]
    aliases: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    phone: String,
    #[serde(default)]
    context: String,
    #[serde(default)]
    strict_context: bool,
    /// `"open_google"`, `"incognito"`, or `"none"`
    #[serde(default)]
    browser_mode: String,
    #[serde(default = "default_pages")]
    pages: usize,
    #[serde(default)]
    deep_verify: bool,
}

fn default_pages() -> usize {
    3
}

#[derive(Debug, Serialize)]
struct UiScanResponse {
    target_label: String,
    engine_name: String,
    raw_hits_count: usize,
    dorks: Vec<DorkQuery>,
    findings: Vec<AnalyzedFinding>,
    summary: UiSummaryStats,
}

#[derive(Debug, Serialize)]
struct UiSummaryStats {
    total: usize,
    high_risk: usize,
    medium_risk: usize,
    low_risk: usize,
    discovered_emails: Vec<String>,
    discovered_phones: Vec<String>,
    public_calendars: Vec<String>,
    profiles: Vec<String>,
}

/// Starts the local web application interface on `http://127.0.0.1:7878` and opens it in the user's browser.
pub async fn run_ui_server(port: u16, auto_open: bool) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to start UI server on http://{}", addr))?;

    let url = format!("http://{}", addr);
    println!();
    println!(
        "{}",
        style("──────────────────────────────────────────────────────────────────────────").dim()
    );
    println!(
        "  {} {}",
        style("●").white().bold(),
        style("Stalker Search — Local Privacy Scanner").white().bold()
    );
    println!(
        "  {} {}",
        style("URL      :").dim(),
        style(&url).white().bold().underlined()
    );
    println!(
        "  {} {}",
        style("Privacy  :").dim(),
        style("127.0.0.1 Loopback Only · Zero Disk History · Zero Telemetry").dim()
    );
    println!(
        "{}",
        style("──────────────────────────────────────────────────────────────────────────").dim()
    );

    if auto_open {
        open_urls_in_active_browser(&[url.clone()], false);
    }

    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };

        tokio::spawn(async move {
            let Some(raw_req) = read_full_http_request(&mut socket).await else {
                return;
            };
            let first_line = raw_req.lines().next().unwrap_or("");

            if first_line.starts_with("OPTIONS ") {
                let resp = "HTTP/1.1 200 OK\r\n\
                            Access-Control-Allow-Origin: *\r\n\
                            Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                            Access-Control-Allow-Headers: Content-Type\r\n\
                            Content-Length: 0\r\n\r\n";
                let _ = socket.write_all(resp.as_bytes()).await;
            } else if first_line.starts_with("GET / ") || first_line.starts_with("GET /index.html")
            {
                let body = INDEX_HTML.as_bytes();
                let headers = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/html; charset=utf-8\r\n\
                     Access-Control-Allow-Origin: *\r\n\
                     Cache-Control: no-store, no-cache, must-revalidate\r\n\
                     X-Content-Type-Options: nosniff\r\n\
                     Content-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(headers.as_bytes()).await;
                let _ = socket.write_all(body).await;
            } else if first_line.starts_with("GET /api/status") {
                let st = get_scan_live_state();
                let json = serde_json::to_string(&st).unwrap_or_else(|_| "{}".into());
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Cache-Control: no-store\r\n\
                     Content-Length: {}\r\n\r\n{}",
                    json.len(),
                    json
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            } else if first_line.starts_with("POST /api/clean") {
                let removed = QueryCache::purge_disk();
                let json = serde_json::json!({
                    "ok": true,
                    "purged_disk_cache": removed,
                    "message": "Local cache cleared."
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Cache-Control: no-store\r\n\
                     Content-Length: {}\r\n\r\n{}",
                    json.len(),
                    json
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            } else if first_line.starts_with("POST /api/scan") {
                let body_str = raw_req
                    .find("\r\n\r\n")
                    .map(|i| &raw_req[i + 4..])
                    .unwrap_or("");

                match serde_json::from_str::<UiScanRequest>(body_str) {
                    Ok(req) => match execute_ui_scan(req).await {
                        Ok(scan_resp) => {
                            let json =
                                serde_json::to_string(&scan_resp).unwrap_or_else(|_| "{}".into());
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Content-Type: application/json\r\n\
                                 Cache-Control: no-store\r\n\
                                 Content-Length: {}\r\n\r\n{}",
                                json.len(),
                                json
                            );
                            let _ = socket.write_all(resp.as_bytes()).await;
                        }
                        Err(e) => {
                            let err_json =
                                serde_json::json!({ "error": e.to_string() }).to_string();
                            let resp = format!(
                                "HTTP/1.1 400 Bad Request\r\n\
                                 Content-Type: application/json\r\n\
                                 Content-Length: {}\r\n\r\n{}",
                                err_json.len(),
                                err_json
                            );
                            let _ = socket.write_all(resp.as_bytes()).await;
                        }
                    },
                    Err(e) => {
                        let err_json =
                            serde_json::json!({ "error": format!("Invalid request JSON: {}", e) })
                                .to_string();
                        let resp = format!(
                            "HTTP/1.1 400 Bad Request\r\n\
                             Content-Type: application/json\r\n\
                             Content-Length: {}\r\n\r\n{}",
                            err_json.len(),
                            err_json
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                    }
                }
            } else {
                let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        });
    }
}

fn split_csv(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn execute_ui_scan(req: UiScanRequest) -> Result<UiScanResponse> {
    let full_name = req.name.trim().to_string();
    let aliases = split_csv(&req.aliases);
    let emails = split_csv(&req.email);
    let phones = split_csv(&req.phone);
    let context_keywords = split_csv(&req.context);

    if full_name.is_empty() && emails.is_empty() && phones.is_empty() {
        anyhow::bail!(
            "Please enter at least one of Name, Email, or Phone Number to start a search."
        );
    }

    let target = ScanTarget {
        full_name,
        aliases,
        usernames: Vec::new(),
        context_keywords,
        emails,
        phones,
        auto_handles: true,
        strict_context: req.strict_context,
    };

    let cfg = AppConfig::load().unwrap_or_default();
    let search_engine = build_engine(cfg.default_engine, &cfg, None)?;
    let dorks = generate_dorks(&target);
    let effective_max = req.pages.clamp(1, 10) * 10;

    let open_google = req.browser_mode == "open_google";
    let incognito = req.browser_mode == "incognito";
    let expected_tabs = if open_google || incognito {
        dorks.len().min(5)
    } else {
        0
    };

    set_scan_live_state(
        true,
        &req.browser_mode,
        expected_tabs,
        if open_google {
            "Opening Google tabs — keep them open until scanning completes..."
        } else if incognito {
            "Opening Incognito tabs — keep them open and check if Google asks to Verify Human..."
        } else {
            "Scanning 18 public datasets in background..."
        },
    );

    let companion_task = if open_google || incognito {
        let listener = bind_companion_listener(DEFAULT_COMPANION_PORT).await?;
        Some(tokio::spawn(async move {
            accept_companion_results(listener, DEFAULT_COMPANION_PORT, expected_tabs, 70)
                .await
                .unwrap_or_default()
        }))
    } else {
        None
    };

    if open_google || incognito {
        let google_urls: Vec<String> = dorks
            .iter()
            .take(5)
            .map(|dork| {
                let encoded: String =
                    url::form_urlencoded::byte_serialize(dork.query.as_bytes()).collect();
                format!("https://www.google.com/search?q={}&udm=14", encoded)
            })
            .collect();

        open_urls_in_active_browser(&google_urls, incognito);
    }

    let mut all_raw_results: Vec<RawSearchResult> = Vec::new();

    // 1. Run 18 Keyless Public APIs concurrently with any browser companion crawling
    let mut osint_hits = run_direct_osint_sweep(&target).await;
    all_raw_results.append(&mut osint_hits);

    // 2. Run web dorks across the configured search engine
    let mut skip_remaining = false;
    for dork in &dorks {
        if skip_remaining {
            break;
        }
        match search_engine.search(dork, effective_max).await {
            Ok(mut hits) => all_raw_results.append(&mut hits),
            Err(err) => {
                if err.to_string().contains("HUMAN_VERIFICATION_REQUIRED") {
                    skip_remaining = true;
                }
            }
        }
    }

    // 3. Collect multi-page Google Search results from the Browser Companion Extension if opened
    if let Some(handle) = companion_task {
        if let Ok(mut companion_hits) = handle.await {
            all_raw_results.append(&mut companion_hits);
        }
    }

    // 4. Stage-2 Email Pivot (Public Google Calendar .ics, Gravatar, OpenPGP)
    let mut stage2_hits = run_second_stage_email_pivot(&all_raw_results, &target).await;
    all_raw_results.append(&mut stage2_hits);

    let raw_hits_count = all_raw_results.len();
    let findings = analyze_results(all_raw_results, &target, req.deep_verify).await;
    mark_scan_finished();

    let high_risk = findings
        .iter()
        .filter(|f| f.risk_level == RiskLevel::High)
        .count();
    let medium_risk = findings
        .iter()
        .filter(|f| f.risk_level == RiskLevel::Medium)
        .count();
    let low_risk = findings
        .iter()
        .filter(|f| f.risk_level == RiskLevel::Low)
        .count();

    let mut discovered_emails = Vec::new();
    let mut discovered_phones = Vec::new();
    let mut public_calendars = Vec::new();
    let mut profiles = Vec::new();

    for f in &findings {
        for leak in &f.pii_leaks {
            match leak {
                crate::models::PiiLeakType::Email(e) => {
                    if !discovered_emails.contains(e) {
                        discovered_emails.push(e.clone());
                    }
                }
                crate::models::PiiLeakType::Phone(p) => {
                    if !discovered_phones.contains(p) {
                        discovered_phones.push(p.clone());
                    }
                }
                _ => {}
            }
        }
        if f.domain.contains("calendar.google.com") && !public_calendars.contains(&f.url) {
            public_calendars.push(f.url.clone());
        }
        if (f.domain.contains("github.com")
            || f.domain.contains("linkedin.com")
            || f.domain.contains("instagram.com")
            || f.domain.contains("reddit.com")
            || f.domain.contains("gravatar.com")
            || f.domain.contains("orcid.org")
            || f.domain.contains("researchgate.net"))
            && profiles.len() < 12
            && !profiles.contains(&f.url)
        {
            profiles.push(f.url.clone());
        }
    }

    Ok(UiScanResponse {
        target_label: target.display_label(),
        engine_name: search_engine.name().to_string(),
        raw_hits_count,
        dorks,
        findings,
        summary: UiSummaryStats {
            total: high_risk + medium_risk + low_risk,
            high_risk,
            medium_risk,
            low_risk,
            discovered_emails,
            discovered_phones,
            public_calendars,
            profiles,
        },
    })
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Stalker Search</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #000000;
      --surface: #050505;
      --surface-elevated: #0a0a0a;
      --border: #1c1c1c;
      --border-strong: #2e2e2e;
      --border-focus: #ffffff;
      --text: #fafafa;
      --text-muted: #737373;
      --danger: #ef4444;
      --danger-bg: #160708;
      --warning: #eab308;
      --warning-bg: #141004;
      --success: #22c55e;
      --success-bg: #05140b;
      --radius: 8px;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      padding: 0;
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    .visually-hidden:where(:not(:focus-within, :active)) {
      position: absolute !important;
      clip-path: inset(50%) !important;
      overflow: hidden !important;
      width: 1px !important;
      height: 1px !important;
      margin: -1px !important;
      padding: 0 !important;
      border: 0 !important;
      white-space: nowrap !important;
    }

    header {
      border-block-end: 1px solid var(--border);
      padding: 1rem 1.5rem;
      background: #000000;
    }

    .header-inner {
      max-width: 980px;
      margin: 0 auto;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.65rem;
    }

    .brand-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: #ffffff;
    }

    .brand h1 {
      font-size: 1rem;
      font-weight: 600;
      letter-spacing: -0.02em;
      margin: 0;
    }

    .brand span {
      color: var(--text-muted);
      font-size: 0.82rem;
      font-weight: 400;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 0.65rem;
    }

    .privacy-pill {
      color: var(--text-muted);
      border: 1px solid var(--border);
      padding: 0.28rem 0.65rem;
      border-radius: 999px;
      font-size: 0.75rem;
    }

    main {
      max-width: 980px;
      margin: 2rem auto;
      padding: 0 1.5rem 4rem;
    }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.5rem;
      margin-block-end: 1.5rem;
    }

    fieldset {
      border: none;
      padding: 0;
      margin: 0 0 1.5rem 0;
    }

    legend {
      font-weight: 600;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-block-end: 0.85rem;
      padding: 0;
    }

    .sub-note {
      font-size: 0.82rem;
      color: var(--text-muted);
      margin-block-start: -0.5rem;
      margin-block-end: 1.15rem;
    }

    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
    }

    .field {
      display: flex;
      flex-direction: column;
      align-items: flex-start;
      gap: 0.25rem;
    }

    label {
      font-weight: 500;
      font-size: 0.85rem;
      color: #e5e5e5;
    }

    .hint {
      display: block;
      color: var(--text-muted);
      font-size: 0.76rem;
    }

    input[type="text"],
    input[type="email"],
    input[type="tel"],
    input[type="search"],
    select {
      width: 100%;
      font: inherit;
      font-size: max(1rem, 14px);
      padding: 0.6rem 0.75rem;
      min-height: 44px;
      background: #000000;
      color: var(--text);
      border: 1px solid var(--border-strong);
      border-radius: 6px;
      transition: border-color 0.15s ease;
    }

    input:hover,
    select:hover {
      border-color: #404040;
    }

    input:focus-visible,
    select:focus-visible,
    button:focus-visible {
      outline: 2px solid var(--border-focus);
      outline-offset: 1px;
    }

    .error-msg {
      display: none;
      color: #f87171;
      font-size: 0.78rem;
      margin-block-start: 0.2rem;
    }

    :is(:user-invalid, .user-invalid-fallback) {
      border-color: var(--danger) !important;
      background-color: var(--danger-bg) !important;
    }

    :is(:user-invalid, .user-invalid-fallback) + .error-msg {
      display: block;
    }

    .identity-alert {
      display: none;
      background: var(--danger-bg);
      border: 1px solid var(--danger);
      color: #fca5a5;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      margin-block-end: 1.25rem;
      font-size: 0.85rem;
    }

    .identity-alert.visible {
      display: block;
    }

    .divider {
      height: 1px;
      background: var(--border);
      margin: 1.5rem 0;
    }

    .radio-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 0.75rem;
    }

    .radio-card {
      display: flex;
      align-items: flex-start;
      gap: 0.65rem;
      background: #000000;
      border: 1px solid var(--border-strong);
      border-radius: 6px;
      padding: 0.85rem 0.95rem;
      cursor: pointer;
      transition: border-color 0.15s ease;
    }

    .radio-card:hover {
      border-color: #525252;
    }

    .radio-card:has(input:checked) {
      border-color: #ffffff;
      background: #0a0a0a;
    }

    .radio-card input[type="radio"] {
      accent-color: #ffffff;
      width: 1rem;
      height: 1rem;
      margin-block-start: 0.18rem;
      flex-shrink: 0;
    }

    .radio-card label {
      cursor: pointer;
      display: block;
    }

    .radio-title {
      display: block;
      font-weight: 600;
      font-size: 0.88rem;
      color: var(--text);
    }

    .radio-sub {
      display: block;
      font-size: 0.76rem;
      color: var(--text-muted);
      font-weight: 400;
      margin-block-start: 0.15rem;
    }

    .options-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      margin-block-start: 1.15rem;
    }

    .checkbox-group {
      display: flex;
      flex-wrap: wrap;
      gap: 1.25rem;
    }

    .checkbox-item {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
    }

    .checkbox-item input[type="checkbox"] {
      accent-color: #ffffff;
      width: 1rem;
      height: 1rem;
    }

    .checkbox-item label {
      font-size: 0.82rem;
      color: #a3a3a3;
      cursor: pointer;
    }

    .submit-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-block-start: 1.5rem;
      padding-block-start: 1.25rem;
      border-block-start: 1px solid var(--border);
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.4rem;
      font: inherit;
      font-weight: 600;
      font-size: 0.88rem;
      min-height: 42px;
      padding: 0.55rem 1.25rem;
      border-radius: 6px;
      border: 1px solid transparent;
      cursor: pointer;
      transition: background-color 0.15s ease, border-color 0.15s ease, opacity 0.15s ease;
    }

    .btn-primary {
      background: #ffffff;
      color: #000000;
    }

    .btn-primary:hover:not(:disabled) {
      background: #e5e5e5;
    }

    .btn-primary:disabled {
      opacity: 0.5;
      cursor: wait;
    }

    .btn-ghost {
      background: transparent;
      color: #a3a3a3;
      border: 1px solid var(--border-strong);
      font-size: 0.8rem;
      min-height: 36px;
      padding: 0.35rem 0.85rem;
    }

    .btn-ghost:hover {
      color: #ffffff;
      border-color: #525252;
    }

    .status-bar {
      display: none;
      align-items: center;
      gap: 0.75rem;
      padding: 0.9rem 1.15rem;
      background: #050505;
      border: 1px solid var(--border-strong);
      border-radius: 6px;
      margin-block-end: 1.5rem;
      color: #d4d4d4;
      font-size: 0.85rem;
    }

    .status-bar.active {
      display: flex;
    }

    .precaution-note {
      background: #000000;
      border: 1px solid var(--border-strong);
      border-inline-start: 3px solid #737373;
      border-radius: 6px;
      padding: 0.7rem 0.95rem;
      margin-block-start: 0.9rem;
      font-size: 0.8rem;
      color: #a3a3a3;
    }

    .precaution-note strong {
      color: #fafafa;
    }

    .verify-alert {
      display: none;
      background: #140f02;
      border: 1.5px solid #f59e0b;
      color: #fde68a;
      padding: 1rem 1.15rem;
      border-radius: 6px;
      margin-block-end: 1.25rem;
      font-size: 0.88rem;
      line-height: 1.5;
    }

    .verify-alert.active {
      display: block;
    }

    .verify-alert strong {
      display: block;
      color: #fbbf24;
      font-size: 0.95rem;
      margin-block-end: 0.25rem;
    }

    .spinner {
      width: 16px;
      height: 16px;
      border: 2px solid #262626;
      border-top-color: #ffffff;
      border-radius: 50%;
      animation: spin 0.75s linear infinite;
      flex-shrink: 0;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 0.75rem;
      margin-block-end: 1.25rem;
    }

    .stat-box {
      background: #000000;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.85rem 1rem;
    }

    .stat-label {
      font-size: 0.74rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .stat-value {
      font-size: 1.5rem;
      font-weight: 700;
      margin-block-start: 0.15rem;
    }

    .footprint-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 0.75rem;
      margin-block-end: 1.25rem;
    }

    .footprint-panel {
      background: #000000;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.85rem 1rem;
    }

    .footprint-panel h3 {
      margin: 0 0 0.45rem 0;
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-muted);
    }

    .tag-list {
      display: flex;
      flex-wrap: wrap;
      gap: 0.35rem;
      margin: 0;
      padding: 0;
      list-style: none;
    }

    .tag {
      background: #0a0a0a;
      border: 1px solid var(--border-strong);
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.76rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      word-break: break-all;
    }

    .table-toolbar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      margin-block-end: 0.85rem;
    }

    .filter-pills {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }

    .pill-btn {
      background: #000000;
      color: var(--text-muted);
      border: 1px solid var(--border-strong);
      padding: 0.3rem 0.75rem;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 500;
      cursor: pointer;
    }

    .pill-btn[aria-pressed="true"] {
      background: #ffffff;
      color: #000000;
      border-color: #ffffff;
    }

    .table-wrap {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: #000000;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.84rem;
    }

    th, td {
      padding: 0.75rem 0.9rem;
      border-block-end: 1px solid var(--border);
      vertical-align: top;
    }

    th {
      background: #050505;
      font-weight: 600;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-muted);
    }

    tr:hover td {
      background: #050505;
    }

    .badge {
      display: inline-block;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      font-weight: 600;
      font-size: 0.7rem;
      letter-spacing: 0.03em;
    }

    .badge-high {
      background: var(--danger-bg);
      color: #f87171;
      border: 1px solid #7f1d1d;
    }

    .badge-medium {
      background: var(--warning-bg);
      color: #facc15;
      border: 1px solid #713f12;
    }

    .badge-low {
      background: var(--success-bg);
      color: #4ade80;
      border: 1px solid #14532d;
    }

    a {
      color: #ffffff;
      text-decoration: underline;
      text-decoration-color: #525252;
      text-underline-offset: 3px;
    }

    a:hover {
      text-decoration-color: #ffffff;
    }

    .snippet-text {
      color: var(--text-muted);
      font-size: 0.78rem;
      margin-block-start: 0.25rem;
      max-width: 500px;
    }

    .remediation-box {
      font-size: 0.78rem;
      color: #a3a3a3;
      max-width: 280px;
    }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div class="brand">
        <span class="brand-dot" aria-hidden="true"></span>
        <h1>Stalker Search</h1>
        <span>Open-Source Digital Footprint Scanner</span>
      </div>
      <div class="header-actions">
        <span class="privacy-pill">127.0.0.1 Local &bull; Zero Cookies or Logs</span>
        <button type="button" id="purge-btn" class="btn btn-ghost">
          Clear Cache
        </button>
      </div>
    </div>
  </header>

  <main>
    <section class="card" aria-labelledby="search-heading">
      <h2 id="search-heading" class="visually-hidden">Search Parameters</h2>
      <search>
        <form id="scan-form" action="/api/scan" method="POST" novalidate>
          <div id="identity-required-error" class="identity-alert" role="alert">
            Please enter at least one of Name, Email, or Phone Number to search.
          </div>

          <fieldset>
            <legend>Identity &amp; Context</legend>
            <p class="sub-note">Enter at least one of <strong>Name</strong>, <strong>Email</strong>, or <strong>Phone Number</strong>. Add <strong>Context</strong> to narrow common names.</p>

            <div class="form-grid">
              <div class="field">
                <label for="full-name">Name</label>
                <span id="name-hint" class="hint">Checks "First Last" &amp; "Last First"</span>
                <input
                  type="text"
                  id="full-name"
                  name="name"
                  autocomplete="off"
                  autocorrect="off"
                  spellcheck="false"
                  enterkeyhint="next"
                  aria-describedby="name-hint"
                >
              </div>

              <div class="field">
                <label for="email">Email</label>
                <span id="email-hint" class="hint">Format: name@example.com</span>
                <input
                  type="email"
                  id="email"
                  name="email"
                  autocomplete="off"
                  autocorrect="off"
                  autocapitalize="none"
                  spellcheck="false"
                  enterkeyhint="next"
                  aria-describedby="email-hint"
                  data-error="email-error"
                >
                <div id="email-error" class="error-msg">
                  <span role="img" aria-label="Error">Error:</span> Enter a valid email address.
                </div>
              </div>

              <div class="field">
                <label for="phone">Phone Number</label>
                <span id="phone-hint" class="hint">Digits or international format</span>
                <input
                  type="tel"
                  id="phone"
                  name="phone"
                  autocomplete="off"
                  autocorrect="off"
                  spellcheck="false"
                  enterkeyhint="next"
                  aria-describedby="phone-hint"
                >
              </div>

              <div class="field">
                <label for="context">Context</label>
                <span id="context-hint" class="hint">College, city, or company (comma-separated)</span>
                <input
                  type="text"
                  id="context"
                  name="context"
                  autocomplete="off"
                  autocorrect="off"
                  spellcheck="false"
                  enterkeyhint="done"
                  aria-describedby="context-hint"
                >
              </div>
            </div>
          </fieldset>

          <div class="divider"></div>

          <fieldset>
            <legend>Search Mode</legend>
            <div class="radio-grid">
              <div class="radio-card">
                <input type="radio" id="mode-open-google" name="browser_mode" value="open_google" checked>
                <label for="mode-open-google">
                  <span class="radio-title">Open Google Search (Faster)</span>
                  <span class="radio-sub">Uses your active browser window to avoid CAPTCHAs and scans all Google result pages.</span>
                </label>
              </div>

              <div class="radio-card">
                <input type="radio" id="mode-incognito" name="browser_mode" value="incognito">
                <label for="mode-incognito">
                  <span class="radio-title">Incognito Search (Private)</span>
                  <span class="radio-sub">Launches Google searches in a Private / Incognito browser window with zero local history.</span>
                </label>
              </div>

              <div class="radio-card">
                <input type="radio" id="mode-background" name="browser_mode" value="none">
                <label for="mode-background">
                  <span class="radio-title">Background APIs Only</span>
                  <span class="radio-sub">Silently queries 18 public datasets (GitHub, News, Academic, Calendar, Gravatar) without opening tabs.</span>
                </label>
              </div>
            </div>

            <div id="precaution-note" class="precaution-note">
              <strong>Precaution:</strong> Do not close the opened Google Search browser tabs until scanning finishes. Once complete, searched query URLs are automatically removed from browser history.
            </div>

            <div class="options-bar">
              <div class="checkbox-group">
                <div class="checkbox-item">
                  <input type="checkbox" id="strict-context" name="strict_context">
                  <label for="strict-context">Strict Context Match Only</label>
                </div>

                <div class="checkbox-item">
                  <input type="checkbox" id="deep-verify" name="deep_verify">
                  <label for="deep-verify">Deep-Verify Links for Leaks</label>
                </div>
              </div>

              <div style="display:flex;align-items:center;gap:0.5rem;">
                <label for="pages" style="font-size:0.8rem;color:var(--text-muted);">Pages:</label>
                <select id="pages" name="pages" style="width:auto;min-height:34px;padding:0.25rem 0.6rem;font-size:0.8rem;">
                  <option value="3">3 Pages</option>
                  <option value="5">5 Pages</option>
                  <option value="10" selected>All Pages (Up to 10)</option>
                </select>
              </div>
            </div>
          </fieldset>

          <div class="submit-row">
            <button type="reset" id="reset-btn" class="btn btn-ghost">
              Reset
            </button>
            <button type="submit" id="submit-btn" class="btn btn-primary">
              Search Footprint
            </button>
          </div>
        </form>
      </search>
    </section>

    <div id="verify-alert" class="verify-alert" role="alert">
      <strong id="verify-alert-title">Human Verification Needed in Incognito Window</strong>
      <span id="verify-alert-body">Please check your Private / Incognito browser tabs and complete Google's "Verify you are human" check. Do NOT close those tabs until complete.</span>
    </div>

    <div id="status-bar" class="status-bar" role="status" aria-live="polite">
      <div class="spinner" aria-hidden="true"></div>
      <span id="status-text">Scanning public datasets and syncing multi-page Google results...</span>
    </div>

    <section id="results-section" class="card" hidden aria-labelledby="results-heading">
      <div class="table-toolbar">
        <div>
          <h2 id="results-heading" style="margin:0;font-size:1rem;font-weight:600;">Results</h2>
          <p id="results-subtitle" style="margin:0.15rem 0 0;font-size:0.78rem;color:var(--text-muted);"></p>
        </div>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
          <button type="button" id="export-md-btn" class="btn btn-ghost">Export Markdown</button>
          <button type="button" id="export-json-btn" class="btn btn-ghost">Export JSON</button>
        </div>
      </div>

      <div class="stats-grid">
        <div class="stat-box">
          <div class="stat-label">Total References</div>
          <div class="stat-value" id="stat-total">0</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">High Risk</div>
          <div class="stat-value" id="stat-high" style="color:#f87171;">0</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Medium Risk</div>
          <div class="stat-value" id="stat-medium" style="color:#facc15;">0</div>
        </div>
        <div class="stat-box">
          <div class="stat-label">Low Risk</div>
          <div class="stat-value" id="stat-low" style="color:#4ade80;">0</div>
        </div>
      </div>

      <div class="footprint-grid">
        <div class="footprint-panel">
          <h3>Emails</h3>
          <ul id="fp-emails" class="tag-list"></ul>
        </div>
        <div class="footprint-panel">
          <h3>Phone Numbers</h3>
          <ul id="fp-phones" class="tag-list"></ul>
        </div>
        <div class="footprint-panel">
          <h3>Google Calendar (.ics)</h3>
          <ul id="fp-calendars" class="tag-list"></ul>
        </div>
        <div class="footprint-panel">
          <h3>Profiles</h3>
          <ul id="fp-profiles" class="tag-list"></ul>
        </div>
      </div>

      <div class="table-toolbar">
        <div class="filter-pills" role="group" aria-label="Filter findings by risk">
          <button type="button" class="pill-btn" data-filter="ALL" aria-pressed="true">All</button>
          <button type="button" class="pill-btn" data-filter="High" aria-pressed="false">High Risk</button>
          <button type="button" class="pill-btn" data-filter="Medium" aria-pressed="false">Medium Risk</button>
          <button type="button" class="pill-btn" data-filter="Low" aria-pressed="false">Low Risk</button>
        </div>
        <div style="min-width:220px;">
          <label for="table-filter-input" class="visually-hidden">Filter findings</label>
          <input
            type="search"
            id="table-filter-input"
            placeholder="Filter results..."
            autocomplete="off"
            autocorrect="off"
            spellcheck="false"
            style="min-height:34px;padding:0.3rem 0.65rem;font-size:0.8rem;"
          >
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Risk</th>
              <th>Conf</th>
              <th>Category</th>
              <th>Reference</th>
              <th>Signals</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody id="findings-tbody"></tbody>
        </table>
      </div>
    </section>
  </main>

  <script>
    (function () {
      const form = document.getElementById('scan-form');
      const nameInput = document.getElementById('full-name');
      const emailInput = document.getElementById('email');
      const phoneInput = document.getElementById('phone');
      const contextInput = document.getElementById('context');
      const pagesSelect = document.getElementById('pages');
      const strictContextInput = document.getElementById('strict-context');
      const deepVerifyInput = document.getElementById('deep-verify');
      const identityAlert = document.getElementById('identity-required-error');
      const submitBtn = document.getElementById('submit-btn');
      const purgeBtn = document.getElementById('purge-btn');
      const statusBar = document.getElementById('status-bar');
      const statusText = document.getElementById('status-text');
      const verifyAlert = document.getElementById('verify-alert');
      const verifyAlertTitle = document.getElementById('verify-alert-title');
      const verifyAlertBody = document.getElementById('verify-alert-body');
      const precautionNote = document.getElementById('precaution-note');
      const resultsSection = document.getElementById('results-section');
      const findingsTbody = document.getElementById('findings-tbody');
      const filterInput = document.getElementById('table-filter-input');

      let currentReportData = null;
      let activeRiskFilter = 'ALL';
      let isScanningNow = false;

      function updatePrecautionText() {
        const mode = document.querySelector('input[name="browser_mode"]:checked')?.value || 'open_google';
        if (mode === 'open_google') {
          precautionNote.hidden = false;
          precautionNote.innerHTML = '';
          const b = document.createElement('strong');
          b.textContent = 'Precaution: ';
          precautionNote.appendChild(b);
          precautionNote.appendChild(
            document.createTextNode(
              'Do NOT close the opened Google Search tabs until scanning finishes. Once synced, searched query URLs are automatically removed from browser history.'
            )
          );
        } else if (mode === 'incognito') {
          precautionNote.hidden = false;
          precautionNote.innerHTML = '';
          const b = document.createElement('strong');
          b.textContent = 'Incognito Precaution: ';
          precautionNote.appendChild(b);
          precautionNote.appendChild(
            document.createTextNode(
              'Keep the Private / Incognito tabs open until scanning completes. If Google shows "Verify you are human", complete it in the Incognito tab. (Also make sure "Run in Private Windows: Allow" is enabled for Stalker Search Companion in about:addons.)'
            )
          );
        } else {
          precautionNote.hidden = true;
        }
      }

      document.querySelectorAll('input[name="browser_mode"]').forEach((r) => {
        r.addEventListener('change', updatePrecautionText);
      });
      updatePrecautionText();

      window.addEventListener('beforeunload', (e) => {
        if (!isScanningNow) return;
        e.preventDefault();
        e.returnValue = 'Scan in progress. Do not close until finished.';
      });

      const linkError = (el, shown) => {
        const errorId = el.dataset.error;
        if (!errorId) return;
        const ids = (el.getAttribute('aria-describedby') || '').split(/\s+/).filter((id) => id && id !== errorId);
        if (shown) ids.push(errorId);
        if (ids.length) el.setAttribute('aria-describedby', ids.join(' '));
        else el.removeAttribute('aria-describedby');
      };

      const announcer = document.createElement('div');
      announcer.setAttribute('aria-live', 'polite');
      announcer.classList.add('visually-hidden');
      document.body.append(announcer);

      const flagged = new WeakSet();
      const syncAria = (el) => {
        if (!el.matches || !el.matches('input, select, textarea')) return;
        const invalid = el.matches(':user-invalid') || el.classList.contains('user-invalid-fallback');
        if (invalid) {
          el.setAttribute('aria-invalid', 'true');
          linkError(el, true);
          flagged.add(el);
        } else if (flagged.has(el) || el.getAttribute('aria-invalid') !== 'true') {
          el.setAttribute('aria-invalid', 'false');
          linkError(el, false);
          flagged.delete(el);
        }
      };

      document.querySelectorAll('input, select, textarea').forEach((el) => syncAria(el));
      document.addEventListener('blur', (e) => syncAria(e.target), true);

      function hasAtLeastOneIdentifier() {
        return (
          nameInput.value.trim().length > 0 ||
          emailInput.value.trim().length > 0 ||
          phoneInput.value.trim().length > 0
        );
      }

      [nameInput, emailInput, phoneInput].forEach((input) => {
        input.addEventListener('input', () => {
          if (hasAtLeastOneIdentifier()) {
            identityAlert.classList.remove('visible');
            [nameInput, emailInput, phoneInput].forEach((el) => {
              el.classList.remove('user-invalid-fallback');
              el.setAttribute('aria-invalid', 'false');
            });
          }
          syncAria(input);
        });
      });

      form.addEventListener('reset', () => {
        identityAlert.classList.remove('visible');
        setTimeout(() => {
          document.querySelectorAll('input, select, textarea').forEach((el) => {
            el.classList.remove('user-invalid-fallback');
            syncAria(el);
          });
        });
      });

      purgeBtn.addEventListener('click', async () => {
        try {
          const resp = await fetch('/api/clean', { method: 'POST' });
          const data = await resp.json();
          form.reset();
          resultsSection.hidden = true;
          currentReportData = null;
          announcer.textContent = data.message || 'Cache cleared.';
          purgeBtn.textContent = 'Cleared';
          setTimeout(() => {
            purgeBtn.textContent = 'Clear Cache';
          }, 2000);
        } catch (_) {}
      });

      form.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!hasAtLeastOneIdentifier()) {
          identityAlert.classList.add('visible');
          nameInput.classList.add('user-invalid-fallback');
          nameInput.setAttribute('aria-invalid', 'true');
          nameInput.focus();
          return;
        }

        if (emailInput.value.trim().length > 0 && !emailInput.validity.valid) {
          emailInput.classList.add('user-invalid-fallback');
          syncAria(emailInput);
          emailInput.focus();
          return;
        }

        identityAlert.classList.remove('visible');
        verifyAlert.classList.remove('active');
        const browserMode =
          document.querySelector('input[name="browser_mode"]:checked')?.value || 'open_google';

        isScanningNow = true;
        submitBtn.disabled = true;
        statusBar.classList.add('active');
        if (browserMode === 'open_google') {
          statusText.textContent =
            'Opening Google Search tabs (Faster) — do NOT close opened tabs until sync finishes...';
        } else if (browserMode === 'incognito') {
          statusText.textContent =
            'Opening Incognito Google Search tabs (Private) — do NOT close tabs; watch for any Verify Human check...';
        } else {
          statusText.textContent =
            'Scanning 18 public datasets in background...';
        }

        const scanStartedAt = Date.now();
        let statusPoller = null;
        if (browserMode === 'open_google' || browserMode === 'incognito') {
          statusPoller = setInterval(async () => {
            try {
              const sResp = await fetch('/api/status');
              if (!sResp.ok) return;
              const st = await sResp.json();
              if (st.status_message) {
                statusText.textContent = st.status_message;
              }
              if (st.human_verify_needed) {
                verifyAlertTitle.textContent = 'Action Needed: Verify Human in Browser Tab';
                verifyAlertBody.textContent =
                  st.status_message ||
                  'Google asked to verify you are human in an opened browser tab. Complete the verification directly inside that tab (keep tabs open) — results will sync automatically once unlocked.';
                verifyAlert.classList.add('active');
              } else if (
                browserMode === 'incognito' &&
                st.tabs_pinged === 0 &&
                Date.now() - scanStartedAt > 4500
              ) {
                verifyAlertTitle.textContent =
                  'Check Your Private / Incognito Window (Verify Human or Private Permission)';
                verifyAlertBody.textContent =
                  'No Incognito tab has synced yet. Switch to your Private/Incognito window: if Google is asking "Verify you are human", complete it in the Incognito tabs and keep them open. Also verify "Run in Private Windows: Allow" is enabled for Stalker Search Companion in about:addons.';
                verifyAlert.classList.add('active');
              }
            } catch (_) {}
          }, 650);
        }

        try {
          const payload = {
            name: nameInput.value.trim(),
            aliases: '',
            email: emailInput.value.trim(),
            phone: phoneInput.value.trim(),
            context: contextInput.value.trim(),
            strict_context: strictContextInput.checked,
            browser_mode: browserMode,
            pages: parseInt(pagesSelect.value, 10) || 10,
            deep_verify: deepVerifyInput.checked,
          };

          const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          const data = await resp.json();

          if (!resp.ok || data.error) {
            identityAlert.textContent = data.error || 'Scan failed.';
            identityAlert.classList.add('visible');
            return;
          }

          currentReportData = data;
          renderReport(data);
        } catch (_) {
          identityAlert.textContent = 'Could not reach local scan server.';
          identityAlert.classList.add('visible');
        } finally {
          isScanningNow = false;
          if (statusPoller) clearInterval(statusPoller);
          verifyAlert.classList.remove('active');
          submitBtn.disabled = false;
          statusBar.classList.remove('active');
        }
      });

      function createTagList(containerId, items, emptyLabel) {
        const ul = document.getElementById(containerId);
        ul.textContent = '';
        if (!items || items.length === 0) {
          const li = document.createElement('li');
          li.className = 'tag';
          li.style.color = 'var(--text-muted)';
          li.textContent = emptyLabel;
          ul.appendChild(li);
          return;
        }
        items.forEach((item) => {
          const li = document.createElement('li');
          li.className = 'tag';
          if (item.startsWith('http://') || item.startsWith('https://')) {
            const a = document.createElement('a');
            a.href = item;
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            a.textContent = item.replace(/^https?:\/\/(www\.)?/, '');
            li.appendChild(a);
          } else {
            li.textContent = item;
          }
          ul.appendChild(li);
        });
      }

      function formatLeakSignal(leak) {
        if (typeof leak === 'string') return leak;
        if (leak.Email) return `Email: ${leak.Email}`;
        if (leak.Phone) return `Phone: ${leak.Phone}`;
        if (leak.DocumentFile) return `File: ${leak.DocumentFile}`;
        if (leak.SensitiveKeyword) return `Keyword: ${leak.SensitiveKeyword}`;
        return JSON.stringify(leak);
      }

      function renderReport(data) {
        resultsSection.hidden = false;
        document.getElementById('results-subtitle').textContent =
          `${data.target_label} · ${data.raw_hits_count} raw hits analyzed`;

        document.getElementById('stat-total').textContent = data.summary.total;
        document.getElementById('stat-high').textContent = data.summary.high_risk;
        document.getElementById('stat-medium').textContent = data.summary.medium_risk;
        document.getElementById('stat-low').textContent = data.summary.low_risk;

        createTagList('fp-emails', data.summary.discovered_emails, 'None');
        createTagList('fp-phones', data.summary.discovered_phones, 'None');
        createTagList('fp-calendars', data.summary.public_calendars, 'Not exposed');
        createTagList('fp-profiles', data.summary.profiles, 'None');

        renderTableRows();
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }

      function renderTableRows() {
        findingsTbody.textContent = '';
        if (!currentReportData || !currentReportData.findings) return;

        const queryFilter = filterInput.value.trim().toLowerCase();
        const filtered = currentReportData.findings.filter((f) => {
          if (activeRiskFilter !== 'ALL' && f.risk_level !== activeRiskFilter) {
            return false;
          }
          if (!queryFilter) return true;
          const hay = `${f.title} ${f.url} ${f.snippet} ${f.domain}`.toLowerCase();
          return hay.includes(queryFilter);
        });

        if (filtered.length === 0) {
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 6;
          td.style.textAlign = 'center';
          td.style.color = 'var(--text-muted)';
          td.style.padding = '2rem';
          td.textContent = 'No matching public exposures found.';
          tr.appendChild(td);
          findingsTbody.appendChild(tr);
          return;
        }

        filtered.forEach((f) => {
          const tr = document.createElement('tr');

          const tdRisk = document.createElement('td');
          const badge = document.createElement('span');
          const riskUpper = String(f.risk_level).toUpperCase();
          badge.className =
            riskUpper === 'HIGH'
              ? 'badge badge-high'
              : riskUpper === 'MEDIUM'
              ? 'badge badge-medium'
              : 'badge badge-low';
          badge.textContent = riskUpper;
          tdRisk.appendChild(badge);
          tr.appendChild(tdRisk);

          const tdConf = document.createElement('td');
          tdConf.style.fontWeight = '600';
          tdConf.textContent = `${Math.round(f.confidence * 100)}%`;
          tr.appendChild(tdConf);

          const tdCat = document.createElement('td');
          tdCat.style.color = 'var(--text-muted)';
          tdCat.textContent = (f.categories || []).join(', ');
          tr.appendChild(tdCat);

          const tdRef = document.createElement('td');
          const titleLink = document.createElement('a');
          titleLink.href = f.url;
          titleLink.target = '_blank';
          titleLink.rel = 'noopener noreferrer';
          titleLink.style.fontWeight = '600';
          titleLink.textContent = f.title || f.url;
          tdRef.appendChild(titleLink);

          const urlDiv = document.createElement('div');
          urlDiv.style.fontSize = '0.74rem';
          urlDiv.style.color = '#737373';
          urlDiv.style.wordBreak = 'break-all';
          urlDiv.textContent = f.url;
          tdRef.appendChild(urlDiv);

          if (f.snippet) {
            const snipDiv = document.createElement('div');
            snipDiv.className = 'snippet-text';
            snipDiv.textContent = f.snippet;
            tdRef.appendChild(snipDiv);
          }
          tr.appendChild(tdRef);

          const tdSignals = document.createElement('td');
          const signals = [];
          (f.pii_leaks || []).forEach((l) => signals.push(formatLeakSignal(l)));
          (f.matched_context || []).forEach((c) => signals.push(`Context: ${c}`));
          if (f.page_verified) signals.push('Verified');
          tdSignals.textContent = signals.length ? signals.join(' · ') : 'Name Match';
          tr.appendChild(tdSignals);

          const tdRem = document.createElement('td');
          tdRem.className = 'remediation-box';
          const advDiv = document.createElement('div');
          advDiv.textContent = f.remediation_advice || '';
          tdRem.appendChild(advDiv);

          if (f.remediation_url) {
            const remLink = document.createElement('a');
            remLink.href = f.remediation_url;
            remLink.target = '_blank';
            remLink.rel = 'noopener noreferrer';
            remLink.style.display = 'inline-block';
            remLink.style.marginTop = '0.3rem';
            remLink.style.fontWeight = '500';
            remLink.textContent = 'Opt-Out / Settings →';
            tdRem.appendChild(remLink);
          }
          tr.appendChild(tdRem);

          findingsTbody.appendChild(tr);
        });
      }

      document.querySelectorAll('.pill-btn').forEach((btn) => {
        btn.addEventListener('click', () => {
          document.querySelectorAll('.pill-btn').forEach((b) => b.setAttribute('aria-pressed', 'false'));
          btn.setAttribute('aria-pressed', 'true');
          activeRiskFilter = btn.dataset.filter;
          renderTableRows();
        });
      });

      filterInput.addEventListener('input', () => renderTableRows());

      document.getElementById('export-json-btn').addEventListener('click', () => {
        if (!currentReportData) return;
        const blob = new Blob([JSON.stringify(currentReportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'footprint-report.json';
        a.click();
        URL.revokeObjectURL(url);
      });

      document.getElementById('export-md-btn').addEventListener('click', () => {
        if (!currentReportData) return;
        const d = currentReportData;
        const lines = [
          `# Digital Footprint Privacy Report`,
          `- **Target**: ${d.target_label}`,
          `- **Total Unique References**: ${d.summary.total} (High: ${d.summary.high_risk}, Medium: ${d.summary.medium_risk}, Low: ${d.summary.low_risk})`,
          ``,
          `## Findings`,
          ``,
        ];
        (d.findings || []).forEach((f, idx) => {
          lines.push(`### ${idx + 1}. [${String(f.risk_level).toUpperCase()}] ${f.title}`);
          lines.push(`- **URL**: ${f.url}`);
          lines.push(`- **Confidence**: ${Math.round(f.confidence * 100)}%`);
          if (f.snippet) lines.push(`- **Snippet**: ${f.snippet}`);
          if (f.remediation_advice) lines.push(`- **Remediation**: ${f.remediation_advice}`);
          if (f.remediation_url) lines.push(`- **Opt-Out Link**: ${f.remediation_url}`);
          lines.push(``);
        });
        const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'footprint-report.md';
        a.click();
        URL.revokeObjectURL(url);
      });
    })();
  </script>
</body>
</html>
"#;
