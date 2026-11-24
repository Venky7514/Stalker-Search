use crate::engines::free::infer_category;
use crate::models::{DorkCategory, RawSearchResult};
use anyhow::{Context, Result};
use console::style;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const DEFAULT_COMPANION_PORT: u16 = 60067;

#[derive(Debug, Clone, Serialize, Default)]
pub struct CompanionLiveState {
    pub active: bool,
    pub browser_mode: String,
    pub expected_tabs: usize,
    pub tabs_pinged: usize,
    pub tabs_completed: usize,
    pub results_count: usize,
    pub human_verify_needed: bool,
    pub status_message: String,
    pub companion_connected: bool,
    pub incognito_allowed: Option<bool>,
}

static LIVE_STATE: Lazy<Mutex<CompanionLiveState>> =
    Lazy::new(|| Mutex::new(CompanionLiveState::default()));

pub fn update_companion_heartbeat(incognito_allowed: bool) {
    if let Ok(mut st) = LIVE_STATE.lock() {
        st.companion_connected = true;
        st.incognito_allowed = Some(incognito_allowed);
    }
}

pub fn set_scan_live_state(active: bool, browser_mode: &str, expected_tabs: usize, message: &str) {
    if let Ok(mut st) = LIVE_STATE.lock() {
        let prev_connected = st.companion_connected;
        let prev_incognito = st.incognito_allowed;
        *st = CompanionLiveState {
            active,
            browser_mode: browser_mode.to_string(),
            expected_tabs,
            tabs_pinged: 0,
            tabs_completed: 0,
            results_count: 0,
            human_verify_needed: false,
            status_message: message.to_string(),
            companion_connected: prev_connected,
            incognito_allowed: prev_incognito,
        };
    }
}

pub fn mark_scan_finished() {
    if let Ok(mut st) = LIVE_STATE.lock() {
        st.active = false;
    }
}

pub fn get_scan_live_state() -> CompanionLiveState {
    LIVE_STATE
        .lock()
        .map(|s| s.clone())
        .unwrap_or_default()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct CompanionFeedPayload {
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    results: Vec<CompanionHit>,
    #[serde(default = "default_true")]
    done: bool,
    #[serde(default)]
    diag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CompanionStatusPayload {
    #[serde(default)]
    status: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    page: usize,
    #[serde(default)]
    hits: usize,
}

#[derive(Debug, Deserialize)]
struct CompanionHit {
    title: String,
    url: String,
    #[serde(default)]
    snippet: String,
}

/// Reads a complete HTTP/1.1 request (headers + full `Content-Length` body) from a TCP stream.
pub async fn read_full_http_request(socket: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 8192];

    loop {
        let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut chunk)).await
        else {
            break;
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);

        if let Some(hdr_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let body_start = hdr_end + 4;
            let headers_str = String::from_utf8_lossy(&buf[..hdr_end]);
            let content_len = headers_str
                .lines()
                .find_map(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower
                        .strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);

            if buf.len() >= body_start + content_len {
                break;
            }
        }
        if buf.len() > 4 * 1024 * 1024 {
            break;
        }
    }

    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buf).into_owned())
    }
}

/// Binds the localhost HTTP bridge synchronously so tabs never race against listener startup.
pub async fn bind_companion_listener(port: u16) -> Result<TcpListener> {
    let addr = format!("127.0.0.1:{}", port);
    TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind Companion Listener on http://{}", addr))
}

/// Starts a localhost HTTP bridge on `127.0.0.1:60067` that receives
/// live Google Search results and status heartbeats from the user's open browser tabs
/// via the Stalker Search Companion extension.
pub async fn listen_for_companion_results(
    port: u16,
    expected_batches: usize,
    timeout_secs: u64,
) -> Result<Vec<RawSearchResult>> {
    let listener = bind_companion_listener(port).await?;
    accept_companion_results(listener, port, expected_batches, timeout_secs).await
}

/// Runs the accept loop on an already-bound `TcpListener`.
pub async fn accept_companion_results(
    listener: TcpListener,
    port: u16,
    expected_batches: usize,
    timeout_secs: u64,
) -> Result<Vec<RawSearchResult>> {
    println!(
        "\n{} Companion Bridge listening on {} (timeout: {}s)...",
        style("[*]").cyan().bold(),
        style(format!("http://127.0.0.1:{}", port)).green().underlined(),
        timeout_secs
    );

    let mut collected = Vec::new();
    let mut batches_received = 0usize;
    let mut hard_deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut idle_deadline = tokio::time::Instant::now() + Duration::from_secs(20);

    loop {
        let active_deadline = hard_deadline.min(idle_deadline);
        let remaining = active_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let accept_res = tokio::time::timeout(remaining, listener.accept()).await;
        let Ok(Ok((mut socket, _))) = accept_res else {
            break;
        };

        let Some(raw_req) = read_full_http_request(&mut socket).await else {
            continue;
        };
        let first_line = raw_req.lines().next().unwrap_or("");

        // Handle CORS Preflight (`OPTIONS`)
        if first_line.starts_with("OPTIONS ") {
            let resp = "HTTP/1.1 200 OK\r\n\
                        Access-Control-Allow-Origin: *\r\n\
                        Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                        Access-Control-Allow-Headers: Content-Type\r\n\
                        Access-Control-Allow-Private-Network: true\r\n\
                        Content-Length: 0\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
            continue;
        }

        // Handle Health Ping (`GET /stalker_ping`)
        if first_line.starts_with("GET /stalker_ping") {
            if let Ok(mut st) = LIVE_STATE.lock() {
                st.tabs_pinged += 1;
            }
            idle_deadline = idle_deadline.max(tokio::time::Instant::now() + Duration::from_secs(20));
            let body = "stalker_pong";
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Access-Control-Allow-Origin: *\r\n\
                 Access-Control-Allow-Private-Network: true\r\n\
                 Content-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            continue;
        }

        // Handle Live Crawling / Human Verification Heartbeat (`POST /stalker_status`)
        if first_line.starts_with("POST /stalker_status") {
            if let Some(body_idx) = raw_req.find("\r\n\r\n") {
                let json_body = &raw_req[body_idx + 4..];
                if let Ok(payload) = serde_json::from_str::<CompanionStatusPayload>(json_body) {
                    if payload.status == "human_verify_needed" {
                        // Extend wait window up to 90s so the user has time to verify human in the browser tab
                        hard_deadline = hard_deadline.max(
                            tokio::time::Instant::now() + Duration::from_secs(90),
                        );
                        idle_deadline = idle_deadline.max(
                            tokio::time::Instant::now() + Duration::from_secs(60),
                        );
                        if let Ok(mut st) = LIVE_STATE.lock() {
                            st.human_verify_needed = true;
                            st.status_message = if payload.message.is_empty() {
                                "Google requires Human Verification in your opened browser tab."
                                    .to_string()
                            } else {
                                payload.message
                            };
                        }
                    } else {
                        idle_deadline = idle_deadline.max(
                            tokio::time::Instant::now() + Duration::from_secs(18),
                        );
                        if let Ok(mut st) = LIVE_STATE.lock() {
                            st.human_verify_needed = false;
                            st.status_message = if !payload.message.is_empty() {
                                payload.message
                            } else {
                                format!(
                                    "Scanning Google Page {} ({} results so far)...",
                                    payload.page.max(1),
                                    payload.hits
                                )
                            };
                        }
                    }
                }
            }

            let ok_body = "stalker_status_ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Access-Control-Allow-Origin: *\r\n\
                 Access-Control-Allow-Private-Network: true\r\n\
                 Content-Length: {}\r\n\r\n{}",
                ok_body.len(),
                ok_body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            continue;
        }

        // Handle Results Feed (`POST /stalker_feed`)
        if first_line.starts_with("POST /stalker_feed") {
            if let Some(body_idx) = raw_req.find("\r\n\r\n") {
                let json_body = &raw_req[body_idx + 4..];
                if let Ok(payload) = serde_json::from_str::<CompanionFeedPayload>(json_body) {
                    let q_label = payload
                        .query
                        .unwrap_or_else(|| "Browser Companion Sync".to_string());
                    let count = payload.results.len();
                    for hit in payload.results {
                        if !hit.url.starts_with("http://") && !hit.url.starts_with("https://") {
                            continue;
                        }
                        if hit.url.contains("google.com/") && !hit.url.contains("/goto?") {
                            continue;
                        }
                        let url_and_cite = format!("{} {}", hit.url, hit.snippet);
                        let cat = infer_category(
                            &url_and_cite,
                            &hit.title,
                            DorkCategory::GeneralMentions,
                        );
                        collected.push(RawSearchResult {
                            title: hit.title,
                            url: hit.url,
                            snippet: hit.snippet.replace('\n', " "),
                            category: cat,
                            dork_used: format!("Companion Browser Sync ({})", q_label),
                            engine: "Browser Companion Bridge".to_string(),
                        });
                    }
                    if payload.done {
                        batches_received += 1;
                        idle_deadline = idle_deadline.max(
                            tokio::time::Instant::now() + Duration::from_secs(14),
                        );
                    } else {
                        // Tab is navigating to the next Google page in real browser context
                        idle_deadline = idle_deadline.max(
                            tokio::time::Instant::now() + Duration::from_secs(20),
                        );
                        hard_deadline = hard_deadline.max(
                            tokio::time::Instant::now() + Duration::from_secs(35),
                        );
                    }
                    if let Ok(mut st) = LIVE_STATE.lock() {
                        st.tabs_completed = batches_received;
                        st.results_count += count;
                        st.status_message = format!(
                            "Synced {}/{} Google tabs ({} results collected) — keep tabs open until finished.",
                            batches_received, expected_batches, st.results_count
                        );
                    }
                    let diag_suffix = match (&payload.diag, count) {
                        (Some(d), 0) if !d.is_empty() => format!(" [{}]", d),
                        _ => String::new(),
                    };
                    println!(
                        "{} Companion Bridge received {} Google results from browser tab ({}/{}{})!{}",
                        style("[+]").green().bold(),
                        style(count).bold(),
                        batches_received,
                        expected_batches,
                        if payload.done { "" } else { ", loading next page" },
                        diag_suffix
                    );
                }
            }

            let ok_body = "stalker_received_ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Access-Control-Allow-Origin: *\r\n\
                 Access-Control-Allow-Private-Network: true\r\n\
                 Content-Length: {}\r\n\r\n{}",
                ok_body.len(),
                ok_body
            );
            let _ = socket.write_all(resp.as_bytes()).await;

            if batches_received >= expected_batches {
                break;
            }
        }
    }

    Ok(collected)
}
