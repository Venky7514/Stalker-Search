mod analyzer;
mod cache;
mod config;
mod dorks;
mod engines;
mod listener;
mod models;
mod report;
mod ui;

use crate::analyzer::analyze_results;
use crate::cache::QueryCache;
use crate::config::AppConfig;
use crate::dorks::{generate_dorks, ScanTarget};
use crate::engines::build_engine;
use crate::engines::free::{
    import_browser_saved_html, run_direct_osint_sweep, run_second_stage_email_pivot,
};
use crate::listener::{listen_for_companion_results, DEFAULT_COMPANION_PORT};
use crate::models::{EngineKind, RawSearchResult};
use crate::report::{export_report, print_terminal_report};
use crate::ui::{run_ui_server, DEFAULT_UI_PORT};
use anyhow::Result;
use clap::{Parser, Subcommand};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "stalker-search",
    version,
    about = "Open-source, local-first digital footprint & self-OSINT privacy scanner (Web UI + CLI)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch the graphical Web Application Interface on 127.0.0.1:7878 (default if no subcommand is given)
    Ui {
        /// Localhost port for the web interface
        #[arg(short, long, default_value_t = DEFAULT_UI_PORT)]
        port: u16,

        /// Do not automatically open the browser tab on startup
        #[arg(long, default_value_t = false)]
        no_open: bool,
    },

    /// Wipe all local cached searches and temporary data from disk
    Clean,

    /// Guided setup to connect a local or self-hosted SearXNG instance
    SearxngSetup,

    /// Configure search engine settings manually
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Preview the targeted search dorks that will be generated for a name, email, or phone
    Dorks {
        /// Full name to search for (optional if --email, --phone, or --username is provided)
        #[arg(short, long)]
        name: Option<String>,

        /// Alternate names, middle names, or nicknames (can be specified multiple times)
        #[arg(short, long)]
        alias: Vec<String>,

        /// Known usernames or handles (can be specified multiple times)
        #[arg(short, long)]
        username: Vec<String>,

        /// Context keywords to narrow results, e.g., city, employer, college (comma-separated or repeated)
        #[arg(short, long, value_delimiter = ',')]
        context: Vec<String>,

        /// Personal or work email addresses to search for
        #[arg(short, long)]
        email: Vec<String>,

        /// Phone numbers to search for (e.g. "+91 9876543210" or "9876543210")
        #[arg(short, long)]
        phone: Vec<String>,

        /// Disable automatic username handle generation from the full name
        #[arg(long, default_value_t = false)]
        no_auto_handles: bool,
    },

    /// Run a full digital footprint scan by Name, Alias, Email, Phone Number, or Context
    Scan {
        /// Full name to audit (optional if --email, --phone, or --username is provided)
        #[arg(short, long)]
        name: Option<String>,

        /// Alternate names, middle names, or nicknames (e.g. --alias "Jane M. Doe")
        #[arg(short, long)]
        alias: Vec<String>,

        /// Known usernames or handles (can be specified multiple times)
        #[arg(short, long)]
        username: Vec<String>,

        /// Context keywords to disambiguate common names (e.g., city, company, university — comma-separated or repeated)
        #[arg(short, long, value_delimiter = ',')]
        context: Vec<String>,

        /// Only show results that match at least one --context keyword (or your --email / --phone)
        #[arg(long, default_value_t = false)]
        strict_context: bool,

        /// Personal or work email addresses to search for (can be used alone or with --name)
        #[arg(short, long)]
        email: Vec<String>,

        /// Phone numbers to search for (can be used alone or with --name)
        #[arg(short, long)]
        phone: Vec<String>,

        /// Search engine backend to use (`free` by default, or `searxng`)
        #[arg(long, value_enum)]
        engine: Option<EngineKind>,

        /// Optional SearXNG instance URL (also automatically used in `free` mode!)
        #[arg(long)]
        url: Option<String>,

        /// Open the targeted Google Search dorks directly in your web browser tabs
        #[arg(long, default_value_t = false)]
        open_google: bool,

        /// Open the targeted Google Search dorks in an Incognito / InPrivate browser window (shows what strangers see!)
        #[arg(long, default_value_t = false)]
        incognito: bool,

        /// Start the local Companion Bridge on 127.0.0.1:60067 to receive live Google Search results from your browser
        #[arg(long, default_value_t = false)]
        listen: bool,

        /// Timeout in seconds for the `--listen` Companion Bridge (wait for multi-page Google crawling)
        #[arg(long, default_value_t = 40)]
        listen_timeout: u64,

        /// Import a Google Search HTML page saved (`Ctrl+S`) from your logged-in browser
        #[arg(long)]
        import_html: Vec<PathBuf>,

        /// Number of search result pages to crawl per query (1..=10, 10 results per page)
        #[arg(long, default_value_t = 3)]
        pages: usize,

        /// Maximum results to fetch per dork query (overrides --pages if higher)
        #[arg(long, default_value_t = 10)]
        max_per_dork: usize,

        /// Fetch open (non-login-walled) deep links to verify the name is present and scan surrounding text for PII
        #[arg(long, default_value_t = false)]
        deep_verify: bool,

        /// Bypass local 24-hour query cache and force fresh search engine requests
        #[arg(long, default_value_t = false)]
        fresh: bool,

        /// Disable automatic username handle permutations from the full name
        #[arg(long, default_value_t = false)]
        no_auto_handles: bool,

        /// Export the privacy audit report to a Markdown (.md) or JSON (.json) file
        #[arg(short = 'o', long)]
        export: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Save search engine preference (`free` or `searxng`)
    Set {
        /// Which search engine backend to use by default (`free` or `searxng`)
        #[arg(long, value_enum)]
        engine: EngineKind,

        /// SearXNG base URL
        #[arg(long)]
        url: Option<String>,
    },

    /// Display the active configuration
    Show,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let command = cli.command.unwrap_or(Commands::Ui {
        port: DEFAULT_UI_PORT,
        no_open: false,
    });

    match command {
        Commands::Ui { port, no_open } => {
            run_ui_server(port, !no_open).await?;
        }
        Commands::Clean => {
            let removed = QueryCache::purge_disk();
            if removed {
                println!(
                    "{} Purged all local cached search queries from disk.",
                    style("[+]").green().bold()
                );
            } else {
                println!(
                    "{} Local disk cache is already clean (zero saved search files).",
                    style("[+]").green().bold()
                );
            }
        }
        Commands::SearxngSetup => handle_searxng_setup()?,
        Commands::Config { action } => handle_config(action)?,
        Commands::Dorks {
            name,
            alias,
            username,
            context,
            email,
            phone,
            no_auto_handles,
        } => {
            let full_name = name.unwrap_or_default();
            if full_name.trim().is_empty()
                && alias.is_empty()
                && email.is_empty()
                && phone.is_empty()
                && username.is_empty()
            {
                anyhow::bail!(
                    "Please provide at least one of `--name`, `--alias`, `--email`, `--phone`, or `--username`."
                );
            }
            let target = ScanTarget {
                full_name,
                aliases: alias,
                usernames: username,
                context_keywords: context
                    .into_iter()
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty())
                    .collect(),
                emails: email,
                phones: phone,
                auto_handles: !no_auto_handles,
                strict_context: false,
            };
            let dorks = generate_dorks(&target);
            println!(
                "\n{} Generated {} targeted dork queries for {}:\n",
                style("[*]").cyan().bold(),
                style(dorks.len()).bold(),
                style(target.display_label()).yellow().bold()
            );
            for (i, d) in dorks.iter().enumerate() {
                println!(
                    "  {}. {} — {}",
                    i + 1,
                    style(format!("[{}]", d.category)).cyan().bold(),
                    style(&d.description).dim()
                );
                println!("     Query: {}\n", style(&d.query).green());
            }
        }
        Commands::Scan {
            name,
            alias,
            username,
            context,
            strict_context,
            email,
            phone,
            engine,
            url,
            open_google,
            incognito,
            listen,
            listen_timeout,
            import_html,
            pages,
            max_per_dork,
            deep_verify,
            fresh,
            no_auto_handles,
            export,
        } => {
            let full_name = name.unwrap_or_default();
            if full_name.trim().is_empty()
                && alias.is_empty()
                && email.is_empty()
                && phone.is_empty()
                && username.is_empty()
            {
                anyhow::bail!(
                    "Please provide at least one of `--name`, `--alias`, `--email`, `--phone`, or `--username`."
                );
            }

            let cfg = AppConfig::load().unwrap_or_default();
            let selected_kind = engine.unwrap_or(cfg.default_engine);
            let search_engine = build_engine(selected_kind, &cfg, url)?;

            let target = ScanTarget {
                full_name,
                aliases: alias,
                usernames: username,
                context_keywords: context
                    .into_iter()
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty())
                    .collect(),
                emails: email,
                phones: phone,
                auto_handles: !no_auto_handles,
                strict_context,
            };

            let effective_max = max_per_dork.max(pages.clamp(1, 10) * 10);
            let dorks = generate_dorks(&target);

            // Optionally open the targeted Google Dork searches in the currently open browser (normal or Private/Incognito)
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

                if incognito {
                    open_urls_in_active_browser(&google_urls, true);
                } else {
                    open_urls_in_active_browser(&google_urls, false);
                }
            }

            let total_steps = dorks.len() as u64 + 1;
            let mut cache = QueryCache::load();
            let mut cache_hits_count = 0usize;

            println!(
                "{} Starting privacy scan for {} using {}...",
                style("[*]").cyan().bold(),
                style(target.display_label()).white().bold(),
                style(search_engine.name()).yellow().bold(),
            );

            let pb = ProgressBar::new(total_steps);
            pb.set_style(
                ProgressStyle::with_template(
                    "{spinner:.cyan} [{bar:35.cyan/blue}] {pos}/{len} {msg}",
                )
                .unwrap()
                .progress_chars("=>-"),
            );
            pb.enable_steady_tick(Duration::from_millis(100));

            let mut all_raw_results: Vec<RawSearchResult> = Vec::new();

            // If `--listen` is passed, start the local Companion Bridge on 127.0.0.1:60067
            if listen {
                let expected = if open_google || incognito {
                    dorks.len().min(5)
                } else {
                    1
                };
                if let Ok(mut companion_hits) =
                    listen_for_companion_results(DEFAULT_COMPANION_PORT, expected, listen_timeout)
                        .await
                {
                    all_raw_results.append(&mut companion_hits);
                }
            }

            // Import any browser-saved Google Search HTML files (`--import-html`)
            for html_path in &import_html {
                match import_browser_saved_html(html_path) {
                    Ok(mut imported) => {
                        pb.println(format!(
                            "{} Imported {} search results from {}",
                            style("[+]").green().bold(),
                            imported.len(),
                            html_path.display()
                        ));
                        all_raw_results.append(&mut imported);
                    }
                    Err(e) => {
                        pb.println(format!(
                            "{} Failed to import {}: {}",
                            style("[!]").yellow().bold(),
                            html_path.display(),
                            e
                        ));
                    }
                }
            }

            // Step 1: 18 Direct Keyless Public APIs (including Google News RSS, arXiv, GitHub, Reddit, OpenAlex, ORCID, Crossref, Archive.org, StackOverflow, NPM, Keybase)
            let osint_cache_key = format!("osint_json_v4::{}", target.display_label().to_lowercase());
            pb.set_message(
                "Sweeping 18 Keyless Public APIs (Google News RSS, arXiv, GitHub, GitLab, StackOverflow, NPM, Reddit, OpenAlex, ORCID, Crossref, Archive.org)...",
            );
            if !fresh {
                if let Some(mut cached) = cache.get(&osint_cache_key) {
                    cache_hits_count += 1;
                    all_raw_results.append(&mut cached);
                } else {
                    let mut osint_hits = run_direct_osint_sweep(&target).await;
                    cache.insert(osint_cache_key, osint_hits.clone());
                    all_raw_results.append(&mut osint_hits);
                }
            } else {
                let mut osint_hits = run_direct_osint_sweep(&target).await;
                cache.insert(osint_cache_key, osint_hits.clone());
                all_raw_results.append(&mut osint_hits);
            }
            pb.inc(1);

            // Step 2: Run web dork queries across the selected search engine (SearXNG / DuckDuckGo / Brave / Google / Serper)
            let mut skip_remaining_dorks = false;
            for dork in &dorks {
                if skip_remaining_dorks {
                    pb.inc(1);
                    continue;
                }

                let cache_key = format!("{:?}::{}", selected_kind, dork.query);
                if !fresh {
                    if let Some(mut cached) = cache.get(&cache_key) {
                        cache_hits_count += 1;
                        all_raw_results.append(&mut cached);
                        pb.inc(1);
                        continue;
                    }
                }

                pb.set_message(format!(
                    "Querying [{}] (up to {} pages)...",
                    dork.category,
                    effective_max.div_ceil(10)
                ));
                match search_engine.search(dork, effective_max).await {
                    Ok(mut hits) => {
                        cache.insert(cache_key.clone(), hits.clone());
                        all_raw_results.append(&mut hits);
                    }
                    Err(err) => {
                        let err_msg = err.to_string();
                        if err_msg.contains("HUMAN_VERIFICATION_REQUIRED") {
                            skip_remaining_dorks = true;
                        } else {
                            pb.println(format!(
                                "{} Query warning for [{}]: {}",
                                style("[!]").yellow().bold(),
                                dork.category,
                                err_msg
                            ));
                        }
                    }
                }
                pb.inc(1);
            }

            // Step 3: Second-Stage Automatic Email Pivot
            // Checks any newly discovered emails (e.g. from GitHub commits) against Public Google Calendar `.ics`, Gravatar, and OpenPGP!
            pb.set_message(
                "Stage-2 Pivot: Checking discovered emails for Public Google Calendars (.ics), Gravatar & PGP...",
            );
            let mut stage2_hits = run_second_stage_email_pivot(&all_raw_results, &target).await;
            all_raw_results.append(&mut stage2_hits);

            pb.finish_with_message(format!(
                "Collected {} raw search hits ({} queries served from local cache).",
                all_raw_results.len(),
                cache_hits_count
            ));

            if deep_verify && !all_raw_results.is_empty() {
                println!(
                    "{} Deep-verifying open deep links (skipping login/WAF sites like LinkedIn, Instagram, ResearchGate)...",
                    style("[*]").cyan().bold()
                );
            }

            let findings = analyze_results(all_raw_results, &target, deep_verify).await;
            print_terminal_report(&target, search_engine.name(), &findings);

            if let Some(export_path) = export {
                if findings.is_empty() && export_path.exists() {
                    println!(
                        "{} Skipped overwriting existing {} because 0 results were returned.",
                        style("[!]").yellow().bold(),
                        style(export_path.display()).underlined()
                    );
                } else {
                    export_report(&export_path, &target, search_engine.name(), &findings)?;
                    println!(
                        "{} Saved detailed privacy audit report to {}",
                        style("[+]").green().bold(),
                        style(export_path.display()).underlined()
                    );
                }
            }
        }
    }

    Ok(())
}

/// Interactive wizard to connect a local or custom SearXNG instance or keep Zero-Key Free Mode.
fn handle_searxng_setup() -> Result<()> {
    println!();
    println!(
        "{}",
        style("==========================================================================").dim()
    );
    println!(
        "{}",
        style("STALKER-SEARCH: SEARXNG SETUP WIZARD").bold().cyan()
    );
    println!(
        "{}",
        style("==========================================================================").dim()
    );
    println!("\nTip: You can run SearXNG locally with Docker via:\n  docker run -d -p 8080:8080 searxng/searxng\n");
    print!("Enter your SearXNG base URL (leave blank to use Zero-Key Free Mode): ");
    let _ = io::stdout().flush();
    let mut url = String::new();
    io::stdin().read_line(&mut url)?;
    let trimmed = url.trim().to_string();

    let mut cfg = AppConfig::load().unwrap_or_default();
    if !trimmed.is_empty() {
        cfg.searxng.base_url = Some(trimmed);
        let path = cfg.save()?;
        println!(
            "\n{} Saved SearXNG URL to {}! Both `--engine free` and `--engine searxng` will now query it.",
            style("[+]").green().bold(),
            path.display()
        );
    } else {
        cfg.default_engine = EngineKind::Free;
        let path = cfg.save()?;
        println!(
            "\n{} Using Zero-Key Free Mode ({}).",
            style("[+]").green().bold(),
            path.display()
        );
    }

    Ok(())
}

struct BrowserSpec {
    display_name: &'static str,
    process_name: &'static str,
    private_flag: &'static str,
    is_firefox_family: bool,
    candidate_paths: Vec<String>,
}

fn known_browsers() -> Vec<BrowserSpec> {
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let program_files =
        std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
    let program_files_x86 = std::env::var("ProgramFiles(x86)")
        .unwrap_or_else(|_| r"C:\Program Files (x86)".to_string());

    vec![
        BrowserSpec {
            display_name: "LibreWolf",
            process_name: "librewolf.exe",
            private_flag: "-private-window",
            is_firefox_family: true,
            candidate_paths: vec![
                format!(r"{}\LibreWolf\librewolf.exe", program_files),
                format!(r"{}\LibreWolf\librewolf.exe", program_files_x86),
                format!(r"{}\Programs\LibreWolf\librewolf.exe", local_app_data),
                "/usr/bin/librewolf".to_string(),
                "/usr/local/bin/librewolf".to_string(),
                "/var/lib/flatpak/exports/bin/io.gitlab.librewolf-community".to_string(),
            ],
        },
        BrowserSpec {
            display_name: "Mozilla Firefox",
            process_name: "firefox.exe",
            private_flag: "-private-window",
            is_firefox_family: true,
            candidate_paths: vec![
                format!(r"{}\Mozilla Firefox\firefox.exe", program_files),
                format!(r"{}\Mozilla Firefox\firefox.exe", program_files_x86),
                format!(r"{}\Mozilla Firefox\firefox.exe", local_app_data),
                "/usr/bin/firefox".to_string(),
                "/usr/local/bin/firefox".to_string(),
                "/snap/bin/firefox".to_string(),
                "/usr/bin/firefox-esr".to_string(),
                "/var/lib/flatpak/exports/bin/org.mozilla.firefox".to_string(),
            ],
        },
        BrowserSpec {
            display_name: "Zen Browser",
            process_name: "zen.exe",
            private_flag: "-private-window",
            is_firefox_family: true,
            candidate_paths: vec![
                format!(r"{}\Zen Browser\zen.exe", program_files),
                format!(r"{}\Programs\Zen Browser\zen.exe", local_app_data),
                "/usr/bin/zen".to_string(),
                "/usr/local/bin/zen".to_string(),
                "/var/lib/flatpak/exports/bin/app.zen_browser.zen".to_string(),
            ],
        },
        BrowserSpec {
            display_name: "Floorp",
            process_name: "floorp.exe",
            private_flag: "-private-window",
            is_firefox_family: true,
            candidate_paths: vec![
                format!(r"{}\Ablaze Floorp\floorp.exe", program_files),
                format!(r"{}\Floorp\floorp.exe", program_files),
                "/usr/bin/floorp".to_string(),
                "/var/lib/flatpak/exports/bin/one.ablaze.floorp".to_string(),
            ],
        },
        BrowserSpec {
            display_name: "Waterfox",
            process_name: "waterfox.exe",
            private_flag: "-private-window",
            is_firefox_family: true,
            candidate_paths: vec![
                format!(r"{}\Waterfox\waterfox.exe", program_files),
                "/usr/bin/waterfox".to_string(),
                "/var/lib/flatpak/exports/bin/net.waterfox.waterfox".to_string(),
            ],
        },
        BrowserSpec {
            display_name: "Mullvad Browser",
            process_name: "mullvadbrowser.exe",
            private_flag: "-private-window",
            is_firefox_family: true,
            candidate_paths: vec![format!(
                r"{}\Mullvad Browser\Browser\mullvadbrowser.exe",
                local_app_data
            )],
        },
        BrowserSpec {
            display_name: "Brave",
            process_name: "brave.exe",
            private_flag: "--incognito",
            is_firefox_family: false,
            candidate_paths: vec![
                format!(
                    r"{}\BraveSoftware\Brave-Browser\Application\brave.exe",
                    program_files
                ),
                format!(
                    r"{}\BraveSoftware\Brave-Browser\Application\brave.exe",
                    program_files_x86
                ),
                format!(
                    r"{}\BraveSoftware\Brave-Browser\Application\brave.exe",
                    local_app_data
                ),
            ],
        },
        BrowserSpec {
            display_name: "Vivaldi",
            process_name: "vivaldi.exe",
            private_flag: "--incognito",
            is_firefox_family: false,
            candidate_paths: vec![
                format!(r"{}\Vivaldi\Application\vivaldi.exe", local_app_data),
                format!(r"{}\Vivaldi\Application\vivaldi.exe", program_files),
            ],
        },
        BrowserSpec {
            display_name: "Google Chrome",
            process_name: "chrome.exe",
            private_flag: "--incognito",
            is_firefox_family: false,
            candidate_paths: vec![
                format!(r"{}\Google\Chrome\Application\chrome.exe", program_files),
                format!(
                    r"{}\Google\Chrome\Application\chrome.exe",
                    program_files_x86
                ),
                format!(r"{}\Google\Chrome\Application\chrome.exe", local_app_data),
            ],
        },
        BrowserSpec {
            display_name: "Opera",
            process_name: "opera.exe",
            private_flag: "--private",
            is_firefox_family: false,
            candidate_paths: vec![
                format!(r"{}\Programs\Opera\opera.exe", local_app_data),
                format!(r"{}\Programs\Opera GX\opera.exe", local_app_data),
            ],
        },
        BrowserSpec {
            display_name: "Microsoft Edge",
            process_name: "msedge.exe",
            private_flag: "--inprivate",
            is_firefox_family: false,
            candidate_paths: vec![
                format!(r"{}\Microsoft\Edge\Application\msedge.exe", program_files_x86),
                format!(r"{}\Microsoft\Edge\Application\msedge.exe", program_files),
            ],
        },
    ]
}

/// Detects whichever Firefox-family browser is currently running or installed on the desktop
/// (e.g. LibreWolf, Mozilla Firefox, Zen, Floorp, Waterfox), falling back to other browsers only if no Firefox-family browser exists.
fn detect_active_or_installed_browser() -> Option<(&'static str, String, &'static str, bool)> {
    let specs = known_browsers();

    #[cfg(target_os = "windows")]
    let tasklist_str = Command::new("tasklist.exe")
        .args(["/FO", "CSV", "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase())
        .unwrap_or_default();

    #[cfg(not(target_os = "windows"))]
    let ps_str = Command::new("ps")
        .args(["-eo", "comm"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase())
        .unwrap_or_default();

    // 1. Prefer an actively running Firefox-family browser (where Stalker Search Companion runs)
    #[cfg(target_os = "windows")]
    for spec in specs.iter().filter(|s| s.is_firefox_family) {
        let needle = format!("\"{}\"", spec.process_name);
        if tasklist_str.contains(&needle) {
            if let Some(exe_path) = spec
                .candidate_paths
                .iter()
                .find(|p| std::path::Path::new(p).exists())
            {
                return Some((
                    spec.display_name,
                    exe_path.clone(),
                    spec.private_flag,
                    spec.is_firefox_family,
                ));
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    for spec in specs.iter().filter(|s| s.is_firefox_family) {
        let linux_proc = spec.process_name.trim_end_matches(".exe");
        if ps_str.lines().any(|l| l.trim().starts_with(linux_proc)) {
            if let Some(exe_path) = spec
                .candidate_paths
                .iter()
                .find(|p| std::path::Path::new(p).exists())
            {
                return Some((
                    spec.display_name,
                    exe_path.clone(),
                    spec.private_flag,
                    spec.is_firefox_family,
                ));
            }
        }
    }

    // 2. Next, prefer any installed Firefox-family browser (even if not open yet)
    for spec in specs.iter().filter(|s| s.is_firefox_family) {
        if let Some(exe_path) = spec
            .candidate_paths
            .iter()
            .find(|p| std::path::Path::new(p).exists())
        {
            return Some((
                spec.display_name,
                exe_path.clone(),
                spec.private_flag,
                spec.is_firefox_family,
            ));
        }
    }

    // 3. Fallback: check other running or installed browsers
    #[cfg(target_os = "windows")]
    for spec in &specs {
        let needle = format!("\"{}\"", spec.process_name);
        if tasklist_str.contains(&needle) {
            if let Some(exe_path) = spec
                .candidate_paths
                .iter()
                .find(|p| std::path::Path::new(p).exists())
            {
                return Some((
                    spec.display_name,
                    exe_path.clone(),
                    spec.private_flag,
                    spec.is_firefox_family,
                ));
            }
        }
    }

    for spec in &specs {
        if let Some(exe_path) = spec
            .candidate_paths
            .iter()
            .find(|p| std::path::Path::new(p).exists())
        {
            return Some((
                spec.display_name,
                exe_path.clone(),
                spec.private_flag,
                spec.is_firefox_family,
            ));
        }
    }

    None
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn GetConsoleWindow() -> *mut std::ffi::c_void;
    fn ShowWindow(hwnd: *mut std::ffi::c_void, n_cmd_show: i32) -> i32;
    fn GetConsoleProcessList(lpdw_process_list: *mut u32, dw_process_count: u32) -> u32;
}

/// If `stalker-search.exe` was double-clicked from File Explorer (so it owns a dedicated console window
/// rather than sharing an interactive PowerShell/CMD terminal), hide the console window so only the
/// standalone desktop software window is shown.
pub fn hide_dedicated_console_window() {
    #[cfg(target_os = "windows")]
    unsafe {
        let mut pids = [0u32; 2];
        let count = GetConsoleProcessList(pids.as_mut_ptr(), 2);
        if count <= 1 {
            let hwnd = GetConsoleWindow();
            if !hwnd.is_null() {
                ShowWindow(hwnd, 0); // SW_HIDE = 0
            }
        }
    }
}

/// Launches the Stalker Search interface as a standalone chromeless desktop application window
/// (no address bar, no browser tabs, dedicated taskbar window).
pub fn launch_desktop_app_window(url: &str) {
    let program_files =
        std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
    let program_files_x86 = std::env::var("ProgramFiles(x86)")
        .unwrap_or_else(|_| r"C:\Program Files (x86)".to_string());
    let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();

    let app_hosts = [
        format!(r"{}\Microsoft\Edge\Application\msedge.exe", program_files_x86),
        format!(r"{}\Microsoft\Edge\Application\msedge.exe", program_files),
        format!(
            r"{}\BraveSoftware\Brave-Browser\Application\brave.exe",
            program_files
        ),
        format!(r"{}\Google\Chrome\Application\chrome.exe", program_files),
        format!(r"{}\Google\Chrome\Application\chrome.exe", local_app_data),
        "/usr/bin/chromium".to_string(),
        "/usr/bin/chromium-browser".to_string(),
        "/usr/bin/brave-browser".to_string(),
        "/usr/bin/google-chrome".to_string(),
        "/usr/bin/microsoft-edge".to_string(),
    ];

    if let Some(host_exe) = app_hosts.iter().find(|p| std::path::Path::new(p).exists()) {
        let profile_dir = std::env::temp_dir().join("stalker_search_desktop_ui");
        let _ = std::fs::create_dir_all(&profile_dir);

        if Command::new(host_exe)
            .args([
                &format!("--app={}", url),
                &format!("--user-data-dir={}", profile_dir.display()),
                "--window-size=1140,860",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-features=Translate,msEdgeSidebarV2",
            ])
            .spawn()
            .is_ok()
        {
            hide_dedicated_console_window();
            return;
        }
    }

    open_urls_in_active_browser(&[url.to_string()], false);
}

/// Opens URLs in whichever browser the user currently has open (either in its Private/Incognito window or normal window).
pub fn open_urls_in_active_browser(urls: &[String], private_mode: bool) {
    if urls.is_empty() {
        return;
    }

    if let Some((browser_name, exe_path, private_flag, is_firefox_family)) =
        detect_active_or_installed_browser()
    {
        if private_mode {
            println!(
                "{} Detected open browser: {} — launching {} tabs in {} mode ({})...",
                style("[*]").cyan().bold(),
                style(browser_name).green().bold(),
                urls.len(),
                style("Private / Incognito").magenta().bold(),
                private_flag
            );

            if is_firefox_family {
                // Firefox & LibreWolf require `-private-window <url>` per tab; wait for window creation on tab 0
                for (i, u) in urls.iter().enumerate() {
                    let _ = Command::new(&exe_path).args([private_flag, u]).spawn();
                    if i == 0 {
                        std::thread::sleep(Duration::from_millis(1100));
                    } else {
                        std::thread::sleep(Duration::from_millis(300));
                    }
                }
            } else {
                // Chromium family accepts `--incognito url1 url2 url3` in one command
                let mut cmd = Command::new(&exe_path);
                cmd.arg(private_flag);
                for u in urls {
                    cmd.arg(u);
                }
                let _ = cmd.spawn();
            }
        } else {
            println!(
                "{} Detected open browser: {} — launching {} tabs...",
                style("[*]").cyan().bold(),
                style(browser_name).green().bold(),
                urls.len()
            );
            let mut cmd = Command::new(&exe_path);
            for u in urls {
                cmd.arg(u);
            }
            let _ = cmd.spawn();
        }
        return;
    }

    // Fallback if browser path isn't in standard locations
    #[cfg(target_os = "windows")]
    for u in urls {
        let _ = Command::new("cmd").args(["/C", "start", "", u]).spawn();
    }

    #[cfg(target_os = "linux")]
    for u in urls {
        let _ = Command::new("xdg-open").arg(u).spawn();
    }

    #[cfg(target_os = "macos")]
    for u in urls {
        let _ = Command::new("open").arg(u).spawn();
    }
}

fn handle_config(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Set { engine, url } => {
            let mut cfg = AppConfig::load().unwrap_or_default();
            cfg.default_engine = engine;
            if let Some(u) = url {
                cfg.searxng.base_url = Some(u);
            }

            let saved_path = cfg.save()?;
            println!(
                "{} Saved configuration (default engine: {}) to {}",
                style("[+]").green().bold(),
                style(engine).yellow().bold(),
                style(saved_path.display()).underlined()
            );
        }
        ConfigAction::Show => {
            let cfg = AppConfig::load()?;
            let path = AppConfig::config_path()?;
            println!(
                "\n{} ({})",
                style("Stalker-Search Configuration").bold().cyan(),
                path.display()
            );
            println!(
                "  Default Engine : {}",
                style(cfg.default_engine).yellow().bold()
            );
            println!(
                "  SearXNG URL    : {}\n",
                cfg.searxng.base_url.as_deref().unwrap_or("<not set>")
            );
        }
    }
    Ok(())
}
