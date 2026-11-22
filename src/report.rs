use crate::dorks::ScanTarget;
use crate::models::{AnalyzedFinding, PiiLeakType, RiskLevel};
use anyhow::{Context, Result};
use chrono::Local;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement,
    Table,
};
use console::style;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

struct IdentityFootprintSummary {
    emails: BTreeSet<String>,
    phones: BTreeSet<String>,
    handles: BTreeSet<String>,
    variants: BTreeSet<String>,
    platforms: BTreeSet<String>,
}

fn summarize_identity(findings: &[AnalyzedFinding]) -> IdentityFootprintSummary {
    let mut emails = BTreeSet::new();
    let mut phones = BTreeSet::new();
    let mut handles = BTreeSet::new();
    let mut variants = BTreeSet::new();
    let mut platforms = BTreeSet::new();

    for f in findings {
        if f.domain != "unknown" {
            platforms.insert(f.domain.clone());
        }
        for leak in &f.pii_leaks {
            match leak {
                PiiLeakType::Email(e) => {
                    emails.insert(e.clone());
                }
                PiiLeakType::Phone(p) => {
                    phones.insert(p.clone());
                }
                _ => {}
            }
        }
        for ctx in &f.matched_context {
            if ctx.starts_with('@') {
                handles.insert(ctx.clone());
            } else if let Some(v) = ctx.strip_prefix("Variant: ") {
                variants.insert(v.to_string());
            }
        }
        // Also extract GitHub `@login` from title if present
        if let Some(idx) = f.title.find('@') {
            let after = &f.title[idx..];
            let token: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '@' || *c == '-' || *c == '_' || *c == '.')
                .collect();
            if token.len() >= 4 {
                handles.insert(token);
            }
        }
    }

    IdentityFootprintSummary {
        emails,
        phones,
        handles,
        variants,
        platforms,
    }
}

/// Prints a colorized summary and detailed table of findings to the terminal.
pub fn print_terminal_report(
    target: &ScanTarget,
    engine_name: &str,
    findings: &[AnalyzedFinding],
) {
    let high_count = findings
        .iter()
        .filter(|f| f.risk_level == RiskLevel::High)
        .count();
    let med_count = findings
        .iter()
        .filter(|f| f.risk_level == RiskLevel::Medium)
        .count();
    let low_count = findings
        .iter()
        .filter(|f| f.risk_level == RiskLevel::Low)
        .count();

    println!();
    println!(
        "{}",
        style("==========================================================================")
            .dim()
    );
    println!(
        "{}  Target: {}  |  Engine: {}",
        style("STALKER-SEARCH PRIVACY AUDIT").bold().cyan(),
        style(target.display_label()).bold().white(),
        style(engine_name).yellow()
    );
    println!(
        "{}",
        style("==========================================================================")
            .dim()
    );
    println!(
        "Total Unique References: {}   |   {} {}   |   {} {}   |   {} {}",
        style(findings.len()).bold(),
        style("HIGH RISK:").bold().red(),
        style(high_count).bold().red(),
        style("MEDIUM RISK:").bold().yellow(),
        style(med_count).bold().yellow(),
        style("LOW RISK:").bold().green(),
        style(low_count).bold().green(),
    );
    println!();

    if findings.is_empty() {
        println!(
            "{}",
            style("No public references found for the given queries.").green()
        );
        return;
    }

    // Identity Footprint Summary Card
    let summary = summarize_identity(findings);
    println!("{}", style("[Identity Footprint Summary]").bold().magenta());
    if !summary.emails.is_empty() {
        println!(
            "  {} {}",
            style("Exposed Emails    :").bold(),
            style(summary.emails.into_iter().collect::<Vec<_>>().join(", "))
                .red()
                .bold()
        );
    }
    if !summary.phones.is_empty() {
        println!(
            "  {} {}",
            style("Exposed Phones    :").bold(),
            style(summary.phones.into_iter().collect::<Vec<_>>().join(", "))
                .red()
                .bold()
        );
    }
    if !summary.handles.is_empty() {
        println!(
            "  {} {}",
            style("Discovered Handles:").bold(),
            style(summary.handles.into_iter().collect::<Vec<_>>().join(", ")).cyan()
        );
    }
    if !summary.variants.is_empty() {
        println!(
            "  {} {}",
            style("Matched Variants  :").bold(),
            summary.variants.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    if !summary.platforms.is_empty() {
        println!(
            "  {} {}",
            style("Active Domains    :").bold(),
            style(summary.platforms.into_iter().collect::<Vec<_>>().join(", ")).yellow()
        );
    }
    println!();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Risk").add_attribute(Attribute::Bold),
            Cell::new("Conf").add_attribute(Attribute::Bold),
            Cell::new("Category").add_attribute(Attribute::Bold),
            Cell::new("Reference (Title & URL)").add_attribute(Attribute::Bold),
            Cell::new("Detected Signals / Leaks").add_attribute(Attribute::Bold),
        ]);

    for f in findings {
        let risk_cell = match f.risk_level {
            RiskLevel::High => Cell::new("HIGH")
                .fg(Color::Red)
                .add_attribute(Attribute::Bold),
            RiskLevel::Medium => Cell::new("MEDIUM")
                .fg(Color::Yellow)
                .add_attribute(Attribute::Bold),
            RiskLevel::Low => Cell::new("LOW").fg(Color::Green),
        };

        let conf_str = format!("{:.0}%", f.confidence * 100.0);
        let cats = f
            .categories
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        let verified_badge = if f.page_verified { " [Verified]" } else { "" };
        let ref_col = format!("{}{}\n{}", f.title.trim(), verified_badge, f.url);

        let mut signals = Vec::new();
        for leak in &f.pii_leaks {
            signals.push(format!("! {}", leak));
        }
        if !f.matched_context.is_empty() {
            signals.push(format!("Context: {}", f.matched_context.join(", ")));
        }
        if signals.is_empty() {
            signals.push("Name match".to_string());
        }

        table.add_row(vec![
            risk_cell,
            Cell::new(conf_str),
            Cell::new(cats),
            Cell::new(ref_col),
            Cell::new(signals.join("\n")),
        ]);
    }

    println!("{table}");
    println!();

    if high_count > 0 {
        println!(
            "{}",
            style("Top Recommended Privacy Actions (High-Risk Exposures):")
                .bold()
                .red()
        );
        for (idx, f) in findings
            .iter()
            .filter(|f| f.risk_level == RiskLevel::High)
            .take(5)
            .enumerate()
        {
            println!(
                "  {}. {} ({})",
                idx + 1,
                style(&f.domain).bold(),
                style(&f.url).underlined()
            );
            println!("     Action: {}", f.remediation_advice);
            if let Some(rem_url) = &f.remediation_url {
                println!("     Opt-out / Removal Link: {}", style(rem_url).cyan());
            }
        }
        println!();
    }

    if target.context_keywords.is_empty() && findings.len() > 3 {
        println!(
            "{} Multiple people may share this name. To isolate one specific person, add:",
            style("[Tip]").cyan().bold()
        );
        println!(
            "      {} (e.g. college, company, or city) + {}",
            style("--context \"Infosys\"").green(),
            style("--strict-context").green()
        );
        println!(
            "      or {} / {} / {}",
            style("--alias \"Middle Name\"").green(),
            style("--email \"you@gmail.com\"").green(),
            style("--phone \"+91 9876543210\"").green()
        );
        println!();
    }
}

/// Exports the audit findings to either Markdown (`.md`) or JSON (`.json`) based on file extension.
pub fn export_report(
    path: &Path,
    target: &ScanTarget,
    engine_name: &str,
    findings: &[AnalyzedFinding],
) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("md")
        .to_lowercase();

    if ext == "json" {
        let json_str = serde_json::to_string_pretty(findings)
            .context("Failed to serialize findings to JSON")?;
        fs::write(path, json_str)
            .with_context(|| format!("Failed to write JSON report to {}", path.display()))?;
    } else {
        let md = build_markdown_report(target, engine_name, findings);
        fs::write(path, md)
            .with_context(|| format!("Failed to write Markdown report to {}", path.display()))?;
    }

    Ok(())
}

fn build_markdown_report(
    target: &ScanTarget,
    engine_name: &str,
    findings: &[AnalyzedFinding],
) -> String {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let high_count = findings
        .iter()
        .filter(|f| f.risk_level == RiskLevel::High)
        .count();
    let med_count = findings
        .iter()
        .filter(|f| f.risk_level == RiskLevel::Medium)
        .count();
    let low_count = findings
        .iter()
        .filter(|f| f.risk_level == RiskLevel::Low)
        .count();

    let mut out = String::new();
    out.push_str(&format!(
        "# Digital Footprint & Privacy Audit Report: {}\n\n",
        target.display_label()
    ));
    out.push_str(&format!("- **Generated At**: `{}`\n", now));
    out.push_str(&format!("- **Search Engine Provider**: `{}`\n", engine_name));
    if !target.context_keywords.is_empty() {
        out.push_str(&format!(
            "- **Context Filters**: `{}`\n",
            target.context_keywords.join(", ")
        ));
    }
    out.push_str(&format!(
        "- **Total Unique References**: **{}** (High Risk: **{}**, Medium Risk: **{}**, Low Risk: **{})\n\n",
        findings.len(),
        high_count,
        med_count,
        low_count
    ));

    out.push_str("---\n\n## Findings Breakdown\n\n");

    for (i, f) in findings.iter().enumerate() {
        out.push_str(&format!(
            "### {}. [{}] {} ({:.0}% Confidence)\n\n",
            i + 1,
            f.risk_level,
            f.title.replace('\n', " "),
            f.confidence * 100.0
        ));
        out.push_str(&format!("- **URL**: {}\n", f.url));
        out.push_str(&format!("- **Domain**: `{}`\n", f.domain));
        let cats = f
            .categories
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("- **Categories**: {}\n", cats));
        if f.page_verified {
            out.push_str("- **Live Page Verification**: Confirmed present on live page\n");
        }
        if !f.pii_leaks.is_empty() {
            let leaks = f
                .pii_leaks
                .iter()
                .map(|l| l.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("- **Detected PII / Sensitive Signals**: `{}`\n", leaks));
        }
        if !f.matched_context.is_empty() {
            out.push_str(&format!(
                "- **Matched Context**: `{}`\n",
                f.matched_context.join(", ")
            ));
        }
        if !f.snippet.trim().is_empty() {
            out.push_str(&format!(
                "- **Snippet**: > {}\n",
                f.snippet.replace('\n', " ")
            ));
        }
        out.push_str(&format!(
            "- **Recommended Privacy Action**: {}\n",
            f.remediation_advice
        ));
        if let Some(rem_url) = &f.remediation_url {
            out.push_str(&format!("- **Action / Removal Link**: {}\n", rem_url));
        }
        out.push('\n');
    }

    out
}
