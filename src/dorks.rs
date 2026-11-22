use crate::models::{DorkCategory, DorkQuery};

/// Parameters describing the person auditing their own digital footprint.
/// Supports searching by Name, Aliases, Email, Phone Number, Username, or any combination.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub full_name: String,
    pub aliases: Vec<String>,
    pub usernames: Vec<String>,
    pub context_keywords: Vec<String>,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub auto_handles: bool,
    pub strict_context: bool,
}

impl ScanTarget {
    /// Human-readable label for the scan target (Name, Email, Phone, or Username).
    pub fn display_label(&self) -> String {
        let mut parts = Vec::new();
        if !self.full_name.trim().is_empty() {
            parts.push(self.full_name.trim().to_string());
        }
        if !self.aliases.is_empty() {
            parts.push(format!("aka {}", self.aliases.join(", ")));
        }
        if !self.emails.is_empty() {
            parts.push(format!("email: {}", self.emails.join(", ")));
        }
        if !self.phones.is_empty() {
            parts.push(format!("phone: {}", self.phones.join(", ")));
        }
        if parts.is_empty() && !self.usernames.is_empty() {
            parts.push(format!("@{}", self.usernames.join(", @")));
        }
        if parts.is_empty() {
            "Unknown Target".to_string()
        } else {
            parts.join(" | ")
        }
    }

    /// Returns cleaned word tokens of the primary full name (e.g., "Jane Doe" -> `["jane", "doe"]`).
    pub fn name_tokens(&self) -> Vec<String> {
        Self::tokenize_name(&self.full_name)
    }

    pub fn tokenize_name(name: &str) -> Vec<String> {
        name.split_whitespace()
            .map(|s| {
                s.chars()
                    .filter(|c| c.is_alphanumeric())
                    .collect::<String>()
            })
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Returns all token sets across `full_name` and `aliases`.
    pub fn all_name_token_sets(&self) -> Vec<Vec<String>> {
        let mut sets = Vec::new();
        let primary = self.name_tokens();
        if !primary.is_empty() {
            sets.push(primary);
        }
        for alias in &self.aliases {
            let toks = Self::tokenize_name(alias);
            if !toks.is_empty() {
                sets.push(toks);
            }
        }
        sets
    }

    /// Returns the exact forward name (`"Jane Doe"`), swapped name order (`"Doe Jane"`),
    /// and all forward + swapped variations of any `--alias` names!
    pub fn exact_name_variants(&self) -> Vec<String> {
        let mut variants = Vec::new();
        let mut all_names = Vec::new();
        if !self.full_name.trim().is_empty() {
            all_names.push(self.full_name.trim().to_string());
        }
        for a in &self.aliases {
            if !a.trim().is_empty() {
                all_names.push(a.trim().to_string());
            }
        }

        for raw_name in all_names {
            if !variants.iter().any(|v: &String| v.eq_ignore_ascii_case(&raw_name)) {
                variants.push(raw_name.clone());
            }
            let tokens: Vec<&str> = raw_name.split_whitespace().collect();
            if tokens.len() >= 2 {
                let mut reversed = tokens.clone();
                reversed.reverse();
                let swapped = reversed.join(" ");
                if !variants.iter().any(|v| v.eq_ignore_ascii_case(&swapped)) {
                    variants.push(swapped);
                }

                if tokens.len() > 2 {
                    let last = tokens[tokens.len() - 1];
                    let rest = tokens[..tokens.len() - 1].join(" ");
                    let last_first = format!("{} {}", last, rest);
                    if !variants.iter().any(|v| v.eq_ignore_ascii_case(&last_first)) {
                        variants.push(last_first);
                    }
                }
            }
        }

        variants
    }

    /// Formats the strict full-name boolean clause: `("Jane Doe" OR "Doe Jane")`.
    pub fn strict_name_clause(&self) -> String {
        let variants = self.exact_name_variants();
        if variants.is_empty() {
            if let Some(email) = self.emails.first() {
                return format!("\"{}\"", email.trim());
            }
            if let Some(phone) = self.phones.first() {
                return format!("\"{}\"", phone.trim());
            }
            if let Some(u) = self.usernames.first() {
                return format!("\"{}\"", u.trim());
            }
            return String::new();
        }
        if variants.len() == 1 {
            format!("\"{}\"", variants[0])
        } else {
            let quoted: Vec<String> = variants
                .iter()
                .take(4)
                .map(|v| format!("\"{}\"", v))
                .collect();
            format!("({})", quoted.join(" OR "))
        }
    }

    /// Generates common formatting variations of user-supplied phone numbers
    /// (e.g. `"+91 9876543210"` -> `["9876543210", "+91 9876543210", "98765 43210", "987-654-3210"]`).
    pub fn phone_variants(&self) -> Vec<String> {
        let mut out = Vec::new();
        for p in &self.phones {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !out.contains(&trimmed.to_string()) {
                out.push(trimmed.to_string());
            }

            let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 10 {
                let last10 = &digits[digits.len() - 10..];
                let candidates = vec![
                    last10.to_string(),
                    format!("{} {}", &last10[..5], &last10[5..]),
                    format!("{}-{}-{}", &last10[..3], &last10[3..6], &last10[6..]),
                    format!("+91 {}", last10),
                    format!("+91-{}", last10),
                ];
                for c in candidates {
                    if !out.contains(&c) {
                        out.push(c);
                    }
                }
            }
        }
        out
    }

    /// Returns pure 10+ digit strings for normalized phone comparison in the analyzer.
    pub fn normalized_phone_digits(&self) -> Vec<String> {
        let mut out = Vec::new();
        for p in &self.phones {
            let digits: String = p.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 10 {
                let last10 = digits[digits.len() - 10..].to_string();
                if !out.contains(&last10) {
                    out.push(last10);
                }
            } else if digits.len() >= 7 && !out.contains(&digits) {
                out.push(digits);
            }
        }
        out
    }

    /// Generates combined full-name handle permutations (plus email local-part handles!).
    /// Never generates a single-word handle like `jane` or `doe`.
    pub fn effective_usernames(&self) -> Vec<String> {
        let mut list = self.usernames.clone();

        // Also extract the username prefix before `@` from any provided `--email`
        for email in &self.emails {
            if let Some(local) = email.split('@').next() {
                let clean = local.trim().to_lowercase();
                if clean.len() >= 4 && !list.iter().any(|u| u.eq_ignore_ascii_case(&clean)) {
                    list.push(clean);
                }
            }
        }

        if self.auto_handles {
            for token_set in self.all_name_token_sets() {
                let parts: Vec<String> =
                    token_set.into_iter().map(|s| s.to_lowercase()).collect();
                if parts.len() >= 2 {
                    let first = &parts[0];
                    let last = &parts[parts.len() - 1];
                    let candidates = vec![
                        format!("{}{}", first, last),
                        format!("{}{}", last, first),
                        format!("{}.{}", first, last),
                        format!("{}.{}", last, first),
                        format!("{}_{}", first, last),
                        format!("{}-{}", first, last),
                    ];
                    for c in candidates {
                        if !list.iter().any(|u| u.eq_ignore_ascii_case(&c)) {
                            list.push(c);
                        }
                    }
                }
            }
        }
        list
    }
}

/// Generates targeted search queries for Name, Aliases, Context, Email, and Phone Number.
pub fn generate_dorks(target: &ScanTarget) -> Vec<DorkQuery> {
    let variants = target.exact_name_variants();
    let mut dorks = Vec::new();

    // --- A. Name & Alias Dorks (if `--name` or `--alias` was provided) ---
    if let Some(forward_name) = variants.first() {
        // 1. Exact Quoted Forward Full-Name Search ("Jane Doe")
        dorks.push(DorkQuery {
            category: DorkCategory::GeneralMentions,
            query: format!("\"{}\"", forward_name),
            description: format!(
                "Exact full-name web, profile & document references for \"{}\"",
                forward_name
            ),
        });

        // 2. Exact Quoted Swapped Full-Name & Alias Searches ("Doe Jane" / Aliases)
        for alt_name in variants.iter().skip(1).take(3) {
            dorks.push(DorkQuery {
                category: DorkCategory::GeneralMentions,
                query: format!("\"{}\"", alt_name),
                description: format!("Swapped / alias name references for \"{}\"", alt_name),
            });
        }

        // 3. Context-Correlated Search (Full Name + Context Keywords like College, Company, City)
        if !target.context_keywords.is_empty() {
            for ctx in &target.context_keywords {
                let trimmed = ctx.trim();
                if !trimmed.is_empty() {
                    dorks.push(DorkQuery {
                        category: DorkCategory::GeneralMentions,
                        query: format!("{} \"{}\"", target.strict_name_clause(), trimmed),
                        description: format!(
                            "Targeted context search correlating full name with \"{}\"",
                            trimmed
                        ),
                    });
                }
            }
        }

        // 4. Exact Full-Name + PDF / Document Exposure
        dorks.push(DorkQuery {
            category: DorkCategory::DocumentsAndFiles,
            query: format!("\"{}\" filetype:pdf", forward_name),
            description:
                "Publicly indexed PDFs, resumes, rosters, and academic papers containing exact full name"
                    .to_string(),
        });

        // 5. Exact Full-Name + Social / Developer Profiles
        dorks.push(DorkQuery {
            category: DorkCategory::SocialProfiles,
            query: format!(
                "\"{}\" (site:linkedin.com OR site:instagram.com OR site:github.com OR site:facebook.com)",
                forward_name
            ),
            description: "Social & developer profile links containing exact full name".to_string(),
        });
    }

    // --- B. Email Address Dorks (works standalone or combined with Name!) ---
    for email in &target.emails {
        let trimmed = email.trim();
        if trimmed.is_empty() {
            continue;
        }
        dorks.push(DorkQuery {
            category: DorkCategory::ContactAndPii,
            query: format!("\"{}\"", trimmed),
            description: format!("Direct web, paste, commit & document leaks for email '{}'", trimmed),
        });
    }

    // --- C. Phone Number Dorks (works standalone or combined with Name!) ---
    let phone_vars = target.phone_variants();
    if !phone_vars.is_empty() {
        let phone_clause = phone_vars
            .iter()
            .take(4)
            .map(|p| format!("\"{}\"", p))
            .collect::<Vec<_>>()
            .join(" OR ");
        dorks.push(DorkQuery {
            category: DorkCategory::ContactAndPii,
            query: phone_clause,
            description: format!(
                "Direct web, directory, resume & data-broker leaks for phone number ({})",
                target.phones.join(", ")
            ),
        });
    }

    // --- D. Explicit User-Provided Handles ---
    if !target.usernames.is_empty() {
        let handles = target
            .usernames
            .iter()
            .take(3)
            .filter(|u| !u.trim().is_empty())
            .map(|u| format!("\"{}\"", u.trim()))
            .collect::<Vec<_>>()
            .join(" OR ");
        if !handles.is_empty() {
            dorks.push(DorkQuery {
                category: DorkCategory::UsernameMentions,
                query: handles,
                description: format!("Direct search for usernames ({})", target.usernames.join(", ")),
            });
        }
    }

    dorks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_name_variants_swaps_order_and_includes_aliases() {
        let target = ScanTarget {
            full_name: "Jane Doe".to_string(),
            aliases: vec!["Jane M Doe".to_string()],
            usernames: vec![],
            context_keywords: vec![],
            emails: vec![],
            phones: vec![],
            auto_handles: true,
            strict_context: false,
        };

        let variants = target.exact_name_variants();
        assert!(variants.contains(&"Jane Doe".to_string()));
        assert!(variants.contains(&"Doe Jane".to_string()));
        assert!(variants.contains(&"Jane M Doe".to_string()));
    }

    #[test]
    fn test_phone_and_email_only_dorks() {
        let target = ScanTarget {
            full_name: String::new(),
            aliases: vec![],
            usernames: vec![],
            context_keywords: vec![],
            emails: vec!["test@example.com".to_string()],
            phones: vec!["+91 9876543210".to_string()],
            auto_handles: false,
            strict_context: false,
        };

        let dorks = generate_dorks(&target);
        assert!(dorks.iter().any(|d| d.query.contains("test@example.com")));
        assert!(dorks.iter().any(|d| d.query.contains("9876543210")));
        assert_eq!(target.normalized_phone_digits(), vec!["9876543210".to_string()]);
    }
}
