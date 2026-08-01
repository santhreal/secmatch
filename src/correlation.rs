//! Dynamic correlation rule engine for grouping related findings.
//!
//! This module provides configurable correlation rules that can be loaded
//! from TOML files. Rules define conditions based on finding tags and kinds,
//! and produce correlated findings when all conditions are met for a target.
//!
//! # Rule Format
//!
//! Correlation rules are TOML files with the following structure:
//!
//! ```toml
//! id = "rule-id"
//! name = "Human Readable Name"
//! severity = "high"
//! description = "What this correlation means"
//!
//! [[conditions]]
//! type = "tag"  # or "kind"
//! values = ["sqli", "sql-injection"]
//! match = "any"  # or "all"
//!
//! result_tags = ["correlated", "high-risk"]
//! matched_values = ["sqli"]
//! ```

use secir::{Finding, FindingKind, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::{debug, warn};

/// A correlation rule that matches findings based on conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    /// Unique identifier for this correlation.
    pub id: String,

    /// Human-readable name.
    pub name: String,

    /// Severity to assign to correlated findings.
    pub severity: String,

    /// Description of what this correlation represents.
    pub description: String,

    /// Conditions that must all be satisfied for this rule to fire.
    pub conditions: Vec<Condition>,

    /// Tags to add to the resulting correlated finding.
    #[serde(default)]
    pub result_tags: Vec<String>,

    /// Values to report as matched in the correlation.
    #[serde(default)]
    pub matched_values: Vec<String>,
}

/// A single condition that must be satisfied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    /// Type of condition: "tag" or "kind".
    pub condition_type: String,

    /// Values to match against.
    pub values: Vec<String>,

    /// How to match: "any" (at least one) or "all" (all must match).
    #[serde(default = "default_match_mode")]
    pub match_mode: String,
}

fn default_match_mode() -> String {
    "any".to_string()
}

impl Condition {
    /// Check if this condition is satisfied by the given tag set.
    #[must_use]
    pub fn matches_tags(&self, tags: &HashSet<String>) -> bool {
        if self.condition_type != "tag" {
            return false;
        }

        match self.match_mode.as_str() {
            "all" => self.values.iter().all(|v| tags.contains(v)),
            _ => self.values.iter().any(|v| tags.contains(v)),
        }
    }

    /// Check if this condition is satisfied by the given kind.
    #[must_use]
    pub fn matches_kind(&self, kind: &FindingKind) -> bool {
        if self.condition_type != "kind" {
            return false;
        }

        // Convert FindingKind to its kebab-case string representation
        let kind_str = kind_to_kebab_case(kind);
        match self.match_mode.as_str() {
            "all" => self
                .values
                .iter()
                .all(|v| kind_str == v.to_ascii_lowercase()),
            _ => self
                .values
                .iter()
                .any(|v| kind_str == v.to_ascii_lowercase()),
        }
    }
}

/// Engine for evaluating correlation rules against findings.
#[derive(Debug, Clone)]
pub struct CorrelationEngine {
    rules: Vec<CorrelationRule>,
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::with_builtin_rules()
    }
}

impl CorrelationEngine {
    /// Create an empty engine with no rules.
    #[must_use]
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Create an engine with built-in default rules.
    #[must_use]
    pub fn with_builtin_rules() -> Self {
        Self {
            rules: vec![
                Self::rce_chain_rule(),
                Self::account_takeover_rule(),
                Self::cloud_compromise_rule(),
                Self::session_hijack_rule(),
                Self::data_breach_rule(),
                Self::tech_exposure_rule(),
            ],
        }
    }

    /// Load rules from a directory containing TOML files.
    ///
    /// Each `.toml` file in the directory is parsed as a correlation rule.
    /// If a rule has the same ID as an existing rule, it overrides the existing one.
    pub fn load_from_dir<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let mut engine = Self::empty();
        let path = path.as_ref();

        if !path.exists() {
            debug!(
                "Correlation rules directory does not exist: {}",
                path.display()
            );
            return Ok(engine);
        }

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "toml") {
                match std::fs::read_to_string(&path) {
                    Ok(content) => match toml::from_str::<CorrelationRule>(&content) {
                        Ok(rule) => {
                            debug!(
                                "Loaded correlation rule: {} from {}",
                                rule.id,
                                path.display()
                            );
                            engine.add_or_override_rule(rule);
                        }
                        Err(e) => {
                            warn!("Failed to parse correlation rule {}: {}", path.display(), e);
                        }
                    },
                    Err(e) => {
                        warn!("Failed to read correlation rule {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(engine)
    }

    /// Add a rule to the engine, or override an existing rule with the same ID.
    pub fn add_or_override_rule(&mut self, rule: CorrelationRule) {
        if let Some(pos) = self.rules.iter().position(|r| r.id == rule.id) {
            self.rules[pos] = rule;
        } else {
            self.rules.push(rule);
        }
    }

    /// Add a rule to the engine.
    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    /// Get all loaded rules.
    #[must_use]
    pub fn rules(&self) -> &[CorrelationRule] {
        &self.rules
    }

    /// Correlate findings based on loaded rules.
    ///
    /// Returns a vector of new findings representing correlations between
    /// the input findings. The original findings are not modified.
    #[must_use]
    pub fn correlate(&self, findings: &[Finding]) -> Vec<Finding> {
        let mut target_info: HashMap<&str, TargetInfo> = HashMap::new();

        // Collect information about each target
        for finding in findings {
            let info = target_info.entry(finding.target.as_str()).or_default();
            info.kinds.insert(finding.kind.clone());
            info.tags.extend(finding.tags.iter().cloned());
        }

        let mut correlations = Vec::new();

        // Evaluate each rule against each target
        for (target, info) in &target_info {
            for rule in &self.rules {
                if self.rule_matches(rule, info) {
                    let severity = parse_severity(&rule.severity);
                    let correlation = Finding {
                        template_id: rule.id.clone(),
                        template_name: rule.name.clone(),
                        template_path: None,
                        target: target.to_string(),
                        severity,
                        kind: FindingKind::Vulnerability,
                        matched_values: rule.matched_values.clone(),
                        extracted: std::collections::HashMap::new(),
                        matched_at: target.to_string(),
                        request: None,
                        response: None,
                        curl_command: None,
                        matcher_name: None,
                        protocol: None,
                        timestamp: chrono::Utc::now(),
                        tags: rule.result_tags.clone(),
                        description: Some(rule.description.clone()),
                        references: vec![],
                        cve_ids: vec![],
                        confidence: None,
                        verification: None,
                    };
                    correlations.push(correlation);
                }
            }
        }

        correlations
    }

    /// Check if a rule matches the given target info.
    fn rule_matches(&self, rule: &CorrelationRule, info: &TargetInfo) -> bool {
        rule.conditions.iter().all(|condition| {
            if condition.condition_type == "tag" {
                condition.matches_tags(&info.tags)
            } else if condition.condition_type == "kind" {
                // For kind conditions, check if ANY of the target's kinds match
                info.kinds.iter().any(|k| condition.matches_kind(k))
            } else {
                false
            }
        })
    }

    // Built-in default rules

    fn rce_chain_rule() -> CorrelationRule {
        CorrelationRule {
            id: "karyx-chain-rce".to_string(),
            name: "Potential RCE Chain".to_string(),
            severity: "critical".to_string(),
            description: "SQL injection combined with file read capabilities may lead to remote code execution".to_string(),
            conditions: vec![
                Condition {
                    condition_type: "tag".to_string(),
                    values: vec!["sqli".to_string(), "sql-injection".to_string()],
                    match_mode: "any".to_string(),
                },
                Condition {
                    condition_type: "tag".to_string(),
                    values: vec!["lfi".to_string(), "file-read".to_string(), "rfi".to_string()],
                    match_mode: "any".to_string(),
                },
            ],
            result_tags: vec!["rce-chain".to_string(), "critical".to_string()],
            matched_values: vec!["sqli".to_string(), "file-read".to_string()],
        }
    }

    fn account_takeover_rule() -> CorrelationRule {
        CorrelationRule {
            id: "karyx-chain-account-takeover".to_string(),
            name: "Account Takeover Risk".to_string(),
            severity: "critical".to_string(),
            description:
                "Default credentials accessible via admin panel may allow account takeover"
                    .to_string(),
            conditions: vec![
                Condition {
                    condition_type: "tag".to_string(),
                    values: vec![
                        "default-credentials".to_string(),
                        "default-login".to_string(),
                    ],
                    match_mode: "any".to_string(),
                },
                Condition {
                    condition_type: "tag".to_string(),
                    values: vec!["admin".to_string(), "admin-panel".to_string()],
                    match_mode: "any".to_string(),
                },
            ],
            result_tags: vec!["account-takeover".to_string(), "critical".to_string()],
            matched_values: vec!["default-credentials".to_string(), "admin-panel".to_string()],
        }
    }

    fn cloud_compromise_rule() -> CorrelationRule {
        CorrelationRule {
            id: "karyx-chain-cloud-compromise".to_string(),
            name: "Cloud Compromise Risk".to_string(),
            severity: "critical".to_string(),
            description: "SSRF combined with accessible cloud metadata may lead to cloud infrastructure compromise".to_string(),
            conditions: vec![
                Condition {
                    condition_type: "tag".to_string(),
                    values: vec!["ssrf".to_string()],
                    match_mode: "any".to_string(),
                },
                Condition {
                    condition_type: "tag".to_string(),
                    values: vec!["cloud-metadata".to_string(), "metadata".to_string()],
                    match_mode: "any".to_string(),
                },
            ],
            result_tags: vec!["cloud-compromise".to_string(), "critical".to_string()],
            matched_values: vec!["ssrf".to_string(), "cloud-metadata".to_string()],
        }
    }

    fn session_hijack_rule() -> CorrelationRule {
        CorrelationRule {
            id: "karyx-chain-session-hijack".to_string(),
            name: "Session Hijacking Risk".to_string(),
            severity: "high".to_string(),
            description:
                "Cross-site scripting with accessible session cookies may allow session hijacking"
                    .to_string(),
            conditions: vec![
                Condition {
                    condition_type: "tag".to_string(),
                    values: vec!["xss".to_string(), "cross-site-scripting".to_string()],
                    match_mode: "any".to_string(),
                },
                Condition {
                    condition_type: "tag".to_string(),
                    values: vec!["session".to_string(), "cookie".to_string()],
                    match_mode: "any".to_string(),
                },
            ],
            result_tags: vec!["session-hijack".to_string(), "high".to_string()],
            matched_values: vec!["xss".to_string(), "session-cookie".to_string()],
        }
    }

    fn data_breach_rule() -> CorrelationRule {
        CorrelationRule {
            id: "karyx-chain-data-breach".to_string(),
            name: "Data Breach Risk".to_string(),
            severity: "high".to_string(),
            description: "Directory listing exposing sensitive files may lead to data breach"
                .to_string(),
            conditions: vec![
                Condition {
                    condition_type: "tag".to_string(),
                    values: vec!["directory-listing".to_string(), "dir-listing".to_string()],
                    match_mode: "any".to_string(),
                },
                Condition {
                    condition_type: "tag".to_string(),
                    values: vec![
                        "sensitive".to_string(),
                        "backup".to_string(),
                        "config".to_string(),
                    ],
                    match_mode: "any".to_string(),
                },
            ],
            result_tags: vec!["data-breach".to_string(), "high".to_string()],
            matched_values: vec![
                "directory-listing".to_string(),
                "sensitive-file".to_string(),
            ],
        }
    }

    fn tech_exposure_rule() -> CorrelationRule {
        CorrelationRule {
            id: "karyx-correlation".to_string(),
            name: "Karyx Correlation".to_string(),
            severity: "high".to_string(),
            description: "Multiple indicators suggest elevated risk".to_string(),
            conditions: vec![
                Condition {
                    condition_type: "kind".to_string(),
                    values: vec!["tech-detect".to_string()],
                    match_mode: "any".to_string(),
                },
                Condition {
                    condition_type: "kind".to_string(),
                    values: vec!["exposure".to_string()],
                    match_mode: "any".to_string(),
                },
            ],
            result_tags: vec!["correlated-risk".to_string(), "high".to_string()],
            matched_values: vec!["tech-detect".to_string(), "exposure".to_string()],
        }
    }
}

/// Information collected about a target's findings.
#[derive(Debug, Default)]
struct TargetInfo {
    kinds: HashSet<FindingKind>,
    tags: HashSet<String>,
}

/// Convert `FindingKind` to its kebab-case string representation.
///
/// This matches the serde serialization format defined in secir.
fn kind_to_kebab_case(kind: &FindingKind) -> String {
    match kind {
        FindingKind::Vulnerability => "vulnerability".to_string(),
        FindingKind::Misconfiguration => "misconfiguration".to_string(),
        FindingKind::Exposure => "exposure".to_string(),
        FindingKind::TechDetect => "tech-detect".to_string(),
        FindingKind::DefaultCredentials => "default-credentials".to_string(),
        FindingKind::InfoDisclosure => "info-disclosure".to_string(),
        FindingKind::FileDiscovery => "file-discovery".to_string(),
        FindingKind::Other => "other".to_string(),
        _ => "other".to_string(), // Handle future variants
    }
}

/// Parse a severity string into a Severity enum.
///
/// Unknown/empty strings map to `Info` (the nuclei convention), but a value
/// that is neither a known severity nor the explicit `unknown`/empty sentinel
/// is a rule-authoring defect (e.g. a `criticl` typo silently downgrading a
/// critical finding to Info). Law-10: surface that loudly rather than swallow
/// it. Called once per rule during correlation, so the warn is not hot-path.
fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" | "unknown" | "" => Severity::Info,
        other => {
            tracing::warn!(
                severity = %other,
                "unrecognized severity string in rule metadata; defaulting to Info (a real severity was likely mistyped)"
            );
            Severity::Info
        }
    }
}

/// Correlate findings using the default correlation engine.
///
/// This is the main entry point for correlation. It uses the default
/// engine which includes built-in rules and loads additional rules
/// from the `rules/correlations/` directory if it exists.
#[must_use]
pub fn correlate_findings(findings: &[Finding]) -> Vec<Finding> {
    let engine = CorrelationEngine::default();
    engine.correlate(findings)
}

/// Correlate findings with a custom rules directory.
///
/// Loads rules from the specified directory in addition to built-in rules.
pub fn correlate_findings_with_rules_dir(findings: &[Finding], rules_dir: &Path) -> Vec<Finding> {
    match CorrelationEngine::load_from_dir(rules_dir) {
        Ok(mut engine) => {
            // Add built-in rules that weren't overridden
            let builtin = CorrelationEngine::with_builtin_rules();
            for rule in builtin.rules() {
                if engine.rules().iter().all(|r| r.id != rule.id) {
                    engine.add_rule(rule.clone());
                }
            }
            engine.correlate(findings)
        }
        Err(e) => {
            warn!(
                "Failed to load correlation rules from {}: {}",
                rules_dir.display(),
                e
            );
            correlate_findings(findings)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secir::Severity;
    use std::collections::HashMap;

    fn test_finding(id: &str, kind: FindingKind, tags: &[&str]) -> Finding {
        Finding {
            template_id: id.to_string(),
            template_name: id.to_string(),
            template_path: None,
            target: "https://example.com".to_string(),
            severity: Severity::High,
            kind,
            matched_values: vec![id.to_string()],
            extracted: HashMap::new(),
            matched_at: "https://example.com".to_string(),
            request: None,
            response: None,
            curl_command: None,
            matcher_name: None,
            protocol: None,
            timestamp: chrono::Utc::now(),
            tags: tags.iter().map(ToString::to_string).collect(),
            description: None,
            references: vec![],
            cve_ids: vec![],
            confidence: None,
            verification: None,
        }
    }

    #[test]
    fn engine_detects_rce_chain() {
        let engine = CorrelationEngine::with_builtin_rules();
        let findings = vec![
            test_finding("sqli", FindingKind::Vulnerability, &["sqli"]),
            test_finding("lfi", FindingKind::Vulnerability, &["lfi", "file-read"]),
        ];

        let correlations = engine.correlate(&findings);
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].template_id, "karyx-chain-rce");
        assert_eq!(correlations[0].severity, Severity::Critical);
    }

    #[test]
    fn engine_detects_account_takeover() {
        let engine = CorrelationEngine::with_builtin_rules();
        let findings = vec![
            test_finding(
                "default-creds",
                FindingKind::DefaultCredentials,
                &["default-credentials"],
            ),
            test_finding("admin", FindingKind::Exposure, &["admin-panel"]),
        ];

        let correlations = engine.correlate(&findings);
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].template_id, "karyx-chain-account-takeover");
    }

    #[test]
    fn engine_detects_tech_exposure() {
        let engine = CorrelationEngine::with_builtin_rules();
        let findings = vec![
            test_finding("tech", FindingKind::TechDetect, &["tech"]),
            test_finding("exposure", FindingKind::Exposure, &["exposure"]),
        ];

        let correlations = engine.correlate(&findings);
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].template_id, "karyx-correlation");
    }

    #[test]
    fn no_correlation_when_conditions_not_met() {
        let engine = CorrelationEngine::with_builtin_rules();
        let findings = vec![
            test_finding("sqli", FindingKind::Vulnerability, &["sqli"]),
            // Missing file-read tag
        ];

        let correlations = engine.correlate(&findings);
        assert!(correlations.is_empty());
    }

    #[test]
    fn condition_matches_tag_any() {
        let cond = Condition {
            condition_type: "tag".to_string(),
            values: vec!["sqli".to_string(), "sql-injection".to_string()],
            match_mode: "any".to_string(),
        };

        let mut tags: HashSet<String> = HashSet::new();
        tags.insert("sqli".to_string());
        assert!(cond.matches_tags(&tags));

        tags.clear();
        tags.insert("other".to_string());
        assert!(!cond.matches_tags(&tags));
    }

    #[test]
    fn condition_matches_kind() {
        let cond = Condition {
            condition_type: "kind".to_string(),
            values: vec!["tech-detect".to_string()],
            match_mode: "any".to_string(),
        };

        assert!(cond.matches_kind(&FindingKind::TechDetect));
        assert!(!cond.matches_kind(&FindingKind::Vulnerability));
    }
}
