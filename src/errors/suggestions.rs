//! "Did you mean?" suggestion system using fuzzy string matching
//!
//! Provides intelligent suggestions for typos and near-matches using
//! the Jaro-Winkler string similarity algorithm.

// These functions are public APIs for error suggestion generation
#![allow(dead_code)]

use strsim::jaro_winkler;

/// Default similarity threshold for suggestions (0.0 to 1.0)
const DEFAULT_THRESHOLD: f64 = 0.6;

/// Find the most similar string from a list of candidates
///
/// Returns the best match if it exceeds the threshold, or None otherwise.
pub fn find_similar<'a>(input: &str, candidates: &[&'a str], threshold: f64) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (jaro_winkler(input, c), *c))
        .filter(|(score, _)| *score > threshold)
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(_, name)| name)
}

/// Find multiple similar strings sorted by similarity
pub fn find_similar_multiple<'a>(
    input: &str,
    candidates: &[&'a str],
    threshold: f64,
    max_results: usize,
) -> Vec<&'a str> {
    let mut matches: Vec<_> = candidates
        .iter()
        .map(|c| (jaro_winkler(input, c), *c))
        .filter(|(score, _)| *score > threshold)
        .collect();

    matches.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    matches
        .into_iter()
        .take(max_results)
        .map(|(_, name)| name)
        .collect()
}

/// Generate a suggestion for an unknown server name
pub fn suggest_server(unknown: &str, known_servers: &[String]) -> String {
    let candidates: Vec<_> = known_servers.iter().map(|s| s.as_str()).collect();

    if let Some(suggestion) = find_similar(unknown, &candidates, DEFAULT_THRESHOLD) {
        format!(
            "Did you mean '{}'?\n\nList available servers with: mcplint servers",
            suggestion
        )
    } else if known_servers.is_empty() {
        "No servers configured.\n\n\
         MCPLint reads server configuration from Claude Desktop config.\n\
         Run 'mcplint doctor' to check configuration paths."
            .to_string()
    } else {
        let server_list = if known_servers.len() <= 5 {
            known_servers.join(", ")
        } else {
            format!(
                "{}, ... ({} more)",
                known_servers[..3].join(", "),
                known_servers.len() - 3
            )
        };
        format!(
            "Unknown server '{}'.\n\n\
             Available servers: {}\n\n\
             List all servers with: mcplint servers",
            unknown, server_list
        )
    }
}

/// Generate a suggestion for an unknown command
pub fn suggest_command(unknown: &str) -> String {
    let commands = [
        "scan",
        "validate",
        "fuzz",
        "servers",
        "rules",
        "init",
        "watch",
        "doctor",
        "explain",
        "cache",
        "fingerprint",
    ];

    if let Some(suggestion) = find_similar(unknown, &commands, DEFAULT_THRESHOLD) {
        format!(
            "Did you mean 'mcplint {}'?\n\nRun 'mcplint --help' to see all commands.",
            suggestion
        )
    } else {
        "Unknown command.\n\nRun 'mcplint --help' to see available commands.".to_string()
    }
}

/// Generate a suggestion for an unknown rule ID
pub fn suggest_rule(unknown: &str, known_rules: &[&str]) -> String {
    if let Some(suggestion) = find_similar(unknown, known_rules, DEFAULT_THRESHOLD) {
        format!(
            "Did you mean '{}'?\n\nList all rules with: mcplint rules --details",
            suggestion
        )
    } else {
        format!(
            "Unknown rule '{}'.\n\nList all rules with: mcplint rules --details",
            unknown
        )
    }
}

/// Generate a suggestion for an unknown output format
pub fn suggest_format(unknown: &str) -> String {
    let formats = ["text", "json", "sarif", "junit", "gitlab"];

    if let Some(suggestion) = find_similar(unknown, &formats, DEFAULT_THRESHOLD) {
        format!(
            "Did you mean '{}'?\n\nAvailable formats: {}",
            suggestion,
            formats.join(", ")
        )
    } else {
        format!(
            "Unknown format '{}'.\n\nAvailable formats: {}",
            unknown,
            formats.join(", ")
        )
    }
}

/// Generate a suggestion for an unknown severity level
pub fn suggest_severity(unknown: &str) -> String {
    let severities = ["info", "low", "medium", "high", "critical"];

    if let Some(suggestion) = find_similar(unknown, &severities, DEFAULT_THRESHOLD) {
        format!(
            "Did you mean '{}'?\n\nAvailable severities: {}",
            suggestion,
            severities.join(", ")
        )
    } else {
        format!(
            "Unknown severity '{}'.\n\nAvailable severities: {}",
            unknown,
            severities.join(", ")
        )
    }
}

/// Generate a suggestion for an unknown profile
pub fn suggest_profile(unknown: &str) -> String {
    let profiles = ["quick", "standard", "intensive", "ci"];

    if let Some(suggestion) = find_similar(unknown, &profiles, DEFAULT_THRESHOLD) {
        format!(
            "Did you mean '{}'?\n\nAvailable profiles: {}",
            suggestion,
            profiles.join(", ")
        )
    } else {
        format!(
            "Unknown profile '{}'.\n\nAvailable profiles: {}",
            unknown,
            profiles.join(", ")
        )
    }
}

/// Suggest missing flags based on common patterns
pub fn suggest_missing_flag(context: &str) -> Option<String> {
    let context_lower = context.to_lowercase();

    if context_lower.contains("output") || context_lower.contains("format") {
        Some("Did you mean to specify an output format? Try: --format json".to_string())
    } else if context_lower.contains("timeout") {
        Some("Did you mean to set a timeout? Try: --timeout 60".to_string())
    } else if context_lower.contains("server") {
        Some("Did you mean to specify a server? Try: mcplint servers".to_string())
    } else if context_lower.contains("rule") {
        Some(
            "Did you mean to specify rules? Try: --include <rule-id> or --exclude <rule-id>"
                .to_string(),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_similar_exact_match() {
        let result = find_similar("scan", &["scan", "init", "rules"], 0.6);
        assert_eq!(result, Some("scan"));
    }

    #[test]
    fn test_find_similar_typo() {
        let result = find_similar("scna", &["scan", "init", "rules"], 0.6);
        assert_eq!(result, Some("scan"));
    }

    #[test]
    fn test_find_similar_close_typo() {
        let result = find_similar("validat", &["validate", "init", "rules"], 0.6);
        assert_eq!(result, Some("validate"));
    }

    #[test]
    fn test_find_similar_no_match() {
        let result = find_similar("xyz", &["scan", "init", "rules"], 0.6);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_similar_multiple() {
        let result = find_similar_multiple("fil", &["file", "filter", "final", "xyz"], 0.5, 3);
        assert!(result.contains(&"file"));
        assert!(result.contains(&"filter"));
        assert!(!result.contains(&"xyz"));
    }

    #[test]
    fn test_suggest_server_typo() {
        let known = vec!["filesystem".to_string(), "memory".to_string()];
        let suggestion = suggest_server("filesystm", &known);
        assert!(suggestion.contains("filesystem"));
        assert!(suggestion.contains("Did you mean"));
    }

    #[test]
    fn test_suggest_server_unknown() {
        let known = vec!["filesystem".to_string(), "memory".to_string()];
        let suggestion = suggest_server("xyz123", &known);
        assert!(suggestion.contains("Unknown server"));
        assert!(suggestion.contains("filesystem"));
    }

    #[test]
    fn test_suggest_server_empty_list() {
        let known: Vec<String> = vec![];
        let suggestion = suggest_server("test", &known);
        assert!(suggestion.contains("No servers configured"));
    }

    #[test]
    fn test_suggest_command_typo() {
        let suggestion = suggest_command("scna");
        assert!(suggestion.contains("scan"));
        assert!(suggestion.contains("Did you mean"));
    }

    #[test]
    fn test_suggest_command_validate() {
        let suggestion = suggest_command("validte");
        assert!(suggestion.contains("validate"));
    }

    #[test]
    fn test_suggest_command_unknown() {
        let suggestion = suggest_command("xyz123");
        assert!(suggestion.contains("Unknown command"));
        assert!(suggestion.contains("--help"));
    }

    #[test]
    fn test_suggest_rule_typo() {
        let rules = ["SEC-001", "SEC-002", "PROTO-001"];
        let suggestion = suggest_rule("SEC-01", &rules);
        assert!(suggestion.contains("SEC-001") || suggestion.contains("SEC-002"));
    }

    #[test]
    fn test_suggest_format_typo() {
        let suggestion = suggest_format("jsn");
        assert!(suggestion.contains("json"));
    }

    #[test]
    fn test_suggest_format_unknown() {
        let suggestion = suggest_format("xyz");
        assert!(suggestion.contains("Unknown format"));
        assert!(suggestion.contains("sarif"));
    }

    #[test]
    fn test_suggest_severity_typo() {
        let suggestion = suggest_severity("hgh");
        assert!(suggestion.contains("high"));
    }

    #[test]
    fn test_suggest_profile_typo() {
        let suggestion = suggest_profile("standar");
        assert!(suggestion.contains("standard"));
    }

    #[test]
    fn test_suggest_missing_flag_output() {
        let suggestion = suggest_missing_flag("missing output specification");
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("--format"));
    }

    #[test]
    fn test_suggest_missing_flag_timeout() {
        let suggestion = suggest_missing_flag("need to set timeout");
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("--timeout"));
    }

    #[test]
    fn test_suggest_missing_flag_none() {
        let suggestion = suggest_missing_flag("random text");
        assert!(suggestion.is_none());
    }

    #[test]
    fn test_jaro_winkler_similarity() {
        // Test that similar strings have high similarity
        assert!(jaro_winkler("scan", "scna") > 0.8);
        assert!(jaro_winkler("validate", "validte") > 0.9);
        assert!(jaro_winkler("filesystem", "filesystm") > 0.9);

        // Test that dissimilar strings have low similarity
        assert!(jaro_winkler("scan", "xyz") < 0.5);
    }
}
