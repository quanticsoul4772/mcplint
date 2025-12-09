//! Rules command - List available security rules

use anyhow::Result;
use colored::Colorize;

use crate::rules::RuleRegistry;
use crate::scanner::Severity;

pub fn run(category: Option<String>, verbose: bool) -> Result<()> {
    let registry = RuleRegistry::default();
    let rules = registry.list_rules(category.as_deref());

    println!("{}", "Available Security Rules".cyan().bold());
    println!("{}", "=".repeat(60));
    println!();

    let categories = [
        ("injection", "Injection Vulnerabilities"),
        ("auth", "Authentication & Authorization"),
        ("transport", "Transport Security"),
        ("protocol", "Protocol Compliance"),
        ("data", "Data Exposure"),
        ("dos", "Denial of Service"),
    ];

    for (cat_id, cat_name) in categories {
        let cat_rules: Vec<_> = rules.iter().filter(|r| r.category == cat_id).collect();

        if cat_rules.is_empty() {
            continue;
        }

        println!("{}", cat_name.yellow().bold());
        println!();

        for rule in cat_rules {
            let severity_colored = Severity::colored_from_str(&rule.severity);

            println!("  {} [{}] {}", rule.id.green(), severity_colored, rule.name);

            if verbose {
                println!("    {}", rule.description.dimmed());
                if !rule.references.is_empty() {
                    println!("    References: {}", rule.references.join(", ").dimmed());
                }
                println!();
            }
        }
        println!();
    }

    println!("{}", format!("Total: {} rules", rules.len()).dimmed());

    Ok(())
}

/// Get all available rule categories
pub fn get_categories() -> Vec<(&'static str, &'static str)> {
    vec![
        ("injection", "Injection Vulnerabilities"),
        ("auth", "Authentication & Authorization"),
        ("transport", "Transport Security"),
        ("protocol", "Protocol Compliance"),
        ("data", "Data Exposure"),
        ("dos", "Denial of Service"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_returns_ok() {
        // Test with no category filter
        let result = run(None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn run_with_category_filter() {
        let result = run(Some("injection".to_string()), false);
        assert!(result.is_ok());
    }

    #[test]
    fn run_with_verbose() {
        let result = run(None, true);
        assert!(result.is_ok());
    }

    #[test]
    fn run_with_category_and_verbose() {
        let result = run(Some("auth".to_string()), true);
        assert!(result.is_ok());
    }

    #[test]
    fn run_with_unknown_category() {
        // Should still succeed but show no rules
        let result = run(Some("nonexistent".to_string()), false);
        assert!(result.is_ok());
    }

    #[test]
    fn get_categories_returns_all() {
        let categories = get_categories();
        assert_eq!(categories.len(), 6);
    }

    #[test]
    fn get_categories_contains_injection() {
        let categories = get_categories();
        assert!(categories.iter().any(|(id, _)| *id == "injection"));
    }

    #[test]
    fn get_categories_contains_auth() {
        let categories = get_categories();
        assert!(categories.iter().any(|(id, _)| *id == "auth"));
    }

    #[test]
    fn get_categories_contains_transport() {
        let categories = get_categories();
        assert!(categories.iter().any(|(id, _)| *id == "transport"));
    }

    #[test]
    fn rule_registry_has_rules() {
        let registry = RuleRegistry::default();
        let rules = registry.list_rules(None);
        assert!(!rules.is_empty());
    }

    #[test]
    fn rule_registry_filter_by_category() {
        let registry = RuleRegistry::default();
        let injection_rules = registry.list_rules(Some("injection"));
        let auth_rules = registry.list_rules(Some("auth"));

        // Both should have some rules
        assert!(!injection_rules.is_empty());
        assert!(!auth_rules.is_empty());

        // All injection rules should have injection category
        for rule in injection_rules {
            assert_eq!(rule.category, "injection");
        }
    }

    #[test]
    fn severity_colored_from_str() {
        // Test that severity coloring works
        let _critical = Severity::colored_from_str("critical");
        let _high = Severity::colored_from_str("high");
        let _medium = Severity::colored_from_str("medium");
        let _low = Severity::colored_from_str("low");
        let _info = Severity::colored_from_str("info");
        // Just verify these don't panic
    }
}
