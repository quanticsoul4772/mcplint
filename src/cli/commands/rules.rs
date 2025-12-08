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
