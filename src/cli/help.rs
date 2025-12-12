//! Contextual help system with recipes and guided workflows
//!
//! Provides interactive help recipes for common tasks and troubleshooting.

use crate::ui::{OutputMode, Printer};
use std::collections::HashMap;

/// A step in a help recipe
#[derive(Debug, Clone)]
pub struct Step {
    /// Description of what this step does
    pub description: String,
    /// Command to run
    pub command: String,
    /// Optional note or explanation
    pub note: Option<String>,
}

impl Step {
    pub fn new(description: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            command: command.into(),
            note: None,
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// A help recipe - a guided workflow for a common task
#[derive(Debug, Clone)]
pub struct Recipe {
    /// Recipe title
    pub title: String,
    /// Short description
    pub description: String,
    /// Steps in the recipe
    pub steps: Vec<Step>,
    /// Related recipes
    pub see_also: Vec<String>,
    /// Tags for searching
    pub tags: Vec<String>,
}

impl Recipe {
    pub fn new(title: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            steps: Vec::new(),
            see_also: Vec::new(),
            tags: Vec::new(),
        }
    }

    pub fn add_step(mut self, step: Step) -> Self {
        self.steps.push(step);
        self
    }

    pub fn see_also(mut self, recipe: impl Into<String>) -> Self {
        self.see_also.push(recipe.into());
        self
    }

    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

/// The help system containing all recipes
pub struct HelpSystem {
    recipes: HashMap<String, Recipe>,
}

impl Default for HelpSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl HelpSystem {
    /// Create a new help system with built-in recipes
    pub fn new() -> Self {
        let mut recipes = HashMap::new();

        // First scan recipe
        recipes.insert(
            "first-scan".to_string(),
            Recipe::new(
                "Running Your First Security Scan",
                "Get started with mcplint security scanning",
            )
            .add_step(Step::new(
                "Check your environment is set up correctly",
                "mcplint doctor",
            ))
            .add_step(Step::new("List available MCP servers", "mcplint servers"))
            .add_step(Step::new(
                "Run a quick security scan",
                "mcplint scan <server-name> --profile quick",
            ))
            .add_step(
                Step::new(
                    "View detailed results with JSON output",
                    "mcplint scan <server-name> --format json",
                )
                .with_note("Replace <server-name> with a server from step 2"),
            )
            .see_also("test-authentication")
            .see_also("ci-integration")
            .tag("getting-started")
            .tag("scan"),
        );

        // Test authentication recipe
        recipes.insert(
            "test-authentication".to_string(),
            Recipe::new(
                "Testing Authentication Security",
                "Comprehensive authentication testing workflow",
            )
            .add_step(Step::new(
                "Run focused auth scan with all rules",
                "mcplint scan <server> --include SEC --profile intensive",
            ))
            .add_step(Step::new(
                "Check specific security rules",
                "mcplint rules --category security --details",
            ))
            .add_step(Step::new(
                "Generate a SARIF report for review",
                "mcplint scan <server> --format sarif --output auth-report.sarif",
            ))
            .add_step(
                Step::new(
                    "Save baseline for future comparison",
                    "mcplint scan <server> --save-baseline auth-baseline.json",
                )
                .with_note("Use baselines to track security improvements over time"),
            )
            .see_also("prevent-injection")
            .see_also("ci-integration")
            .tag("security")
            .tag("authentication"),
        );

        // Prevent injection recipe
        recipes.insert(
            "prevent-injection".to_string(),
            Recipe::new(
                "Preventing Injection Attacks",
                "How to detect and prevent injection vulnerabilities",
            )
            .add_step(Step::new(
                "Scan for injection vulnerabilities",
                "mcplint scan <server> --include injection --details",
            ))
            .add_step(Step::new(
                "Review tool schemas for dangerous patterns",
                "mcplint validate <server> --include TOOL",
            ))
            .add_step(Step::new(
                "Fuzz test parameter handling",
                "mcplint fuzz <server> --profile intensive --target-tools <tool-name>",
            ))
            .add_step(Step::new(
                "Get AI explanation of findings",
                "mcplint explain <server>",
            ))
            .see_also("test-authentication")
            .see_also("schema-validation")
            .tag("security")
            .tag("injection"),
        );

        // CI integration recipe
        recipes.insert(
            "ci-integration".to_string(),
            Recipe::new(
                "Setting Up CI/CD Integration",
                "Integrate mcplint into your CI/CD pipeline",
            )
            .add_step(
                Step::new("Generate a project configuration", "mcplint init")
                    .with_note("Creates .mcplint.toml with sensible defaults"),
            )
            .add_step(Step::new(
                "Test with CI-friendly output",
                "mcplint scan <server> --format sarif --fail-on high",
            ))
            .add_step(
                Step::new(
                    "Add to GitHub Actions",
                    "# .github/workflows/security.yml\n\
                     #   - uses: actions/checkout@v4\n\
                     #   - run: cargo install mcplint\n\
                     #   - run: mcplint scan <server> --format sarif",
                )
                .with_note("mcplint returns exit code 1 when issues are found"),
            )
            .add_step(Step::new(
                "Create a baseline for incremental scanning",
                "mcplint scan <server> --save-baseline baseline.json",
            ))
            .see_also("first-scan")
            .see_also("baseline-management")
            .tag("ci")
            .tag("automation"),
        );

        // Schema validation recipe
        recipes.insert(
            "schema-validation".to_string(),
            Recipe::new(
                "Validating Tool Schemas",
                "Ensure your MCP server schemas are correct and secure",
            )
            .add_step(Step::new(
                "Run protocol validation",
                "mcplint validate <server> --details",
            ))
            .add_step(Step::new(
                "Check schema-specific rules",
                "mcplint rules --category schema --details",
            ))
            .add_step(Step::new(
                "Generate tool fingerprints for tracking changes",
                "mcplint fingerprint generate <server>",
            ))
            .add_step(Step::new(
                "Compare with previous fingerprint",
                "mcplint fingerprint compare <server> --baseline fingerprint.json",
            ))
            .see_also("prevent-injection")
            .tag("schema")
            .tag("validation"),
        );

        // Baseline management recipe
        recipes.insert(
            "baseline-management".to_string(),
            Recipe::new(
                "Managing Security Baselines",
                "Track security improvements with baseline comparisons",
            )
            .add_step(Step::new(
                "Create an initial baseline",
                "mcplint scan <server> --save-baseline baseline.json",
            ))
            .add_step(Step::new(
                "Run a scan comparing to baseline",
                "mcplint scan <server> --baseline baseline.json",
            ))
            .add_step(
                Step::new(
                    "Update baseline after fixing issues",
                    "mcplint scan <server> --save-baseline baseline.json",
                )
                .with_note("Only update baseline after reviewing and fixing findings"),
            )
            .see_also("ci-integration")
            .tag("baseline")
            .tag("diff"),
        );

        // Fuzzing recipe
        recipes.insert(
            "fuzz-testing".to_string(),
            Recipe::new(
                "Fuzz Testing Your Server",
                "Find edge cases and crashes with coverage-guided fuzzing",
            )
            .add_step(Step::new(
                "Run a quick fuzz test",
                "mcplint fuzz <server> --profile quick",
            ))
            .add_step(Step::new(
                "Run intensive fuzzing for thorough testing",
                "mcplint fuzz <server> --profile intensive --iterations 10000",
            ))
            .add_step(Step::new(
                "Fuzz specific tools",
                "mcplint fuzz <server> --target-tools read_file,write_file",
            ))
            .add_step(
                Step::new(
                    "Save interesting inputs for reproduction",
                    "mcplint fuzz <server> --save-corpus ./corpus",
                )
                .with_note("Corpus contains inputs that triggered new behavior"),
            )
            .see_also("prevent-injection")
            .tag("fuzzing")
            .tag("testing"),
        );

        // Troubleshooting recipe
        recipes.insert(
            "troubleshooting".to_string(),
            Recipe::new(
                "Troubleshooting Common Issues",
                "Diagnose and fix common problems",
            )
            .add_step(Step::new(
                "Run environment diagnostics",
                "mcplint doctor --extended",
            ))
            .add_step(Step::new(
                "Check server configuration",
                "mcplint servers --details",
            ))
            .add_step(
                Step::new(
                    "Test with increased timeout",
                    "mcplint validate <server> --timeout 60",
                )
                .with_note("Some servers need longer startup time"),
            )
            .add_step(Step::new(
                "View verbose output for debugging",
                "RUST_LOG=debug mcplint validate <server>",
            ))
            .see_also("first-scan")
            .tag("troubleshooting")
            .tag("debug"),
        );

        Self { recipes }
    }

    /// Get a recipe by name
    pub fn get_recipe(&self, name: &str) -> Option<&Recipe> {
        self.recipes.get(name)
    }

    /// List all available recipes
    pub fn list_recipes(&self) -> Vec<(&String, &Recipe)> {
        let mut recipes: Vec<_> = self.recipes.iter().collect();
        recipes.sort_by(|a, b| a.0.cmp(b.0));
        recipes
    }

    /// Search recipes by tag or keyword
    pub fn search(&self, query: &str) -> Vec<(&String, &Recipe)> {
        let query_lower = query.to_lowercase();
        self.recipes
            .iter()
            .filter(|(name, recipe)| {
                name.contains(&query_lower)
                    || recipe.title.to_lowercase().contains(&query_lower)
                    || recipe.description.to_lowercase().contains(&query_lower)
                    || recipe.tags.iter().any(|t| t.contains(&query_lower))
            })
            .collect()
    }

    /// Display a recipe
    pub fn show_recipe(&self, name: &str, mode: OutputMode) {
        let printer = Printer::with_mode(mode);

        if let Some(recipe) = self.get_recipe(name) {
            printer.newline();

            // Title box
            if mode.unicode_enabled() {
                let title_line = format!(" {} ", recipe.title);
                let border = "─".repeat(title_line.len() + 2);
                printer.header(&format!("╭{}╮", border));
                printer.header(&format!("│ {} │", title_line));
                printer.header(&format!("╰{}╯", border));
            } else {
                printer.header(&format!("=== {} ===", recipe.title));
            }

            printer.newline();
            printer.println(&recipe.description);
            printer.newline();

            // Steps
            for (i, step) in recipe.steps.iter().enumerate() {
                let step_num = i + 1;

                if mode.unicode_enabled() {
                    printer.println(&format!("{}. {}", step_num, step.description));
                    printer.println(&format!("   → {}", step.command));
                } else {
                    printer.println(&format!("{}. {}", step_num, step.description));
                    printer.println(&format!("   $ {}", step.command));
                }

                if let Some(note) = &step.note {
                    if mode.colors_enabled() {
                        use colored::Colorize;
                        println!("   {}", format!("Note: {}", note).dimmed());
                    } else {
                        printer.println(&format!("   Note: {}", note));
                    }
                }
                printer.newline();
            }

            // See also
            if !recipe.see_also.is_empty() {
                printer.separator();
                printer.println("See also:");
                for related in &recipe.see_also {
                    if mode.unicode_enabled() {
                        printer.println(&format!("  • mcplint how-do-i {}", related));
                    } else {
                        printer.println(&format!("  - mcplint how-do-i {}", related));
                    }
                }
            }
        } else {
            // Recipe not found - suggest similar
            let available: Vec<_> = self.recipes.keys().map(|s| s.as_str()).collect();
            if let Some(suggestion) =
                crate::errors::suggestions::find_similar(name, &available, 0.5)
            {
                printer.error(&format!("Recipe '{}' not found.", name));
                printer.println(&format!("Did you mean '{}'?", suggestion));
            } else {
                printer.error(&format!("Recipe '{}' not found.", name));
                printer.println("Run 'mcplint how-do-i' to see available recipes.");
            }
        }
    }

    /// Display list of all recipes
    pub fn show_list(&self, mode: OutputMode) {
        let printer = Printer::with_mode(mode);

        printer.newline();
        printer.header("Available Help Recipes");
        printer.separator();
        printer.newline();

        for (name, recipe) in self.list_recipes() {
            let bullet = if mode.unicode_enabled() { "•" } else { "-" };
            printer.println(&format!("  {} {} - {}", bullet, name, recipe.description));
        }

        printer.newline();
        printer.println("Usage: mcplint how-do-i <recipe-name>");
        printer.println("       mcplint how-do-i --search <keyword>");
        printer.newline();
    }

    /// Display search results
    pub fn show_search_results(&self, query: &str, mode: OutputMode) {
        let printer = Printer::with_mode(mode);
        let results = self.search(query);

        printer.newline();
        if results.is_empty() {
            printer.println(&format!("No recipes found matching '{}'.", query));
            printer.println("Run 'mcplint how-do-i' to see all available recipes.");
        } else {
            printer.header(&format!("Recipes matching '{}':", query));
            printer.newline();

            for (name, recipe) in results {
                printer.println(&format!("  {} - {}", name, recipe.description));
            }

            printer.newline();
            printer.println("Usage: mcplint how-do-i <recipe-name>");
        }
        printer.newline();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_system_has_recipes() {
        let help = HelpSystem::new();
        assert!(!help.recipes.is_empty());
    }

    #[test]
    fn get_recipe_returns_existing() {
        let help = HelpSystem::new();
        assert!(help.get_recipe("first-scan").is_some());
        assert!(help.get_recipe("test-authentication").is_some());
    }

    #[test]
    fn get_recipe_returns_none_for_unknown() {
        let help = HelpSystem::new();
        assert!(help.get_recipe("unknown-recipe").is_none());
    }

    #[test]
    fn list_recipes_returns_all() {
        let help = HelpSystem::new();
        let list = help.list_recipes();
        assert!(list.len() >= 5);
    }

    #[test]
    fn search_by_tag() {
        let help = HelpSystem::new();
        let results = help.search("security");
        assert!(!results.is_empty());
    }

    #[test]
    fn search_by_title() {
        let help = HelpSystem::new();
        let results = help.search("authentication");
        assert!(!results.is_empty());
    }

    #[test]
    fn search_no_results() {
        let help = HelpSystem::new();
        let results = help.search("xyznonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn recipe_has_steps() {
        let help = HelpSystem::new();
        let recipe = help.get_recipe("first-scan").unwrap();
        assert!(!recipe.steps.is_empty());
    }

    #[test]
    fn recipe_has_see_also() {
        let help = HelpSystem::new();
        let recipe = help.get_recipe("test-authentication").unwrap();
        assert!(!recipe.see_also.is_empty());
    }

    #[test]
    fn step_creation() {
        let step = Step::new("Test step", "test command").with_note("A note");
        assert_eq!(step.description, "Test step");
        assert_eq!(step.command, "test command");
        assert_eq!(step.note, Some("A note".to_string()));
    }

    #[test]
    fn recipe_builder() {
        let recipe = Recipe::new("Test", "A test recipe")
            .add_step(Step::new("Step 1", "cmd1"))
            .see_also("other")
            .tag("test");

        assert_eq!(recipe.title, "Test");
        assert_eq!(recipe.steps.len(), 1);
        assert_eq!(recipe.see_also, vec!["other"]);
        assert_eq!(recipe.tags, vec!["test"]);
    }
}
