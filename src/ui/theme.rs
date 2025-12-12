//! Theme system for consistent CLI colors and styling
//!
//! Provides severity-based coloring for security findings and UI elements.
//!
//! Note: The primary `Severity` enum is defined in `crate::scanner::finding::Severity`
//! with full serialization support. This module provides theming utilities that work
//! with that enum.

use colored::Colorize;

use crate::scanner::Severity;

/// Theme configuration for mcplint CLI output
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Theme {
    /// Whether colors are enabled
    pub colors_enabled: bool,
    /// Whether unicode symbols are enabled
    pub unicode_enabled: bool,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            colors_enabled: true,
            unicode_enabled: true,
        }
    }
}

impl Theme {
    /// Create a plain theme (no colors, ASCII only)
    #[allow(dead_code)]
    pub fn plain() -> Self {
        Self {
            colors_enabled: false,
            unicode_enabled: false,
        }
    }

    /// Create a theme for CI environments
    #[allow(dead_code)]
    pub fn ci() -> Self {
        Self {
            colors_enabled: false,
            unicode_enabled: false,
        }
    }
}

/// Security-focused theme with predefined styles
#[allow(dead_code)]
pub struct SecurityTheme;

impl SecurityTheme {
    /// Style text by severity
    #[allow(dead_code)]
    pub fn severity(text: &str, severity: Severity) -> String {
        text.color(severity.color()).to_string()
    }

    /// Style for success messages
    #[allow(dead_code)]
    pub fn success(text: &str) -> colored::ColoredString {
        text.green().bold()
    }

    /// Style for error messages
    #[allow(dead_code)]
    pub fn error(text: &str) -> colored::ColoredString {
        text.red().bold()
    }

    /// Style for warning messages
    #[allow(dead_code)]
    pub fn warning(text: &str) -> colored::ColoredString {
        text.yellow()
    }

    /// Style for informational messages
    #[allow(dead_code)]
    pub fn info(text: &str) -> colored::ColoredString {
        text.cyan()
    }

    /// Style for dimmed/secondary text
    #[allow(dead_code)]
    pub fn dimmed(text: &str) -> colored::ColoredString {
        text.dimmed()
    }

    /// Style for highlighted/emphasized text
    #[allow(dead_code)]
    pub fn highlight(text: &str) -> colored::ColoredString {
        text.yellow().bold()
    }

    /// Style for command/code text
    #[allow(dead_code)]
    pub fn code(text: &str) -> colored::ColoredString {
        text.cyan()
    }

    /// Horizontal separator line
    #[allow(dead_code)]
    pub fn separator() -> colored::ColoredString {
        "━".repeat(60).dimmed()
    }

    /// Check mark for success
    #[allow(dead_code)]
    pub fn check_mark() -> &'static str {
        "✓"
    }

    /// X mark for failure
    #[allow(dead_code)]
    pub fn x_mark() -> &'static str {
        "✗"
    }

    /// Warning symbol
    #[allow(dead_code)]
    pub fn warning_symbol() -> &'static str {
        "⚠"
    }

    /// Arrow for recommendations/suggestions
    #[allow(dead_code)]
    pub fn arrow() -> &'static str {
        "→"
    }

    /// Bullet point
    #[allow(dead_code)]
    pub fn bullet() -> &'static str {
        "•"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_defaults() {
        let theme = Theme::default();
        assert!(theme.colors_enabled);
        assert!(theme.unicode_enabled);
    }

    #[test]
    fn theme_plain() {
        let theme = Theme::plain();
        assert!(!theme.colors_enabled);
        assert!(!theme.unicode_enabled);
    }

    #[test]
    fn theme_ci() {
        let theme = Theme::ci();
        assert!(!theme.colors_enabled);
        assert!(!theme.unicode_enabled);
    }

    #[test]
    fn security_theme_symbols() {
        assert_eq!(SecurityTheme::check_mark(), "✓");
        assert_eq!(SecurityTheme::x_mark(), "✗");
        assert_eq!(SecurityTheme::warning_symbol(), "⚠");
        assert_eq!(SecurityTheme::arrow(), "→");
        assert_eq!(SecurityTheme::bullet(), "•");
    }

    #[test]
    fn security_theme_severity_styling() {
        let text = "Test message";

        // Test all severity levels
        let critical = SecurityTheme::severity(text, Severity::Critical);
        assert!(!critical.is_empty());

        let high = SecurityTheme::severity(text, Severity::High);
        assert!(!high.is_empty());

        let medium = SecurityTheme::severity(text, Severity::Medium);
        assert!(!medium.is_empty());

        let low = SecurityTheme::severity(text, Severity::Low);
        assert!(!low.is_empty());

        let info = SecurityTheme::severity(text, Severity::Info);
        assert!(!info.is_empty());
    }

    #[test]
    fn security_theme_success_styling() {
        let styled = SecurityTheme::success("Success message");
        assert!(styled.to_string().contains("Success message"));
    }

    #[test]
    fn security_theme_error_styling() {
        let styled = SecurityTheme::error("Error message");
        assert!(styled.to_string().contains("Error message"));
    }

    #[test]
    fn security_theme_warning_styling() {
        let styled = SecurityTheme::warning("Warning message");
        assert!(styled.to_string().contains("Warning message"));
    }

    #[test]
    fn security_theme_info_styling() {
        let styled = SecurityTheme::info("Info message");
        assert!(styled.to_string().contains("Info message"));
    }

    #[test]
    fn security_theme_dimmed_styling() {
        let styled = SecurityTheme::dimmed("Dimmed text");
        assert!(styled.to_string().contains("Dimmed text"));
    }

    #[test]
    fn security_theme_highlight_styling() {
        let styled = SecurityTheme::highlight("Highlighted text");
        assert!(styled.to_string().contains("Highlighted text"));
    }

    #[test]
    fn security_theme_code_styling() {
        let styled = SecurityTheme::code("code_snippet()");
        assert!(styled.to_string().contains("code_snippet()"));
    }

    #[test]
    fn security_theme_separator() {
        let sep = SecurityTheme::separator();
        let sep_str = sep.to_string();
        // Separator should contain repeated characters
        assert!(sep_str.len() > 10);
    }

    #[test]
    fn theme_clone() {
        let theme1 = Theme::default();
        let theme2 = theme1.clone();
        assert_eq!(theme1.colors_enabled, theme2.colors_enabled);
        assert_eq!(theme1.unicode_enabled, theme2.unicode_enabled);
    }

    #[test]
    fn theme_debug() {
        let theme = Theme::default();
        let debug_str = format!("{:?}", theme);
        assert!(debug_str.contains("Theme"));
    }

    #[test]
    fn theme_custom() {
        let theme = Theme {
            colors_enabled: true,
            unicode_enabled: false,
        };
        assert!(theme.colors_enabled);
        assert!(!theme.unicode_enabled);
    }
}
