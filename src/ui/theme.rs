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
}
