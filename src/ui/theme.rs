//! Theme system for consistent CLI colors and styling
//!
//! Provides severity-based coloring for security findings and UI elements.

use colored::{Color, Colorize};

/// Security severity levels with associated colors
/// Ordered from least to most severe for proper comparison (Info < Low < Medium < High < Critical)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational finding (dim/gray)
    Info,
    /// Low severity issue (blue)
    Low,
    /// Medium severity issue (yellow)
    Medium,
    /// High severity issue (red)
    High,
    /// Critical security issue (red, bold)
    Critical,
}

impl Severity {
    /// Get the color associated with this severity
    pub fn color(&self) -> Color {
        match self {
            Severity::Info => Color::BrightBlack,
            Severity::Low => Color::Blue,
            Severity::Medium => Color::Yellow,
            Severity::High => Color::Red,
            Severity::Critical => Color::Red,
        }
    }

    /// Get a styled string representation
    pub fn styled(&self) -> colored::ColoredString {
        match self {
            Severity::Info => "INFO".dimmed(),
            Severity::Low => "LOW".blue(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::High => "HIGH".red(),
            Severity::Critical => "CRITICAL".red().bold(),
        }
    }

    /// Get icon for this severity
    pub fn icon(&self) -> &'static str {
        match self {
            Severity::Info => "⚪",
            Severity::Low => "🔵",
            Severity::Medium => "🟡",
            Severity::High => "🟠",
            Severity::Critical => "🔴",
        }
    }
}

/// Theme configuration for mcplint CLI output
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
    pub fn plain() -> Self {
        Self {
            colors_enabled: false,
            unicode_enabled: false,
        }
    }

    /// Create a theme for CI environments
    pub fn ci() -> Self {
        Self {
            colors_enabled: false,
            unicode_enabled: false,
        }
    }
}

/// Security-focused theme with predefined styles
pub struct SecurityTheme;

impl SecurityTheme {
    /// Style text by severity
    pub fn severity(text: &str, severity: Severity) -> String {
        text.color(severity.color()).to_string()
    }

    /// Style for success messages
    pub fn success(text: &str) -> colored::ColoredString {
        text.green().bold()
    }

    /// Style for error messages
    pub fn error(text: &str) -> colored::ColoredString {
        text.red().bold()
    }

    /// Style for warning messages
    pub fn warning(text: &str) -> colored::ColoredString {
        text.yellow()
    }

    /// Style for informational messages
    pub fn info(text: &str) -> colored::ColoredString {
        text.cyan()
    }

    /// Style for dimmed/secondary text
    pub fn dimmed(text: &str) -> colored::ColoredString {
        text.dimmed()
    }

    /// Style for highlighted/emphasized text
    pub fn highlight(text: &str) -> colored::ColoredString {
        text.yellow().bold()
    }

    /// Style for command/code text
    pub fn code(text: &str) -> colored::ColoredString {
        text.cyan()
    }

    /// Horizontal separator line
    pub fn separator() -> colored::ColoredString {
        "━".repeat(60).dimmed()
    }

    /// Check mark for success
    pub fn check_mark() -> &'static str {
        "✓"
    }

    /// X mark for failure
    pub fn x_mark() -> &'static str {
        "✗"
    }

    /// Warning symbol
    pub fn warning_symbol() -> &'static str {
        "⚠"
    }

    /// Arrow for recommendations/suggestions
    pub fn arrow() -> &'static str {
        "→"
    }

    /// Bullet point
    pub fn bullet() -> &'static str {
        "•"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_colors() {
        assert_eq!(Severity::Critical.color(), Color::Red);
        assert_eq!(Severity::High.color(), Color::Red);
        assert_eq!(Severity::Medium.color(), Color::Yellow);
        assert_eq!(Severity::Low.color(), Color::Blue);
    }

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
}
