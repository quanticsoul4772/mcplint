//! Output abstraction layer for consistent CLI output
//!
//! Provides automatic detection of output mode (interactive, CI, plain)
//! and centralized print functions that respect the current mode.

use std::io::{self, IsTerminal, Write};

/// Output mode for the CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Interactive terminal with colors and unicode
    Interactive,
    /// CI environment - plain text, no colors
    CI,
    /// Piped output - plain text, no colors
    Plain,
}

impl OutputMode {
    /// Detect the appropriate output mode based on environment
    pub fn detect() -> Self {
        // Check if running in CI
        if is_ci::cached() {
            return OutputMode::CI;
        }

        // Check if stdout is a terminal
        if io::stdout().is_terminal() {
            OutputMode::Interactive
        } else {
            OutputMode::Plain
        }
    }

    /// Whether colors should be used
    pub fn colors_enabled(&self) -> bool {
        matches!(self, OutputMode::Interactive)
    }

    /// Whether unicode symbols should be used
    pub fn unicode_enabled(&self) -> bool {
        matches!(self, OutputMode::Interactive)
    }

    /// Whether progress bars should be shown
    pub fn progress_enabled(&self) -> bool {
        matches!(self, OutputMode::Interactive)
    }
}

impl Default for OutputMode {
    fn default() -> Self {
        Self::detect()
    }
}

/// Centralized printer that respects output mode
#[derive(Debug, Clone)]
pub struct Printer {
    mode: OutputMode,
}

impl Default for Printer {
    fn default() -> Self {
        Self::new()
    }
}

impl Printer {
    /// Create a new printer with auto-detected mode
    pub fn new() -> Self {
        Self {
            mode: OutputMode::detect(),
        }
    }

    /// Create a printer with a specific mode
    pub fn with_mode(mode: OutputMode) -> Self {
        Self { mode }
    }

    /// Get the current output mode
    pub fn mode(&self) -> OutputMode {
        self.mode
    }

    /// Print a line to stdout
    pub fn println(&self, message: &str) {
        println!("{}", message);
    }

    /// Print to stdout without newline
    #[allow(dead_code)]
    pub fn print(&self, message: &str) {
        print!("{}", message);
        let _ = io::stdout().flush();
    }

    /// Print a blank line
    pub fn newline(&self) {
        println!();
    }

    /// Print a separator line
    pub fn separator(&self) {
        if self.mode.unicode_enabled() {
            println!("{}", "━".repeat(60));
        } else {
            println!("{}", "-".repeat(60));
        }
    }

    /// Print a header with emphasis
    pub fn header(&self, text: &str) {
        use colored::Colorize;
        if self.mode.colors_enabled() {
            println!("{}", text.cyan().bold());
        } else {
            println!("{}", text);
        }
    }

    /// Print a success message
    pub fn success(&self, message: &str) {
        use colored::Colorize;
        let symbol = if self.mode.unicode_enabled() {
            "✓"
        } else {
            "[OK]"
        };
        if self.mode.colors_enabled() {
            println!("{} {}", symbol.green(), message.green());
        } else {
            println!("{} {}", symbol, message);
        }
    }

    /// Print an error message
    pub fn error(&self, message: &str) {
        use colored::Colorize;
        let symbol = if self.mode.unicode_enabled() {
            "✗"
        } else {
            "[ERROR]"
        };
        if self.mode.colors_enabled() {
            eprintln!("{} {}", symbol.red(), message.red());
        } else {
            eprintln!("{} {}", symbol, message);
        }
    }

    /// Print a warning message
    #[allow(dead_code)]
    pub fn warning(&self, message: &str) {
        use colored::Colorize;
        let symbol = if self.mode.unicode_enabled() {
            "⚠"
        } else {
            "[WARN]"
        };
        if self.mode.colors_enabled() {
            println!("{} {}", symbol.yellow(), message.yellow());
        } else {
            println!("{} {}", symbol, message);
        }
    }

    /// Print an info message
    #[allow(dead_code)]
    pub fn info(&self, message: &str) {
        use colored::Colorize;
        let symbol = if self.mode.unicode_enabled() {
            "ℹ"
        } else {
            "[INFO]"
        };
        if self.mode.colors_enabled() {
            println!("{} {}", symbol.cyan(), message);
        } else {
            println!("{} {}", symbol, message);
        }
    }

    /// Print a bullet point item
    #[allow(dead_code)]
    pub fn bullet(&self, message: &str) {
        let symbol = if self.mode.unicode_enabled() {
            "•"
        } else {
            "-"
        };
        println!("  {} {}", symbol, message);
    }

    /// Print a key-value pair
    pub fn kv(&self, key: &str, value: &str) {
        use colored::Colorize;
        if self.mode.colors_enabled() {
            println!("  {}: {}", key.cyan(), value);
        } else {
            println!("  {}: {}", key, value);
        }
    }

    /// Print a labeled section header
    #[allow(dead_code)]
    pub fn section(&self, label: &str, value: &str) {
        use colored::Colorize;
        if self.mode.colors_enabled() {
            println!("{} {}", label.cyan(), value.yellow().bold());
        } else {
            println!("{} {}", label, value);
        }
    }

    /// Print dimmed/secondary text
    #[allow(dead_code)]
    pub fn dimmed(&self, message: &str) {
        use colored::Colorize;
        if self.mode.colors_enabled() {
            println!("{}", message.dimmed());
        } else {
            println!("{}", message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_mode_colors() {
        assert!(OutputMode::Interactive.colors_enabled());
        assert!(!OutputMode::CI.colors_enabled());
        assert!(!OutputMode::Plain.colors_enabled());
    }

    #[test]
    fn output_mode_unicode() {
        assert!(OutputMode::Interactive.unicode_enabled());
        assert!(!OutputMode::CI.unicode_enabled());
        assert!(!OutputMode::Plain.unicode_enabled());
    }

    #[test]
    fn output_mode_progress() {
        assert!(OutputMode::Interactive.progress_enabled());
        assert!(!OutputMode::CI.progress_enabled());
        assert!(!OutputMode::Plain.progress_enabled());
    }

    #[test]
    fn printer_with_mode() {
        let printer = Printer::with_mode(OutputMode::CI);
        assert_eq!(printer.mode(), OutputMode::CI);
    }

    #[test]
    fn printer_default() {
        let printer = Printer::default();
        // Mode depends on environment, just verify it doesn't panic
        let _ = printer.mode();
    }
}
