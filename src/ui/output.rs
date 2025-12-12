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

    #[test]
    fn output_mode_detect() {
        // Just verify detection doesn't panic
        let _mode = OutputMode::detect();
    }

    #[test]
    fn output_mode_default() {
        let mode = OutputMode::default();
        // Should be one of the valid modes
        assert!(matches!(
            mode,
            OutputMode::Interactive | OutputMode::CI | OutputMode::Plain
        ));
    }

    #[test]
    fn output_mode_equality() {
        assert_eq!(OutputMode::Interactive, OutputMode::Interactive);
        assert_eq!(OutputMode::CI, OutputMode::CI);
        assert_eq!(OutputMode::Plain, OutputMode::Plain);
        assert_ne!(OutputMode::Interactive, OutputMode::CI);
        assert_ne!(OutputMode::CI, OutputMode::Plain);
    }

    #[test]
    fn output_mode_debug() {
        let mode = OutputMode::Interactive;
        let debug_str = format!("{:?}", mode);
        assert!(debug_str.contains("Interactive"));
    }

    #[test]
    fn output_mode_clone_copy() {
        let mode1 = OutputMode::Interactive;
        let mode2 = mode1;
        assert_eq!(mode1, mode2);
    }

    #[test]
    fn printer_println() {
        let printer = Printer::with_mode(OutputMode::CI);
        // Should not panic
        printer.println("Test message");
    }

    #[test]
    fn printer_print() {
        let printer = Printer::with_mode(OutputMode::CI);
        // Should not panic
        printer.print("Test message");
    }

    #[test]
    fn printer_newline() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.newline();
    }

    #[test]
    fn printer_separator_ci() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.separator();
    }

    #[test]
    fn printer_separator_interactive() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        printer.separator();
    }

    #[test]
    fn printer_header_ci() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.header("Test Header");
    }

    #[test]
    fn printer_header_interactive() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        printer.header("Test Header");
    }

    #[test]
    fn printer_success_ci() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.success("Operation successful");
    }

    #[test]
    fn printer_success_interactive() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        printer.success("Operation successful");
    }

    #[test]
    fn printer_error_ci() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.error("Error occurred");
    }

    #[test]
    fn printer_error_interactive() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        printer.error("Error occurred");
    }

    #[test]
    fn printer_warning_ci() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.warning("Warning message");
    }

    #[test]
    fn printer_warning_interactive() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        printer.warning("Warning message");
    }

    #[test]
    fn printer_info_ci() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.info("Info message");
    }

    #[test]
    fn printer_info_interactive() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        printer.info("Info message");
    }

    #[test]
    fn printer_bullet_ci() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.bullet("Bullet point");
    }

    #[test]
    fn printer_bullet_interactive() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        printer.bullet("Bullet point");
    }

    #[test]
    fn printer_kv_ci() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.kv("Key", "Value");
    }

    #[test]
    fn printer_kv_interactive() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        printer.kv("Key", "Value");
    }

    #[test]
    fn printer_section_ci() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.section("Section", "Content");
    }

    #[test]
    fn printer_section_interactive() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        printer.section("Section", "Content");
    }

    #[test]
    fn printer_dimmed_ci() {
        let printer = Printer::with_mode(OutputMode::CI);
        printer.dimmed("Dimmed text");
    }

    #[test]
    fn printer_dimmed_interactive() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        printer.dimmed("Dimmed text");
    }

    #[test]
    fn printer_clone() {
        let printer1 = Printer::with_mode(OutputMode::CI);
        let printer2 = printer1.clone();
        assert_eq!(printer1.mode(), printer2.mode());
    }

    #[test]
    fn printer_debug() {
        let printer = Printer::with_mode(OutputMode::Interactive);
        let debug_str = format!("{:?}", printer);
        assert!(debug_str.contains("Printer"));
    }

    #[test]
    fn printer_new() {
        let printer = Printer::new();
        // Should not panic and should return a valid mode
        let mode = printer.mode();
        assert!(matches!(
            mode,
            OutputMode::Interactive | OutputMode::CI | OutputMode::Plain
        ));
    }

    #[test]
    fn printer_all_modes_complete_workflow() {
        for mode in [OutputMode::Interactive, OutputMode::CI, OutputMode::Plain] {
            let printer = Printer::with_mode(mode);
            printer.header("Header");
            printer.separator();
            printer.success("Success");
            printer.error("Error");
            printer.warning("Warning");
            printer.info("Info");
            printer.bullet("Bullet");
            printer.kv("Key", "Value");
            printer.section("Section", "Content");
            printer.dimmed("Dimmed");
            printer.newline();
        }
    }

    #[test]
    fn output_mode_plain_flags() {
        let mode = OutputMode::Plain;
        assert!(!mode.colors_enabled());
        assert!(!mode.unicode_enabled());
        assert!(!mode.progress_enabled());
    }
}
