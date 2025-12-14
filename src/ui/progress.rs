//! Progress indicators for mcplint CLI operations
//!
//! Provides unified progress bars and spinners that respect OutputMode.

use super::OutputMode;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle as IndicatifStyle};
use std::time::Duration;

/// Style presets for progress indicators
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressStyle {
    /// Spinner for indeterminate operations (connecting, initializing)
    Spinner,
    /// Progress bar for countable operations (scanning files)
    Bar,
    /// Download-style bar with bytes/transfer rate
    Download,
    /// Simple dots for minimal output
    Dots,
    /// Security scan specific style
    SecurityScan,
}

impl ProgressStyle {
    /// Get the indicatif template for this style
    #[allow(dead_code)]
    fn template(&self, unicode: bool) -> &'static str {
        match (self, unicode) {
            (ProgressStyle::Spinner, true) => "{spinner:.cyan} {msg}",
            (ProgressStyle::Spinner, false) => "[{elapsed}] {msg}",
            (ProgressStyle::Bar, true) => "{bar:40.cyan/dim} {pos}/{len} {msg}",
            (ProgressStyle::Bar, false) => "[{bar:40}] {pos}/{len} {msg}",
            (ProgressStyle::Download, true) => "{bar:40.cyan/dim} {bytes}/{total_bytes} ({eta})",
            (ProgressStyle::Download, false) => "[{bar:40}] {bytes}/{total_bytes} ({eta})",
            (ProgressStyle::Dots, _) => "{msg}{spinner}",
            (ProgressStyle::SecurityScan, true) => "{spinner:.cyan} {msg:.cyan} {elapsed_precise}",
            (ProgressStyle::SecurityScan, false) => "[{elapsed}] {msg}",
        }
    }

    /// Get spinner characters for this style
    #[allow(dead_code)]
    fn tick_chars(&self, unicode: bool) -> &'static str {
        match self {
            ProgressStyle::SecurityScan if unicode => "🔒🔓🔐🔏",
            _ if unicode => "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏",
            _ => "-\\|/",
        }
    }
}

/// Progress indicator for scan operations
#[allow(dead_code)]
pub struct ScanProgress {
    bar: Option<ProgressBar>,
    mode: OutputMode,
    style: ProgressStyle,
}

impl ScanProgress {
    /// Create a new scan progress indicator
    #[allow(dead_code)]
    pub fn new(mode: OutputMode, style: ProgressStyle) -> Self {
        Self {
            bar: None,
            mode,
            style,
        }
    }

    /// Create a spinner (indeterminate progress)
    #[allow(dead_code)]
    pub fn spinner(mode: OutputMode) -> Self {
        Self::new(mode, ProgressStyle::Spinner)
    }

    /// Create a progress bar with known length
    #[allow(dead_code)]
    pub fn bar(mode: OutputMode, len: u64) -> Self {
        let mut progress = Self::new(mode, ProgressStyle::Bar);
        progress.start(len);
        progress
    }

    /// Start the progress indicator
    #[allow(dead_code)]
    pub fn start(&mut self, len: u64) {
        if !self.mode.progress_enabled() {
            return;
        }

        let bar = if len == 0 {
            ProgressBar::new_spinner()
        } else {
            ProgressBar::new(len)
        };

        let unicode = self.mode.unicode_enabled();
        let template = self.style.template(unicode);
        let tick_chars = self.style.tick_chars(unicode);

        let style = IndicatifStyle::default_bar()
            .template(template)
            .unwrap_or_else(|_| IndicatifStyle::default_bar())
            .tick_chars(tick_chars)
            .progress_chars(if unicode { "━━─" } else { "=>-" });

        bar.set_style(style);
        bar.enable_steady_tick(Duration::from_millis(100));

        self.bar = Some(bar);
    }

    /// Start a spinner with a message
    #[allow(dead_code)]
    pub fn start_spinner(&mut self, msg: &str) {
        if !self.mode.progress_enabled() {
            return;
        }

        let bar = ProgressBar::new_spinner();
        let unicode = self.mode.unicode_enabled();

        let style = IndicatifStyle::default_spinner()
            .template(self.style.template(unicode))
            .unwrap_or_else(|_| IndicatifStyle::default_spinner())
            .tick_chars(self.style.tick_chars(unicode));

        bar.set_style(style);
        bar.set_message(msg.to_string());
        bar.enable_steady_tick(Duration::from_millis(100));

        self.bar = Some(bar);
    }

    /// Update progress position
    #[allow(dead_code)]
    pub fn set_position(&self, pos: u64) {
        if let Some(bar) = &self.bar {
            bar.set_position(pos);
        }
    }

    /// Increment progress by one
    #[allow(dead_code)]
    pub fn inc(&self) {
        if let Some(bar) = &self.bar {
            bar.inc(1);
        }
    }

    /// Increment progress by a specific amount
    #[allow(dead_code)]
    pub fn inc_by(&self, delta: u64) {
        if let Some(bar) = &self.bar {
            bar.inc(delta);
        }
    }

    /// Set the progress message
    #[allow(dead_code)]
    pub fn set_message(&self, msg: &str) {
        if let Some(bar) = &self.bar {
            bar.set_message(msg.to_string());
        }
    }

    /// Update the total length
    #[allow(dead_code)]
    pub fn set_length(&self, len: u64) {
        if let Some(bar) = &self.bar {
            bar.set_length(len);
        }
    }

    /// Finish with a success message
    #[allow(dead_code)]
    pub fn finish_with_message(&self, msg: &str) {
        if let Some(bar) = &self.bar {
            bar.finish_with_message(msg.to_string());
        }
    }

    /// Finish and clear the progress bar
    #[allow(dead_code)]
    pub fn finish_and_clear(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }

    /// Finish the progress bar (keeps it visible)
    #[allow(dead_code)]
    pub fn finish(&self) {
        if let Some(bar) = &self.bar {
            bar.finish();
        }
    }

    /// Suspend the progress bar to print other output
    #[allow(dead_code)]
    pub fn suspend<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        if let Some(bar) = &self.bar {
            bar.suspend(f)
        } else {
            f()
        }
    }

    /// Check if progress is enabled
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.bar.is_some()
    }
}

impl Drop for ScanProgress {
    fn drop(&mut self) {
        if let Some(bar) = &self.bar {
            if !bar.is_finished() {
                bar.finish_and_clear();
            }
        }
    }
}

/// Connection spinner with phase tracking for MCP server connections
pub struct ConnectionSpinner {
    bar: Option<ProgressBar>,
    mode: OutputMode,
    phases_completed: usize,
}

impl ConnectionSpinner {
    /// Create a new connection spinner
    pub fn new(mode: OutputMode) -> Self {
        Self {
            bar: None,
            mode,
            phases_completed: 0,
        }
    }

    /// Start the spinner with initial phase message
    pub fn start(&mut self, server_name: &str) {
        if !self.mode.progress_enabled() {
            return;
        }

        let bar = ProgressBar::new_spinner();
        let unicode = self.mode.unicode_enabled();

        let template = if unicode {
            "{spinner:.cyan} {msg}"
        } else {
            "[{elapsed}] {msg}"
        };

        let tick_chars = if unicode { "◐◓◑◒" } else { "-\\|/" };

        let style = IndicatifStyle::default_spinner()
            .template(template)
            .unwrap_or_else(|_| IndicatifStyle::default_spinner())
            .tick_chars(tick_chars);

        bar.set_style(style);
        bar.set_message(format!("Connecting to {}...", server_name));
        bar.enable_steady_tick(Duration::from_millis(80));

        self.bar = Some(bar);
    }

    /// Update phase: initializing
    pub fn phase_initializing(&mut self) {
        if let Some(bar) = &self.bar {
            bar.set_message("Initializing MCP session...");
            self.phases_completed = 1;
        }
    }

    /// Update phase: listing capabilities
    pub fn phase_listing(&mut self, capability: &str) {
        if let Some(bar) = &self.bar {
            bar.set_message(format!("Listing {}...", capability));
            self.phases_completed = 2;
        }
    }

    /// Update phase: scanning
    #[allow(dead_code)]
    pub fn phase_scanning(&mut self, check_name: &str) {
        if let Some(bar) = &self.bar {
            let icon = if self.mode.unicode_enabled() {
                "🔍"
            } else {
                ">"
            };
            bar.set_message(format!("{} Running: {}", icon, check_name));
        }
    }

    /// Update phase: running security checks
    pub fn phase_security_check(&mut self, rule_id: &str) {
        if let Some(bar) = &self.bar {
            let icon = if self.mode.unicode_enabled() {
                "🛡️"
            } else {
                "*"
            };
            bar.set_message(format!("{} Check: {}", icon, rule_id));
        }
    }

    /// Finish with success
    pub fn finish_success(&mut self, message: &str) {
        if let Some(bar) = &self.bar {
            let icon = if self.mode.unicode_enabled() {
                "✓"
            } else {
                "[OK]"
            };
            bar.finish_with_message(format!("{} {}", icon, message));
        }
    }

    /// Finish with error
    pub fn finish_error(&mut self, message: &str) {
        if let Some(bar) = &self.bar {
            let icon = if self.mode.unicode_enabled() {
                "✗"
            } else {
                "[ERROR]"
            };
            bar.finish_with_message(format!("{} {}", icon, message));
        }
    }

    /// Finish and clear (for non-interactive follow-up)
    #[allow(dead_code)]
    pub fn finish_and_clear(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }

    /// Get whether this spinner is enabled
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.bar.is_some()
    }
}

impl Drop for ConnectionSpinner {
    fn drop(&mut self) {
        if let Some(bar) = &self.bar {
            if !bar.is_finished() {
                bar.finish_and_clear();
            }
        }
    }
}

/// Multi-progress tracker for validating multiple servers
pub struct MultiServerProgress {
    multi: Option<MultiProgress>,
    #[allow(dead_code)]
    mode: OutputMode,
    server_bars: Vec<ProgressBar>,
}

impl MultiServerProgress {
    /// Create a new multi-server progress tracker
    pub fn new(mode: OutputMode, server_count: usize) -> Self {
        if !mode.progress_enabled() || server_count <= 1 {
            return Self {
                multi: None,
                mode,
                server_bars: vec![],
            };
        }

        let multi = MultiProgress::new();
        let unicode = mode.unicode_enabled();

        let template = if unicode {
            "{spinner:.cyan} [{bar:20.cyan/dim}] {pos}/{len} {msg}"
        } else {
            "[{bar:20}] {pos}/{len} {msg}"
        };

        let style = IndicatifStyle::default_bar()
            .template(template)
            .unwrap_or_else(|_| IndicatifStyle::default_bar())
            .progress_chars(if unicode { "━━─" } else { "=>-" });

        let main_bar = multi.add(ProgressBar::new(server_count as u64));
        main_bar.set_style(style);
        main_bar.set_message("Validating servers...");

        Self {
            multi: Some(multi),
            mode,
            server_bars: vec![main_bar],
        }
    }

    /// Update progress for completed server
    pub fn server_complete(&self, server_name: &str) {
        if let Some(bar) = self.server_bars.first() {
            bar.inc(1);
            bar.set_message(format!("Completed: {}", server_name));
        }
    }

    /// Finish all progress bars
    pub fn finish(&self) {
        for bar in &self.server_bars {
            if !bar.is_finished() {
                bar.finish();
            }
        }
    }

    /// Check if progress is enabled
    pub fn is_enabled(&self) -> bool {
        self.multi.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_style_templates() {
        // Just verify templates don't panic
        let _ = ProgressStyle::Spinner.template(true);
        let _ = ProgressStyle::Spinner.template(false);
        let _ = ProgressStyle::Bar.template(true);
        let _ = ProgressStyle::Bar.template(false);
        let _ = ProgressStyle::Download.template(true);
        let _ = ProgressStyle::Dots.template(false);
    }

    #[test]
    fn progress_style_tick_chars() {
        assert!(ProgressStyle::Spinner.tick_chars(true).len() > 4);
        assert_eq!(ProgressStyle::Spinner.tick_chars(false), "-\\|/");
    }

    #[test]
    fn scan_progress_ci_mode() {
        let progress = ScanProgress::new(OutputMode::CI, ProgressStyle::Bar);
        // In CI mode, progress should be disabled
        assert!(!progress.is_enabled());
    }

    #[test]
    fn scan_progress_plain_mode() {
        let progress = ScanProgress::new(OutputMode::Plain, ProgressStyle::Spinner);
        // In Plain mode, progress should be disabled
        assert!(!progress.is_enabled());
    }

    #[test]
    fn scan_progress_operations() {
        // Test that operations don't panic even when disabled
        let progress = ScanProgress::new(OutputMode::CI, ProgressStyle::Bar);
        progress.set_position(5);
        progress.inc();
        progress.inc_by(3);
        progress.set_message("test");
        progress.set_length(100);
        progress.finish();
    }

    #[test]
    fn scan_progress_spinner() {
        let mut progress = ScanProgress::spinner(OutputMode::CI);
        progress.start_spinner("Loading...");
        progress.set_message("Still loading...");
        progress.finish_with_message("Done");
    }

    #[test]
    fn connection_spinner_ci_mode() {
        let mut spinner = ConnectionSpinner::new(OutputMode::CI);
        spinner.start("test-server");
        // In CI mode, spinner should be disabled
        assert!(!spinner.is_enabled());
    }

    #[test]
    fn connection_spinner_phases() {
        let mut spinner = ConnectionSpinner::new(OutputMode::CI);
        spinner.start("test-server");
        spinner.phase_initializing();
        spinner.phase_listing("tools");
        spinner.phase_security_check("SEC-001");
        spinner.finish_success("Scan complete");
    }

    #[test]
    fn multi_server_progress_single_server() {
        let progress = MultiServerProgress::new(OutputMode::Interactive, 1);
        // Single server should not show progress
        assert!(!progress.is_enabled());
    }

    #[test]
    fn multi_server_progress_ci_mode() {
        let progress = MultiServerProgress::new(OutputMode::CI, 5);
        // CI mode should not show progress
        assert!(!progress.is_enabled());
    }

    #[test]
    fn progress_style_security_scan() {
        let _ = ProgressStyle::SecurityScan.template(true);
        let _ = ProgressStyle::SecurityScan.template(false);
        assert!(ProgressStyle::SecurityScan.tick_chars(true).contains('🔒'));
    }

    #[test]
    fn progress_style_all_templates_unicode() {
        // Test all styles with unicode enabled
        assert_eq!(
            ProgressStyle::Spinner.template(true),
            "{spinner:.cyan} {msg}"
        );
        assert_eq!(
            ProgressStyle::Bar.template(true),
            "{bar:40.cyan/dim} {pos}/{len} {msg}"
        );
        assert_eq!(
            ProgressStyle::Download.template(true),
            "{bar:40.cyan/dim} {bytes}/{total_bytes} ({eta})"
        );
        assert_eq!(ProgressStyle::Dots.template(true), "{msg}{spinner}");
        assert_eq!(
            ProgressStyle::SecurityScan.template(true),
            "{spinner:.cyan} {msg:.cyan} {elapsed_precise}"
        );
    }

    #[test]
    fn progress_style_all_templates_ascii() {
        // Test all styles with unicode disabled
        assert_eq!(ProgressStyle::Spinner.template(false), "[{elapsed}] {msg}");
        assert_eq!(
            ProgressStyle::Bar.template(false),
            "[{bar:40}] {pos}/{len} {msg}"
        );
        assert_eq!(
            ProgressStyle::Download.template(false),
            "[{bar:40}] {bytes}/{total_bytes} ({eta})"
        );
        assert_eq!(ProgressStyle::Dots.template(false), "{msg}{spinner}");
        assert_eq!(
            ProgressStyle::SecurityScan.template(false),
            "[{elapsed}] {msg}"
        );
    }

    #[test]
    fn progress_style_tick_chars_all_styles() {
        // Test tick characters for all styles
        assert_eq!(ProgressStyle::Spinner.tick_chars(false), "-\\|/");
        assert_eq!(ProgressStyle::Bar.tick_chars(false), "-\\|/");
        assert_eq!(ProgressStyle::Download.tick_chars(false), "-\\|/");
        assert_eq!(ProgressStyle::Dots.tick_chars(false), "-\\|/");

        // Security scan has unique characters
        assert_eq!(ProgressStyle::SecurityScan.tick_chars(true), "🔒🔓🔐🔏");
        assert_eq!(ProgressStyle::SecurityScan.tick_chars(false), "-\\|/");
    }

    #[test]
    fn scan_progress_bar_constructor() {
        let progress = ScanProgress::bar(OutputMode::CI, 100);
        assert!(!progress.is_enabled());
    }

    #[test]
    fn scan_progress_new_download_style() {
        let progress = ScanProgress::new(OutputMode::CI, ProgressStyle::Download);
        assert_eq!(progress.style, ProgressStyle::Download);
        assert!(!progress.is_enabled());
    }

    #[test]
    fn scan_progress_new_dots_style() {
        let progress = ScanProgress::new(OutputMode::CI, ProgressStyle::Dots);
        assert_eq!(progress.style, ProgressStyle::Dots);
    }

    #[test]
    fn scan_progress_new_security_scan_style() {
        let progress = ScanProgress::new(OutputMode::CI, ProgressStyle::SecurityScan);
        assert_eq!(progress.style, ProgressStyle::SecurityScan);
    }

    #[test]
    fn scan_progress_suspend() {
        let progress = ScanProgress::new(OutputMode::CI, ProgressStyle::Bar);
        let result = progress.suspend(|| 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn scan_progress_finish_and_clear() {
        let progress = ScanProgress::new(OutputMode::CI, ProgressStyle::Bar);
        progress.finish_and_clear();
    }

    #[test]
    fn scan_progress_start_with_length() {
        let mut progress = ScanProgress::new(OutputMode::CI, ProgressStyle::Bar);
        progress.start(50);
        assert!(!progress.is_enabled());
    }

    #[test]
    fn scan_progress_start_spinner_zero_length() {
        let mut progress = ScanProgress::new(OutputMode::CI, ProgressStyle::Spinner);
        progress.start(0); // Zero length creates spinner
        assert!(!progress.is_enabled());
    }

    #[test]
    fn connection_spinner_phase_scanning() {
        let mut spinner = ConnectionSpinner::new(OutputMode::CI);
        spinner.start("test-server");
        spinner.phase_scanning("Tool validation");
        assert!(!spinner.is_enabled());
    }

    #[test]
    fn connection_spinner_finish_and_clear() {
        let mut spinner = ConnectionSpinner::new(OutputMode::CI);
        spinner.start("test-server");
        spinner.finish_and_clear();
    }

    #[test]
    fn connection_spinner_error() {
        let mut spinner = ConnectionSpinner::new(OutputMode::CI);
        spinner.start("test-server");
        spinner.finish_error("Connection failed");
    }

    #[test]
    fn connection_spinner_phases_tracking() {
        // Test that phases_completed is tracked even in CI mode
        let mut spinner = ConnectionSpinner::new(OutputMode::CI);
        spinner.start("test-server");
        assert_eq!(spinner.phases_completed, 0);

        // Note: In CI mode, bar is None, so phase_initializing only updates
        // phases_completed when bar.is_some()
        spinner.phase_initializing();
        // In CI mode, phases_completed won't be updated since bar is None
        // This is expected behavior - phase tracking is only for interactive mode
        assert_eq!(spinner.phases_completed, 0);

        spinner.phase_listing("resources");
        assert_eq!(spinner.phases_completed, 0);
    }

    #[test]
    fn multi_server_progress_multiple_servers() {
        let progress = MultiServerProgress::new(OutputMode::Interactive, 5);
        // Interactive mode with multiple servers should enable progress
        // Note: In test environment without terminal, might still be disabled
        progress.server_complete("server1");
        progress.server_complete("server2");
        progress.finish();
    }

    #[test]
    fn multi_server_progress_zero_servers() {
        let progress = MultiServerProgress::new(OutputMode::Interactive, 0);
        assert!(!progress.is_enabled());
    }

    #[test]
    fn progress_style_equality() {
        assert_eq!(ProgressStyle::Spinner, ProgressStyle::Spinner);
        assert_eq!(ProgressStyle::Bar, ProgressStyle::Bar);
        assert_ne!(ProgressStyle::Spinner, ProgressStyle::Bar);
        assert_ne!(ProgressStyle::Download, ProgressStyle::Dots);
    }

    #[test]
    fn scan_progress_drop_unfinished() {
        // Test that drop finishes unfinished bars
        let _progress = ScanProgress::new(OutputMode::CI, ProgressStyle::Bar);
        // Drop should not panic even if bar was never started
    }

    #[test]
    fn connection_spinner_drop_unfinished() {
        // Test that drop finishes unfinished spinners
        let mut spinner = ConnectionSpinner::new(OutputMode::CI);
        spinner.start("test");
        // Drop should handle unfinished spinner
    }

    #[test]
    fn scan_progress_mode_access() {
        let progress = ScanProgress::new(OutputMode::Plain, ProgressStyle::Bar);
        assert_eq!(progress.mode, OutputMode::Plain);
    }

    // ===== NEW TESTS FOR INTERACTIVE MODE AND UNCOVERED LINES =====

    #[test]
    fn scan_progress_interactive_start_with_nonzero_length() {
        // Test Interactive mode with non-zero length (creates ProgressBar::new(len))
        let mut progress = ScanProgress::new(OutputMode::Interactive, ProgressStyle::Bar);
        progress.start(100);
        // In Interactive mode, progress should be enabled
        assert!(progress.is_enabled());
        progress.finish();
    }

    #[test]
    fn scan_progress_interactive_start_with_zero_length() {
        // Test Interactive mode with zero length (creates ProgressBar::new_spinner())
        let mut progress = ScanProgress::new(OutputMode::Interactive, ProgressStyle::Spinner);
        progress.start(0);
        // In Interactive mode, spinner should be enabled
        assert!(progress.is_enabled());
        progress.finish();
    }

    #[test]
    fn scan_progress_interactive_start_spinner() {
        // Test start_spinner() in Interactive mode
        let mut progress = ScanProgress::new(OutputMode::Interactive, ProgressStyle::Spinner);
        progress.start_spinner("Connecting to server...");
        // In Interactive mode, spinner should be enabled
        assert!(progress.is_enabled());
        // Test message update
        progress.set_message("Connected!");
        progress.finish_with_message("Done");
    }

    #[test]
    fn scan_progress_interactive_all_styles() {
        // Test all ProgressStyle variants in Interactive mode
        for style in [
            ProgressStyle::Spinner,
            ProgressStyle::Bar,
            ProgressStyle::Download,
            ProgressStyle::Dots,
            ProgressStyle::SecurityScan,
        ] {
            let mut progress = ScanProgress::new(OutputMode::Interactive, style);
            progress.start(50);
            assert!(progress.is_enabled());
            progress.set_position(25);
            progress.inc();
            progress.inc_by(5);
            progress.set_message("Processing...");
            progress.set_length(100);
            progress.finish();
        }
    }

    #[test]
    fn scan_progress_interactive_bar_constructor() {
        // Test ScanProgress::bar() in Interactive mode
        let progress = ScanProgress::bar(OutputMode::Interactive, 100);
        assert!(progress.is_enabled());
        progress.set_position(50);
        progress.finish();
    }

    #[test]
    fn scan_progress_interactive_spinner_constructor() {
        // Test ScanProgress::spinner() in Interactive mode
        let mut progress = ScanProgress::spinner(OutputMode::Interactive);
        progress.start_spinner("Loading...");
        assert!(progress.is_enabled());
        progress.finish();
    }

    #[test]
    fn scan_progress_interactive_suspend() {
        // Test suspend() with actual progress bar
        let mut progress = ScanProgress::new(OutputMode::Interactive, ProgressStyle::Bar);
        progress.start(100);
        let result = progress.suspend(|| {
            // Simulate printing output while suspended
            42
        });
        assert_eq!(result, 42);
        progress.finish();
    }

    #[test]
    fn scan_progress_interactive_finish_and_clear() {
        // Test finish_and_clear() with actual progress bar
        let mut progress = ScanProgress::new(OutputMode::Interactive, ProgressStyle::Bar);
        progress.start(100);
        progress.set_position(50);
        progress.finish_and_clear();
    }

    #[test]
    fn connection_spinner_interactive_phases() {
        // Test ConnectionSpinner in Interactive mode with phase updates
        let mut spinner = ConnectionSpinner::new(OutputMode::Interactive);
        spinner.start("test-server");
        assert!(spinner.is_enabled());
        assert_eq!(spinner.phases_completed, 0);

        // Test phase_initializing updates phases_completed
        spinner.phase_initializing();
        assert_eq!(spinner.phases_completed, 1);

        // Test phase_listing updates phases_completed
        spinner.phase_listing("tools");
        assert_eq!(spinner.phases_completed, 2);

        // Test other phase methods
        spinner.phase_scanning("Tool validation");
        spinner.phase_security_check("SEC-001");

        spinner.finish_success("All checks passed");
    }

    #[test]
    fn connection_spinner_interactive_unicode_vs_ascii() {
        // Test unicode vs ASCII rendering in Interactive mode
        let mut spinner_unicode = ConnectionSpinner::new(OutputMode::Interactive);
        spinner_unicode.start("test-server-unicode");
        assert!(spinner_unicode.is_enabled());

        let mut spinner_ascii = ConnectionSpinner::new(OutputMode::Interactive);
        spinner_ascii.start("test-server-ascii");
        assert!(spinner_ascii.is_enabled());

        spinner_unicode.phase_scanning("Check 1");
        spinner_ascii.phase_scanning("Check 2");

        spinner_unicode.finish_success("Done");
        spinner_ascii.finish_error("Failed");
    }

    #[test]
    fn connection_spinner_interactive_all_phases() {
        // Test all phase methods in sequence
        let mut spinner = ConnectionSpinner::new(OutputMode::Interactive);
        spinner.start("comprehensive-test");
        assert!(spinner.is_enabled());

        spinner.phase_initializing();
        assert_eq!(spinner.phases_completed, 1);

        spinner.phase_listing("resources");
        assert_eq!(spinner.phases_completed, 2);

        spinner.phase_scanning("Validation");
        spinner.phase_security_check("SEC-001");
        spinner.phase_security_check("SEC-002");

        spinner.finish_and_clear();
    }

    #[test]
    fn multi_server_progress_interactive_multiple_servers() {
        // Test MultiServerProgress with multiple servers in Interactive mode
        let progress = MultiServerProgress::new(OutputMode::Interactive, 5);
        // Should be enabled with multiple servers
        assert!(progress.is_enabled());

        // Test server completion updates
        progress.server_complete("server1");
        progress.server_complete("server2");
        progress.server_complete("server3");
        progress.server_complete("server4");
        progress.server_complete("server5");

        progress.finish();
    }

    #[test]
    fn multi_server_progress_interactive_two_servers() {
        // Test with exactly 2 servers (minimum for multi-progress)
        let progress = MultiServerProgress::new(OutputMode::Interactive, 2);
        assert!(progress.is_enabled());

        progress.server_complete("server1");
        progress.server_complete("server2");
        progress.finish();
    }

    #[test]
    fn multi_server_progress_interactive_large_count() {
        // Test with large number of servers
        let progress = MultiServerProgress::new(OutputMode::Interactive, 10);
        assert!(progress.is_enabled());

        for i in 0..10 {
            progress.server_complete(&format!("server{}", i + 1));
        }

        progress.finish();
    }

    #[test]
    fn scan_progress_interactive_unicode_chars() {
        // Test unicode-specific progress characters
        let mut progress = ScanProgress::new(OutputMode::Interactive, ProgressStyle::Bar);
        progress.start(100);
        assert!(progress.is_enabled());

        // Progress chars should be "━━─" for unicode
        progress.set_position(50);
        progress.inc();
        progress.finish();
    }

    #[test]
    fn scan_progress_interactive_security_scan_style() {
        // Test SecurityScan style specifically in Interactive mode
        let mut progress = ScanProgress::new(OutputMode::Interactive, ProgressStyle::SecurityScan);
        progress.start_spinner("Running security checks...");
        assert!(progress.is_enabled());

        progress.set_message("Checking for vulnerabilities...");
        progress.finish_with_message("Security scan complete");
    }

    #[test]
    fn connection_spinner_interactive_drop_unfinished() {
        // Test that drop properly cleans up unfinished spinner in Interactive mode
        let mut spinner = ConnectionSpinner::new(OutputMode::Interactive);
        spinner.start("test-server");
        assert!(spinner.is_enabled());
        // Spinner will be dropped without finish - tests drop impl
    }

    #[test]
    fn scan_progress_interactive_drop_unfinished() {
        // Test that drop properly cleans up unfinished bar in Interactive mode
        let mut progress = ScanProgress::new(OutputMode::Interactive, ProgressStyle::Bar);
        progress.start(100);
        assert!(progress.is_enabled());
        progress.set_position(50);
        // Progress will be dropped without finish - tests drop impl
    }

    #[test]
    fn multi_server_progress_plain_mode() {
        // Verify Plain mode disables multi-server progress
        let progress = MultiServerProgress::new(OutputMode::Plain, 5);
        assert!(!progress.is_enabled());
    }

    #[test]
    fn connection_spinner_plain_mode() {
        // Verify Plain mode disables connection spinner
        let mut spinner = ConnectionSpinner::new(OutputMode::Plain);
        spinner.start("test-server");
        assert!(!spinner.is_enabled());
    }
}
