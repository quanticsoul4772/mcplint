//! Progress indicators for mcplint CLI operations
//!
//! Provides unified progress bars and spinners that respect OutputMode.

use super::OutputMode;
use indicatif::{ProgressBar, ProgressStyle as IndicatifStyle};
use std::time::Duration;

/// Style presets for progress indicators
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
}

impl ProgressStyle {
    /// Get the indicatif template for this style
    fn template(&self, unicode: bool) -> &'static str {
        match (self, unicode) {
            (ProgressStyle::Spinner, true) => "{spinner:.cyan} {msg}",
            (ProgressStyle::Spinner, false) => "[{elapsed}] {msg}",
            (ProgressStyle::Bar, true) => "{bar:40.cyan/dim} {pos}/{len} {msg}",
            (ProgressStyle::Bar, false) => "[{bar:40}] {pos}/{len} {msg}",
            (ProgressStyle::Download, true) => "{bar:40.cyan/dim} {bytes}/{total_bytes} ({eta})",
            (ProgressStyle::Download, false) => "[{bar:40}] {bytes}/{total_bytes} ({eta})",
            (ProgressStyle::Dots, _) => "{msg}{spinner}",
        }
    }

    /// Get spinner characters for this style
    fn tick_chars(&self, unicode: bool) -> &'static str {
        if unicode {
            "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        } else {
            "-\\|/"
        }
    }
}

/// Progress indicator for scan operations
pub struct ScanProgress {
    bar: Option<ProgressBar>,
    mode: OutputMode,
    style: ProgressStyle,
}

impl ScanProgress {
    /// Create a new scan progress indicator
    pub fn new(mode: OutputMode, style: ProgressStyle) -> Self {
        Self {
            bar: None,
            mode,
            style,
        }
    }

    /// Create a spinner (indeterminate progress)
    pub fn spinner(mode: OutputMode) -> Self {
        Self::new(mode, ProgressStyle::Spinner)
    }

    /// Create a progress bar with known length
    pub fn bar(mode: OutputMode, len: u64) -> Self {
        let mut progress = Self::new(mode, ProgressStyle::Bar);
        progress.start(len);
        progress
    }

    /// Start the progress indicator
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
    pub fn set_position(&self, pos: u64) {
        if let Some(bar) = &self.bar {
            bar.set_position(pos);
        }
    }

    /// Increment progress by one
    pub fn inc(&self) {
        if let Some(bar) = &self.bar {
            bar.inc(1);
        }
    }

    /// Increment progress by a specific amount
    pub fn inc_by(&self, delta: u64) {
        if let Some(bar) = &self.bar {
            bar.inc(delta);
        }
    }

    /// Set the progress message
    pub fn set_message(&self, msg: &str) {
        if let Some(bar) = &self.bar {
            bar.set_message(msg.to_string());
        }
    }

    /// Update the total length
    pub fn set_length(&self, len: u64) {
        if let Some(bar) = &self.bar {
            bar.set_length(len);
        }
    }

    /// Finish with a success message
    pub fn finish_with_message(&self, msg: &str) {
        if let Some(bar) = &self.bar {
            bar.finish_with_message(msg.to_string());
        }
    }

    /// Finish and clear the progress bar
    pub fn finish_and_clear(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }

    /// Finish the progress bar (keeps it visible)
    pub fn finish(&self) {
        if let Some(bar) = &self.bar {
            bar.finish();
        }
    }

    /// Suspend the progress bar to print other output
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
}
