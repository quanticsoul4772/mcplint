//! User interface components for mcplint CLI
//!
//! This module provides a unified output system for consistent CLI presentation
//! across all commands, with support for:
//! - Interactive terminal output with colors and progress bars
//! - CI-friendly plain text output
//! - Consistent theming for security severity levels
//!
//! # Architecture
//!
//! The UI system is built around three core concepts:
//! 1. **OutputMode**: Detects whether we're in interactive, CI, or plain mode
//! 2. **Theme**: Provides consistent colors for severity levels and UI elements
//! 3. **Progress**: Unified progress indicators (bars, spinners) that respect OutputMode

pub mod output;
pub mod progress;
pub mod theme;

// Re-exports for convenient access
pub use output::{OutputMode, Printer};
pub use progress::{ConnectionSpinner, MultiServerProgress, ProgressStyle, ScanProgress};
pub use theme::{SecurityTheme, Severity, Theme};
