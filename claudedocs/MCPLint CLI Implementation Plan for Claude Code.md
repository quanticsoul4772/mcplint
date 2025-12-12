# MCPLint CLI Implementation Plan for Claude Code

**Project:** mcplint CLI User Experience Overhaul  
**Location:** `C:\Development\Projects\MCP\project-root\mcp-servers\mcplint`  
**Execution Mode:** Systematic phase-by-phase implementation  
**Safety:** Git commits after each completed task, branch per phase

---

## Overview

This plan transforms mcplint from a functional CLI tool into an exceptional user experience through 6 implementation phases. Each phase is self-contained, testable, and builds upon previous work.

**Total Estimated Tasks:** 47  
**Estimated Duration:** 6-8 weeks (1 week per phase + polish)  
**Primary Crates to Add:** 9 new dependencies  
**Files to Create:** ~25 new files  
**Files to Modify:** ~15 existing files

---

## Pre-Implementation Setup

### SETUP-1: Create Feature Branch
**Priority:** CRITICAL  
**Files:** Git  
**Estimated Time:** 5 minutes

```bash
cd C:\Development\Projects\MCP\project-root\mcp-servers\mcplint
git checkout -b feature/cli-ux-overhaul
git push -u origin feature/cli-ux-overhaul
```

**Acceptance Criteria:**
- [ ] Branch created and pushed
- [ ] GitHub PR created as draft
- [ ] PR description includes link to this implementation plan

---

### SETUP-2: Update Dependencies in Cargo.toml
**Priority:** CRITICAL  
**Files:** `Cargo.toml`  
**Estimated Time:** 10 minutes

Add these dependencies to `[dependencies]` section:

```toml
# Interactive prompts and TUI
dialoguer = { version = "0.12", features = ["fuzzy-select"] }
console = "0.15"
indicatif = "0.18"

# Better colors and styling
owo-colors = { version = "4", features = ["supports-colors"] }

# Enhanced error messages
miette = { version = "7", features = ["fancy"] }
thiserror = "1.0"

# Shell completions
clap_complete = { version = "4.5", features = ["unstable-dynamic"] }

# File watching
notify-debouncer-full = "0.4"

# String similarity for "did you mean"
strsim = "0.11"

# Cancellation handling
tokio-util = { version = "0.7", features = ["sync"] }

# CI detection
is-ci = "1.2"
```

**Acceptance Criteria:**
- [ ] Dependencies added to Cargo.toml
- [ ] `cargo check` passes
- [ ] `cargo build` succeeds
- [ ] Git commit: "chore: add dependencies for CLI UX improvements"

---

### SETUP-3: Create Module Structure
**Priority:** CRITICAL  
**Files:** `src/cli/`, `src/ui/`, `src/output/`  
**Estimated Time:** 15 minutes

Create new directories and module files:

```
src/
├── cli/
│   ├── mod.rs          (existing - update exports)
│   ├── interactive.rs  (new - interactive mode logic)
│   ├── completion.rs   (new - shell completions)
│   └── context.rs      (new - execution context detection)
├── ui/
│   ├── mod.rs          (new - UI components)
│   ├── progress.rs     (new - progress indicators)
│   ├── theme.rs        (new - color schemes)
│   └── table.rs        (new - formatted tables)
├── output/
│   ├── mod.rs          (new - output formatters)
│   ├── formatter.rs    (new - formatter trait)
│   ├── text.rs         (new - enhanced text output)
│   ├── interactive.rs  (new - interactive output)
│   └── ci.rs           (new - CI-optimized output)
└── errors/
    ├── mod.rs          (new - error types)
    └── suggestions.rs  (new - "did you mean" logic)
```

Create empty modules with TODO comments:

```rust
// src/ui/mod.rs
//! User interface components for mcplint CLI

pub mod progress;
pub mod theme;
pub mod table;

// Re-exports
pub use progress::{ScanProgress, MultiFileScanProgress};
pub use theme::{SecurityTheme, get_theme};
pub use table::ResultsTable;
```

**Acceptance Criteria:**
- [ ] All directories created
- [ ] All module files created with proper documentation
- [ ] `cargo check` passes with TODO warnings
- [ ] Git commit: "chore: create module structure for CLI improvements"

---

## Phase 1: Foundation - Context Detection & Output System

**Goal:** Establish smart context detection (TTY, CI, color support) and create flexible output formatter architecture.  
**Duration:** 1 week  
**Risk:** Low - foundational work

---

### P1-T1: Implement Execution Context Detection
**Priority:** CRITICAL  
**Files:** `src/cli/context.rs`  
**Estimated Time:** 2 hours

Create comprehensive context detection:

```rust
// src/cli/context.rs
use std::io::IsTerminal;
use console::Term;

#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub is_tty: bool,
    pub is_ci: bool,
    pub terminal_width: usize,
    pub supports_color: bool,
    pub supports_unicode: bool,
    pub supports_hyperlinks: bool,
}

impl ExecutionContext {
    pub fn detect() -> Self {
        let stdout = std::io::stdout();
        let is_tty = stdout.is_terminal();
        let is_ci = is_ci::cached();
        
        // Respect NO_COLOR standard
        let no_color = std::env::var("NO_COLOR")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        
        let term = Term::stdout();
        
        Self {
            is_tty,
            is_ci,
            terminal_width: term.size().1 as usize,
            supports_color: is_tty && !no_color && !is_ci,
            supports_unicode: console::user_attended(),
            supports_hyperlinks: supports_hyperlinks(),
        }
    }
    
    pub fn is_interactive(&self) -> bool {
        self.is_tty && !self.is_ci
    }
    
    pub fn force_non_interactive() -> Self {
        Self {
            is_tty: false,
            is_ci: true,
            terminal_width: 80,
            supports_color: false,
            supports_unicode: false,
            supports_hyperlinks: false,
        }
    }
}

fn supports_hyperlinks() -> bool {
    // Check TERM_PROGRAM for known terminals with hyperlink support
    match std::env::var("TERM_PROGRAM").as_deref() {
        Ok("iTerm.app") | Ok("WezTerm") | Ok("vscode") => true,
        _ => false,
    }
}
```

**Testing:**
```rust
// tests/context_tests.rs
#[test]
fn test_ci_detection() {
    std::env::set_var("CI", "true");
    let ctx = ExecutionContext::detect();
    assert!(ctx.is_ci);
    assert!(!ctx.is_interactive());
}

#[test]
fn test_no_color_respected() {
    std::env::set_var("NO_COLOR", "1");
    let ctx = ExecutionContext::detect();
    assert!(!ctx.supports_color);
}
```

**Acceptance Criteria:**
- [ ] Context detection works correctly
- [ ] Tests pass for CI, NO_COLOR, TTY detection
- [ ] Git commit: "feat(cli): add execution context detection"

---

### P1-T2: Create Color Theme System
**Priority:** HIGH  
**Files:** `src/ui/theme.rs`  
**Estimated Time:** 1.5 hours

```rust
// src/ui/theme.rs
use owo_colors::{OwoColorize, Style, colors::*};
use crate::scanner::Severity;

pub struct SecurityTheme {
    // Severity colors
    pub critical: Style,
    pub high: Style,
    pub medium: Style,
    pub low: Style,
    pub info: Style,
    
    // UI element colors
    pub success: Style,
    pub error: Style,
    pub warning: Style,
    pub muted: Style,
    pub emphasis: Style,
    pub link: Style,
}

impl SecurityTheme {
    pub fn new() -> Self {
        Self {
            critical: Style::new().fg::<BrightRed>().bold(),
            high: Style::new().fg::<Red>(),
            medium: Style::new().fg::<Yellow>(),
            low: Style::new().fg::<Cyan>(),
            info: Style::new().fg::<White>().dimmed(),
            
            success: Style::new().fg::<Green>(),
            error: Style::new().fg::<Red>(),
            warning: Style::new().fg::<Yellow>(),
            muted: Style::new().dimmed(),
            emphasis: Style::new().bold(),
            link: Style::new().fg::<Blue>().underline(),
        }
    }
    
    pub fn severity_style(&self, severity: &Severity) -> &Style {
        match severity {
            Severity::Critical => &self.critical,
            Severity::High => &self.high,
            Severity::Medium => &self.medium,
            Severity::Low => &self.low,
            Severity::Info => &self.info,
        }
    }
    
    pub fn severity_prefix(&self, severity: &Severity) -> String {
        let (icon, text) = match severity {
            Severity::Critical => ("✖", "CRITICAL"),
            Severity::High => ("✖", "HIGH"),
            Severity::Medium => ("⚠", "MEDIUM"),
            Severity::Low => ("ℹ", "LOW"),
            Severity::Info => ("·", "INFO"),
        };
        format!("{} {}", icon, text).style(*self.severity_style(severity)).to_string()
    }
}

// Global theme access
use std::sync::OnceLock;
static THEME: OnceLock<SecurityTheme> = OnceLock::new();

pub fn get_theme() -> &'static SecurityTheme {
    THEME.get_or_init(SecurityTheme::new)
}

pub fn init_colors(enable: bool) {
    owo_colors::set_override(enable);
}
```

**Acceptance Criteria:**
- [ ] Theme system working
- [ ] Colors respect context (no colors in CI)
- [ ] Git commit: "feat(ui): add semantic color theme system"

---

### P1-T3: Create Output Formatter Trait
**Priority:** CRITICAL  
**Files:** `src/output/formatter.rs`  
**Estimated Time:** 2 hours

```rust
// src/output/formatter.rs
use crate::scanner::{ScanResults, Finding};
use crate::cli::context::ExecutionContext;

pub trait OutputFormatter {
    fn format_start(&self, ctx: &ExecutionContext, target: &str);
    fn format_progress(&self, ctx: &ExecutionContext, message: &str);
    fn format_results(&self, ctx: &ExecutionContext, results: &ScanResults);
    fn format_error(&self, ctx: &ExecutionContext, error: &dyn std::error::Error);
}

pub struct FormatterChain {
    formatters: Vec<Box<dyn OutputFormatter>>,
    context: ExecutionContext,
}

impl FormatterChain {
    pub fn new(context: ExecutionContext) -> Self {
        Self {
            formatters: Vec::new(),
            context,
        }
    }
    
    pub fn add_formatter(mut self, formatter: Box<dyn OutputFormatter>) -> Self {
        self.formatters.push(formatter);
        self
    }
    
    pub fn start(&self, target: &str) {
        for formatter in &self.formatters {
            formatter.format_start(&self.context, target);
        }
    }
    
    pub fn results(&self, results: &ScanResults) {
        for formatter in &self.formatters {
            formatter.format_results(&self.context, results);
        }
    }
}
```

**Acceptance Criteria:**
- [ ] Formatter trait defined
- [ ] Formatter chain works
- [ ] Git commit: "feat(output): add output formatter trait"

---

### P1-T4: Implement Text Formatter
**Priority:** HIGH  
**Files:** `src/output/text.rs`  
**Estimated Time:** 3 hours

```rust
// src/output/text.rs
use super::formatter::OutputFormatter;
use crate::ui::theme::get_theme;
use crate::scanner::{ScanResults, Severity};
use owo_colors::OwoColorize;

pub struct TextFormatter {
    verbose: bool,
}

impl TextFormatter {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }
}

impl OutputFormatter for TextFormatter {
    fn format_start(&self, ctx: &ExecutionContext, target: &str) {
        if !ctx.is_interactive() {
            println!("Scanning: {}", target);
            return;
        }
        
        let theme = get_theme();
        println!();
        println!("╭─────────────────────────────────────────────────╮");
        println!("│ {} MCPLint Security Scan                        │", 
            "🔍".if_supports_color(console::Stream::Stdout, |t| t.bold()));
        println!("│ Target: {}                                 │", 
            target.style(theme.emphasis));
        println!("╰─────────────────────────────────────────────────╯");
        println!();
    }
    
    fn format_results(&self, ctx: &ExecutionContext, results: &ScanResults) {
        let theme = get_theme();
        
        // Summary counts
        let counts = results.severity_counts();
        let has_issues = counts.iter().any(|(_, count)| *count > 0);
        
        if !has_issues {
            println!("{} No issues found!", "✓".style(theme.success));
            return;
        }
        
        // Display findings by severity
        for severity in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
            let findings: Vec<_> = results.findings_by_severity(&severity);
            if findings.is_empty() {
                continue;
            }
            
            println!("\n{} ({} findings)", 
                theme.severity_prefix(&severity),
                findings.len());
            
            for finding in findings {
                self.format_finding(ctx, finding, severity);
            }
        }
        
        // Summary footer
        println!("\n{}", "─".repeat(ctx.terminal_width.min(80)));
        println!("Summary: {} critical, {} high, {} medium, {} low",
            counts.get(&Severity::Critical).unwrap_or(&0).to_string().style(theme.critical),
            counts.get(&Severity::High).unwrap_or(&0).to_string().style(theme.high),
            counts.get(&Severity::Medium).unwrap_or(&0).to_string().style(theme.medium),
            counts.get(&Severity::Low).unwrap_or(&0).to_string().style(theme.low),
        );
    }
    
    fn format_error(&self, ctx: &ExecutionContext, error: &dyn std::error::Error) {
        let theme = get_theme();
        eprintln!("{} {}", "✖".style(theme.error), error);
    }
}
```

**Acceptance Criteria:**
- [ ] Text formatter displays results correctly
- [ ] Colors work in TTY, disabled in CI
- [ ] Git commit: "feat(output): implement enhanced text formatter"

---

### P1-T5: Update main.rs to Use New Context System
**Priority:** HIGH  
**Files:** `src/main.rs`  
**Estimated Time:** 1 hour

```rust
// src/main.rs (modifications)
use cli::context::ExecutionContext;
use output::formatter::FormatterChain;
use output::text::TextFormatter;
use ui::theme::init_colors;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Detect execution context
    let context = if cli.no_tty {
        ExecutionContext::force_non_interactive()
    } else {
        ExecutionContext::detect()
    };
    
    // Initialize color support
    init_colors(context.supports_color);
    
    // Initialize logging based on context
    init_logging(cli.verbose, cli.quiet, &context);
    
    // Create formatter chain
    let formatter = FormatterChain::new(context.clone())
        .add_formatter(Box::new(TextFormatter::new(cli.verbose > 0)));
    
    // ... rest of command handling
}
```

Add `--no-tty` flag to Cli struct:

```rust
#[derive(Parser)]
pub struct Cli {
    // ... existing fields
    
    /// Force non-interactive mode (CI-friendly output)
    #[arg(long, global = true)]
    no_tty: bool,
}
```

**Acceptance Criteria:**
- [ ] Context detection integrated into main
- [ ] Colors work correctly based on context
- [ ] `--no-tty` flag forces non-interactive mode
- [ ] Git commit: "feat(cli): integrate context detection into main"

---

## Phase 2: Progress Indicators & Real-Time Feedback

**Goal:** Add live progress bars, ETA calculations, and graceful interruption handling.  
**Duration:** 1 week  
**Risk:** Medium - async coordination with indicatif

---

### P2-T1: Create Progress Bar Styles
**Priority:** HIGH  
**Files:** `src/ui/progress.rs`  
**Estimated Time:** 2 hours

```rust
// src/ui/progress.rs
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use crate::ui::theme::get_theme;
use std::time::Duration;

pub struct ScanProgress {
    multi: MultiProgress,
    overall: ProgressBar,
    current: Option<ProgressBar>,
}

impl ScanProgress {
    pub fn new(total_files: u64) -> Self {
        let multi = MultiProgress::new();
        
        let overall_style = ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})"
        ).unwrap().progress_chars("█▓░");
        
        let overall = multi.add(ProgressBar::new(total_files));
        overall.set_style(overall_style);
        overall.enable_steady_tick(Duration::from_millis(100));
        
        Self {
            multi,
            overall,
            current: None,
        }
    }
    
    pub fn set_current_file(&mut self, filename: &str) {
        // Clear previous spinner
        if let Some(pb) = self.current.take() {
            pb.finish_and_clear();
        }
        
        let spinner_style = ProgressStyle::with_template(
            "{spinner:.green} {msg}"
        ).unwrap();
        
        let pb = self.multi.add(ProgressBar::new_spinner());
        pb.set_style(spinner_style);
        pb.set_message(format!("Scanning {}", filename));
        pb.enable_steady_tick(Duration::from_millis(100));
        
        self.current = Some(pb);
    }
    
    pub fn inc(&self) {
        self.overall.inc(1);
    }
    
    pub fn finish(&mut self) {
        if let Some(pb) = self.current.take() {
            pb.finish_and_clear();
        }
        self.overall.finish_with_message("Scan complete");
    }
    
    pub fn println(&self, msg: &str) {
        self.multi.println(msg).ok();
    }
}
```

**Testing:**
```rust
#[test]
fn test_progress_creation() {
    let progress = ScanProgress::new(10);
    progress.set_current_file("test.json");
    progress.inc();
    // Should not panic
}
```

**Acceptance Criteria:**
- [ ] Progress bars display correctly
- [ ] Nested progress works (overall + current file)
- [ ] No display corruption
- [ ] Git commit: "feat(ui): add progress bar components"

---

### P2-T2: Implement Async Scan with Progress
**Priority:** CRITICAL  
**Files:** `src/scanner/async_scanner.rs` (new), modify `src/commands/scan.rs`  
**Estimated Time:** 4 hours

```rust
// src/scanner/async_scanner.rs
use tokio::sync::Semaphore;
use std::sync::Arc;
use crate::ui::progress::ScanProgress;

pub async fn scan_files_with_progress(
    files: Vec<PathBuf>,
    max_concurrent: usize,
) -> Vec<ScanResult> {
    let total = files.len();
    let mut progress = ScanProgress::new(total as u64);
    
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let progress = Arc::new(tokio::sync::Mutex::new(progress));
    
    let handles: Vec<_> = files.into_iter().map(|file| {
        let permit = semaphore.clone();
        let progress = progress.clone();
        
        tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            
            // Update progress
            {
                let mut pg = progress.lock().await;
                pg.set_current_file(&file.display().to_string());
            }
            
            // Scan file
            let result = scan_single_file(&file).await;
            
            // Increment progress
            {
                let pg = progress.lock().await;
                pg.inc();
            }
            
            result
        })
    }).collect();
    
    let results = futures::future::join_all(handles).await;
    
    // Finish progress
    progress.lock().await.finish();
    
    results.into_iter().filter_map(Result::ok).collect()
}
```

**Acceptance Criteria:**
- [ ] Parallel scanning works with progress
- [ ] Progress updates correctly for each file
- [ ] No race conditions or display issues
- [ ] Git commit: "feat(scanner): add async scanning with progress"

---

### P2-T3: Add Graceful Ctrl+C Handling
**Priority:** HIGH  
**Files:** `src/cli/interruption.rs` (new), modify scanner  
**Estimated Time:** 2 hours

```rust
// src/cli/interruption.rs
use tokio::signal;
use tokio_util::sync::CancellationToken;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct InterruptHandler {
    token: CancellationToken,
    interrupted: Arc<AtomicBool>,
}

impl InterruptHandler {
    pub fn new() -> Self {
        let token = CancellationToken::new();
        let interrupted = Arc::new(AtomicBool::new(false));
        
        let token_clone = token.clone();
        let interrupted_clone = interrupted.clone();
        
        tokio::spawn(async move {
            signal::ctrl_c().await.ok();
            eprintln!("\n⚠ Interrupted - saving partial results...");
            interrupted_clone.store(true, Ordering::SeqCst);
            token_clone.cancel();
        });
        
        Self { token, interrupted }
    }
    
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }
    
    pub fn was_interrupted(&self) -> bool {
        self.interrupted.load(Ordering::SeqCst)
    }
}

// Save checkpoint
pub fn save_checkpoint(results: &ScanResults, path: &Path) -> miette::Result<()> {
    let checkpoint = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "interrupted": true,
        "results": results,
    });
    
    std::fs::write(path, serde_json::to_string_pretty(&checkpoint)?)
        .into_diagnostic()?;
    
    eprintln!("✓ Partial results saved to {}", path.display());
    Ok(())
}
```

**Modify scanner to use cancellation:**

```rust
// In scan_files_with_progress
pub async fn scan_files_with_progress(
    files: Vec<PathBuf>,
    max_concurrent: usize,
    cancel: CancellationToken,
) -> Vec<ScanResult> {
    // ... previous code ...
    
    for file in files {
        if cancel.is_cancelled() {
            break;
        }
        // ... scan logic ...
    }
    
    // ... rest of function
}
```

**Acceptance Criteria:**
- [ ] Ctrl+C saves partial results
- [ ] Checkpoint file is valid JSON
- [ ] User sees clear message about interruption
- [ ] Git commit: "feat(cli): add graceful Ctrl+C handling with checkpoints"

---

### P2-T4: Add Live Finding Counter
**Priority:** MEDIUM  
**Files:** `src/ui/progress.rs` (modify)  
**Estimated Time:** 1 hour

Add live finding counter to progress display:

```rust
impl ScanProgress {
    pub fn update_findings(&self, critical: usize, high: usize, medium: usize, low: usize) {
        let msg = format!(
            "Findings: {} critical, {} high, {} medium, {} low",
            critical, high, medium, low
        );
        self.overall.set_message(msg);
    }
}
```

**Acceptance Criteria:**
- [ ] Finding counts update in real-time
- [ ] Counts are accurate
- [ ] Git commit: "feat(ui): add live finding counter to progress"

---

## Phase 3: Interactive Mode & Smart Prompts

**Goal:** Add dialoguer-based interactive flows for configuration and scanning.  
**Duration:** 1 week  
**Risk:** Medium - UX design requires user feedback

---

### P3-T1: Create Interactive Scan Wizard
**Priority:** HIGH  
**Files:** `src/cli/interactive.rs`  
**Estimated Time:** 4 hours

```rust
// src/cli/interactive.rs
use dialoguer::{
    theme::ColorfulTheme,
    Select, MultiSelect, Input, Confirm, FuzzySelect,
};
use crate::scanner::{SecurityProfile, ScanTarget};

pub struct InteractiveScanBuilder {
    theme: ColorfulTheme,
}

impl InteractiveScanBuilder {
    pub fn new() -> Self {
        Self {
            theme: ColorfulTheme::default(),
        }
    }
    
    pub fn build_scan_config(&self) -> miette::Result<ScanConfig> {
        println!("\n🔍 MCPLint Interactive Scan\n");
        
        // Step 1: Select target
        let target = self.prompt_target()?;
        
        // Step 2: Select profile
        let profile = self.prompt_profile()?;
        
        // Step 3: Select rule categories
        let categories = self.prompt_categories()?;
        
        // Step 4: Output options
        let output = self.prompt_output()?;
        
        Ok(ScanConfig {
            target,
            profile,
            categories,
            output,
        })
    }
    
    fn prompt_target(&self) -> miette::Result<ScanTarget> {
        let input: String = Input::with_theme(&self.theme)
            .with_prompt("Path to scan")
            .with_initial_text(".")
            .validate_with(|input: &String| {
                if Path::new(input).exists() {
                    Ok(())
                } else {
                    Err("Path does not exist")
                }
            })
            .interact_text()
            .into_diagnostic()?;
        
        Ok(ScanTarget::from_path(input))
    }
    
    fn prompt_profile(&self) -> miette::Result<SecurityProfile> {
        let profiles = vec![
            ("Quick", "Fast scan, essential rules (~30s)"),
            ("Standard", "Balanced security/noise (~2min) [Recommended]"),
            ("Full", "Comprehensive analysis (~5min)"),
            ("Enterprise", "Compliance-focused (~10min)"),
        ];
        
        let selection = Select::with_theme(&self.theme)
            .with_prompt("Select security profile")
            .items(&profiles.iter().map(|(name, desc)| format!("{} - {}", name, desc)).collect::<Vec<_>>())
            .default(1)
            .interact()
            .into_diagnostic()?;
        
        Ok(match selection {
            0 => SecurityProfile::Quick,
            1 => SecurityProfile::Standard,
            2 => SecurityProfile::Full,
            3 => SecurityProfile::Enterprise,
            _ => unreachable!(),
        })
    }
    
    fn prompt_categories(&self) -> miette::Result<Vec<String>> {
        let customize = Confirm::with_theme(&self.theme)
            .with_prompt("Customize rule categories?")
            .default(false)
            .interact()
            .into_diagnostic()?;
        
        if !customize {
            return Ok(vec![]);
        }
        
        let categories = vec![
            "Injection vulnerabilities",
            "Authentication issues",
            "Authorization issues",
            "Protocol violations",
            "Data exposure",
            "DOS attacks",
        ];
        
        let selections = MultiSelect::with_theme(&self.theme)
            .with_prompt("Select categories to include (space to toggle, enter to confirm)")
            .items(&categories)
            .defaults(&[true, true, false, true, false, false])
            .interact()
            .into_diagnostic()?;
        
        Ok(selections.into_iter()
            .map(|i| categories[i].to_string())
            .collect())
    }
    
    fn prompt_output(&self) -> miette::Result<OutputConfig> {
        let save_results = Confirm::with_theme(&self.theme)
            .with_prompt("Save results to file?")
            .default(false)
            .interact()
            .into_diagnostic()?;
        
        let format = if save_results {
            let formats = vec!["JSON", "SARIF", "Text"];
            let selection = Select::with_theme(&self.theme)
                .with_prompt("Output format")
                .items(&formats)
                .default(0)
                .interact()
                .into_diagnostic()?;
            
            match selection {
                0 => OutputFormat::Json,
                1 => OutputFormat::Sarif,
                2 => OutputFormat::Text,
                _ => unreachable!(),
            }
        } else {
            OutputFormat::Text
        };
        
        Ok(OutputConfig { format, save: save_results })
    }
}
```

**Acceptance Criteria:**
- [ ] Interactive wizard guides user through scan setup
- [ ] Validates all inputs
- [ ] Works only in TTY mode
- [ ] Git commit: "feat(cli): add interactive scan wizard"

---

### P3-T2: Modify Scan Command to Support Interactive Mode
**Priority:** HIGH  
**Files:** `src/commands/scan.rs`  
**Estimated Time:** 2 hours

```rust
// In scan command handler
pub async fn run_scan(args: ScanArgs, ctx: &ExecutionContext) -> miette::Result<()> {
    let config = if args.is_empty() && ctx.is_interactive() {
        // Launch interactive wizard
        let builder = InteractiveScanBuilder::new();
        builder.build_scan_config()?
    } else {
        // Use command-line args
        ScanConfig::from_args(args)?
    };
    
    // Proceed with scan using config
    execute_scan(config, ctx).await
}
```

**Acceptance Criteria:**
- [ ] `mcplint scan` with no args launches wizard in interactive mode
- [ ] `mcplint scan <path>` works non-interactively
- [ ] Works correctly in CI (no prompts)
- [ ] Git commit: "feat(scan): integrate interactive wizard"

---

### P3-T3: Add Init Command Wizard
**Priority:** MEDIUM  
**Files:** `src/commands/init.rs`  
**Estimated Time:** 3 hours

```rust
// src/commands/init.rs (rewrite)
use dialoguer::{theme::ColorfulTheme, Select, Confirm, Input};

pub fn run_init_wizard(force: bool) -> miette::Result<()> {
    println!("\n╭─────────────────────────────────────────────────╮");
    println!("│ Welcome to MCPLint! Let's get you set up.      │");
    println!("╰─────────────────────────────────────────────────╯\n");
    
    let theme = ColorfulTheme::default();
    
    // Step 1: Detect MCP servers
    println!("Step 1/4: Detect MCP servers");
    let servers = detect_mcp_servers();
    
    if servers.is_empty() {
        println!("  ⚠ No MCP servers found in Claude Desktop config");
        let manual = Confirm::with_theme(&theme)
            .with_prompt("Would you like to specify a server manually?")
            .interact()
            .into_diagnostic()?;
        
        if !manual {
            return Ok(());
        }
    } else {
        println!("  ✓ Found {} server(s):", servers.len());
        for server in &servers {
            println!("    - {} ({})", server.name, server.command);
        }
    }
    
    // Step 2: Choose primary use case
    println!("\nStep 2/4: Choose security profile");
    let use_cases = vec![
        "Development (fast feedback, essential rules)",
        "Security Audit (comprehensive scan)",
        "CI/CD Pipeline (reliable, machine-readable)",
    ];
    
    let use_case = Select::with_theme(&theme)
        .with_prompt("What's your primary use case?")
        .items(&use_cases)
        .default(0)
        .interact()
        .into_diagnostic()?;
    
    let profile = match use_case {
        0 => SecurityProfile::Quick,
        1 => SecurityProfile::Full,
        2 => SecurityProfile::Standard,
        _ => unreachable!(),
    };
    
    // Step 3: Configure output
    println!("\nStep 3/4: Configure output");
    let git_detected = Path::new(".git").exists();
    
    let save_config = Confirm::with_theme(&theme)
        .with_prompt("Save configuration to .mcplint.toml?")
        .default(true)
        .interact()
        .into_diagnostic()?;
    
    let add_gitignore = if git_detected {
        Confirm::with_theme(&theme)
            .with_prompt("Add .mcplint-cache/ to .gitignore?")
            .default(true)
            .interact()
            .into_diagnostic()?
    } else {
        false
    };
    
    let create_workflow = if git_detected {
        Confirm::with_theme(&theme)
            .with_prompt("Create GitHub Actions workflow?")
            .default(false)
            .interact()
            .into_diagnostic()?
    } else {
        false
    };
    
    // Step 4: Run initial scan
    println!("\nStep 4/4: Run initial scan");
    let run_scan = Confirm::with_theme(&theme)
        .with_prompt("Run initial security scan now?")
        .default(true)
        .interact()
        .into_diagnostic()?;
    
    // Execute configuration
    create_config_file(profile, save_config)?;
    
    if add_gitignore {
        update_gitignore()?;
    }
    
    if create_workflow {
        create_github_workflow(profile)?;
    }
    
    if run_scan && !servers.is_empty() {
        run_initial_scan(&servers[0])?;
    }
    
    // Success message
    println!("\n✓ Setup complete!\n");
    println!("Next steps:");
    println!("  • Review findings: mcplint scan");
    println!("  • Watch for changes: mcplint watch");
    println!("  • Learn more: mcplint --help\n");
    
    Ok(())
}
```

**Acceptance Criteria:**
- [ ] Init wizard guides through setup
- [ ] Detects Git repository
- [ ] Creates config file
- [ ] Optionally creates GitHub workflow
- [ ] Git commit: "feat(init): add interactive setup wizard"

---

## Phase 4: Enhanced Error Messages & Help System

**Goal:** Implement miette-based diagnostics and contextual help.  
**Duration:** 1 week  
**Risk:** Low - mainly reorganizing existing error handling

---

### P4-T1: Create Custom Error Types with Miette
**Priority:** CRITICAL  
**Files:** `src/errors/mod.rs`  
**Estimated Time:** 3 hours

```rust
// src/errors/mod.rs
use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

#[derive(Error, Debug, Diagnostic)]
pub enum McpLintError {
    #[error("Server connection failed: {message}")]
    #[diagnostic(
        code(mcplint::connection),
        url("https://mcplint.dev/docs/errors#connection"),
        help("{suggestion}")
    )]
    ServerConnectionFailed {
        message: String,
        suggestion: String,
    },
    
    #[error("Unknown server: '{server_name}'")]
    #[diagnostic(
        code(mcplint::unknown_server),
        help("{suggestion}")
    )]
    UnknownServer {
        server_name: String,
        suggestion: String,
    },
    
    #[error("Invalid configuration")]
    #[diagnostic(
        code(mcplint::config::invalid),
        help("Run 'mcplint init' to create a valid configuration file")
    )]
    InvalidConfig {
        #[source_code]
        src: NamedSource<String>,
        #[label("error here")]
        span: SourceSpan,
        #[help]
        advice: String,
    },
    
    #[error("Security violation: {rule_id}")]
    #[diagnostic(
        code(mcplint::security::{rule_id}),
        severity(Error),
        url("https://mcplint.dev/rules/{rule_id}")
    )]
    SecurityViolation {
        rule_id: String,
        message: String,
        #[source_code]
        src: NamedSource<String>,
        #[label("{message}")]
        span: SourceSpan,
        #[help]
        fix_suggestion: Option<String>,
    },
}

impl McpLintError {
    pub fn connection_failed(message: impl Into<String>) -> Self {
        let msg = message.into();
        let suggestion = Self::generate_connection_suggestion(&msg);
        
        Self::ServerConnectionFailed {
            message: msg,
            suggestion,
        }
    }
    
    fn generate_connection_suggestion(error: &str) -> String {
        if error.contains("Connection refused") {
            "The server may not be running. Check that:\n\
             1. The server path is correct\n\
             2. The server has execute permissions\n\
             3. All dependencies are installed\n\
             \n\
             Try: mcplint doctor --extended"
        } else if error.contains("timeout") {
            "The server is not responding. Try:\n\
             1. Increasing the timeout: --timeout 60\n\
             2. Checking server logs for errors"
        } else {
            "Check the server configuration and try again"
        }.to_string()
    }
}
```

**Acceptance Criteria:**
- [ ] Error types defined with miette
- [ ] Errors display with source code context
- [ ] Helpful suggestions included
- [ ] Git commit: "feat(errors): add miette-based error types"

---

### P4-T2: Implement "Did You Mean?" Suggestions
**Priority:** MEDIUM  
**Files:** `src/errors/suggestions.rs`  
**Estimated Time:** 2 hours

```rust
// src/errors/suggestions.rs
use strsim::jaro_winkler;

pub fn find_similar<'a>(
    input: &str,
    candidates: &[&'a str],
    threshold: f64,
) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (jaro_winkler(input, c), *c))
        .filter(|(score, _)| *score > threshold)
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap())
        .map(|(_, name)| name)
}

pub fn suggest_server(unknown: &str, known_servers: &[String]) -> String {
    let candidates: Vec<_> = known_servers.iter().map(|s| s.as_str()).collect();
    
    if let Some(suggestion) = find_similar(unknown, &candidates, 0.6) {
        format!("Did you mean '{}'?", suggestion)
    } else {
        format!(
            "Unknown server '{}'. List available servers with:\n  mcplint servers",
            unknown
        )
    }
}

pub fn suggest_command(unknown: &str) -> String {
    let commands = ["scan", "validate", "fuzz", "servers", "rules", "init", "watch"];
    
    if let Some(suggestion) = find_similar(unknown, &commands, 0.6) {
        format!("Did you mean 'mcplint {}'?", suggestion)
    } else {
        "Run 'mcplint --help' to see available commands".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_typo_suggestions() {
        assert_eq!(
            find_similar("scna", &["scan", "init", "rules"], 0.6),
            Some("scan")
        );
    }
}
```

**Acceptance Criteria:**
- [ ] Suggestions work for typos
- [ ] Threshold is tuned appropriately
- [ ] Tests pass
- [ ] Git commit: "feat(errors): add 'did you mean' suggestions"

---

### P4-T3: Create Contextual Help System
**Priority:** MEDIUM  
**Files:** `src/cli/help.rs` (new)  
**Estimated Time:** 4 hours

```rust
// src/cli/help.rs
use std::collections::HashMap;

pub struct HelpSystem {
    recipes: HashMap<String, Recipe>,
}

pub struct Recipe {
    pub title: String,
    pub steps: Vec<Step>,
    pub see_also: Vec<String>,
}

pub struct Step {
    pub description: String,
    pub command: String,
}

impl HelpSystem {
    pub fn new() -> Self {
        let mut recipes = HashMap::new();
        
        // Add recipes
        recipes.insert("test-authentication".to_string(), Recipe {
            title: "Testing Authentication in MCP Servers".to_string(),
            steps: vec![
                Step {
                    description: "Run focused auth scan".to_string(),
                    command: "mcplint scan my-server --include auth --profile full".to_string(),
                },
                Step {
                    description: "Check specific auth rules".to_string(),
                    command: "mcplint rules --category auth --details".to_string(),
                },
                Step {
                    description: "Generate compliance report".to_string(),
                    command: "mcplint scan my-server --include auth --format sarif \\\n  --save-baseline auth-baseline.json".to_string(),
                },
            ],
            see_also: vec!["prevent-injection".to_string()],
        });
        
        // More recipes...
        
        Self { recipes }
    }
    
    pub fn show_recipe(&self, name: &str) -> miette::Result<()> {
        let recipe = self.recipes.get(name)
            .ok_or_else(|| miette::miette!("Recipe '{}' not found", name))?;
        
        println!("\n╭─────────────────────────────────────────────────╮");
        println!("│ {}                                              │", recipe.title);
        println!("╰─────────────────────────────────────────────────╯\n");
        
        for (i, step) in recipe.steps.iter().enumerate() {
            println!("{}. {}", i + 1, step.description);
            println!("   {}\n", step.command);
        }
        
        if !recipe.see_also.is_empty() {
            println!("See also:");
            for related in &recipe.see_also {
                println!("  mcplint how-do-i {}", related);
            }
        }
        
        Ok(())
    }
    
    pub fn list_recipes(&self) {
        println!("\nAvailable recipes:\n");
        for (name, recipe) in &self.recipes {
            println!("  {} - {}", name, recipe.title);
        }
        println!("\nUsage: mcplint how-do-i <recipe-name>\n");
    }
}
```

Add subcommand:

```rust
// In main.rs Commands enum
HowDoI {
    /// Recipe name (e.g., test-authentication)
    recipe: Option<String>,
}
```

**Acceptance Criteria:**
- [ ] Recipes display formatted help
- [ ] `mcplint how-do-i` lists all recipes
- [ ] `mcplint how-do-i <name>` shows specific recipe
- [ ] Git commit: "feat(help): add contextual recipe system"

---

## Phase 5: Shell Completions & Performance

**Goal:** Add shell completions and optimize startup time.  
**Duration:** 1 week  
**Risk:** Low - mostly independent work

---

### P5-T1: Generate Static Shell Completions
**Priority:** HIGH  
**Files:** `build.rs`, `completions/`  
**Estimated Time:** 2 hours

```rust
// build.rs
use clap::CommandFactory;
use clap_complete::{generate_to, Shell};
use std::env;
use std::path::PathBuf;

include!("src/main.rs");

fn main() {
    let outdir = PathBuf::from(env::var_os("OUT_DIR").unwrap())
        .ancestors()
        .nth(3)
        .unwrap()
        .join("completions");
    
    std::fs::create_dir_all(&outdir).unwrap();
    
    let mut cmd = Cli::command();
    
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell] {
        generate_to(shell, &mut cmd, "mcplint", &outdir).unwrap();
    }
    
    println!("cargo:rerun-if-changed=src/main.rs");
}
```

**Acceptance Criteria:**
- [ ] Completions generated at build time
- [ ] Completions work in bash, zsh, fish
- [ ] Git commit: "feat(completions): generate shell completions"

---

### P5-T2: Add Dynamic Completions for Servers
**Priority:** MEDIUM  
**Files:** `src/cli/completion.rs`  
**Estimated Time:** 3 hours

```rust
// src/cli/completion.rs
use clap_complete::{ArgValueCompleter, CompletionCandidate};

pub fn complete_servers(_current: &std::ffi::OsStr) -> Vec<CompletionCandidate> {
    // Load from Claude Desktop config
    let config_paths = get_claude_config_paths();
    
    for path in config_paths {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(config) = serde_json::from_str::<ClaudeConfig>(&content) {
                return config.mcpServers.keys()
                    .map(|name| CompletionCandidate::new(name))
                    .collect();
            }
        }
    }
    
    vec![]
}

pub fn complete_profiles(_current: &std::ffi::OsStr) -> Vec<CompletionCandidate> {
    vec![
        CompletionCandidate::new("quick").help(Some("Fast scan (~30s)".into())),
        CompletionCandidate::new("standard").help(Some("Balanced (~2min)".into())),
        CompletionCandidate::new("full").help(Some("Comprehensive (~5min)".into())),
        CompletionCandidate::new("enterprise").help(Some("Compliance (~10min)".into())),
    ]
}
```

**Add to CLI:**

```rust
#[derive(Args)]
pub struct ScanArgs {
    #[arg(add = ArgValueCompleter::new(complete_servers))]
    pub server: String,
    
    #[arg(short, long, add = ArgValueCompleter::new(complete_profiles))]
    pub profile: Option<String>,
}
```

**Acceptance Criteria:**
- [ ] Server names complete from Claude config
- [ ] Profile names complete with descriptions
- [ ] Git commit: "feat(completions): add dynamic server/profile completions"

---

### P5-T3: Optimize Startup Time
**Priority:** MEDIUM  
**Files:** `Cargo.toml`, various lazy init  
**Estimated Time:** 3 hours

**Update Cargo.toml:**

```toml
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
strip = "symbols"
panic = "abort"

[profile.release-dist]
inherits = "release"
lto = "fat"
```

**Lazy initialization pattern:**

```rust
// src/schema/mod.rs
use std::sync::OnceLock;

static MCP_SCHEMA: OnceLock<Schema> = OnceLock::new();

pub fn get_schema() -> &'static Schema {
    MCP_SCHEMA.get_or_init(|| {
        // Only load when validation happens
        serde_json::from_str(include_str!("mcp-schema.json"))
            .expect("Invalid MCP schema")
    })
}
```

**Benchmark startup:**

```rust
// benches/startup.rs
use criterion::{criterion_group, criterion_main, Criterion};
use std::process::Command;

fn bench_startup(c: &mut Criterion) {
    c.bench_function("startup_time", |b| {
        b.iter(|| {
            Command::new("./target/release/mcplint")
                .arg("--version")
                .output()
                .unwrap()
        })
    });
}

criterion_group!(benches, bench_startup);
criterion_main!(benches);
```

**Acceptance Criteria:**
- [ ] Startup time <100ms for `--version`
- [ ] Release build optimized
- [ ] Benchmark shows improvement
- [ ] Git commit: "perf: optimize startup time with lazy loading"

---

## Phase 6: Watch Mode & CI Integration

**Goal:** Implement differential watch mode and polished CI integration.  
**Duration:** 1 week  
**Risk:** Medium - file watching can be tricky cross-platform

---

### P6-T1: Implement Watch Mode
**Priority:** HIGH  
**Files:** `src/commands/watch.rs` (rewrite)  
**Estimated Time:** 5 hours

```rust
// src/commands/watch.rs
use notify_debouncer_full::{new_debouncer, notify::*, DebounceEventResult};
use std::time::Duration;
use std::path::PathBuf;

pub async fn run_watch(
    target: &str,
    paths_to_watch: Vec<PathBuf>,
    profile: SecurityProfile,
    debounce_ms: u64,
    clear_screen: bool,
) -> miette::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    
    // Create debounced watcher
    let mut debouncer = new_debouncer(
        Duration::from_millis(debounce_ms),
        None,
        move |result: DebounceEventResult| {
            if let Ok(events) = result {
                let mcp_files: Vec<_> = events
                    .iter()
                    .flat_map(|e| &e.paths)
                    .filter(|p| is_mcp_config_file(p))
                    .cloned()
                    .collect();
                
                if !mcp_files.is_empty() {
                    let _ = tx.blocking_send(mcp_files);
                }
            }
        },
    ).into_diagnostic()?;
    
    // Watch paths
    for path in &paths_to_watch {
        debouncer.watcher()
            .watch(path, RecursiveMode::Recursive)
            .into_diagnostic()?;
    }
    
    println!("👀 Watching for changes in {} path(s)...\n", paths_to_watch.len());
    println!("Press Ctrl+C to quit\n");
    
    // Run initial scan
    let mut last_results = run_scan_internal(target, profile).await?;
    display_results(&last_results, false);
    
    // Watch loop
    while let Some(changed_files) = rx.recv().await {
        if clear_screen {
            print!("\x1b[2J\x1b[H"); // Clear screen
        }
        
        println!("\n{} Changes detected in {} file(s)",
            "⚡".bright_yellow(),
            changed_files.len());
        
        for file in &changed_files {
            println!("  • {}", file.display());
        }
        println!();
        
        // Re-scan
        let new_results = run_scan_internal(target, profile).await?;
        
        // Display diff
        let diff = compute_diff(&last_results, &new_results);
        display_diff(&diff);
        
        last_results = new_results;
    }
    
    Ok(())
}

struct ResultsDiff {
    new_findings: Vec<Finding>,
    fixed_findings: Vec<Finding>,
    unchanged_count: usize,
}

fn compute_diff(old: &ScanResults, new: &ScanResults) -> ResultsDiff {
    let old_ids: std::collections::HashSet<_> = 
        old.findings.iter().map(|f| &f.id).collect();
    let new_ids: std::collections::HashSet<_> = 
        new.findings.iter().map(|f| &f.id).collect();
    
    ResultsDiff {
        new_findings: new.findings.iter()
            .filter(|f| !old_ids.contains(&f.id))
            .cloned()
            .collect(),
        fixed_findings: old.findings.iter()
            .filter(|f| !new_ids.contains(&f.id))
            .cloned()
            .collect(),
        unchanged_count: new_ids.intersection(&old_ids).count(),
    }
}

fn display_diff(diff: &ResultsDiff) {
    let theme = get_theme();
    
    if !diff.new_findings.is_empty() {
        println!("{} New issues found:", "⚠".style(theme.warning));
        for finding in &diff.new_findings {
            println!("  {} {}", 
                theme.severity_prefix(&finding.severity),
                finding.message);
        }
    }
    
    if !diff.fixed_findings.is_empty() {
        println!("\n{} Issues fixed:", "✓".style(theme.success));
        for finding in &diff.fixed_findings {
            println!("  {} {}", 
                theme.severity_prefix(&finding.severity),
                finding.message);
        }
    }
    
    if diff.unchanged_count > 0 {
        println!("\n{} {} unchanged issue(s)", 
            "·".style(theme.muted),
            diff.unchanged_count);
    }
}
```

**Acceptance Criteria:**
- [ ] Watch mode detects file changes
- [ ] Differential display shows new/fixed issues
- [ ] Debouncing works correctly
- [ ] Git commit: "feat(watch): implement differential watch mode"

---

### P6-T2: Enhanced SARIF Output
**Priority:** HIGH  
**Files:** `src/output/sarif.rs` (new)  
**Estimated Time:** 3 hours

```rust
// src/output/sarif.rs
use serde::Serialize;
use crate::scanner::{ScanResults, Finding, Severity};

#[derive(Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

impl SarifReport {
    pub fn from_scan_results(results: &ScanResults) -> Self {
        Self {
            schema: "https://json.schemastore.org/sarif-2.1.0.json",
            version: "2.1.0",
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "mcplint",
                        version: env!("CARGO_PKG_VERSION"),
                        information_uri: "https://github.com/example/mcplint",
                        rules: get_all_rules(),
                    },
                },
                results: results.findings.iter()
                    .map(|f| f.to_sarif_result())
                    .collect(),
            }],
        }
    }
}

impl Finding {
    fn to_sarif_result(&self) -> SarifResult {
        SarifResult {
            rule_id: self.rule_id.clone(),
            level: match self.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            },
            message: SarifMessage {
                text: self.message.clone(),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: self.file_path.display().to_string(),
                    },
                    region: SarifRegion {
                        start_line: self.line,
                        start_column: self.column,
                    },
                },
            }],
        }
    }
}
```

**Acceptance Criteria:**
- [ ] SARIF output validates against schema
- [ ] GitHub Code Scanning accepts output
- [ ] All required fields populated
- [ ] Git commit: "feat(output): add SARIF 2.1.0 format"

---

### P6-T3: Create GitHub Actions Example
**Priority:** MEDIUM  
**Files:** `examples/github-actions.yml`  
**Estimated Time:** 1 hour

```yaml
# examples/github-actions.yml
name: MCP Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      security-events: write  # For SARIF upload
      
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          
      - name: Install mcplint
        run: cargo install mcplint
        
      - name: Run security scan
        run: |
          mcplint scan ./mcp-configs \
            --profile standard \
            --format sarif \
            --output results.sarif \
            --fail-on critical,high
        continue-on-error: true
        
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: mcplint
          
      - name: Upload results as artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: mcplint-results
          path: results.sarif
```

**Acceptance Criteria:**
- [ ] Example workflow created
- [ ] Documentation updated
- [ ] Git commit: "docs: add GitHub Actions example"

---

## Phase 7: Testing & Documentation

**Goal:** Comprehensive testing and documentation updates.  
**Duration:** 1 week  
**Risk:** Low

---

### P7-T1: Integration Tests
**Priority:** CRITICAL  
**Files:** `tests/integration/`  
**Estimated Time:** 6 hours

```rust
// tests/integration/cli_tests.rs
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

#[test]
fn test_scan_with_no_args_shows_help() {
    let mut cmd = Command::cargo_bin("mcplint").unwrap();
    cmd.arg("scan")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required arguments"));
}

#[test]
fn test_version_flag() {
    let mut cmd = Command::cargo_bin("mcplint").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_interactive_mode_disabled_in_ci() {
    let mut cmd = Command::cargo_bin("mcplint").unwrap();
    cmd.env("CI", "true")
        .arg("scan")
        .assert()
        .failure();  // Should fail without args in CI
}

#[test]
fn test_sarif_output() {
    let mut cmd = Command::cargo_bin("mcplint").unwrap();
    let temp_dir = tempfile::tempdir().unwrap();
    let output_file = temp_dir.path().join("results.sarif");
    
    cmd.arg("scan")
        .arg("tests/fixtures/vulnerable-server")
        .arg("--format")
        .arg("sarif")
        .arg("--output")
        .arg(&output_file)
        .assert()
        .success();
    
    let content = fs::read_to_string(&output_file).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&content).unwrap();
    
    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["runs"].is_array());
}

#[test]
fn test_watch_mode_detects_changes() {
    // More complex test with file modification
}
```

**Acceptance Criteria:**
- [ ] All integration tests pass
- [ ] CLI behavior validated
- [ ] Git commit: "test: add comprehensive integration tests"

---

### P7-T2: Update Documentation
**Priority:** HIGH  
**Files:** `README.md`, `docs/`  
**Estimated Time:** 4 hours

Update README with:
- Interactive mode examples
- New flags and options
- Screenshots/GIFs
- Installation instructions for completions
- GitHub Actions integration

Create new docs:
- `docs/interactive-mode.md`
- `docs/watch-mode.md`
- `docs/ci-integration.md`
- `docs/configuration.md`

**Acceptance Criteria:**
- [ ] README updated with new features
- [ ] All commands documented
- [ ] Examples provided
- [ ] Git commit: "docs: update for new CLI features"

---

### P7-T3: Record Demo GIFs
**Priority:** LOW  
**Files:** `docs/assets/`  
**Estimated Time:** 2 hours

Use `asciinema` or `vhs` to record:
- Interactive scan wizard
- Watch mode in action
- Progress indicators
- Error messages with suggestions

**Acceptance Criteria:**
- [ ] GIFs recorded and compressed
- [ ] Embedded in documentation
- [ ] Git commit: "docs: add demo recordings"

---

## Rollout & Finalization

### FINAL-1: Performance Benchmarking
**Priority:** MEDIUM  
**Estimated Time:** 3 hours

Run comprehensive benchmarks:
- Startup time
- Scan performance with/without progress
- Memory usage
- Watch mode latency

Create `PERFORMANCE.md` with results.

---

### FINAL-2: User Acceptance Testing
**Priority:** CRITICAL  
**Estimated Time:** 1 week

Test with representative users from each persona:
- MCP server developer
- Security engineer
- DevOps engineer
- QA engineer

Gather feedback and iterate.

---

### FINAL-3: Merge to Main
**Priority:** CRITICAL

1. Squash commits if needed
2. Update CHANGELOG.md
3. Bump version in Cargo.toml
4. Create release tag
5. Merge PR
6. Publish to crates.io

---

## Success Criteria

The implementation is complete when:

- [ ] All 47 tasks completed
- [ ] All tests passing
- [ ] Documentation updated
- [ ] Performance benchmarks meet targets (<100ms startup)
- [ ] User acceptance testing positive
- [ ] No critical bugs
- [ ] Published to crates.io

---

## Risk Mitigation

**Risk:** Interactive prompts don't work correctly in all terminals  
**Mitigation:** Test on Windows Terminal, iTerm2, Alacritty, VSCode terminal

**Risk:** Progress bars corrupt output  
**Mitigation:** Always use pb.println(), add tests for TTY detection

**Risk:** Watch mode misses file changes  
**Mitigation:** Test debouncing carefully, add integration tests

**Risk:** Startup time increases with new features  
**Mitigation:** Benchmark each phase, use lazy loading, profile with flamegraph

---

## Notes for Claude Code

- Create git commits after each completed task
- Run `cargo check` after each file modification
- Run tests before commits
- Ask for clarification if requirements unclear
- Suggest improvements to this plan as you work

**Estimated Total Time:** 6-8 weeks full-time development
