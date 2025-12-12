# Modern Rust CLI patterns for building mcplint

**Bottom line:** Building an exceptional CLI experience for mcplint requires combining six core crates—clap 4.x, dialoguer, indicatif, console, owo-colors, and miette—with careful attention to interactive/non-interactive mode detection, semantic color systems, and graceful degradation. The best security tools like ripgrep achieve **sub-10ms startup** through lazy initialization, SIMD optimization, and LTO, while tools like GitHub CLI demonstrate how progressive disclosure and smart defaults create intuitive workflows.

This guide provides production-ready patterns from analyzing ripgrep, bat, starship, Semgrep, and Trivy, combined with 2024-2025 best practices from the Rust CLI ecosystem.

## The modern Rust CLI crate stack

The console-rs family (dialoguer, indicatif, console) works seamlessly with clap and provides the foundation for professional CLI UX. Here's the recommended dependency configuration:

```toml
[dependencies]
clap = { version = "4.5", features = ["derive"] }
clap_complete = { version = "4.5", features = ["unstable-dynamic"] }
dialoguer = "0.12"
indicatif = "0.18"
console = "0.15"
owo-colors = "4"
miette = { version = "7", features = ["fancy"] }
thiserror = "1.0"
```

**clap 4.x** uses derive macros by default—they generate equivalent code to the builder pattern with no runtime overhead, just slightly longer compile times. Use builder pattern only when dynamically generating arguments at runtime. The derive approach provides type safety and better documentation:

```rust
use clap::{Parser, Subcommand, Args, ValueEnum};

#[derive(Parser)]
#[command(version, about, arg_required_else_help = true)]
#[command(help_template = "{about-section}\n\nUsage: {usage}\n\n{all-args}\n\nExamples:\n  {bin} scan mcp-server.json\n  {bin} scan --profile strict ./servers/")]
pub struct Cli {
    #[arg(long, value_enum, default_value = "auto")]
    pub color: ColorChoice,
    
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan MCP server configurations for security issues
    Scan(ScanArgs),
    /// Initialize a new mcplint configuration
    Init,
    /// Watch files and re-scan on changes
    Watch(WatchArgs),
}

#[derive(Args)]
pub struct ScanArgs {
    /// Files or directories to scan
    #[arg(value_hint = clap::ValueHint::AnyPath)]
    pub targets: Vec<PathBuf>,
    
    /// Security profile to use
    #[arg(short, long, value_enum, default_value = "standard")]
    pub profile: SecurityProfile,
    
    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    pub format: OutputFormat,
}

#[derive(Clone, ValueEnum)]
pub enum SecurityProfile { Strict, Standard, Permissive }

#[derive(Clone, ValueEnum)]
pub enum OutputFormat { Text, Json, Sarif }
```

## Mixing interactive and non-interactive modes seamlessly

The key pattern—demonstrated by GitHub CLI's `gh pr create`—is **flag-driven non-interactive mode with TTY detection fallback**. When required parameters are missing and stdin is a terminal, prompt interactively; otherwise, fail with helpful error messages.

```rust
use std::io::IsTerminal;
use dialoguer::{Select, MultiSelect, Input, Confirm, theme::ColorfulTheme};

impl ScanArgs {
    pub fn resolve_interactive(mut self) -> miette::Result<Self> {
        let is_tty = std::io::stdin().is_terminal();
        
        // If no targets specified, prompt or error
        if self.targets.is_empty() {
            if is_tty {
                let target: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Path to scan")
                    .validate_with(|input: &String| {
                        if Path::new(input).exists() { Ok(()) }
                        else { Err("Path does not exist") }
                    })
                    .interact_text()
                    .into_diagnostic()?;
                self.targets.push(PathBuf::from(target));
            } else {
                return Err(miette::miette!(
                    "No targets specified. Provide paths as arguments or run interactively."
                ));
            }
        }
        
        // Offer profile selection in interactive mode if using default
        if is_tty && self.profile == SecurityProfile::Standard {
            let should_customize = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Customize security profile?")
                .default(false)
                .interact()
                .unwrap_or(false);
            
            if should_customize {
                let profiles = ["strict", "standard", "permissive"];
                let selection = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Select security profile")
                    .items(&profiles)
                    .default(1)
                    .interact()
                    .unwrap_or(1);
                self.profile = match selection {
                    0 => SecurityProfile::Strict,
                    2 => SecurityProfile::Permissive,
                    _ => SecurityProfile::Standard,
                };
            }
        }
        
        Ok(self)
    }
}
```

**Environment detection pattern** for CI/scripting contexts:

```rust
fn is_interactive() -> bool {
    // CI environments are never interactive
    if std::env::var("CI").is_ok() { return false; }
    if is_ci::cached() { return false; }
    
    // Check TTY
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}
```

## Progress feedback with indicatif and async tokio integration

For multi-file scanning operations, **indicatif's MultiProgress** displays parallel worker progress elegantly:

```rust
use indicatif::{MultiProgress, ProgressBar, ProgressStyle, ProgressIterator};
use std::sync::Arc;

fn create_scan_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}"
    ).unwrap().progress_chars("█▓░")
}

async fn scan_files_with_progress(files: Vec<PathBuf>) -> Vec<LintResult> {
    let multi = Arc::new(MultiProgress::new());
    
    // Overall progress
    let total_pb = multi.add(ProgressBar::new(files.len() as u64));
    total_pb.set_style(create_scan_style());
    total_pb.set_message("Scanning files...");
    
    let semaphore = Arc::new(tokio::sync::Semaphore::new(4)); // Max 4 concurrent
    let mut handles = Vec::new();
    
    for file in files {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let multi = multi.clone();
        let total_pb = total_pb.clone();
        
        handles.push(tokio::spawn(async move {
            let pb = multi.add(ProgressBar::new_spinner());
            pb.set_style(ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}").unwrap());
            pb.set_message(format!("Scanning {}", file.display()));
            pb.enable_steady_tick(std::time::Duration::from_millis(100));
            
            let result = scan_single_file(&file).await;
            
            pb.finish_and_clear();
            total_pb.inc(1);
            drop(permit);
            result
        }));
    }
    
    let results = futures::future::join_all(handles).await;
    total_pb.finish_with_message("Scan complete");
    
    results.into_iter().filter_map(Result::ok).collect()
}
```

**Critical indicatif integration rule:** Never use `println!()` while progress bars are active—use `pb.println()` instead to avoid display corruption.

## Semantic colors for security severity levels

**owo-colors** outperforms the colored crate with zero allocations and no_std compatibility:

```rust
use owo_colors::{OwoColorize, Style};

pub struct SecurityStyles {
    pub critical: Style,
    pub high: Style,
    pub medium: Style,
    pub low: Style,
    pub info: Style,
    pub success: Style,
}

impl SecurityStyles {
    pub fn new() -> Self {
        Self {
            critical: Style::new().bright_red().bold(),    // CVE-critical, RCE
            high: Style::new().red(),                       // SQL injection, auth bypass
            medium: Style::new().yellow(),                  // XSS, CSRF
            low: Style::new().cyan(),                       // Info disclosure
            info: Style::new().white().dimmed(),           // Suggestions
            success: Style::new().green(),                  // Clean scan
        }
    }
    
    pub fn for_severity(&self, severity: Severity) -> &Style {
        match severity {
            Severity::Critical => &self.critical,
            Severity::High => &self.high,
            Severity::Medium => &self.medium,
            Severity::Low => &self.low,
            Severity::Info => &self.info,
        }
    }
}

// Global color control via --color flag
fn init_colors(choice: ColorChoice) {
    match choice {
        ColorChoice::Always => owo_colors::set_override(true),
        ColorChoice::Never => owo_colors::set_override(false),
        ColorChoice::Auto => {
            // Respect NO_COLOR standard
            if std::env::var("NO_COLOR").map(|v| !v.is_empty()).unwrap_or(false) {
                owo_colors::set_override(false);
            }
        }
    }
}
```

## Diagnostic-quality error messages with miette

miette transforms errors from frustrating to helpful by showing source context, suggestions, and documentation links:

```rust
use miette::{Diagnostic, NamedSource, SourceSpan, Result};
use thiserror::Error;

#[derive(Error, Debug, Diagnostic)]
pub enum McpLintError {
    #[error("Unknown MCP tool '{tool_name}'")]
    #[diagnostic(
        code(mcplint::validation::unknown_tool),
        url("https://docs.mcplint.dev/errors/E0001"),
        help("{suggestion}")
    )]
    UnknownTool {
        tool_name: String,
        #[source_code]
        src: NamedSource<String>,
        #[label("undefined tool specified here")]
        span: SourceSpan,
        suggestion: String,
    },
    
    #[error("Security vulnerability detected: {message}")]
    #[diagnostic(
        code(mcplint::security::{code}),
        severity(Error),
        help("Review MCP security best practices at https://docs.mcplint.dev/security")
    )]
    SecurityIssue {
        message: String,
        code: String,
        #[source_code]
        src: NamedSource<String>,
        #[label("vulnerable code pattern")]
        span: SourceSpan,
    },
    
    #[error("Found {count} issues")]
    #[diagnostic(code(mcplint::multiple))]
    MultipleIssues {
        count: usize,
        #[related]
        issues: Vec<McpLintError>,
    },
}

// Helper constructor with "did you mean?" suggestions
impl McpLintError {
    pub fn unknown_tool(
        name: &str,
        source: &str,
        span: (usize, usize),
        known_tools: &[&str],
    ) -> Self {
        let suggestion = find_similar(name, known_tools)
            .map(|s| format!("Did you mean '{}'?", s))
            .unwrap_or_else(|| "Check available tools with 'mcplint list-tools'".into());
        
        Self::UnknownTool {
            tool_name: name.to_string(),
            src: NamedSource::new("mcp-config.json", source.to_string()),
            span: span.into(),
            suggestion,
        }
    }
}
```

**"Did you mean?" implementation** using strsim (clap's approach):

```rust
use strsim::jaro;

fn find_similar<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates.iter()
        .map(|c| (jaro(input, c), *c))
        .filter(|(score, _)| *score > 0.7)  // 0.7 threshold
        .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap())
        .map(|(_, name)| name)
}
```

## Shell completions with dynamic context-aware suggestions

clap_complete's `unstable-dynamic` feature enables runtime completions from config files or APIs:

```rust
use clap_complete::{ArgValueCompleter, CompletionCandidate};

fn complete_profiles(current: &std::ffi::OsStr) -> Vec<CompletionCandidate> {
    // Read from config file
    let config_path = dirs::config_dir()
        .map(|p| p.join("mcplint/config.toml"));
    
    if let Some(path) = config_path {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(config) = toml::from_str::<Config>(&content) {
                return config.profiles.iter()
                    .filter(|p| p.name.starts_with(&current.to_string_lossy()))
                    .map(|p| CompletionCandidate::new(&p.name)
                        .help(Some(p.description.clone().into())))
                    .collect();
            }
        }
    }
    
    // Fallback to built-in profiles
    vec![
        CompletionCandidate::new("strict").help(Some("Maximum security checks".into())),
        CompletionCandidate::new("standard").help(Some("Balanced security/noise".into())),
        CompletionCandidate::new("permissive").help(Some("Minimal warnings".into())),
    ]
}

// In CLI definition
#[arg(long, add = ArgValueCompleter::new(complete_profiles))]
pub profile: String,
```

**Build-time completion generation** for distribution:

```rust
// build.rs
use clap_complete::{generate_to, Shell};

fn main() {
    let outdir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("completions/");
    std::fs::create_dir_all(&outdir).unwrap();
    
    let mut cmd = Cli::command();
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::PowerShell] {
        generate_to(shell, &mut cmd, "mcplint", &outdir).unwrap();
    }
}
```

## Achieving sub-100ms startup time

ripgrep achieves **<10ms startup** through these patterns mcplint should adopt:

**1. Lazy initialization with OnceLock:**

```rust
use std::sync::OnceLock;

struct McpLinter {
    config_path: PathBuf,
    // Expensive resources loaded lazily
    schema: OnceLock<Schema>,
    rules: OnceLock<Vec<Rule>>,
}

impl McpLinter {
    fn schema(&self) -> &Schema {
        self.schema.get_or_init(|| {
            // Only load when validation actually happens
            Schema::from_json(include_str!("mcp-schema.json")).unwrap()
        })
    }
}
```

**2. Release profile optimization:**

```toml
[profile.release]
opt-level = 3
lto = "thin"          # Good balance; "fat" for maximum optimization
codegen-units = 1     # Better optimization at cost of compile time
strip = "symbols"     # Remove debug symbols
panic = "abort"       # Smaller binary, no unwinding

[profile.release-dist]
inherits = "release"
lto = "fat"           # Maximum optimization for distribution builds
```

**3. Profile-guided optimization** for release builds:

```bash
# Using cargo-pgo
cargo install cargo-pgo
cargo pgo build
./target/release/mcplint scan benchmarks/*.json  # Representative workload
cargo pgo optimize
```

## Watch mode with notify and incremental analysis

```rust
use notify_debouncer_full::{new_debouncer, notify::RecursiveMode, DebounceEventResult};
use std::time::Duration;

pub async fn watch_mode(paths: Vec<PathBuf>) -> miette::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    
    let mut debouncer = new_debouncer(
        Duration::from_millis(500),
        None,
        move |result: DebounceEventResult| {
            if let Ok(events) = result {
                let mcp_files: Vec<_> = events.iter()
                    .flat_map(|e| &e.paths)
                    .filter(|p| is_mcp_file(p))
                    .cloned()
                    .collect();
                if !mcp_files.is_empty() {
                    let _ = tx.blocking_send(mcp_files);
                }
            }
        },
    ).into_diagnostic()?;
    
    for path in &paths {
        debouncer.watch(path, RecursiveMode::Recursive).into_diagnostic()?;
    }
    
    println!("Watching for changes... (press Ctrl+C to quit)\n");
    
    // Initial scan
    let files = collect_mcp_files(&paths);
    display_results(&scan_files(&files).await);
    
    // Watch loop
    while let Some(changed_files) = rx.recv().await {
        print!("\x1b[2J\x1b[H");  // Clear screen
        println!("[{}] Changes detected in {} file(s)\n", 
            chrono::Local::now().format("%H:%M:%S"),
            changed_files.len());
        display_results(&scan_files(&changed_files).await);
    }
    
    Ok(())
}
```

## CI/CD integration with SARIF and exit codes

**Exit code conventions** following security scanner standards:

```rust
pub enum ExitCode {
    Success = 0,           // No issues found
    IssuesFound = 1,       // Lint violations detected (fails CI)
    ToolError = 2,         // Configuration/parse errors
}

impl From<&ScanResult> for ExitCode {
    fn from(result: &ScanResult) -> Self {
        if result.has_errors() { ExitCode::IssuesFound }
        else if result.has_tool_errors() { ExitCode::ToolError }
        else { ExitCode::Success }
    }
}
```

**SARIF output** for GitHub Code Scanning:

```rust
use serde::Serialize;

#[derive(Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

impl SarifReport {
    fn from_results(results: &[LintResult]) -> Self {
        Self {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            version: "2.1.0",
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "mcplint",
                        version: env!("CARGO_PKG_VERSION"),
                        information_uri: "https://github.com/example/mcplint",
                        rules: get_rule_definitions(),
                    },
                },
                results: results.iter().map(|r| r.to_sarif_result()).collect(),
            }],
        }
    }
}
```

**GitHub Actions workflow:**

```yaml
- name: Run mcplint
  run: mcplint scan --format=sarif --output=results.sarif ./mcp-configs/

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
    category: mcplint
```

**Auto-detect CI environment:**

```rust
fn configure_output() -> OutputConfig {
    let is_ci = is_ci::cached();
    let is_github = std::env::var("GITHUB_ACTIONS").is_ok();
    
    OutputConfig {
        format: if is_github { OutputFormat::Sarif } 
               else if is_ci { OutputFormat::Json }
               else { OutputFormat::Text },
        colors: !is_ci && should_use_color(),
    }
}
```

## Library mode alongside CLI binary

Structure mcplint for both programmatic use and CLI:

```
mcplint/
├── Cargo.toml
├── src/
│   ├── lib.rs          # Public API for library consumers
│   ├── main.rs         # CLI binary entry point
│   ├── cli/            # CLI-specific code
│   │   ├── mod.rs
│   │   ├── args.rs
│   │   └── output.rs
│   └── core/           # Shared logic (library + CLI)
│       ├── mod.rs
│       ├── scanner.rs
│       ├── rules.rs
│       └── types.rs
```

```rust
// lib.rs - Clean public API
pub mod core;
pub use core::{Scanner, ScanResult, Rule, Severity};

// main.rs - Thin CLI wrapper
use mcplint::{Scanner, ScanResult};
mod cli;

fn main() -> miette::Result<()> {
    let args = cli::Args::parse();
    let scanner = Scanner::new(args.config())?;
    let results = scanner.scan(&args.targets)?;
    cli::output::display(&results, args.format)?;
    std::process::exit(ExitCode::from(&results) as i32);
}
```

## Graceful Ctrl+C handling with partial result saving

```rust
use tokio::signal;
use tokio_util::sync::CancellationToken;

async fn scan_with_cancellation(files: Vec<PathBuf>) -> miette::Result<ScanResult> {
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    
    tokio::spawn(async move {
        signal::ctrl_c().await.ok();
        eprintln!("\nInterrupted - saving partial results...");
        cancel_clone.cancel();
    });
    
    let mut results = Vec::new();
    
    for file in files {
        if cancel.is_cancelled() {
            break;
        }
        results.push(scan_single_file(&file).await?);
    }
    
    if cancel.is_cancelled() {
        // Save checkpoint
        let checkpoint = Checkpoint { results: results.clone(), interrupted: true };
        std::fs::write("mcplint-checkpoint.json", serde_json::to_string(&checkpoint)?)?;
        eprintln!("Partial results saved to mcplint-checkpoint.json");
    }
    
    Ok(ScanResult::from(results))
}
```

## Accessibility requirements

```rust
fn should_use_color() -> bool {
    // NO_COLOR standard takes precedence
    if std::env::var("NO_COLOR").map(|v| !v.is_empty()).unwrap_or(false) {
        return false;
    }
    // TERM=dumb means no color support
    if std::env::var("TERM").map(|v| v == "dumb").unwrap_or(false) {
        return false;
    }
    // Default to TTY detection
    std::io::stdout().is_terminal()
}

// Always use symbols alongside colors
fn severity_prefix(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "✖ CRITICAL",
        Severity::High => "✖ HIGH",
        Severity::Medium => "⚠ MEDIUM", 
        Severity::Low => "ℹ LOW",
        Severity::Info => "· INFO",
    }
}
```

## Anti-patterns to avoid

| Anti-pattern | Better approach |
|-------------|-----------------|
| `unwrap()` on user input | Use `?` with context via miette |
| Hardcoded version strings | Use `env!("CARGO_PKG_VERSION")` |
| Interactive prompts without TTY check | Always gate with `is_terminal()` |
| `println!()` during progress bars | Use `pb.println()` |
| Forcing colors without override | Respect `NO_COLOR` and `--color` flag |
| Loading schemas at startup | Lazy load with `OnceLock` |
| Single-threaded file scanning | Use rayon for CPU-bound parallel work |
| Ignoring Ctrl+C | Save partial results on interruption |

## Conclusion

Building mcplint with these patterns positions it alongside professional tools like ripgrep and Semgrep. The key architectural decisions are: **derive-based clap** for type-safe argument parsing, **TTY-aware mode switching** for seamless interactive/scripting use, **miette diagnostics** for helpful error messages with source context, **lazy initialization** for fast startup, and **SARIF output** for CI integration. 

The recommended implementation order: start with clap argument parsing and basic scanning, add indicatif progress display, implement miette error handling with "did you mean?" suggestions, add shell completions, implement watch mode with notify, and finally add SARIF output for GitHub Code Scanning integration. This progression builds user-facing value incrementally while establishing solid architectural foundations.