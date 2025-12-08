# Technical Debt Analysis: MCPLint M0-M6

**Generated:** December 7, 2025
**Codebase:** ~16,000 lines of Rust

---

## Executive Summary

The mcplint codebase has accumulated several categories of technical debt through the M0-M6 development phases. This document catalogs the debt, prioritizes remediation, and provides actionable refactoring recommendations.

| Category | Items | Priority | Effort |
|----------|-------|----------|--------|
| Dead Code / Unused Annotations | 30+ | 🟡 Medium | Low |
| Function Complexity | 4 functions | 🟢 Low | Medium |
| TODO/FIXME Comments | 2 | 🔴 High | Low |
| Code Duplication | 3 areas | 🟡 Medium | Medium |
| Large Files | 5 files >500 LOC | 🟡 Medium | High |
| Type Conversion Overhead | 2 areas | 🟢 Low | Low |
| Error Handling Inconsistency | Multiple | 🟡 Medium | Medium |

---

## Category 1: Dead Code and Unused Annotations

### Problem

The codebase has 30+ `#[allow(dead_code)]` and 15+ `#[allow(unused_imports)]` annotations. While some are intentional (public API exports not yet consumed), many indicate:
- Features implemented but not wired up
- Defensive public methods that may never be used
- Premature abstractions

### Files Affected

| File | Count | Notes |
|------|-------|-------|
| `src/scanner/context.rs` | 11 | Many unused config builders |
| `src/scanner/finding.rs` | 5 | Evidence/Reference factory methods |
| `src/validator/engine.rs` | 4 | Unused validation helpers |
| `src/transport/mod.rs` | 3 | Unused transport types |
| `src/ai/mod.rs` | 7 | Public re-exports (intentional) |
| `src/baseline/mod.rs` | 2 | Public re-exports (intentional) |

### Remediation

```rust
// BEFORE: Defensive dead_code annotation
#[allow(dead_code)]
pub fn resource(uri: impl Into<String>) -> Self { ... }

// AFTER: Either use it or remove it
// Option 1: Wire it up (if useful)
// Option 2: Remove completely (if speculative)
// Option 3: Add #[cfg(test)] if only for tests
```

**Effort:** 2-4 hours
**Priority:** 🟡 Medium - Does not affect functionality but impacts maintainability

---

## Category 2: Function Complexity (Too Many Arguments)

### Problem

4 command functions require `#[allow(clippy::too_many_arguments)]`:

| Function | Args | Location |
|----------|------|----------|
| `scan::run()` | 14 | `src/cli/commands/scan.rs:19` |
| `explain::run_scan()` | 11 | `src/cli/commands/explain.rs:91` |
| `fuzz::run()` | 10 | `src/cli/commands/fuzz.rs:11` |
| `watch::run()` | 6 | `src/cli/commands/watch.rs:17` |

### Remediation

Create configuration structs to group related parameters:

```rust
// BEFORE: 14 separate arguments
pub async fn run(
    server: &str,
    args: &[String],
    profile: CliScanProfile,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    timeout: u64,
    format: OutputFormat,
    explain: bool,
    ai_provider: CliAiProvider,
    ai_model: Option<String>,
    baseline_path: Option<PathBuf>,
    save_baseline: Option<PathBuf>,
    update_baseline: bool,
    diff_only: bool,
    fail_on: Option<Vec<Severity>>,
) -> Result<()>

// AFTER: Grouped into config structs
pub struct ScanArgs {
    pub server: String,
    pub args: Vec<String>,
    pub config: ScanRunConfig,
    pub output: OutputConfig,
    pub baseline: BaselineConfig,
    pub ai: Option<AiConfig>,
}

pub async fn run(args: ScanArgs) -> Result<()>
```

**Effort:** 4-6 hours
**Priority:** 🟢 Low - Code works, just harder to maintain

---

## Category 3: Incomplete Implementations (TODO/FIXME)

### Problem

2 TODO comments indicate incomplete functionality:

```rust
// src/cli/commands/validate.rs:
// TODO: Implement actual validation

// src/fuzzer/corpus.rs:
// TODO: Implement corpus loading from disk
```

### Analysis

1. **validate.rs**: The validate command exists but may be a stub
2. **corpus.rs**: Corpus persistence not implemented (important for fuzzer resume)

### Remediation

1. **validate.rs**: Audit and either implement or document as "planned feature"
2. **corpus.rs**: Implement corpus save/load for fuzzer resume capability

**Effort:** 8-16 hours
**Priority:** 🔴 High - These represent missing promised functionality

---

## Category 4: Code Duplication

### Problem Areas

#### 4.1 Profile Conversion (2 locations)

```rust
// src/main.rs:542-547
let scan_profile = match profile {
    ScanProfile::Quick => scanner::ScanProfile::Quick,
    ScanProfile::Standard => scanner::ScanProfile::Standard,
    ScanProfile::Full => scanner::ScanProfile::Full,
    ScanProfile::Enterprise => scanner::ScanProfile::Enterprise,
};

// src/cli/commands/scan.rs:49-54
let scan_profile = match profile {
    CliScanProfile::Quick => ScanProfile::Quick,
    ...
};
```

**Fix:** Implement `From<CliScanProfile> for ScanProfile`

#### 4.2 AI Provider Configuration (scan.rs and explain.rs)

Both files have similar AI config building logic (~30 lines duplicated).

**Fix:** Extract to shared `ai::config_from_cli()` function

#### 4.3 Severity Formatting (multiple locations)

```rust
// Pattern repeated in scan.rs, mod.rs, watch.rs
let severity = match finding.severity {
    Severity::Critical => "CRITICAL".red().bold(),
    Severity::High => "HIGH".red(),
    Severity::Medium => "MEDIUM".yellow(),
    ...
};
```

**Fix:** Add `Severity::colored_display()` method

### Remediation

```rust
// Consolidated conversions
impl From<CliScanProfile> for ScanProfile {
    fn from(p: CliScanProfile) -> Self {
        match p {
            CliScanProfile::Quick => ScanProfile::Quick,
            CliScanProfile::Standard => ScanProfile::Standard,
            CliScanProfile::Full => ScanProfile::Full,
            CliScanProfile::Enterprise => ScanProfile::Enterprise,
        }
    }
}

impl Severity {
    pub fn colored_display(&self) -> colored::ColoredString {
        match self {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".red(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".blue(),
            Severity::Info => "INFO".dimmed(),
        }
    }
}
```

**Effort:** 2-4 hours
**Priority:** 🟡 Medium - Increases maintenance burden

---

## Category 5: Large Files (>500 LOC)

### Problem

5 files exceed 500 lines, indicating potential need for decomposition:

| File | Lines | Suggested Split |
|------|-------|-----------------|
| `src/scanner/engine.rs` | 882 | Split checks into separate modules |
| `src/validator/engine.rs` | 863 | Split by validation category |
| `src/ai/config.rs` | 789 | Extract builder to separate file |
| `src/main.rs` | 553 | Extract command structs to types.rs |
| `src/fuzzer/session.rs` | 517 | Extract stats/reporting |

### Remediation Strategy

```
src/scanner/
├── mod.rs           # Re-exports
├── engine.rs        # Core engine (reduced)
├── checks/
│   ├── mod.rs
│   ├── injection.rs
│   ├── auth.rs
│   ├── transport.rs
│   ├── protocol.rs
│   └── data.rs
└── context.rs
```

**Effort:** 16-24 hours
**Priority:** 🟡 Medium - Large files are harder to navigate/test

---

## Category 6: Type Conversion Overhead

### Problem

The CLI uses its own `CliScanProfile`, `CliAiProvider` types that are near-identical to the library types. This requires conversion at every boundary.

### Current State

```rust
// main.rs defines
enum ScanProfile { Quick, Standard, Full, Enterprise }

// scanner/mod.rs also defines
enum ScanProfile { Quick, Standard, Full, Enterprise }

// Requires conversion in every command
```

### Remediation

Option 1: **Use library types directly in CLI** (preferred)
```rust
// main.rs
use crate::scanner::ScanProfile;  // Use library type directly
```

Option 2: **Unify with feature flags**
```rust
// scanner/mod.rs
#[derive(clap::ValueEnum)]
pub enum ScanProfile { ... }
```

**Effort:** 2-3 hours
**Priority:** 🟢 Low - Works fine, just adds boilerplate

---

## Category 7: Error Handling Inconsistency

### Problem

Mixed error handling patterns across the codebase:

```rust
// Pattern 1: anyhow Result with context
.map_err(|e| anyhow::anyhow!("Failed to load: {}", e))?

// Pattern 2: Direct ? without context
let result = operation()?;  // Lost context on failure

// Pattern 3: Manual eprintln + continue
if let Err(e) = operation() {
    eprintln!("{}", format!("Error: {}", e).red());
    // continues...
}
```

### Remediation

1. Define custom error types for each module
2. Use `thiserror` consistently
3. Add context with `.context()` from anyhow

```rust
// Consistent error handling
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Failed to connect to server: {0}")]
    ConnectionFailed(#[from] std::io::Error),

    #[error("Server timeout after {0}s")]
    Timeout(u64),

    #[error("Invalid server response: {0}")]
    InvalidResponse(String),
}
```

**Effort:** 8-12 hours
**Priority:** 🟡 Medium - Impacts debuggability

---

## Category 8: Test Coverage Gaps

### Problem Areas

1. **Integration tests sparse**: Only 2 integration test files
2. **AI module mocking**: Tests use mock provider but real provider paths untested
3. **Fuzzer persistence**: No tests for corpus save/load (not implemented)
4. **Watch mode**: Limited test coverage for file system events

### Remediation

```rust
// Add integration test for AI providers
#[tokio::test]
#[ignore] // Requires API key
async fn test_anthropic_provider_real() {
    // Real API call test
}

// Add property tests for finding fingerprinting
proptest! {
    #[test]
    fn fingerprint_is_stable(finding in finding_strategy()) {
        let fp1 = FindingFingerprint::from_finding(&finding);
        let fp2 = FindingFingerprint::from_finding(&finding);
        prop_assert_eq!(fp1, fp2);
    }
}
```

**Effort:** 16-24 hours
**Priority:** 🟡 Medium - Important for regression prevention

---

## Prioritized Remediation Roadmap

### Phase 1: Quick Wins (Week 1)
- [ ] Fix TODO comments in validate.rs and corpus.rs
- [ ] Add `From` impls to eliminate type conversion duplication
- [ ] Add `Severity::colored_display()` method

### Phase 2: Structural Improvements (Week 2)
- [ ] Refactor command functions to use config structs
- [ ] Audit and clean dead_code annotations
- [ ] Consolidate AI config building

### Phase 3: Major Refactoring (Week 3-4)
- [ ] Split large files (scanner/engine.rs, validator/engine.rs)
- [ ] Implement consistent error types
- [ ] Add missing integration tests

---

## Metrics

| Metric | Current | Target |
|--------|---------|--------|
| `#[allow(dead_code)]` count | 30 | <10 |
| `#[allow(clippy::too_many_arguments)]` count | 4 | 0 |
| TODO/FIXME count | 2 | 0 |
| Files >500 LOC | 5 | 2 |
| Test coverage (estimated) | 65% | 80% |

---

*Document Version: 1.0*
*Author: Claude Code Analysis Agent*
