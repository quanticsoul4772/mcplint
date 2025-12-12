# Plan: Phase 2 Preparation - Output Infrastructure

## Date: 2025-12-11

## Context
Phase 1 (Smart Context Detection) completed successfully. Before implementing Phase 2 (Progress Indicators), we need to address technical debt in the output system.

## Hypothesis
Creating a centralized output/UI infrastructure BEFORE implementing progress indicators will:
1. Reduce code duplication (currently 330 println! calls)
2. Enable consistent theming across all commands
3. Make CI detection automatic for all output
4. Provide clean foundation for progress bars and spinners

## Technical Debt Identified
| Issue | Count | Impact |
|-------|-------|--------|
| `unwrap()` calls | 712 | Potential panics |
| `println!` in commands | 330 | No output abstraction |
| Direct color calls | 164 | Inconsistent theming |
| `#[allow(dead_code)]` | 20+ | Mostly intentional |

## Implementation Steps

### Step 1: Add Dependencies (SETUP-2)
```toml
indicatif = "0.18"
console = "0.15"
dialoguer = { version = "0.12", features = ["fuzzy-select"] }
owo-colors = { version = "4", features = ["supports-colors"] }
miette = { version = "7", features = ["fancy"] }
thiserror = "1.0"
is-ci = "1.2"
```

### Step 2: Create Module Structure (SETUP-3)
```
src/ui/
├── mod.rs        # Module exports
├── progress.rs   # Progress bar/spinner types
├── theme.rs      # Color theme definitions
└── table.rs      # Table formatting
```

### Step 3: Basic Theme System
- Define `SecurityTheme` with severity-based colors
- Critical: red, High: orange, Medium: yellow, Low: blue, Info: dim
- CI mode: no colors, simplified output

### Step 4: Output Abstraction
- `OutputMode` enum: Interactive, CI, Plain
- Auto-detect based on `is-ci` and TTY
- Centralized print functions that respect mode

### Step 5: Migrate Proof of Concept
- Migrate `scan` command to new system
- Migrate `validate` command to new system
- Verify no regressions

## Expected Outcomes
- Clean foundation for Phase 2 progress indicators
- Consistent output across all commands
- CI-friendly output mode
- Reduced code duplication

## Risks & Mitigation
| Risk | Mitigation |
|------|------------|
| Breaking existing output | Keep old code working, migrate incrementally |
| Over-engineering | Start minimal, add features as needed |
| Test failures | Run full test suite after each change |

## Success Criteria
- [x] All dependencies added and building (indicatif, console, dialoguer, is_ci)
- [x] `src/ui/` module compiles with basic types (mod.rs, output.rs, theme.rs, progress.rs)
- [x] Theme system provides consistent colors (Severity enum, SecurityTheme helpers)
- [x] CI detection works correctly (OutputMode::detect() with is_ci::cached())
- [x] At least 1 command migrated without regression (doctor command)
- [x] All 1716+ tests still passing

## Phase 2 Prep Complete - Ready for Progress Indicators
The UI infrastructure is now in place. Next steps:
1. Implement progress bar for scans using indicatif + ScanProgress
2. Implement spinner for connection states
3. Migrate more commands incrementally to use Printer
4. Add ETA calculations for long operations
