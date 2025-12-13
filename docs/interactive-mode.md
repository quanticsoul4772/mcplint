# Interactive Mode

MCPLint includes interactive wizards that provide a guided experience for common operations. This document covers how interactive mode works, when it activates, and how to use each wizard.

## Overview

Interactive mode activates automatically when:

1. **Running in a TTY** - Terminal supports user input
2. **Not in CI** - No CI environment variables detected (CI, GITHUB_ACTIONS, etc.)
3. **Arguments omitted** - Required command arguments not provided

When these conditions are met, MCPLint launches a wizard to guide you through the operation.

## Detection Logic

Interactive mode uses the following detection:

```rust
pub fn is_interactive_available() -> bool {
    let output_mode = OutputMode::detect();
    matches!(output_mode, OutputMode::Interactive | OutputMode::Rich)
}
```

The `OutputMode` detection considers:
- `isatty()` check on stdout
- CI environment variables (CI, GITHUB_ACTIONS, GITLAB_CI, etc.)
- NO_COLOR environment variable
- Terminal capabilities

## Scan Wizard

The scan wizard activates when running `mcplint scan` without a server argument.

### Flow

1. **Server Selection** - FuzzySelect from configured servers
2. **Scan Profile** - Choose quick/standard/full/enterprise
3. **Categories** - Multi-select rule categories to include
4. **Output Format** - text/json/sarif/junit/gitlab
5. **Fail Threshold** - Severities that cause exit code 1

### Example Session

```
$ mcplint scan

? Select server to scan
> filesystem-server
  memory-server
  github-mcp

? Select scan profile
> Standard (recommended)
  Quick
  Full
  Enterprise

? Include categories (space to select, enter to confirm)
  [x] security
  [x] protocol
  [ ] experimental

? Output format
> Text (human-readable)
  JSON
  SARIF

? Fail on which severities?
  [x] Critical
  [x] High
  [ ] Medium
  [ ] Low
```

### Programmatic Structure

```rust
pub struct ScanWizardResult {
    pub server: String,
    pub profile: ScanProfile,
    pub include_categories: Option<Vec<String>>,
    pub output_format: OutputFormat,
    pub fail_on: Option<Vec<Severity>>,
}
```

## Fuzz Wizard

The fuzz wizard activates when running `mcplint fuzz` without a server argument.

### Flow

1. **Server Selection** - FuzzySelect from configured servers
2. **Fuzz Profile** - Choose quick/standard/intensive/CI
3. **Duration** - Fuzzing duration in seconds
4. **Workers** - Number of parallel workers
5. **Corpus** - Optional corpus directory path

### Profile Descriptions

| Profile | Duration | Workers | Use Case |
|---------|----------|---------|----------|
| Quick | 60s | 2 | Fast smoke test |
| Standard | 300s | 4 | Regular testing |
| Intensive | 3600s | 8 | Deep coverage |
| CI | 120s | 2 | CI/CD pipelines |

### Programmatic Structure

```rust
pub struct FuzzWizardResult {
    pub server: String,
    pub profile: FuzzProfile,
    pub duration: u64,
    pub workers: usize,
    pub corpus: Option<String>,
}
```

## Explain Wizard

The explain wizard activates when running `mcplint explain` without a server argument.

### Flow

1. **Server Selection** - FuzzySelect from configured servers
2. **AI Provider** - Choose Ollama/Anthropic/OpenAI
3. **Audience Level** - Choose beginner/intermediate/expert
4. **Severity Filter** - Optional minimum severity to explain
5. **Max Findings** - Optional limit on number of findings (3/5/10/All)
6. **Interactive Follow-up** - Enable Q&A mode after explanations

### Provider Descriptions

| Provider | Description | Requirements |
|----------|-------------|--------------|
| Ollama | Local AI (recommended) | Ollama installed, no API key |
| Anthropic | Claude API | ANTHROPIC_API_KEY |
| OpenAI | GPT API | OPENAI_API_KEY |

### Audience Levels

| Level | Description | Detail Level |
|-------|-------------|--------------|
| Beginner | New to security concepts | High detail, more examples |
| Intermediate | Familiar with basics | Balanced explanations |
| Expert | Security professional | Concise, technical focus |

### Example Session

```
$ mcplint explain

? Select server to scan
> filesystem-server
  memory-server
  github-mcp

? Select AI provider
> Ollama - Local AI (no API key required) [Recommended]
  Anthropic - Claude API (requires ANTHROPIC_API_KEY)
  OpenAI - GPT API (requires OPENAI_API_KEY)

? Select audience level
> Intermediate - Familiar with security basics
  Beginner - New to security concepts
  Expert - Security professional

? Filter by minimum severity?
> No filter (explain all findings)
  Critical only
  High and above
  Medium and above

? Maximum findings to explain?
> 5 findings
  3 findings
  10 findings
  All findings

? Enable interactive follow-up questions?
> Yes
  No
```

### Programmatic Structure

```rust
pub struct ExplainWizardResult {
    pub server: String,
    pub provider: CliAiProvider,
    pub audience: CliAudienceLevel,
    pub min_severity: Option<Severity>,
    pub max_findings: Option<usize>,
    pub interactive_followup: bool,
}
```

## Init Wizard

The init wizard activates when running `mcplint init` in interactive mode.

### Flow

1. **Output Path** - Config file location (default: .mcplint.toml)
2. **Servers to Test** - Multi-select from configured servers
3. **Default Profile** - Default scan profile for config
4. **CI Workflow** - Create GitHub Actions workflow
5. **Initial Scan** - Run scan after init

### Generated Files

When **Create CI Workflow** is selected:
- `.github/workflows/mcplint.yml` - GitHub Actions workflow

The wizard also:
- Adds `.mcplint-cache/` to `.gitignore`
- Creates the configuration file with wizard selections

### Programmatic Structure

```rust
pub struct InitWizardResult {
    pub output_path: String,
    pub servers_to_test: Vec<String>,
    pub default_profile: ScanProfile,
    pub create_ci_workflow: bool,
    pub run_initial_scan: bool,
}
```

## Disabling Interactive Mode

Interactive mode is automatically disabled in:

- CI environments (detected via environment variables)
- Non-TTY contexts (piped output, scripts)
- When NO_COLOR is set

To explicitly run non-interactively, provide all required arguments:

```bash
# Non-interactive scan
mcplint scan filesystem-server --profile standard

# Non-interactive fuzz
mcplint fuzz filesystem-server --duration 300 --workers 4

# Non-interactive explain
mcplint explain filesystem-server --provider ollama --audience intermediate
```

## Implementation Details

### Dependencies

Interactive mode uses the `dialoguer` crate with FuzzySelect, Select, MultiSelect, Confirm, and Input components.

### Environment Variables Checked

- `CI` - Generic CI indicator
- `GITHUB_ACTIONS` - GitHub Actions
- `GITLAB_CI` - GitLab CI
- `TRAVIS` - Travis CI
- `CIRCLECI` - CircleCI
- `JENKINS_URL` - Jenkins
- `NO_COLOR` - Disable colors (implies non-interactive)

### Error Handling

If interactive mode is unavailable but required arguments are missing:

```
Error: Server argument required in non-interactive mode.
Run with --help for usage information.
```

## Testing

Interactive mode has dedicated integration tests in `tests/interactive_tests.rs`:

- Structure tests for wizard result types
- Output format validation
- Profile variant coverage
- CI environment detection
- Clone and Debug trait verification

Run tests with:

```bash
cargo test --test interactive_tests
```
