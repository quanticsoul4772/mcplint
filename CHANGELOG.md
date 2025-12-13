# Changelog

All notable changes to MCPLint will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2025-12-13

### Added

- **HTML Output Format**
  - Rich HTML reports with severity distribution charts
  - Finding cards with detailed information
  - Remediation guidance integration
  - Responsive design for all devices
  - Available via `--format html` on scan command
  - Integrated into interactive scan wizard

## [0.3.0] - 2025-12-12

### Added

- **Interactive Mode**
  - Scan wizard with server selection, profile choice, and category filtering
  - Fuzz wizard with profile, duration, workers, and corpus configuration
  - Init wizard for guided configuration file creation
  - Explain wizard with AI provider, audience level, and severity filtering
  - Automatic TTY and CI environment detection
  - FuzzySelect for intuitive server selection

- **Init Command Enhancements**
  - GitHub Actions workflow generation (.github/workflows/mcplint.yml)
  - Automatic .gitignore entry for .mcplint-cache/
  - Wizard-driven configuration with sensible defaults

### Changed

- Server argument now optional for scan, fuzz, and explain commands (wizard activates)
- OutputFormat and ScanProfile types consolidated in cli module
- Improved module organization for library consumers

### Tests

- Added interactive_tests.rs with 30 integration tests
- Test coverage for wizard result structs and output formats
- AI provider and audience level variant tests
- CI environment detection tests

## [0.2.0] - 2025-12-12

### Added

- **Phase 1: Smart Context Detection**
  - Automatic detection of TTY, CI, and plain output modes
  - NO_COLOR environment variable support
  - Unicode/ASCII fallback based on terminal capabilities

- **Phase 2: Progress Indicators**
  - Real-time progress bars for scan operations
  - Connection spinners with phase tracking
  - Multi-server progress tracking

- **Phase 3: Output Formatting**
  - Unified Printer API for consistent CLI output
  - Security-themed color system for severity levels
  - Structured output with separators, headers, key-value pairs

- **Phase 4: Enhanced Error Handling**
  - Miette-based diagnostic errors with source context
  - "Did you mean?" suggestions using Jaro-Winkler similarity
  - Contextual help for common errors (connection, timeout, config)

- **Phase 5: Shell Completions**
  - Dynamic shell completions for bash, zsh, fish, PowerShell
  - Server name completion from Claude Desktop config
  - Profile and format completion with descriptions

- **Phase 6: Watch Mode & CI Integration**
  - Differential watch mode showing new/fixed issues
  - Debounced file watching with configurable interval
  - Enhanced SARIF output for GitHub Code Scanning

- **Multi-Server Scanning**
  - Parallel scanning of multiple MCP servers
  - Configurable concurrency with semaphore control
  - Combined SARIF output for CI/CD pipelines
  - Aggregated statistics and severity counts

### Changed

- Improved CLI user experience across all commands
- Better error messages with actionable suggestions
- Optimized startup time (<20ms)

### Performance

- Startup time: ~18ms (target <100ms)
- Binary size: 8.0MB
- Test suite: 4,519 tests in ~2.2s

## [0.1.0] - 2025-12-01

### Added

- Initial release
- MCP protocol validation (56 rules)
- Security scanning with 15+ detection rules
- Coverage-guided fuzzing
- AI-assisted vulnerability explanation
- Multi-backend caching (memory, filesystem, Redis)
- SARIF, JUnit, GitLab output formats
- Watch mode for development
- Doctor command for environment checks
