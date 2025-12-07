# Contributing to MCPLint

Thank you for your interest in contributing to MCPLint!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/mcplint.git`
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Run lints: `cargo clippy`
7. Format code: `cargo fmt`
8. Commit your changes
9. Push to your fork and submit a pull request

## Development Setup

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the project
cargo build

# Run tests
cargo test

# Run with debug output
cargo run -- -vvv validate node your-server.js
```

## Code Style

- Follow Rust conventions and idioms
- Run `cargo fmt` before committing
- Ensure `cargo clippy` passes without warnings
- Add tests for new functionality

## Adding Security Rules

Security rules are defined in `src/rules/mod.rs`. Each rule should have:

- A unique ID following the pattern `MCP-<CATEGORY>-###`
- Categories: `injection`, `auth`, `transport`, `protocol`, `data`, `dos`
- Clear name and description
- Appropriate severity level
- References to CWE or CVE where applicable

## Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Update documentation if needed
- Add tests for new functionality
- Ensure CI passes before requesting review

## Reporting Issues

When reporting bugs, please include:

- MCPLint version (`mcplint --version`)
- Operating system and version
- Steps to reproduce
- Expected vs actual behavior
- Any relevant error messages

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
