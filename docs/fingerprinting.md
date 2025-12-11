# Tool Definition Fingerprinting

MCPLint provides a dual-tier fingerprinting system for MCP tool definitions that enables:
- **Schema Change Detection**: Track meaningful changes to tool schemas over time
- **Audit Trail**: Maintain cryptographic evidence of tool definitions for compliance
- **CI/CD Integration**: Detect breaking changes before deployment

## Overview

The fingerprinting system generates two types of hashes for each tool:

| Hash Type | Purpose | Ignores |
|-----------|---------|---------|
| **Semantic Hash** | Detect functional changes | Descriptions, whitespace, property ordering |
| **Full Hash** | Audit trail / tamper detection | Nothing (captures everything) |

## Quick Start

### CLI Usage

```bash
# Generate fingerprints for all tools on a server
mcplint fingerprint generate my-server

# Generate and save to file
mcplint fingerprint generate my-server --output fingerprints.json

# Compare against a baseline
mcplint fingerprint compare my-server --baseline baseline.json

# Output as JSON
mcplint fingerprint generate my-server --format json
```

### Programmatic Usage

```rust
use mcplint::fingerprinting::{FingerprintHasher, FingerprintComparator, ChangeSeverity};
use mcplint::protocol::mcp::Tool;

// Generate a fingerprint from a tool definition
let fingerprint = FingerprintHasher::fingerprint(&tool)?;
println!("Tool: {}", fingerprint.tool_name);
println!("Semantic hash: {}", fingerprint.semantic_hash);

// Compare two fingerprints
let diff = FingerprintComparator::compare(&old_fingerprint, &new_fingerprint);
println!("Severity: {:?}", diff.severity);

if diff.severity >= ChangeSeverity::Major {
    println!("Breaking changes detected!");
    for change in &diff.changes {
        println!("  - {:?}", change);
    }
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Fingerprinting System                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │    Tool      │───▶│  Normalizer  │───▶│     Hasher       │  │
│  │  Definition  │    │              │    │                  │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│                             │                     │              │
│                             ▼                     ▼              │
│                      ┌──────────────┐    ┌──────────────────┐  │
│                      │  Normalized  │    │  ToolFingerprint │  │
│                      │   Schema     │    │                  │  │
│                      └──────────────┘    └──────────────────┘  │
│                                                   │              │
│                                                   ▼              │
│                                          ┌──────────────────┐  │
│                                          │   Comparator     │  │
│                                          │                  │  │
│                                          └──────────────────┘  │
│                                                   │              │
│                                                   ▼              │
│                                          ┌──────────────────┐  │
│                                          │ FingerprintDiff  │  │
│                                          │  + Severity      │  │
│                                          │  + Changes       │  │
│                                          │  + Recommendations│  │
│                                          └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### SchemaNormalizer

Canonicalizes JSON schemas for consistent fingerprinting:

- **Property Ordering**: Sorts properties alphabetically
- **Type Canonicalization**: Normalizes type aliases (`String` → `string`, `bool` → `boolean`)
- **Required Sorting**: Sorts required field arrays
- **Description Handling**: Removes for semantic hash, normalizes for full hash

### FingerprintHasher

Generates SHA-256 hashes from normalized schemas:

```rust
// Generate fingerprint for a single tool
let fp = FingerprintHasher::fingerprint(&tool)?;

// Batch fingerprint multiple tools
let fingerprints = FingerprintHasher::fingerprint_all_ok(&tools);
```

### FingerprintComparator

Compares fingerprints and generates detailed diff reports:

```rust
let diff = FingerprintComparator::compare(&old_fp, &new_fp);

// Check severity
match diff.severity {
    ChangeSeverity::Breaking => panic!("Breaking changes!"),
    ChangeSeverity::Major => warn!("Major changes detected"),
    ChangeSeverity::Minor => info!("New features added"),
    ChangeSeverity::Patch => debug!("Documentation changes"),
    ChangeSeverity::None => {}
}
```

## Change Types

| Change Type | Severity | Description |
|-------------|----------|-------------|
| `ParameterRemoved` (required) | Breaking | Required parameter was removed |
| `TypeChanged` | Breaking | Parameter type incompatibility |
| `RequiredChanged` (→ required) | Major | Optional became required |
| `ParameterAdded` (required) | Major | New required parameter |
| `ParameterAdded` (optional) | Minor | New optional parameter |
| `ConstraintAdded` | Minor | New validation constraint |
| `ConstraintRemoved` | Minor | Validation relaxed |
| `DescriptionChanged` | Patch | Documentation only |

## Severity Levels

```
Breaking > Major > Minor > Patch > None

Breaking (✗): Requires client updates, may break existing integrations
Major    (!): Significant changes, review recommended
Minor    (+): New features, backward compatible
Patch    (~): Documentation/metadata only
None     (✓): No changes detected
```

## Data Structures

### ToolFingerprint

```rust
pub struct ToolFingerprint {
    pub tool_name: String,           // Tool identifier
    pub semantic_hash: String,       // SHA-256 (64 chars) - functional changes
    pub full_hash: String,           // SHA-256 (64 chars) - all changes
    pub schema_version: Option<String>,
    pub created_at: DateTime<Utc>,
    pub mcplint_version: String,
    pub metadata: FingerprintMetadata,
}
```

### FingerprintMetadata

```rust
pub struct FingerprintMetadata {
    pub parameter_count: usize,
    pub required_params: Vec<String>,
    pub param_types: HashMap<String, String>,
    pub complexity_score: u32,
}
```

### FingerprintDiff

```rust
pub struct FingerprintDiff {
    pub tool_name: String,
    pub old_semantic_hash: String,
    pub new_semantic_hash: String,
    pub old_full_hash: String,
    pub new_full_hash: String,
    pub changes: Vec<ChangeType>,
    pub severity: ChangeSeverity,
    pub summary: String,
    pub recommendations: Vec<String>,
}
```

## Baseline Integration

Fingerprints integrate with MCPLint's baseline system for incremental scanning:

```rust
use mcplint::baseline::Baseline;

// Create baseline with fingerprints
let baseline = Baseline::from_results(&scan_results)
    .with_fingerprints(fingerprints);

// Save for future comparison
baseline.save("baseline.json")?;

// Load and check for fingerprint changes
let loaded = Baseline::load("baseline.json")?;
if loaded.has_fingerprints() {
    let stored_fp = loaded.get_fingerprint("my_tool");
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: MCP Schema Check

on: [push, pull_request]

jobs:
  fingerprint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install MCPLint
        run: cargo install mcplint

      - name: Generate fingerprints
        run: mcplint fingerprint generate ./my-server --output current.json

      - name: Compare with baseline
        run: |
          mcplint fingerprint compare ./my-server --baseline baseline.json
          EXIT_CODE=$?
          if [ $EXIT_CODE -eq 1 ]; then
            echo "::error::Breaking changes detected!"
            exit 1
          elif [ $EXIT_CODE -eq 2 ]; then
            echo "::warning::Major changes detected"
          fi
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No changes or minor/patch changes |
| 1 | Breaking changes detected |
| 2 | Major changes detected |

## JSON Output Format

```json
{
  "tool_name": "read_file",
  "semantic_hash": "a1b2c3d4e5f6...",
  "full_hash": "f6e5d4c3b2a1...",
  "schema_version": null,
  "created_at": "2025-01-15T10:30:00Z",
  "mcplint_version": "0.1.0",
  "metadata": {
    "parameter_count": 2,
    "required_params": ["path"],
    "param_types": {
      "path": "string",
      "encoding": "string"
    },
    "complexity_score": 5
  }
}
```

## Best Practices

1. **Store baselines in version control** - Track schema evolution over time
2. **Run fingerprint checks in CI** - Catch breaking changes before merge
3. **Use semantic hash for compatibility** - Ignore non-functional changes
4. **Use full hash for audit** - Cryptographic proof of exact definitions
5. **Review Major changes** - May require client updates even if not breaking
6. **Document intentional changes** - Add context when updating baselines

## Troubleshooting

### "Baseline does not contain tool fingerprints"

The baseline was created before fingerprinting was added. Regenerate with:

```bash
mcplint fingerprint generate my-server --output new-baseline.json
```

### Hash mismatch on identical tools

Ensure both environments use the same MCPLint version. Schema normalization may differ between versions.

### Slow fingerprinting

Fingerprinting is CPU-bound (SHA-256). For many tools, consider:
- Running in parallel across servers
- Caching fingerprints between runs
- Using `--output` to persist results
