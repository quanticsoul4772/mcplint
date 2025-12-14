# Enhanced Error Context with anyhow::Context

## Design Document

**Version:** 1.0
**Date:** 2025-12-14
**Status:** Proposed

---

## 1. Problem Statement

### Current Issue
Many error sites in MCPLint use bare `?` operators without operation context:

```rust
// Current (less helpful):
let config = std::fs::read_to_string(path)?;
// Error: "No such file or directory"

// Improved:
let config = std::fs::read_to_string(&path)
    .with_context(|| format!("Failed to read config from {}", path.display()))?;
// Error: "Failed to read config from /path/to/config.toml: No such file or directory"
```

### Impact
- **Debugging difficulty**: Users get cryptic errors like "No such file or directory" without knowing which file
- **Support burden**: More back-and-forth needed to diagnose issues
- **User frustration**: File I/O, network, and spawn errors lack actionable context

### Current State Analysis

**Files already using context well:**
- `src/ai/engine.rs` - Good context on rate limiting and generation
- `src/ai/neo4j_kb.rs` - Good context on Neo4j and embedding operations
- `src/ai/provider/*.rs` - Good context on API requests
- `src/cache/redis.rs` - Good context on Redis operations
- `src/cli/commands/multi_scan.rs` - Good context on config reading
- `src/cli/commands/servers.rs` - Good context on config reading
- `src/transport/stdio.rs` - Good context on spawn

**Files needing improvement:**
| File | Operations Missing Context | Priority |
|------|---------------------------|----------|
| `src/cli/commands/init.rs` | 6 file operations | High |
| `src/cache/filesystem.rs` | 8+ async file operations | High |
| `src/fuzzer/corpus.rs` | 10+ file operations | Medium |
| `src/cli/commands/fingerprint.rs` | 2 file writes | Medium |
| `src/cli/commands/cache.rs` | 2 file operations | Medium |
| `src/cli/completions.rs` | 1 file create | Low |
| `src/cli/commands/doctor.rs` | Multiple Command spawns | Low |
| `src/main.rs` | 1 directory creation | Low |

---

## 2. Design Principles

### 2.1 Context Message Guidelines

**DO:**
- Include the specific resource (file path, URL, server name)
- Use action verbs: "Failed to read", "Failed to write", "Failed to connect"
- Be specific about the operation: "Failed to create cache directory" not "IO error"

**DON'T:**
- Duplicate information already in the underlying error
- Use vague messages: "Error occurred", "Operation failed"
- Include sensitive data (passwords, tokens)

### 2.2 Context Patterns by Operation Type

**File Read:**
```rust
std::fs::read_to_string(&path)
    .with_context(|| format!("Failed to read {}", path.display()))?;
```

**File Write:**
```rust
fs::write(&path, &content)
    .with_context(|| format!("Failed to write to {}", path.display()))?;
```

**Directory Creation:**
```rust
fs::create_dir_all(&path)
    .with_context(|| format!("Failed to create directory {}", path.display()))?;
```

**Process Spawn:**
```rust
Command::new(&cmd)
    .spawn()
    .with_context(|| format!("Failed to spawn process: {}", cmd))?;
```

**Network Request:**
```rust
client.get(&url).send().await
    .with_context(|| format!("Failed to send request to {}", url))?;
```

**JSON Parsing:**
```rust
serde_json::from_str(&content)
    .with_context(|| format!("Failed to parse JSON from {}", source))?;
```

---

## 3. Implementation Plan

### Phase 1: High-Priority CLI Commands (6 changes)

**File: `src/cli/commands/init.rs`**

| Line | Current | Proposed |
|------|---------|----------|
| 290 | `fs::write(path, &config_content)?` | `fs::write(path, &config_content).with_context(\|\| format!("Failed to write config to {}", path.display()))?` |
| 363 | `fs::create_dir_all(workflow_dir)?` | `fs::create_dir_all(workflow_dir).with_context(\|\| format!("Failed to create workflow directory {}", workflow_dir.display()))?` |
| 410 | `fs::write(&workflow_path, workflow_content)?` | `fs::write(&workflow_path, workflow_content).with_context(\|\| format!("Failed to write GitHub Actions workflow to {}", workflow_path.display()))?` |
| 429 | `fs::read_to_string(gitignore_path)?` | `fs::read_to_string(gitignore_path).with_context(\|\| "Failed to read .gitignore")?` |
| 431 | `fs::write(gitignore_path, ...)?` | `fs::write(gitignore_path, ...).with_context(\|\| "Failed to update .gitignore")?` |
| 441 | `fs::write(gitignore_path, ...)?` | `fs::write(gitignore_path, ...).with_context(\|\| "Failed to create .gitignore")?` |

### Phase 2: Cache Filesystem Operations (8 changes)

**File: `src/cache/filesystem.rs`**

| Line | Current | Proposed |
|------|---------|----------|
| 50 | `fs::create_dir_all(&category_path).await?` | `fs::create_dir_all(&category_path).await.with_context(\|\| format!("Failed to create cache category directory: {}", category))?` |
| 72 | `fs::File::open(path).await?` | `fs::File::open(path).await.with_context(\|\| format!("Failed to open cache file {}", path.display()))?` |
| 74 | `file.read_to_end(&mut contents).await?` | `file.read_to_end(&mut contents).await.context("Failed to read cache file contents")?` |
| 92 | `fs::create_dir_all(parent).await?` | `fs::create_dir_all(parent).await.with_context(\|\| format!("Failed to create cache parent directory {}", parent.display()))?` |
| 97 | `fs::File::create(path).await?` | `fs::File::create(path).await.with_context(\|\| format!("Failed to create cache file {}", path.display()))?` |
| 98 | `file.write_all(&contents).await?` | `file.write_all(&contents).await.context("Failed to write cache file contents")?` |
| 113 | `fs::read_dir(&category_path).await?` | `fs::read_dir(&category_path).await.with_context(\|\| format!("Failed to list cache directory {}", category_path.display()))?` |
| 188 | `fs::remove_file(&path).await?` | `fs::remove_file(&path).await.with_context(\|\| format!("Failed to remove cache file {}", path.display()))?` |

### Phase 3: Fuzzer Corpus Operations (10 changes)

**File: `src/fuzzer/corpus.rs`**

| Line | Current | Proposed |
|------|---------|----------|
| 297 | `fs::create_dir_all(&seeds_dir)?` | `fs::create_dir_all(&seeds_dir).with_context(\|\| format!("Failed to create seeds directory {}", seeds_dir.display()))?` |
| 303 | `fs::write(filepath, json)?` | `fs::write(&filepath, json).with_context(\|\| format!("Failed to write seed file {}", filepath.display()))?` |
| 344 | `fs::create_dir_all(&crashes_dir)?` | `fs::create_dir_all(&crashes_dir).with_context(\|\| format!("Failed to create crashes directory {}", crashes_dir.display()))?` |
| 349 | `fs::write(filepath, json)?` | `fs::write(&filepath, json).with_context(\|\| format!("Failed to write crash record {}", filepath.display()))?` |
| 361 | `fs::create_dir_all(&hangs_dir)?` | `fs::create_dir_all(&hangs_dir).with_context(\|\| format!("Failed to create hangs directory {}", hangs_dir.display()))?` |
| 366 | `fs::write(filepath, json)?` | `fs::write(&filepath, json).with_context(\|\| format!("Failed to write hang record {}", filepath.display()))?` |
| 384 | `fs::create_dir_all(&interesting_dir)?` | `fs::create_dir_all(&interesting_dir).with_context(\|\| format!("Failed to create interesting directory {}", interesting_dir.display()))?` |
| 389 | `fs::write(filepath, json)?` | `fs::write(&filepath, json).with_context(\|\| format!("Failed to write interesting input {}", filepath.display()))?` |
| 227 | `fs::read_dir(&crashes_dir)?` | `fs::read_dir(&crashes_dir).with_context(\|\| format!("Failed to read crashes directory {}", crashes_dir.display()))?` |
| (etc) | Similar for hangs and interesting dirs | Add context to all read_dir calls |

### Phase 4: Other CLI Commands (5 changes)

**File: `src/cli/commands/fingerprint.rs`**
| Line | Current | Proposed |
|------|---------|----------|
| 139 | `std::fs::write(path, content)?` | `std::fs::write(&path, content).with_context(\|\| format!("Failed to write fingerprint to {}", path.display()))?` |

**File: `src/cli/commands/cache.rs`**
| Line | Current | Proposed |
|------|---------|----------|
| 148-149 | `std::fs::write(&output, ...)` | `std::fs::write(&output, ...).with_context(\|\| format!("Failed to export cache to {}", output.display()))?` |

**File: `src/cli/completions.rs`**
| Line | Current | Proposed |
|------|---------|----------|
| 35 | `std::fs::File::create(path)?` | `std::fs::File::create(&path).with_context(\|\| format!("Failed to create completions file {}", path.display()))?` |

**File: `src/main.rs`**
| Line | Current | Proposed |
|------|---------|----------|
| 952 | `std::fs::create_dir_all(&dir)?` | `std::fs::create_dir_all(&dir).with_context(\|\| format!("Failed to create output directory {}", dir.display()))?` |

### Phase 5: Command Spawning (optional, lower priority)

**File: `src/cli/commands/doctor.rs`**

The Command spawning in doctor.rs already handles errors gracefully with match expressions, so explicit context may not add much value. Consider adding context only if the error messages prove unhelpful in practice.

---

## 4. Import Requirements

Files needing new imports:

```rust
// Files that need to add:
use anyhow::Context;

// Files already having it (no change needed):
// - src/ai/engine.rs
// - src/ai/neo4j_kb.rs
// - src/ai/provider/*.rs
// - src/cache/filesystem.rs (already has it)
// - src/cache/redis.rs
// - src/cli/commands/multi_scan.rs
// - etc.
```

**Files needing import addition:**
- `src/cli/commands/init.rs`
- `src/fuzzer/corpus.rs`
- `src/cli/commands/fingerprint.rs`
- `src/cli/completions.rs`

---

## 5. Testing Strategy

### Manual Testing
1. Trigger each error condition:
   - Read non-existent file
   - Write to read-only location
   - Create directory without permissions
   - Connect to non-existent server

2. Verify error messages include:
   - Operation description
   - Resource identifier (path, URL, etc.)
   - Original error cause

### Automated Testing
Add test cases for error messages where practical:

```rust
#[test]
fn test_config_read_error_has_context() {
    let result = read_config(Path::new("/nonexistent/config.toml"));
    let err = result.unwrap_err();
    assert!(err.to_string().contains("Failed to read"));
    assert!(err.to_string().contains("/nonexistent/config.toml"));
}
```

---

## 6. Rollout Plan

### Step 1: Phase 1 (CLI commands/init.rs)
- Highest user visibility
- Most common error scenario (first-time setup)
- ~6 changes

### Step 2: Phase 2 (cache/filesystem.rs)
- Important for troubleshooting cache issues
- ~8 changes

### Step 3: Phase 3-4 (fuzzer + other CLI)
- Lower frequency operations
- ~15 changes

### Step 4: Review and document
- Update CLAUDE.md if needed
- Update CHANGELOG.md

---

## 7. Success Metrics

| Metric | Target |
|--------|--------|
| All file I/O operations have context | 100% |
| All network operations have context | 100% |
| All spawn operations have context | 100% |
| Error messages include resource identifier | 100% |
| No regression in existing tests | Pass |

---

## 8. File Changes Summary

| File | Changes | Lines Affected |
|------|---------|----------------|
| `src/cli/commands/init.rs` | Add context + import | 6 operations |
| `src/cache/filesystem.rs` | Add context (import exists) | 8 operations |
| `src/fuzzer/corpus.rs` | Add context + import | 10+ operations |
| `src/cli/commands/fingerprint.rs` | Add context + import | 1 operation |
| `src/cli/commands/cache.rs` | Add context (import exists) | 1 operation |
| `src/cli/completions.rs` | Add context + import | 1 operation |
| `src/main.rs` | Add context (import exists) | 1 operation |

**Total: ~28+ operations across 7 files**

---

## 9. Example Error Message Improvements

### Before
```
Error: No such file or directory (os error 2)
```

### After
```
Error: Failed to read config from /home/user/.config/mcplint/config.toml

Caused by:
    No such file or directory (os error 2)
```

### Before
```
Error: Permission denied (os error 13)
```

### After
```
Error: Failed to create cache directory /home/user/.mcplint-cache/schemas

Caused by:
    Permission denied (os error 13)
```

---

## Appendix A: Quick Reference

### Pattern for file read:
```rust
.with_context(|| format!("Failed to read {}", path.display()))?
```

### Pattern for file write:
```rust
.with_context(|| format!("Failed to write to {}", path.display()))?
```

### Pattern for directory:
```rust
.with_context(|| format!("Failed to create directory {}", path.display()))?
```

### Pattern for network:
```rust
.with_context(|| format!("Failed to connect to {}", url))?
```

### Pattern for spawn:
```rust
.with_context(|| format!("Failed to spawn {}", command))?
```

### Pattern for JSON:
```rust
.with_context(|| format!("Failed to parse {} as JSON", source))?
```
