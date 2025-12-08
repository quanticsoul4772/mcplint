# M4: Caching System Implementation Plan

## Overview

M4 implements a multi-backend caching layer for MCPLint, providing persistence for schemas, scan results, validation outputs, fuzzer corpus, and tool hashes for rug-pull detection.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Cache Manager                                │
│                    (Unified interface for all caches)                │
├─────────────────────────────────────────────────────────────────────┤
│                         Cache Trait                                  │
│   get() | set() | delete() | exists() | clear() | stats()          │
├──────────────────┬──────────────────┬───────────────────────────────┤
│    Filesystem    │      Memory      │            Redis              │
│   ~/.mcplint/    │   In-process     │    redis://host:port          │
│     cache/       │   HashMap        │      with TTL                 │
└──────────────────┴──────────────────┴───────────────────────────────┘
```

## File Structure

```
src/cache/
├── mod.rs              # Module exports, CacheManager, CacheConfig
├── backend.rs          # CacheBackend enum and trait definitions
├── filesystem.rs       # Filesystem cache implementation
├── memory.rs           # In-memory cache implementation
├── redis.rs            # Redis cache implementation
├── entry.rs            # CacheEntry with metadata (TTL, created, accessed)
├── key.rs              # CacheKey types for type-safe cache keys
└── stats.rs            # Cache statistics and metrics
```

## Components

### 1. Core Types (`mod.rs`, `backend.rs`)

```rust
/// Cache backend selection
#[derive(Debug, Clone)]
pub enum CacheBackend {
    Filesystem { path: PathBuf },
    Memory,
    Redis { url: String, ttl: Duration },
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub backend: CacheBackend,
    pub schema_ttl: Duration,      // Default: 1 hour
    pub result_ttl: Duration,      // Default: 24 hours
    pub validation_ttl: Duration,  // Default: 1 hour
    pub corpus_persist: bool,      // Default: true
    pub max_size_bytes: Option<u64>, // Optional size limit
}

/// Unified cache trait
#[async_trait]
pub trait Cache: Send + Sync {
    async fn get(&self, key: &CacheKey) -> Result<Option<CacheEntry>>;
    async fn set(&self, key: &CacheKey, entry: CacheEntry) -> Result<()>;
    async fn delete(&self, key: &CacheKey) -> Result<()>;
    async fn exists(&self, key: &CacheKey) -> Result<bool>;
    async fn clear(&self, category: Option<CacheCategory>) -> Result<u64>;
    async fn stats(&self) -> Result<CacheStats>;
    async fn prune_expired(&self) -> Result<u64>;
}
```

### 2. Cache Keys (`key.rs`)

```rust
/// Type-safe cache key categories
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CacheCategory {
    Schema,
    ScanResult,
    Validation,
    Corpus,
    ToolHash,
    AiResponse, // Future: M5
}

/// Cache key with category and identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub category: CacheCategory,
    pub identifier: String,
}

impl CacheKey {
    /// Schema cache key: hash of server executable + args
    pub fn schema(server_hash: &str) -> Self;

    /// Scan result key: server_hash + ruleset_hash
    pub fn scan_result(server_hash: &str, ruleset_hash: &str) -> Self;

    /// Validation key: server_hash + protocol_version
    pub fn validation(server_hash: &str, protocol_version: &str) -> Self;

    /// Corpus key: server identifier
    pub fn corpus(server_id: &str) -> Self;

    /// Tool hash key: server_id for rug-pull detection
    pub fn tool_hash(server_id: &str) -> Self;
}
```

### 3. Cache Entry (`entry.rs`)

```rust
/// Cached data with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// The cached data (serialized JSON)
    pub data: Vec<u8>,
    /// When this entry was created
    pub created_at: DateTime<Utc>,
    /// When this entry was last accessed
    pub last_accessed: DateTime<Utc>,
    /// Time-to-live for this entry
    pub ttl: Duration,
    /// Size in bytes
    pub size_bytes: u64,
    /// Optional metadata
    pub metadata: HashMap<String, String>,
}

impl CacheEntry {
    pub fn is_expired(&self) -> bool;
    pub fn remaining_ttl(&self) -> Option<Duration>;
}
```

### 4. Filesystem Backend (`filesystem.rs`)

```rust
/// Filesystem-based cache storage
pub struct FilesystemCache {
    base_path: PathBuf,
    config: CacheConfig,
}

impl FilesystemCache {
    /// Create with default path (~/.mcplint/cache/)
    pub fn new(config: CacheConfig) -> Result<Self>;

    /// Create with custom path
    pub fn with_path(path: PathBuf, config: CacheConfig) -> Result<Self>;
}

// Directory structure:
// ~/.mcplint/cache/
// ├── schemas/
// │   └── {server_hash}.json
// ├── scan_results/
// │   └── {server_hash}_{ruleset_hash}.json
// ├── validation/
// │   └── {server_hash}_{protocol_version}.json
// ├── corpus/
// │   └── {server_id}/
// │       ├── crashes/
// │       ├── hangs/
// │       └── interesting/
// ├── tool_hashes/
// │   └── {server_id}.json
// └── metadata.json  # Cache stats and housekeeping
```

### 5. Memory Backend (`memory.rs`)

```rust
/// In-memory cache for CI/ephemeral environments
pub struct MemoryCache {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
    config: CacheConfig,
    stats: AtomicCacheStats,
}

impl MemoryCache {
    pub fn new(config: CacheConfig) -> Self;
}
```

### 6. Redis Backend (`redis.rs`)

```rust
/// Redis-based distributed cache
pub struct RedisCache {
    client: redis::Client,
    config: CacheConfig,
    prefix: String,
}

impl RedisCache {
    pub async fn new(url: &str, config: CacheConfig) -> Result<Self>;

    /// Connect with connection pool
    pub async fn with_pool(url: &str, pool_size: usize, config: CacheConfig) -> Result<Self>;
}
```

### 7. Cache Statistics (`stats.rs`)

```rust
/// Cache usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: u64,
    pub total_size_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub hit_ratio: f64,
    pub by_category: HashMap<CacheCategory, CategoryStats>,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStats {
    pub entries: u64,
    pub size_bytes: u64,
    pub expired: u64,
}
```

### 8. Cache Manager (`mod.rs`)

```rust
/// Unified cache manager
pub struct CacheManager {
    backend: Box<dyn Cache>,
    config: CacheConfig,
}

impl CacheManager {
    /// Create from configuration
    pub async fn new(config: CacheConfig) -> Result<Self>;

    /// Schema caching
    pub async fn get_schema(&self, server_hash: &str) -> Result<Option<Vec<Tool>>>;
    pub async fn set_schema(&self, server_hash: &str, tools: &[Tool]) -> Result<()>;

    /// Scan result caching
    pub async fn get_scan_result(&self, server_hash: &str, ruleset_hash: &str)
        -> Result<Option<ScanResults>>;
    pub async fn set_scan_result(&self, server_hash: &str, ruleset_hash: &str,
        results: &ScanResults) -> Result<()>;

    /// Validation caching
    pub async fn get_validation(&self, server_hash: &str, protocol_version: &str)
        -> Result<Option<ValidationResult>>;
    pub async fn set_validation(&self, server_hash: &str, protocol_version: &str,
        result: &ValidationResult) -> Result<()>;

    /// Corpus management
    pub async fn get_corpus(&self, server_id: &str) -> Result<Option<CorpusData>>;
    pub async fn set_corpus(&self, server_id: &str, corpus: &CorpusData) -> Result<()>;
    pub async fn append_corpus(&self, server_id: &str, input: &FuzzInput) -> Result<()>;

    /// Tool hash for rug-pull detection
    pub async fn get_tool_hash(&self, server_id: &str) -> Result<Option<ToolHashRecord>>;
    pub async fn set_tool_hash(&self, server_id: &str, record: &ToolHashRecord) -> Result<()>;
    pub async fn check_rug_pull(&self, server_id: &str, current_tools: &[Tool])
        -> Result<Option<RugPullDetection>>;

    /// Maintenance
    pub async fn prune_expired(&self) -> Result<u64>;
    pub async fn clear(&self, category: Option<CacheCategory>) -> Result<u64>;
    pub async fn stats(&self) -> Result<CacheStats>;
    pub async fn export(&self, path: &Path) -> Result<()>;
    pub async fn import(&self, path: &Path) -> Result<u64>;
}
```

## CLI Integration

### New `cache` Command

```rust
// src/cli/commands/cache.rs

/// Cache management subcommands
#[derive(Subcommand)]
pub enum CacheCommand {
    /// Show cache statistics
    Stats {
        /// Show detailed per-category breakdown
        #[arg(long)]
        detailed: bool,
    },

    /// Clear cache
    Clear {
        /// Clear only specific category
        #[arg(long)]
        category: Option<CacheCategory>,

        /// Clear expired entries only
        #[arg(long)]
        expired_only: bool,
    },

    /// Export corpus for sharing
    Export {
        /// Output path
        #[arg(required = true)]
        output: PathBuf,

        /// Server ID to export (or all)
        #[arg(long)]
        server: Option<String>,
    },

    /// Import corpus
    Import {
        /// Input path
        #[arg(required = true)]
        input: PathBuf,
    },

    /// Prune expired entries
    Prune,
}
```

### CLI Examples

```bash
# Show cache usage
mcplint cache stats
mcplint cache stats --detailed

# Clear caches
mcplint cache clear                    # Clear all
mcplint cache clear --category schemas # Clear only schemas
mcplint cache clear --expired-only     # Clear expired only

# Export/import corpus
mcplint cache export ./corpus-backup.tar.gz
mcplint cache export ./corpus-backup.tar.gz --server my-server
mcplint cache import ./corpus-backup.tar.gz

# Prune expired entries
mcplint cache prune
```

## Integration Points

### 1. Scanner Integration

```rust
// In scanner/engine.rs
impl ScanEngine {
    pub async fn scan_with_cache(
        &self,
        server: &str,
        cache: &CacheManager,
    ) -> Result<ScanResults> {
        let server_hash = hash_server(server);
        let ruleset_hash = self.ruleset_hash();

        // Check cache first
        if let Some(cached) = cache.get_scan_result(&server_hash, &ruleset_hash).await? {
            return Ok(cached);
        }

        // Run scan
        let results = self.scan(server).await?;

        // Cache results
        cache.set_scan_result(&server_hash, &ruleset_hash, &results).await?;

        Ok(results)
    }
}
```

### 2. Validator Integration

```rust
// In validator/engine.rs
impl Validator {
    pub async fn validate_with_cache(
        &self,
        server: &str,
        protocol_version: &str,
        cache: &CacheManager,
    ) -> Result<ValidationResult> {
        let server_hash = hash_server(server);

        // Check cache
        if let Some(cached) = cache.get_validation(&server_hash, protocol_version).await? {
            return Ok(cached);
        }

        // Run validation
        let result = self.validate(server).await?;

        // Cache result
        cache.set_validation(&server_hash, protocol_version, &result).await?;

        Ok(result)
    }
}
```

### 3. Fuzzer Integration

```rust
// In fuzzer/session.rs
impl FuzzSession {
    pub async fn run_with_cache(
        &mut self,
        cache: &CacheManager,
    ) -> Result<FuzzResults> {
        // Load existing corpus from cache
        if let Some(corpus_data) = cache.get_corpus(&self.server_id()).await? {
            self.corpus.load_from_cache(corpus_data)?;
        }

        // Run fuzzing
        let results = self.run().await?;

        // Save corpus to cache
        cache.set_corpus(&self.server_id(), &self.corpus.to_cache_data()).await?;

        Ok(results)
    }
}
```

### 4. Rug-Pull Detection Integration

```rust
// In scanner/rules/rug_pull.rs
pub async fn check_rug_pull(
    server_id: &str,
    current_tools: &[Tool],
    cache: &CacheManager,
) -> Result<Option<Finding>> {
    if let Some(detection) = cache.check_rug_pull(server_id, current_tools).await? {
        return Ok(Some(Finding {
            rule_id: "SEC-015".to_string(),
            severity: Severity::High,
            message: format!(
                "Tool definitions changed since last scan: {} tools added, {} removed, {} modified",
                detection.added.len(),
                detection.removed.len(),
                detection.modified.len()
            ),
            evidence: serde_json::to_value(&detection)?,
            ..Default::default()
        }));
    }

    // Store current hash for future detection
    let record = ToolHashRecord::from_tools(current_tools);
    cache.set_tool_hash(server_id, &record).await?;

    Ok(None)
}
```

## Configuration

### Default Configuration

```rust
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            backend: CacheBackend::Filesystem {
                path: dirs::home_dir()
                    .unwrap_or_default()
                    .join(".mcplint")
                    .join("cache"),
            },
            schema_ttl: Duration::from_secs(3600),      // 1 hour
            result_ttl: Duration::from_secs(86400),     // 24 hours
            validation_ttl: Duration::from_secs(3600), // 1 hour
            corpus_persist: true,
            max_size_bytes: None,
        }
    }
}
```

### TOML Configuration

```toml
[cache]
backend = "filesystem"         # filesystem | memory | redis
path = "~/.mcplint/cache"      # For filesystem backend
redis_url = "redis://localhost:6379"  # For redis backend
schema_ttl = "1h"
result_ttl = "24h"
corpus_persist = true
max_size = "1GB"               # Optional size limit
```

## Implementation Phases

### Phase 1: Core Infrastructure
1. Create `src/cache/mod.rs` with `CacheConfig` and module structure
2. Implement `CacheKey` and `CacheEntry` types
3. Define `Cache` trait with full interface
4. Implement `CacheStats`

### Phase 2: Filesystem Backend
1. Implement `FilesystemCache` with directory structure
2. Add file locking for concurrent access
3. Implement metadata tracking
4. Add compression support (optional)

### Phase 3: Memory Backend
1. Implement `MemoryCache` with `RwLock<HashMap>`
2. Add LRU eviction when size limit reached
3. Implement atomic stats tracking

### Phase 4: Redis Backend
1. Implement `RedisCache` with connection pooling
2. Add key prefixing and TTL support
3. Implement batch operations

### Phase 5: Cache Manager
1. Implement unified `CacheManager` interface
2. Add schema, scan result, validation caching
3. Add corpus caching and management
4. Implement rug-pull detection with tool hashing

### Phase 6: CLI Integration
1. Add `cache` command with subcommands
2. Integrate caching into existing commands
3. Add `--no-cache` and `--cache-only` flags

### Phase 7: Testing & Documentation
1. Unit tests for each backend
2. Integration tests for cache manager
3. CI caching examples
4. Performance benchmarks

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn filesystem_cache_basic_operations() {
        let cache = FilesystemCache::new(CacheConfig::default())?;
        let key = CacheKey::schema("test-server");

        // Set and get
        cache.set(&key, entry.clone()).await?;
        let retrieved = cache.get(&key).await?;
        assert_eq!(retrieved, Some(entry));

        // Delete
        cache.delete(&key).await?;
        assert!(cache.get(&key).await?.is_none());
    }

    #[tokio::test]
    async fn cache_expiration() {
        let config = CacheConfig {
            schema_ttl: Duration::from_millis(100),
            ..Default::default()
        };
        let cache = MemoryCache::new(config);

        cache.set(&key, entry).await?;
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(cache.get(&key).await?.is_none());
    }

    #[tokio::test]
    async fn rug_pull_detection() {
        let cache = CacheManager::new(CacheConfig::default()).await?;

        // Store initial tools
        let tools_v1 = vec![tool("read_file"), tool("write_file")];
        cache.set_tool_hash("server1", &ToolHashRecord::from_tools(&tools_v1)).await?;

        // Modified tools
        let tools_v2 = vec![tool("read_file"), tool("execute_shell")];
        let detection = cache.check_rug_pull("server1", &tools_v2).await?;

        assert!(detection.is_some());
        assert_eq!(detection.unwrap().added, vec!["execute_shell"]);
        assert_eq!(detection.unwrap().removed, vec!["write_file"]);
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn scan_with_cache_hit() {
    let cache = CacheManager::new(CacheConfig::default()).await?;
    let engine = ScanEngine::new(ScanConfig::default());

    // First scan - cache miss
    let start = Instant::now();
    let result1 = engine.scan_with_cache("./test-server", &cache).await?;
    let first_duration = start.elapsed();

    // Second scan - cache hit
    let start = Instant::now();
    let result2 = engine.scan_with_cache("./test-server", &cache).await?;
    let second_duration = start.elapsed();

    assert_eq!(result1, result2);
    assert!(second_duration < first_duration / 10); // Much faster
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Cache MCPLint
        uses: actions/cache@v4
        with:
          path: ~/.mcplint/cache
          key: mcplint-${{ hashFiles('mcp-config.json') }}-${{ github.sha }}
          restore-keys: |
            mcplint-${{ hashFiles('mcp-config.json') }}-
            mcplint-

      - name: Run MCPLint
        run: |
          mcplint check ./my-server --format=sarif --output=results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Success Criteria

1. **Functional**
   - All three backends (filesystem, memory, Redis) fully operational
   - Cache hit/miss tracking with accurate stats
   - TTL expiration working correctly
   - Rug-pull detection via tool hash comparison

2. **Performance**
   - Cache lookup < 10ms (filesystem), < 1ms (memory), < 5ms (Redis)
   - 90%+ cache hit rate for repeated scans
   - Minimal memory overhead for memory backend

3. **Integration**
   - Scanner, validator, fuzzer all use caching seamlessly
   - CLI commands for cache management work correctly
   - CI/CD integration tested and documented

4. **Testing**
   - >90% code coverage for cache module
   - All backends tested with same test suite
   - Race condition tests for concurrent access

## Dependencies

```toml
# Add to Cargo.toml
redis = { version = "0.27", features = ["tokio-comp"], optional = true }
lz4 = { version = "1.28", optional = true }  # Optional compression

[features]
redis = ["dep:redis"]
compression = ["dep:lz4"]
```

## Estimated Effort

| Phase | Description | Effort |
|-------|-------------|--------|
| 1 | Core Infrastructure | Small |
| 2 | Filesystem Backend | Medium |
| 3 | Memory Backend | Small |
| 4 | Redis Backend | Medium |
| 5 | Cache Manager | Medium |
| 6 | CLI Integration | Small |
| 7 | Testing | Medium |

**Total: Medium complexity milestone**
