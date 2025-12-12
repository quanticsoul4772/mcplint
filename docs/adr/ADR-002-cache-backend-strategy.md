# ADR-002: Cache Backend Strategy

## Status
Accepted

## Date
2025-12-11

## Context

MCPLint uses caching to improve performance across multiple use cases:
- **Schema caching**: Avoid re-fetching tool schemas from servers
- **Scan result caching**: Skip redundant security scans
- **Validation caching**: Reuse protocol validation results
- **Corpus caching**: Persist fuzzing corpus across sessions
- **Tool hash caching**: Detect schema changes (rug-pull detection)

Different deployment scenarios have different requirements:
- Local development: Simple, no external dependencies
- CI/CD pipelines: Fast, ephemeral, deterministic
- Team environments: Shared cache for collaboration
- Air-gapped systems: No network dependencies

## Decision

### Multi-Backend Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CacheManager                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Cache Interface                      │   │
│  │  get(key) -> Option<Value>                       │   │
│  │  set(key, value, ttl)                            │   │
│  │  delete(key)                                      │   │
│  │  clear()                                          │   │
│  └─────────────────────────────────────────────────┘   │
│           │              │              │               │
│     ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐       │
│     │  Memory   │  │Filesystem │  │   Redis   │       │
│     │  Backend  │  │  Backend  │  │  Backend  │       │
│     └───────────┘  └───────────┘  └───────────┘       │
└─────────────────────────────────────────────────────────┘
```

### Backend Selection Algorithm

```
Environment Variable: MCPLINT_CACHE_BACKEND

1. Explicit Selection:
   - "memory"     → MemoryCache
   - "filesystem" → FilesystemCache
   - "redis"      → RedisCache (requires REDIS_URL)
   - "none"       → NoOpCache (disabled)

2. Auto-Detection (if not set):
   - If CI=true or GITHUB_ACTIONS=true → MemoryCache
   - If REDIS_URL is set → RedisCache
   - Otherwise → FilesystemCache (default)

3. Fallback Chain:
   - RedisCache fails → FilesystemCache
   - FilesystemCache fails → MemoryCache
   - MemoryCache always succeeds
```

### Cache Categories & TTLs

| Category | Default TTL | Purpose |
|----------|-------------|---------|
| Schema | 1 hour | Tool/resource schemas |
| ScanResult | 15 minutes | Security scan results |
| Validation | 30 minutes | Protocol validation |
| Corpus | 7 days | Fuzzing corpus data |
| ToolHash | 30 days | Rug-pull detection baselines |

### Backend Characteristics

| Backend | Persistence | Shared | Performance | Dependencies |
|---------|-------------|--------|-------------|--------------|
| Memory | No | No | Fastest | None |
| Filesystem | Yes | No* | Fast | Disk I/O |
| Redis | Yes | Yes | Network | Redis server |

*Filesystem can be shared via network mounts

### Implementation

```rust
// src/cache/mod.rs
pub struct CacheManager {
    backend: Box<dyn CacheBackend>,
    metrics: CacheMetrics,
}

impl CacheManager {
    pub fn from_env() -> Self {
        let backend = match std::env::var("MCPLINT_CACHE_BACKEND") {
            Ok(b) if b == "memory" => Box::new(MemoryCache::new()),
            Ok(b) if b == "redis" => {
                match RedisCache::from_env() {
                    Ok(r) => Box::new(r),
                    Err(_) => Box::new(FilesystemCache::default()),
                }
            }
            Ok(b) if b == "none" => Box::new(NoOpCache),
            _ => {
                if is_ci_environment() {
                    Box::new(MemoryCache::new())
                } else {
                    Box::new(FilesystemCache::default())
                }
            }
        };
        Self { backend, metrics: Default::default() }
    }
}
```

### Cache Key Design

```
Pattern: {category}:{server}:{operation}:{hash}

Examples:
- schema:filesystem-server:tools:abc123
- scan:my-server:full:def456
- corpus:test-server:mutation:ghi789
```

## Consequences

### Positive
- Flexible deployment options
- Graceful degradation on failures
- CI-friendly defaults
- Team collaboration via Redis
- Clear upgrade path

### Negative
- Multiple backends to maintain
- Redis adds operational complexity
- Cache invalidation complexity

### Risks
- Stale cache causing false negatives → mitigation: reasonable TTLs
- Cache poisoning → mitigation: key includes server identity
- Disk space growth → mitigation: LRU eviction, size limits

## Alternatives Considered

### 1. Filesystem Only
Simple, but doesn't work well in CI or team settings.
- Rejected: Limited flexibility

### 2. SQLite Backend
Single-file database for structured caching.
- Deferred: Adds complexity, filesystem works for now

### 3. No Caching
Stateless operation only.
- Rejected: Poor performance for repeated operations

## Configuration

```toml
# .mcplint.toml
[cache]
backend = "filesystem"  # memory, filesystem, redis, none
directory = "~/.cache/mcplint"
max_size_mb = 500

[cache.ttl]
schema = "1h"
scan_result = "15m"
validation = "30m"
corpus = "7d"
tool_hash = "30d"
```

## References

- `src/cache/mod.rs`: CacheManager implementation
- `src/cache/memory.rs`: In-memory backend
- `src/cache/filesystem.rs`: Filesystem backend
- `src/cache/redis.rs`: Redis backend
