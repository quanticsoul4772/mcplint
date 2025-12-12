# MCPLint Performance Benchmarks

**Generated:** December 12, 2025
**Platform:** Windows 11
**Build:** Release (optimized)

---

## Summary

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Startup time (--version) | <100ms | ~18ms | PASS |
| Startup time (--help) | <100ms | ~22ms | PASS |
| Binary size | <20MB | 8.0MB | PASS |
| Rules list | <100ms | ~31ms | PASS |
| Servers list | <100ms | ~34ms | PASS |
| Cache stats | <100ms | ~38ms | PASS |
| Test suite (2188 tests) | <30s | ~2.2s | PASS |

---

## Detailed Results

### Startup Time

**Target:** <100ms for `--version`

```
Run 1: 68.2ms (cold cache)
Run 2: 16.6ms
Run 3: 18.2ms
Run 4: 16.6ms
Run 5: 19.4ms

Average (warm): ~17.7ms
```

**--help command:**
```
Run 1: 32.6ms (cold cache)
Run 2: 25.7ms
Run 3: 18.0ms
Run 4: 17.9ms
Run 5: 17.9ms

Average (warm): ~20.0ms
```

### Command Performance

| Command | Time |
|---------|------|
| `mcplint rules` | 31ms |
| `mcplint servers` | 34ms |
| `mcplint cache stats` | 38ms |
| `mcplint doctor` | 2.8s* |

*Doctor command checks external dependencies (Node.js, Python, etc.) which adds latency.

### Binary Size

- Release build: **8.0 MB**
- Includes all features (fuzzing, AI providers, caching)

### Test Suite

- **2,188 library tests** in ~2.2 seconds
- **2,331 binary tests**
- **Total: 4,519 tests**

---

## Optimizations Applied

1. **Lazy initialization** - Schemas loaded on-demand
2. **Release profile** - LTO, single codegen unit, symbol stripping
3. **Efficient CLI parsing** - clap with derive macros
4. **Cached config loading** - Server configs cached after first load

---

## Recommendations

1. All performance targets met
2. Startup time well under 100ms target
3. Binary size reasonable for feature set
4. Test suite runs quickly for CI/CD

---

*Benchmarks run on Windows 11, results may vary by platform.*
