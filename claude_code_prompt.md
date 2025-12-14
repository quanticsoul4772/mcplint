# MCPLint AI Enhancement Implementation

## Context

mcplint is a security testing tool for MCP servers, written in Rust. It currently uses AI only for post-detection explanations. We want to expand AI usage for semantic knowledge graphs, better prompts, and AI-powered detection.

## Implementation Documents Location

Project directory: `C:\Development\Projects\MCP\project-root\mcp-servers\mcplint`

Implementation guides (read these first):
1. **mcplint_ai_roadmap.md** - Complete roadmap and priorities
2. **mcplint_advanced_prompts.md** - Week 1: Advanced prompt engineering
3. **mcplint_neo4j_integration.md** - Week 2-3: Neo4j vector database
4. **mcplint_ai_detection.md** - Week 4+: AI-powered detection

## Prerequisites

**Environment Variables Required:**
```bash
# Neo4j (already configured in .env)
NEO4J_URI
NEO4J_USERNAME
NEO4J_PASSWORD
NEO4J_DATABASE

# Voyage AI (get from https://www.voyageai.com/)
VOYAGE_API_KEY
```

Note: Neo4j credentials are already set in .env file. Voyage AI key needed for Week 2.

## Phase 1 Implementation (Weeks 1-3)

### Week 1: Advanced Prompt Engineering

**Objective:** 15-20% better explanation quality, zero cost

**Implementation Steps:**

1. Read mcplint_advanced_prompts.md
2. Examine existing code: src/ai/engine.rs, src/ai/prompt.rs, src/cli/commands/explain.rs
3. Create src/ai/prompt_templates.rs (copy implementation from mcplint_advanced_prompts.md)
4. Integrate with ExplainEngine (modify src/ai/engine.rs)
5. Update module exports (modify src/ai/mod.rs - add: pub mod prompt_templates;)
6. Test: cargo test && cargo build --release

**Success Criteria:**
- All tests pass
- Explanations include category-specific analysis
- Few-shot examples visible in prompts

### Week 2-3: Neo4j Knowledge Graph Integration

**Objective:** Semantic similarity search, RAG-powered explanations

**Implementation Steps:**

1. Read mcplint_neo4j_integration.md
2. Add to Cargo.toml: neo4rs = "0.7"
3. Get Voyage AI API key from https://www.voyageai.com/
4. Create src/ai/neo4j_kb.rs (copy implementation from mcplint_neo4j_integration.md)
5. Modify src/ai/engine.rs (add knowledge_graph field, with_knowledge_graph method)
6. Update src/cli/commands/explain.rs (initialize Neo4j connection)
7. Update src/ai/mod.rs (add: pub mod neo4j_kb;)
8. Test and verify in Neo4j Browser

**Success Criteria:**
- Neo4j connection successful
- Vector indexes created
- Findings stored after scans
- Semantic similarity search works

## Testing Strategy

**Unit Tests:**
```bash
cargo test
```

**Integration Test:**
```bash
# Run scan
mcplint scan test-server --explain

# Check Neo4j (https://console.neo4j.io/)
MATCH (v:Vulnerability) RETURN count(v)
```

## Common Issues

**Neo4j connection fails:** Check .env file has correct credentials
**Voyage AI 401:** Check VOYAGE_API_KEY is set
**Compilation errors:** Run cargo update && cargo clean && cargo build

## Development Workflow

1. Read the implementation doc for current week
2. Review existing code
3. Create new files as specified
4. Run cargo check frequently
5. Write tests as you implement
6. Manual test with real MCP server
7. Verify in Neo4j

The implementation documents contain production-ready Rust code - copy implementations directly.

## Next Steps After Phase 1

- Week 4-5: AI-powered detection (mcplint_ai_detection.md)
- Week 6-8: Knowledge base population
- Month 3+: Feedback loops

Focus on Phase 1 first - get advanced prompts and Neo4j working.
