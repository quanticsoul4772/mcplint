# MCPLint Neo4j Vector Integration Plan

## 1. Add Dependencies to Cargo.toml

```toml
[dependencies]
# Existing dependencies...

# Neo4j driver
neo4rs = "0.7"

# Embeddings API (Voyage AI recommended for code)
reqwest = { version = "0.12", features = ["json"] }  # Already exists
```

## 2. Neo4j Knowledge Graph Module

### src/ai/neo4j_kb.rs (NEW FILE)

```rust
//! Neo4j Security Knowledge Graph
//! 
//! Combines vector search with graph traversal for:
//! - Similar vulnerability finding
//! - CVE/CWE knowledge retrieval
//! - Cross-server pattern detection
//! - Remediation pattern matching

use anyhow::{Context, Result};
use neo4rs::{Graph, Query, ConfigBuilder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::scanner::Finding;

/// Neo4j connection credentials
#[derive(Clone)]
pub struct Neo4jConfig {
    pub uri: String,
    pub username: String,
    pub password: String,
    pub database: String,
}

impl Neo4jConfig {
    /// Load from environment variables
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            uri: std::env::var("NEO4J_URI")
                .context("NEO4J_URI not set")?,
            username: std::env::var("NEO4J_USERNAME")
                .unwrap_or_else(|_| "neo4j".to_string()),
            password: std::env::var("NEO4J_PASSWORD")
                .context("NEO4J_PASSWORD not set")?,
            database: std::env::var("NEO4J_DATABASE")
                .unwrap_or_else(|_| "neo4j".to_string()),
        })
    }
}

/// Security knowledge graph backed by Neo4j
pub struct SecurityKnowledgeGraph {
    graph: Arc<Graph>,
    embedder: Arc<dyn EmbeddingProvider>,
}

/// Vector embedding provider trait
#[async_trait::async_trait]
pub trait EmbeddingProvider: Send + Sync {
    async fn embed(&self, text: &str) -> Result<Vec<f32>>;
    fn dimensions(&self) -> usize;
}

/// Voyage AI embedding provider (recommended for code)
pub struct VoyageEmbedder {
    api_key: String,
    model: String,
    dimensions: usize,
}

impl VoyageEmbedder {
    pub fn new() -> Result<Self> {
        let api_key = std::env::var("VOYAGE_API_KEY")
            .context("VOYAGE_API_KEY not set")?;
        
        Ok(Self {
            api_key,
            model: "voyage-code-2".to_string(),
            dimensions: 1536,
        })
    }
}

#[async_trait::async_trait]
impl EmbeddingProvider for VoyageEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let client = reqwest::Client::new();
        
        #[derive(Serialize)]
        struct Request {
            input: Vec<String>,
            model: String,
        }
        
        #[derive(Deserialize)]
        struct Response {
            data: Vec<EmbeddingData>,
        }
        
        #[derive(Deserialize)]
        struct EmbeddingData {
            embedding: Vec<f32>,
        }
        
        let response: Response = client
            .post("https://api.voyageai.com/v1/embeddings")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&Request {
                input: vec![text.to_string()],
                model: self.model.clone(),
            })
            .send()
            .await?
            .json()
            .await?;
        
        Ok(response.data[0].embedding.clone())
    }
    
    fn dimensions(&self) -> usize {
        self.dimensions
    }
}

/// Similar finding result
#[derive(Debug, Clone)]
pub struct SimilarFinding {
    pub finding_id: String,
    pub rule_id: String,
    pub similarity_score: f64,
    pub title: String,
    pub server: String,
}

/// CWE knowledge record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweKnowledge {
    pub id: String,
    pub name: String,
    pub description: String,
    pub mitigation: String,
}

/// CVE record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveRecord {
    pub id: String,
    pub description: String,
    pub cvss_score: f32,
    pub published_date: String,
}

impl SecurityKnowledgeGraph {
    /// Create a new knowledge graph connection
    pub async fn new(config: Neo4jConfig, embedder: Arc<dyn EmbeddingProvider>) -> Result<Self> {
        let graph_config = ConfigBuilder::default()
            .uri(&config.uri)
            .user(&config.username)
            .password(&config.password)
            .db(&config.database)
            .build()?;
        
        let graph = Arc::new(Graph::new(graph_config).await?);
        
        let kg = Self { graph, embedder };
        
        // Initialize schema and indexes
        kg.initialize_schema().await?;
        
        Ok(kg)
    }
    
    /// Initialize Neo4j schema and vector indexes
    async fn initialize_schema(&self) -> Result<()> {
        // Create constraints
        let constraints = vec![
            "CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (c:CWE) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT tool_id IF NOT EXISTS FOR (t:Tool) REQUIRE (t.server, t.name) IS UNIQUE",
        ];
        
        for constraint in constraints {
            let query = Query::new(constraint.to_string());
            let _ = self.graph.run(query).await; // Ignore if already exists
        }
        
        // Create vector index for vulnerabilities
        // Note: Adjust dimensions based on your embedding model
        let dimensions = self.embedder.dimensions();
        let create_vector_index = format!(
            "CREATE VECTOR INDEX vulnerability_embeddings IF NOT EXISTS
             FOR (v:Vulnerability) ON (v.embedding)
             OPTIONS {{
               indexConfig: {{
                 `vector.dimensions`: {},
                 `vector.similarity_function`: 'cosine'
               }}
             }}",
            dimensions
        );
        
        let query = Query::new(create_vector_index);
        let _ = self.graph.run(query).await;
        
        // Create vector index for CWEs
        let create_cwe_index = format!(
            "CREATE VECTOR INDEX cwe_embeddings IF NOT EXISTS
             FOR (c:CWE) ON (c.embedding)
             OPTIONS {{
               indexConfig: {{
                 `vector.dimensions`: {},
                 `vector.similarity_function`: 'cosine'
               }}
             }}",
            dimensions
        );
        
        let query = Query::new(create_cwe_index);
        let _ = self.graph.run(query).await;
        
        Ok(())
    }
    
    /// Store a finding in the knowledge graph
    pub async fn store_finding(&self, finding: &Finding, server: &str) -> Result<()> {
        // Generate embedding for the finding
        let embedding_text = format!(
            "{} {} {}",
            finding.title,
            finding.description,
            finding.evidence.iter()
                .map(|e| e.data.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );
        
        let embedding = self.embedder.embed(&embedding_text).await?;
        
        // Store in Neo4j
        let query = Query::new(
            "MERGE (v:Vulnerability {id: $id})
             SET v.rule_id = $rule_id,
                 v.severity = $severity,
                 v.title = $title,
                 v.description = $description,
                 v.server = $server,
                 v.embedding = $embedding,
                 v.updated_at = datetime()
             RETURN v"
        )
        .param("id", finding.id.clone())
        .param("rule_id", finding.rule_id.clone())
        .param("severity", finding.severity.to_string())
        .param("title", finding.title.clone())
        .param("description", finding.description.clone())
        .param("server", server.to_string())
        .param("embedding", embedding);
        
        self.graph.run(query).await?;
        
        // Link to CWE if available
        if let Some(cwe_ref) = finding.references.iter()
            .find(|r| r.kind == crate::scanner::ReferenceKind::Cwe) 
        {
            self.link_to_cwe(&finding.id, &cwe_ref.id).await?;
        }
        
        Ok(())
    }
    
    /// Link a vulnerability to a CWE
    async fn link_to_cwe(&self, vuln_id: &str, cwe_id: &str) -> Result<()> {
        let query = Query::new(
            "MATCH (v:Vulnerability {id: $vuln_id})
             MERGE (c:CWE {id: $cwe_id})
             MERGE (v)-[:MAPS_TO]->(c)"
        )
        .param("vuln_id", vuln_id.to_string())
        .param("cwe_id", cwe_id.to_string());
        
        self.graph.run(query).await?;
        Ok(())
    }
    
    /// Find similar vulnerabilities using vector search
    pub async fn find_similar_vulnerabilities(
        &self,
        finding: &Finding,
        top_k: usize,
        min_similarity: f64,
    ) -> Result<Vec<SimilarFinding>> {
        // Generate embedding
        let embedding_text = format!("{} {}", finding.title, finding.description);
        let embedding = self.embedder.embed(&embedding_text).await?;
        
        // Vector similarity search in Neo4j
        let query = Query::new(
            "CALL db.index.vector.queryNodes('vulnerability_embeddings', $top_k, $embedding)
             YIELD node as vuln, score
             WHERE score >= $min_similarity AND vuln.id <> $current_id
             RETURN vuln.id as id,
                    vuln.rule_id as rule_id,
                    vuln.title as title,
                    vuln.server as server,
                    score
             ORDER BY score DESC"
        )
        .param("top_k", top_k as i64)
        .param("embedding", embedding)
        .param("min_similarity", min_similarity)
        .param("current_id", finding.id.clone());
        
        let mut result = self.graph.execute(query).await?;
        let mut similar = Vec::new();
        
        while let Some(row) = result.next().await? {
            similar.push(SimilarFinding {
                finding_id: row.get("id")?,
                rule_id: row.get("rule_id")?,
                title: row.get("title")?,
                server: row.get("server")?,
                similarity_score: row.get("score")?,
            });
        }
        
        Ok(similar)
    }
    
    /// Get CWE knowledge for a finding
    pub async fn get_cwe_knowledge(&self, cwe_id: &str) -> Result<Option<CweKnowledge>> {
        let query = Query::new(
            "MATCH (c:CWE {id: $cwe_id})
             RETURN c.id as id,
                    c.name as name,
                    c.description as description,
                    c.mitigation as mitigation"
        )
        .param("cwe_id", cwe_id.to_string());
        
        let mut result = self.graph.execute(query).await?;
        
        if let Some(row) = result.next().await? {
            Ok(Some(CweKnowledge {
                id: row.get("id")?,
                name: row.get("name")?,
                description: row.get("description")?,
                mitigation: row.get("mitigation")?,
            }))
        } else {
            Ok(None)
        }
    }
    
    /// Find cross-server patterns (same vulnerability in different servers)
    pub async fn find_cross_server_patterns(
        &self,
        min_similarity: f64,
    ) -> Result<Vec<(String, String, String, f64)>> {
        let query = Query::new(
            "MATCH (v1:Vulnerability)
             CALL db.index.vector.queryNodes('vulnerability_embeddings', 10, v1.embedding)
             YIELD node as v2, score
             WHERE score >= $min_similarity 
               AND v1.server <> v2.server
               AND id(v1) < id(v2)
             RETURN DISTINCT v1.server as server1,
                    v2.server as server2,
                    v1.rule_id as rule_id,
                    score
             ORDER BY score DESC
             LIMIT 100"
        )
        .param("min_similarity", min_similarity);
        
        let mut result = self.graph.execute(query).await?;
        let mut patterns = Vec::new();
        
        while let Some(row) = result.next().await? {
            patterns.push((
                row.get("server1")?,
                row.get("server2")?,
                row.get("rule_id")?,
                row.get("score")?,
            ));
        }
        
        Ok(patterns)
    }
    
    /// Get related CVEs for a finding (via CWE mapping)
    pub async fn get_related_cves(&self, finding: &Finding) -> Result<Vec<CveRecord>> {
        let query = Query::new(
            "MATCH (v:Vulnerability {id: $vuln_id})-[:MAPS_TO]->(cwe:CWE)<-[:EXPLOITS]-(cve:CVE)
             RETURN cve.id as id,
                    cve.description as description,
                    cve.cvss_score as cvss_score,
                    cve.published_date as published_date
             ORDER BY cve.cvss_score DESC
             LIMIT 10"
        )
        .param("vuln_id", finding.id.clone());
        
        let mut result = self.graph.execute(query).await?;
        let mut cves = Vec::new();
        
        while let Some(row) = result.next().await? {
            cves.push(CveRecord {
                id: row.get("id")?,
                description: row.get("description")?,
                cvss_score: row.get("cvss_score")?,
                published_date: row.get("published_date")?,
            });
        }
        
        Ok(cves)
    }
    
    /// Populate CWE knowledge base (run once during initialization)
    pub async fn populate_cwe_knowledge(&self) -> Result<()> {
        // Sample CWEs - in production, load from CWE database
        let cwes = vec![
            ("CWE-78", "OS Command Injection", "Improper neutralization of special elements used in OS commands", "Use parameterized APIs, validate input, apply allowlists"),
            ("CWE-79", "Cross-site Scripting", "Improper neutralization of input during web page generation", "Escape output, use Content Security Policy, validate input"),
            ("CWE-89", "SQL Injection", "Improper neutralization of special elements in SQL commands", "Use parameterized queries, ORMs, input validation"),
            ("CWE-502", "Deserialization of Untrusted Data", "Deserializing untrusted data without validation", "Avoid deserializing untrusted data, use safe formats, validate schemas"),
        ];
        
        for (id, name, desc, mitigation) in cwes {
            // Generate embedding for CWE
            let embedding_text = format!("{} {} {}", name, desc, mitigation);
            let embedding = self.embedder.embed(&embedding_text).await?;
            
            let query = Query::new(
                "MERGE (c:CWE {id: $id})
                 SET c.name = $name,
                     c.description = $description,
                     c.mitigation = $mitigation,
                     c.embedding = $embedding"
            )
            .param("id", id.to_string())
            .param("name", name.to_string())
            .param("description", desc.to_string())
            .param("mitigation", mitigation.to_string())
            .param("embedding", embedding);
            
            self.graph.run(query).await?;
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    #[ignore] // Requires Neo4j connection
    async fn test_store_and_retrieve() {
        let config = Neo4jConfig::from_env().unwrap();
        let embedder = Arc::new(VoyageEmbedder::new().unwrap());
        let kg = SecurityKnowledgeGraph::new(config, embedder).await.unwrap();
        
        let finding = Finding::new(
            "MCP-INJ-001",
            crate::scanner::Severity::High,
            "Command Injection",
            "Tool accepts unsanitized input",
        );
        
        kg.store_finding(&finding, "test-server").await.unwrap();
        
        let similar = kg.find_similar_vulnerabilities(&finding, 5, 0.8).await.unwrap();
        assert!(!similar.is_empty());
    }
}
```

## 3. Integration with ExplainEngine

### src/ai/engine.rs (MODIFICATIONS)

```rust
// Add to ExplainEngine struct
pub struct ExplainEngine {
    provider: Arc<dyn AiProvider>,
    cache: Option<Arc<CacheManager>>,
    rate_limiter: Arc<RateLimiter>,
    default_context: ExplanationContext,
    stats: Arc<RwLock<EngineStats>>,
    
    // NEW: Knowledge graph integration
    knowledge_graph: Option<Arc<SecurityKnowledgeGraph>>,
}

impl ExplainEngine {
    /// Add knowledge graph support
    pub fn with_knowledge_graph(mut self, kg: Arc<SecurityKnowledgeGraph>) -> Self {
        self.knowledge_graph = Some(kg);
        self
    }
    
    /// Enhanced explain with RAG
    pub async fn explain_with_context(
        &self,
        finding: &Finding,
        context: &ExplanationContext,
    ) -> Result<ExplanationResponse> {
        // Check cache first (existing logic)
        if let Some(cached) = self.get_cached(finding, context).await {
            return Ok(cached);
        }
        
        // NEW: Check semantic similarity in knowledge graph
        if let Some(kg) = &self.knowledge_graph {
            let similar = kg.find_similar_vulnerabilities(finding, 1, 0.95).await?;
            
            if let Some(sim) = similar.first() {
                tracing::info!(
                    "Found similar finding: {} (score: {:.3})",
                    sim.finding_id,
                    sim.similarity_score
                );
                
                // Try to get cached explanation for similar finding
                let similar_finding = Finding::new(
                    &sim.rule_id,
                    finding.severity, // Use same severity
                    &sim.title,
                    "", // Description not needed for cache lookup
                );
                
                if let Some(cached) = self.get_cached(&similar_finding, context).await {
                    tracing::info!("Using cached explanation from similar finding");
                    return Ok(cached);
                }
            }
        }
        
        // NEW: Augment prompt with knowledge graph context
        let augmented_context = if let Some(kg) = &self.knowledge_graph {
            let mut ctx = context.clone();
            
            // Get CWE knowledge
            if let Some(cwe_ref) = finding.references.iter()
                .find(|r| r.kind == crate::scanner::ReferenceKind::Cwe)
            {
                if let Ok(Some(cwe_knowledge)) = kg.get_cwe_knowledge(&cwe_ref.id).await {
                    ctx.cwe_details = Some(cwe_knowledge);
                }
            }
            
            // Get related CVEs
            if let Ok(cves) = kg.get_related_cves(finding).await {
                ctx.related_cves = cves;
            }
            
            ctx
        } else {
            context.clone()
        };
        
        // Rate limit and generate (existing logic)
        let estimated_tokens = estimate_tokens(finding);
        self.rate_limiter.acquire(estimated_tokens).await?;
        
        let response = self.provider
            .explain_finding(finding, &augmented_context)
            .await?;
        
        // Update stats (existing logic)
        {
            let mut stats = self.stats.write().await;
            stats.total_explanations += 1;
            stats.api_calls += 1;
            if response.metadata.tokens_used > 0 {
                stats.tokens_used += response.metadata.tokens_used as u64;
                self.rate_limiter
                    .record_tokens(response.metadata.tokens_used, estimated_tokens)
                    .await;
            }
            if response.metadata.response_time_ms > 0 {
                stats.total_response_time_ms += response.metadata.response_time_ms;
            }
        }
        
        // Store in cache (existing logic)
        self.store_cached(finding, context, &response).await;
        
        // NEW: Store in knowledge graph
        if let Some(kg) = &self.knowledge_graph {
            let server = context.server_name;
            if let Err(e) = kg.store_finding(finding, server).await {
                tracing::warn!("Failed to store finding in knowledge graph: {}", e);
            }
        }
        
        Ok(response)
    }
}
```

## 4. CLI Integration

### src/cli/commands/explain.rs (MODIFICATIONS)

```rust
use crate::ai::neo4j_kb::{Neo4jConfig, SecurityKnowledgeGraph, VoyageEmbedder};

pub async fn run_scan(
    // ... existing parameters
) -> Result<()> {
    // ... existing server resolution and scan logic
    
    // Create AI configuration
    let ai_config = build_ai_config(provider, model, timeout)?;
    
    // Create explain engine
    let mut engine = ExplainEngine::new(ai_config)?;
    
    // Add cache support (existing)
    if !no_cache {
        if let Ok(cache) = CacheManager::new(CacheConfig::default()).await {
            engine = engine.with_cache(Arc::new(cache));
        }
    }
    
    // NEW: Add knowledge graph support
    if let Ok(neo4j_config) = Neo4jConfig::from_env() {
        match VoyageEmbedder::new() {
            Ok(embedder) => {
                match SecurityKnowledgeGraph::new(neo4j_config, Arc::new(embedder)).await {
                    Ok(kg) => {
                        tracing::info!("Connected to Neo4j knowledge graph");
                        engine = engine.with_knowledge_graph(Arc::new(kg));
                    }
                    Err(e) => {
                        tracing::warn!("Failed to connect to knowledge graph: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Voyage AI embeddings not available: {}", e);
            }
        }
    }
    
    // ... rest of existing logic
}
```

## 5. Environment Variables

Add to your `.env` or export in shell:

```bash
# Neo4j (already configured)
export NEO4J_URI=neo4j+s://b0751520.databases.neo4j.io
export NEO4J_USERNAME=neo4j
export NEO4J_PASSWORD=zTO7A2LGX9Wp9VjSgA9ZNnuh4ch2W_U4A0qafVurHNE
export NEO4J_DATABASE=neo4j

# Voyage AI for embeddings (recommended for code)
export VOYAGE_API_KEY=your_voyage_api_key

# Alternative: OpenAI embeddings
# export OPENAI_API_KEY=your_openai_api_key
```

## 6. Usage Examples

### Basic Explain with RAG

```bash
# Scan and explain with knowledge graph augmentation
mcplint scan my-server --explain --provider ollama

# The system will:
# 1. Check Neo4j for similar past findings (semantic search)
# 2. Retrieve related CVE/CWE knowledge
# 3. Augment prompts with graph context
# 4. Store new findings in graph for future queries
```

### Knowledge Graph Queries

Add new CLI commands for knowledge graph exploration:

```bash
# Find cross-server vulnerability patterns
mcplint kg patterns --min-similarity 0.9

# Show knowledge graph stats
mcplint kg stats

# Export vulnerability graph
mcplint kg export --format graphml

# Find all vulnerabilities linked to a CWE
mcplint kg cwe CWE-78
```

## Benefits

1. **Smarter Caching**: Semantic similarity search finds similar findings even with different wording
2. **Richer Context**: CVE/CWE knowledge automatically augments explanations
3. **Pattern Detection**: Identify same vulnerabilities across different servers
4. **Learning System**: Knowledge graph grows with each scan
5. **Relationship Traversal**: "What CVEs exploit this weakness?" queries
6. **No Separate Vector DB**: Neo4j handles both graph + vectors

## Cost Analysis

**Voyage AI Embeddings:**
- Model: `voyage-code-2` (optimized for code)
- Cost: $0.00012 per 1K tokens
- Dimensions: 1536
- Typical finding: ~500 tokens
- Cost per finding: ~$0.00006

**Neo4j Aura Free:**
- Storage: 200K nodes, 400K relationships (plenty for vulnerabilities)
- Memory: Enough for vector indexes
- Vector index: Built-in, no extra cost

**Total Additional Cost:**
- ~$0.05 per 1000 findings for embeddings
- Neo4j: $0 (using free tier)

## Next Steps

1. **Week 1**: Implement `neo4j_kb.rs` module
2. **Week 2**: Integrate with ExplainEngine
3. **Week 3**: Add CLI commands for KG exploration
4. **Week 4**: Populate CWE/CVE knowledge base
5. **Month 2**: Add AI-powered detection using KG context
