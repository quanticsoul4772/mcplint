//! Neo4j Security Knowledge Graph
//!
//! Combines vector search with graph traversal for:
//! - Similar vulnerability finding
//! - CVE/CWE knowledge retrieval
//! - Cross-server pattern detection
//! - Remediation pattern matching
//!
//! Requires the `neo4j` feature to be enabled.

use anyhow::{Context, Result};
use async_trait::async_trait;
use neo4rs::{Graph, Query};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::scanner::{Finding, ReferenceKind};

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
            uri: std::env::var("NEO4J_URI").context("NEO4J_URI not set")?,
            username: std::env::var("NEO4J_USERNAME").unwrap_or_else(|_| "neo4j".to_string()),
            password: std::env::var("NEO4J_PASSWORD").context("NEO4J_PASSWORD not set")?,
            database: std::env::var("NEO4J_DATABASE").unwrap_or_else(|_| "neo4j".to_string()),
        })
    }

    /// Create config from explicit values
    pub fn new(uri: String, username: String, password: String, database: String) -> Self {
        Self {
            uri,
            username,
            password,
            database,
        }
    }
}

/// Vector embedding provider trait
#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    /// Generate embedding vector for text
    async fn embed(&self, text: &str) -> Result<Vec<f32>>;

    /// Get the dimensionality of embeddings
    fn dimensions(&self) -> usize;
}

/// Voyage AI embedding provider (recommended for code)
pub struct VoyageEmbedder {
    api_key: String,
    model: String,
    dimensions: usize,
    client: reqwest::Client,
}

impl VoyageEmbedder {
    const API_URL: &'static str = "https://api.voyageai.com/v1/embeddings";

    /// Create a new Voyage embedder from environment
    pub fn new() -> Result<Self> {
        let api_key = std::env::var("VOYAGE_API_KEY").context("VOYAGE_API_KEY not set")?;
        Self::with_api_key(api_key)
    }

    /// Create with explicit API key
    pub fn with_api_key(api_key: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            api_key,
            model: "voyage-code-2".to_string(),
            dimensions: 1536,
            client,
        })
    }

    /// Use a different model (e.g., "voyage-2" for general text)
    pub fn with_model(mut self, model: &str) -> Self {
        self.model = model.to_string();
        // Adjust dimensions based on model
        self.dimensions = match model {
            "voyage-code-2" => 1536,
            "voyage-2" => 1024,
            "voyage-lite-02-instruct" => 1024,
            _ => 1536,
        };
        self
    }
}

#[async_trait]
impl EmbeddingProvider for VoyageEmbedder {
    async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        #[derive(Serialize)]
        struct Request<'a> {
            input: Vec<&'a str>,
            model: &'a str,
        }

        #[derive(Deserialize)]
        struct Response {
            data: Vec<EmbeddingData>,
        }

        #[derive(Deserialize)]
        struct EmbeddingData {
            embedding: Vec<f32>,
        }

        let response: Response = self
            .client
            .post(Self::API_URL)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&Request {
                input: vec![text],
                model: &self.model,
            })
            .send()
            .await
            .context("Failed to send embedding request")?
            .json()
            .await
            .context("Failed to parse embedding response")?;

        response
            .data
            .into_iter()
            .next()
            .map(|d| d.embedding)
            .context("No embedding in response")
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }
}

/// Similar finding result from vector search
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

/// Security knowledge graph backed by Neo4j
pub struct SecurityKnowledgeGraph {
    graph: Arc<Graph>,
    embedder: Arc<dyn EmbeddingProvider>,
}

impl SecurityKnowledgeGraph {
    /// Create a new knowledge graph connection
    pub async fn new(config: Neo4jConfig, embedder: Arc<dyn EmbeddingProvider>) -> Result<Self> {
        // neo4rs 0.7 uses Graph::new(uri, user, password) directly
        let graph = Arc::new(
            Graph::new(&config.uri, &config.username, &config.password)
                .await
                .context("Failed to connect to Neo4j")?,
        );

        let kg = Self { graph, embedder };

        // Initialize schema and indexes
        kg.initialize_schema().await?;

        Ok(kg)
    }

    /// Initialize Neo4j schema and vector indexes
    async fn initialize_schema(&self) -> Result<()> {
        // Create constraints (ignore errors if already exist)
        let constraints = [
            "CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (c:CWE) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE",
        ];

        for constraint in constraints {
            let query = Query::new(constraint.to_string());
            let _ = self.graph.run(query).await; // Ignore if already exists
        }

        // Create vector index for vulnerabilities
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
            finding
                .evidence
                .iter()
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
                .to_string(),
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
        if let Some(cwe_ref) = finding
            .references
            .iter()
            .find(|r| r.kind == ReferenceKind::Cwe)
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
                .to_string(),
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
                .to_string(),
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
                .to_string(),
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
    ) -> Result<Vec<CrossServerPattern>> {
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
                .to_string(),
        )
        .param("min_similarity", min_similarity);

        let mut result = self.graph.execute(query).await?;
        let mut patterns = Vec::new();

        while let Some(row) = result.next().await? {
            patterns.push(CrossServerPattern {
                server1: row.get("server1")?,
                server2: row.get("server2")?,
                rule_id: row.get("rule_id")?,
                similarity_score: row.get("score")?,
            });
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
                .to_string(),
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

    /// Populate CWE knowledge base with common security weaknesses
    pub async fn populate_cwe_knowledge(&self) -> Result<()> {
        let cwes = [
            (
                "CWE-22",
                "Path Traversal",
                "Improper limitation of a pathname to a restricted directory",
                "Canonicalize paths, validate against allowed directory, use allowlists",
            ),
            (
                "CWE-78",
                "OS Command Injection",
                "Improper neutralization of special elements used in OS commands",
                "Use parameterized APIs, validate input, apply allowlists",
            ),
            (
                "CWE-79",
                "Cross-site Scripting",
                "Improper neutralization of input during web page generation",
                "Escape output, use Content Security Policy, validate input",
            ),
            (
                "CWE-89",
                "SQL Injection",
                "Improper neutralization of special elements in SQL commands",
                "Use parameterized queries, ORMs, input validation",
            ),
            (
                "CWE-94",
                "Code Injection",
                "Improper control of generation of code",
                "Avoid dynamic code execution, use safe APIs, validate input",
            ),
            (
                "CWE-287",
                "Improper Authentication",
                "Failure to properly verify identity of actor",
                "Implement proper authentication, use standard protocols",
            ),
            (
                "CWE-352",
                "Cross-Site Request Forgery",
                "Forcing user to execute unwanted actions",
                "Use CSRF tokens, SameSite cookies, verify origin",
            ),
            (
                "CWE-502",
                "Deserialization of Untrusted Data",
                "Deserializing untrusted data without validation",
                "Avoid deserializing untrusted data, use safe formats, validate schemas",
            ),
            (
                "CWE-918",
                "Server-Side Request Forgery",
                "Making server perform requests on behalf of attacker",
                "Validate URLs, use allowlists, disable redirects",
            ),
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
                    .to_string(),
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

    /// Get knowledge graph statistics
    pub async fn get_stats(&self) -> Result<KnowledgeGraphStats> {
        let query = Query::new(
            "MATCH (v:Vulnerability)
             WITH count(v) as vuln_count
             MATCH (c:CWE)
             WITH vuln_count, count(c) as cwe_count
             MATCH (cve:CVE)
             RETURN vuln_count, cwe_count, count(cve) as cve_count"
                .to_string(),
        );

        let mut result = self.graph.execute(query).await?;

        if let Some(row) = result.next().await? {
            Ok(KnowledgeGraphStats {
                vulnerability_count: row.get::<i64>("vuln_count")? as usize,
                cwe_count: row.get::<i64>("cwe_count")? as usize,
                cve_count: row.get::<i64>("cve_count")? as usize,
            })
        } else {
            Ok(KnowledgeGraphStats::default())
        }
    }

    /// Check if the knowledge graph is connected and healthy
    pub async fn health_check(&self) -> Result<bool> {
        let query = Query::new("RETURN 1 as ok".to_string());
        let mut result = self.graph.execute(query).await?;

        if let Some(row) = result.next().await? {
            let ok: i64 = row.get("ok")?;
            Ok(ok == 1)
        } else {
            Ok(false)
        }
    }
}

/// Cross-server vulnerability pattern
#[derive(Debug, Clone)]
pub struct CrossServerPattern {
    pub server1: String,
    pub server2: String,
    pub rule_id: String,
    pub similarity_score: f64,
}

/// Knowledge graph statistics
#[derive(Debug, Clone, Default)]
pub struct KnowledgeGraphStats {
    pub vulnerability_count: usize,
    pub cwe_count: usize,
    pub cve_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Severity;

    fn sample_finding() -> Finding {
        Finding::new(
            "MCP-INJ-001",
            Severity::High,
            "Command Injection",
            "Tool accepts unsanitized input in command parameter",
        )
        .with_cwe("78")
    }

    #[test]
    fn neo4j_config_from_values() {
        let config = Neo4jConfig::new(
            "neo4j://localhost".to_string(),
            "neo4j".to_string(),
            "password".to_string(),
            "neo4j".to_string(),
        );

        assert_eq!(config.uri, "neo4j://localhost");
        assert_eq!(config.username, "neo4j");
    }

    #[test]
    fn similar_finding_debug() {
        let similar = SimilarFinding {
            finding_id: "test-id".to_string(),
            rule_id: "MCP-001".to_string(),
            similarity_score: 0.95,
            title: "Test Finding".to_string(),
            server: "test-server".to_string(),
        };

        let debug_str = format!("{:?}", similar);
        assert!(debug_str.contains("test-id"));
        assert!(debug_str.contains("0.95"));
    }

    #[test]
    fn cwe_knowledge_serialization() {
        let cwe = CweKnowledge {
            id: "CWE-78".to_string(),
            name: "OS Command Injection".to_string(),
            description: "Test description".to_string(),
            mitigation: "Test mitigation".to_string(),
        };

        let json = serde_json::to_string(&cwe).unwrap();
        assert!(json.contains("CWE-78"));

        let parsed: CweKnowledge = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "CWE-78");
    }

    #[test]
    fn cve_record_serialization() {
        let cve = CveRecord {
            id: "CVE-2024-1234".to_string(),
            description: "Test vulnerability".to_string(),
            cvss_score: 9.8,
            published_date: "2024-01-01".to_string(),
        };

        let json = serde_json::to_string(&cve).unwrap();
        assert!(json.contains("CVE-2024-1234"));
        assert!(json.contains("9.8"));
    }

    #[test]
    fn cross_server_pattern_clone() {
        let pattern = CrossServerPattern {
            server1: "server-a".to_string(),
            server2: "server-b".to_string(),
            rule_id: "MCP-001".to_string(),
            similarity_score: 0.92,
        };

        let cloned = pattern.clone();
        assert_eq!(cloned.server1, "server-a");
        assert_eq!(cloned.similarity_score, 0.92);
    }

    #[test]
    fn knowledge_graph_stats_default() {
        let stats = KnowledgeGraphStats::default();
        assert_eq!(stats.vulnerability_count, 0);
        assert_eq!(stats.cwe_count, 0);
        assert_eq!(stats.cve_count, 0);
    }

    // Integration tests require Neo4j connection
    #[tokio::test]
    #[ignore] // Run with: cargo test --features neo4j -- --ignored
    async fn test_neo4j_connection() {
        let config = Neo4jConfig::from_env().expect("Neo4j config from env");

        // Create a mock embedder for testing
        struct MockEmbedder;

        #[async_trait]
        impl EmbeddingProvider for MockEmbedder {
            async fn embed(&self, _text: &str) -> Result<Vec<f32>> {
                Ok(vec![0.0; 1536])
            }
            fn dimensions(&self) -> usize {
                1536
            }
        }

        let embedder = Arc::new(MockEmbedder);
        let kg = SecurityKnowledgeGraph::new(config, embedder).await;

        assert!(kg.is_ok(), "Should connect to Neo4j");

        let kg = kg.unwrap();
        let healthy = kg.health_check().await.unwrap();
        assert!(healthy, "Knowledge graph should be healthy");
    }

    #[tokio::test]
    #[ignore] // Run with: cargo test --features neo4j -- --ignored
    async fn test_store_and_find_similar() {
        let config = Neo4jConfig::from_env().expect("Neo4j config from env");
        let embedder = Arc::new(VoyageEmbedder::new().expect("Voyage embedder"));
        let kg = SecurityKnowledgeGraph::new(config, embedder)
            .await
            .expect("Knowledge graph");

        let finding = sample_finding();
        kg.store_finding(&finding, "test-server")
            .await
            .expect("Store finding");

        let similar = kg
            .find_similar_vulnerabilities(&finding, 5, 0.8)
            .await
            .expect("Find similar");

        // Should find at least one similar (itself or previously stored)
        println!("Found {} similar findings", similar.len());
    }
}
