# M5: AI-Assisted Vulnerability Explanation - Design Document

## Overview

**Milestone**: M5 - AI-Assisted Vulnerability Explanation
**Goal**: Enhance security findings with AI-generated explanations, remediation guidance, and educational context
**Dependencies**: M2 (Scanner), M4 (Cache)

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          MCPLint CLI                                     │
├─────────────────────────────────────────────────────────────────────────┤
│  mcplint scan --explain [--provider anthropic|openai|local]             │
│  mcplint explain <finding-id>                                            │
│  mcplint explain --interactive                                           │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      AI Explanation Engine                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐ │
│  │  ExplainConfig  │  │ ExplainEngine   │  │   PromptBuilder         │ │
│  │  - provider     │  │ - generate()    │  │   - security_context    │ │
│  │  - model        │  │ - batch()       │  │   - finding_template    │ │
│  │  - cache_ttl    │  │ - interactive() │  │   - remediation_prompt  │ │
│  └─────────────────┘  └────────┬────────┘  └─────────────────────────┘ │
└────────────────────────────────┼────────────────────────────────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
          ▼                      ▼                      ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI Provider   │    │   AI Provider   │    │   AI Provider   │
│   (Anthropic)   │    │    (OpenAI)     │    │    (Ollama)     │
│                 │    │                 │    │                 │
│  Claude-3.5     │    │  GPT-4-turbo    │    │  Llama-3/Phi-3  │
│  Claude-3-opus  │    │  GPT-4o         │    │  Local models   │
└────────┬────────┘    └────────┬────────┘    └────────┬────────┘
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     Cache Layer (M4 Integration)                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  CacheCategory::AiResponse                                        │  │
│  │  Key: hash(finding_id + provider + model + prompt_version)        │  │
│  │  TTL: 7 days (configurable)                                       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Module Structure

```
src/
├── ai/
│   ├── mod.rs              # Module exports
│   ├── config.rs           # AI provider configuration
│   ├── engine.rs           # Main explanation engine
│   ├── prompt.rs           # Prompt templates and builder
│   ├── provider/
│   │   ├── mod.rs          # Provider trait and registry
│   │   ├── anthropic.rs    # Anthropic Claude integration
│   │   ├── openai.rs       # OpenAI GPT integration
│   │   └── ollama.rs       # Local Ollama integration
│   ├── response.rs         # AI response structures
│   └── rate_limit.rs       # Rate limiting and retry logic
├── cli/commands/
│   └── explain.rs          # CLI explain command
└── lib.rs                  # Export ai module
```

## Data Structures

### AI Configuration

```rust
/// AI provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Active provider (anthropic, openai, ollama)
    pub provider: AiProvider,
    /// Model identifier (e.g., "claude-3-5-sonnet-20241022")
    pub model: String,
    /// API key (loaded from env or config)
    pub api_key: Option<String>,
    /// Ollama base URL (for local provider)
    pub ollama_url: Option<String>,
    /// Max tokens for response
    pub max_tokens: u32,
    /// Temperature for generation
    pub temperature: f32,
    /// Cache TTL in seconds (default: 7 days)
    pub cache_ttl_secs: u64,
    /// Enable streaming responses
    pub stream: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiProvider {
    Anthropic,
    OpenAI,
    Ollama,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: AiProvider::Anthropic,
            model: "claude-3-5-sonnet-20241022".to_string(),
            api_key: None,
            ollama_url: Some("http://localhost:11434".to_string()),
            max_tokens: 2048,
            temperature: 0.3,
            cache_ttl_secs: 7 * 24 * 60 * 60, // 7 days
            stream: false,
        }
    }
}
```

### AI Response Structure

```rust
/// AI-generated explanation for a security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationResponse {
    /// Finding ID this explanation is for
    pub finding_id: String,
    /// Human-readable vulnerability explanation
    pub explanation: VulnerabilityExplanation,
    /// Remediation guidance
    pub remediation: RemediationGuide,
    /// Educational context
    pub education: EducationalContext,
    /// Provider and model used
    pub metadata: ExplanationMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityExplanation {
    /// Plain-language summary (1-2 sentences)
    pub summary: String,
    /// Technical deep-dive (markdown)
    pub technical_details: String,
    /// Attack scenario description
    pub attack_scenario: String,
    /// Real-world impact assessment
    pub impact: String,
    /// Likelihood rating (low/medium/high)
    pub likelihood: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationGuide {
    /// Immediate mitigation steps
    pub immediate_actions: Vec<String>,
    /// Long-term fix recommendation
    pub permanent_fix: String,
    /// Code example (if applicable)
    pub code_example: Option<CodeExample>,
    /// Verification steps
    pub verification: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeExample {
    /// Programming language
    pub language: String,
    /// "before" code (vulnerable)
    pub before: String,
    /// "after" code (fixed)
    pub after: String,
    /// Explanation of changes
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EducationalContext {
    /// Related CWEs with descriptions
    pub related_weaknesses: Vec<WeaknessInfo>,
    /// Similar vulnerability patterns
    pub similar_patterns: Vec<String>,
    /// Security best practices
    pub best_practices: Vec<String>,
    /// Further reading links
    pub resources: Vec<ResourceLink>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeaknessInfo {
    pub cwe_id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLink {
    pub title: String,
    pub url: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationMetadata {
    pub provider: String,
    pub model: String,
    pub generated_at: String,
    pub prompt_version: String,
    pub tokens_used: u32,
    pub cached: bool,
}
```

## Provider Trait

```rust
/// Trait for AI providers
#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Provider name
    fn name(&self) -> &'static str;

    /// Generate explanation for a finding
    async fn explain_finding(
        &self,
        finding: &Finding,
        context: &ExplanationContext,
    ) -> Result<ExplanationResponse>;

    /// Generate explanations for multiple findings (batch)
    async fn explain_batch(
        &self,
        findings: &[Finding],
        context: &ExplanationContext,
    ) -> Result<Vec<ExplanationResponse>>;

    /// Interactive follow-up question
    async fn ask_followup(
        &self,
        explanation: &ExplanationResponse,
        question: &str,
    ) -> Result<String>;

    /// Check if provider is available
    async fn health_check(&self) -> Result<bool>;
}

/// Context for explanation generation
#[derive(Debug, Clone)]
pub struct ExplanationContext {
    /// Server name/type being analyzed
    pub server_name: String,
    /// Technology stack (if known)
    pub tech_stack: Vec<String>,
    /// Target audience expertise level
    pub audience: AudienceLevel,
    /// Preferred remediation language
    pub code_language: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceLevel {
    Beginner,
    Intermediate,
    Expert,
}
```

## Prompt Templates

### Security Finding Prompt

```rust
const FINDING_PROMPT: &str = r#"
You are a security expert analyzing MCP (Model Context Protocol) server vulnerabilities.
Analyze the following security finding and provide a comprehensive explanation.

## Finding Details
- Rule ID: {rule_id}
- Severity: {severity}
- Title: {title}
- Description: {description}
- Location: {location}
- Evidence: {evidence}
- CWE References: {cwe_refs}

## Server Context
- Server Name: {server_name}
- Technology Stack: {tech_stack}

## Instructions
Provide your analysis in the following JSON structure:
{
  "explanation": {
    "summary": "One or two sentence plain-language summary",
    "technical_details": "Markdown-formatted technical deep-dive",
    "attack_scenario": "Realistic attack scenario description",
    "impact": "Business and technical impact assessment",
    "likelihood": "low|medium|high"
  },
  "remediation": {
    "immediate_actions": ["Step 1", "Step 2"],
    "permanent_fix": "Description of proper fix",
    "code_example": {
      "language": "rust",
      "before": "// Vulnerable code",
      "after": "// Fixed code",
      "explanation": "What changed and why"
    },
    "verification": ["How to verify the fix"]
  },
  "education": {
    "related_weaknesses": [
      {"cwe_id": "CWE-XXX", "name": "Name", "description": "Description"}
    ],
    "similar_patterns": ["Pattern 1", "Pattern 2"],
    "best_practices": ["Practice 1", "Practice 2"],
    "resources": [
      {"title": "Title", "url": "URL", "category": "documentation|article|tool"}
    ]
  }
}

Target audience expertise level: {audience_level}
Preferred code language for examples: {code_language}
"#;
```

## CLI Integration

### New Commands

```bash
# Scan with AI explanations
mcplint scan ./server --explain
mcplint scan ./server --explain --provider openai --model gpt-4o

# Explain specific finding
mcplint explain MCP-INJ-001 --finding-id abc123

# Interactive mode
mcplint explain --interactive ./scan-results.json

# Configure AI provider
mcplint config set ai.provider anthropic
mcplint config set ai.model claude-3-5-sonnet-20241022
mcplint config set ai.api_key $ANTHROPIC_API_KEY
```

### CLI Structure

```rust
/// Explain command arguments
#[derive(Parser)]
pub struct ExplainArgs {
    /// Path to scan results JSON, or scan a server directly
    #[arg(required = true)]
    pub target: String,

    /// AI provider to use
    #[arg(long, value_enum, default_value = "anthropic")]
    pub provider: CliAiProvider,

    /// Model to use
    #[arg(long)]
    pub model: Option<String>,

    /// Specific finding ID to explain
    #[arg(long)]
    pub finding_id: Option<String>,

    /// Interactive follow-up mode
    #[arg(long, short)]
    pub interactive: bool,

    /// Target audience expertise
    #[arg(long, value_enum, default_value = "intermediate")]
    pub audience: CliAudienceLevel,

    /// Preferred code language for examples
    #[arg(long)]
    pub code_lang: Option<String>,

    /// Output format
    #[arg(long, short, value_enum, default_value = "text")]
    pub format: OutputFormat,

    /// Skip cache (force regeneration)
    #[arg(long)]
    pub no_cache: bool,
}

#[derive(ValueEnum, Clone)]
pub enum CliAiProvider {
    Anthropic,
    OpenAI,
    Ollama,
}

#[derive(ValueEnum, Clone)]
pub enum CliAudienceLevel {
    Beginner,
    Intermediate,
    Expert,
}
```

## Cache Integration

### AI Response Caching

```rust
impl CacheManager {
    /// Get cached AI explanation
    pub async fn get_explanation(&self, key: &ExplanationCacheKey) -> Result<Option<ExplanationResponse>> {
        let cache_key = CacheKey::ai_response(&key.to_hash());
        self.get(&cache_key).await
    }

    /// Cache AI explanation
    pub async fn set_explanation(
        &self,
        key: &ExplanationCacheKey,
        response: &ExplanationResponse,
        ttl: Duration,
    ) -> Result<()> {
        let cache_key = CacheKey::ai_response(&key.to_hash());
        self.set_with_ttl(&cache_key, response, ttl).await
    }
}

/// Cache key components for AI explanations
#[derive(Debug, Clone)]
pub struct ExplanationCacheKey {
    pub finding_id: String,
    pub rule_id: String,
    pub provider: String,
    pub model: String,
    pub prompt_version: String,
    pub audience: String,
}

impl ExplanationCacheKey {
    pub fn to_hash(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.finding_id.hash(&mut hasher);
        self.rule_id.hash(&mut hasher);
        self.provider.hash(&mut hasher);
        self.model.hash(&mut hasher);
        self.prompt_version.hash(&mut hasher);
        self.audience.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}
```

## Rate Limiting

```rust
/// Rate limiter for API calls
pub struct RateLimiter {
    /// Requests per minute limit
    rpm_limit: u32,
    /// Tokens per minute limit
    tpm_limit: u32,
    /// Current window start
    window_start: Instant,
    /// Requests in current window
    requests: u32,
    /// Tokens in current window
    tokens: u32,
}

impl RateLimiter {
    pub fn new(rpm: u32, tpm: u32) -> Self {
        Self {
            rpm_limit: rpm,
            tpm_limit: tpm,
            window_start: Instant::now(),
            requests: 0,
            tokens: 0,
        }
    }

    /// Wait if necessary and record request
    pub async fn acquire(&mut self, estimated_tokens: u32) -> Result<()> {
        self.reset_if_needed();

        if self.requests >= self.rpm_limit || self.tokens + estimated_tokens > self.tpm_limit {
            let wait_time = 60 - self.window_start.elapsed().as_secs();
            tokio::time::sleep(Duration::from_secs(wait_time)).await;
            self.reset();
        }

        self.requests += 1;
        self.tokens += estimated_tokens;
        Ok(())
    }

    fn reset_if_needed(&mut self) {
        if self.window_start.elapsed() > Duration::from_secs(60) {
            self.reset();
        }
    }

    fn reset(&mut self) {
        self.window_start = Instant::now();
        self.requests = 0;
        self.tokens = 0;
    }
}
```

## Implementation Phases

### Phase 1: Core Infrastructure (3-4 hours)
1. Create `src/ai/mod.rs` with module structure
2. Implement `AiConfig` and configuration loading
3. Implement `AiProvider` trait
4. Add rate limiting infrastructure
5. Unit tests for configuration

### Phase 2: Provider Implementations (4-5 hours)
1. Implement Anthropic provider (Claude API)
2. Implement OpenAI provider (GPT-4 API)
3. Implement Ollama provider (local models)
4. Provider health checks and error handling
5. Integration tests with mock responses

### Phase 3: Prompt Engineering (2-3 hours)
1. Design and test prompt templates
2. Implement `PromptBuilder` with context injection
3. Response parsing and validation
4. Handle malformed AI responses gracefully
5. Prompt versioning for cache invalidation

### Phase 4: Cache Integration (2 hours)
1. Extend cache key for AI responses
2. Implement cache lookup/storage for explanations
3. TTL management and cache invalidation
4. Cache statistics for AI responses

### Phase 5: CLI Integration (3-4 hours)
1. Implement `explain` subcommand
2. Add `--explain` flag to scan command
3. Interactive mode with follow-up questions
4. Output formatting (text, JSON, markdown)
5. Environment variable configuration

### Phase 6: Enhanced Output (2-3 hours)
1. Rich text formatting for terminal
2. Markdown export option
3. Integration with existing SARIF output
4. HTML report generation (optional)

### Phase 7: Testing & Documentation (2-3 hours)
1. Integration tests with real providers
2. Mock provider for unit testing
3. Documentation and examples
4. Error message improvements

## Dependencies

### New Crates

```toml
[dependencies]
# HTTP client for API calls
reqwest = { version = "0.12", features = ["json", "stream"] }

# Async streaming support
futures = "0.3"
tokio-stream = "0.1"

# JSON parsing (already present)
serde_json = "1.0"

# Rate limiting
governor = "0.6"

# Markdown rendering for terminal (optional)
termimad = "0.30"
```

### Environment Variables

```bash
# Anthropic
ANTHROPIC_API_KEY=sk-ant-...

# OpenAI
OPENAI_API_KEY=sk-...

# Ollama (optional, defaults to localhost)
OLLAMA_BASE_URL=http://localhost:11434
```

## Security Considerations

1. **API Key Storage**: Keys loaded from environment variables only, never stored in config files
2. **Prompt Injection**: AI responses are parsed as JSON, not executed
3. **Rate Limiting**: Prevent excessive API costs with built-in rate limiting
4. **Cache Security**: Cached responses don't contain sensitive finding data
5. **Local Option**: Ollama provides air-gapped option for sensitive environments

## Success Metrics

1. **Response Quality**: AI explanations rated useful by security practitioners
2. **Cache Hit Rate**: >80% for repeated scans of same servers
3. **Response Time**: <5s for cached, <30s for new explanations
4. **Provider Coverage**: All three providers functional with fallback support
5. **Test Coverage**: >80% for new ai module

## Future Enhancements (Post-M5)

1. **Custom Prompts**: User-defined prompt templates
2. **Fine-tuning**: Custom model fine-tuned on MCP security data
3. **Multi-language**: Explanations in different languages
4. **Team Features**: Shared explanation cache across team
5. **Feedback Loop**: User ratings to improve prompts
6. **RAG Integration**: Vector search over security knowledge base
