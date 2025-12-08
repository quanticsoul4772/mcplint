//! AI Configuration - Provider and model settings
//!
//! Defines configuration for AI providers including API keys,
//! model selection, and rate limiting parameters.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// AI provider selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AiProvider {
    /// Anthropic Claude models
    #[default]
    Anthropic,
    /// OpenAI GPT models
    OpenAI,
    /// Local Ollama models
    Ollama,
}

impl AiProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            AiProvider::Anthropic => "anthropic",
            AiProvider::OpenAI => "openai",
            AiProvider::Ollama => "ollama",
        }
    }

    pub fn default_model(&self) -> &'static str {
        match self {
            AiProvider::Anthropic => "claude-sonnet-4-20250514",
            AiProvider::OpenAI => "gpt-4o",
            AiProvider::Ollama => "llama3.2",
        }
    }

    pub fn env_key_name(&self) -> &'static str {
        match self {
            AiProvider::Anthropic => "ANTHROPIC_API_KEY",
            AiProvider::OpenAI => "OPENAI_API_KEY",
            AiProvider::Ollama => "OLLAMA_BASE_URL",
        }
    }
}

impl std::fmt::Display for AiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for AiProvider {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "anthropic" | "claude" => Ok(AiProvider::Anthropic),
            "openai" | "gpt" => Ok(AiProvider::OpenAI),
            "ollama" | "local" => Ok(AiProvider::Ollama),
            _ => Err(()),
        }
    }
}

/// Target audience expertise level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AudienceLevel {
    /// Security beginners, plain language
    Beginner,
    /// Some security knowledge
    #[default]
    Intermediate,
    /// Security professionals
    Expert,
}

impl AudienceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            AudienceLevel::Beginner => "beginner",
            AudienceLevel::Intermediate => "intermediate",
            AudienceLevel::Expert => "expert",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AudienceLevel::Beginner => "someone new to security concepts",
            AudienceLevel::Intermediate => "a developer with some security knowledge",
            AudienceLevel::Expert => "an experienced security professional",
        }
    }
}

impl std::fmt::Display for AudienceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for AudienceLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "beginner" | "novice" => Ok(AudienceLevel::Beginner),
            "intermediate" | "medium" => Ok(AudienceLevel::Intermediate),
            "expert" | "advanced" => Ok(AudienceLevel::Expert),
            _ => Err(()),
        }
    }
}

/// AI provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Active provider
    pub provider: AiProvider,
    /// Model identifier
    pub model: String,
    /// API key (loaded from environment)
    #[serde(skip_serializing)]
    pub api_key: Option<String>,
    /// Ollama base URL
    pub ollama_url: String,
    /// Maximum tokens for response
    pub max_tokens: u32,
    /// Temperature for generation (0.0 - 1.0)
    pub temperature: f32,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
    /// Enable streaming responses
    pub stream: bool,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Retry attempts on failure
    pub max_retries: u32,
    /// Rate limit: requests per minute
    pub rate_limit_rpm: u32,
    /// Rate limit: tokens per minute
    pub rate_limit_tpm: u32,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            provider: AiProvider::default(),
            model: AiProvider::default().default_model().to_string(),
            api_key: None,
            ollama_url: "http://localhost:11434".to_string(),
            max_tokens: 4096,
            temperature: 0.3,
            cache_ttl_secs: 7 * 24 * 60 * 60, // 7 days
            stream: false,
            timeout_secs: 120,
            max_retries: 3,
            rate_limit_rpm: 50,
            rate_limit_tpm: 100_000,
        }
    }
}

impl AiConfig {
    /// Create config for Anthropic Claude
    pub fn anthropic() -> Self {
        Self {
            provider: AiProvider::Anthropic,
            model: "claude-sonnet-4-20250514".to_string(),
            ..Default::default()
        }
    }

    /// Create config for OpenAI GPT
    pub fn openai() -> Self {
        Self {
            provider: AiProvider::OpenAI,
            model: "gpt-4o".to_string(),
            rate_limit_rpm: 60,
            rate_limit_tpm: 150_000,
            ..Default::default()
        }
    }

    /// Create config for local Ollama
    pub fn ollama() -> Self {
        Self {
            provider: AiProvider::Ollama,
            model: "llama3.2".to_string(),
            rate_limit_rpm: 1000, // Local models don't need rate limiting
            rate_limit_tpm: 1_000_000,
            ..Default::default()
        }
    }

    /// Set the provider
    pub fn with_provider(mut self, provider: AiProvider) -> Self {
        self.provider = provider;
        self.model = provider.default_model().to_string();
        self
    }

    /// Set the model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Set the API key
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Set Ollama URL
    pub fn with_ollama_url(mut self, url: impl Into<String>) -> Self {
        self.ollama_url = url.into();
        self
    }

    /// Set max tokens
    pub fn with_max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = tokens;
        self
    }

    /// Set temperature
    pub fn with_temperature(mut self, temp: f32) -> Self {
        self.temperature = temp.clamp(0.0, 1.0);
        self
    }

    /// Set cache TTL
    pub fn with_cache_ttl(mut self, duration: Duration) -> Self {
        self.cache_ttl_secs = duration.as_secs();
        self
    }

    /// Disable caching
    pub fn without_cache(mut self) -> Self {
        self.cache_ttl_secs = 0;
        self
    }

    /// Enable streaming
    pub fn with_streaming(mut self) -> Self {
        self.stream = true;
        self
    }

    /// Get cache TTL as Duration
    pub fn cache_ttl(&self) -> Duration {
        Duration::from_secs(self.cache_ttl_secs)
    }

    /// Get timeout as Duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Load API key from environment
    pub fn load_api_key_from_env(&mut self) {
        if self.api_key.is_none() {
            self.api_key = std::env::var(self.provider.env_key_name()).ok();
        }
    }

    /// Check if API key is available
    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some() || self.provider == AiProvider::Ollama
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if !self.has_api_key() && self.provider != AiProvider::Ollama {
            return Err(format!(
                "Missing API key. Set {} environment variable",
                self.provider.env_key_name()
            ));
        }

        if self.max_tokens == 0 {
            return Err("max_tokens must be greater than 0".to_string());
        }

        if self.timeout_secs == 0 {
            return Err("timeout_secs must be greater than 0".to_string());
        }

        Ok(())
    }
}

/// Builder for AiConfig
#[derive(Debug, Clone, Default)]
pub struct AiConfigBuilder {
    provider: Option<AiProvider>,
    model: Option<String>,
    api_key: Option<String>,
    base_url: Option<String>,
    timeout: Option<u64>,
    max_tokens: Option<u32>,
    temperature: Option<f32>,
}

impl AiConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn provider(mut self, provider: AiProvider) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn model(mut self, model: &str) -> Self {
        self.model = Some(model.to_string());
        self
    }

    pub fn api_key(mut self, key: &str) -> Self {
        self.api_key = Some(key.to_string());
        self
    }

    pub fn base_url(mut self, url: &str) -> Self {
        self.base_url = Some(url.to_string());
        self
    }

    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout = Some(secs);
        self
    }

    pub fn max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = Some(tokens);
        self
    }

    pub fn temperature(mut self, temp: f32) -> Self {
        self.temperature = Some(temp);
        self
    }

    pub fn build(self) -> AiConfig {
        let provider = self.provider.unwrap_or_default();
        let mut config = match provider {
            AiProvider::Anthropic => AiConfig::anthropic(),
            AiProvider::OpenAI => AiConfig::openai(),
            AiProvider::Ollama => AiConfig::ollama(),
        };

        if let Some(model) = self.model {
            config.model = model;
        }
        if let Some(key) = self.api_key {
            config.api_key = Some(key);
        }
        if let Some(url) = self.base_url {
            config.ollama_url = url;
        }
        if let Some(timeout) = self.timeout {
            config.timeout_secs = timeout;
        }
        if let Some(tokens) = self.max_tokens {
            config.max_tokens = tokens;
        }
        if let Some(temp) = self.temperature {
            config.temperature = temp.clamp(0.0, 1.0);
        }

        config
    }
}

impl AiConfig {
    /// Create a builder for configuration
    pub fn builder() -> AiConfigBuilder {
        AiConfigBuilder::new()
    }
}

/// Context for generating explanations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationContext {
    /// Server name being analyzed
    pub server_name: String,
    /// Technology stack
    pub tech_stack: Vec<String>,
    /// Target audience level
    pub audience: AudienceLevel,
    /// Preferred code language for examples
    pub code_language: Option<String>,
    /// Include educational content
    pub include_education: bool,
    /// Include code examples
    pub include_code_examples: bool,
}

impl Default for ExplanationContext {
    fn default() -> Self {
        Self {
            server_name: "Unknown Server".to_string(),
            tech_stack: Vec::new(),
            audience: AudienceLevel::default(),
            code_language: None,
            include_education: true,
            include_code_examples: true,
        }
    }
}

impl AiConfig {
    /// Load AI configuration from a TOML config file
    ///
    /// Looks for config in:
    /// 1. Specified path (if provided)
    /// 2. .mcplint.toml in current directory
    /// 3. ~/.config/mcplint/config.toml
    pub fn load_from_file(path: Option<&str>) -> Result<Self, ConfigLoadError> {
        let config_paths = if let Some(p) = path {
            vec![std::path::PathBuf::from(p)]
        } else {
            let mut paths = vec![
                std::path::PathBuf::from(".mcplint.toml"),
                std::path::PathBuf::from("mcplint.toml"),
            ];

            // Add user config directory
            if let Some(config_dir) = dirs::config_dir() {
                paths.push(config_dir.join("mcplint").join("config.toml"));
            }

            paths
        };

        // Try each path
        for config_path in &config_paths {
            if config_path.exists() {
                return Self::load_from_path(config_path);
            }
        }

        Err(ConfigLoadError::NotFound)
    }

    /// Load config from a specific path
    fn load_from_path(path: &std::path::Path) -> Result<Self, ConfigLoadError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigLoadError::ReadError(e.to_string()))?;

        Self::parse_toml(&content)
    }

    /// Parse AI config from TOML content
    fn parse_toml(content: &str) -> Result<Self, ConfigLoadError> {
        let table: toml::Table = content
            .parse()
            .map_err(|e: toml::de::Error| ConfigLoadError::ParseError(e.to_string()))?;

        // Get [ai] section
        let ai_section = table
            .get("ai")
            .and_then(|v| v.as_table())
            .ok_or(ConfigLoadError::MissingSection("[ai]".to_string()))?;

        let mut config = AiConfig::default();

        // Parse provider
        if let Some(provider_str) = ai_section.get("provider").and_then(|v| v.as_str()) {
            if let Ok(provider) = provider_str.parse::<AiProvider>() {
                config.provider = provider;
                // Update default model for provider
                config.model = provider.default_model().to_string();
            }
        }

        // Parse model (override default)
        if let Some(model) = ai_section.get("model").and_then(|v| v.as_str()) {
            config.model = model.to_string();
        }

        // Parse Ollama URL
        if let Some(url) = ai_section.get("ollama_url").and_then(|v| v.as_str()) {
            config.ollama_url = url.to_string();
        }

        // Parse max_tokens
        if let Some(tokens) = ai_section.get("max_tokens").and_then(|v| v.as_integer()) {
            config.max_tokens = tokens as u32;
        }

        // Parse temperature
        if let Some(temp) = ai_section.get("temperature").and_then(|v| v.as_float()) {
            config.temperature = (temp as f32).clamp(0.0, 1.0);
        }

        // Parse cache TTL
        if let Some(ttl) = ai_section.get("cache_ttl").and_then(|v| v.as_integer()) {
            config.cache_ttl_secs = ttl as u64;
        }

        // Parse rate limits
        if let Some(rpm) = ai_section
            .get("rate_limit_rpm")
            .and_then(|v| v.as_integer())
        {
            config.rate_limit_rpm = rpm as u32;
        }

        if let Some(tpm) = ai_section
            .get("rate_limit_tpm")
            .and_then(|v| v.as_integer())
        {
            config.rate_limit_tpm = tpm as u32;
        }

        // Load API key from environment (never from config file for security)
        config.load_api_key_from_env();

        Ok(config)
    }

    /// Try to load from file, falling back to defaults
    pub fn load_or_default(path: Option<&str>) -> Self {
        match Self::load_from_file(path) {
            Ok(config) => {
                tracing::debug!("Loaded AI config from file");
                config
            }
            Err(ConfigLoadError::NotFound) => {
                tracing::debug!("No config file found, using defaults");
                let mut config = Self::default();
                config.load_api_key_from_env();
                config
            }
            Err(e) => {
                tracing::warn!("Failed to load config: {}, using defaults", e);
                let mut config = Self::default();
                config.load_api_key_from_env();
                config
            }
        }
    }
}

/// Error type for config loading
#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    #[error("Config file not found")]
    NotFound,

    #[error("Failed to read config file: {0}")]
    ReadError(String),

    #[error("Failed to parse config file: {0}")]
    ParseError(String),

    #[error("Missing required section: {0}")]
    MissingSection(String),
}

impl ExplanationContext {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            ..Default::default()
        }
    }

    pub fn with_audience(mut self, audience: AudienceLevel) -> Self {
        self.audience = audience;
        self
    }

    pub fn with_tech_stack(mut self, tech: Vec<String>) -> Self {
        self.tech_stack = tech;
        self
    }

    pub fn with_code_language(mut self, lang: impl Into<String>) -> Self {
        self.code_language = Some(lang.into());
        self
    }

    pub fn without_education(mut self) -> Self {
        self.include_education = false;
        self
    }

    pub fn without_code_examples(mut self) -> Self {
        self.include_code_examples = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = AiConfig::default();
        assert_eq!(config.provider, AiProvider::Anthropic);
        assert!(config.max_tokens > 0);
        assert!(config.temperature >= 0.0 && config.temperature <= 1.0);
    }

    #[test]
    fn provider_parsing() {
        assert_eq!("anthropic".parse::<AiProvider>(), Ok(AiProvider::Anthropic));
        assert_eq!("OPENAI".parse::<AiProvider>(), Ok(AiProvider::OpenAI));
        assert_eq!("local".parse::<AiProvider>(), Ok(AiProvider::Ollama));
        assert!("invalid".parse::<AiProvider>().is_err());
    }

    #[test]
    fn audience_parsing() {
        assert_eq!(
            "beginner".parse::<AudienceLevel>(),
            Ok(AudienceLevel::Beginner)
        );
        assert_eq!("EXPERT".parse::<AudienceLevel>(), Ok(AudienceLevel::Expert));
        assert!("invalid".parse::<AudienceLevel>().is_err());
    }

    #[test]
    fn config_builder() {
        let config = AiConfig::default()
            .with_provider(AiProvider::OpenAI)
            .with_model("gpt-4-turbo")
            .with_max_tokens(2048)
            .with_temperature(0.5);

        assert_eq!(config.provider, AiProvider::OpenAI);
        assert_eq!(config.model, "gpt-4-turbo");
        assert_eq!(config.max_tokens, 2048);
        assert_eq!(config.temperature, 0.5);
    }

    #[test]
    fn config_validation() {
        // Ollama doesn't need API key
        let ollama_config = AiConfig::ollama();
        assert!(ollama_config.validate().is_ok());

        // Anthropic without key should fail
        let anthropic_config = AiConfig::anthropic();
        assert!(anthropic_config.validate().is_err());

        // Anthropic with key should pass
        let with_key = AiConfig::anthropic().with_api_key("test-key");
        assert!(with_key.validate().is_ok());
    }

    #[test]
    fn parse_toml_basic() {
        let toml_content = r#"
[ai]
provider = "ollama"
model = "llama3.2"
ollama_url = "http://localhost:11434"
max_tokens = 2048
temperature = 0.5
cache_ttl = 3600
rate_limit_rpm = 100
rate_limit_tpm = 50000
"#;
        let config = AiConfig::parse_toml(toml_content).unwrap();
        assert_eq!(config.provider, AiProvider::Ollama);
        assert_eq!(config.model, "llama3.2");
        assert_eq!(config.ollama_url, "http://localhost:11434");
        assert_eq!(config.max_tokens, 2048);
        assert_eq!(config.temperature, 0.5);
        assert_eq!(config.cache_ttl_secs, 3600);
        assert_eq!(config.rate_limit_rpm, 100);
        assert_eq!(config.rate_limit_tpm, 50000);
    }

    #[test]
    fn parse_toml_anthropic() {
        let toml_content = r#"
[ai]
provider = "anthropic"
model = "claude-sonnet-4-20250514"
max_tokens = 4096
"#;
        let config = AiConfig::parse_toml(toml_content).unwrap();
        assert_eq!(config.provider, AiProvider::Anthropic);
        assert_eq!(config.model, "claude-sonnet-4-20250514");
        assert_eq!(config.max_tokens, 4096);
    }

    #[test]
    fn parse_toml_openai() {
        let toml_content = r#"
[ai]
provider = "openai"
model = "gpt-4o"
temperature = 0.7
"#;
        let config = AiConfig::parse_toml(toml_content).unwrap();
        assert_eq!(config.provider, AiProvider::OpenAI);
        assert_eq!(config.model, "gpt-4o");
        assert_eq!(config.temperature, 0.7);
    }

    #[test]
    fn parse_toml_missing_section() {
        let toml_content = r#"
[general]
format = "text"
"#;
        let result = AiConfig::parse_toml(toml_content);
        assert!(result.is_err());
        match result {
            Err(ConfigLoadError::MissingSection(section)) => {
                assert_eq!(section, "[ai]");
            }
            _ => panic!("Expected MissingSection error"),
        }
    }

    #[test]
    fn parse_toml_partial_config() {
        // Only provider specified, should use defaults for everything else
        let toml_content = r#"
[ai]
provider = "ollama"
"#;
        let config = AiConfig::parse_toml(toml_content).unwrap();
        assert_eq!(config.provider, AiProvider::Ollama);
        // Model should be updated to Ollama's default
        assert_eq!(config.model, "llama3.2");
        // Other fields should be defaults
        assert_eq!(config.max_tokens, 4096);
        assert!(config.temperature > 0.0);
    }

    #[test]
    fn parse_toml_invalid_provider() {
        // Invalid provider should keep default
        let toml_content = r#"
[ai]
provider = "invalid_provider"
"#;
        let config = AiConfig::parse_toml(toml_content).unwrap();
        // Default provider is Anthropic
        assert_eq!(config.provider, AiProvider::Anthropic);
    }

    #[test]
    fn parse_toml_temperature_clamp() {
        // Temperature should be clamped to 0.0-1.0
        let toml_content = r#"
[ai]
provider = "ollama"
temperature = 2.5
"#;
        let config = AiConfig::parse_toml(toml_content).unwrap();
        assert_eq!(config.temperature, 1.0);
    }

    #[test]
    fn load_or_default_nonexistent() {
        // When file doesn't exist, should return defaults with env key loaded
        let config = AiConfig::load_or_default(Some("/nonexistent/path/config.toml"));
        assert_eq!(config.provider, AiProvider::Anthropic);
        assert!(config.max_tokens > 0);
    }

    #[test]
    fn config_load_error_display() {
        let err = ConfigLoadError::NotFound;
        assert!(err.to_string().contains("not found"));

        let err = ConfigLoadError::ReadError("permission denied".to_string());
        assert!(err.to_string().contains("permission denied"));

        let err = ConfigLoadError::ParseError("invalid toml".to_string());
        assert!(err.to_string().contains("invalid toml"));

        let err = ConfigLoadError::MissingSection("[ai]".to_string());
        assert!(err.to_string().contains("[ai]"));
    }
}
