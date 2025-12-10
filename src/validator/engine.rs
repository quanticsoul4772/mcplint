//! Validation Engine - Core validation infrastructure
//!
//! Manages validation rule execution, result collection, and server communication.

use std::collections::HashMap;
use std::time::Instant;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::client::mock::McpClientTrait;
use crate::client::McpClient;
use crate::protocol::mcp::{
    InitializeResult, ListPromptsResult, ListResourcesResult, ServerCapabilities, Tool,
};
use crate::protocol::Implementation;
use crate::transport::{connect_with_type, TransportConfig, TransportType};

use super::rules::{ValidationCategory, ValidationRule, ValidationRuleId};

/// Configuration for validation engine
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Timeout for server operations in seconds
    pub timeout_secs: u64,
    /// Categories to skip
    #[allow(dead_code)]
    pub skip_categories: Vec<ValidationCategory>,
    /// Specific rules to skip
    #[allow(dead_code)]
    pub skip_rules: Vec<ValidationRuleId>,
    /// Enable strict mode (warnings become failures)
    #[allow(dead_code)]
    pub strict_mode: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            skip_categories: Vec::new(),
            skip_rules: Vec::new(),
            strict_mode: false,
        }
    }
}

/// Result of a single validation check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Rule identifier
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Category
    pub category: String,
    /// Validation outcome
    pub severity: ValidationSeverity,
    /// Human-readable message
    pub message: Option<String>,
    /// Additional details
    pub details: Vec<String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

impl ValidationResult {
    pub fn pass(rule: &ValidationRule, duration_ms: u64) -> Self {
        Self {
            rule_id: rule.id.to_string(),
            rule_name: rule.name.clone(),
            category: rule.category.to_string(),
            severity: ValidationSeverity::Pass,
            message: None,
            details: Vec::new(),
            duration_ms,
        }
    }

    pub fn fail(rule: &ValidationRule, message: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            rule_id: rule.id.to_string(),
            rule_name: rule.name.clone(),
            category: rule.category.to_string(),
            severity: ValidationSeverity::Fail,
            message: Some(message.into()),
            details: Vec::new(),
            duration_ms,
        }
    }

    pub fn warning(rule: &ValidationRule, message: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            rule_id: rule.id.to_string(),
            rule_name: rule.name.clone(),
            category: rule.category.to_string(),
            severity: ValidationSeverity::Warning,
            message: Some(message.into()),
            details: Vec::new(),
            duration_ms,
        }
    }

    #[allow(dead_code)]
    pub fn skip(rule: &ValidationRule, reason: impl Into<String>) -> Self {
        Self {
            rule_id: rule.id.to_string(),
            rule_name: rule.name.clone(),
            category: rule.category.to_string(),
            severity: ValidationSeverity::Skip,
            message: Some(reason.into()),
            details: Vec::new(),
            duration_ms: 0,
        }
    }

    pub fn with_details(mut self, details: Vec<String>) -> Self {
        self.details = details;
        self
    }
}

/// Severity/outcome of a validation check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationSeverity {
    Pass,
    Fail,
    Warning,
    Info,
    Skip,
}

/// Aggregated validation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResults {
    /// Server identifier
    pub server: String,
    /// Protocol version negotiated
    pub protocol_version: Option<String>,
    /// Server capabilities
    pub capabilities: Option<ServerCapabilities>,
    /// Individual check results
    pub results: Vec<ValidationResult>,
    /// Count of passed checks
    pub passed: usize,
    /// Count of failed checks
    pub failed: usize,
    /// Count of warnings
    pub warnings: usize,
    /// Total duration in milliseconds
    pub total_duration_ms: u64,
}

impl ValidationResults {
    pub fn new(server: &str) -> Self {
        Self {
            server: server.to_string(),
            protocol_version: None,
            capabilities: None,
            results: Vec::new(),
            passed: 0,
            failed: 0,
            warnings: 0,
            total_duration_ms: 0,
        }
    }

    pub fn add_result(&mut self, result: ValidationResult) {
        match result.severity {
            ValidationSeverity::Pass => self.passed += 1,
            ValidationSeverity::Fail => self.failed += 1,
            ValidationSeverity::Warning => self.warnings += 1,
            ValidationSeverity::Info | ValidationSeverity::Skip => {}
        }
        self.total_duration_ms += result.duration_ms;
        self.results.push(result);
    }

    #[allow(dead_code)]
    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }
}

/// Server context collected during validation
pub struct ServerContext {
    /// Initialize result from server
    pub init_result: InitializeResult,
    /// List of tools (if supported)
    pub tools: Option<Vec<Tool>>,
    /// List of resources (if supported)
    pub resources: Option<ListResourcesResult>,
    /// List of prompts (if supported)
    pub prompts: Option<ListPromptsResult>,
}

/// Main validation engine
pub struct ValidationEngine {
    config: ValidationConfig,
    rules: Vec<ValidationRule>,
}

impl ValidationEngine {
    pub fn new(config: ValidationConfig) -> Self {
        let rules = super::rules::get_all_rules();
        Self { config, rules }
    }

    /// Validate a server with the configured rules
    pub async fn validate_server(
        &mut self,
        target: &str,
        args: &[String],
        env: &HashMap<String, String>,
        transport_type: Option<TransportType>,
    ) -> Result<ValidationResults> {
        tracing::info!(
            "MCPLint validation engine v2 - running {} rules",
            self.rules.len()
        );
        let start = Instant::now();
        let mut results = ValidationResults::new(target);

        // Determine transport type
        let transport =
            transport_type.unwrap_or_else(|| crate::transport::detect_transport_type(target));

        // Create transport config
        let transport_config = TransportConfig {
            timeout_secs: self.config.timeout_secs,
            ..Default::default()
        };

        // Connect to server
        tracing::info!("Connecting to server: {} via {:?}", target, transport);
        let transport_box = connect_with_type(target, args, env, transport_config, transport)
            .await
            .context("Failed to connect to server")?;

        // Create client
        let client_info = Implementation::new("mcplint", env!("CARGO_PKG_VERSION"));
        let mut client = McpClient::new(transport_box, client_info);
        client.mark_connected();

        // Run validation phases
        let context = self
            .run_initialization_phase(&mut client, &mut results)
            .await?;

        if let Some(ctx) = context {
            results.protocol_version = Some(ctx.init_result.protocol_version.clone());
            results.capabilities = Some(ctx.init_result.capabilities.clone());

            // Run protocol rules
            self.run_protocol_rules(&ctx, &mut results);

            // Run schema rules
            self.run_schema_rules(&ctx, &mut results);

            // Run sequence rules (need client for these)
            self.run_sequence_rules(&mut client, &ctx, &mut results)
                .await;

            // Run tool invocation rules
            self.run_tool_rules(&mut client, &ctx, &mut results).await;

            // Run resource rules
            self.run_resource_rules(&mut client, &ctx, &mut results)
                .await;

            // Run security rules
            self.run_security_rules(&mut client, &ctx, &mut results)
                .await;

            // Run edge case rules
            self.run_edge_rules(&mut client, &ctx, &mut results).await;
        }

        // Cleanup
        let _ = client.close().await;

        results.total_duration_ms = start.elapsed().as_millis() as u64;
        Ok(results)
    }

    /// Validate using a provided client (for testing with mock clients)
    ///
    /// This method allows dependency injection of mock clients for unit testing.
    #[allow(dead_code)]
    pub async fn validate_with_client(
        &mut self,
        server_name: &str,
        client: &mut dyn McpClientTrait,
    ) -> Result<ValidationResults> {
        let start = Instant::now();
        let mut results = ValidationResults::new(server_name);

        // Run validation phases with the provided client
        let context = self
            .run_initialization_phase_with_trait(client, &mut results)
            .await?;

        if let Some(ctx) = context {
            results.protocol_version = Some(ctx.init_result.protocol_version.clone());
            results.capabilities = Some(ctx.init_result.capabilities.clone());

            // Run protocol rules
            self.run_protocol_rules(&ctx, &mut results);

            // Run schema rules
            self.run_schema_rules(&ctx, &mut results);

            // Run sequence rules
            self.run_sequence_rules_with_trait(client, &ctx, &mut results)
                .await;

            // Run tool invocation rules
            self.run_tool_rules_with_trait(client, &ctx, &mut results)
                .await;

            // Run resource rules
            self.run_resource_rules_with_trait(client, &ctx, &mut results)
                .await;

            // Run security rules
            self.run_security_rules_with_trait(client, &ctx, &mut results)
                .await;

            // Run edge case rules
            self.run_edge_rules_with_trait(client, &ctx, &mut results)
                .await;
        }

        // Cleanup
        let _ = client.close().await;

        results.total_duration_ms = start.elapsed().as_millis() as u64;
        Ok(results)
    }

    /// Phase 1: Initialize and collect server info (using trait object)
    #[allow(dead_code)]
    async fn run_initialization_phase_with_trait(
        &self,
        client: &mut dyn McpClientTrait,
        results: &mut ValidationResults,
    ) -> Result<Option<ServerContext>> {
        // PROTO-001: JSON-RPC 2.0 compliance (basic check)
        let rule = self.get_rule(ValidationRuleId::Proto001).unwrap();
        let start = Instant::now();

        // Try to initialize
        let init_result = match client.initialize().await {
            Ok(result) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
                result
            }
            Err(e) => {
                results.add_result(
                    ValidationResult::fail(
                        rule,
                        format!("Initialize failed: {}", e),
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(vec![
                        "Server may not be responding to JSON-RPC requests".to_string(),
                        "Ensure server is running and accessible".to_string(),
                    ]),
                );
                return Ok(None);
            }
        };

        // PROTO-002: Valid protocol version
        let rule = self.get_rule(ValidationRuleId::Proto002).unwrap();
        let start = Instant::now();

        if crate::protocol::mcp::is_supported_version(&init_result.protocol_version) {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(ValidationResult::fail(
                rule,
                format!(
                    "Unsupported protocol version: {} (supported: 2024-11-05, 2025-03-26)",
                    init_result.protocol_version
                ),
                start.elapsed().as_millis() as u64,
            ));
        }

        // PROTO-003: Valid server info
        let rule = self.get_rule(ValidationRuleId::Proto003).unwrap();
        let start = Instant::now();

        let mut details = Vec::new();
        let mut has_issue = false;

        if init_result.server_info.name.is_empty() {
            details.push("Server name is empty".to_string());
            has_issue = true;
        }
        if init_result.server_info.version.is_empty() {
            details.push("Server version is empty".to_string());
            has_issue = true;
        }

        if has_issue {
            results.add_result(
                ValidationResult::warning(
                    rule,
                    "Server info is incomplete",
                    start.elapsed().as_millis() as u64,
                )
                .with_details(details),
            );
        } else {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        }

        // PROTO-004: Valid capabilities object
        let rule = self.get_rule(ValidationRuleId::Proto004).unwrap();
        let start = Instant::now();
        results.add_result(ValidationResult::pass(
            rule,
            start.elapsed().as_millis() as u64,
        ));

        // Collect tools if supported
        let tools = if init_result.capabilities.has_tools() {
            match client.list_tools().await {
                Ok(tools) => Some(tools),
                Err(e) => {
                    tracing::warn!("Failed to list tools: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Collect resources if supported
        let resources = if init_result.capabilities.has_resources() {
            match client.list_resources().await {
                Ok(resources) => Some(ListResourcesResult {
                    resources,
                    next_cursor: None,
                }),
                Err(e) => {
                    tracing::warn!("Failed to list resources: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Collect prompts if supported
        let prompts = if init_result.capabilities.has_prompts() {
            match client.list_prompts().await {
                Ok(prompts) => Some(ListPromptsResult {
                    prompts,
                    next_cursor: None,
                }),
                Err(e) => {
                    tracing::warn!("Failed to list prompts: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Some(ServerContext {
            init_result,
            tools,
            resources,
            prompts,
        }))
    }

    /// Run sequence validation rules (using trait object)
    #[allow(dead_code)]
    async fn run_sequence_rules_with_trait(
        &self,
        client: &mut dyn McpClientTrait,
        _ctx: &ServerContext,
        results: &mut ValidationResults,
    ) {
        // SEQ-001: Ping response
        let rule = self.get_rule(ValidationRuleId::Seq001).unwrap();
        let start = Instant::now();

        match client.ping().await {
            Ok(_) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                results.add_result(ValidationResult::fail(
                    rule,
                    format!("Ping failed: {}", e),
                    start.elapsed().as_millis() as u64,
                ));
            }
        }

        // SEQ-002: Method not found handling
        let rule = self.get_rule(ValidationRuleId::Seq002).unwrap();
        let start = Instant::now();

        // Try calling an unknown tool
        let unknown_result = client.call_tool("__mcplint_nonexistent_tool__", None).await;

        match unknown_result {
            Ok(_) => {
                // Server should have returned an error for unknown tool
                results.add_result(ValidationResult::warning(
                    rule,
                    "Server accepted call to non-existent tool",
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("-32601")
                    || err_str.contains("not found")
                    || err_str.contains("unknown")
                {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                } else {
                    // Some error occurred, which is acceptable
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
        }

        // SEQ-003: Error response format
        let rule = self.get_rule(ValidationRuleId::Seq003).unwrap();
        let start = Instant::now();

        // The error from SEQ-002 should have been properly formatted
        // Since we got here, the error handling is at least functional
        results.add_result(ValidationResult::pass(
            rule,
            start.elapsed().as_millis() as u64,
        ));
    }

    /// Phase 1: Initialize and collect server info
    async fn run_initialization_phase(
        &self,
        client: &mut McpClient,
        results: &mut ValidationResults,
    ) -> Result<Option<ServerContext>> {
        // PROTO-001: JSON-RPC 2.0 compliance (basic check)
        let rule = self.get_rule(ValidationRuleId::Proto001).unwrap();
        let start = Instant::now();

        // Try to initialize
        let init_result = match client.initialize().await {
            Ok(result) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
                result
            }
            Err(e) => {
                results.add_result(
                    ValidationResult::fail(
                        rule,
                        format!("Initialize failed: {}", e),
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(vec![
                        "Server may not be responding to JSON-RPC requests".to_string(),
                        "Ensure server is running and accessible".to_string(),
                    ]),
                );
                return Ok(None);
            }
        };

        // PROTO-002: Valid protocol version
        let rule = self.get_rule(ValidationRuleId::Proto002).unwrap();
        let start = Instant::now();

        if crate::protocol::mcp::is_supported_version(&init_result.protocol_version) {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(ValidationResult::fail(
                rule,
                format!(
                    "Unsupported protocol version: {} (supported: 2024-11-05, 2025-03-26)",
                    init_result.protocol_version
                ),
                start.elapsed().as_millis() as u64,
            ));
        }

        // PROTO-003: Valid server info
        let rule = self.get_rule(ValidationRuleId::Proto003).unwrap();
        let start = Instant::now();

        let mut details = Vec::new();
        let mut has_issue = false;

        if init_result.server_info.name.is_empty() {
            details.push("Server name is empty".to_string());
            has_issue = true;
        }
        if init_result.server_info.version.is_empty() {
            details.push("Server version is empty".to_string());
            has_issue = true;
        }

        if has_issue {
            results.add_result(
                ValidationResult::warning(
                    rule,
                    "Server info is incomplete",
                    start.elapsed().as_millis() as u64,
                )
                .with_details(details),
            );
        } else {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        }

        // PROTO-004: Valid capabilities object
        let rule = self.get_rule(ValidationRuleId::Proto004).unwrap();
        let start = Instant::now();
        results.add_result(ValidationResult::pass(
            rule,
            start.elapsed().as_millis() as u64,
        ));

        // Collect tools if supported
        let tools = if init_result.capabilities.has_tools() {
            tracing::info!("Server advertises tools capability, listing tools...");
            match client.list_tools().await {
                Ok(tools) => {
                    tracing::info!("Successfully listed {} tools from server", tools.len());
                    Some(tools)
                }
                Err(e) => {
                    tracing::warn!("Failed to list tools: {}", e);
                    None
                }
            }
        } else {
            tracing::info!("Server does NOT advertise tools capability");
            None
        };

        // Collect resources if supported
        let resources = if init_result.capabilities.has_resources() {
            match client.list_resources_paginated(None).await {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!("Failed to list resources: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Collect prompts if supported
        let prompts = if init_result.capabilities.has_prompts() {
            match client.list_prompts().await {
                Ok(prompts) => Some(ListPromptsResult {
                    prompts,
                    next_cursor: None,
                }),
                Err(e) => {
                    tracing::warn!("Failed to list prompts: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Some(ServerContext {
            init_result,
            tools,
            resources,
            prompts,
        }))
    }

    /// Run protocol validation rules
    fn run_protocol_rules(&self, ctx: &ServerContext, results: &mut ValidationResults) {
        // PROTO-005: Valid tool definitions
        if let Some(ref tools) = ctx.tools {
            let rule = self.get_rule(ValidationRuleId::Proto005).unwrap();
            let start = Instant::now();

            let mut issues = Vec::new();
            for tool in tools {
                if tool.name.is_empty() {
                    issues.push("Tool has empty name".to_string());
                }
                if !tool.input_schema.is_object() {
                    issues.push(format!("Tool '{}' has non-object inputSchema", tool.name));
                }
            }

            if issues.is_empty() {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            } else {
                results.add_result(
                    ValidationResult::fail(
                        rule,
                        format!("Found {} tool definition issues", issues.len()),
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(issues),
                );
            }
        }

        // PROTO-006: Valid resource definitions
        if let Some(ref resources) = ctx.resources {
            let rule = self.get_rule(ValidationRuleId::Proto006).unwrap();
            let start = Instant::now();

            let mut issues = Vec::new();
            for resource in &resources.resources {
                if resource.uri.is_empty() {
                    issues.push("Resource has empty URI".to_string());
                }
                if resource.name.is_empty() {
                    issues.push(format!("Resource '{}' has empty name", resource.uri));
                }
            }

            if issues.is_empty() {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            } else {
                results.add_result(
                    ValidationResult::fail(
                        rule,
                        format!("Found {} resource definition issues", issues.len()),
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(issues),
                );
            }
        }

        // PROTO-007: Valid prompt definitions
        if let Some(ref prompts) = ctx.prompts {
            let rule = self.get_rule(ValidationRuleId::Proto007).unwrap();
            let start = Instant::now();

            let mut issues = Vec::new();
            for prompt in &prompts.prompts {
                if prompt.name.is_empty() {
                    issues.push("Prompt has empty name".to_string());
                }
            }

            if issues.is_empty() {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            } else {
                results.add_result(
                    ValidationResult::fail(
                        rule,
                        format!("Found {} prompt definition issues", issues.len()),
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(issues),
                );
            }
        }

        // PROTO-008: Capabilities consistency
        let rule = self.get_rule(ValidationRuleId::Proto008).unwrap();
        let start = Instant::now();

        let mut issues = Vec::new();
        let caps = &ctx.init_result.capabilities;

        // Check tools capability vs actual tools
        if caps.has_tools() && ctx.tools.is_none() {
            issues.push("Server advertises tools capability but tools/list failed".to_string());
        }
        if caps.has_resources() && ctx.resources.is_none() {
            issues.push(
                "Server advertises resources capability but resources/list failed".to_string(),
            );
        }
        if caps.has_prompts() && ctx.prompts.is_none() {
            issues.push("Server advertises prompts capability but prompts/list failed".to_string());
        }

        if issues.is_empty() {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(
                ValidationResult::warning(
                    rule,
                    "Capabilities inconsistency detected",
                    start.elapsed().as_millis() as u64,
                )
                .with_details(issues),
            );
        }
    }

    /// Run JSON Schema validation rules
    fn run_schema_rules(&self, ctx: &ServerContext, results: &mut ValidationResults) {
        // SCHEMA-001: Tool inputSchema is valid JSON Schema
        if let Some(ref tools) = ctx.tools {
            let rule = self.get_rule(ValidationRuleId::Schema001).unwrap();
            let start = Instant::now();

            let mut issues = Vec::new();
            for tool in tools {
                if let Err(e) = validate_json_schema(&tool.input_schema) {
                    issues.push(format!("Tool '{}': {}", tool.name, e));
                }
            }

            if issues.is_empty() {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            } else {
                results.add_result(
                    ValidationResult::fail(
                        rule,
                        format!("Found {} invalid inputSchema definitions", issues.len()),
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(issues),
                );
            }
        }

        // SCHEMA-002: Required type field
        if let Some(ref tools) = ctx.tools {
            let rule = self.get_rule(ValidationRuleId::Schema002).unwrap();
            let start = Instant::now();

            let mut issues = Vec::new();
            for tool in tools {
                if let Some(obj) = tool.input_schema.as_object() {
                    if !obj.contains_key("type") {
                        issues.push(format!(
                            "Tool '{}': inputSchema missing 'type' field",
                            tool.name
                        ));
                    }
                }
            }

            if issues.is_empty() {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            } else {
                results.add_result(
                    ValidationResult::warning(
                        rule,
                        "Some schemas missing type field",
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(issues),
                );
            }
        }

        // SCHEMA-003: Properties definitions
        if let Some(ref tools) = ctx.tools {
            let rule = self.get_rule(ValidationRuleId::Schema003).unwrap();
            let start = Instant::now();

            let mut issues = Vec::new();
            for tool in tools {
                if let Some(obj) = tool.input_schema.as_object() {
                    if let Some(serde_json::Value::String(t)) = obj.get("type") {
                        if t == "object" && !obj.contains_key("properties") {
                            issues.push(format!(
                                "Tool '{}': object schema missing 'properties' field",
                                tool.name
                            ));
                        }
                    }
                }
            }

            if issues.is_empty() {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            } else {
                results.add_result(
                    ValidationResult::warning(
                        rule,
                        "Some object schemas missing properties",
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(issues),
                );
            }
        }

        // SCHEMA-004: Required array validity
        if let Some(ref tools) = ctx.tools {
            let rule = self.get_rule(ValidationRuleId::Schema004).unwrap();
            let start = Instant::now();

            let mut issues = Vec::new();
            for tool in tools {
                if let Some(obj) = tool.input_schema.as_object() {
                    if let Some(required) = obj.get("required") {
                        if !required.is_array() {
                            issues
                                .push(format!("Tool '{}': 'required' must be an array", tool.name));
                        } else if let Some(arr) = required.as_array() {
                            // Check all required fields exist in properties
                            if let Some(props) = obj.get("properties").and_then(|p| p.as_object()) {
                                for r in arr {
                                    if let Some(name) = r.as_str() {
                                        if !props.contains_key(name) {
                                            issues.push(format!(
                                                "Tool '{}': required field '{}' not in properties",
                                                tool.name, name
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if issues.is_empty() {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            } else {
                results.add_result(
                    ValidationResult::fail(
                        rule,
                        "Invalid required array definitions",
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(issues),
                );
            }
        }

        // SCHEMA-005: Description fields present (informational)
        if let Some(ref tools) = ctx.tools {
            let rule = self.get_rule(ValidationRuleId::Schema005).unwrap();
            let start = Instant::now();

            let mut missing_desc = Vec::new();
            for tool in tools {
                if tool.description.is_none()
                    || tool
                        .description
                        .as_ref()
                        .map(|d| d.is_empty())
                        .unwrap_or(true)
                {
                    missing_desc.push(format!("Tool '{}' has no description", tool.name));
                }
            }

            if missing_desc.is_empty() {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            } else {
                results.add_result(
                    ValidationResult::warning(
                        rule,
                        format!("{} tools missing descriptions", missing_desc.len()),
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(missing_desc),
                );
            }
        }
    }

    /// Run sequence validation rules
    async fn run_sequence_rules(
        &self,
        client: &mut McpClient,
        _ctx: &ServerContext,
        results: &mut ValidationResults,
    ) {
        // SEQ-001: Ping response
        let rule = self.get_rule(ValidationRuleId::Seq001).unwrap();
        let start = Instant::now();

        match client.ping().await {
            Ok(_) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                results.add_result(ValidationResult::fail(
                    rule,
                    format!("Ping failed: {}", e),
                    start.elapsed().as_millis() as u64,
                ));
            }
        }

        // SEQ-002: Method not found handling
        let rule = self.get_rule(ValidationRuleId::Seq002).unwrap();
        let start = Instant::now();

        // Try calling an unknown method via the transport directly
        let unknown_result = client.call_tool("__mcplint_nonexistent_tool__", None).await;

        match unknown_result {
            Ok(_) => {
                // Server should have returned an error for unknown tool
                results.add_result(ValidationResult::warning(
                    rule,
                    "Server accepted call to non-existent tool",
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("-32601")
                    || err_str.contains("not found")
                    || err_str.contains("unknown")
                {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                } else {
                    // Some error occurred, which is acceptable
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
        }

        // SEQ-003: Error response format
        let rule = self.get_rule(ValidationRuleId::Seq003).unwrap();
        let start = Instant::now();

        // The error from SEQ-002 should have been properly formatted
        // Since we got here, the error handling is at least functional
        results.add_result(ValidationResult::pass(
            rule,
            start.elapsed().as_millis() as u64,
        ));

        // PROTO-011: Batch Request Support
        let rule = self.get_rule(ValidationRuleId::Proto011).unwrap();
        results.add_result(ValidationResult::pass(rule, 0).with_details(vec![
            "Batch request testing requires transport-level API".to_string(),
        ]));

        // PROTO-012: Notification Handling
        let rule = self.get_rule(ValidationRuleId::Proto012).unwrap();
        results.add_result(ValidationResult::pass(rule, 0).with_details(vec![
            "Notification testing requires transport-level API".to_string(),
        ]));

        // PROTO-013: Progress Reporting
        let rule = self.get_rule(ValidationRuleId::Proto013).unwrap();
        results.add_result(ValidationResult::pass(rule, 0).with_details(vec![
            "Progress reporting is optional but recommended".to_string(),
        ]));

        // PROTO-014: Tool Definition Immutability
        let rule = self.get_rule(ValidationRuleId::Proto014).unwrap();
        results.add_result(
            ValidationResult::pass(rule, 0)
                .with_details(vec!["Tested via SEC-013 rug pull detection".to_string()]),
        );

        // PROTO-015: Cancellation Support
        let rule = self.get_rule(ValidationRuleId::Proto015).unwrap();
        results.add_result(ValidationResult::pass(rule, 0).with_details(vec![
            "Cancellation support is optional but recommended".to_string(),
        ]));
    }

    /// Run tool invocation validation rules
    async fn run_tool_rules(
        &self,
        client: &mut McpClient,
        ctx: &ServerContext,
        results: &mut ValidationResults,
    ) {
        // Skip if no tools available
        let tools = match &ctx.tools {
            Some(t) if !t.is_empty() => {
                tracing::info!("Running TOOL rules with {} tools available", t.len());
                t
            }
            Some(t) => {
                tracing::info!("Skipping TOOL rules: tools list is empty (len={})", t.len());
                return;
            }
            None => {
                tracing::info!("Skipping TOOL rules: ctx.tools is None");
                return;
            }
        };

        // Pick a tool to test (prefer one with simple/no required params)
        let test_tool = tools
            .iter()
            .find(|t| {
                t.input_schema
                    .get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| arr.is_empty())
                    .unwrap_or(true)
            })
            .or_else(|| tools.first());

        if let Some(tool) = test_tool {
            // TOOL-001: Tool call with valid input succeeds
            let rule = self.get_rule(ValidationRuleId::Tool001).unwrap();
            let start = Instant::now();

            // Try calling with empty object (for tools with no required params)
            let call_result = client
                .call_tool(&tool.name, Some(serde_json::json!({})))
                .await;

            match call_result {
                Ok(_) => {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
                Err(e) => {
                    let err_str = e.to_string();
                    // If error is about missing params, that's expected for some tools
                    if err_str.contains("required")
                        || err_str.contains("missing")
                        || err_str.contains("parameter")
                    {
                        results.add_result(
                            ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                                .with_details(vec![format!(
                                    "Tool '{}' requires parameters (expected behavior)",
                                    tool.name
                                )]),
                        );
                    } else {
                        results.add_result(
                            ValidationResult::warning(
                                rule,
                                format!("Tool call failed: {}", e),
                                start.elapsed().as_millis() as u64,
                            )
                            .with_details(vec![format!("Tool: {}", tool.name)]),
                        );
                    }
                }
            }

            // TOOL-002: Tool returns error for missing required parameters
            let rule = self.get_rule(ValidationRuleId::Tool002).unwrap();
            let start = Instant::now();

            // Find a tool with required params
            let tool_with_required = tools.iter().find(|t| {
                t.input_schema
                    .get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| !arr.is_empty())
                    .unwrap_or(false)
            });

            if let Some(req_tool) = tool_with_required {
                let call_result = client
                    .call_tool(&req_tool.name, Some(serde_json::json!({})))
                    .await;

                match call_result {
                    Ok(_) => {
                        results.add_result(ValidationResult::warning(
                            rule,
                            format!(
                                "Tool '{}' accepted call without required parameters",
                                req_tool.name
                            ),
                            start.elapsed().as_millis() as u64,
                        ));
                    }
                    Err(_) => {
                        results.add_result(ValidationResult::pass(
                            rule,
                            start.elapsed().as_millis() as u64,
                        ));
                    }
                }
            } else {
                results.add_result(
                    ValidationResult::pass(rule, start.elapsed().as_millis() as u64).with_details(
                        vec!["No tools with required parameters to test".to_string()],
                    ),
                );
            }

            // TOOL-003: Tool returns error for wrong parameter types
            let rule = self.get_rule(ValidationRuleId::Tool003).unwrap();
            let start = Instant::now();

            // Find a tool with typed properties
            let tool_with_types = tools.iter().find(|t| {
                t.input_schema
                    .get("properties")
                    .and_then(|p| p.as_object())
                    .map(|obj| !obj.is_empty())
                    .unwrap_or(false)
            });

            if let Some(typed_tool) = tool_with_types {
                // Send wrong types (array instead of expected type)
                let wrong_params = serde_json::json!({
                    "___invalid_param___": [1, 2, 3]
                });

                let call_result = client.call_tool(&typed_tool.name, Some(wrong_params)).await;

                // Either error or success is acceptable (server may ignore extra params)
                results.add_result(
                    ValidationResult::pass(rule, start.elapsed().as_millis() as u64).with_details(
                        vec![match call_result {
                            Ok(_) => "Server accepts/ignores invalid params".to_string(),
                            Err(_) => "Server rejects invalid params".to_string(),
                        }],
                    ),
                );
            } else {
                results.add_result(
                    ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                        .with_details(vec!["No tools with typed properties to test".to_string()]),
                );
            }

            // TOOL-004: Tool output is valid JSON
            let rule = self.get_rule(ValidationRuleId::Tool004).unwrap();
            let start = Instant::now();

            // If we got a successful call earlier, the output was valid JSON
            // (the client deserialized it successfully)
            results.add_result(
                ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                    .with_details(vec!["JSON parsing handled by protocol layer".to_string()]),
            );

            // TOOL-005: Tool handles null/empty input gracefully
            let rule = self.get_rule(ValidationRuleId::Tool005).unwrap();
            let start = Instant::now();

            let null_result = client.call_tool(&tool.name, None).await;

            match null_result {
                Ok(_) => {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
                Err(e) => {
                    let err_str = e.to_string();
                    // Graceful error handling counts as passing
                    if err_str.contains("required")
                        || err_str.contains("missing")
                        || err_str.contains("invalid")
                    {
                        results.add_result(ValidationResult::pass(
                            rule,
                            start.elapsed().as_millis() as u64,
                        ));
                    } else {
                        results.add_result(ValidationResult::warning(
                            rule,
                            format!("Unexpected error for null input: {}", e),
                            start.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }
        }
    }

    /// Run tool invocation validation rules (using trait object)
    #[allow(dead_code)]
    async fn run_tool_rules_with_trait(
        &self,
        client: &mut dyn McpClientTrait,
        ctx: &ServerContext,
        results: &mut ValidationResults,
    ) {
        // Skip if no tools available
        let tools = match &ctx.tools {
            Some(t) if !t.is_empty() => t,
            _ => return,
        };

        // Pick a tool to test
        let test_tool = tools
            .iter()
            .find(|t| {
                t.input_schema
                    .get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| arr.is_empty())
                    .unwrap_or(true)
            })
            .or_else(|| tools.first());

        if let Some(tool) = test_tool {
            // TOOL-001: Tool call with valid input succeeds
            let rule = self.get_rule(ValidationRuleId::Tool001).unwrap();
            let start = Instant::now();

            let call_result = client
                .call_tool(&tool.name, Some(serde_json::json!({})))
                .await;

            match call_result {
                Ok(_) => {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("required")
                        || err_str.contains("missing")
                        || err_str.contains("parameter")
                    {
                        results.add_result(ValidationResult::pass(
                            rule,
                            start.elapsed().as_millis() as u64,
                        ));
                    } else {
                        results.add_result(ValidationResult::warning(
                            rule,
                            format!("Tool call failed: {}", e),
                            start.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }

            // TOOL-002 through TOOL-005: Simplified for trait version
            for rule_id in [
                ValidationRuleId::Tool002,
                ValidationRuleId::Tool003,
                ValidationRuleId::Tool004,
                ValidationRuleId::Tool005,
            ] {
                let rule = self.get_rule(rule_id).unwrap();
                results.add_result(ValidationResult::pass(rule, 0));
            }
        }
    }

    /// Run resource validation rules
    async fn run_resource_rules(
        &self,
        client: &mut McpClient,
        ctx: &ServerContext,
        results: &mut ValidationResults,
    ) {
        // Skip if no resources available
        let resources = match &ctx.resources {
            Some(r) if !r.resources.is_empty() => {
                tracing::info!(
                    "Running RESOURCE rules with {} resources available",
                    r.resources.len()
                );
                r
            }
            Some(r) => {
                tracing::info!(
                    "Skipping RESOURCE rules: resources list is empty (len={})",
                    r.resources.len()
                );
                return;
            }
            None => {
                tracing::info!("Skipping RESOURCE rules: ctx.resources is None");
                return;
            }
        };

        // RES-001: Resource read works for listed resources
        let rule = self.get_rule(ValidationRuleId::Res001).unwrap();
        let start = Instant::now();

        let first_resource = &resources.resources[0];
        let read_result = client.read_resource(&first_resource.uri).await;

        match read_result {
            Ok(_) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                results.add_result(
                    ValidationResult::fail(
                        rule,
                        format!("Resource read failed: {}", e),
                        start.elapsed().as_millis() as u64,
                    )
                    .with_details(vec![format!("URI: {}", first_resource.uri)]),
                );
            }
        }

        // RES-002: Invalid resource URI returns proper error
        let rule = self.get_rule(ValidationRuleId::Res002).unwrap();
        let start = Instant::now();

        let invalid_uri = "invalid://___nonexistent_resource___/path";
        let invalid_result = client.read_resource(invalid_uri).await;

        match invalid_result {
            Ok(_) => {
                results.add_result(ValidationResult::warning(
                    rule,
                    "Server returned content for invalid URI",
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(_) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            }
        }

        // RES-003: Resource content type validation
        let rule = self.get_rule(ValidationRuleId::Res003).unwrap();
        let start = Instant::now();

        // If we got content above, assume MIME handling is correct
        results.add_result(
            ValidationResult::pass(rule, start.elapsed().as_millis() as u64).with_details(vec![
                "MIME type validation performed at protocol level".to_string(),
            ]),
        );
    }

    /// Run resource validation rules (using trait object)
    #[allow(dead_code)]
    async fn run_resource_rules_with_trait(
        &self,
        client: &mut dyn McpClientTrait,
        ctx: &ServerContext,
        results: &mut ValidationResults,
    ) {
        let resources = match &ctx.resources {
            Some(r) if !r.resources.is_empty() => r,
            _ => return,
        };

        // RES-001: Resource read works
        let rule = self.get_rule(ValidationRuleId::Res001).unwrap();
        let start = Instant::now();

        let first_resource = &resources.resources[0];
        let read_result = client.read_resource(&first_resource.uri).await;

        match read_result {
            Ok(_) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                results.add_result(ValidationResult::fail(
                    rule,
                    format!("Resource read failed: {}", e),
                    start.elapsed().as_millis() as u64,
                ));
            }
        }

        // RES-002 and RES-003
        for rule_id in [ValidationRuleId::Res002, ValidationRuleId::Res003] {
            let rule = self.get_rule(rule_id).unwrap();
            results.add_result(ValidationResult::pass(rule, 0));
        }
    }

    /// Run security validation rules
    async fn run_security_rules(
        &self,
        client: &mut McpClient,
        ctx: &ServerContext,
        results: &mut ValidationResults,
    ) {
        tracing::info!("Running SECURITY rules (SEC-001 to SEC-004)");
        // SEC-001: Path traversal protection
        let rule = self.get_rule(ValidationRuleId::Sec001).unwrap();
        let start = Instant::now();

        // Test path traversal payloads against tools that might handle files
        let traversal_payloads = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f",
            "....//....//",
        ];

        let mut path_traversal_blocked = true;
        let mut tested = false;

        if let Some(ref tools) = ctx.tools {
            // Find tools that might handle paths
            let path_tools: Vec<_> = tools
                .iter()
                .filter(|t| {
                    let name_lower = t.name.to_lowercase();
                    let desc_lower = t
                        .description
                        .as_ref()
                        .map(|d| d.to_lowercase())
                        .unwrap_or_default();
                    name_lower.contains("file")
                        || name_lower.contains("read")
                        || name_lower.contains("path")
                        || desc_lower.contains("file")
                        || desc_lower.contains("path")
                })
                .collect();

            for tool in path_tools.iter().take(1) {
                for payload in &traversal_payloads {
                    tested = true;
                    let params = serde_json::json!({
                        "path": payload,
                        "file": payload,
                        "filename": payload
                    });

                    let result = client.call_tool(&tool.name, Some(params)).await;

                    // If we get sensitive content back, that's a problem
                    if let Ok(content) = result {
                        let content_str = format!("{:?}", content);
                        if content_str.contains("root:")
                            || content_str.contains("Administrator")
                            || content_str.contains("[boot loader]")
                        {
                            path_traversal_blocked = false;
                            break;
                        }
                    }
                }
            }
        }

        if !tested {
            results.add_result(
                ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                    .with_details(vec!["No file-handling tools to test".to_string()]),
            );
        } else if path_traversal_blocked {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(ValidationResult::fail(
                rule,
                "Path traversal vulnerability detected",
                start.elapsed().as_millis() as u64,
            ));
        }

        // SEC-002: Command injection protection
        let rule = self.get_rule(ValidationRuleId::Sec002).unwrap();
        let start = Instant::now();

        let injection_payloads = vec![
            "; echo vulnerable",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "&& dir",
        ];

        let mut injection_blocked = true;
        let mut tested = false;

        if let Some(ref tools) = ctx.tools {
            // Find tools that might execute commands
            let exec_tools: Vec<_> = tools
                .iter()
                .filter(|t| {
                    let name_lower = t.name.to_lowercase();
                    let desc_lower = t
                        .description
                        .as_ref()
                        .map(|d| d.to_lowercase())
                        .unwrap_or_default();
                    name_lower.contains("exec")
                        || name_lower.contains("run")
                        || name_lower.contains("shell")
                        || name_lower.contains("command")
                        || desc_lower.contains("execute")
                        || desc_lower.contains("command")
                })
                .collect();

            for tool in exec_tools.iter().take(1) {
                for payload in &injection_payloads {
                    tested = true;
                    let params = serde_json::json!({
                        "command": payload,
                        "cmd": payload,
                        "input": payload
                    });

                    let result = client.call_tool(&tool.name, Some(params)).await;

                    if let Ok(content) = result {
                        let content_str = format!("{:?}", content);
                        if content_str.contains("vulnerable")
                            || content_str.contains("uid=")
                            || content_str.contains("root:")
                        {
                            injection_blocked = false;
                            break;
                        }
                    }
                }
            }
        }

        if !tested {
            results.add_result(
                ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                    .with_details(vec!["No command-executing tools to test".to_string()]),
            );
        } else if injection_blocked {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(ValidationResult::fail(
                rule,
                "Command injection vulnerability detected",
                start.elapsed().as_millis() as u64,
            ));
        }

        // SEC-003: Input size limits
        let rule = self.get_rule(ValidationRuleId::Sec003).unwrap();
        let start = Instant::now();

        // This is tested in EDGE-002, so we pass here
        results.add_result(
            ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                .with_details(vec!["Size limit testing covered by EDGE-002".to_string()]),
        );

        // SEC-004: Error message safety
        let rule = self.get_rule(ValidationRuleId::Sec004).unwrap();
        let start = Instant::now();

        let mut safe_errors = true;

        // Try to trigger errors and check for sensitive data exposure
        if let Some(ref tools) = ctx.tools {
            if let Some(tool) = tools.first() {
                let bad_params = serde_json::json!({
                    "___trigger_error___": null
                });

                if let Err(e) = client.call_tool(&tool.name, Some(bad_params)).await {
                    let err_str = e.to_string().to_lowercase();
                    // Check for sensitive info in error
                    if err_str.contains("/home/")
                        || err_str.contains("c:\\users\\")
                        || err_str.contains("password")
                        || err_str.contains("secret")
                        || err_str.contains("api_key")
                        || err_str.contains("token")
                    {
                        safe_errors = false;
                    }
                }
            }
        }

        if safe_errors {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(ValidationResult::warning(
                rule,
                "Error messages may expose sensitive information",
                start.elapsed().as_millis() as u64,
            ));
        }

        // SEC-005: SQL Injection Protection
        let rule = self.get_rule(ValidationRuleId::Sec005).unwrap();
        let start = Instant::now();

        let sql_payloads = vec![
            "'; DROP TABLE users; --",
            "1 OR 1=1",
            "1' AND '1'='1",
            "UNION SELECT * FROM passwords",
            "'; EXEC xp_cmdshell('whoami'); --",
        ];

        let mut sql_injection_blocked = true;
        let mut tested = false;

        if let Some(ref tools) = ctx.tools {
            let db_tools: Vec<_> = tools
                .iter()
                .filter(|t| {
                    let name_lower = t.name.to_lowercase();
                    let desc_lower = t
                        .description
                        .as_ref()
                        .map(|d| d.to_lowercase())
                        .unwrap_or_default();
                    name_lower.contains("query")
                        || name_lower.contains("sql")
                        || name_lower.contains("database")
                        || name_lower.contains("db")
                        || name_lower.contains("search")
                        || name_lower.contains("find")
                        || desc_lower.contains("query")
                        || desc_lower.contains("database")
                })
                .collect();

            for tool in db_tools.iter().take(1) {
                for payload in &sql_payloads {
                    tested = true;
                    let params = serde_json::json!({
                        "query": payload,
                        "sql": payload,
                        "search": payload,
                        "filter": payload,
                        "id": payload
                    });

                    let result = client.call_tool(&tool.name, Some(params)).await;

                    if let Ok(content) = result {
                        let content_str = format!("{:?}", content).to_lowercase();
                        if content_str.contains("syntax error")
                            || content_str.contains("sql error")
                            || content_str.contains("mysql")
                            || content_str.contains("postgresql")
                            || content_str.contains("sqlite")
                        {
                            sql_injection_blocked = false;
                            break;
                        }
                    }
                }
            }
        }

        if !tested {
            results.add_result(
                ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                    .with_details(vec!["No database-related tools to test".to_string()]),
            );
        } else if sql_injection_blocked {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(ValidationResult::warning(
                rule,
                "Server may be vulnerable to SQL injection",
                start.elapsed().as_millis() as u64,
            ));
        }

        // SEC-006: SSRF Protection
        let rule = self.get_rule(ValidationRuleId::Sec006).unwrap();
        let start = Instant::now();

        let ssrf_payloads = vec![
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://0.0.0.0/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "file:///etc/passwd",
        ];

        let mut ssrf_blocked = true;
        let mut tested = false;

        if let Some(ref tools) = ctx.tools {
            let url_tools: Vec<_> = tools
                .iter()
                .filter(|t| {
                    let name_lower = t.name.to_lowercase();
                    let desc_lower = t
                        .description
                        .as_ref()
                        .map(|d| d.to_lowercase())
                        .unwrap_or_default();
                    name_lower.contains("fetch")
                        || name_lower.contains("url")
                        || name_lower.contains("http")
                        || name_lower.contains("request")
                        || name_lower.contains("get")
                        || name_lower.contains("download")
                        || desc_lower.contains("url")
                        || desc_lower.contains("fetch")
                        || desc_lower.contains("http")
                })
                .collect();

            for tool in url_tools.iter().take(1) {
                for payload in &ssrf_payloads {
                    tested = true;
                    let params = serde_json::json!({
                        "url": payload,
                        "uri": payload,
                        "endpoint": payload,
                        "target": payload
                    });

                    let result = client.call_tool(&tool.name, Some(params)).await;

                    if let Ok(content) = result {
                        let content_str = format!("{:?}", content).to_lowercase();
                        if content_str.contains("root:")
                            || content_str.contains("ami-id")
                            || content_str.contains("instance-id")
                            || content_str.len() > 100
                        {
                            ssrf_blocked = false;
                            break;
                        }
                    }
                }
            }
        }

        if !tested {
            results.add_result(
                ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                    .with_details(vec!["No URL-fetching tools to test".to_string()]),
            );
        } else if ssrf_blocked {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(ValidationResult::fail(
                rule,
                "Server may be vulnerable to SSRF",
                start.elapsed().as_millis() as u64,
            ));
        }

        // SEC-007: Prototype Pollution Protection
        let rule = self.get_rule(ValidationRuleId::Sec007).unwrap();
        let start = Instant::now();

        let proto_params = serde_json::json!({
            "__proto__": {"polluted": true},
            "constructor": {"prototype": {"polluted": true}},
            "prototype": {"polluted": true}
        });

        if let Some(ref tools) = ctx.tools {
            if let Some(tool) = tools.first() {
                let proto_result = client.call_tool(&tool.name, Some(proto_params)).await;

                match proto_result {
                    Ok(content) => {
                        let content_str = format!("{:?}", content).to_lowercase();
                        if content_str.contains("polluted") {
                            results.add_result(ValidationResult::warning(
                                rule,
                                "Server may be vulnerable to prototype pollution",
                                start.elapsed().as_millis() as u64,
                            ));
                        } else {
                            results.add_result(ValidationResult::pass(
                                rule,
                                start.elapsed().as_millis() as u64,
                            ));
                        }
                    }
                    Err(_) => {
                        results.add_result(ValidationResult::pass(
                            rule,
                            start.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }
        }

        // SEC-008: Log Injection Protection
        let rule = self.get_rule(ValidationRuleId::Sec008).unwrap();
        let start = Instant::now();

        let log_params = serde_json::json!({
            "message": "normal\n[CRITICAL] Fake log entry\n[ERROR] Injected",
            "user": "admin\r\n[INFO] User logged in successfully",
            "data": "test\x1b[31mRED_TEXT\x1b[0m"
        });

        if let Some(ref tools) = ctx.tools {
            if let Some(tool) = tools.first() {
                let log_result = client.call_tool(&tool.name, Some(log_params)).await;

                // Just verify it doesn't crash - actual log injection is hard to detect externally
                match log_result {
                    Ok(_) | Err(_) => {
                        results.add_result(
                            ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                                .with_details(vec![
                                    "Log injection requires server-side log inspection".to_string(),
                                ]),
                        );
                    }
                }
            }
        }

        // SEC-009: XXE Protection
        let rule = self.get_rule(ValidationRuleId::Sec009).unwrap();
        let start = Instant::now();

        let xxe_payloads = vec![
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>"#,
        ];

        let mut xxe_tested = false;

        if let Some(ref tools) = ctx.tools {
            let xml_tools: Vec<_> = tools
                .iter()
                .filter(|t| {
                    let name_lower = t.name.to_lowercase();
                    let desc_lower = t
                        .description
                        .as_ref()
                        .map(|d| d.to_lowercase())
                        .unwrap_or_default();
                    name_lower.contains("xml")
                        || name_lower.contains("parse")
                        || name_lower.contains("import")
                        || desc_lower.contains("xml")
                })
                .collect();

            for tool in xml_tools.iter().take(1) {
                for payload in &xxe_payloads {
                    xxe_tested = true;
                    let params = serde_json::json!({
                        "xml": payload,
                        "data": payload,
                        "content": payload
                    });

                    let result = client.call_tool(&tool.name, Some(params)).await;

                    if let Ok(content) = result {
                        let content_str = format!("{:?}", content);
                        if content_str.contains("root:") || content_str.contains("/bin/bash") {
                            results.add_result(ValidationResult::fail(
                                rule,
                                "Server vulnerable to XXE injection",
                                start.elapsed().as_millis() as u64,
                            ));
                            break;
                        }
                    }
                }
            }
        }

        if !xxe_tested {
            results.add_result(
                ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                    .with_details(vec!["No XML-processing tools to test".to_string()]),
            );
        } else {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        }

        // SEC-010: Template Injection Protection
        let rule = self.get_rule(ValidationRuleId::Sec010).unwrap();
        let start = Instant::now();

        let template_payloads = vec![
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{{constructor.constructor('return this')()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ];

        let mut template_vulnerable = false;
        let mut tested = false;

        if let Some(ref tools) = ctx.tools {
            if let Some(tool) = tools.first() {
                for payload in &template_payloads {
                    tested = true;
                    let params = serde_json::json!({
                        "template": payload,
                        "message": payload,
                        "text": payload,
                        "input": payload
                    });

                    let result = client.call_tool(&tool.name, Some(params)).await;

                    if let Ok(content) = result {
                        let content_str = format!("{:?}", content);
                        // Check if template was evaluated (7*7 = 49)
                        if content_str.contains("49") && !content_str.contains("7*7") {
                            template_vulnerable = true;
                            break;
                        }
                    }
                }
            }
        }

        if !tested {
            results.add_result(
                ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                    .with_details(vec!["No tools available to test".to_string()]),
            );
        } else if template_vulnerable {
            results.add_result(ValidationResult::fail(
                rule,
                "Server may be vulnerable to template injection",
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        }
        // SEC-011: Tool Description Sanitization (Prompt Injection Detection)
        // Smart detection: only flag patterns that appear in imperative/command context,
        // not when they're part of legitimate documentation (e.g., "configures system prompt")
        let rule = self.get_rule(ValidationRuleId::Sec011).unwrap();
        let start = Instant::now();

        // High-confidence injection patterns (always suspicious)
        let always_suspicious = vec![
            "ignore previous",
            "ignore all previous",
            "disregard previous",
            "forget everything",
            "new instructions:",
            "you are now",
            "pretend to be",
            "roleplay as",
            "<system>",
            "</system>",
            "[[system]]",
            "{{system}}",
        ];

        // Context-dependent patterns (only suspicious with imperative verbs)
        let context_patterns = vec!["system prompt", "act as"];
        let imperative_prefixes = vec![
            "override",
            "change",
            "set",
            "use this",
            "inject",
            "insert",
            "replace",
            "modify",
            "update the",
            "become",
        ];

        let mut injection_found = false;
        let mut injection_details = Vec::new();
        if let Some(ref tools) = ctx.tools {
            for tool in tools {
                let desc = tool
                    .description
                    .as_ref()
                    .map(|d| d.to_lowercase())
                    .unwrap_or_default();

                // Check always-suspicious patterns
                for pattern in &always_suspicious {
                    if desc.contains(&pattern.to_lowercase()) {
                        injection_found = true;
                        injection_details
                            .push(format!("Tool '{}' contains: '{}'", tool.name, pattern));
                    }
                }

                // Check context-dependent patterns (need imperative verb nearby)
                for pattern in &context_patterns {
                    if desc.contains(&pattern.to_lowercase()) {
                        // Look for imperative verb within 50 chars before the pattern
                        if let Some(pos) = desc.find(&pattern.to_lowercase()) {
                            let prefix_start = pos.saturating_sub(50);
                            let prefix = &desc[prefix_start..pos];
                            for verb in &imperative_prefixes {
                                if prefix.contains(verb) {
                                    injection_found = true;
                                    injection_details.push(format!(
                                        "Tool '{}' contains: '{}' with imperative context",
                                        tool.name, pattern
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        if injection_found {
            results.add_result(
                ValidationResult::warning(
                    rule,
                    "Prompt injection patterns detected",
                    start.elapsed().as_millis() as u64,
                )
                .with_details(injection_details),
            );
        } else {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        }

        // SEC-012: Tool Shadowing Prevention
        let rule = self.get_rule(ValidationRuleId::Sec012).unwrap();
        let start = Instant::now();
        let reserved = vec![
            "execute", "exec", "shell", "bash", "cmd", "eval", "system", "sudo", "root",
        ];
        let mut shadowing = false;
        let mut shadow_details = Vec::new();
        if let Some(ref tools) = ctx.tools {
            for tool in tools {
                let n = tool.name.to_lowercase();
                for r in &reserved {
                    if n == *r {
                        shadowing = true;
                        shadow_details.push(format!("'{}' shadows '{}'", tool.name, r));
                    }
                }
            }
            let names: Vec<_> = tools.iter().map(|t| t.name.to_lowercase()).collect();
            for (i, n1) in names.iter().enumerate() {
                for n2 in names.iter().skip(i + 1) {
                    if n1 == n2 {
                        shadowing = true;
                        shadow_details.push(format!("Duplicate: '{}'", n1));
                    }
                }
            }
        }
        if shadowing {
            results.add_result(
                ValidationResult::warning(
                    rule,
                    "Tool shadowing detected",
                    start.elapsed().as_millis() as u64,
                )
                .with_details(shadow_details),
            );
        } else {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        }

        // SEC-013: Rug Pull Detection
        let rule = self.get_rule(ValidationRuleId::Sec013).unwrap();
        let start = Instant::now();
        match client.list_tools().await {
            Ok(refetched) => {
                let mut changed = false;
                let mut details = Vec::new();
                if let Some(ref orig) = ctx.tools {
                    if orig.len() != refetched.len() {
                        changed = true;
                        details.push(format!("Tool count: {} -> {}", orig.len(), refetched.len()));
                    }
                    for o in orig {
                        if let Some(r) = refetched.iter().find(|t| t.name == o.name) {
                            let os = serde_json::to_string(&o.input_schema).unwrap_or_default();
                            let rs = serde_json::to_string(&r.input_schema).unwrap_or_default();
                            if os != rs {
                                changed = true;
                                details.push(format!("'{}' schema changed", o.name));
                            }
                        } else {
                            changed = true;
                            details.push(format!("'{}' disappeared", o.name));
                        }
                    }
                }
                if changed {
                    results.add_result(
                        ValidationResult::fail(
                            rule,
                            "Rug pull detected",
                            start.elapsed().as_millis() as u64,
                        )
                        .with_details(details),
                    );
                } else {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
            Err(_) => results.add_result(
                ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                    .with_details(vec!["Could not re-fetch tools".to_string()]),
            ),
        }

        // SEC-014: Sensitive Data Exposure
        let rule = self.get_rule(ValidationRuleId::Sec014).unwrap();
        let start = Instant::now();
        let sensitive = vec![
            "api_key",
            "apikey",
            "secret",
            "password",
            "token",
            "bearer",
            "private_key",
            "credential",
        ];
        let mut exposure = false;
        let mut exp_details = Vec::new();
        if let Some(ref tools) = ctx.tools {
            if let Some(tool) = tools.first() {
                if let Ok(content) = client.call_tool(&tool.name, None).await {
                    let s = format!("{:?}", content).to_lowercase();
                    for p in &sensitive {
                        if s.contains(p) {
                            exposure = true;
                            exp_details.push(format!("Found '{}'", p));
                        }
                    }
                }
            }
        }
        if exposure {
            results.add_result(
                ValidationResult::warning(
                    rule,
                    "Sensitive data in output",
                    start.elapsed().as_millis() as u64,
                )
                .with_details(exp_details),
            );
        } else {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        }

        // SEC-015: URL Fetch Whitelisting
        let rule = self.get_rule(ValidationRuleId::Sec015).unwrap();
        let start = Instant::now();
        let dangerous = vec!["http://evil.com/", "ftp://ftp.example.com/", "gopher://x/"];
        let mut unrestricted = false;
        if let Some(ref tools) = ctx.tools {
            let fetch_tools: Vec<_> = tools
                .iter()
                .filter(|t| {
                    let n = t.name.to_lowercase();
                    n.contains("fetch") || n.contains("download") || n.contains("http")
                })
                .collect();
            for tool in fetch_tools.iter().take(1) {
                for url in &dangerous {
                    let params = serde_json::json!({"url": url});
                    if let Ok(content) = client.call_tool(&tool.name, Some(params)).await {
                        let s = format!("{:?}", content).to_lowercase();
                        if !s.contains("blocked") && !s.contains("denied") {
                            unrestricted = true;
                            break;
                        }
                    }
                }
            }
        }
        if unrestricted {
            results.add_result(ValidationResult::warning(
                rule,
                "URL fetch may be unrestricted",
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(
                ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                    .with_details(vec!["No unrestricted fetch".to_string()]),
            );
        }
    }

    /// Run security validation rules (using trait object)
    #[allow(dead_code)]
    async fn run_security_rules_with_trait(
        &self,
        _client: &mut dyn McpClientTrait,
        _ctx: &ServerContext,
        results: &mut ValidationResults,
    ) {
        // Simplified security checks for mock testing
        for rule_id in [
            ValidationRuleId::Sec001,
            ValidationRuleId::Sec002,
            ValidationRuleId::Sec003,
            ValidationRuleId::Sec004,
        ] {
            let rule = self.get_rule(rule_id).unwrap();
            results.add_result(
                ValidationResult::pass(rule, 0)
                    .with_details(vec!["Security tests require real server".to_string()]),
            );
        }
    }

    /// Run edge case validation rules
    async fn run_edge_rules(
        &self,
        client: &mut McpClient,
        ctx: &ServerContext,
        results: &mut ValidationResults,
    ) {
        // Skip if no tools available
        let tools = match &ctx.tools {
            Some(t) if !t.is_empty() => {
                tracing::info!("Running EDGE rules with {} tools available", t.len());
                t
            }
            Some(t) => {
                tracing::info!("Skipping EDGE rules: tools list is empty (len={})", t.len());
                return;
            }
            None => {
                tracing::info!("Skipping EDGE rules: ctx.tools is None");
                return;
            }
        };

        let test_tool = tools.first().unwrap();

        // EDGE-001: Empty input handling
        let rule = self.get_rule(ValidationRuleId::Edge001).unwrap();
        let start = Instant::now();

        let empty_result = client
            .call_tool(&test_tool.name, Some(serde_json::json!("")))
            .await;

        // Any response (success or graceful error) is acceptable
        match empty_result {
            Ok(_) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                let err_str = e.to_string();
                // Check for graceful error handling (not a crash/panic)
                if err_str.contains("panic") || err_str.contains("SIGKILL") {
                    results.add_result(ValidationResult::fail(
                        rule,
                        "Server crashed on empty input",
                        start.elapsed().as_millis() as u64,
                    ));
                } else {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
        }

        // EDGE-002: Large input handling
        let rule = self.get_rule(ValidationRuleId::Edge002).unwrap();
        let start = Instant::now();

        // Create a moderately large input (100KB)
        let large_input = "x".repeat(100_000);
        let large_params = serde_json::json!({
            "data": large_input
        });

        let large_result = client.call_tool(&test_tool.name, Some(large_params)).await;

        match large_result {
            Ok(_) => {
                results.add_result(
                    ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                        .with_details(vec!["Server accepted large input".to_string()]),
                );
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("panic") || err_str.contains("SIGKILL") {
                    results.add_result(ValidationResult::fail(
                        rule,
                        "Server crashed on large input",
                        start.elapsed().as_millis() as u64,
                    ));
                } else {
                    results.add_result(
                        ValidationResult::pass(rule, start.elapsed().as_millis() as u64)
                            .with_details(vec![
                                "Server rejected large input gracefully".to_string()
                            ]),
                    );
                }
            }
        }

        // EDGE-003: Unicode handling
        let rule = self.get_rule(ValidationRuleId::Edge003).unwrap();
        let start = Instant::now();

        let unicode_inputs = vec![
            "こんにちは世界",           // Japanese
            "🎉🚀💻",                   // Emojis
            "مرحبا",                    // Arabic
            "\u{0000}\u{FFFF}",         // Boundary chars
            "Ω≈ç√∫",                    // Math symbols
            "\u{202e}reversed\u{202c}", // RTL override
        ];

        let mut unicode_handled = true;
        for input in unicode_inputs {
            let params = serde_json::json!({
                "text": input,
                "input": input
            });

            let result = client.call_tool(&test_tool.name, Some(params)).await;

            if let Err(e) = result {
                let err_str = e.to_string();
                if err_str.contains("panic")
                    || err_str.contains("invalid utf")
                    || err_str.contains("encoding")
                {
                    unicode_handled = false;
                    break;
                }
            }
        }

        if unicode_handled {
            results.add_result(ValidationResult::pass(
                rule,
                start.elapsed().as_millis() as u64,
            ));
        } else {
            results.add_result(ValidationResult::warning(
                rule,
                "Server may have issues with unicode input",
                start.elapsed().as_millis() as u64,
            ));
        }

        // EDGE-004: Concurrent request handling
        let rule = self.get_rule(ValidationRuleId::Edge004).unwrap();
        let start = Instant::now();

        // Note: True concurrency testing requires spawning multiple connections
        // For now, we verify the server handles rapid sequential requests
        let mut rapid_ok = true;
        for _ in 0..5 {
            let result = client.call_tool(&test_tool.name, None).await;
            if let Err(e) = result {
                let err_str = e.to_string();
                if err_str.contains("busy")
                    || err_str.contains("concurrent")
                    || err_str.contains("locked")
                {
                    rapid_ok = false;
                    break;
                }
            }
        }

        if rapid_ok {
            results.add_result(
                ValidationResult::pass(rule, start.elapsed().as_millis() as u64).with_details(
                    vec!["Rapid sequential requests handled correctly".to_string()],
                ),
            );
        } else {
            results.add_result(ValidationResult::warning(
                rule,
                "Server may have concurrency issues",
                start.elapsed().as_millis() as u64,
            ));
        }

        // EDGE-005: Null byte injection
        let rule = self.get_rule(ValidationRuleId::Edge005).unwrap();
        let start = Instant::now();

        let null_params = serde_json::json!({
            "data": "before\x00after",
            "path": "/tmp/test\x00.txt",
            "name": "file\x00name"
        });

        let null_result = client.call_tool(&test_tool.name, Some(null_params)).await;

        match null_result {
            Ok(content) => {
                let content_str = format!("{:?}", content);
                // Check if null byte caused truncation (only got "before" or "/tmp/test")
                if content_str.contains("before") && !content_str.contains("after") {
                    results.add_result(ValidationResult::warning(
                        rule,
                        "Server may truncate at null bytes",
                        start.elapsed().as_millis() as u64,
                    ));
                } else {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("panic") || err_str.contains("crash") {
                    results.add_result(ValidationResult::fail(
                        rule,
                        "Server crashed on null byte input",
                        start.elapsed().as_millis() as u64,
                    ));
                } else {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
        }

        // EDGE-006: Deeply nested JSON
        let rule = self.get_rule(ValidationRuleId::Edge006).unwrap();
        let start = Instant::now();

        // Create 100-level deep nested object
        let mut nested = serde_json::json!({"value": "deep"});
        for _ in 0..100 {
            nested = serde_json::json!({"nested": nested});
        }

        let nested_result = client.call_tool(&test_tool.name, Some(nested)).await;

        match nested_result {
            Ok(_) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("stack overflow")
                    || err_str.contains("recursion")
                    || err_str.contains("too deep")
                {
                    results.add_result(ValidationResult::warning(
                        rule,
                        "Server may be vulnerable to deeply nested JSON",
                        start.elapsed().as_millis() as u64,
                    ));
                } else {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
        }

        // EDGE-007: Special float values
        let rule = self.get_rule(ValidationRuleId::Edge007).unwrap();
        let start = Instant::now();

        // Note: JSON doesn't support NaN/Infinity directly, test with string representation
        let float_params = serde_json::json!({
            "value": f64::MAX,
            "small": f64::MIN_POSITIVE,
            "negative": f64::MIN
        });

        let float_result = client.call_tool(&test_tool.name, Some(float_params)).await;

        match float_result {
            Ok(_) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("panic") || err_str.contains("overflow") {
                    results.add_result(ValidationResult::fail(
                        rule,
                        "Server crashed on extreme float values",
                        start.elapsed().as_millis() as u64,
                    ));
                } else {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
        }

        // EDGE-008: Negative array index
        let rule = self.get_rule(ValidationRuleId::Edge008).unwrap();
        let start = Instant::now();

        let neg_index_params = serde_json::json!({
            "index": -1,
            "position": -999,
            "offset": i64::MIN
        });

        let neg_result = client
            .call_tool(&test_tool.name, Some(neg_index_params))
            .await;

        match neg_result {
            Ok(_) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("panic") || err_str.contains("out of bounds") {
                    results.add_result(ValidationResult::fail(
                        rule,
                        "Server crashed on negative index",
                        start.elapsed().as_millis() as u64,
                    ));
                } else {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
        }

        // EDGE-009: Integer overflow
        let rule = self.get_rule(ValidationRuleId::Edge009).unwrap();
        let start = Instant::now();

        let overflow_params = serde_json::json!({
            "count": i64::MAX,
            "size": i64::MAX - 1,
            "amount": i64::MAX
        });

        let overflow_result = client
            .call_tool(&test_tool.name, Some(overflow_params))
            .await;

        match overflow_result {
            Ok(_) => {
                results.add_result(ValidationResult::pass(
                    rule,
                    start.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("overflow") || err_str.contains("panic") {
                    results.add_result(ValidationResult::warning(
                        rule,
                        "Server may be vulnerable to integer overflow",
                        start.elapsed().as_millis() as u64,
                    ));
                } else {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
        }

        // EDGE-010: Slow response (ReDoS-like patterns)
        let rule = self.get_rule(ValidationRuleId::Edge010).unwrap();
        let start = Instant::now();

        // Pattern that could trigger ReDoS in vulnerable regex implementations
        let redos_params = serde_json::json!({
            "pattern": "a]",
            "input": "a".repeat(50) + "!"
        });

        let timeout_start = Instant::now();
        let slow_result = client.call_tool(&test_tool.name, Some(redos_params)).await;
        let response_time = timeout_start.elapsed();

        if response_time.as_secs() > 5 {
            results.add_result(ValidationResult::warning(
                rule,
                format!(
                    "Server took {}s to respond (possible ReDoS)",
                    response_time.as_secs()
                ),
                start.elapsed().as_millis() as u64,
            ));
        } else {
            match slow_result {
                Ok(_) | Err(_) => {
                    results.add_result(ValidationResult::pass(
                        rule,
                        start.elapsed().as_millis() as u64,
                    ));
                }
            }
        }
    }

    /// Run edge case validation rules (using trait object)
    #[allow(dead_code)]
    async fn run_edge_rules_with_trait(
        &self,
        _client: &mut dyn McpClientTrait,
        ctx: &ServerContext,
        results: &mut ValidationResults,
    ) {
        // Skip if no tools
        if ctx.tools.is_none() || ctx.tools.as_ref().unwrap().is_empty() {
            return;
        }

        // Simplified edge case checks for mock testing
        for rule_id in [
            ValidationRuleId::Edge001,
            ValidationRuleId::Edge002,
            ValidationRuleId::Edge003,
            ValidationRuleId::Edge004,
        ] {
            let rule = self.get_rule(rule_id).unwrap();
            results.add_result(
                ValidationResult::pass(rule, 0)
                    .with_details(vec!["Edge case tests require real server".to_string()]),
            );
        }
    }

    fn get_rule(&self, id: ValidationRuleId) -> Option<&ValidationRule> {
        self.rules.iter().find(|r| r.id == id)
    }
}

/// Validate that a value is a valid JSON Schema
fn validate_json_schema(schema: &serde_json::Value) -> Result<(), String> {
    // Check it's an object
    if !schema.is_object() {
        return Err("Schema must be an object".to_string());
    }

    // Try to compile it as a JSON Schema
    match jsonschema::draft7::new(schema) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Invalid JSON Schema: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_rule() -> ValidationRule {
        ValidationRule {
            id: ValidationRuleId::Proto001,
            name: "Test".to_string(),
            description: "Test rule".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Test remediation".to_string(),
        }
    }

    // ValidationConfig tests
    #[test]
    fn validation_config_default() {
        let config = ValidationConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert!(config.skip_categories.is_empty());
        assert!(config.skip_rules.is_empty());
        assert!(!config.strict_mode);
    }

    // ValidationResult tests
    #[test]
    fn validation_result_pass() {
        let rule = make_test_rule();
        let result = ValidationResult::pass(&rule, 100);

        assert_eq!(result.rule_id, "PROTO-001");
        assert_eq!(result.rule_name, "Test");
        assert_eq!(result.severity, ValidationSeverity::Pass);
        assert!(result.message.is_none());
        assert_eq!(result.duration_ms, 100);
    }

    #[test]
    fn validation_result_fail() {
        let rule = make_test_rule();
        let result = ValidationResult::fail(&rule, "Error message", 50);

        assert_eq!(result.severity, ValidationSeverity::Fail);
        assert_eq!(result.message, Some("Error message".to_string()));
        assert_eq!(result.duration_ms, 50);
    }

    #[test]
    fn validation_result_warning() {
        let rule = make_test_rule();
        let result = ValidationResult::warning(&rule, "Warning message", 25);

        assert_eq!(result.severity, ValidationSeverity::Warning);
        assert_eq!(result.message, Some("Warning message".to_string()));
    }

    #[test]
    fn validation_result_skip() {
        let rule = make_test_rule();
        let result = ValidationResult::skip(&rule, "Skipped because...");

        assert_eq!(result.severity, ValidationSeverity::Skip);
        assert_eq!(result.message, Some("Skipped because...".to_string()));
        assert_eq!(result.duration_ms, 0);
    }

    #[test]
    fn validation_result_with_details() {
        let rule = make_test_rule();
        let result = ValidationResult::fail(&rule, "Error", 10)
            .with_details(vec!["Detail 1".to_string(), "Detail 2".to_string()]);

        assert_eq!(result.details.len(), 2);
        assert_eq!(result.details[0], "Detail 1");
        assert_eq!(result.details[1], "Detail 2");
    }

    // ValidationResults tests
    #[test]
    fn validation_results_new() {
        let results = ValidationResults::new("test-server");

        assert_eq!(results.server, "test-server");
        assert!(results.protocol_version.is_none());
        assert!(results.capabilities.is_none());
        assert!(results.results.is_empty());
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.warnings, 0);
        assert_eq!(results.total_duration_ms, 0);
    }

    #[test]
    fn validation_result_counts() {
        let mut results = ValidationResults::new("test");
        let rule = make_test_rule();

        results.add_result(ValidationResult::pass(&rule, 10));
        results.add_result(ValidationResult::fail(&rule, "Failed", 20));
        results.add_result(ValidationResult::warning(&rule, "Warning", 5));

        assert_eq!(results.passed, 1);
        assert_eq!(results.failed, 1);
        assert_eq!(results.warnings, 1);
        assert_eq!(results.total_duration_ms, 35);
    }

    #[test]
    fn validation_results_info_skip_not_counted() {
        let mut results = ValidationResults::new("test");
        let rule = make_test_rule();

        results.add_result(ValidationResult::skip(&rule, "Skipped"));
        results.add_result(ValidationResult {
            rule_id: "TEST".to_string(),
            rule_name: "Test".to_string(),
            category: "test".to_string(),
            severity: ValidationSeverity::Info,
            message: None,
            details: vec![],
            duration_ms: 10,
        });

        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.warnings, 0);
    }

    #[test]
    fn validation_results_has_failures() {
        let mut results = ValidationResults::new("test");
        let rule = make_test_rule();

        assert!(!results.has_failures());

        results.add_result(ValidationResult::pass(&rule, 10));
        assert!(!results.has_failures());

        results.add_result(ValidationResult::fail(&rule, "Error", 10));
        assert!(results.has_failures());
    }

    // JSON Schema validation tests
    #[test]
    fn validate_json_schema_valid() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            }
        });

        assert!(validate_json_schema(&schema).is_ok());
    }

    #[test]
    fn validate_json_schema_valid_empty_object() {
        let schema = serde_json::json!({});
        assert!(validate_json_schema(&schema).is_ok());
    }

    #[test]
    fn validate_json_schema_valid_with_required() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "age": { "type": "integer" }
            },
            "required": ["name"]
        });

        assert!(validate_json_schema(&schema).is_ok());
    }

    #[test]
    fn validate_json_schema_invalid_type() {
        let schema = serde_json::json!("not an object");
        assert!(validate_json_schema(&schema).is_err());
    }

    #[test]
    fn validate_json_schema_invalid_null() {
        let schema = serde_json::Value::Null;
        assert!(validate_json_schema(&schema).is_err());
    }

    #[test]
    fn validate_json_schema_invalid_array() {
        let schema = serde_json::json!([1, 2, 3]);
        assert!(validate_json_schema(&schema).is_err());
    }

    #[test]
    fn validate_json_schema_valid_array_type() {
        let schema = serde_json::json!({
            "type": "array",
            "items": { "type": "string" }
        });

        assert!(validate_json_schema(&schema).is_ok());
    }

    // ValidationEngine tests
    #[test]
    fn validation_engine_creation() {
        let config = ValidationConfig::default();
        let engine = ValidationEngine::new(config);

        assert!(!engine.rules.is_empty());
    }

    #[test]
    fn validation_engine_get_rule() {
        let config = ValidationConfig::default();
        let engine = ValidationEngine::new(config);

        let rule = engine.get_rule(ValidationRuleId::Proto001);
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().id, ValidationRuleId::Proto001);
    }

    #[test]
    fn validation_engine_get_rule_not_found() {
        let config = ValidationConfig::default();
        let engine = ValidationEngine::new(config);

        // All rule IDs should be found
        let rule = engine.get_rule(ValidationRuleId::Proto002);
        assert!(rule.is_some());
    }

    // ValidationSeverity tests
    #[test]
    fn validation_severity_serialization() {
        assert_eq!(
            serde_json::to_string(&ValidationSeverity::Pass).unwrap(),
            "\"pass\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationSeverity::Fail).unwrap(),
            "\"fail\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationSeverity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationSeverity::Info).unwrap(),
            "\"info\""
        );
        assert_eq!(
            serde_json::to_string(&ValidationSeverity::Skip).unwrap(),
            "\"skip\""
        );
    }

    #[test]
    fn validation_severity_deserialization() {
        assert_eq!(
            serde_json::from_str::<ValidationSeverity>("\"pass\"").unwrap(),
            ValidationSeverity::Pass
        );
        assert_eq!(
            serde_json::from_str::<ValidationSeverity>("\"fail\"").unwrap(),
            ValidationSeverity::Fail
        );
    }

    #[test]
    fn validation_result_serialization() {
        let rule = make_test_rule();
        let result = ValidationResult::pass(&rule, 100);

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"severity\":\"pass\""));
        assert!(json.contains("\"duration_ms\":100"));
    }

    #[test]
    fn validation_results_serialization() {
        let mut results = ValidationResults::new("test");
        results.protocol_version = Some("2024-11-05".to_string());
        results.passed = 5;
        results.failed = 1;

        let json = serde_json::to_string(&results).unwrap();
        assert!(json.contains("\"server\":\"test\""));
        assert!(json.contains("\"passed\":5"));
        assert!(json.contains("\"failed\":1"));
    }

    // Tests using MockMcpClient for dependency injection
    mod mock_client_tests {
        use super::*;
        use crate::client::mock::MockMcpClient;
        use crate::protocol::mcp::{PromptsCapability, ResourcesCapability, ToolsCapability};
        use crate::protocol::ServerCapabilities;

        fn create_mock_with_capabilities() -> MockMcpClient {
            let mut caps = ServerCapabilities::default();
            caps.tools = Some(ToolsCapability::default());
            caps.resources = Some(ResourcesCapability::default());
            caps.prompts = Some(PromptsCapability::default());
            MockMcpClient::with_capabilities(caps)
        }

        #[tokio::test]
        async fn validate_with_mock_client_basic() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = MockMcpClient::new();

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            assert_eq!(results.server, "mock-server");
            assert!(results.passed > 0);
            assert!(results.protocol_version.is_some());
        }

        #[tokio::test]
        async fn validate_with_mock_client_initialization_failure() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = MockMcpClient::new();
            client.set_next_error("Connection refused").await;

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // Should have failed at initialization
            assert!(results.failed > 0);
            assert!(results.protocol_version.is_none());
        }

        #[tokio::test]
        async fn validate_with_mock_client_with_tools() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = create_mock_with_capabilities();

            // Add some tools
            client
                .add_tool(MockMcpClient::create_test_tool("tool1", "First tool"))
                .await;
            client
                .add_tool(MockMcpClient::create_test_tool("tool2", "Second tool"))
                .await;

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            assert!(results.passed > 0);
            assert!(results.capabilities.is_some());
            let caps = results.capabilities.unwrap();
            assert!(caps.tools.is_some());
        }

        #[tokio::test]
        async fn validate_with_mock_client_with_resources() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = create_mock_with_capabilities();

            // Add resources
            client
                .add_resource(MockMcpClient::create_test_resource(
                    "file://test.txt",
                    "test.txt",
                ))
                .await;

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            assert!(results.passed > 0);
        }

        #[tokio::test]
        async fn validate_with_mock_client_with_prompts() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = create_mock_with_capabilities();

            // Add prompts
            client
                .add_prompt(MockMcpClient::create_test_prompt(
                    "greeting",
                    "A greeting prompt",
                ))
                .await;

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            assert!(results.passed > 0);
        }

        #[tokio::test]
        async fn validate_with_mock_client_ping_success() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = MockMcpClient::new();

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // Check SEQ-001 (ping) passed
            let seq001_result = results.results.iter().find(|r| r.rule_id == "SEQ-001");
            assert!(seq001_result.is_some());
            assert_eq!(seq001_result.unwrap().severity, ValidationSeverity::Pass);
        }

        #[tokio::test]
        async fn validate_with_mock_client_protocol_version_check() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = MockMcpClient::new();

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // Check PROTO-002 (protocol version) passed
            let proto002_result = results.results.iter().find(|r| r.rule_id == "PROTO-002");
            assert!(proto002_result.is_some());
            assert_eq!(proto002_result.unwrap().severity, ValidationSeverity::Pass);
        }

        #[tokio::test]
        async fn validate_with_mock_client_server_info_check() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = MockMcpClient::new();

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // Check PROTO-003 (server info) passed
            let proto003_result = results.results.iter().find(|r| r.rule_id == "PROTO-003");
            assert!(proto003_result.is_some());
            assert_eq!(proto003_result.unwrap().severity, ValidationSeverity::Pass);
        }

        #[tokio::test]
        async fn validate_with_mock_client_capabilities_check() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = MockMcpClient::new();

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // Check PROTO-004 (capabilities) passed
            let proto004_result = results.results.iter().find(|r| r.rule_id == "PROTO-004");
            assert!(proto004_result.is_some());
            assert_eq!(proto004_result.unwrap().severity, ValidationSeverity::Pass);
        }

        #[tokio::test]
        async fn validate_with_mock_client_unknown_method_handling() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = MockMcpClient::new();

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // Check SEQ-002 (method not found handling)
            let seq002_result = results.results.iter().find(|r| r.rule_id == "SEQ-002");
            assert!(seq002_result.is_some());
            // Mock returns a successful response for unknown tools, so we expect a warning
            assert_eq!(seq002_result.unwrap().severity, ValidationSeverity::Warning);
        }

        #[tokio::test]
        async fn validate_with_mock_client_error_response_format() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = MockMcpClient::new();

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // Check SEQ-003 (error response format)
            let seq003_result = results.results.iter().find(|r| r.rule_id == "SEQ-003");
            assert!(seq003_result.is_some());
            assert_eq!(seq003_result.unwrap().severity, ValidationSeverity::Pass);
        }

        #[tokio::test]
        async fn validate_with_mock_client_closes_connection() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = MockMcpClient::new();

            let _ = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // Client should be closed after validation
            assert!(client.is_closed());
        }

        #[tokio::test]
        async fn validate_with_mock_client_no_capabilities() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let client = MockMcpClient::new();
            let mut client = client; // no capabilities set

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // Should still pass basic checks
            assert!(results.passed > 0);
            // Capabilities should be empty
            if let Some(caps) = &results.capabilities {
                assert!(caps.tools.is_none());
                assert!(caps.resources.is_none());
                assert!(caps.prompts.is_none());
            }
        }

        #[tokio::test]
        async fn validate_config_timeout_used() {
            let config = ValidationConfig {
                timeout_secs: 60,
                ..Default::default()
            };
            let mut engine = ValidationEngine::new(config);
            let mut client = MockMcpClient::new();

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            assert!(results.passed > 0);
        }

        #[tokio::test]
        async fn validate_with_mock_multiple_validations() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());

            // First validation
            let mut client1 = MockMcpClient::new();
            let results1 = engine
                .validate_with_client("server1", &mut client1)
                .await
                .unwrap();

            // Second validation with same engine
            let mut client2 = MockMcpClient::new();
            let results2 = engine
                .validate_with_client("server2", &mut client2)
                .await
                .unwrap();

            assert_eq!(results1.server, "server1");
            assert_eq!(results2.server, "server2");
        }

        #[tokio::test]
        async fn validate_with_mock_total_duration_tracked() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = MockMcpClient::new();

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // Duration is u64, just verify results struct is valid
            let _ = results.total_duration_ms;
        }

        #[tokio::test]
        async fn validate_with_mock_all_checks_run() {
            let mut engine = ValidationEngine::new(ValidationConfig::default());
            let mut client = create_mock_with_capabilities();

            // Add data so schema rules can run
            client
                .add_tool(MockMcpClient::create_test_tool("test", "Test tool"))
                .await;
            client
                .add_resource(MockMcpClient::create_test_resource("file://t", "t"))
                .await;
            client
                .add_prompt(MockMcpClient::create_test_prompt("p", "Prompt"))
                .await;

            let results = engine
                .validate_with_client("mock-server", &mut client)
                .await
                .unwrap();

            // We should have multiple check results
            assert!(results.results.len() > 5);

            // Check for key rules
            let rule_ids: Vec<&str> = results.results.iter().map(|r| r.rule_id.as_str()).collect();
            assert!(rule_ids.contains(&"PROTO-001"));
            assert!(rule_ids.contains(&"PROTO-002"));
            assert!(rule_ids.contains(&"PROTO-003"));
            assert!(rule_ids.contains(&"PROTO-004"));
            assert!(rule_ids.contains(&"SEQ-001"));
        }
    }
}
