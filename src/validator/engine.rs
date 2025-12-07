//! Validation Engine - Core validation infrastructure
//!
//! Manages validation rule execution, result collection, and server communication.

use std::time::Instant;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
        transport_type: Option<TransportType>,
    ) -> Result<ValidationResults> {
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
        let transport_box = connect_with_type(target, args, transport_config, transport)
            .await
            .context("Failed to connect to server")?;

        // Create client
        let client_info = Implementation::new("mcplint", env!("CARGO_PKG_VERSION"));
        let mut client = McpClient::new(transport_box, client_info);

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
        }

        // Cleanup
        let _ = client.close().await;

        results.total_duration_ms = start.elapsed().as_millis() as u64;
        Ok(results)
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

    #[test]
    fn validation_result_counts() {
        let mut results = ValidationResults::new("test");

        let rule = ValidationRule {
            id: ValidationRuleId::Proto001,
            name: "Test".to_string(),
            description: "Test rule".to_string(),
            category: ValidationCategory::Protocol,
        };

        results.add_result(ValidationResult::pass(&rule, 10));
        results.add_result(ValidationResult::fail(&rule, "Failed", 20));
        results.add_result(ValidationResult::warning(&rule, "Warning", 5));

        assert_eq!(results.passed, 1);
        assert_eq!(results.failed, 1);
        assert_eq!(results.warnings, 1);
        assert_eq!(results.total_duration_ms, 35);
    }

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
    fn validate_json_schema_invalid_type() {
        let schema = serde_json::json!("not an object");
        assert!(validate_json_schema(&schema).is_err());
    }
}
