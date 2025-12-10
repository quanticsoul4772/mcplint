//! Validation Rules - Protocol compliance rule definitions
//!
//! Defines all validation rules for MCP protocol compliance checking.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Validation rule identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidationRuleId {
    // Protocol rules (PROTO-001 to PROTO-010)
    #[serde(rename = "PROTO-001")]
    Proto001,
    #[serde(rename = "PROTO-002")]
    Proto002,
    #[serde(rename = "PROTO-003")]
    Proto003,
    #[serde(rename = "PROTO-004")]
    Proto004,
    #[serde(rename = "PROTO-005")]
    Proto005,
    #[serde(rename = "PROTO-006")]
    Proto006,
    #[serde(rename = "PROTO-007")]
    Proto007,
    #[serde(rename = "PROTO-008")]
    Proto008,
    #[serde(rename = "PROTO-009")]
    Proto009,
    #[serde(rename = "PROTO-010")]
    Proto010,

    // Schema rules (SCHEMA-001 to SCHEMA-005)
    #[serde(rename = "SCHEMA-001")]
    Schema001,
    #[serde(rename = "SCHEMA-002")]
    Schema002,
    #[serde(rename = "SCHEMA-003")]
    Schema003,
    #[serde(rename = "SCHEMA-004")]
    Schema004,
    #[serde(rename = "SCHEMA-005")]
    Schema005,

    // Sequence rules (SEQ-001 to SEQ-003)
    #[serde(rename = "SEQ-001")]
    Seq001,
    #[serde(rename = "SEQ-002")]
    Seq002,
    #[serde(rename = "SEQ-003")]
    Seq003,

    // Tool invocation rules (TOOL-001 to TOOL-005)
    #[serde(rename = "TOOL-001")]
    Tool001,
    #[serde(rename = "TOOL-002")]
    Tool002,
    #[serde(rename = "TOOL-003")]
    Tool003,
    #[serde(rename = "TOOL-004")]
    Tool004,
    #[serde(rename = "TOOL-005")]
    Tool005,

    // Resource rules (RES-001 to RES-003)
    #[serde(rename = "RES-001")]
    Res001,
    #[serde(rename = "RES-002")]
    Res002,
    #[serde(rename = "RES-003")]
    Res003,

    // Security rules (SEC-001 to SEC-004)
    #[serde(rename = "SEC-001")]
    Sec001,
    #[serde(rename = "SEC-002")]
    Sec002,
    #[serde(rename = "SEC-003")]
    Sec003,
    #[serde(rename = "SEC-004")]
    Sec004,

    // Edge case rules (EDGE-001 to EDGE-010)
    #[serde(rename = "EDGE-001")]
    Edge001,
    #[serde(rename = "EDGE-002")]
    Edge002,
    #[serde(rename = "EDGE-003")]
    Edge003,
    #[serde(rename = "EDGE-004")]
    Edge004,
    #[serde(rename = "EDGE-005")]
    Edge005,
    #[serde(rename = "EDGE-006")]
    Edge006,
    #[serde(rename = "EDGE-007")]
    Edge007,
    #[serde(rename = "EDGE-008")]
    Edge008,
    #[serde(rename = "EDGE-009")]
    Edge009,
    #[serde(rename = "EDGE-010")]
    Edge010,

    // Security rules (SEC-005 to SEC-010)
    #[serde(rename = "SEC-005")]
    Sec005,
    #[serde(rename = "SEC-006")]
    Sec006,
    #[serde(rename = "SEC-007")]
    Sec007,
    #[serde(rename = "SEC-008")]
    Sec008,
    #[serde(rename = "SEC-009")]
    Sec009,
    #[serde(rename = "SEC-010")]
    Sec010,

    // New security rules (SEC-011 to SEC-015)
    #[serde(rename = "SEC-011")]
    Sec011,
    #[serde(rename = "SEC-012")]
    Sec012,
    #[serde(rename = "SEC-013")]
    Sec013,
    #[serde(rename = "SEC-014")]
    Sec014,
    #[serde(rename = "SEC-015")]
    Sec015,

    // Protocol rules (PROTO-011 to PROTO-015)
    #[serde(rename = "PROTO-011")]
    Proto011,
    #[serde(rename = "PROTO-012")]
    Proto012,
    #[serde(rename = "PROTO-013")]
    Proto013,
    #[serde(rename = "PROTO-014")]
    Proto014,
    #[serde(rename = "PROTO-015")]
    Proto015,
}

impl fmt::Display for ValidationRuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationRuleId::Proto001 => write!(f, "PROTO-001"),
            ValidationRuleId::Proto002 => write!(f, "PROTO-002"),
            ValidationRuleId::Proto003 => write!(f, "PROTO-003"),
            ValidationRuleId::Proto004 => write!(f, "PROTO-004"),
            ValidationRuleId::Proto005 => write!(f, "PROTO-005"),
            ValidationRuleId::Proto006 => write!(f, "PROTO-006"),
            ValidationRuleId::Proto007 => write!(f, "PROTO-007"),
            ValidationRuleId::Proto008 => write!(f, "PROTO-008"),
            ValidationRuleId::Proto009 => write!(f, "PROTO-009"),
            ValidationRuleId::Proto010 => write!(f, "PROTO-010"),
            ValidationRuleId::Schema001 => write!(f, "SCHEMA-001"),
            ValidationRuleId::Schema002 => write!(f, "SCHEMA-002"),
            ValidationRuleId::Schema003 => write!(f, "SCHEMA-003"),
            ValidationRuleId::Schema004 => write!(f, "SCHEMA-004"),
            ValidationRuleId::Schema005 => write!(f, "SCHEMA-005"),
            ValidationRuleId::Seq001 => write!(f, "SEQ-001"),
            ValidationRuleId::Seq002 => write!(f, "SEQ-002"),
            ValidationRuleId::Seq003 => write!(f, "SEQ-003"),
            ValidationRuleId::Tool001 => write!(f, "TOOL-001"),
            ValidationRuleId::Tool002 => write!(f, "TOOL-002"),
            ValidationRuleId::Tool003 => write!(f, "TOOL-003"),
            ValidationRuleId::Tool004 => write!(f, "TOOL-004"),
            ValidationRuleId::Tool005 => write!(f, "TOOL-005"),
            ValidationRuleId::Res001 => write!(f, "RES-001"),
            ValidationRuleId::Res002 => write!(f, "RES-002"),
            ValidationRuleId::Res003 => write!(f, "RES-003"),
            ValidationRuleId::Sec001 => write!(f, "SEC-001"),
            ValidationRuleId::Sec002 => write!(f, "SEC-002"),
            ValidationRuleId::Sec003 => write!(f, "SEC-003"),
            ValidationRuleId::Sec004 => write!(f, "SEC-004"),
            ValidationRuleId::Edge001 => write!(f, "EDGE-001"),
            ValidationRuleId::Edge002 => write!(f, "EDGE-002"),
            ValidationRuleId::Edge003 => write!(f, "EDGE-003"),
            ValidationRuleId::Edge004 => write!(f, "EDGE-004"),
            ValidationRuleId::Edge005 => write!(f, "EDGE-005"),
            ValidationRuleId::Edge006 => write!(f, "EDGE-006"),
            ValidationRuleId::Edge007 => write!(f, "EDGE-007"),
            ValidationRuleId::Edge008 => write!(f, "EDGE-008"),
            ValidationRuleId::Edge009 => write!(f, "EDGE-009"),
            ValidationRuleId::Edge010 => write!(f, "EDGE-010"),
            ValidationRuleId::Sec005 => write!(f, "SEC-005"),
            ValidationRuleId::Sec006 => write!(f, "SEC-006"),
            ValidationRuleId::Sec007 => write!(f, "SEC-007"),
            ValidationRuleId::Sec008 => write!(f, "SEC-008"),
            ValidationRuleId::Sec009 => write!(f, "SEC-009"),
            ValidationRuleId::Sec010 => write!(f, "SEC-010"),
            ValidationRuleId::Sec011 => write!(f, "SEC-011"),
            ValidationRuleId::Sec012 => write!(f, "SEC-012"),
            ValidationRuleId::Sec013 => write!(f, "SEC-013"),
            ValidationRuleId::Sec014 => write!(f, "SEC-014"),
            ValidationRuleId::Sec015 => write!(f, "SEC-015"),
            ValidationRuleId::Proto011 => write!(f, "PROTO-011"),
            ValidationRuleId::Proto012 => write!(f, "PROTO-012"),
            ValidationRuleId::Proto013 => write!(f, "PROTO-013"),
            ValidationRuleId::Proto014 => write!(f, "PROTO-014"),
            ValidationRuleId::Proto015 => write!(f, "PROTO-015"),
        }
    }
}

/// Validation rule category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationCategory {
    /// Protocol compliance rules
    Protocol,
    /// JSON Schema validation rules
    Schema,
    /// Message sequence rules
    Sequence,
    /// Tool invocation rules
    Tool,
    /// Resource access rules
    Resource,
    /// Security testing rules
    Security,
    /// Edge case handling rules
    Edge,
}

impl fmt::Display for ValidationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationCategory::Protocol => write!(f, "protocol"),
            ValidationCategory::Schema => write!(f, "schema"),
            ValidationCategory::Sequence => write!(f, "sequence"),
            ValidationCategory::Tool => write!(f, "tool"),
            ValidationCategory::Resource => write!(f, "resource"),
            ValidationCategory::Security => write!(f, "security"),
            ValidationCategory::Edge => write!(f, "edge"),
        }
    }
}

/// A validation rule definition
#[derive(Debug, Clone)]
pub struct ValidationRule {
    pub id: ValidationRuleId,
    pub name: String,
    #[allow(dead_code)] // Used for documentation/reporting
    pub description: String,
    pub category: ValidationCategory,
    /// How to fix issues found by this rule
    pub remediation: String,
}

/// Get all validation rules
pub fn get_all_rules() -> Vec<ValidationRule> {
    vec![
        // Protocol rules
        ValidationRule {
            id: ValidationRuleId::Proto001,
            name: "JSON-RPC 2.0 Compliance".to_string(),
            description: "Server must respond with valid JSON-RPC 2.0 messages".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Ensure server returns {\"jsonrpc\": \"2.0\", \"id\": ..., \"result\": ...} for all responses".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto002,
            name: "Valid Protocol Version".to_string(),
            description: "Server must return a supported MCP protocol version".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Return protocolVersion: \"2024-11-05\" or \"2025-03-26\" in initialize response".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto003,
            name: "Valid Server Info".to_string(),
            description: "Server must provide valid name and version in serverInfo".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Include serverInfo: {name: \"your-server\", version: \"1.0.0\"} in initialize response".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto004,
            name: "Valid Capabilities Object".to_string(),
            description: "Server capabilities must be a valid object".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Return capabilities as an object with tools/resources/prompts as needed".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto005,
            name: "Valid Tool Definitions".to_string(),
            description: "All tools must have valid name and inputSchema".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Each tool needs: {name: \"tool-name\", inputSchema: {type: \"object\", properties: {...}}}".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto006,
            name: "Valid Resource Definitions".to_string(),
            description: "All resources must have valid URI and name".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Each resource needs: {uri: \"file:///path\", name: \"resource-name\"}".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto007,
            name: "Valid Prompt Definitions".to_string(),
            description: "All prompts must have valid name".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Each prompt needs: {name: \"prompt-name\", description: \"...\"}".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto008,
            name: "Capabilities Consistency".to_string(),
            description: "Advertised capabilities must match actual functionality".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Only advertise capabilities (tools/resources/prompts) that your server actually implements".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto009,
            name: "Error Code Compliance".to_string(),
            description: "Errors must use standard JSON-RPC error codes".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Use standard codes: -32700 (parse error), -32600 (invalid request), -32601 (method not found), -32602 (invalid params), -32603 (internal error)".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto010,
            name: "Content Type Handling".to_string(),
            description: "Server must handle content types correctly".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Use correct mimeType for content: text/plain, application/json, etc.".to_string(),
        },
        // Schema rules
        ValidationRule {
            id: ValidationRuleId::Schema001,
            name: "Valid JSON Schema".to_string(),
            description: "Tool inputSchema must be valid JSON Schema".to_string(),
            category: ValidationCategory::Schema,
            remediation: "Ensure inputSchema is valid JSON Schema draft-07. Use https://json-schema.org to validate".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Schema002,
            name: "Schema Type Field".to_string(),
            description: "Schema should include a type field".to_string(),
            category: ValidationCategory::Schema,
            remediation: "Add \"type\": \"object\" to your inputSchema".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Schema003,
            name: "Object Properties".to_string(),
            description: "Object schemas should define properties".to_string(),
            category: ValidationCategory::Schema,
            remediation: "Add \"properties\": {...} defining each parameter for object-type schemas".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Schema004,
            name: "Required Array Valid".to_string(),
            description: "Required fields must exist in properties".to_string(),
            category: ValidationCategory::Schema,
            remediation: "Ensure all fields listed in \"required\": [...] are defined in \"properties\"".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Schema005,
            name: "Description Fields".to_string(),
            description: "Tools should include descriptions for clarity".to_string(),
            category: ValidationCategory::Schema,
            remediation: "Add description field to tools and their parameters for better discoverability".to_string(),
        },
        // Sequence rules
        ValidationRule {
            id: ValidationRuleId::Seq001,
            name: "Ping Response".to_string(),
            description: "Server must respond to ping requests".to_string(),
            category: ValidationCategory::Sequence,
            remediation: "Implement handler for \"ping\" method that returns an empty result {}".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Seq002,
            name: "Unknown Method Handling".to_string(),
            description: "Server must return JSON-RPC error -32601 for unknown tools".to_string(),
            category: ValidationCategory::Sequence,
            remediation: "Return {\"error\": {\"code\": -32601, \"message\": \"Method not found\"}} for unknown tool calls, not a success response".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Seq003,
            name: "Error Response Format".to_string(),
            description: "Error responses must follow JSON-RPC format".to_string(),
            category: ValidationCategory::Sequence,
            remediation: "Return errors as {\"jsonrpc\": \"2.0\", \"id\": N, \"error\": {\"code\": -32XXX, \"message\": \"...\"}}".to_string(),
        },
        // Tool invocation rules
        ValidationRule {
            id: ValidationRuleId::Tool001,
            name: "Tool Call Valid Input".to_string(),
            description: "Tool call with valid input succeeds".to_string(),
            category: ValidationCategory::Tool,
            remediation: "Ensure tool handler processes valid input and returns content array".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Tool002,
            name: "Tool Missing Required Params".to_string(),
            description: "Tool must return JSON-RPC error for missing required parameters".to_string(),
            category: ValidationCategory::Tool,
            remediation: "Validate required params BEFORE execution. Return {\"error\": {\"code\": -32602, \"message\": \"Missing required parameter: X\"}}, NOT a success with error text".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Tool003,
            name: "Tool Invalid Param Types".to_string(),
            description: "Tool returns error for wrong parameter types".to_string(),
            category: ValidationCategory::Tool,
            remediation: "Validate parameter types against schema. Return error -32602 for type mismatches".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Tool004,
            name: "Tool Output Valid JSON".to_string(),
            description: "Tool output is valid JSON format".to_string(),
            category: ValidationCategory::Tool,
            remediation: "Return content as [{type: \"text\", text: \"...\"}] or [{type: \"resource\", ...}]".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Tool005,
            name: "Tool Null Input Handling".to_string(),
            description: "Tool handles null/empty input gracefully".to_string(),
            category: ValidationCategory::Tool,
            remediation: "Handle null/undefined params gracefully - return proper error, don't crash".to_string(),
        },
        // Resource rules
        ValidationRule {
            id: ValidationRuleId::Res001,
            name: "Resource Read Works".to_string(),
            description: "Resource read operation succeeds for listed resources".to_string(),
            category: ValidationCategory::Resource,
            remediation: "Ensure resources/read handler returns content for all listed resource URIs".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Res002,
            name: "Resource Invalid URI Error".to_string(),
            description: "Invalid resource URI returns proper error".to_string(),
            category: ValidationCategory::Resource,
            remediation: "Return error for non-existent resource URIs, not empty content".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Res003,
            name: "Resource Content Type".to_string(),
            description: "Resource content matches declared mimeType".to_string(),
            category: ValidationCategory::Resource,
            remediation: "Set correct mimeType: text/plain for text, application/json for JSON, etc.".to_string(),
        },
        // Security rules
        ValidationRule {
            id: ValidationRuleId::Sec001,
            name: "Path Traversal Protection".to_string(),
            description: "Server rejects path traversal attempts".to_string(),
            category: ValidationCategory::Security,
            remediation: "Validate and sanitize file paths. Block ../ and %2e%2e%2f sequences. Use path canonicalization".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec002,
            name: "Command Injection Protection".to_string(),
            description: "Server rejects command injection attempts".to_string(),
            category: ValidationCategory::Security,
            remediation: "Never pass user input directly to shell. Use parameterized commands or escape special characters".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec003,
            name: "Input Size Limits".to_string(),
            description: "Server enforces input size limits".to_string(),
            category: ValidationCategory::Security,
            remediation: "Set maximum input sizes. Reject requests over limit with appropriate error".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec004,
            name: "Error Message Safety".to_string(),
            description: "Error messages do not expose sensitive data".to_string(),
            category: ValidationCategory::Security,
            remediation: "Sanitize error messages. Never expose file paths, credentials, or internal details".to_string(),
        },
        // Edge case rules
        ValidationRule {
            id: ValidationRuleId::Edge001,
            name: "Empty Input Handling".to_string(),
            description: "Server handles empty string inputs gracefully".to_string(),
            category: ValidationCategory::Edge,
            remediation: "Check for empty/null inputs and return meaningful error, don't crash".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Edge002,
            name: "Large Input Handling".to_string(),
            description: "Server handles oversized inputs gracefully".to_string(),
            category: ValidationCategory::Edge,
            remediation: "Set input size limits and return error for oversized requests, don't hang or crash".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Edge003,
            name: "Unicode Handling".to_string(),
            description: "Server handles unicode and special characters correctly".to_string(),
            category: ValidationCategory::Edge,
            remediation: "Use UTF-8 encoding throughout. Test with emoji, CJK, RTL, and special characters".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Edge004,
            name: "Concurrent Request Handling".to_string(),
            description: "Server handles concurrent requests without corruption".to_string(),
            category: ValidationCategory::Edge,
            remediation: "Use proper async patterns. Avoid shared mutable state or protect with locks".to_string(),
        },
        // New edge case rules
        ValidationRule {
            id: ValidationRuleId::Edge005,
            name: "Null Byte Injection".to_string(),
            description: "Server handles null bytes in input without truncation or crash".to_string(),
            category: ValidationCategory::Edge,
            remediation: "Sanitize or reject input containing null bytes (\\x00)".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Edge006,
            name: "Deeply Nested JSON".to_string(),
            description: "Server handles deeply nested JSON without stack overflow".to_string(),
            category: ValidationCategory::Edge,
            remediation: "Set recursion limits when parsing JSON. Reject excessively nested structures".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Edge007,
            name: "Special Float Values".to_string(),
            description: "Server handles NaN, Infinity, -Infinity correctly".to_string(),
            category: ValidationCategory::Edge,
            remediation: "Validate numeric inputs. Handle or reject special float values explicitly".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Edge008,
            name: "Negative Array Index".to_string(),
            description: "Server rejects negative indices gracefully".to_string(),
            category: ValidationCategory::Edge,
            remediation: "Validate array indices are non-negative before use".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Edge009,
            name: "Integer Overflow".to_string(),
            description: "Server handles very large integers without overflow".to_string(),
            category: ValidationCategory::Edge,
            remediation: "Use BigInt or validate integer bounds before arithmetic operations".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Edge010,
            name: "Slow Response Handling".to_string(),
            description: "Server responds within reasonable time for complex inputs".to_string(),
            category: ValidationCategory::Edge,
            remediation: "Implement timeouts for operations. Set complexity limits on inputs".to_string(),
        },
        // New security rules
        ValidationRule {
            id: ValidationRuleId::Sec005,
            name: "SQL Injection Protection".to_string(),
            description: "Server rejects SQL injection attempts".to_string(),
            category: ValidationCategory::Security,
            remediation: "Use parameterized queries. Never concatenate user input into SQL strings".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec006,
            name: "SSRF Protection".to_string(),
            description: "Server blocks server-side request forgery attempts".to_string(),
            category: ValidationCategory::Security,
            remediation: "Validate and whitelist URLs. Block internal IPs (127.0.0.1, 10.x, 192.168.x, 169.254.x)".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec007,
            name: "Prototype Pollution Protection".to_string(),
            description: "Server rejects __proto__ and constructor manipulation".to_string(),
            category: ValidationCategory::Security,
            remediation: "Sanitize object keys. Reject __proto__, constructor, prototype in input".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec008,
            name: "Log Injection Protection".to_string(),
            description: "Server sanitizes newlines in logged input".to_string(),
            category: ValidationCategory::Security,
            remediation: "Escape or reject newlines (\\n, \\r) in user input before logging".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec009,
            name: "XXE Protection".to_string(),
            description: "Server rejects XML external entity injection".to_string(),
            category: ValidationCategory::Security,
            remediation: "Disable external entity processing. Use safe XML parsers".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec010,
            name: "Template Injection Protection".to_string(),
            description: "Server rejects template injection attempts".to_string(),
            category: ValidationCategory::Security,
            remediation: "Escape template delimiters. Never pass user input directly to template engines".to_string(),
        },
        // New security rules: Prompt injection, tool shadowing, rug pull
        ValidationRule {
            id: ValidationRuleId::Sec011,
            name: "Tool Description Sanitization".to_string(),
            description: "Tool descriptions must not contain hidden instructions or prompt injection attempts".to_string(),
            category: ValidationCategory::Security,
            remediation: "Review tool descriptions for hidden instructions. Remove any text that attempts to override LLM behavior".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec012,
            name: "Tool Shadowing Prevention".to_string(),
            description: "Tool names must not shadow or impersonate other tools".to_string(),
            category: ValidationCategory::Security,
            remediation: "Use unique tool names. Avoid names that could be confused with common tools like read_file, write_file, execute".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec013,
            name: "Rug Pull Detection".to_string(),
            description: "Tool definitions should not change unexpectedly after initial registration".to_string(),
            category: ValidationCategory::Security,
            remediation: "Implement tool definition caching. Alert on schema changes between sessions".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec014,
            name: "Sensitive Data Exposure".to_string(),
            description: "Server should not expose sensitive data in tool responses".to_string(),
            category: ValidationCategory::Security,
            remediation: "Sanitize tool outputs. Redact secrets, tokens, and credentials from responses".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Sec015,
            name: "URL Fetch Whitelisting".to_string(),
            description: "URL fetching tools should validate against whitelist".to_string(),
            category: ValidationCategory::Security,
            remediation: "Implement URL whitelisting. Restrict allowed domains for fetch operations".to_string(),
        },
        // New protocol rules
        ValidationRule {
            id: ValidationRuleId::Proto011,
            name: "Batch Request Support".to_string(),
            description: "Server should handle JSON-RPC batch requests correctly".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Implement batch request handling per JSON-RPC 2.0 spec. Return array of responses".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto012,
            name: "Notification Handling".to_string(),
            description: "Server must not respond to notification messages (no id field)".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Check for missing id field. Process notification silently without sending response".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto013,
            name: "Progress Reporting".to_string(),
            description: "Long-running operations should report progress".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Send progress notifications for operations taking more than a few seconds".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto014,
            name: "Tool Definition Immutability".to_string(),
            description: "Tool definitions should remain stable during a session".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Cache tool definitions. Do not modify tool schemas during active session".to_string(),
        },
        ValidationRule {
            id: ValidationRuleId::Proto015,
            name: "Cancellation Support".to_string(),
            description: "Server should support request cancellation".to_string(),
            category: ValidationCategory::Protocol,
            remediation: "Implement notifications/cancelled handler. Clean up resources on cancel".to_string(),
        },
    ]
}

/// Get rules by category
#[allow(dead_code)]
pub fn get_rules_by_category(category: ValidationCategory) -> Vec<ValidationRule> {
    get_all_rules()
        .into_iter()
        .filter(|r| r.category == category)
        .collect()
}

/// Get a rule by ID
#[allow(dead_code)]
pub fn get_rule_by_id(id: ValidationRuleId) -> Option<ValidationRule> {
    get_all_rules().into_iter().find(|r| r.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_rules_have_unique_ids() {
        let rules = get_all_rules();
        let mut ids: std::collections::HashSet<ValidationRuleId> = std::collections::HashSet::new();

        for rule in &rules {
            assert!(ids.insert(rule.id), "Duplicate rule ID: {:?}", rule.id);
        }
    }

    #[test]
    fn rule_id_display() {
        assert_eq!(ValidationRuleId::Proto001.to_string(), "PROTO-001");
        assert_eq!(ValidationRuleId::Schema001.to_string(), "SCHEMA-001");
        assert_eq!(ValidationRuleId::Seq001.to_string(), "SEQ-001");
    }

    #[test]
    fn category_display() {
        assert_eq!(ValidationCategory::Protocol.to_string(), "protocol");
        assert_eq!(ValidationCategory::Schema.to_string(), "schema");
        assert_eq!(ValidationCategory::Sequence.to_string(), "sequence");
    }

    #[test]
    fn get_protocol_rules() {
        let rules = get_rules_by_category(ValidationCategory::Protocol);
        assert!(!rules.is_empty());
        assert!(rules
            .iter()
            .all(|r| r.category == ValidationCategory::Protocol));
    }

    #[test]
    fn get_schema_rules() {
        let rules = get_rules_by_category(ValidationCategory::Schema);
        assert!(!rules.is_empty());
        assert!(rules
            .iter()
            .all(|r| r.category == ValidationCategory::Schema));
    }

    #[test]
    fn get_sequence_rules() {
        let rules = get_rules_by_category(ValidationCategory::Sequence);
        assert!(!rules.is_empty());
        assert!(rules
            .iter()
            .all(|r| r.category == ValidationCategory::Sequence));
    }
}
