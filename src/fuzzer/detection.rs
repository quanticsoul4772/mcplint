//! Crash Detection - Detect and classify crashes and hangs
//!
//! Analyzes responses from MCP servers to detect crashes,
//! hangs, and other interesting behaviors.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::corpus::{CrashType, InterestingReason};

/// Detects and classifies crashes/hangs/errors
pub struct CrashDetector {
    /// Timeout threshold in milliseconds
    timeout_ms: u64,
}

impl CrashDetector {
    /// Create a new crash detector
    pub fn new(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }

    /// Analyze a fuzz response for crash indicators
    pub fn analyze(&self, response: &FuzzResponse) -> CrashAnalysis {
        match &response.result {
            FuzzResponseResult::Success(value) => self.analyze_success(value),
            FuzzResponseResult::Error(e) => self.classify_error(e),
            FuzzResponseResult::Timeout => CrashAnalysis::Hang(HangInfo {
                timeout_ms: self.timeout_ms,
            }),
            FuzzResponseResult::ConnectionLost(reason) => CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::ConnectionDrop,
                message: reason.clone(),
                stack_trace: None,
            }),
            FuzzResponseResult::ProcessExit(code) => {
                let crash_type = match *code {
                    139 => CrashType::Segfault,         // SIGSEGV
                    134 => CrashType::AssertionFailure, // SIGABRT
                    137 => CrashType::OutOfMemory,      // SIGKILL (often OOM)
                    _ => {
                        if *code != 0 {
                            CrashType::Panic
                        } else {
                            return CrashAnalysis::None;
                        }
                    }
                };

                CrashAnalysis::Crash(CrashInfo {
                    crash_type,
                    message: format!("Process exited with code {}", code),
                    stack_trace: None,
                })
            }
        }
    }

    /// Analyze successful response for interesting patterns
    fn analyze_success(&self, value: &Value) -> CrashAnalysis {
        // Check for error-like content in success response
        if let Some(obj) = value.as_object() {
            // Some servers return errors in result field
            if obj.contains_key("error") || obj.contains_key("errorCode") {
                return CrashAnalysis::Interesting(InterestingReason::UnexpectedSuccess);
            }

            // Check for stack traces in result
            if let Some(s) = obj.get("message").and_then(|m| m.as_str()) {
                if s.contains("panic") || s.contains("stack backtrace") || s.contains("Error:") {
                    return CrashAnalysis::Interesting(InterestingReason::ProtocolViolation);
                }
            }
        }

        CrashAnalysis::None
    }

    /// Classify error response
    fn classify_error(&self, error: &JsonRpcError) -> CrashAnalysis {
        // Check for crash indicators in error message
        let message = &error.message;

        // Panic detection
        if message.contains("panic")
            || message.contains("panicked at")
            || message.contains("stack backtrace")
            || message.contains("thread 'main' panicked")
        {
            return CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::Panic,
                message: message.clone(),
                stack_trace: Self::extract_stack_trace(message),
            });
        }

        // Memory error detection
        if message.contains("out of memory")
            || message.contains("allocation")
            || message.contains("memory exhausted")
            || message.contains("OOM")
        {
            return CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::OutOfMemory,
                message: message.clone(),
                stack_trace: None,
            });
        }

        // Assertion failure detection
        if message.contains("assertion failed")
            || message.contains("assert!")
            || message.contains("debug_assert")
        {
            return CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::AssertionFailure,
                message: message.clone(),
                stack_trace: Self::extract_stack_trace(message),
            });
        }

        // Segfault detection
        if message.contains("SIGSEGV")
            || message.contains("segmentation fault")
            || message.contains("invalid memory")
            || message.contains("null pointer")
        {
            return CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::Segfault,
                message: message.clone(),
                stack_trace: Self::extract_stack_trace(message),
            });
        }

        // Check for interesting (non-crash) conditions
        match error.code {
            // Standard JSON-RPC errors
            -32700 => CrashAnalysis::Interesting(InterestingReason::ProtocolViolation), // Parse error
            -32600 => CrashAnalysis::Interesting(InterestingReason::ProtocolViolation), // Invalid request
            -32601 => CrashAnalysis::None, // Method not found (expected for fuzzing)
            -32602 => CrashAnalysis::None, // Invalid params (expected)
            -32603 => {
                // Internal error - might be interesting
                if message.len() > 100 {
                    // Verbose internal error might leak info
                    CrashAnalysis::Interesting(InterestingReason::ProtocolViolation)
                } else {
                    CrashAnalysis::None
                }
            }
            // Non-standard error codes are interesting
            code if !((-32099..=-32000).contains(&code) || (-32768..=-32600).contains(&code)) => {
                CrashAnalysis::Interesting(InterestingReason::NewErrorCode)
            }
            _ => CrashAnalysis::None,
        }
    }

    /// Extract stack trace from error message
    fn extract_stack_trace(message: &str) -> Option<String> {
        // Look for common stack trace patterns
        if let Some(idx) = message.find("stack backtrace:") {
            return Some(message[idx..].to_string());
        }
        if let Some(idx) = message.find("at ") {
            let remainder = &message[idx..];
            if remainder.contains(".rs:") {
                return Some(remainder.to_string());
            }
        }
        None
    }
}

/// Result of a fuzz request
#[derive(Debug, Clone)]
pub struct FuzzResponse {
    /// The result of the request
    pub result: FuzzResponseResult,
    /// Response time in milliseconds
    pub response_time_ms: u64,
}

impl FuzzResponse {
    /// Create a success response
    pub fn success(value: Value) -> Self {
        Self {
            result: FuzzResponseResult::Success(value),
            response_time_ms: 0,
        }
    }

    /// Create an error response
    pub fn error(code: i32, message: impl Into<String>) -> Self {
        Self {
            result: FuzzResponseResult::Error(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            response_time_ms: 0,
        }
    }

    /// Create a timeout response
    pub fn timeout() -> Self {
        Self {
            result: FuzzResponseResult::Timeout,
            response_time_ms: 0,
        }
    }

    /// Create a connection lost response
    pub fn connection_lost(reason: impl Into<String>) -> Self {
        Self {
            result: FuzzResponseResult::ConnectionLost(reason.into()),
            response_time_ms: 0,
        }
    }

    /// Create a process exit response
    pub fn process_exit(code: i32) -> Self {
        Self {
            result: FuzzResponseResult::ProcessExit(code),
            response_time_ms: 0,
        }
    }

    /// Set response time
    pub fn with_time(mut self, ms: u64) -> Self {
        self.response_time_ms = ms;
        self
    }

    /// Create from a JSON-RPC response
    pub fn from_jsonrpc(value: &Value) -> Self {
        if let Some(result) = value.get("result") {
            return Self::success(result.clone());
        }

        if let Some(error) = value.get("error") {
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-32603) as i32;
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error")
                .to_string();
            let data = error.get("data").cloned();

            return Self {
                result: FuzzResponseResult::Error(JsonRpcError {
                    code,
                    message,
                    data,
                }),
                response_time_ms: 0,
            };
        }

        Self::error(-32603, "Invalid JSON-RPC response")
    }
}

/// The result type of a fuzz response
#[derive(Debug, Clone)]
pub enum FuzzResponseResult {
    /// Successful response with result value
    Success(Value),
    /// Error response
    Error(JsonRpcError),
    /// Request timed out
    Timeout,
    /// Connection was lost
    ConnectionLost(String),
    /// Server process exited
    ProcessExit(i32),
}

/// JSON-RPC error structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Optional error data
    pub data: Option<Value>,
}

/// Analysis result from crash detector
#[derive(Debug, Clone)]
pub enum CrashAnalysis {
    /// No crash or interesting behavior
    None,
    /// Crash detected
    Crash(CrashInfo),
    /// Hang detected
    Hang(HangInfo),
    /// Interesting (non-crash) behavior
    Interesting(InterestingReason),
}

impl CrashAnalysis {
    /// Check if this is a crash
    pub fn is_crash(&self) -> bool {
        matches!(self, CrashAnalysis::Crash(_))
    }

    /// Check if this is a hang
    pub fn is_hang(&self) -> bool {
        matches!(self, CrashAnalysis::Hang(_))
    }

    /// Check if this is interesting
    pub fn is_interesting(&self) -> bool {
        matches!(self, CrashAnalysis::Interesting(_))
    }
}

/// Information about a detected crash
#[derive(Debug, Clone)]
pub struct CrashInfo {
    /// Type of crash
    pub crash_type: CrashType,
    /// Error message
    pub message: String,
    /// Stack trace if available
    pub stack_trace: Option<String>,
}

/// Information about a detected hang
#[derive(Debug, Clone)]
pub struct HangInfo {
    /// Timeout that was exceeded
    pub timeout_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_panic() {
        let detector = CrashDetector::new(5000);

        let response = FuzzResponse::error(-32603, "thread 'main' panicked at 'assertion failed'");

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::Panic,
                ..
            })
        ));
    }

    #[test]
    fn detect_oom() {
        let detector = CrashDetector::new(5000);

        let response = FuzzResponse::error(-32603, "out of memory: allocation failed");

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::OutOfMemory,
                ..
            })
        ));
    }

    #[test]
    fn detect_timeout() {
        let detector = CrashDetector::new(5000);

        let response = FuzzResponse::timeout();

        let analysis = detector.analyze(&response);
        assert!(matches!(analysis, CrashAnalysis::Hang(_)));
    }

    #[test]
    fn detect_process_exit() {
        let detector = CrashDetector::new(5000);

        let response = FuzzResponse::process_exit(139);

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::Segfault,
                ..
            })
        ));
    }

    #[test]
    fn normal_error_not_crash() {
        let detector = CrashDetector::new(5000);

        let response = FuzzResponse::error(-32601, "Method not found");

        let analysis = detector.analyze(&response);
        assert!(matches!(analysis, CrashAnalysis::None));
    }

    #[test]
    fn from_jsonrpc() {
        let success = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"data": "test"},
            "id": 1
        });

        let response = FuzzResponse::from_jsonrpc(&success);
        assert!(matches!(response.result, FuzzResponseResult::Success(_)));

        let error = serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": "Not found"},
            "id": 1
        });

        let response = FuzzResponse::from_jsonrpc(&error);
        assert!(matches!(response.result, FuzzResponseResult::Error(_)));
    }

    #[test]
    fn from_jsonrpc_invalid_response() {
        let invalid = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1
        });

        let response = FuzzResponse::from_jsonrpc(&invalid);
        assert!(matches!(response.result, FuzzResponseResult::Error(_)));
    }

    #[test]
    fn detect_assertion_failure() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::error(-32603, "assertion failed: x > 0");

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::AssertionFailure,
                ..
            })
        ));
    }

    #[test]
    fn detect_segfault() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::error(-32603, "SIGSEGV: segmentation fault");

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::Segfault,
                ..
            })
        ));
    }

    #[test]
    fn detect_null_pointer() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::error(-32603, "null pointer dereference");

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::Segfault,
                ..
            })
        ));
    }

    #[test]
    fn detect_connection_lost() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::connection_lost("connection reset by peer");

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::ConnectionDrop,
                ..
            })
        ));
    }

    #[test]
    fn detect_process_exit_abort() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::process_exit(134);

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::AssertionFailure,
                ..
            })
        ));
    }

    #[test]
    fn detect_process_exit_oom() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::process_exit(137);

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::OutOfMemory,
                ..
            })
        ));
    }

    #[test]
    fn detect_process_exit_success() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::process_exit(0);

        let analysis = detector.analyze(&response);
        assert!(matches!(analysis, CrashAnalysis::None));
    }

    #[test]
    fn detect_panic_with_stack_trace() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::error(
            -32603,
            "thread 'main' panicked at 'assertion failed'\nstack backtrace:\n  0: foo::bar\n",
        );

        let analysis = detector.analyze(&response);
        if let CrashAnalysis::Crash(info) = analysis {
            assert_eq!(info.crash_type, CrashType::Panic);
            assert!(info.stack_trace.is_some());
        } else {
            panic!("Expected Crash analysis");
        }
    }

    #[test]
    fn detect_interesting_parse_error() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::error(-32700, "Parse error");

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Interesting(InterestingReason::ProtocolViolation)
        ));
    }

    #[test]
    fn detect_interesting_invalid_request() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::error(-32600, "Invalid Request");

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Interesting(InterestingReason::ProtocolViolation)
        ));
    }

    #[test]
    fn detect_interesting_new_error_code() {
        let detector = CrashDetector::new(5000);
        // Non-standard error code
        let response = FuzzResponse::error(123, "Custom error");

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Interesting(InterestingReason::NewErrorCode)
        ));
    }

    #[test]
    fn detect_interesting_verbose_internal_error() {
        let detector = CrashDetector::new(5000);
        // Long internal error message might leak info
        let long_message = "Internal error: ".to_string() + &"x".repeat(100);
        let response = FuzzResponse::error(-32603, &long_message);

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Interesting(InterestingReason::ProtocolViolation)
        ));
    }

    #[test]
    fn analyze_success_with_error_content() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::success(serde_json::json!({
            "error": "Something went wrong",
            "errorCode": 500
        }));

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Interesting(InterestingReason::UnexpectedSuccess)
        ));
    }

    #[test]
    fn analyze_success_with_panic_message() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::success(serde_json::json!({
            "message": "panic occurred in handler"
        }));

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Interesting(InterestingReason::ProtocolViolation)
        ));
    }

    #[test]
    fn analyze_normal_success() {
        let detector = CrashDetector::new(5000);
        let response = FuzzResponse::success(serde_json::json!({
            "tools": []
        }));

        let analysis = detector.analyze(&response);
        assert!(matches!(analysis, CrashAnalysis::None));
    }

    #[test]
    fn crash_analysis_is_crash() {
        let analysis = CrashAnalysis::Crash(CrashInfo {
            crash_type: CrashType::Panic,
            message: "test".to_string(),
            stack_trace: None,
        });
        assert!(analysis.is_crash());
        assert!(!analysis.is_hang());
        assert!(!analysis.is_interesting());
    }

    #[test]
    fn crash_analysis_is_hang() {
        let analysis = CrashAnalysis::Hang(HangInfo { timeout_ms: 5000 });
        assert!(!analysis.is_crash());
        assert!(analysis.is_hang());
        assert!(!analysis.is_interesting());
    }

    #[test]
    fn crash_analysis_is_interesting() {
        let analysis = CrashAnalysis::Interesting(InterestingReason::NewCoverage);
        assert!(!analysis.is_crash());
        assert!(!analysis.is_hang());
        assert!(analysis.is_interesting());
    }

    #[test]
    fn fuzz_response_with_time() {
        let response = FuzzResponse::success(serde_json::json!({})).with_time(123);
        assert_eq!(response.response_time_ms, 123);
    }

    #[test]
    fn from_jsonrpc_error_with_data() {
        let error = serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32603,
                "message": "Internal error",
                "data": {"details": "more info"}
            },
            "id": 1
        });

        let response = FuzzResponse::from_jsonrpc(&error);
        if let FuzzResponseResult::Error(e) = response.result {
            assert!(e.data.is_some());
        } else {
            panic!("Expected error response");
        }
    }

    #[test]
    fn detect_process_exit_non_standard_panic() {
        let detector = CrashDetector::new(5000);
        // Non-zero exit code that isn't one of the special ones (139, 134, 137)
        let response = FuzzResponse::process_exit(1);

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Crash(CrashInfo {
                crash_type: CrashType::Panic,
                ..
            })
        ));
    }

    #[test]
    fn extract_stack_trace_with_at_pattern() {
        let detector = CrashDetector::new(5000);
        // Test stack trace extraction with "at " pattern and .rs: file reference
        let response = FuzzResponse::error(
            -32603,
            "assertion failed: x > 0\nat main.rs:42:5 in function foo",
        );

        let analysis = detector.analyze(&response);
        if let CrashAnalysis::Crash(info) = analysis {
            assert_eq!(info.crash_type, CrashType::AssertionFailure);
            assert!(info.stack_trace.is_some());
            let trace = info.stack_trace.unwrap();
            assert!(trace.contains("at main.rs:42:5"));
        } else {
            panic!("Expected Crash analysis");
        }
    }

    #[test]
    fn analyze_success_with_error_code_field() {
        let detector = CrashDetector::new(5000);
        // Test success response with "errorCode" field (not just "error")
        let response = FuzzResponse::success(serde_json::json!({
            "errorCode": 404,
            "status": "failed"
        }));

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Interesting(InterestingReason::UnexpectedSuccess)
        ));
    }

    #[test]
    fn analyze_success_with_stack_backtrace() {
        let detector = CrashDetector::new(5000);
        // Test success response with "stack backtrace" in message
        let response = FuzzResponse::success(serde_json::json!({
            "message": "stack backtrace:\n  0: foo\n  1: bar"
        }));

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Interesting(InterestingReason::ProtocolViolation)
        ));
    }

    #[test]
    fn analyze_success_with_error_prefix() {
        let detector = CrashDetector::new(5000);
        // Test success response with "Error:" prefix in message
        let response = FuzzResponse::success(serde_json::json!({
            "message": "Error: something went wrong"
        }));

        let analysis = detector.analyze(&response);
        assert!(matches!(
            analysis,
            CrashAnalysis::Interesting(InterestingReason::ProtocolViolation)
        ));
    }

    #[test]
    fn detect_reserved_error_code_range_server_error() {
        let detector = CrashDetector::new(5000);
        // Test error code in reserved range -32099 to -32000 (Server error)
        let response = FuzzResponse::error(-32050, "Server error");

        let analysis = detector.analyze(&response);
        // Reserved codes in this range are not interesting
        assert!(matches!(analysis, CrashAnalysis::None));
    }

    #[test]
    fn detect_reserved_error_code_range_jsonrpc() {
        let detector = CrashDetector::new(5000);
        // Test error code in reserved range -32768 to -32600 (JSON-RPC reserved)
        let response = FuzzResponse::error(-32650, "Reserved error");

        let analysis = detector.analyze(&response);
        // Reserved codes in this range are not interesting
        assert!(matches!(analysis, CrashAnalysis::None));
    }

    #[test]
    fn detect_short_internal_error() {
        let detector = CrashDetector::new(5000);
        // Short internal error message (<=100 chars) should not be interesting
        let response = FuzzResponse::error(-32603, "Internal error");

        let analysis = detector.analyze(&response);
        assert!(matches!(analysis, CrashAnalysis::None));
    }

    #[test]
    fn detect_panic_panicked_at_variant() {
        let detector = CrashDetector::new(5000);
        // Test "panicked at" variant specifically
        let response = FuzzResponse::error(-32603, "panicked at 'index out of bounds'");

        let analysis = detector.analyze(&response);
        assert!(analysis.is_crash());
        if let CrashAnalysis::Crash(info) = analysis {
            assert_eq!(info.crash_type, CrashType::Panic);
        }
    }

    #[test]
    fn detect_oom_allocation_variant() {
        let detector = CrashDetector::new(5000);
        // Test "allocation" variant specifically
        let response = FuzzResponse::error(-32603, "allocation failed");

        let analysis = detector.analyze(&response);
        assert!(analysis.is_crash());
        if let CrashAnalysis::Crash(info) = analysis {
            assert_eq!(info.crash_type, CrashType::OutOfMemory);
        }
    }

    #[test]
    fn detect_oom_memory_exhausted_variant() {
        let detector = CrashDetector::new(5000);
        // Test "memory exhausted" variant
        let response = FuzzResponse::error(-32603, "memory exhausted");

        let analysis = detector.analyze(&response);
        assert!(analysis.is_crash());
        if let CrashAnalysis::Crash(info) = analysis {
            assert_eq!(info.crash_type, CrashType::OutOfMemory);
        }
    }

    #[test]
    fn detect_oom_variant() {
        let detector = CrashDetector::new(5000);
        // Test "OOM" variant
        let response = FuzzResponse::error(-32603, "OOM killer activated");

        let analysis = detector.analyze(&response);
        assert!(analysis.is_crash());
        if let CrashAnalysis::Crash(info) = analysis {
            assert_eq!(info.crash_type, CrashType::OutOfMemory);
        }
    }

    #[test]
    fn detect_assertion_assert_variant() {
        let detector = CrashDetector::new(5000);
        // Test "assert!" variant
        let response = FuzzResponse::error(-32603, "assert! failed in module");

        let analysis = detector.analyze(&response);
        assert!(analysis.is_crash());
        if let CrashAnalysis::Crash(info) = analysis {
            assert_eq!(info.crash_type, CrashType::AssertionFailure);
        }
    }

    #[test]
    fn detect_assertion_debug_assert_variant() {
        let detector = CrashDetector::new(5000);
        // Test "debug_assert" variant
        let response = FuzzResponse::error(-32603, "debug_assert triggered");

        let analysis = detector.analyze(&response);
        assert!(analysis.is_crash());
        if let CrashAnalysis::Crash(info) = analysis {
            assert_eq!(info.crash_type, CrashType::AssertionFailure);
        }
    }

    #[test]
    fn detect_segfault_invalid_memory_variant() {
        let detector = CrashDetector::new(5000);
        // Test "invalid memory" variant
        let response = FuzzResponse::error(-32603, "invalid memory reference");

        let analysis = detector.analyze(&response);
        assert!(analysis.is_crash());
        if let CrashAnalysis::Crash(info) = analysis {
            assert_eq!(info.crash_type, CrashType::Segfault);
        }
    }

    #[test]
    fn detect_segfault_segmentation_fault_variant() {
        let detector = CrashDetector::new(5000);
        // Test "segmentation fault" variant
        let response = FuzzResponse::error(-32603, "segmentation fault occurred");

        let analysis = detector.analyze(&response);
        assert!(analysis.is_crash());
        if let CrashAnalysis::Crash(info) = analysis {
            assert_eq!(info.crash_type, CrashType::Segfault);
        }
    }
}
