//! Server Integration Tests
//!
//! Tests that use real MCP server connections.
//! These tests require configured servers in claude_desktop_config.json
//! and will be skipped if servers are not available.

use std::collections::HashMap;

use mcplint::transport::{connect_with_type, TransportConfig, TransportType};
use mcplint::validator::{ValidationConfig, ValidationEngine, ValidationSeverity};

/// Helper to check if the filesystem server is available
fn filesystem_server_available() -> bool {
    // The filesystem server should be available on Windows with node
    std::path::Path::new("C:\\Program Files\\nodejs\\node.exe").exists()
        && std::path::Path::new(
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js",
        )
        .exists()
}

/// Helper to check if the memory server is available
fn memory_server_available() -> bool {
    std::path::Path::new("C:\\Program Files\\nodejs\\node.exe").exists()
        && std::path::Path::new("C:\\Users\\rbsmi\\mcp-memory-server\\dist\\index.js").exists()
}

// =============================================================================
// Transport Tests - Test connection and basic communication
// =============================================================================

mod transport_tests {
    use super::*;

    #[tokio::test]
    async fn connect_to_filesystem_server() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let result = connect_with_type(
            command,
            &args,
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await;

        match result {
            Ok(mut transport) => {
                // Verify we got a connection
                assert_eq!(transport.transport_type(), "stdio");
                // Clean up
                let _ = transport.close().await;
            }
            Err(e) => {
                // Server might not be installed - that's OK
                eprintln!("Could not connect to filesystem server: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn transport_request_initialize() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let mut transport = connect_with_type(
            command,
            &args,
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await
        .expect("Should connect");

        // Send initialize request
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mcplint-test",
                "version": "1.0.0"
            }
        });

        let response = transport.request("initialize", Some(params)).await;

        match response {
            Ok(resp) => {
                // Should have a result
                assert!(resp.result.is_some() || resp.error.is_some());
                if let Some(result) = resp.result {
                    // Check for expected fields
                    assert!(result.get("protocolVersion").is_some());
                    assert!(result.get("capabilities").is_some());
                }
            }
            Err(e) => {
                panic!("Initialize request failed: {}", e);
            }
        }

        let _ = transport.close().await;
    }

    #[tokio::test]
    async fn transport_notify_initialized() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let mut transport = connect_with_type(
            command,
            &args,
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await
        .expect("Should connect");

        // Initialize first
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mcplint-test",
                "version": "1.0.0"
            }
        });
        let _ = transport.request("initialize", Some(params)).await;

        // Send initialized notification
        let result = transport.notify("notifications/initialized", None).await;
        assert!(result.is_ok());

        let _ = transport.close().await;
    }

    #[tokio::test]
    async fn transport_ping() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let mut transport = connect_with_type(
            command,
            &args,
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await
        .expect("Should connect");

        // Initialize first
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mcplint-test",
                "version": "1.0.0"
            }
        });
        let _ = transport.request("initialize", Some(params)).await;
        let _ = transport.notify("notifications/initialized", None).await;

        // Ping
        let response = transport.request("ping", None).await;
        assert!(response.is_ok());

        let _ = transport.close().await;
    }

    #[tokio::test]
    async fn transport_list_tools() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let mut transport = connect_with_type(
            command,
            &args,
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await
        .expect("Should connect");

        // Initialize
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mcplint-test",
                "version": "1.0.0"
            }
        });
        let _ = transport.request("initialize", Some(params)).await;
        let _ = transport.notify("notifications/initialized", None).await;

        // List tools
        let response = transport.request("tools/list", None).await;
        assert!(response.is_ok());

        let resp = response.unwrap();
        if let Some(result) = resp.result {
            assert!(result.get("tools").is_some());
            let tools = result["tools"].as_array().unwrap();
            // Filesystem server should have tools
            assert!(!tools.is_empty());
        }

        let _ = transport.close().await;
    }
}

// =============================================================================
// Validator Tests - Test validation engine with real servers
// =============================================================================

mod validator_tests {
    use super::*;

    #[tokio::test]
    async fn validate_filesystem_server() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig {
            timeout_secs: 60,
            ..Default::default()
        };
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await;

        match results {
            Ok(r) => {
                // Should have run some rules
                assert!(!r.results.is_empty());
                // Should have protocol version
                assert!(r.protocol_version.is_some());
                // Should have capabilities
                assert!(r.capabilities.is_some());
                // Most rules should pass
                assert!(r.passed > 0);

                // Print summary
                eprintln!(
                    "Validation: {} passed, {} failed, {} warnings",
                    r.passed, r.failed, r.warnings
                );
            }
            Err(e) => {
                panic!("Validation failed: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn validate_protocol_rules_run() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await
            .expect("Validation should succeed");

        // Check for PROTO rules
        let proto_results: Vec<_> = results
            .results
            .iter()
            .filter(|r| r.rule_id.starts_with("PROTO-"))
            .collect();

        assert!(!proto_results.is_empty(), "Should have PROTO rules");

        // PROTO-001 and PROTO-002 should pass for a compliant server
        let proto001 = results.results.iter().find(|r| r.rule_id == "PROTO-001");
        assert!(proto001.is_some());
        assert_eq!(proto001.unwrap().severity, ValidationSeverity::Pass);

        let proto002 = results.results.iter().find(|r| r.rule_id == "PROTO-002");
        assert!(proto002.is_some());
        assert_eq!(proto002.unwrap().severity, ValidationSeverity::Pass);
    }

    #[tokio::test]
    async fn validate_schema_rules_run() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await
            .expect("Validation should succeed");

        // Check for SCHEMA rules
        let schema_results: Vec<_> = results
            .results
            .iter()
            .filter(|r| r.rule_id.starts_with("SCHEMA-"))
            .collect();

        assert!(!schema_results.is_empty(), "Should have SCHEMA rules");
    }

    #[tokio::test]
    async fn validate_sequence_rules_run() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await
            .expect("Validation should succeed");

        // Check for SEQ rules
        let seq_results: Vec<_> = results
            .results
            .iter()
            .filter(|r| r.rule_id.starts_with("SEQ-"))
            .collect();

        assert!(!seq_results.is_empty(), "Should have SEQ rules");

        // SEQ-001 (ping) should pass
        let seq001 = results.results.iter().find(|r| r.rule_id == "SEQ-001");
        assert!(seq001.is_some());
        assert_eq!(seq001.unwrap().severity, ValidationSeverity::Pass);
    }

    #[tokio::test]
    async fn validate_tool_rules_run() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await
            .expect("Validation should succeed");

        // Check for TOOL rules
        let tool_results: Vec<_> = results
            .results
            .iter()
            .filter(|r| r.rule_id.starts_with("TOOL-"))
            .collect();

        assert!(!tool_results.is_empty(), "Should have TOOL rules");
    }

    #[tokio::test]
    async fn validate_security_rules_run() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await
            .expect("Validation should succeed");

        // Check for SEC rules
        let sec_results: Vec<_> = results
            .results
            .iter()
            .filter(|r| r.rule_id.starts_with("SEC-"))
            .collect();

        assert!(!sec_results.is_empty(), "Should have SEC rules");

        // SEC-006 (SSRF) is known to fail on filesystem server
        let sec006 = results.results.iter().find(|r| r.rule_id == "SEC-006");
        assert!(sec006.is_some());
    }

    #[tokio::test]
    async fn validate_edge_rules_run() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await
            .expect("Validation should succeed");

        // Check for EDGE rules
        let edge_results: Vec<_> = results
            .results
            .iter()
            .filter(|r| r.rule_id.starts_with("EDGE-"))
            .collect();

        assert!(!edge_results.is_empty(), "Should have EDGE rules");
    }

    #[tokio::test]
    async fn validate_results_count_consistency() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await
            .expect("Validation should succeed");

        // Verify counts are consistent
        let pass_count = results
            .results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Pass)
            .count();
        let fail_count = results
            .results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Fail)
            .count();
        let warning_count = results
            .results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Warning)
            .count();

        assert_eq!(pass_count, results.passed);
        assert_eq!(fail_count, results.failed);
        assert_eq!(warning_count, results.warnings);
    }

    #[tokio::test]
    async fn validate_with_custom_timeout() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig {
            timeout_secs: 120, // Longer timeout
            ..Default::default()
        };
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await;

        assert!(results.is_ok());
    }

    #[tokio::test]
    async fn validate_with_env_vars() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        // Pass custom env vars
        let mut env = HashMap::new();
        env.insert("MCPLINT_TEST".to_string(), "true".to_string());

        let results = engine
            .validate_server(command, &args, &env, Some(TransportType::Stdio))
            .await;

        assert!(results.is_ok());
    }

    #[tokio::test]
    async fn validate_duration_recorded() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await
            .expect("Validation should succeed");

        // Total duration should be > 0
        assert!(results.total_duration_ms > 0);

        // Individual rule durations should be >= 0
        for result in &results.results {
            // Some rules might complete instantly (0ms is valid)
            assert!(result.duration_ms < 60_000); // But shouldn't take more than 60s
        }
    }
}

// =============================================================================
// Error Handling Tests
// =============================================================================

mod error_tests {
    use super::*;

    #[tokio::test]
    async fn connect_to_nonexistent_server() {
        let config = TransportConfig::default();

        let result = connect_with_type(
            "nonexistent-command-12345",
            &[],
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await;

        // Should fail to spawn
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn validate_nonexistent_server() {
        let config = ValidationConfig::default();
        let mut engine = ValidationEngine::new(config);

        let result = engine
            .validate_server(
                "nonexistent-command-12345",
                &[],
                &HashMap::new(),
                Some(TransportType::Stdio),
            )
            .await;

        // Should fail to connect
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn validate_with_wrong_args() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ValidationConfig {
            timeout_secs: 10, // Short timeout
            ..Default::default()
        };
        let mut engine = ValidationEngine::new(config);

        // Pass invalid script path - Node will spawn and exit with MODULE_NOT_FOUND error
        // The validation should either fail or produce error results
        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec!["nonexistent-script.js".to_string()];

        let result = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await;

        // Node exits immediately with an error when script not found,
        // which causes the validation to fail during initialization
        // The actual behavior may be error OR no results, depending on timing
        match result {
            Ok(r) => {
                // If we got results, initialization likely failed (PROTO-001 should fail)
                let proto001 = r.results.iter().find(|res| res.rule_id == "PROTO-001");
                if let Some(p) = proto001 {
                    assert_eq!(p.severity, ValidationSeverity::Fail);
                }
            }
            Err(_) => {
                // Connection failed - this is expected
            }
        }
    }
}

// =============================================================================
// Memory Server Tests (if available)
// =============================================================================

mod memory_server_tests {
    use super::*;

    #[tokio::test]
    async fn validate_memory_server() {
        if !memory_server_available() {
            eprintln!("Skipping: memory server not available");
            return;
        }

        let config = ValidationConfig {
            timeout_secs: 60,
            ..Default::default()
        };
        let mut engine = ValidationEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec!["C:\\Users\\rbsmi\\mcp-memory-server\\dist\\index.js".to_string()];

        let results = engine
            .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
            .await;

        match results {
            Ok(r) => {
                assert!(!r.results.is_empty());
                assert!(r.passed > 0);
                eprintln!(
                    "Memory server: {} passed, {} failed, {} warnings",
                    r.passed, r.failed, r.warnings
                );
            }
            Err(e) => {
                eprintln!("Memory server validation failed: {}", e);
            }
        }
    }
}

// =============================================================================
// Concurrency Tests
// =============================================================================

mod concurrency_tests {
    use super::*;

    #[tokio::test]
    async fn parallel_validations() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        // Run two validations concurrently
        let handle1 = {
            let args = args.clone();
            tokio::spawn(async move {
                let config = ValidationConfig::default();
                let mut engine = ValidationEngine::new(config);
                engine
                    .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
                    .await
            })
        };

        let handle2 = {
            let args = args.clone();
            tokio::spawn(async move {
                let config = ValidationConfig::default();
                let mut engine = ValidationEngine::new(config);
                engine
                    .validate_server(command, &args, &HashMap::new(), Some(TransportType::Stdio))
                    .await
            })
        };

        let (result1, result2) = tokio::join!(handle1, handle2);

        // Both should complete
        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let r1 = result1.unwrap().unwrap();
        let r2 = result2.unwrap().unwrap();

        // Both should have results
        assert!(!r1.results.is_empty());
        assert!(!r2.results.is_empty());
    }
}

// =============================================================================
// Scanner Tests - Test security scanning with real servers
// =============================================================================

mod scanner_tests {
    use super::*;
    use mcplint::scanner::{ScanConfig, ScanEngine, ScanProfile};

    #[tokio::test]
    async fn scan_filesystem_server() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ScanConfig {
            profile: ScanProfile::Standard,
            timeout_secs: 60,
            ..Default::default()
        };
        let engine = ScanEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .scan(command, &args, Some(TransportType::Stdio))
            .await;

        match results {
            Ok(r) => {
                // Should have run some checks
                assert!(r.total_checks > 0);
                // Duration should be recorded
                assert!(r.duration_ms > 0);
                // Profile should be recorded
                assert_eq!(r.profile, "standard");

                eprintln!(
                    "Scan: {} checks, {} findings (C:{} H:{} M:{} L:{} I:{})",
                    r.total_checks,
                    r.total_findings(),
                    r.summary.critical,
                    r.summary.high,
                    r.summary.medium,
                    r.summary.low,
                    r.summary.info
                );
            }
            Err(e) => {
                panic!("Scan failed: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn scan_with_quick_profile() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ScanConfig {
            profile: ScanProfile::Quick,
            timeout_secs: 30,
            ..Default::default()
        };
        let engine = ScanEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .scan(command, &args, Some(TransportType::Stdio))
            .await
            .expect("Scan should succeed");

        assert_eq!(results.profile, "quick");
    }

    #[tokio::test]
    async fn scan_with_deep_profile() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ScanConfig {
            profile: ScanProfile::Full,
            timeout_secs: 120,
            ..Default::default()
        };
        let engine = ScanEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .scan(command, &args, Some(TransportType::Stdio))
            .await
            .expect("Scan should succeed");

        assert_eq!(results.profile, "full");
        // Full scan should run more checks
        assert!(results.total_checks > 0);
    }

    #[tokio::test]
    async fn scan_findings_have_proper_structure() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ScanConfig::default();
        let engine = ScanEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .scan(command, &args, Some(TransportType::Stdio))
            .await
            .expect("Scan should succeed");

        // If there are any findings, verify their structure
        for finding in &results.findings {
            assert!(!finding.rule_id.is_empty());
            assert!(!finding.title.is_empty());
            assert!(!finding.description.is_empty());
        }
    }

    #[tokio::test]
    async fn scan_results_summary_matches_findings() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = ScanConfig::default();
        let engine = ScanEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let results = engine
            .scan(command, &args, Some(TransportType::Stdio))
            .await
            .expect("Scan should succeed");

        // Count findings by severity
        let critical = results
            .findings
            .iter()
            .filter(|f| matches!(f.severity, mcplint::scanner::Severity::Critical))
            .count();
        let high = results
            .findings
            .iter()
            .filter(|f| matches!(f.severity, mcplint::scanner::Severity::High))
            .count();
        let medium = results
            .findings
            .iter()
            .filter(|f| matches!(f.severity, mcplint::scanner::Severity::Medium))
            .count();
        let low = results
            .findings
            .iter()
            .filter(|f| matches!(f.severity, mcplint::scanner::Severity::Low))
            .count();
        let info = results
            .findings
            .iter()
            .filter(|f| matches!(f.severity, mcplint::scanner::Severity::Info))
            .count();

        assert_eq!(results.summary.critical, critical);
        assert_eq!(results.summary.high, high);
        assert_eq!(results.summary.medium, medium);
        assert_eq!(results.summary.low, low);
        assert_eq!(results.summary.info, info);
    }

    #[tokio::test]
    async fn scan_memory_server() {
        if !memory_server_available() {
            eprintln!("Skipping: memory server not available");
            return;
        }

        let config = ScanConfig::default();
        let engine = ScanEngine::new(config);

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec!["C:\\Users\\rbsmi\\mcp-memory-server\\dist\\index.js".to_string()];

        let results = engine
            .scan(command, &args, Some(TransportType::Stdio))
            .await;

        match results {
            Ok(r) => {
                assert!(r.total_checks > 0);
                eprintln!(
                    "Memory server scan: {} checks, {} findings",
                    r.total_checks,
                    r.total_findings()
                );
            }
            Err(e) => {
                eprintln!("Memory server scan failed: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn scan_with_nonexistent_server() {
        let config = ScanConfig::default();
        let engine = ScanEngine::new(config);

        let result = engine
            .scan("nonexistent-command-12345", &[], Some(TransportType::Stdio))
            .await;

        // Should fail to connect
        assert!(result.is_err());
    }
}

// =============================================================================
// Transport Direct Tests - Test transport layer directly
// =============================================================================

mod transport_direct_tests {
    use super::*;

    #[tokio::test]
    async fn stdio_transport_initialization() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let mut transport = connect_with_type(
            command,
            &args,
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await
        .expect("Should connect");

        // Should report stdio type
        assert_eq!(transport.transport_type(), "stdio");

        // Should be able to close cleanly
        let close_result = transport.close().await;
        assert!(close_result.is_ok());
    }

    #[tokio::test]
    async fn transport_handles_multiple_requests() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let mut transport = connect_with_type(
            command,
            &args,
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await
        .expect("Should connect");

        // Initialize
        let params = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mcplint-test",
                "version": "1.0.0"
            }
        });
        let _ = transport.request("initialize", Some(params)).await;
        let _ = transport.notify("notifications/initialized", None).await;

        // Make multiple sequential requests
        for _ in 0..3 {
            let response = transport.request("tools/list", None).await;
            assert!(response.is_ok());
        }

        let _ = transport.close().await;
    }

    #[tokio::test]
    async fn transport_with_environment_variables() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        // Pass custom environment variables
        let mut env = HashMap::new();
        env.insert("MCPLINT_TEST_VAR".to_string(), "test_value".to_string());
        env.insert("NODE_ENV".to_string(), "test".to_string());

        let result = connect_with_type(command, &args, &env, config, TransportType::Stdio).await;

        // Should succeed with env vars
        assert!(result.is_ok());

        if let Ok(mut transport) = result {
            let _ = transport.close().await;
        }
    }
}

// =============================================================================
// Client Tests - Test MCP client functionality
// =============================================================================

mod client_tests {
    use super::*;
    use mcplint::client::McpClient;
    use mcplint::protocol::Implementation;

    #[tokio::test]
    async fn client_full_lifecycle() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let transport = connect_with_type(
            command,
            &args,
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await
        .expect("Should connect");

        let client_info = Implementation::new("mcplint-test", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        // Initialize
        let init_result = client.initialize().await;
        assert!(init_result.is_ok());

        let init = init_result.unwrap();
        assert!(!init.protocol_version.is_empty());
        assert!(!init.server_info.name.is_empty());

        // List tools
        if init.capabilities.has_tools() {
            let tools = client.list_tools().await;
            assert!(tools.is_ok());
            let tools = tools.unwrap();
            assert!(!tools.is_empty());

            // Filesystem server should have these tools
            let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
            assert!(
                tool_names.contains(&"read_file") || tool_names.contains(&"list_directory"),
                "Expected filesystem tools"
            );
        }

        // List resources
        if init.capabilities.has_resources() {
            let resources = client.list_resources().await;
            assert!(resources.is_ok());
        }

        // Close
        let close_result = client.close().await;
        assert!(close_result.is_ok());
    }

    #[tokio::test]
    async fn client_call_tool() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let transport = connect_with_type(
            command,
            &args,
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await
        .expect("Should connect");

        let client_info = Implementation::new("mcplint-test", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        let _ = client.initialize().await.expect("Initialize should work");

        // Call list_directory tool
        let tool_args = serde_json::json!({
            "path": "C:\\Development"
        });

        let result = client.call_tool("list_directory", Some(tool_args)).await;

        match result {
            Ok(response) => {
                // Should get content back
                assert!(!response.content.is_empty());
            }
            Err(e) => {
                // Some errors are acceptable (e.g., permission denied)
                eprintln!("Tool call error (may be expected): {}", e);
            }
        }

        let _ = client.close().await;
    }

    #[tokio::test]
    async fn client_read_resource() {
        if !filesystem_server_available() {
            eprintln!("Skipping: filesystem server not available");
            return;
        }

        let config = TransportConfig {
            timeout_secs: 30,
            ..Default::default()
        };

        let command = "C:\\Program Files\\nodejs\\node.exe";
        let args = vec![
            "C:\\npm-global\\node_modules\\@modelcontextprotocol\\server-filesystem\\dist\\index.js"
                .to_string(),
            "C:\\Development".to_string(),
        ];

        let transport = connect_with_type(
            command,
            &args,
            &HashMap::new(),
            config,
            TransportType::Stdio,
        )
        .await
        .expect("Should connect");

        let client_info = Implementation::new("mcplint-test", "1.0.0");
        let mut client = McpClient::new(transport, client_info);
        client.mark_connected();

        let init = client.initialize().await.expect("Initialize should work");

        if init.capabilities.has_resources() {
            let resources = client.list_resources().await.expect("List should work");
            if !resources.is_empty() {
                // Try to read the first resource
                let result = client.read_resource(&resources[0].uri).await;
                // Result may succeed or fail depending on the resource
                match result {
                    Ok(contents) => {
                        assert!(!contents.contents.is_empty());
                    }
                    Err(_) => {
                        // Some resources may not be readable
                    }
                }
            }
        }

        let _ = client.close().await;
    }
}
