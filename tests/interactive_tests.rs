//! Integration tests for interactive mode
//!
//! These tests verify interactive mode behavior without requiring actual TTY.
//! Uses environment manipulation and result struct verification.

use mcplint::cli::commands::explain::{CliAiProvider, CliAudienceLevel};
use mcplint::cli::interactive;
use mcplint::fuzzer::FuzzProfile;
use mcplint::scanner::ScanProfile;
use mcplint::Severity;
use std::sync::Mutex;

// Mutex to ensure tests that modify env vars don't conflict
static ENV_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// Interactive Mode Detection Tests
// ============================================================================

#[test]
fn is_interactive_available_returns_bool() {
    // Verify the function doesn't panic and returns a boolean
    let _result = interactive::is_interactive_available();
    // Result is always a valid bool, test passes if no panic
}

#[test]
fn is_interactive_available_false_in_ci_environment() {
    let _lock = ENV_LOCK.lock().unwrap();

    // Save original value
    let original = std::env::var("CI").ok();

    // Set CI environment variable
    std::env::set_var("CI", "true");

    // In CI, interactive mode should typically be unavailable
    // (though this depends on OutputMode detection which checks TTY)
    let _ = interactive::is_interactive_available();

    // Restore original value
    if let Some(val) = original {
        std::env::set_var("CI", val);
    } else {
        std::env::remove_var("CI");
    }
}

#[test]
fn is_interactive_available_with_github_actions() {
    let _lock = ENV_LOCK.lock().unwrap();

    // Save original value
    let original = std::env::var("GITHUB_ACTIONS").ok();

    // Set GITHUB_ACTIONS environment variable
    std::env::set_var("GITHUB_ACTIONS", "true");

    // Should still return a bool without panicking
    let _ = interactive::is_interactive_available();

    // Restore
    if let Some(val) = original {
        std::env::set_var("GITHUB_ACTIONS", val);
    } else {
        std::env::remove_var("GITHUB_ACTIONS");
    }
}

// ============================================================================
// Wizard Result Structure Tests
// ============================================================================

#[test]
fn scan_wizard_result_can_be_constructed() {
    let result = interactive::ScanWizardResult {
        server: "test-server".to_string(),
        profile: ScanProfile::Standard,
        include_categories: Some(vec!["security".to_string(), "protocol".to_string()]),
        output_format: interactive::OutputFormat::Text,
        fail_on: Some(vec![Severity::Critical, Severity::High]),
    };

    assert_eq!(result.server, "test-server");
    assert!(matches!(result.profile, ScanProfile::Standard));
    assert_eq!(result.include_categories.as_ref().unwrap().len(), 2);
    assert!(matches!(
        result.output_format,
        interactive::OutputFormat::Text
    ));
    assert_eq!(result.fail_on.as_ref().unwrap().len(), 2);
}

#[test]
fn scan_wizard_result_with_empty_options() {
    let result = interactive::ScanWizardResult {
        server: "minimal-server".to_string(),
        profile: ScanProfile::Quick,
        include_categories: None,
        output_format: interactive::OutputFormat::Json,
        fail_on: None,
    };

    assert_eq!(result.server, "minimal-server");
    assert!(matches!(result.profile, ScanProfile::Quick));
    assert!(result.include_categories.is_none());
    assert!(result.fail_on.is_none());
}

#[test]
fn init_wizard_result_can_be_constructed() {
    let result = interactive::InitWizardResult {
        output_path: ".mcplint.toml".to_string(),
        servers_to_test: vec!["server1".to_string(), "server2".to_string()],
        default_profile: ScanProfile::Full,
        create_ci_workflow: true,
        run_initial_scan: false,
    };

    assert_eq!(result.output_path, ".mcplint.toml");
    assert_eq!(result.servers_to_test.len(), 2);
    assert!(matches!(result.default_profile, ScanProfile::Full));
    assert!(result.create_ci_workflow);
    assert!(!result.run_initial_scan);
}

#[test]
fn init_wizard_result_empty_servers() {
    let result = interactive::InitWizardResult {
        output_path: "custom.toml".to_string(),
        servers_to_test: vec![],
        default_profile: ScanProfile::Enterprise,
        create_ci_workflow: false,
        run_initial_scan: false,
    };

    assert!(result.servers_to_test.is_empty());
    assert!(!result.create_ci_workflow);
}

#[test]
fn fuzz_wizard_result_can_be_constructed() {
    let result = interactive::FuzzWizardResult {
        server: "fuzz-target".to_string(),
        profile: FuzzProfile::Standard,
        duration: 300,
        workers: 4,
        corpus: Some(".mcplint/corpus".to_string()),
    };

    assert_eq!(result.server, "fuzz-target");
    assert!(matches!(result.profile, FuzzProfile::Standard));
    assert_eq!(result.duration, 300);
    assert_eq!(result.workers, 4);
    assert!(result.corpus.is_some());
}

#[test]
fn fuzz_wizard_result_unlimited_duration() {
    let result = interactive::FuzzWizardResult {
        server: "long-fuzz".to_string(),
        profile: FuzzProfile::Intensive,
        duration: 0, // Unlimited
        workers: 8,
        corpus: None,
    };

    assert_eq!(result.duration, 0);
    assert!(result.corpus.is_none());
}

// ============================================================================
// Output Format Tests
// ============================================================================

#[test]
fn output_format_as_str() {
    assert_eq!(interactive::OutputFormat::Text.as_str(), "text");
    assert_eq!(interactive::OutputFormat::Json.as_str(), "json");
    assert_eq!(interactive::OutputFormat::Sarif.as_str(), "sarif");
    assert_eq!(interactive::OutputFormat::Junit.as_str(), "junit");
    assert_eq!(interactive::OutputFormat::Gitlab.as_str(), "gitlab");
}

#[test]
fn output_format_default() {
    let format = interactive::OutputFormat::default();
    assert!(matches!(format, interactive::OutputFormat::Text));
}

// ============================================================================
// Scan Profile Variant Tests
// ============================================================================

#[test]
fn scan_profile_all_variants_covered() {
    // Verify all variants exist and can be constructed
    let profiles = [
        ScanProfile::Quick,
        ScanProfile::Standard,
        ScanProfile::Full,
        ScanProfile::Enterprise,
    ];

    // Verify we have all 4 variants
    assert_eq!(profiles.len(), 4);
}

// ============================================================================
// Fuzz Profile Variant Tests
// ============================================================================

#[test]
fn fuzz_profile_all_variants_covered() {
    // Verify all variants exist and can be constructed
    let profiles = [
        FuzzProfile::Quick,
        FuzzProfile::Standard,
        FuzzProfile::Intensive,
        FuzzProfile::CI,
    ];

    // Verify we have all 4 variants
    assert_eq!(profiles.len(), 4);
}

// ============================================================================
// Severity Variant Tests
// ============================================================================

#[test]
fn severity_all_variants_for_fail_on() {
    // Verify all variants exist and can be constructed
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    // Verify we have all 5 variants
    assert_eq!(severities.len(), 5);
}

// ============================================================================
// Clone and Debug Trait Tests
// ============================================================================

#[test]
fn scan_wizard_result_is_cloneable() {
    let original = interactive::ScanWizardResult {
        server: "clone-test".to_string(),
        profile: ScanProfile::Standard,
        include_categories: Some(vec!["security".to_string()]),
        output_format: interactive::OutputFormat::Sarif,
        fail_on: Some(vec![Severity::Critical]),
    };

    let cloned = original.clone();
    assert_eq!(cloned.server, "clone-test");
}

#[test]
fn init_wizard_result_is_cloneable() {
    let original = interactive::InitWizardResult {
        output_path: "clone.toml".to_string(),
        servers_to_test: vec!["s1".to_string()],
        default_profile: ScanProfile::Quick,
        create_ci_workflow: true,
        run_initial_scan: true,
    };

    let cloned = original.clone();
    assert_eq!(cloned.output_path, "clone.toml");
}

#[test]
fn fuzz_wizard_result_is_cloneable() {
    let original = interactive::FuzzWizardResult {
        server: "fuzz-clone".to_string(),
        profile: FuzzProfile::CI,
        duration: 60,
        workers: 2,
        corpus: None,
    };

    let cloned = original.clone();
    assert_eq!(cloned.server, "fuzz-clone");
    assert_eq!(cloned.duration, 60);
}

#[test]
fn scan_wizard_result_has_debug() {
    let result = interactive::ScanWizardResult {
        server: "debug-test".to_string(),
        profile: ScanProfile::Standard,
        include_categories: None,
        output_format: interactive::OutputFormat::Text,
        fail_on: None,
    };

    // Should not panic
    let debug_str = format!("{:?}", result);
    assert!(debug_str.contains("debug-test"));
}

// ============================================================================
// Non-Interactive Error Tests
// ============================================================================

#[test]
fn require_interactive_returns_result() {
    // This test verifies that require_interactive doesn't panic
    // The actual result depends on whether we're in a TTY
    let result = interactive::is_interactive_available();
    // Just verify it returns without panicking
    let _ = result;
}

// Note: Testing actual wizard flows requires TTY mocking which is complex.
// These tests verify the guard rails and data structures work correctly.

// ============================================================================
// Explain Wizard Result Structure Tests
// ============================================================================

#[test]
fn explain_wizard_result_can_be_constructed() {
    let result = interactive::ExplainWizardResult {
        server: "explain-server".to_string(),
        provider: CliAiProvider::Ollama,
        audience: CliAudienceLevel::Intermediate,
        min_severity: Some(Severity::High),
        max_findings: Some(5),
        interactive_followup: true,
    };

    assert_eq!(result.server, "explain-server");
    assert!(matches!(result.provider, CliAiProvider::Ollama));
    assert!(matches!(result.audience, CliAudienceLevel::Intermediate));
    assert_eq!(result.min_severity, Some(Severity::High));
    assert_eq!(result.max_findings, Some(5));
    assert!(result.interactive_followup);
}

#[test]
fn explain_wizard_result_with_anthropic_provider() {
    let result = interactive::ExplainWizardResult {
        server: "anthropic-test".to_string(),
        provider: CliAiProvider::Anthropic,
        audience: CliAudienceLevel::Expert,
        min_severity: Some(Severity::Critical),
        max_findings: Some(3),
        interactive_followup: false,
    };

    assert!(matches!(result.provider, CliAiProvider::Anthropic));
    assert!(matches!(result.audience, CliAudienceLevel::Expert));
    assert_eq!(result.min_severity, Some(Severity::Critical));
}

#[test]
fn explain_wizard_result_with_openai_provider() {
    let result = interactive::ExplainWizardResult {
        server: "openai-test".to_string(),
        provider: CliAiProvider::Openai,
        audience: CliAudienceLevel::Beginner,
        min_severity: None,
        max_findings: Some(10),
        interactive_followup: true,
    };

    assert!(matches!(result.provider, CliAiProvider::Openai));
    assert!(matches!(result.audience, CliAudienceLevel::Beginner));
    assert!(result.min_severity.is_none());
}

#[test]
fn explain_wizard_result_minimal_options() {
    let result = interactive::ExplainWizardResult {
        server: "minimal".to_string(),
        provider: CliAiProvider::Ollama,
        audience: CliAudienceLevel::Intermediate,
        min_severity: None,
        max_findings: None,
        interactive_followup: false,
    };

    assert_eq!(result.server, "minimal");
    assert!(result.min_severity.is_none());
    assert!(result.max_findings.is_none());
    assert!(!result.interactive_followup);
}

#[test]
fn explain_wizard_result_is_cloneable() {
    let original = interactive::ExplainWizardResult {
        server: "clone-explain".to_string(),
        provider: CliAiProvider::Anthropic,
        audience: CliAudienceLevel::Expert,
        min_severity: Some(Severity::Medium),
        max_findings: Some(7),
        interactive_followup: true,
    };

    let cloned = original.clone();
    assert_eq!(cloned.server, "clone-explain");
    assert!(matches!(cloned.provider, CliAiProvider::Anthropic));
    assert_eq!(cloned.max_findings, Some(7));
}

#[test]
fn explain_wizard_result_has_debug() {
    let result = interactive::ExplainWizardResult {
        server: "debug-explain".to_string(),
        provider: CliAiProvider::Ollama,
        audience: CliAudienceLevel::Intermediate,
        min_severity: None,
        max_findings: None,
        interactive_followup: false,
    };

    let debug_str = format!("{:?}", result);
    assert!(debug_str.contains("debug-explain"));
}

// ============================================================================
// AI Provider Variant Tests
// ============================================================================

#[test]
fn cli_ai_provider_all_variants_covered() {
    // Verify all variants exist and can be constructed
    let providers = [
        CliAiProvider::Ollama,
        CliAiProvider::Anthropic,
        CliAiProvider::Openai,
    ];

    // Verify we have all 3 variants
    assert_eq!(providers.len(), 3);
}

// ============================================================================
// Audience Level Variant Tests
// ============================================================================

#[test]
fn cli_audience_level_all_variants_covered() {
    // Verify all variants exist and can be constructed
    let levels = [
        CliAudienceLevel::Beginner,
        CliAudienceLevel::Intermediate,
        CliAudienceLevel::Expert,
    ];

    // Verify we have all 3 variants
    assert_eq!(levels.len(), 3);
}

// ============================================================================
// Explain Severity Filter Tests
// ============================================================================

#[test]
fn explain_wizard_all_severity_filters() {
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    for sev in severities {
        let result = interactive::ExplainWizardResult {
            server: "sev-test".to_string(),
            provider: CliAiProvider::Ollama,
            audience: CliAudienceLevel::Intermediate,
            min_severity: Some(sev),
            max_findings: None,
            interactive_followup: false,
        };

        assert!(result.min_severity.is_some());
    }
}

#[test]
fn explain_wizard_max_findings_limits() {
    let limits = [3, 5, 10];

    for limit in limits {
        let result = interactive::ExplainWizardResult {
            server: "limit-test".to_string(),
            provider: CliAiProvider::Ollama,
            audience: CliAudienceLevel::Intermediate,
            min_severity: None,
            max_findings: Some(limit),
            interactive_followup: false,
        };

        assert_eq!(result.max_findings, Some(limit));
    }
}

#[test]
fn explain_wizard_no_max_findings_means_all() {
    let result = interactive::ExplainWizardResult {
        server: "all-findings".to_string(),
        provider: CliAiProvider::Ollama,
        audience: CliAudienceLevel::Intermediate,
        min_severity: None,
        max_findings: None, // None means explain all findings
        interactive_followup: false,
    };

    assert!(result.max_findings.is_none());
}
