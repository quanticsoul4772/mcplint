//! Finding Fingerprint - Stable identification for baseline comparison
//!
//! Generates stable fingerprints for findings to enable accurate
//! baseline comparison across scans.

use sha2::{Digest, Sha256};

use crate::scanner::Finding;

/// Generate stable fingerprints for findings
pub struct FindingFingerprint;

impl FindingFingerprint {
    /// Create a fingerprint from a finding
    ///
    /// Uses: rule_id + location + normalized evidence
    /// Returns a 16-character hex string (first 64 bits of SHA256)
    pub fn from_finding(finding: &Finding) -> String {
        let mut hasher = Sha256::new();

        // Core identifying fields
        hasher.update(finding.rule_id.as_bytes());
        hasher.update(b"|");
        hasher.update(finding.location.component.as_bytes());
        hasher.update(b"|");
        hasher.update(finding.location.identifier.as_bytes());

        // Normalize and hash evidence
        for evidence in &finding.evidence {
            hasher.update(b"|");
            hasher.update(Self::evidence_kind_str(&evidence.kind).as_bytes());
            hasher.update(b":");
            hasher.update(Self::normalize_evidence(&evidence.data).as_bytes());
        }

        let result = hasher.finalize();
        format!("{:x}", result)[..16].to_string()
    }

    /// Normalize evidence data for stable comparison
    ///
    /// Removes timestamps, request IDs, UUIDs, and other variable content
    fn normalize_evidence(data: &str) -> String {
        data.lines()
            .filter(|l| !l.to_lowercase().contains("timestamp"))
            .filter(|l| !l.to_lowercase().contains("request_id"))
            .filter(|l| !l.to_lowercase().contains("request-id"))
            .filter(|l| !Self::looks_like_uuid(l))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Check if a line appears to be primarily a UUID
    fn looks_like_uuid(line: &str) -> bool {
        let trimmed = line.trim();
        // UUID format: 8-4-4-4-12 hex chars
        if trimmed.len() == 36 {
            let parts: Vec<_> = trimmed.split('-').collect();
            if parts.len() == 5 {
                return parts[0].len() == 8
                    && parts[1].len() == 4
                    && parts[2].len() == 4
                    && parts[3].len() == 4
                    && parts[4].len() == 12
                    && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
            }
        }
        false
    }

    fn evidence_kind_str(kind: &crate::scanner::EvidenceKind) -> &'static str {
        match kind {
            crate::scanner::EvidenceKind::Request => "request",
            crate::scanner::EvidenceKind::Response => "response",
            crate::scanner::EvidenceKind::Configuration => "configuration",
            crate::scanner::EvidenceKind::Observation => "observation",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Evidence, EvidenceKind, FindingLocation, Severity};

    fn create_test_finding() -> Finding {
        Finding::new(
            "MCP-INJ-001",
            Severity::High,
            "Test Finding",
            "Test description",
        )
        .with_location(FindingLocation::tool("test_tool"))
        .with_evidence(Evidence::new(
            EvidenceKind::Observation,
            "dangerous pattern detected",
            "Found injection pattern",
        ))
    }

    #[test]
    fn fingerprint_stability() {
        let finding = create_test_finding();
        let fp1 = FindingFingerprint::from_finding(&finding);
        let fp2 = FindingFingerprint::from_finding(&finding);
        assert_eq!(fp1, fp2, "Fingerprints should be stable");
        assert_eq!(fp1.len(), 16, "Fingerprint should be 16 hex chars");
    }

    #[test]
    fn fingerprint_uniqueness() {
        let finding1 = create_test_finding();
        let mut finding2 = create_test_finding();
        finding2.rule_id = "MCP-INJ-002".to_string();

        let fp1 = FindingFingerprint::from_finding(&finding1);
        let fp2 = FindingFingerprint::from_finding(&finding2);
        assert_ne!(fp1, fp2, "Different findings should have different fingerprints");
    }

    #[test]
    fn normalize_removes_timestamps() {
        let data = "line1\ntimestamp: 2025-01-01\nline2";
        let normalized = FindingFingerprint::normalize_evidence(data);
        assert!(!normalized.contains("timestamp"));
        assert!(normalized.contains("line1"));
        assert!(normalized.contains("line2"));
    }

    #[test]
    fn uuid_detection() {
        assert!(FindingFingerprint::looks_like_uuid(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(!FindingFingerprint::looks_like_uuid("not a uuid"));
        assert!(!FindingFingerprint::looks_like_uuid(
            "550e8400-e29b-41d4-a716"
        ));
    }
}
