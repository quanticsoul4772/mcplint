//! SEC-044: Unicode Hidden Instructions Detection
//!
//! Detects hidden Unicode characters that could be used to embed
//! invisible instructions in tool descriptions or responses.

use crate::protocol::mcp::Tool;
use crate::scanner::finding::{Evidence, Finding, FindingLocation, Severity};

/// Detector for Unicode-based hidden instruction attacks
pub struct UnicodeHiddenDetector;

/// Information about a detected suspicious character
#[derive(Debug, Clone)]
pub struct SuspiciousChar {
    /// The character (stored for detailed analysis/display)
    #[allow(dead_code)] // Used in Debug derive and reserved for detailed reporting
    pub char: char,
    /// Unicode code point
    pub codepoint: u32,
    /// Position in string
    pub position: usize,
    /// Category of suspicious character
    pub category: UnicodeCategory,
}

/// Categories of suspicious Unicode characters
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnicodeCategory {
    /// Zero-width characters (invisible)
    ZeroWidth,
    /// Bidirectional control characters (RTL override)
    Bidirectional,
    /// Tag characters (invisible metadata)
    Tag,
    /// Homoglyphs (visually similar to ASCII)
    Homoglyph,
    /// Combining characters (can hide text)
    Combining,
    /// Private use area (undefined behavior)
    PrivateUse,
    /// Deprecated format characters
    DeprecatedFormat,
}

impl std::fmt::Display for UnicodeCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnicodeCategory::ZeroWidth => write!(f, "zero-width"),
            UnicodeCategory::Bidirectional => write!(f, "bidirectional-control"),
            UnicodeCategory::Tag => write!(f, "tag-character"),
            UnicodeCategory::Homoglyph => write!(f, "homoglyph"),
            UnicodeCategory::Combining => write!(f, "combining"),
            UnicodeCategory::PrivateUse => write!(f, "private-use"),
            UnicodeCategory::DeprecatedFormat => write!(f, "deprecated-format"),
        }
    }
}

impl UnicodeHiddenDetector {
    /// Create a new detector
    pub fn new() -> Self {
        Self
    }

    /// Check all tools for Unicode hidden instructions
    pub fn check_tools(&self, tools: &[Tool]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for tool in tools {
            // Check tool name
            let name_suspicious = self.detect_suspicious_unicode(&tool.name);
            if !name_suspicious.is_empty() {
                findings.push(self.create_finding(
                    &tool.name,
                    "name",
                    &tool.name,
                    &name_suspicious,
                ));
            }

            // Check tool description
            if let Some(ref desc) = tool.description {
                let desc_suspicious = self.detect_suspicious_unicode(desc);
                if !desc_suspicious.is_empty() {
                    findings.push(self.create_finding(
                        &tool.name,
                        "description",
                        desc,
                        &desc_suspicious,
                    ));
                }
            }

            // Check schema for string values that might contain hidden chars
            if let Some(schema_findings) = self.check_schema(&tool.name, &tool.input_schema) {
                findings.extend(schema_findings);
            }
        }

        findings
    }

    /// Detect suspicious Unicode characters in text
    pub fn detect_suspicious_unicode(&self, text: &str) -> Vec<SuspiciousChar> {
        let mut suspicious = Vec::new();

        for (pos, ch) in text.char_indices() {
            if let Some(category) = self.classify_char(ch, text, pos) {
                suspicious.push(SuspiciousChar {
                    char: ch,
                    codepoint: ch as u32,
                    position: pos,
                    category,
                });
            }
        }

        suspicious
    }

    /// Classify a character as suspicious if applicable
    fn classify_char(&self, ch: char, text: &str, pos: usize) -> Option<UnicodeCategory> {
        let cp = ch as u32;

        // Zero-width characters (invisible)
        if matches!(
            cp,
            0x200B  // Zero Width Space
            | 0x200C  // Zero Width Non-Joiner
            | 0x200D  // Zero Width Joiner
            | 0xFEFF  // Byte Order Mark / Zero Width No-Break Space
            | 0x2060  // Word Joiner
            | 0x2061  // Function Application
            | 0x2062  // Invisible Times
            | 0x2063  // Invisible Separator
            | 0x2064  // Invisible Plus
            | 0x180E // Mongolian Vowel Separator
        ) {
            return Some(UnicodeCategory::ZeroWidth);
        }

        // Bidirectional control characters (can reverse text display)
        if matches!(
            cp,
            0x200E  // Left-to-Right Mark
            | 0x200F  // Right-to-Left Mark
            | 0x202A  // Left-to-Right Embedding
            | 0x202B  // Right-to-Left Embedding
            | 0x202C  // Pop Directional Formatting
            | 0x202D  // Left-to-Right Override
            | 0x202E  // Right-to-Left Override
            | 0x2066  // Left-to-Right Isolate
            | 0x2067  // Right-to-Left Isolate
            | 0x2068  // First Strong Isolate
            | 0x2069 // Pop Directional Isolate
        ) {
            return Some(UnicodeCategory::Bidirectional);
        }

        // Tag characters (invisible, used for language tagging)
        if (0xE0000..=0xE007F).contains(&cp) || (0xE0100..=0xE01EF).contains(&cp) {
            return Some(UnicodeCategory::Tag);
        }

        // Homoglyphs - characters that look like ASCII but aren't
        // This is a selection of common attack vectors
        if self.is_homoglyph(ch) {
            return Some(UnicodeCategory::Homoglyph);
        }

        // Excessive combining characters (can hide or obscure text)
        if (0x0300..=0x036F).contains(&cp) || // Combining Diacritical Marks
           (0x1AB0..=0x1AFF).contains(&cp) || // Combining Diacritical Marks Extended
           (0x1DC0..=0x1DFF).contains(&cp) || // Combining Diacritical Marks Supplement
           (0x20D0..=0x20FF).contains(&cp) || // Combining Diacritical Marks for Symbols
           (0xFE20..=0xFE2F).contains(&cp)
        // Combining Half Marks
        {
            // Only flag if there are excessive combining marks
            if self.has_excessive_combining(text, pos) {
                return Some(UnicodeCategory::Combining);
            }
        }

        // Private Use Area (undefined, could be anything)
        if (0xE000..=0xF8FF).contains(&cp) || // BMP Private Use
           (0xF0000..=0xFFFFD).contains(&cp) || // Supplementary Private Use Area-A
           (0x100000..=0x10FFFD).contains(&cp)
        // Supplementary Private Use Area-B
        {
            return Some(UnicodeCategory::PrivateUse);
        }

        // Deprecated format characters (U+206A through U+206F)
        if (0x206A..=0x206F).contains(&cp) {
            return Some(UnicodeCategory::DeprecatedFormat);
        }

        None
    }

    /// Check if a character is a homoglyph (looks like ASCII but isn't)
    fn is_homoglyph(&self, ch: char) -> bool {
        // Common homoglyphs used in attacks
        matches!(
            ch,
            // Cyrillic homoglyphs for Latin letters
            'а' | 'е' | 'о' | 'р' | 'с' | 'у' | 'х' |  // Cyrillic lowercase
            'А' | 'В' | 'Е' | 'К' | 'М' | 'Н' | 'О' | 'Р' | 'С' | 'Т' | 'У' | 'Х' |  // Cyrillic uppercase
            // Greek homoglyphs
            'Α' | 'Β' | 'Ε' | 'Ζ' | 'Η' | 'Ι' | 'Κ' | 'Μ' | 'Ν' | 'Ο' | 'Ρ' | 'Τ' | 'Υ' | 'Χ' |
            // Fullwidth ASCII (can bypass filters)
            'Ａ'..='Ｚ' | 'ａ'..='ｚ' | '０'..='９' |
            // Mathematical alphanumeric symbols (can look like normal letters)
            '𝐀'..='𝐙' | '𝐚'..='𝐳' |  // Bold
            '𝑨'..='𝒁' | '𝒂'..='𝒛' |  // Italic
            '𝗔'..='𝗭' | '𝗮'..='𝘇' |  // Sans-serif bold
            '𝘈'..='𝘡' | '𝘢'..='𝘻' |  // Sans-serif italic
            // Other confusables
            'ı' |  // Dotless i
            'ȷ' |  // Dotless j
            'ɑ' |  // Latin small letter alpha
            'ɡ' |  // Latin small letter script g
            'ℓ' |  // Script small l
            '℮' |  // Estimated symbol (looks like e)
            'ⅰ'..='ⅻ' | 'Ⅰ'..='Ⅻ'  // Roman numerals
        )
    }

    /// Check if there are excessive combining characters at a position
    fn has_excessive_combining(&self, text: &str, pos: usize) -> bool {
        let chars: Vec<char> = text.chars().collect();
        let char_pos = text[..pos].chars().count();

        // Count consecutive combining characters
        let mut combining_count = 0;
        for ch in chars.iter().skip(char_pos) {
            let cp = *ch as u32;
            if (0x0300..=0x036F).contains(&cp)
                || (0x1AB0..=0x1AFF).contains(&cp)
                || (0x1DC0..=0x1DFF).contains(&cp)
                || (0x20D0..=0x20FF).contains(&cp)
                || (0xFE20..=0xFE2F).contains(&cp)
            {
                combining_count += 1;
            } else {
                break;
            }
        }

        // More than 2 combining characters is suspicious
        combining_count > 2
    }

    /// Check JSON schema for hidden characters
    fn check_schema(&self, tool_name: &str, schema: &serde_json::Value) -> Option<Vec<Finding>> {
        let mut findings = Vec::new();

        self.check_schema_recursive(tool_name, schema, &mut findings, "");

        if findings.is_empty() {
            None
        } else {
            Some(findings)
        }
    }

    fn check_schema_recursive(
        &self,
        tool_name: &str,
        value: &serde_json::Value,
        findings: &mut Vec<Finding>,
        path: &str,
    ) {
        match value {
            serde_json::Value::String(s) => {
                let suspicious = self.detect_suspicious_unicode(s);
                if !suspicious.is_empty() {
                    findings.push(self.create_finding(
                        tool_name,
                        &format!("schema{}", path),
                        s,
                        &suspicious,
                    ));
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    self.check_schema_recursive(
                        tool_name,
                        item,
                        findings,
                        &format!("{}[{}]", path, i),
                    );
                }
            }
            serde_json::Value::Object(obj) => {
                for (key, val) in obj {
                    // Check the key itself
                    let key_suspicious = self.detect_suspicious_unicode(key);
                    if !key_suspicious.is_empty() {
                        findings.push(self.create_finding(
                            tool_name,
                            &format!("schema{}.key", path),
                            key,
                            &key_suspicious,
                        ));
                    }
                    // Recurse into value
                    self.check_schema_recursive(
                        tool_name,
                        val,
                        findings,
                        &format!("{}.{}", path, key),
                    );
                }
            }
            _ => {}
        }
    }

    /// Create a finding from detected suspicious characters
    fn create_finding(
        &self,
        tool_name: &str,
        field: &str,
        text: &str,
        suspicious: &[SuspiciousChar],
    ) -> Finding {
        let categories: Vec<_> = suspicious
            .iter()
            .map(|s| s.category)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let severity = self.assess_severity(&categories);

        let char_details: Vec<String> = suspicious
            .iter()
            .take(5)
            .map(|s| {
                format!(
                    "U+{:04X} ({}) at pos {}",
                    s.codepoint, s.category, s.position
                )
            })
            .collect();

        let truncated_text = if text.len() > 50 {
            format!("{}...", &text[..50])
        } else {
            text.to_string()
        };

        Finding::new(
            "MCP-SEC-044",
            severity,
            "Unicode Hidden Instructions Detected",
            format!(
                "Tool '{}' {} contains {} suspicious Unicode character(s) that could hide malicious instructions.",
                tool_name,
                field,
                suspicious.len()
            ),
        )
        .with_location(FindingLocation::tool(tool_name).with_context(field))
        .with_evidence(Evidence::observation(
            format!("Detected: {}", char_details.join(", ")),
            format!("In text: \"{}\"", truncated_text),
        ))
        .with_remediation(
            "Remove or replace suspicious Unicode characters. Use ASCII-only text for tool \
             descriptions and names. Implement Unicode normalization and validation.",
        )
        .with_cwe("116")
    }

    /// Assess severity based on character categories found
    fn assess_severity(&self, categories: &[UnicodeCategory]) -> Severity {
        // RTL overrides and zero-width characters are most dangerous
        if categories.contains(&UnicodeCategory::Bidirectional) {
            return Severity::Critical;
        }

        if categories.contains(&UnicodeCategory::ZeroWidth) {
            return Severity::High;
        }

        if categories.contains(&UnicodeCategory::Tag) {
            return Severity::High;
        }

        if categories.contains(&UnicodeCategory::Homoglyph) {
            return Severity::High;
        }

        if categories.contains(&UnicodeCategory::PrivateUse) {
            return Severity::Medium;
        }

        Severity::Medium
    }
}

impl Default for UnicodeHiddenDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tool(name: &str, description: Option<&str>) -> Tool {
        Tool {
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            input_schema: json!({"type": "object"}),
        }
    }

    #[test]
    fn detect_zero_width_space() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{200B}world"; // Zero-width space

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::ZeroWidth);
    }

    #[test]
    fn detect_rtl_override() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{202E}world"; // RTL override

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Bidirectional);
    }

    #[test]
    fn detect_cyrillic_homoglyph() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hеllo"; // Cyrillic 'е' instead of Latin 'e'

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Homoglyph);
    }

    #[test]
    fn detect_tag_characters() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{E0001}world"; // Language tag

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Tag);
    }

    #[test]
    fn clean_text_no_detection() {
        let detector = UnicodeHiddenDetector::new();
        let text = "This is a normal tool description with no hidden characters.";

        let suspicious = detector.detect_suspicious_unicode(text);
        assert!(suspicious.is_empty());
    }

    #[test]
    fn check_tool_with_hidden_chars() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool(
            "test\u{200B}tool",
            Some("A tool with hidden\u{202E}text"),
        )];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 2); // One for name, one for description
    }

    #[test]
    fn severity_assessment() {
        let detector = UnicodeHiddenDetector::new();

        // RTL is critical
        assert_eq!(
            detector.assess_severity(&[UnicodeCategory::Bidirectional]),
            Severity::Critical
        );

        // Zero-width is high
        assert_eq!(
            detector.assess_severity(&[UnicodeCategory::ZeroWidth]),
            Severity::High
        );

        // Private use is medium
        assert_eq!(
            detector.assess_severity(&[UnicodeCategory::PrivateUse]),
            Severity::Medium
        );
    }

    #[test]
    fn fullwidth_detection() {
        let detector = UnicodeHiddenDetector::new();
        let text = "exec\u{FF45}cute"; // Fullwidth 'e'

        let suspicious = detector.detect_suspicious_unicode(text);
        assert!(!suspicious.is_empty());
        assert_eq!(suspicious[0].category, UnicodeCategory::Homoglyph);
    }

    // Test 1: UnicodeHiddenDetector creation
    #[test]
    fn test_detector_creation() {
        let detector = UnicodeHiddenDetector::new();
        let detector_default = UnicodeHiddenDetector;

        let text = "normal text";
        assert!(detector.detect_suspicious_unicode(text).is_empty());
        assert!(detector_default.detect_suspicious_unicode(text).is_empty());
    }

    // Test 2: check_tools with safe tools
    #[test]
    fn test_check_tools_with_safe_tools() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![
            make_tool("safe_tool", Some("This is a safe description")),
            make_tool("another_tool", Some("No hidden characters here")),
            make_tool("third_tool", None),
        ];

        let findings = detector.check_tools(&tools);
        assert!(findings.is_empty());
    }

    // Test 3: Detection of Left-to-Right Mark
    #[test]
    fn test_detect_ltr_mark() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{200E}world"; // LTR mark

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Bidirectional);
        assert_eq!(suspicious[0].codepoint, 0x200E);
    }

    // Test 4: Detection of Right-to-Left Mark
    #[test]
    fn test_detect_rtl_mark() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{200F}world"; // RTL mark

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Bidirectional);
        assert_eq!(suspicious[0].codepoint, 0x200F);
    }

    // Test 5: Detection of Left-to-Right Embedding
    #[test]
    fn test_detect_ltr_embedding() {
        let detector = UnicodeHiddenDetector::new();
        let text = "test\u{202A}content"; // LTR embedding

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Bidirectional);
    }

    // Test 6: Detection of Right-to-Left Embedding
    #[test]
    fn test_detect_rtl_embedding() {
        let detector = UnicodeHiddenDetector::new();
        let text = "test\u{202B}content"; // RTL embedding

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Bidirectional);
    }

    // Test 7: Detection of Zero Width Non-Joiner
    #[test]
    fn test_detect_zero_width_non_joiner() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{200C}world"; // ZWNJ

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::ZeroWidth);
        assert_eq!(suspicious[0].codepoint, 0x200C);
    }

    // Test 8: Detection of Zero Width Joiner
    #[test]
    fn test_detect_zero_width_joiner() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{200D}world"; // ZWJ

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::ZeroWidth);
        assert_eq!(suspicious[0].codepoint, 0x200D);
    }

    // Test 9: Detection of Byte Order Mark
    #[test]
    fn test_detect_byte_order_mark() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{FEFF}world"; // BOM

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::ZeroWidth);
    }

    // Test 10: Detection of Greek homoglyphs
    #[test]
    fn test_detect_greek_homoglyphs() {
        let detector = UnicodeHiddenDetector::new();
        let text = "helloΑworld"; // Greek capital Alpha

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Homoglyph);
    }

    // Test 11: Detection of mathematical alphanumeric symbols
    #[test]
    fn test_detect_mathematical_symbols() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello𝐀world"; // Mathematical bold A

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Homoglyph);
    }

    // Test 12: Detection of invisible characters
    #[test]
    fn test_detect_word_joiner() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{2060}world"; // Word joiner

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::ZeroWidth);
    }

    // Test 13: Multiple tools with mixed findings
    #[test]
    fn test_multiple_tools_mixed_findings() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![
            make_tool("safe_tool", Some("Normal description")),
            make_tool("bad\u{200B}tool", Some("Also\u{202E}bad")),
            make_tool("another_safe", Some("Clean text")),
        ];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 2); // Only the bad tool has findings
        assert!(findings
            .iter()
            .all(|f| f.location.identifier == "bad\u{200B}tool"));
    }

    // Test 14: Nested unicode characters
    #[test]
    fn test_nested_unicode_in_description() {
        let detector = UnicodeHiddenDetector::new();
        let text = "start\u{200B}middle\u{202E}end\u{200C}finish";

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 3);
        assert_eq!(suspicious[0].category, UnicodeCategory::ZeroWidth);
        assert_eq!(suspicious[1].category, UnicodeCategory::Bidirectional);
        assert_eq!(suspicious[2].category, UnicodeCategory::ZeroWidth);
    }

    // Test 15: Unicode in tool input schemas
    #[test]
    fn test_unicode_in_input_schema_string() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![Tool {
            name: "test_tool".to_string(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "field": {
                        "type": "string",
                        "description": "Field with\u{200B}hidden char"
                    }
                }
            }),
        }];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("test_tool"));
    }

    // Test 16: Unicode in schema keys
    #[test]
    fn test_unicode_in_schema_keys() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![Tool {
            name: "test_tool".to_string(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bad\u{200B}key": {
                        "type": "string"
                    }
                }
            }),
        }];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("test_tool"));
    }

    // Test 17: Empty string edge case
    #[test]
    fn test_empty_string() {
        let detector = UnicodeHiddenDetector::new();
        let text = "";

        let suspicious = detector.detect_suspicious_unicode(text);
        assert!(suspicious.is_empty());
    }

    // Test 18: ASCII-only text
    #[test]
    fn test_ascii_only_text() {
        let detector = UnicodeHiddenDetector::new();
        let text = "The quick brown fox jumps over the lazy dog. 1234567890!@#$%^&*()";

        let suspicious = detector.detect_suspicious_unicode(text);
        assert!(suspicious.is_empty());
    }

    // Test 19: Finding severity for bidirectional is critical
    #[test]
    fn test_finding_severity_critical_for_bidirectional() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("tool", Some("text\u{202E}rtl"))];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    // Test 20: Finding severity for zero-width is high
    #[test]
    fn test_finding_severity_high_for_zero_width() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("tool", Some("text\u{200B}space"))];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    // Test 21: Finding severity for tag characters is high
    #[test]
    fn test_finding_severity_high_for_tag() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("tool", Some("text\u{E0001}tag"))];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    // Test 22: Finding severity for homoglyphs is high
    #[test]
    fn test_finding_severity_high_for_homoglyph() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("tool", Some("tеxt"))]; // Cyrillic е

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    // Test 23: Finding location validation for tool name
    #[test]
    fn test_finding_location_for_tool_name() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("bad\u{200B}tool", None)];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.identifier, "bad\u{200B}tool");
        assert!(findings[0]
            .location
            .context
            .as_ref()
            .unwrap()
            .contains("name"));
    }

    // Test 24: Finding location validation for description
    #[test]
    fn test_finding_location_for_description() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("tool", Some("bad\u{200B}desc"))];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.identifier, "tool");
        assert!(findings[0]
            .location
            .context
            .as_ref()
            .unwrap()
            .contains("description"));
    }

    // Test 25: Private use area detection
    #[test]
    fn test_detect_private_use_area() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{E000}world"; // Private use area

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::PrivateUse);
        assert_eq!(suspicious[0].codepoint, 0xE000);
    }

    // Test 26: Deprecated format characters
    #[test]
    fn test_detect_deprecated_format() {
        let detector = UnicodeHiddenDetector::new();
        let text = "hello\u{206A}world"; // Deprecated format char

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::DeprecatedFormat);
    }

    // Test 27: Combining marks (excessive)
    #[test]
    fn test_detect_excessive_combining() {
        let detector = UnicodeHiddenDetector::new();
        let text = "e\u{0301}\u{0302}\u{0303}\u{0304}"; // e with 4 combining marks

        let suspicious = detector.detect_suspicious_unicode(text);
        assert!(!suspicious.is_empty());
        assert_eq!(suspicious[0].category, UnicodeCategory::Combining);
    }

    // Test 28: Normal combining marks (not excessive)
    #[test]
    fn test_normal_combining_not_detected() {
        let detector = UnicodeHiddenDetector::new();
        let text = "café"; // e with acute accent (single combining mark)

        let suspicious = detector.detect_suspicious_unicode(text);
        // Should not detect single or double combining marks
        assert!(suspicious.is_empty() || suspicious.len() < 2);
    }

    // Test 29: Schema with nested objects
    #[test]
    fn test_schema_nested_objects() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![Tool {
            name: "test_tool".to_string(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "outer": {
                        "type": "object",
                        "properties": {
                            "inner": {
                                "type": "string",
                                "default": "value\u{200B}hidden"
                            }
                        }
                    }
                }
            }),
        }];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .location
            .context
            .as_ref()
            .unwrap()
            .contains("schema"));
    }

    // Test 30: Schema with arrays
    #[test]
    fn test_schema_with_arrays() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![Tool {
            name: "test_tool".to_string(),
            description: None,
            input_schema: json!({
                "type": "array",
                "items": [
                    "clean",
                    "bad\u{200B}item",
                    "also_clean"
                ]
            }),
        }];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
    }

    // Test 31: Position tracking in suspicious chars
    #[test]
    fn test_position_tracking() {
        let detector = UnicodeHiddenDetector::new();
        let text = "abc\u{200B}def\u{202E}ghi";

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 2);
        assert_eq!(suspicious[0].position, 3); // Position after "abc"
        assert_eq!(suspicious[1].position, 9); // Position after "abc\u{200B}def" (3 + 3 + 3 bytes for UTF-8)
    }

    // Test 32: Finding evidence contains character details
    #[test]
    fn test_finding_evidence_details() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("tool", Some("test\u{200B}text"))];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].evidence.is_empty());
        assert!(findings[0].evidence[0].data.contains("U+200B"));
    }

    // Test 33: Finding remediation is present
    #[test]
    fn test_finding_remediation_present() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("tool", Some("test\u{200B}text"))];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].remediation.is_empty());
        assert!(findings[0].remediation.contains("ASCII"));
    }

    // Test 34: Finding CWE reference is set
    #[test]
    fn test_finding_cwe_set() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("tool", Some("test\u{200B}text"))];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].references.iter().any(|r| r.id.contains("116")));
    }

    // Test 35: Finding rule ID is correct
    #[test]
    fn test_finding_rule_id() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("tool", Some("test\u{200B}text"))];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "MCP-SEC-044");
    }

    // Test 36: UnicodeCategory Display trait
    #[test]
    fn test_unicode_category_display() {
        assert_eq!(format!("{}", UnicodeCategory::ZeroWidth), "zero-width");
        assert_eq!(
            format!("{}", UnicodeCategory::Bidirectional),
            "bidirectional-control"
        );
        assert_eq!(format!("{}", UnicodeCategory::Tag), "tag-character");
        assert_eq!(format!("{}", UnicodeCategory::Homoglyph), "homoglyph");
        assert_eq!(format!("{}", UnicodeCategory::Combining), "combining");
        assert_eq!(format!("{}", UnicodeCategory::PrivateUse), "private-use");
        assert_eq!(
            format!("{}", UnicodeCategory::DeprecatedFormat),
            "deprecated-format"
        );
    }

    // Test 37: Multiple unicode categories in one text
    #[test]
    fn test_multiple_categories_severity() {
        let detector = UnicodeHiddenDetector::new();

        // Test that bidirectional takes precedence
        assert_eq!(
            detector.assess_severity(&[
                UnicodeCategory::ZeroWidth,
                UnicodeCategory::Bidirectional,
                UnicodeCategory::PrivateUse
            ]),
            Severity::Critical
        );

        // Test that zero-width takes precedence over others (except bidirectional)
        assert_eq!(
            detector.assess_severity(&[UnicodeCategory::ZeroWidth, UnicodeCategory::PrivateUse]),
            Severity::High
        );
    }

    // Test 38: Tool with only name having unicode
    #[test]
    fn test_tool_name_only_unicode() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![make_tool("bad\u{200B}name", None)];

        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .location
            .context
            .as_ref()
            .unwrap()
            .contains("name"));
    }

    // Test 39: Dotless i and j homoglyphs
    #[test]
    fn test_dotless_homoglyphs() {
        let detector = UnicodeHiddenDetector::new();
        let text = "admın"; // Dotless i

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Homoglyph);
    }

    // Test 40: Roman numeral homoglyphs
    #[test]
    fn test_roman_numeral_homoglyphs() {
        let detector = UnicodeHiddenDetector::new();
        let text = "testⅠdata"; // Roman numeral I

        let suspicious = detector.detect_suspicious_unicode(text);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].category, UnicodeCategory::Homoglyph);
    }

    // Additional coverage tests for untested code paths

    #[test]
    fn test_function_application() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{2061}b")[0].category,
            UnicodeCategory::ZeroWidth
        );
    }

    #[test]
    fn test_invisible_times() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{2062}b")[0].category,
            UnicodeCategory::ZeroWidth
        );
    }

    #[test]
    fn test_invisible_separator() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{2063}b")[0].category,
            UnicodeCategory::ZeroWidth
        );
    }

    #[test]
    fn test_invisible_plus() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{2064}b")[0].category,
            UnicodeCategory::ZeroWidth
        );
    }

    #[test]
    fn test_mongolian_separator() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{180E}b")[0].category,
            UnicodeCategory::ZeroWidth
        );
    }

    #[test]
    fn test_pop_dir_format() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{202C}b")[0].category,
            UnicodeCategory::Bidirectional
        );
    }

    #[test]
    fn test_ltr_override_char() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{202D}b")[0].category,
            UnicodeCategory::Bidirectional
        );
    }

    #[test]
    fn test_ltr_isolate_char() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{2066}b")[0].category,
            UnicodeCategory::Bidirectional
        );
    }

    #[test]
    fn test_rtl_isolate_char() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{2067}b")[0].category,
            UnicodeCategory::Bidirectional
        );
    }

    #[test]
    fn test_first_strong_isolate_char() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{2068}b")[0].category,
            UnicodeCategory::Bidirectional
        );
    }

    #[test]
    fn test_pop_dir_isolate() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{2069}b")[0].category,
            UnicodeCategory::Bidirectional
        );
    }

    #[test]
    fn test_tag_upper_range() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{E0100}b")[0].category,
            UnicodeCategory::Tag
        );
    }

    #[test]
    fn test_private_use_supp_a() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{F0000}b")[0].category,
            UnicodeCategory::PrivateUse
        );
    }

    #[test]
    fn test_private_use_supp_b() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{100000}b")[0].category,
            UnicodeCategory::PrivateUse
        );
    }

    #[test]
    fn test_deprecated_format_end() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("a\u{206F}b")[0].category,
            UnicodeCategory::DeprecatedFormat
        );
    }

    #[test]
    fn test_combining_extended() {
        let detector = UnicodeHiddenDetector::new();
        let text = "e\u{1AB0}\u{1AB1}\u{1AB2}\u{1AB3}";
        assert_eq!(
            detector.detect_suspicious_unicode(text)[0].category,
            UnicodeCategory::Combining
        );
    }

    #[test]
    fn test_combining_supplement() {
        let detector = UnicodeHiddenDetector::new();
        let text = "e\u{1DC0}\u{1DC1}\u{1DC2}\u{1DC3}";
        assert_eq!(
            detector.detect_suspicious_unicode(text)[0].category,
            UnicodeCategory::Combining
        );
    }

    #[test]
    fn test_combining_symbols() {
        let detector = UnicodeHiddenDetector::new();
        let text = "a\u{20D0}\u{20D1}\u{20D2}\u{20D3}";
        assert_eq!(
            detector.detect_suspicious_unicode(text)[0].category,
            UnicodeCategory::Combining
        );
    }

    #[test]
    fn test_combining_half() {
        let detector = UnicodeHiddenDetector::new();
        let text = "a\u{FE20}\u{FE21}\u{FE22}\u{FE23}";
        assert_eq!(
            detector.detect_suspicious_unicode(text)[0].category,
            UnicodeCategory::Combining
        );
    }

    #[test]
    fn test_truncate_many_chars() {
        let detector = UnicodeHiddenDetector::new();
        let text = "a\u{200B}b\u{200B}c\u{200B}d\u{200B}e\u{200B}f\u{200B}g";
        let tools = vec![make_tool("t", Some(text))];
        let findings = detector.check_tools(&tools);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_truncate_long_text() {
        let detector = UnicodeHiddenDetector::new();
        let long = format!("{}\u{200B}{}", "a".repeat(30), "b".repeat(30));
        let tools = vec![make_tool("t", Some(&long))];
        let findings = detector.check_tools(&tools);
        assert!(findings[0].evidence[0].description.contains("..."));
    }

    #[test]
    fn test_schema_nulls() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![Tool {
            name: "t".into(),
            description: None,
            input_schema: json!({"f": null}),
        }];
        assert!(detector.check_tools(&tools).is_empty());
    }

    #[test]
    fn test_schema_bools() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![Tool {
            name: "t".into(),
            description: None,
            input_schema: json!({"r": true}),
        }];
        assert!(detector.check_tools(&tools).is_empty());
    }

    #[test]
    fn test_schema_numbers() {
        let detector = UnicodeHiddenDetector::new();
        let tools = vec![Tool {
            name: "t".into(),
            description: None,
            input_schema: json!({"m": 100}),
        }];
        assert!(detector.check_tools(&tools).is_empty());
    }

    #[test]
    fn test_cyrillic_upper() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.detect_suspicious_unicode("Н")[0].category,
            UnicodeCategory::Homoglyph
        );
    }

    #[test]
    fn test_greek_upper() {
        let detector = UnicodeHiddenDetector::new();
        let chars = detector.detect_suspicious_unicode("ΒΕΖΗ");
        assert!(chars.len() >= 4);
        assert!(chars
            .iter()
            .all(|c| c.category == UnicodeCategory::Homoglyph));
    }

    #[test]
    fn test_math_italic() {
        let detector = UnicodeHiddenDetector::new();
        let chars = detector.detect_suspicious_unicode("𝑨𝒁");
        assert_eq!(chars.len(), 2);
        assert!(chars
            .iter()
            .all(|c| c.category == UnicodeCategory::Homoglyph));
    }

    #[test]
    fn test_sans_bold() {
        let detector = UnicodeHiddenDetector::new();
        let chars = detector.detect_suspicious_unicode("𝗔𝗭");
        assert_eq!(chars.len(), 2);
        assert!(chars
            .iter()
            .all(|c| c.category == UnicodeCategory::Homoglyph));
    }

    #[test]
    fn test_sans_italic() {
        let detector = UnicodeHiddenDetector::new();
        let chars = detector.detect_suspicious_unicode("𝘈𝘡");
        assert_eq!(chars.len(), 2);
        assert!(chars
            .iter()
            .all(|c| c.category == UnicodeCategory::Homoglyph));
    }

    #[test]
    fn test_confusables() {
        let detector = UnicodeHiddenDetector::new();
        let chars = detector.detect_suspicious_unicode("ıȷɑɡℓ℮");
        assert!(chars.len() >= 6);
        assert!(chars
            .iter()
            .all(|c| c.category == UnicodeCategory::Homoglyph));
    }

    #[test]
    fn test_severity_combining_cat() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.assess_severity(&[UnicodeCategory::Combining]),
            Severity::Medium
        );
    }

    #[test]
    fn test_severity_deprecated_cat() {
        let detector = UnicodeHiddenDetector::new();
        assert_eq!(
            detector.assess_severity(&[UnicodeCategory::DeprecatedFormat]),
            Severity::Medium
        );
    }

    #[test]
    fn test_default_detector() {
        let detector = UnicodeHiddenDetector::default();
        assert!(detector.detect_suspicious_unicode("normal").is_empty());
    }

    #[test]
    fn test_empty_tool_list() {
        let detector = UnicodeHiddenDetector::new();
        assert!(detector.check_tools(&Vec::<Tool>::new()).is_empty());
    }

    #[test]
    fn test_mixed_combining() {
        let detector = UnicodeHiddenDetector::new();
        let text = "a\u{0301}\u{1AB0}\u{20D0}\u{FE20}";
        assert_eq!(
            detector.detect_suspicious_unicode(text)[0].category,
            UnicodeCategory::Combining
        );
    }
}
