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
}
