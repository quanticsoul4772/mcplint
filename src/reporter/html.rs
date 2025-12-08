//! HTML Report Generator
//!
//! Generates rich HTML reports for security scan results with:
//! - Severity distribution charts
//! - Detailed finding cards
//! - Remediation guidance
//! - Executive summary

use crate::scanner::{ScanResults, Severity};

/// Generate an HTML report from scan results
pub fn generate_html(results: &ScanResults) -> String {
    let severity_data = get_severity_data(results);
    let findings_html = generate_findings_html(results);
    let summary_html = generate_summary_html(results);
    let timestamp = chrono::Utc::now().to_rfc3339();

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCPLint Security Report - {server}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --accent-blue: #58a6ff;
            --severity-critical: #f85149;
            --severity-high: #f0883e;
            --severity-medium: #d29922;
            --severity-low: #3fb950;
            --severity-info: #8b949e;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}

        h1 {{
            font-size: 1.75rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }}

        .meta {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .summary-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
        }}

        .summary-card.critical {{
            border-left: 4px solid var(--severity-critical);
        }}

        .summary-card.high {{
            border-left: 4px solid var(--severity-high);
        }}

        .summary-card.medium {{
            border-left: 4px solid var(--severity-medium);
        }}

        .summary-card.low {{
            border-left: 4px solid var(--severity-low);
        }}

        .summary-card.info {{
            border-left: 4px solid var(--severity-info);
        }}

        .summary-card .label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 0.25rem;
        }}

        .summary-card .value {{
            font-size: 2rem;
            font-weight: 600;
        }}

        .chart-container {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}

        .chart-title {{
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 1rem;
        }}

        .bar-chart {{
            display: flex;
            height: 24px;
            border-radius: 4px;
            overflow: hidden;
            background: var(--bg-tertiary);
        }}

        .bar-segment {{
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
            min-width: 30px;
        }}

        .bar-segment.critical {{ background: var(--severity-critical); }}
        .bar-segment.high {{ background: var(--severity-high); }}
        .bar-segment.medium {{ background: var(--severity-medium); }}
        .bar-segment.low {{ background: var(--severity-low); }}
        .bar-segment.info {{ background: var(--severity-info); }}

        .chart-legend {{
            display: flex;
            gap: 1.5rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
        }}

        .legend-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}

        .legend-dot.critical {{ background: var(--severity-critical); }}
        .legend-dot.high {{ background: var(--severity-high); }}
        .legend-dot.medium {{ background: var(--severity-medium); }}
        .legend-dot.low {{ background: var(--severity-low); }}
        .legend-dot.info {{ background: var(--severity-info); }}

        .findings-section {{
            margin-top: 2rem;
        }}

        .section-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }}

        .finding-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}

        .finding-header {{
            padding: 1rem;
            display: flex;
            align-items: flex-start;
            gap: 1rem;
            border-bottom: 1px solid var(--border-color);
        }}

        .severity-badge {{
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            flex-shrink: 0;
        }}

        .severity-badge.critical {{
            background: var(--severity-critical);
            color: white;
        }}

        .severity-badge.high {{
            background: var(--severity-high);
            color: white;
        }}

        .severity-badge.medium {{
            background: var(--severity-medium);
            color: black;
        }}

        .severity-badge.low {{
            background: var(--severity-low);
            color: black;
        }}

        .severity-badge.info {{
            background: var(--severity-info);
            color: white;
        }}

        .finding-title {{
            font-weight: 600;
            margin-bottom: 0.25rem;
        }}

        .finding-rule {{
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}

        .finding-body {{
            padding: 1rem;
        }}

        .finding-description {{
            margin-bottom: 1rem;
        }}

        .finding-detail {{
            margin-bottom: 0.75rem;
        }}

        .finding-detail-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 0.25rem;
        }}

        .finding-detail-value {{
            font-size: 0.875rem;
            background: var(--bg-tertiary);
            padding: 0.5rem;
            border-radius: 4px;
            font-family: monospace;
            word-break: break-all;
        }}

        .remediation {{
            background: rgba(63, 185, 80, 0.1);
            border: 1px solid rgba(63, 185, 80, 0.3);
            border-radius: 4px;
            padding: 1rem;
            margin-top: 1rem;
        }}

        .remediation-title {{
            font-weight: 600;
            color: var(--severity-low);
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
        }}

        .references {{
            margin-top: 1rem;
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}

        .reference-tag {{
            background: var(--bg-tertiary);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            color: var(--accent-blue);
            text-decoration: none;
        }}

        .reference-tag:hover {{
            background: var(--border-color);
        }}

        .no-findings {{
            background: rgba(63, 185, 80, 0.1);
            border: 1px solid rgba(63, 185, 80, 0.3);
            border-radius: 6px;
            padding: 2rem;
            text-align: center;
        }}

        .no-findings-icon {{
            font-size: 3rem;
            margin-bottom: 1rem;
        }}

        .no-findings-title {{
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--severity-low);
            margin-bottom: 0.5rem;
        }}

        footer {{
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}

        @media print {{
            body {{
                background: white;
                color: black;
            }}

            .summary-card, .chart-container, .finding-card {{
                border-color: #ddd;
                background: white;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>MCPLint Security Report</h1>
            <div class="meta">
                <div>Server: <strong>{server}</strong></div>
                <div>Profile: <strong>{profile}</strong></div>
                <div>Generated: {timestamp}</div>
                <div>Duration: {duration_ms}ms | Checks: {total_checks}</div>
            </div>
        </header>

        {summary_html}

        <div class="chart-container">
            <div class="chart-title">Severity Distribution</div>
            {severity_chart}
            <div class="chart-legend">
                <div class="legend-item">
                    <div class="legend-dot critical"></div>
                    <span>Critical ({critical})</span>
                </div>
                <div class="legend-item">
                    <div class="legend-dot high"></div>
                    <span>High ({high})</span>
                </div>
                <div class="legend-item">
                    <div class="legend-dot medium"></div>
                    <span>Medium ({medium})</span>
                </div>
                <div class="legend-item">
                    <div class="legend-dot low"></div>
                    <span>Low ({low})</span>
                </div>
                <div class="legend-item">
                    <div class="legend-dot info"></div>
                    <span>Info ({info})</span>
                </div>
            </div>
        </div>

        <div class="findings-section">
            <h2 class="section-title">Findings ({total_findings})</h2>
            {findings_html}
        </div>

        <footer>
            Generated by MCPLint v{version} |
            <a href="https://github.com/quanticsoul4772/mcplint" style="color: var(--accent-blue);">Documentation</a>
        </footer>
    </div>
</body>
</html>"##,
        server = html_escape(&results.server),
        profile = html_escape(&results.profile),
        timestamp = timestamp,
        duration_ms = results.duration_ms,
        total_checks = results.total_checks,
        summary_html = summary_html,
        severity_chart = generate_severity_chart(&severity_data),
        critical = severity_data.critical,
        high = severity_data.high,
        medium = severity_data.medium,
        low = severity_data.low,
        info = severity_data.info,
        total_findings = results.findings.len(),
        findings_html = findings_html,
        version = env!("CARGO_PKG_VERSION"),
    )
}

struct SeverityData {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    total: usize,
}

fn get_severity_data(results: &ScanResults) -> SeverityData {
    SeverityData {
        critical: results.summary.critical,
        high: results.summary.high,
        medium: results.summary.medium,
        low: results.summary.low,
        info: results.summary.info,
        total: results.findings.len(),
    }
}

fn generate_severity_chart(data: &SeverityData) -> String {
    if data.total == 0 {
        return r#"<div class="bar-chart"><div class="bar-segment info" style="width: 100%;">No findings</div></div>"#.to_string();
    }

    let mut segments = Vec::new();
    let total = data.total as f64;

    if data.critical > 0 {
        let pct = (data.critical as f64 / total * 100.0).round();
        segments.push(format!(
            r#"<div class="bar-segment critical" style="width: {}%;">{}</div>"#,
            pct, data.critical
        ));
    }

    if data.high > 0 {
        let pct = (data.high as f64 / total * 100.0).round();
        segments.push(format!(
            r#"<div class="bar-segment high" style="width: {}%;">{}</div>"#,
            pct, data.high
        ));
    }

    if data.medium > 0 {
        let pct = (data.medium as f64 / total * 100.0).round();
        segments.push(format!(
            r#"<div class="bar-segment medium" style="width: {}%;">{}</div>"#,
            pct, data.medium
        ));
    }

    if data.low > 0 {
        let pct = (data.low as f64 / total * 100.0).round();
        segments.push(format!(
            r#"<div class="bar-segment low" style="width: {}%;">{}</div>"#,
            pct, data.low
        ));
    }

    if data.info > 0 {
        let pct = (data.info as f64 / total * 100.0).round();
        segments.push(format!(
            r#"<div class="bar-segment info" style="width: {}%;">{}</div>"#,
            pct, data.info
        ));
    }

    format!(r#"<div class="bar-chart">{}</div>"#, segments.join(""))
}

fn generate_summary_html(results: &ScanResults) -> String {
    format!(
        r#"<div class="summary-grid">
            <div class="summary-card critical">
                <div class="label">Critical</div>
                <div class="value">{}</div>
            </div>
            <div class="summary-card high">
                <div class="label">High</div>
                <div class="value">{}</div>
            </div>
            <div class="summary-card medium">
                <div class="label">Medium</div>
                <div class="value">{}</div>
            </div>
            <div class="summary-card low">
                <div class="label">Low</div>
                <div class="value">{}</div>
            </div>
            <div class="summary-card info">
                <div class="label">Info</div>
                <div class="value">{}</div>
            </div>
        </div>"#,
        results.summary.critical,
        results.summary.high,
        results.summary.medium,
        results.summary.low,
        results.summary.info,
    )
}

fn generate_findings_html(results: &ScanResults) -> String {
    if results.findings.is_empty() {
        return r#"<div class="no-findings">
            <div class="no-findings-icon">✓</div>
            <div class="no-findings-title">No Security Issues Found</div>
            <div>The scan completed successfully with no vulnerabilities detected.</div>
        </div>"#
            .to_string();
    }

    // Sort findings by severity (critical first)
    let mut sorted_findings = results.findings.clone();
    sorted_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    sorted_findings
        .iter()
        .map(|f| {
            let severity_class = match f.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };

            let location_html = if !f.location.component.is_empty() {
                format!(
                    r#"<div class="finding-detail">
                        <div class="finding-detail-label">Location</div>
                        <div class="finding-detail-value">{}: {}</div>
                    </div>"#,
                    html_escape(&f.location.component),
                    html_escape(&f.location.identifier)
                )
            } else {
                String::new()
            };

            let evidence_html = if !f.evidence.is_empty() {
                let evidence_items: Vec<String> = f
                    .evidence
                    .iter()
                    .map(|e| {
                        format!(
                            r#"<div class="finding-detail">
                                <div class="finding-detail-label">{:?}</div>
                                <div class="finding-detail-value">{}</div>
                            </div>"#,
                            e.kind,
                            html_escape(&e.description)
                        )
                    })
                    .collect();
                evidence_items.join("")
            } else {
                String::new()
            };

            let remediation_html = if !f.remediation.is_empty() {
                format!(
                    r#"<div class="remediation">
                        <div class="remediation-title">Remediation</div>
                        <div>{}</div>
                    </div>"#,
                    html_escape(&f.remediation)
                )
            } else {
                String::new()
            };

            let references_html = if !f.references.is_empty() {
                let refs: Vec<String> = f
                    .references
                    .iter()
                    .map(|r| {
                        if let Some(url) = &r.url {
                            format!(
                                r#"<a href="{}" class="reference-tag" target="_blank">{}</a>"#,
                                html_escape(url),
                                html_escape(&r.id)
                            )
                        } else {
                            format!(
                                r#"<span class="reference-tag">{}</span>"#,
                                html_escape(&r.id)
                            )
                        }
                    })
                    .collect();
                format!(r#"<div class="references">{}</div>"#, refs.join(""))
            } else {
                String::new()
            };

            format!(
                r#"<div class="finding-card">
                    <div class="finding-header">
                        <span class="severity-badge {severity_class}">{severity}</span>
                        <div>
                            <div class="finding-title">{title}</div>
                            <div class="finding-rule">{rule_id}</div>
                        </div>
                    </div>
                    <div class="finding-body">
                        <div class="finding-description">{description}</div>
                        {location_html}
                        {evidence_html}
                        {remediation_html}
                        {references_html}
                    </div>
                </div>"#,
                severity_class = severity_class,
                severity = f.severity.as_str().to_uppercase(),
                title = html_escape(&f.title),
                rule_id = html_escape(&f.rule_id),
                description = html_escape(&f.description),
                location_html = location_html,
                evidence_html = evidence_html,
                remediation_html = remediation_html,
                references_html = references_html,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Finding, ScanProfile};

    #[test]
    fn generate_empty_report() {
        let results = ScanResults::new("test-server", ScanProfile::Standard);
        let html = generate_html(&results);

        assert!(html.contains("MCPLint Security Report"));
        assert!(html.contains("test-server"));
        assert!(html.contains("No Security Issues Found"));
    }

    #[test]
    fn generate_report_with_findings() {
        let mut results = ScanResults::new("vulnerable-server", ScanProfile::Full);
        results.add_finding(Finding::new(
            "MCP-INJ-001",
            Severity::Critical,
            "Command Injection",
            "Found command injection vulnerability",
        ));
        results.add_finding(Finding::new(
            "MCP-AUTH-001",
            Severity::High,
            "Missing Authentication",
            "Server lacks authentication",
        ));

        let html = generate_html(&results);

        assert!(html.contains("vulnerable-server"));
        assert!(html.contains("Command Injection"));
        assert!(html.contains("Missing Authentication"));
        assert!(html.contains("CRITICAL"));
        assert!(html.contains("HIGH"));
    }

    #[test]
    fn html_escape_works() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"test\""), "&quot;test&quot;");
    }

    #[test]
    fn severity_chart_generation() {
        let data = SeverityData {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            info: 0,
            total: 10,
        };

        let chart = generate_severity_chart(&data);
        assert!(chart.contains("bar-segment critical"));
        assert!(chart.contains("bar-segment high"));
        assert!(chart.contains("bar-segment medium"));
        assert!(chart.contains("bar-segment low"));
    }
}
