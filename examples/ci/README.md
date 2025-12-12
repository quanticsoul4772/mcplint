# MCPLint CI Integration Examples

This directory contains example CI/CD workflows for integrating MCPLint security scanning into your development pipeline.

## Available Examples

### 1. Simple GitHub Actions (`github-actions-simple.yml`)

A minimal workflow for basic security scanning. Good starting point for:
- Quick integration
- Small projects
- Initial testing

### 2. Full GitHub Actions (`github-actions-mcp-scan.yml`)

A comprehensive workflow with advanced features:
- SARIF output for GitHub Code Scanning integration
- Matrix builds for multiple MCP servers
- Baseline comparison for PR regression detection
- Automatic security summary reports
- Artifact preservation for audit trails

## Quick Start

### Option 1: Simple Integration

```bash
# Copy the simple workflow to your project
cp github-actions-simple.yml /path/to/your/mcp-server/.github/workflows/

# Modify the server command as needed
```

### Option 2: Full Integration with SARIF

```bash
# Copy the full workflow to your project
cp github-actions-mcp-scan.yml /path/to/your/mcp-server/.github/workflows/

# Configure your servers in the matrix section
```

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MCPLINT_VERSION` | MCPLint version to install | `0.1.0` |
| `FAIL_ON_FINDINGS` | Fail build on security findings | `false` |

### Scan Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `quick` | Fast scan, basic checks | Development/testing |
| `standard` | Balanced scan | CI/CD pipelines |
| `comprehensive` | Deep scan, all checks | Security audits |

## SARIF Integration

SARIF (Static Analysis Results Interchange Format) allows MCPLint findings to appear directly in GitHub's Security tab.

### Enabling SARIF Upload

1. Ensure your workflow has the required permissions:
   ```yaml
   permissions:
     security-events: write
     contents: read
   ```

2. Run MCPLint with SARIF output:
   ```bash
   mcplint scan <server> --output sarif > results.sarif
   ```

3. Upload results:
   ```yaml
   - uses: github/codeql-action/upload-sarif@v3
     with:
       sarif_file: results.sarif
   ```

## Watch Mode for Development

For local development with continuous scanning:

```bash
# Watch for file changes and re-scan automatically
mcplint watch my-server --watch-path ./src --debounce 1000

# With differential display (shows new/fixed issues)
# This is enabled by default in watch mode
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings |
| 1 | Success, findings detected |
| 2 | Error during scan |
| 3 | Partial success |
| 4 | Timeout |

## GitLab CI Example

```yaml
# .gitlab-ci.yml
security-scan:
  stage: test
  image: rust:latest
  before_script:
    - cargo install mcplint
  script:
    - mcplint scan $MCP_SERVER_CMD --profile standard
  artifacts:
    reports:
      sast: results.sarif
```

## Jenkins Pipeline Example

```groovy
// Jenkinsfile
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'cargo install mcplint'
                sh 'mcplint scan ./my-mcp-server --profile standard --output sarif > results.sarif'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'results.sarif'
                }
            }
        }
    }
}
```

## Best Practices

1. **Start with Standard Profile**: Use `--profile standard` for CI/CD pipelines. Reserve `comprehensive` for periodic security audits.

2. **Enable SARIF for PRs**: Upload SARIF results to enable GitHub Code Scanning annotations on pull requests.

3. **Set Up Baseline Comparison**: Track new vs fixed issues to prevent security regressions.

4. **Don't Fail on All Findings**: Start with `FAIL_ON_FINDINGS=false` and gradually increase strictness.

5. **Use Watch Mode Locally**: Enable `mcplint watch` during development to catch issues early.

## Support

For issues or feature requests, please visit:
https://github.com/quanticsoul4772/mcplint/issues
