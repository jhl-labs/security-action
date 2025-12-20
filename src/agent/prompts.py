"""AI Agent 프롬프트 템플릿"""

SYSTEM_PROMPT = """You are a senior security engineer reviewing code for vulnerabilities.
Your role is to analyze security findings from automated scanners and provide:
1. Accurate assessment of the vulnerability
2. Clear explanation of the security impact
3. Actionable remediation suggestions
4. Code fixes when possible

Be concise but thorough. Focus on practical security implications.
If a finding appears to be a false positive, explain why.

Always respond in a structured format as requested."""


ANALYZE_FINDING_PROMPT = """Analyze this security finding and determine if it's a real vulnerability or false positive.

## Scanner Finding
- Scanner: {scanner}
- Rule ID: {rule_id}
- Severity: {severity}
- Message: {message}
- File: {file_path}:{line_start}

## Code Context
```{language}
{code_snippet}
```

## Surrounding Code
```{language}
{surrounding_code}
```

Analyze this finding and respond in the following JSON format:
{{
    "category": "<category: secret_exposure|sql_injection|xss|command_injection|path_traversal|insecure_deserialization|vulnerable_dependency|hardcoded_credentials|insecure_crypto|other>",
    "severity": "<severity: critical|high|medium|low|info>",
    "title": "<short title>",
    "description": "<detailed description of the vulnerability>",
    "impact": "<potential security impact if exploited>",
    "is_false_positive": <true|false>,
    "false_positive_reason": "<reason if false positive, null otherwise>",
    "confidence": <0.0-1.0>
}}"""


GENERATE_REMEDIATION_PROMPT = """Based on the security analysis, provide remediation guidance.

## Finding Analysis
- Category: {category}
- Severity: {severity}
- Title: {title}
- Description: {description}
- Impact: {impact}

## Vulnerable Code
```{language}
{code_snippet}
```

Provide remediation in the following JSON format:
{{
    "summary": "<one-line summary of the fix>",
    "detailed_explanation": "<step-by-step explanation of how to fix>",
    "code_fix": "<corrected code snippet or null if not applicable>",
    "references": ["<relevant security documentation URLs>"],
    "effort_estimate": "<low|medium|high>"
}}"""


GENERATE_PR_COMMENT_PROMPT = """Generate a GitHub PR comment for this security finding.

## Analysis
- Title: {title}
- Severity: {severity}
- Category: {category}
- Description: {description}
- Impact: {impact}

## Location
- File: {file_path}
- Line: {line_start}

## Remediation
- Summary: {remediation_summary}
- Fix: {code_fix}

Generate a concise, actionable PR comment in Markdown format.
Include:
1. A clear title with severity emoji
2. Brief description of the issue
3. The fix suggestion
4. Optional: link to documentation

Keep it under 500 characters when possible."""


GENERATE_SUMMARY_PROMPT = """Generate an executive summary of the security review.

## Findings Overview
Total findings reviewed: {total_findings}
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

## Categories Found
{categories}

## Key Findings
{key_findings}

Generate a brief executive summary (3-5 sentences) highlighting:
1. Overall security posture
2. Most critical issues requiring immediate attention
3. General recommendations

Format as Markdown."""
