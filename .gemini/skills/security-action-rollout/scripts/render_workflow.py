#!/usr/bin/env python3
"""Render a security-action workflow from simple parameters."""

from __future__ import annotations

import argparse
from pathlib import Path


BOOL_MAP = {
    "1": True,
    "true": True,
    "yes": True,
    "y": True,
    "on": True,
    "0": False,
    "false": False,
    "no": False,
    "n": False,
    "off": False,
}


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized not in BOOL_MAP:
        raise argparse.ArgumentTypeError(f"Invalid boolean value: {value}")
    return BOOL_MAP[normalized]


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def format_runs_on(labels: list[str]) -> list[str]:
    if len(labels) == 1:
        return [f"    runs-on: {labels[0]}"]

    lines = ["    runs-on:"]
    for label in labels:
        lines.append(f"      - {label}")
    return lines


def build_events(
    events: list[str],
    target_branch: str,
    pr_types: list[str],
    schedule_cron: str | None,
) -> list[str]:
    lines = ["on:"]
    lowered = {event.lower() for event in events}

    if "pull_request" in lowered:
        types = ", ".join(pr_types)
        lines.extend(
            [
                "  pull_request:",
                f"    branches: [{target_branch}]",
                f"    types: [{types}]",
            ]
        )

    if "push" in lowered:
        lines.extend(["  push:", f"    branches: [{target_branch}]"])

    if "workflow_dispatch" in lowered:
        lines.append("  workflow_dispatch:")

    if "schedule" in lowered and schedule_cron:
        lines.extend(["  schedule:", f"    - cron: '{schedule_cron}'"])

    return lines


def build_permissions(upload_sarif: bool) -> list[str]:
    lines = [
        "    permissions:",
        "      contents: read",
        "      checks: write",
        "      statuses: write",
        "      pull-requests: write",
    ]

    if upload_sarif:
        lines.append("      security-events: write")

    return lines


def build_with_block(args: argparse.Namespace) -> list[str]:
    fail_on_findings = "true" if args.mode == "gate" else "false"
    upload_sarif = "true" if args.upload_sarif else "false"
    parallel = "true" if args.parallel else "false"
    scanner_checks = "true" if args.scanner_checks else "false"
    post_summary = "true" if args.post_summary else "false"
    native_audit = "true" if args.native_audit else "false"

    lines = [
        "        with:",
        "          secret-scan: 'true'",
        "          code-scan: 'true'",
        "          dependency-scan: 'true'",
        f"          native-audit: '{native_audit}'",
        f"          severity-threshold: '{args.severity_threshold}'",
        f"          fail-on-findings: '{fail_on_findings}'",
        f"          upload-sarif: '{upload_sarif}'",
        f"          sarif-category: '{args.sarif_category}'",
        "          fail-on-sarif-upload-error: 'false'",
        f"          scanner-checks: '{scanner_checks}'",
        f"          post-summary: '{post_summary}'",
        f"          parallel: '{parallel}'",
        f"          github-token: {args.github_token_expr}",
    ]

    if args.config_path:
        lines.append(f"          config-path: '{args.config_path}'")

    if args.enable_ai_review:
        lines.extend(
            [
                "          ai-review: 'true'",
                f"          ai-provider: '{args.ai_provider}'",
                f"          ai-model: {args.ai_model_expr}",
            ]
        )
        if args.ai_provider == "anthropic":
            lines.append(f"          anthropic-api-key: {args.anthropic_api_key_expr}")
        else:
            lines.extend(
                [
                    f"          openai-api-key: {args.openai_api_key_expr}",
                    f"          openai-base-url: {args.openai_base_url_expr}",
                ]
            )

    if args.enable_sonar:
        lines.extend(
            [
                "          sonar-scan: 'true'",
                f"          sonar-host-url: {args.sonar_host_url_expr}",
                f"          sonar-token: {args.sonar_token_expr}",
                f"          sonar-project-key: '{args.sonar_project_key}'",
            ]
        )

    return lines


def build_workflow(args: argparse.Namespace) -> str:
    events = parse_csv(args.events)
    if not events:
        raise ValueError("At least one event is required")

    pr_types = parse_csv(args.pr_types)
    if "pull_request" in {event.lower() for event in events} and not pr_types:
        raise ValueError("pr-types must not be empty when pull_request is enabled")

    lines: list[str] = [f"name: {args.workflow_name}", ""]
    lines.extend(build_events(events, args.target_branch, pr_types, args.schedule_cron))
    lines.extend(
        [
            "",
            "jobs:",
            f"  {args.job_name}:",
        ]
    )
    lines.extend(format_runs_on(parse_csv(args.runs_on)))
    lines.extend(build_permissions(args.upload_sarif))
    lines.extend(
        [
            "    steps:",
            "      - uses: actions/checkout@v4",
            "",
            "      - name: Run Security Scan",
            f"        uses: {args.action_ref}",
        ]
    )
    lines.extend(build_with_block(args))
    lines.append("")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render a security-action workflow")

    parser.add_argument("--workflow-name", default="Security Scan")
    parser.add_argument("--job-name", default="security")
    parser.add_argument("--action-ref", default="jhl-labs/security-action@main")
    parser.add_argument("--runs-on", default="ubuntu-latest")

    parser.add_argument("--events", default="pull_request,push")
    parser.add_argument("--target-branch", default="main")
    parser.add_argument("--pr-types", default="opened,synchronize,reopened")
    parser.add_argument("--schedule-cron", default=None)

    parser.add_argument("--mode", choices=["report", "gate"], default="report")
    parser.add_argument("--severity-threshold", default="high")
    parser.add_argument("--upload-sarif", type=parse_bool, default=False)
    parser.add_argument("--sarif-category", default="security-action")

    parser.add_argument("--parallel", type=parse_bool, default=False)
    parser.add_argument("--scanner-checks", type=parse_bool, default=False)
    parser.add_argument("--post-summary", type=parse_bool, default=True)
    parser.add_argument("--native-audit", type=parse_bool, default=False)

    parser.add_argument("--config-path", default=None)
    parser.add_argument("--github-token-expr", default="${{ secrets.GITHUB_TOKEN }}")

    parser.add_argument("--enable-ai-review", type=parse_bool, default=False)
    parser.add_argument("--ai-provider", choices=["openai", "anthropic"], default="openai")
    parser.add_argument("--ai-model-expr", default="${{ secrets.AI_MODEL }}")
    parser.add_argument("--openai-api-key-expr", default="${{ secrets.OPENAI_API_KEY }}")
    parser.add_argument("--openai-base-url-expr", default="${{ secrets.OPENAI_BASE_URL }}")
    parser.add_argument("--anthropic-api-key-expr", default="${{ secrets.ANTHROPIC_API_KEY }}")

    parser.add_argument("--enable-sonar", type=parse_bool, default=False)
    parser.add_argument("--sonar-host-url-expr", default="${{ secrets.SONAR_HOST_URL }}")
    parser.add_argument("--sonar-token-expr", default="${{ secrets.SONAR_TOKEN }}")
    parser.add_argument("--sonar-project-key", default="security-action")

    parser.add_argument(
        "--output",
        default=".github/workflows/security-check.yaml",
        help="Output workflow path",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    content = build_workflow(args)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    print(f"Workflow written: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
