from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


TEXT_EXTENSIONS = {
    "",
    ".cfg",
    ".conf",
    ".cjs",
    ".go",
    ".gyp",
    ".js",
    ".json",
    ".jsonl",
    ".lock",
    ".log",
    ".md",
    ".mjs",
    ".mod",
    ".ps1",
    ".pth",
    ".py",
    ".sum",
    ".tsx",
    ".ts",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

SKIP_DIRS = {
    ".git/objects",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".eggs",
    "site-packages",
    "dist-packages",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
}

AGENT_CONFIG_NAMES = {
    ".mcp.json",
    ".claude.json",
    "settings.json",
}

AGENT_CONFIG_PARTS = {
    ".claude",
    ".cursor",
    ".gemini",
    ".copilot",
}

NESTED_MCP_AGENT_CONFIG_PARTS = {
    ".claude",
    ".cursor",
    ".gemini",
}

DYNAMIC_DNS_PATTERNS = (
    "freemyip.com",
    "duckdns.org",
    "no-ip.com",
    "dynu.net",
    "ddns.net",
    "hopto.org",
    "zapto.org",
)

PUBLIC_FORMATTER_DOMAINS = (
    "jsonformatter.org",
    "codebeautify.org",
)

PUBLIC_FORMATTER_SURFACE_PATTERNS = (
    "/recentlinkspage/json/",
    "/service/getdatafromid",
    "recent links",
    "public recent links",
    "saved paste",
    "shareable url",
    "urlid=",
    "six-hex",
    "public clipboard",
)

NPM_INSTALL_TIME_LIFECYCLE_SCRIPTS = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "preuninstall",
    "uninstall",
    "postuninstall",
}

SHADOWABLE_TOOL_NAMES = {
    "ssh",
    "git",
    "npm",
    "node",
    "python",
    "powershell",
    "gh",
    "claude",
    "codex",
    "composer",
    "pnpm",
    "yarn",
}

CREDENTIAL_ADJACENT_NAMES = {
    ".env",
    ".env.local",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "service-account.json",
    "token.json",
}

CONFIG_REVIEW_NAMES = {
    "openclaw.json",
    "openclaw.config.json",
    "config.json",
    "settings.json",
    ".env",
    ".env.local",
}

DYNATRACE_TOKEN_PATTERN = re.compile(
    r"dt0[cs][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64,}",
    re.IGNORECASE,
)

DYNATRACE_TEAMPCP_REPO_TERMS = (
    "hard-copilot",
    "hard-csc",
    "hard-iam",
    "local-cluster-setup",
    "nonprod-dtappghrunner",
    "prod-copilot",
    "prod-csc",
    "prod-dtappghrunner",
    "prod-iam",
)

DYNATRACE_TEAMPCP_SERVICE_TERMS = (
    "dynatrace.scorecards",
    "dynatrace.security.enrichment",
    "dynatrace.security.operations",
    "dynatrace.security.threats.exploits",
    "dynatrace.sensitive.data.center",
    "dynatrace.services",
    "dynatrace.snowflake.connector",
    "dynatrace.software.lifecycle",
    "dynatrace.specktrack",
    "dynatrace.storage.management",
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    phase2_hint: str
    path: str
    reason: str
    evidence: str
    boundary: str


@dataclass(frozen=True)
class Report:
    root: str
    mode: str = "announce-only"
    mutated: bool = False
    findings: list[Finding] = field(default_factory=list)


def scan_path(root: str | Path) -> Report:
    base = Path(root).resolve()
    findings: list[Finding] = []

    for path in _iter_candidate_files(base):
        rel = _relative_path(base, path)
        path_text = rel.replace("\\", "/")
        findings.extend(_scan_path_surface(path_text))

        content = _read_text(path)
        if content is None:
            continue
        findings.extend(_scan_content(path_text, content))

    return Report(root=str(base), findings=findings)


def render_markdown(report: Report) -> str:
    indicator_count = sum(
        1 for finding in report.findings if finding.category == "indicator"
    )
    exposure_count = sum(
        1 for finding in report.findings if finding.category == "exposure"
    )
    inventory_count = sum(
        1 for finding in report.findings if finding.category == "inventory"
    )
    lines = [
        "# Never-Ending Story Fire Door Report",
        "",
        f"Root: `{report.root}`",
        f"Mode: {report.mode}",
        f"Target mutated: {'yes' if report.mutated else 'no'}",
        f"Indicator matches: {indicator_count}",
        f"Exposure review: {exposure_count}",
        f"Trust-surface inventory: {inventory_count}",
        "",
        "This is an inventory of supply-chain and trust-surface signals. "
        "Findings describe matches, not verdicts.",
        "",
    ]

    if not report.findings:
        lines.append(
            "No findings matched the current rule set. This is not an all-clear "
            "— coverage is intentionally narrow. See Current Coverage Limits."
        )
        return "\n".join(lines) + "\n"

    indicator_findings = [
        finding for finding in report.findings if finding.category == "indicator"
    ]
    exposure_findings = [
        finding for finding in report.findings if finding.category == "exposure"
    ]
    inventory_findings = [
        finding for finding in report.findings if finding.category == "inventory"
    ]

    lines.extend(["## Indicator Matches", ""])
    if indicator_findings:
        _append_findings(lines, indicator_findings)
    else:
        lines.extend(["No indicator matches in the current rule set.", ""])

    lines.extend(["## Exposure Review", ""])
    if exposure_findings:
        _append_findings(lines, exposure_findings)
    else:
        lines.extend(["No exposure-review findings in the current rule set.", ""])

    lines.extend(["## Trust-Surface Inventory", ""])
    if inventory_findings:
        _append_findings(lines, inventory_findings)
    else:
        lines.extend(["No trust-surface inventory findings in the current rule set.", ""])

    lines.extend(
        [
            "## Safety",
            "",
            "This report is announce-only. It did not block, delete, install,",
            "uninstall, edit configs, rotate secrets, or change system settings.",
            "",
        ]
    )
    return "\n".join(lines)


def _append_findings(lines: list[str], findings: list[Finding]) -> None:
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.rule_id}",
                "",
                f"- Severity: {finding.severity}",
                f"- Phase 2 hint (no current action): {finding.phase2_hint}",
                f"- Boundary: {finding.boundary}",
                f"- Path: `{finding.path}`",
                f"- Reason: {finding.reason}",
                f"- Evidence: `{finding.evidence}`",
                "",
            ]
        )


def _iter_candidate_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = _relative_path(root, path).replace("\\", "/")
        if _should_skip(rel):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        yield path


def _should_skip(rel: str) -> bool:
    parts = set(rel.split("/"))
    if parts.intersection(SKIP_DIRS):
        return True
    return any(rel.startswith(skip + "/") for skip in SKIP_DIRS)


def _relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            return None
    except OSError:
        return None


def _scan_path_surface(path_text: str) -> list[Finding]:
    findings: list[Finding] = []
    lowered = path_text.lower()
    name = Path(path_text).name
    parts = set(Path(path_text).parts)

    if _is_agent_config(name, parts):
        findings.append(
            Finding(
                rule_id="agent.config_surface",
                category="inventory",
                severity="info",
                phase2_hint="hold",
                path=path_text,
                reason="Inventory only — agent/tool configuration surface present.",
                evidence=path_text,
                boundary="agent config",
            )
        )

    if "/.git/hooks/" in "/" + lowered:
        findings.append(
            Finding(
                rule_id="inventory.git_hook",
                category="inventory",
                severity="info",
                phase2_hint="hold",
                path=path_text,
                reason="Inventory only — Git hook present.",
                evidence=path_text,
                boundary="Git hook",
            )
        )

    if "/.github/workflows/" in "/" + lowered:
        findings.append(
            Finding(
                rule_id="ci.workflow_surface",
                category="inventory",
                severity="info",
                phase2_hint="hold",
                path=path_text,
                reason="Inventory only — CI workflow surface present.",
                evidence=path_text,
                boundary="CI workflow",
            )
        )

    if name in {"sitecustomize.py", "usercustomize.py"} or lowered.endswith(".pth"):
        findings.append(
            Finding(
                rule_id="inventory.python_import_hook",
                category="inventory",
                severity="info",
                phase2_hint="hold",
                path=path_text,
                reason="Inventory only — Python import-time hook surface present.",
                evidence=name,
                boundary="Python import-time hook",
            )
        )

    if name.lower() in SHADOWABLE_TOOL_NAMES:
        findings.append(
            Finding(
                rule_id="inventory.tool_shadowing_candidate",
                category="inventory",
                severity="info",
                phase2_hint="hold",
                path=path_text,
                reason=(
                    "Inventory only — repo-local file is named like a trusted "
                    "developer tool and could shadow PATH resolution."
                ),
                evidence=name,
                boundary="tool/PATH shadowing",
            )
        )

    if name.lower() in CREDENTIAL_ADJACENT_NAMES:
        findings.append(
            Finding(
                rule_id="inventory.credential_adjacent_path",
                category="inventory",
                severity="info",
                phase2_hint="hold",
                path=path_text,
                reason=(
                    "Inventory only — credential-adjacent file name observed. "
                    "The scanner reports the path only."
                ),
                evidence=path_text,
                boundary="credential-adjacent file",
            )
        )

    if name.lower() in {"skill.md", "hook.md"}:
        findings.append(
            Finding(
                rule_id="inventory.extension_metadata_surface",
                category="inventory",
                severity="info",
                phase2_hint="hold",
                path=path_text,
                reason="Inventory only — local skill or hook metadata file present.",
                evidence=name,
                boundary="agent/plugin extension",
            )
        )

    return findings


def _is_agent_config(name: str, parts: set[str]) -> bool:
    if name == ".mcp.json" or name == ".claude.json":
        return True
    if name == "mcp.json" and parts.intersection(NESTED_MCP_AGENT_CONFIG_PARTS):
        return True
    if name in AGENT_CONFIG_NAMES and parts.intersection(AGENT_CONFIG_PARTS):
        return True
    return False


def _scan_content(path_text: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lowered = content.lower()
    suffix = Path(path_text).suffix.lower()
    name = Path(path_text).name
    is_go_dependency_file = path_text in {"go.mod", "go.sum"} or path_text.endswith(
        "/go.mod"
    ) or path_text.endswith("/go.sum")
    is_go_source = suffix == ".go"

    if name == "package.json":
        findings.extend(_scan_package_json(path_text, content))

    if name.lower() == ".npmrc":
        findings.extend(_scan_npmrc(path_text, content))

    if name.lower() in CONFIG_REVIEW_NAMES:
        findings.extend(_scan_exposure_config(path_text, content))

    if name == "binding.gyp":
        findings.extend(_scan_binding_gyp(path_text, content))

    if name in {"composer.json", "composer.lock"}:
        findings.extend(_scan_composer_file(path_text, content))

    if _is_workflow_file(path_text):
        findings.extend(_scan_workflow_file(path_text, content))

    findings.extend(_scan_public_formatter_exposure(path_text, content))
    findings.extend(_scan_dynatrace_exposure(path_text, content))

    if (is_go_dependency_file or is_go_source) and "github.com/shopsprint/decimal" in content:
        severity = "critical" if "v1.3.3" in content else "high"
        findings.append(
            Finding(
                rule_id="go.shopsprint_decimal",
                category="indicator",
                severity=severity,
                phase2_hint="block" if severity == "critical" else "hold",
                path=path_text,
                reason=(
                    "Matches Socket May 19 2026 typosquat indicator. "
                    "A matched indicator, not a verdict — verify file context."
                ),
                evidence=_line_evidence(content, "github.com/shopsprint/decimal"),
                boundary="dependency identity",
            )
        )

    has_lookup_txt = "lookuptxt" in lowered or "lookup_txt" in lowered
    has_exec = "os/exec" in content or "exec.command" in lowered
    has_init = "func init" in lowered
    if is_go_source and has_init and has_lookup_txt and has_exec:
        findings.append(
            Finding(
                rule_id="go.import_time_dns_exec",
                category="indicator",
                severity="critical",
                phase2_hint="block",
                path=path_text,
                reason="Import-time code combines DNS TXT lookup with command execution.",
                evidence="func init + LookupTXT + exec.Command",
                boundary="import-time execution",
            )
        )

    if is_go_source and has_lookup_txt and any(
        pattern in lowered for pattern in DYNAMIC_DNS_PATTERNS
    ):
        findings.append(
            Finding(
                rule_id="network.dns_txt_dynamic_dns",
                category="indicator",
                severity="high",
                phase2_hint="hold",
                path=path_text,
                reason="DNS TXT lookup references a dynamic DNS provider.",
                evidence=_first_matching(content, DYNAMIC_DNS_PATTERNS),
                boundary="network/DNS",
            )
        )

    return findings


def _scan_npmrc(path_text: str, content: str) -> list[Finding]:
    if not re.search(r"^\s*git\s*=", content, re.IGNORECASE | re.MULTILINE):
        return []
    return [
        Finding(
            rule_id="exposure.npmrc_git_override",
            category="exposure",
            severity="high",
            phase2_hint="hold",
            path=path_text,
            reason=".npmrc overrides the git executable used by package manager flows.",
            evidence="git=<redacted>",
            boundary="package install hook",
        )
    ]


def _scan_exposure_config(path_text: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    if re.search(r"\b(0\.0\.0\.0|\[::\]|::)\b", content):
        findings.append(
            Finding(
                rule_id="exposure.public_bind_config",
                category="exposure",
                severity="high",
                phase2_hint="hold",
                path=path_text,
                reason="Config appears to bind a service to all interfaces.",
                evidence="public bind address",
                boundary="service exposure config",
            )
        )
    if re.search(r"['\"]?\b(auth|authentication|requireAuth)\b['\"]?\s*[:=]\s*(false|0|off|disabled)", content, re.IGNORECASE):
        findings.append(
            Finding(
                rule_id="exposure.weak_auth_config",
                category="exposure",
                severity="high",
                phase2_hint="hold",
                path=path_text,
                reason="Config appears to disable authentication.",
                evidence="auth disabled",
                boundary="service exposure config",
            )
        )
    if re.search(r"['\"]?\b(allow|allowed)\w*\b['\"]?\s*[:=]\s*(\*|\"?\*\"?)", content, re.IGNORECASE):
        findings.append(
            Finding(
                rule_id="exposure.broad_allow_config",
                category="exposure",
                severity="medium",
                phase2_hint="review",
                path=path_text,
                reason="Config appears to allow all origins, hosts, users, or tools.",
                evidence="broad allow",
                boundary="service exposure config",
            )
        )
    return findings


def _scan_workflow_file(path_text: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lowered = content.lower()

    if (
        "actions_id_token_request_token" in lowered
        or "actions_id_token_request_url" in lowered
        or "github_token" in lowered
        or re.search(r"\bid-token\s*:\s*write\b", content, re.IGNORECASE)
    ):
        findings.append(
            Finding(
                rule_id="ci.workflow_token_surface",
                category="exposure",
                severity="medium",
                phase2_hint="rotate-review",
                path=path_text,
                reason="GitHub Actions workflow references token or OIDC request surfaces.",
                evidence="token/OIDC workflow surface",
                boundary="CI token surface",
            )
        )

    if (
        re.search(r"\bbase64\b", content, re.IGNORECASE)
        and re.search(r"\b(curl|wget|bash|sh|python|node)\b", content, re.IGNORECASE)
    ) or re.search(r"curl\s+-skl\b", content, re.IGNORECASE):
        findings.append(
            Finding(
                rule_id="ci.workflow_encoded_exec",
                category="exposure",
                severity="high",
                phase2_hint="hold",
                path=path_text,
                reason="GitHub Actions workflow combines encoding with shell or network execution.",
                evidence="base64 + shell/network execution",
                boundary="CI command execution",
            )
        )

    has_untrusted_trigger = re.search(
        r"^\s*(issues|issue_comment|pull_request_review|pull_request_review_comment)\s*:",
        content,
        re.IGNORECASE | re.MULTILINE,
    )
    has_write_permission = re.search(
        r"\b(contents|issues|pull-requests|discussions|actions)\s*:\s*write\b",
        content,
        re.IGNORECASE,
    )
    if has_untrusted_trigger and has_write_permission:
        findings.append(
            Finding(
                rule_id="ci.workflow_untrusted_write_surface",
                category="exposure",
                severity="high",
                phase2_hint="hold",
                path=path_text,
                reason="Workflow appears reachable from issue/PR surfaces while granting write permissions.",
                evidence="untrusted trigger + write permission",
                boundary="CI trust boundary",
            )
        )

    if "anthropics/claude-code-action@" in lowered:
        findings.append(
            Finding(
                rule_id="ci.claude_code_action_surface",
                category="inventory",
                severity="info",
                phase2_hint="hold",
                path=path_text,
                reason="Inventory only — workflow uses Claude Code Action.",
                evidence="anthropics/claude-code-action",
                boundary="agentic CI action",
            )
        )

    if re.search(r"allowed_non_write_users\s*:\s*['\"]?\*", content, re.IGNORECASE):
        findings.append(
            Finding(
                rule_id="ci.claude_code_action_untrusted_users",
                category="exposure",
                severity="high",
                phase2_hint="hold",
                path=path_text,
                reason="Claude Code Action allows all non-write users.",
                evidence="allowed_non_write_users: *",
                boundary="agentic CI action",
            )
        )

    if "mcp__github__get_issue" in lowered and "mcp__github__update_issue" in lowered:
        findings.append(
            Finding(
                rule_id="ci.claude_code_action_github_mcp_write_surface",
                category="exposure",
                severity="medium",
                phase2_hint="hold",
                path=path_text,
                reason="Claude Code Action exposes both GitHub issue read and update MCP tools.",
                evidence="mcp__github__get_issue + mcp__github__update_issue",
                boundary="agentic CI action",
            )
        )

    return findings


def _scan_binding_gyp(path_text: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for expansion in re.findall(r"<!\([\s\S]*?\)", content):
        suspicious = re.search(
            r"\b(node|bun|curl|wget|powershell|pwsh|bash|sh|python|python3)\b|/tmp/|%TEMP%|\.js\b|>\s*/dev/null|2>&1",
            expansion,
            re.IGNORECASE,
        )
        findings.append(
            Finding(
                rule_id=(
                    "node.binding_gyp_command_execution"
                    if suspicious
                    else "node.binding_gyp_command_expansion"
                ),
                category="indicator" if suspicious else "inventory",
                severity="high" if suspicious else "info",
                phase2_hint="hold",
                path=path_text,
                reason="binding.gyp contains node-gyp command expansion.",
                evidence=_truncate_evidence(expansion),
                boundary="package install hook",
            )
        )
    return findings


def _scan_composer_file(path_text: str, content: str) -> list[Finding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    packages = []
    if isinstance(data, dict):
        if isinstance(data.get("packages"), list):
            packages.extend(data["packages"])
        if isinstance(data.get("packages-dev"), list):
            packages.extend(data["packages-dev"])
        packages.append(data)

    findings: list[Finding] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        require = package.get("require") if isinstance(package.get("require"), dict) else {}
        extra = package.get("extra") if isinstance(package.get("extra"), dict) else {}
        plugin_entry = extra.get("class") or extra.get("plugin-class")
        capabilities = []
        if package.get("type") == "composer-plugin":
            capabilities.append("type=composer-plugin")
        if "composer-plugin-api" in require:
            capabilities.append("require=composer-plugin-api")
        if isinstance(plugin_entry, (str, list)):
            capabilities.append("extra.class/plugin-class")
        if not capabilities:
            continue
        name = package.get("name") if isinstance(package.get("name"), str) else "(root composer package)"
        findings.append(
            Finding(
                rule_id="composer.plugin_capability",
                category="inventory",
                severity="info",
                phase2_hint="hold",
                path=path_text,
                reason="Composer package declares install/update-time plugin capability.",
                evidence=f"{name}: {', '.join(capabilities)}",
                boundary="Composer install hook",
            )
        )
    return findings


def _scan_public_formatter_exposure(path_text: str, content: str) -> list[Finding]:
    domain = _first_matching(content, PUBLIC_FORMATTER_DOMAINS)
    if not domain:
        return []

    surface = _first_matching(content, PUBLIC_FORMATTER_SURFACE_PATTERNS)
    if not surface:
        return []

    return [
        Finding(
            rule_id="exposure.public_formatter_surface",
            category="exposure",
            severity="medium",
            phase2_hint="rotate-review",
            path=path_text,
            reason=(
                "Local file references public JSON/code formatter saved-paste "
                "surfaces. Review whether secrets, PII, tokens, or internal "
                "payloads were pasted into a public formatter."
            ),
            evidence=f"{domain} + {surface}",
            boundary="public paste exposure",
        )
    ]


def _scan_dynatrace_exposure(path_text: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    seen_tokens = set(DYNATRACE_TOKEN_PATTERN.findall(content))
    for token in sorted(seen_tokens):
        findings.append(
            Finding(
                rule_id="exposure.dynatrace_token_shape",
                category="exposure",
                severity="high",
                phase2_hint="rotate-review",
                path=path_text,
                reason="Dynatrace token-shaped credential appears in local text.",
                evidence=_redact_dynatrace_token(token),
                boundary="credential exposure",
            )
        )

    for term in DYNATRACE_TEAMPCP_REPO_TERMS:
        if term in content:
            findings.append(
                Finding(
                    rule_id="exposure.dynatrace_teampcp_repo_term",
                    category="exposure",
                    severity="medium",
                    phase2_hint="review",
                    path=path_text,
                    reason="Dynatrace/TeamPCP repository term appears in local metadata or notes.",
                    evidence=term,
                    boundary="public screenshot / repo-name exposure",
                )
            )

    for term in DYNATRACE_TEAMPCP_SERVICE_TERMS:
        if term in content:
            findings.append(
                Finding(
                    rule_id="exposure.dynatrace_teampcp_service_term",
                    category="exposure",
                    severity="medium",
                    phase2_hint="review",
                    path=path_text,
                    reason="Dynatrace/TeamPCP service term appears in local metadata or notes.",
                    evidence=term,
                    boundary="public screenshot / service-name exposure",
                )
            )

    return findings


def _scan_package_json(path_text: str, content: str) -> list[Finding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return []

    lifecycle_hooks = [
        name
        for name in sorted(scripts)
        if name in NPM_INSTALL_TIME_LIFECYCLE_SCRIPTS
    ]
    if not lifecycle_hooks:
        return []

    return [
        Finding(
            rule_id="inventory.npm_lifecycle_script",
            category="inventory",
            severity="info",
            phase2_hint="hold",
            path=path_text,
            reason="Inventory only — npm install-time lifecycle script present.",
            evidence=", ".join(lifecycle_hooks),
            boundary="package install hook",
        )
    ]


def _line_evidence(content: str, needle: str) -> str:
    for line in content.splitlines():
        if needle in line:
            return line.strip()
    return needle


def _is_workflow_file(path_text: str) -> bool:
    lowered = path_text.lower()
    return "/.github/workflows/" in "/" + lowered and (
        lowered.endswith(".yml") or lowered.endswith(".yaml")
    )


def _first_matching(content: str, patterns: tuple[str, ...]) -> str:
    lowered = content.lower()
    for pattern in patterns:
        if pattern in lowered:
            return pattern
    return ""


def _truncate_evidence(value: str, max_length: int = 180) -> str:
    if len(value) <= max_length:
        return value
    return value[: max_length - 3] + "..."


def _redact_dynatrace_token(token: str) -> str:
    parts = token.split(".")
    if len(parts) < 3:
        return "dt0***"
    return f"{parts[0]}.{parts[1]}.<redacted>"
