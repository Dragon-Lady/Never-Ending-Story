from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


TEXT_EXTENSIONS = {
    "",
    ".cfg",
    ".conf",
    ".go",
    ".json",
    ".lock",
    ".md",
    ".mod",
    ".ps1",
    ".pth",
    ".py",
    ".sum",
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

    findings.extend(_scan_public_formatter_exposure(path_text, content))

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


def _scan_public_formatter_exposure(path_text: str, content: str) -> list[Finding]:
    lowered = content.lower()
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


def _first_matching(content: str, patterns: tuple[str, ...]) -> str:
    lowered = content.lower()
    for pattern in patterns:
        if pattern in lowered:
            return pattern
    return ""
