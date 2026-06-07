from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ZERO_SHA = "0" * 40

# Inline allowlist escape hatch. A line containing this marker is skipped by
# every rule. Use it on lines that legitimately carry IOC-shaped strings: this
# detector's own pattern definitions and test fixtures, or a deploy script
# that really does ssh-then-exec. It is explicit and grep-auditable on purpose --
# matching detect-secrets' `# pragma: allowlist secret` philosophy.
IGNORE_MARKER = re.compile(r"push-guard:\s*ignore", re.IGNORECASE)

PLACEHOLDER_WORDS = {
    "changeme",
    "example",
    "placeholder",
    "replace",
    "sample",
    "test",
    "your",
}

# Each entry: (rule_id, pattern, reason, high_confidence)
# high_confidence == True means the match is a provider-specific token *shape*
# (ghp_, github_pat_, sk-, AKIA/ASIA). A value matching one of these is a real
# secret even if it happens to contain a word like "test" or "your", so the
# placeholder filter MUST NOT suppress it. Only low-confidence/structural
# markers honor the placeholder filter.
SECRET_PATTERNS = [
    (
        "secret.github_fine_grained_token",
        re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
        "GitHub fine-grained token pattern",
        True,
    ),
    (
        "secret.github_token",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
        "GitHub token pattern",
        True,
    ),
    (
        "secret.openai_token",
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        "OpenAI-style token pattern",
        True,
    ),
    (
        "secret.aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "AWS access key pattern",
        True,
    ),
    (
        "secret.private_key",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        "Private key block marker",
        False,
    ),
]

# Keyword may be embedded in an underscore/dash-delimited identifier so that
# names like AWS_SECRET_ACCESS_KEY or CLIENT_SECRET_TOKEN are matched, not just
# bare `secret=`. The negative lookbehind keeps the keyword on a real boundary
# (start, space, `_`, `-`) instead of matching inside an unrelated word.
GENERIC_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd)"
    r"(?:[_-][A-Za-z0-9]+)*"
    r"\s*[:=]\s*['\"]?([^'\"\s]{20,})"
)

SHAI_HULUD_SSH_PATTERNS = [
    (
        "workflow.shai_hulud_ssh_tmp",
        re.compile(r"/tmp/\.sshu-[A-Za-z0-9_-]*", re.I),
        "Hidden /tmp/.sshu-* SSH propagation artifact",  # push-guard: ignore
    ),
    (
        "workflow.shai_hulud_ai_loader",
        re.compile(r"\bai_(?:setup\.sh|init\.js)\b", re.I),
        "AI-themed Shai-Hulud SSH loader/payload filename",
    ),
    (
        "workflow.ssh_fanout_exec",
        re.compile(r"\b(?:ssh|scp|rsync)\b.*\b(?:bun|node|sh|bash|curl|wget)\b", re.I),  # push-guard: ignore
        "SSH fan-out combined with script/network execution",
    ),
    (
        "workflow.bun_tmp_exec",
        re.compile(r"\bBun\.spawnSync\b.*(?:/tmp/|ai_setup\.sh|ai_init\.js)", re.I),
        "Bun execution paired with temp or AI-themed payload behavior",
    ),
]

HADES_PYPI_PATTERNS = [
    (
        "workflow.hades_pypi_bun_download",
        re.compile(r"oven-sh/bun/releases/download|bun-v\d+\.\d+\.\d+", re.I),  # push-guard: ignore
        "Hades/Miasma PyPI Bun runtime bootstrap marker",
    ),
    (
        "workflow.hades_pypi_bun_sentinel",
        re.compile(r"\.bun_ran\b", re.I),  # push-guard: ignore
        "Hades/Miasma PyPI Bun startup sentinel",
    ),
    (
        "workflow.hades_anthropic_camouflage",
        re.compile(r"api\.anthropic\.com/v1/api", re.I),  # push-guard: ignore
        "Hades/Miasma Anthropic-host camouflage endpoint",
    ),
    (
        "workflow.hades_github_exfil_marker",
        re.compile(
            r"Hades - The End for the Damned|"  # push-guard: ignore
            r"IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully|"  # push-guard: ignore
            r"results/results-[^\"'\s]*\.json|"  # push-guard: ignore
            r"\bformat-results\b|"  # push-guard: ignore
            r"\bRun Copilot\b",  # push-guard: ignore
            re.I,
        ),  # push-guard: ignore
        "Hades/Miasma GitHub or Actions exfiltration marker",
    ),
    (
        "workflow.hades_github_token_monitor",
        re.compile(
            r"gh-token-monitor|GitHub Commit Monitor|"  # push-guard: ignore
            r"gh-token-monitor\.service|com\.github\.token-monitor\.plist",  # push-guard: ignore
            re.I,
        ),  # push-guard: ignore
        "Hades/Miasma GitHub token-monitor persistence marker",
    ),
]


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    path: str
    line: int
    reason: str
    evidence: str


class PushGuardInspectionError(RuntimeError):
    """Raised when push guard cannot inspect Git push content cleanly."""


def scan_text_for_secrets(text: str, path: str = "<text>") -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        findings.extend(_scan_line(line, path, line_number))
    return findings


def scan_git_push(repo: str | Path, stdin_text: str) -> list[SecretFinding]:
    repo_path = Path(repo)
    findings: list[SecretFinding] = []
    for local_ref, local_sha, _remote_ref, remote_sha in _parse_pre_push(stdin_text):
        if local_sha == ZERO_SHA:
            continue
        diffs = _diffs_for_push_ref(repo_path, local_ref, local_sha, remote_sha)
        for diff_text in diffs:
            findings.extend(_scan_diff(diff_text))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="never-ending-story-push-guard",
        description="Local pre-push secret guard. Blocks likely secret pushes.",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository path. Defaults to current directory.",
    )
    args = parser.parse_args(argv)

    stdin_text = sys.stdin.read()
    try:
        findings = scan_git_push(args.repo, stdin_text)
    except RuntimeError as exc:
        print(
            "Never-Ending Story push guard could not inspect this push.",
            file=sys.stderr,
        )
        print(str(exc), file=sys.stderr)
        print("Blocking push because inspection failed.", file=sys.stderr)
        return 1

    if not findings:
        return 0

    print("Never-Ending Story push guard blocked this push.", file=sys.stderr)
    print("Likely secret material matched. Values are redacted.", file=sys.stderr)
    for finding in findings:
        print(
            f"- {finding.rule_id} at {finding.path}:{finding.line} "
            f"({finding.reason}; {finding.evidence})",
            file=sys.stderr,
        )
    print("Review locally, remove or rotate the secret, then retry.", file=sys.stderr)
    return 1


def _scan_line(line: str, path: str, line_number: int) -> list[SecretFinding]:
    findings: list[SecretFinding] = []

    # Explicit per-line opt-out. Skip the whole line for every rule.
    if IGNORE_MARKER.search(line):
        return findings

    for rule_id, pattern, reason, high_confidence in SECRET_PATTERNS:
        for match in pattern.finditer(line):
            # High-confidence provider token shapes are never suppressed by a
            # placeholder word - a real ghp_/sk-/AKIA value that merely contains
            # "test" or "your" is still a real secret and must be caught.
            if not high_confidence and _looks_like_placeholder(match.group(0)):
                continue
            findings.append(
                SecretFinding(
                    rule_id=rule_id,
                    path=path,
                    line=line_number,
                    reason=reason,
                    evidence="<redacted>",
                )
            )

    # Only consider the lower-confidence generic-assignment rule when no
    # specific token already matched this line. This avoids double-reporting a
    # single leak while still catching secrets that only the generic rule can
    # see, such as AWS_SECRET_ACCESS_KEY values with no provider prefix.
    if not findings:
        match = GENERIC_ASSIGNMENT.search(line)
        if match and not _value_is_placeholder(match.group(1)):
            findings.append(
                SecretFinding(
                    rule_id="secret.generic_assignment",
                    path=path,
                    line=line_number,
                    reason="High-entropy-looking secret assignment",
                    evidence="<redacted>",
                )
            )

    findings.extend(_scan_line_for_workflow_compromise(line, path, line_number))
    findings.extend(_scan_line_for_hades_pypi(line, path, line_number))

    return findings


def _scan_line_for_workflow_compromise(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    if not _is_workflow_or_script_path(normalized_path):
        return []

    findings: list[SecretFinding] = []
    for rule_id, pattern, reason in SHAI_HULUD_SSH_PATTERNS:
        if pattern.search(line):
            findings.append(
                SecretFinding(
                    rule_id=rule_id,
                    path=path,
                    line=line_number,
                    reason=reason,
                    evidence="<redacted>",
                )
            )

    if (
        re.search(r"\binfectHost\s*\(", line)
        or re.search(r"\bremote(?:Loader|Payload)Script\b", line)
    ):
        findings.append(
            SecretFinding(
                rule_id="workflow.shai_hulud_ssh_shape",
                path=path,
                line=line_number,
                reason="Shai-Hulud SSH propagation function/variable shape",
                evidence="<redacted>",
            )
        )

    return findings


def _scan_line_for_hades_pypi(
    line: str, path: str, line_number: int
) -> list[SecretFinding]:
    normalized_path = path.replace("\\", "/")
    lowered_path = normalized_path.lower()
    if lowered_path.endswith((".md", ".mdx", ".txt", ".rst")):
        return []

    is_pth = lowered_path.endswith(".pth")
    is_code_or_workflow = is_pth or _is_workflow_or_script_path(normalized_path)
    if not is_code_or_workflow:
        return []

    findings: list[SecretFinding] = []

    if (
        is_pth
        and re.match(r"\s*import(?:\s|;)", line)
        and re.search(
            r"urllib\.request|urlretrieve|subprocess\.run|tempfile\.gettempdir|"
            r"_index\.js|oven-sh/bun/releases/download|\.bun_ran|\bbun\s+run\b",  # push-guard: ignore
            line,
            re.I,
        )
    ):
        findings.append(
            SecretFinding(
                rule_id="workflow.hades_pypi_pth_loader",
                path=path,
                line=line_number,
                reason="Executable .pth startup hook with Hades/Miasma loader behavior",
                evidence="<redacted>",
            )
        )

    for rule_id, pattern, reason in HADES_PYPI_PATTERNS:
        if pattern.search(line):
            findings.append(
                SecretFinding(
                    rule_id=rule_id,
                    path=path,
                    line=line_number,
                    reason=reason,
                    evidence="<redacted>",
                )
            )

    return findings


def _is_workflow_or_script_path(path: str) -> bool:
    lowered = path.lower()
    if lowered.endswith((".md", ".mdx", ".txt", ".rst")):
        return False
    if any(
        marker in lowered
        for marker in (
            "/.github/workflows/",
            ".github/workflows/",
            "/.githooks/",
            ".githooks/",
            "/hooks/",
            "hooks/",
            "/scripts/",
            "scripts/",
            "/bin/",
            "bin/",
            "/tools/",
            "tools/",
            "/ci/",
            "ci/",
        )
    ):
        return True
    return lowered.endswith((".sh", ".bash", ".zsh", ".js", ".cjs", ".mjs", ".ps1", ".py", ".yml", ".yaml"))


def _looks_like_placeholder(value: str) -> bool:
    """Substring check, used only for low-confidence/structural markers."""
    lowered = value.lower()
    return any(word in lowered for word in PLACEHOLDER_WORDS)


def _value_is_placeholder(value: str) -> bool:
    """True only when an assigned value is *dominated* by placeholder text.

    The earlier behaviour skipped any value that merely *contained* a
    placeholder word, which silently let secrets through. Now a value counts as
    a placeholder only when it is an obvious dummy shape, stacks two or more
    placeholder words, or is left with almost nothing real after the placeholder
    words are removed.
    """
    lowered = value.lower()
    if re.fullmatch(r"[<\[{(].*[>\]})]", value):
        return True
    if re.fullmatch(r"[x*._\-]{8,}", lowered):
        return True
    present = [word for word in PLACEHOLDER_WORDS if word in lowered]
    if len(present) >= 2:
        return True
    residue = lowered
    for word in present:
        residue = residue.replace(word, "")
    residue = re.sub(r"[^a-z0-9]", "", residue)
    return len(residue) < 8


def _parse_pre_push(stdin_text: str) -> list[tuple[str, str, str, str]]:
    refs: list[tuple[str, str, str, str]] = []
    for line in stdin_text.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        refs.append((parts[0], parts[1], parts[2], parts[3]))
    return refs


def _diffs_for_push_ref(
    repo: Path, local_ref: str, local_sha: str, remote_sha: str
) -> list[str]:
    if remote_sha == ZERO_SHA:
        commits = _run_git(
            repo,
            ["rev-list", "--reverse", local_sha, "--not", "--remotes"],
        ).splitlines()
        if not commits:
            commits = [local_sha]
        return [
            _run_git(repo, ["show", "--format=", "--unified=0", "--no-ext-diff", commit])
            for commit in commits
        ]

    return [
        _run_git(
            repo,
            [
                "diff",
                "--unified=0",
                "--no-ext-diff",
                "--diff-filter=ACMRT",
                remote_sha,
                local_sha,
            ],
        )
    ]


def _scan_diff(diff_text: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    current_path = "<diff>"
    new_line = 0
    in_hunk = False
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_path = line[6:]
            continue
        if line.startswith("@@"):
            new_line = _parse_hunk_new_line(line)
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            findings.extend(_scan_line(line[1:], current_path, max(new_line, 1)))
            new_line += 1
            continue
        if line.startswith("-") and not line.startswith("---"):
            continue
        if line.startswith("\\ No newline"):
            continue
        new_line += 1
    return findings


def _parse_hunk_new_line(line: str) -> int:
    match = re.search(r"\+(\d+)", line)
    if not match:
        return 0
    return int(match.group(1))


def _run_git(repo: Path, args: list[str]) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        stderr = _first_stderr_line(exc.stderr)
        detail = f": {stderr}" if stderr else ""
        raise PushGuardInspectionError(
            f"git {' '.join(args)} failed with exit {exc.returncode}{detail}"
        ) from exc
    return completed.stdout


def _first_stderr_line(stderr: str | None) -> str:
    if not stderr:
        return ""
    for line in stderr.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
