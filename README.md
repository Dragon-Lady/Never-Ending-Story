# Never-Ending Story

Read-only local scanner for developer trust surfaces, public paste exposure,
and supply-chain hygiene signals.

Never-Ending Story is the broad lane. Incident-specific tools such as
HereWeGoAgain can stay focused on known malware, worm, and stealer indicators;
this project handles adjacent exposure and trust-surface review without claiming
that a host is compromised.

## Safety Boundary

- No network calls.
- No package installs.
- No deletion, quarantine, uninstall, cleanup, or credential rotation.
- No service, registry, firewall, PATH, shell profile, Git hook, CI workflow, or
  agent config edits.
- No claims that a host is clean.

The scanner is announce-only. Findings are signals for human review.

## Report Lanes

- `Indicator Matches`: known high-signal patterns that need immediate context
  review.
- `Exposure Review`: public paste, formatter, or data-spill surfaces where
  secrets or personal data may have left a local machine.
- `Trust-Surface Inventory`: agent configs, Git hooks, CI workflows, npm
  lifecycle scripts, and import-time hook surfaces that should be understood
  before running code.

## Current Triggers

- Public formatter / saved-paste exposure notes involving tools such as
  `jsonformatter.org` or `codebeautify.org` plus saved-paste mechanics like
  `Recent Links`, `/recentLinksPage/json/`, `/service/getDataFromID`, `urlid=`,
  or six-hex paste IDs.
- Terminal escape protocol risks, including iTerm2 SSH conductor markers such
  as `DCS 2000p` and `OSC 135` that can make untrusted text unsafe to print
  directly in a terminal emulator.
- Service exposure config patterns such as binding to `0.0.0.0` / `::`,
  disabled authentication, or broad allow-list values.
- Known Socket May 19 anchor: `github.com/shopsprint/decimal`, especially
  `v1.3.3`.
- Go import-time DNS TXT plus command execution: `func init`, `LookupTXT`, and
  `exec.Command`.
- DNS TXT references to dynamic DNS providers such as `freemyip.com`.
- Agent config surfaces: `.mcp.json`, `.claude*`, `.cursor`, `.gemini`, and
  `.copilot` canonical config files only.
- Skill/hook metadata files such as `SKILL.md` and `HOOK.md`.
- Bare nested `mcp.json` inside confirmed agent config directories: `.claude`,
  `.cursor`, and `.gemini`.
- Git hooks.
- GitHub Actions workflow files, token/OIDC surfaces, encoded shell/network
  execution patterns, untrusted issue/PR triggers with write permissions, and
  Claude Code Action review surfaces such as broad `allowed_non_write_users` or
  GitHub issue read/update MCP tool combinations.
- npm install-time lifecycle scripts in `package.json`: `preinstall`,
  `install`, `postinstall`, `prepare`, `preuninstall`, `uninstall`,
  `postuninstall`.
- Root `binding.gyp` command expansion through `<!(...)`, especially when it
  invokes Node, Bun, shell/network tools, temp paths, JavaScript files, or
  silent redirects.
- Composer plugin capability in `composer.json` or `composer.lock`, including
  `type=composer-plugin`, `composer-plugin-api`, and `extra.class` /
  `extra.plugin-class`.
- `.npmrc` `git=` executable overrides that can affect package install flows.
- Repo-local files named like trusted developer tools such as `ssh`, `git`,
  `npm`, `node`, `python`, `gh`, `claude`, `codex`, `composer`, `pnpm`, or
  `yarn`, which may shadow PATH resolution.
- Python import-time hook surfaces outside skipped env/cache directories:
  `sitecustomize.py`, `usercustomize.py`, and `.pth` files.
- Credential-adjacent file names such as `.env`, `.npmrc`, `.pypirc`,
  `id_rsa`, `id_ed25519`, `credentials.json`, `service-account.json`, and
  `token.json`. These are reported by path only.
- Dynatrace-shaped token exposure and selected Dynatrace/TeamPCP repo or
  service-name strings observed in public threat-context screenshots. Token
  evidence is redacted.
- Aikido / BleepingComputer JetBrains Marketplace AI-key stealer indicators:
  exact reported plugin IDs such as `org.sm.yms.toolkit` and the reported
  `39.107.60[.]51/api/software/key` endpoint.

## Run

```powershell
python -m never_ending_story.cli C:\path\to\scan
```

Write a Markdown report:

```powershell
python -m never_ending_story.cli C:\path\to\scan --out report.md
```

## Push Guard

`never_ending_story.push_guard` is a pre-push secret-leak guard module. It is
not automatically installed into any repository hook. See `PUSH_GUARD.md`.

## Coverage Limits

This scanner is intentionally narrow. It does not yet inspect Node general
script entries such as `test`, `build`, `lint`, `start`, or `dev`; npm lockfile
resolved URLs; Python `setup.py`/`pyproject.toml` build hooks; executable
`import` lines inside `.pth` files; Cargo `build.rs`; PowerShell profiles;
shell scripts; `.env`; `.envrc`; VS Code settings; generic secret regexes; or
arbitrary PII patterns.

## Push Guard upgrade preparation

The reviewed `.push-guard-allow` file scopes exceptions to exact workflow rules
and files containing detector definitions, inert fixtures or scanner metadata.
It cannot exempt credentials, personal terms or private paths. Review any change
to an allowed file; an exception applies to that rule throughout that file.

Keep the shared hook tool at 0.4.2 during migration. Existing inline fixture
comments remain temporarily because its pre-push command does not read this
policy. Push Guard 0.4.3 ignores those comments and reads policy from the
destination base commit. Establish and review the policy there before upgrading;
adding it in the same push as a matching fixture cannot approve that fixture.
New destination refs have no base policy and receive no exceptions.

Verify outgoing ranges and built packages with the reviewed candidate scanner
before upgrading. Package scans must select this reviewed repository policy
explicitly. Do not disable verification to get a fixture through the hook.
