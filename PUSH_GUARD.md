# Never-Ending Story Push Guard

Status: local guard module implemented, not installed into any repository hook.

Purpose: prevent likely secrets from being pushed if wired into a Git
`pre-push` hook.

## Boundary

- Local only.
- No network calls.
- No package installs.
- No target file mutation.
- No secret values printed.
- Uses the `git` subprocess only to read commit diffs.
- No mutation through Git and no other subprocess execution.
- No automatic hook installation yet.
- No claim that a repository is clean.

The guard exits nonzero when likely secret material is detected in commits being
pushed. Git treats a nonzero `pre-push` hook exit as a failed push.
Blocking a push is Git's response to the advisory. The scanner remains
read-only and does not mutate files. Override is available with
`git push --no-verify` when the matched value is known not to be a secret.

## Current Secret Signals

- GitHub classic token prefixes: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
- GitHub fine-grained token prefix: `github_pat_`
- OpenAI-style `sk-...` tokens
- AWS access key IDs: `AKIA...` / `ASIA...`
- private key block markers
- generic long `api_key`, `token`, `secret`, or `password` assignments

All evidence is redacted as `<redacted>`.

## Run Manually

The hook CLI expects Git `pre-push` input on stdin. Manual dry runs are best
done from an actual hook or a test fixture.

```powershell
python -m never_ending_story.push_guard --repo C:\path\to\repo
```

## Hook Installation Status

Not installed.

Before installing into any repo, review the rule set and wording, choose the
target repositories intentionally, install repo-by-repo rather than globally,
and preserve or intentionally chain any existing hooks.

## Known Limits

- Pattern-based detection can miss secrets or flag non-secrets.
- Long non-secret identifiers in assignments such as
  `secret = mySuperLongFunctionCallHereWithNoSpaces` can match the generic
  assignment rule.
- Compound underscored names such as `AWS_SECRET_ACCESS_KEY` are not matched by
  the generic keyword boundary. Prefix-specific rules can still catch known
  token formats such as `AKIA...` / `ASIA...`.
- If a hook is installed from a Git subdirectory, Git may resolve `--repo` to a
  parent repository root. This is acceptable for current diff-only scanning, but
  future path-relative features such as allowlists or report output must resolve
  and document the canonical Git root first.
- It blocks likely matches; it does not rotate exposed credentials.
- If a real secret was committed, rotate from a clean context after removing it.
- It should be treated as a seatbelt, not a guarantee.
