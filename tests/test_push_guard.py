import unittest
from io import StringIO
from unittest.mock import patch

from never_ending_story.push_guard import (
    _scan_diff,
    main,
    scan_text_for_secrets,
)


class PushGuardTests(unittest.TestCase):
    def test_detects_github_tokens_without_returning_secret_value(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        findings = scan_text_for_secrets(f"token={secret}", path="example.env")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.github_token", findings[0].rule_id)
        self.assertEqual("example.env", findings[0].path)
        self.assertNotIn(secret, findings[0].evidence)
        self.assertIn("redacted", findings[0].evidence.lower())

    def test_detects_github_fine_grained_token_without_returning_secret_value(self):
        secret = "github_pat_11AAAAAAA0abcdefghijklmnopqrstuvwxyzABCDEFGHI"
        findings = scan_text_for_secrets(secret, path="notes.txt")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.github_fine_grained_token", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_detects_private_key_block_without_returning_body(self):
        text = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "abc123abc123abc123abc123\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        findings = scan_text_for_secrets(text, path="id_key")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.private_key", findings[0].rule_id)
        self.assertNotIn("abc123abc123abc123abc123", findings[0].evidence)

    def test_detects_openai_style_token_without_returning_secret_value(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyzABCDEF"
        findings = scan_text_for_secrets(f"OPENAI_API_KEY={secret}", path=".env")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.openai_token", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_detects_aws_access_key_without_returning_secret_value(self):
        secret = "AKIAABCDEFGHIJKLMNOP"
        findings = scan_text_for_secrets(f"AWS_ACCESS_KEY_ID={secret}", path=".env")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.aws_access_key", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_detects_generic_secret_assignment_without_returning_secret_value(self):
        secret = "superlongsecretvalue1234567890"
        findings = scan_text_for_secrets(f"api_key = '{secret}'", path="config.py")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.generic_assignment", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_ignores_obvious_placeholders(self):
        text = "\n".join(
            [
                "api_key=YOUR_API_KEY_HERE",
                "token=example-token-placeholder",
                "password=changeme",
            ]
        )
        findings = scan_text_for_secrets(text, path="README.md")

        self.assertEqual([], findings)

    def test_specific_token_is_not_hidden_by_placeholder_comment(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        findings = scan_text_for_secrets(
            f'token = "{secret}"  # test this config',
            path="config.py",
        )

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.github_token", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_token_shape_with_embedded_placeholder_word_is_detected(self):
        secret = "ghp_test" + "a" * 30
        findings = scan_text_for_secrets(secret, path="config.py")

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.github_token", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_detects_underscored_secret_assignment(self):
        secret = "abcdEFGH1234ijklMNOP5678qrstUVWX"
        findings = scan_text_for_secrets(
            f"AWS_SECRET_ACCESS_KEY={secret}", path=".env"
        )

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.generic_assignment", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_generic_secret_with_embedded_common_word_is_not_skipped(self):
        secret = "mytestpasswordABCDEF1234567890"
        findings = scan_text_for_secrets(
            f"password = '{secret}'", path="config.py"
        )

        self.assertEqual(1, len(findings))
        self.assertEqual("secret.generic_assignment", findings[0].rule_id)
        self.assertNotIn(secret, findings[0].evidence)

    def test_verbose_dummy_placeholder_value_is_still_ignored(self):
        findings = scan_text_for_secrets(
            "api_key = 'your-api-key-here-please-replace'", path="README.md"
        )

        self.assertEqual([], findings)

    def test_scan_diff_reports_added_secret_path_and_line(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        diff_text = "\n".join(
            [
                "diff --git a/config.py b/config.py",
                "index 1111111..2222222 100644",
                "--- a/config.py",
                "+++ b/config.py",
                "@@ -10,3 +10,4 @@",
                " context line one",
                " context line two",
                f"+token = '{secret}'",
            ]
        )

        findings = _scan_diff(diff_text)

        self.assertEqual(1, len(findings))
        self.assertEqual("config.py", findings[0].path)
        self.assertEqual(12, findings[0].line)

    def test_scan_diff_blocks_shai_hulud_ssh_shape_in_scripts(self):
        diff_text = "\n".join(
            [
                "diff --git a/scripts/sync.js b/scripts/sync.js",
                "index 1111111..2222222 100644",
                "--- a/scripts/sync.js",
                "+++ b/scripts/sync.js",
                "@@ -1,0 +1,5 @@",
                "+async function infectHost(targetSshHost, remoteLoaderScript, remotePayloadScript) {",  # push-guard: ignore
                "+  const remoteWorkDir = \"/tmp/.sshu-\" + Math.random().toString(36).slice(2, 8);",  # push-guard: ignore
                "+  const remoteLoaderFileName = \"ai_setup.sh\";",  # push-guard: ignore
                "+  const remotePayloadFileName = \"ai_init.js\";",  # push-guard: ignore
                "+  Bun.spawnSync([\"ssh\", targetSshHost, \"sh\", remoteLoaderFileName]);",  # push-guard: ignore
            ]
        )

        findings = _scan_diff(diff_text)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("workflow.shai_hulud_ssh_shape", rule_ids)
        self.assertIn("workflow.shai_hulud_ssh_tmp", rule_ids)
        self.assertIn("workflow.shai_hulud_ai_loader", rule_ids)

    def test_scan_diff_does_not_block_markdown_indicator_notes(self):
        diff_text = "\n".join(
            [
                "diff --git a/docs/note.md b/docs/note.md",
                "index 1111111..2222222 100644",
                "--- a/docs/note.md",
                "+++ b/docs/note.md",
                "@@ -1,0 +1,3 @@",
                "+Watch /tmp/.sshu-* directories.",  # push-guard: ignore
                "+Look for ai_setup.sh and ai_init.js.",  # push-guard: ignore
                "+Mention infectHost only as a defensive note.",
            ]
        )

        self.assertEqual([], _scan_diff(diff_text))

    def test_ignore_marker_suppresses_secret_and_workflow_rules(self):
        # A line carrying the explicit opt-out marker is skipped by every rule,
        # even when it contains a real token shape and an IOC pattern.
        line = (
            "+const k = \"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\";"  # push-guard: ignore
            "  Bun.spawnSync([\"ssh\", h, \"/tmp/.sshu-x\"]);  # push-guard: ignore"
        )
        diff_text = "\n".join(
            [
                "diff --git a/scripts/sync.js b/scripts/sync.js",
                "+++ b/scripts/sync.js",
                "@@ -1,0 +1,1 @@",
                line,
            ]
        )

        self.assertEqual([], _scan_diff(diff_text))

    def test_main_blocks_and_reports_redacted_findings(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        finding_diff = "\n".join(
            [
                "diff --git a/config.py b/config.py",
                "--- a/config.py",
                "+++ b/config.py",
                "@@ -1,0 +1,1 @@",
                f"+token = '{secret}'",
            ]
        )

        with (
            patch(
                "never_ending_story.push_guard._diffs_for_push_ref",
                return_value=[finding_diff],
            ),
            patch("sys.stdin", StringIO("refs/heads/main abc refs/heads/main def\n")),
            patch("sys.stderr", new_callable=StringIO) as stderr,
        ):
            exit_code = main(["--repo", "."])

        self.assertEqual(1, exit_code)
        output = stderr.getvalue()
        self.assertIn("blocked this push", output)
        self.assertIn("<redacted>", output)
        self.assertNotIn(secret, output)

    def test_main_reports_clean_git_inspection_error_without_traceback(self):
        with (
            patch(
                "never_ending_story.push_guard._diffs_for_push_ref",
                side_effect=RuntimeError("git diff failed"),
            ),
            patch("sys.stdin", StringIO("refs/heads/main abc refs/heads/main def\n")),
            patch("sys.stderr", new_callable=StringIO) as stderr,
        ):
            exit_code = main(["--repo", "."])

        self.assertEqual(1, exit_code)
        output = stderr.getvalue()
        self.assertIn("could not inspect this push", output)
        self.assertIn("Blocking push because inspection failed", output)
        self.assertNotIn("Traceback", output)


if __name__ == "__main__":
    unittest.main()
