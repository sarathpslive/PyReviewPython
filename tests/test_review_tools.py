from __future__ import annotations

import unittest

from agent.review_tools import scan_python_source


class ReviewToolsTests(unittest.TestCase):
    def test_detects_apikey_variants(self) -> None:
        snippet = "\n".join(
            [
                "def load_configuration():",
                "    apiKey = 'demo-key-replace-with-secret-manager'",
                "    apikey = 'demo-key-2'",
                "    client_secret = 'demo-secret'",
                "    return apiKey",
            ]
        )

        findings = scan_python_source(snippet)
        sec002 = [item for item in findings if item.get("rule_id") == "SEC002"]
        evidence = {str(item.get("evidence", "")).lower() for item in sec002}

        self.assertGreaterEqual(len(sec002), 3)
        self.assertIn("apikey", evidence)
        self.assertIn("apikey", {value.replace("_", "") for value in evidence})
        self.assertIn("client_secret", evidence)

    def test_syntax_error_keeps_sensitive_fallback_findings(self) -> None:
        # Intentionally incomplete call to emulate partial/long snippets from UI paste operations.
        snippet = "\n".join(
            [
                "def broken():",
                "    apikey = 'demo-password-change-me'",
                "    payload = {",
                "    return payload",
            ]
        )

        findings = scan_python_source(snippet)
        rule_ids = [str(item.get("rule_id")) for item in findings]

        self.assertIn("PY001", rule_ids)
        self.assertIn("SEC002", rule_ids)

    def test_long_single_line_assignment_is_detected(self) -> None:
        long_value = "x" * 2000
        snippet = f"apikey = '{long_value}'"

        findings = scan_python_source(snippet)
        sec002 = [item for item in findings if item.get("rule_id") == "SEC002"]

        self.assertEqual(len(sec002), 1)
        self.assertEqual(sec002[0].get("severity"), "critical")
        self.assertEqual(sec002[0].get("severity_label"), "Critical / Blocker")
        self.assertTrue(sec002[0].get("pr_blocking"))


# ---------------------------------------------------------------------------
# New tests: multi-vulnerability snippet (SQLi + Command Injection + Path Traversal)
# ---------------------------------------------------------------------------

_MULTI_VULN_SNIPPET = """
import sqlite3
import subprocess
import os

def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

def ping_host(host_input):
    command = f"ping -c 1 {host_input}"
    output = subprocess.check_output(command, shell=True, text=True)
    return output

def read_user_file(filename):
    base_dir = "/var/data"
    filepath = os.path.join(base_dir, filename)
    with open(filepath, "r") as f:
        return f.read()
"""


class MultiVulnerabilityTests(unittest.TestCase):

    def setUp(self) -> None:
        self.findings = scan_python_source(_MULTI_VULN_SNIPPET)
        self.rule_ids = [f.get("rule_id") for f in self.findings]

    # ------------------------------------------------------------------
    # SEC003: SQL Injection
    # ------------------------------------------------------------------
    def test_sql_injection_detected(self) -> None:
        sec003 = [f for f in self.findings if f.get("rule_id") == "SEC003"]
        self.assertGreaterEqual(len(sec003), 1, "SEC003 SQL injection should be detected")

    def test_sql_injection_no_duplicate(self) -> None:
        """The f-string assignment and cursor.execute() must produce ONE finding, not two."""
        sec003 = [f for f in self.findings if f.get("rule_id") == "SEC003"]
        self.assertEqual(len(sec003), 1, (
            f"Expected exactly 1 SEC003 finding (dedup), got {len(sec003)}: "
            + str([(f.get('line'), f.get('evidence')) for f in sec003])
        ))

    def test_sql_injection_is_critical(self) -> None:
        sec003 = next((f for f in self.findings if f.get("rule_id") == "SEC003"), None)
        self.assertIsNotNone(sec003)
        self.assertEqual(sec003.get("severity"), "critical")
        self.assertTrue(sec003.get("pr_blocking"))

    def test_sql_injection_has_replacement(self) -> None:
        sec003 = next((f for f in self.findings if f.get("rule_id") == "SEC003"), None)
        self.assertIsNotNone(sec003)
        self.assertIn("?", sec003.get("replacement", ""), "Replacement should use parameterized query")

    # ------------------------------------------------------------------
    # SEC004: Command Injection
    # ------------------------------------------------------------------
    def test_command_injection_detected(self) -> None:
        sec004 = [f for f in self.findings if f.get("rule_id") == "SEC004"]
        self.assertGreaterEqual(len(sec004), 1, "SEC004 Command Injection should be detected")

    def test_command_injection_is_critical(self) -> None:
        sec004 = next((f for f in self.findings if f.get("rule_id") == "SEC004"), None)
        self.assertIsNotNone(sec004)
        self.assertEqual(sec004.get("severity"), "critical")
        self.assertTrue(sec004.get("pr_blocking"))

    def test_command_injection_has_replacement(self) -> None:
        sec004 = next((f for f in self.findings if f.get("rule_id") == "SEC004"), None)
        self.assertIsNotNone(sec004)
        replacement = sec004.get("replacement", "")
        self.assertIn("check_output", replacement, "Replacement should show safe subprocess.check_output list form")
        self.assertNotIn("shell=True", replacement, "Replacement must NOT contain shell=True")

    # ------------------------------------------------------------------
    # SEC005: Path Traversal
    # ------------------------------------------------------------------
    def test_path_traversal_detected(self) -> None:
        sec005 = [f for f in self.findings if f.get("rule_id") == "SEC005"]
        self.assertGreaterEqual(len(sec005), 1, "SEC005 Path Traversal should be detected")

    def test_path_traversal_is_critical(self) -> None:
        sec005 = next((f for f in self.findings if f.get("rule_id") == "SEC005"), None)
        self.assertIsNotNone(sec005)
        self.assertEqual(sec005.get("severity"), "critical")
        self.assertTrue(sec005.get("pr_blocking"))

    def test_path_traversal_has_replacement(self) -> None:
        sec005 = next((f for f in self.findings if f.get("rule_id") == "SEC005"), None)
        self.assertIsNotNone(sec005)
        replacement = sec005.get("replacement", "")
        self.assertIn("os.path.basename", replacement, "Replacement should use basename sanitization")

    # ------------------------------------------------------------------
    # SUG001: Context manager suggestion
    # ------------------------------------------------------------------
    def test_sug001_connection_suggestion(self) -> None:
        sug001 = [f for f in self.findings if f.get("rule_id") == "SUG001"]
        self.assertGreaterEqual(len(sug001), 1, "SUG001 context manager suggestion should appear")

    def test_sug001_is_non_blocking(self) -> None:
        sug001 = next((f for f in self.findings if f.get("rule_id") == "SUG001"), None)
        self.assertIsNotNone(sug001)
        self.assertFalse(sug001.get("pr_blocking"), "SUG001 must be non-blocking")
        self.assertIn(sug001.get("severity"), ("minor", "info"))

    # ------------------------------------------------------------------
    # All three security vulnerabilities present
    # ------------------------------------------------------------------
    def test_all_three_security_vulns_present(self) -> None:
        self.assertIn("SEC003", self.rule_ids, "SQL Injection (SEC003) must be detected")
        self.assertIn("SEC004", self.rule_ids, "Command Injection (SEC004) must be detected")
        self.assertIn("SEC005", self.rule_ids, "Path Traversal (SEC005) must be detected")


class CommandInjectionEdgeCaseTests(unittest.TestCase):
    """Targeted tests for SEC004 edge cases."""

    def test_shell_true_without_fstring_is_flagged(self) -> None:
        snippet = (
            "import subprocess\n"
            "def run(cmd):\n"
            "    subprocess.run(cmd, shell=True)\n"
        )
        findings = scan_python_source(snippet)
        sec004 = [f for f in findings if f.get("rule_id") == "SEC004"]
        self.assertGreaterEqual(len(sec004), 1)

    def test_safe_subprocess_list_not_flagged(self) -> None:
        snippet = (
            "import subprocess\n"
            "def run():\n"
            "    subprocess.run(['ls', '-la'], capture_output=True)\n"
        )
        findings = scan_python_source(snippet)
        sec004 = [f for f in findings if f.get("rule_id") == "SEC004"]
        self.assertEqual(len(sec004), 0, "Safe list-form subprocess with no shell=True must not be flagged")


class PathTraversalEdgeCaseTests(unittest.TestCase):
    """Targeted tests for SEC005 edge cases."""

    def test_join_with_only_literals_not_flagged(self) -> None:
        snippet = (
            "import os\n"
            "def path():\n"
            "    return os.path.join('/var/data', 'known_file.txt')\n"
        )
        findings = scan_python_source(snippet)
        sec005 = [f for f in findings if f.get("rule_id") == "SEC005"]
        self.assertEqual(len(sec005), 0, "os.path.join with only string literals should not be flagged")

    def test_join_with_variable_is_flagged(self) -> None:
        snippet = (
            "import os\n"
            "def read(filename):\n"
            "    return os.path.join('/var/data', filename)\n"
        )
        findings = scan_python_source(snippet)
        sec005 = [f for f in findings if f.get("rule_id") == "SEC005"]
        self.assertGreaterEqual(len(sec005), 1)


if __name__ == "__main__":
    unittest.main()