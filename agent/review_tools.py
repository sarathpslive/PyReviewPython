from __future__ import annotations

import ast
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

OWASP_TOP_10 = [
    "Broken Access Control",
    "Cryptographic Failures",
    "Injection",
    "Insecure Design",
    "Security Misconfiguration",
    "Vulnerable and Outdated Components",
    "Identification and Authentication Failures",
    "Software and Data Integrity Failures",
    "Security Logging and Monitoring Failures",
    "Server-Side Request Forgery (SSRF)",
]

_SENSITIVE_NAME_TOKENS = {
    "apikey",
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "accesskey",
    "clientsecret",
    "privatekey",
    "authkey",
}

_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*=\s*([\"']).{4,}\2\s*$",
    re.IGNORECASE,
)

_SEVERITY_POLICY = {
    "critical": {"label": "Critical / Blocker", "pr_blocking": True},
    "major": {"label": "Major / Required", "pr_blocking": True},
    "minor": {"label": "Minor / Suggestion", "pr_blocking": False},
    "info": {"label": "Info / Nitpick (Nit)", "pr_blocking": False},
}


def _python_ast_issues(source: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        syntax_issue = {
            "line": exc.lineno or 1,
            "severity": "critical",
            "rule_id": "PY001",
            "category": "syntax",
            "message": f"Python syntax error: {exc.msg}",
            "recommendation": "Fix the syntax before review continues.",
            "evidence": exc.text.strip() if exc.text else "",
        }
        # Keep scanning lexically so partial diffs / long incomplete snippets still report security signals.
        return [syntax_issue, *_lexical_fallback_issues(source)]

    # Generic dangerous calls (non-subprocess; subprocess is handled precisely by SEC004)
    suspicious_calls = {
        "eval": "Avoid dynamic execution; prefer explicit parsing or safe APIs.",
        "exec": "Avoid runtime code execution from untrusted input.",
        "pickle.loads": "Deserialization from untrusted input can lead to code execution.",
        "yaml.load": "Use safe loaders like yaml.safe_load instead of yaml.load.",
        "requests.get": "Ensure outbound requests are constrained and validated. Consider timeouts.",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _call_name(node.func)
            if func_name in suspicious_calls:
                issues.append({
                    "line": getattr(node, "lineno", 1),
                    "severity": "critical" if func_name in {"eval", "exec", "pickle.loads"} else "major",
                    "rule_id": "SEC001",
                    "category": "security",
                    "message": f"Suspicious call detected: {func_name}",
                    "recommendation": suspicious_calls[func_name],
                    "evidence": func_name,
                })

    # -----------------------------------------------------------------
    # SEC004: Command Injection via subprocess / os.system with shell=True
    #         or dynamic command string formatting.
    # -----------------------------------------------------------------
    _SUBPROCESS_FUNCS = {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.call",
        "os.system",
        "os.popen",
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _call_name(node.func)
        if func_name not in _SUBPROCESS_FUNCS:
            continue

        # Check for shell=True keyword
        has_shell_true = any(
            isinstance(kw, ast.keyword) and kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )

        # Check whether the command argument is dynamically constructed (f-string or Name)
        cmd_arg = node.args[0] if node.args else None
        cmd_is_dynamic = isinstance(cmd_arg, (ast.JoinedStr, ast.BinOp, ast.Call))

        if has_shell_true or cmd_is_dynamic:
            func_short = func_name.split(".")[-1]
            issues.append({
                "line": getattr(node, "lineno", 1),
                "severity": "critical",
                "rule_id": "SEC004",
                "category": "security",
                "message": (
                    "Command Injection: subprocess called with shell=True and a dynamic command string. "
                    "An attacker can append arbitrary shell commands using ;, &&, or | operators."
                ),
                "recommendation": (
                    "Pass the command as a list of arguments and remove shell=True so the OS never "
                    "invokes a shell interpreter. Validate and whitelist every element of user input."
                ),
                "evidence": f"{func_name}(..., shell=True)" if has_shell_true else f"{func_name}(f\"...\", ...)",
                "replacement": (
                    f"# Pass command as a list — no shell interpreter invoked\n"
                    f"output = subprocess.check_output([\"ping\", \"-c\", \"1\", host_input], text=True)"
                    if func_short in ("check_output",)
                    else (
                        f"# Pass command as a list — no shell interpreter invoked\n"
                        f"result = subprocess.run([\"your_cmd\", arg1, arg2], capture_output=True, text=True, check=True)"
                    )
                ),
            })

    # -----------------------------------------------------------------
    # SEC003: SQL Injection — detect f-string SQL assignment and execute()
    # Produce ONE consolidated finding per query: prefer the execute() line
    # so the finding points at the actual injection site with a targeted fix.
    # -----------------------------------------------------------------
    sql_fstring_variables: dict[str, dict] = {}   # var_name -> preliminary finding dict
    sql_injection_issues: list[dict[str, Any]] = []
    sql_reported_vars: set[str] = set()           # vars already surfaced via execute()

    for node in ast.walk(tree):
        # Step 1: detect SQL f-string assignments
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.JoinedStr):
            target_names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            sql_text = "".join(item.value for item in node.value.values if isinstance(item, ast.Constant)).lower()
            has_sql_keyword = any(keyword in sql_text for keyword in ("select ", "insert ", "update ", "delete "))
            has_interpolation = any(isinstance(item, ast.FormattedValue) for item in node.value.values)

            if has_sql_keyword and has_interpolation:
                preliminary = {
                    "line": getattr(node, "lineno", 1),
                    "severity": "critical",
                    "rule_id": "SEC003",
                    "category": "security",
                    "message": "SQL Injection: SQL query built with string interpolation — user input is embedded directly into the query.",
                    "recommendation": "Use parameterized queries. Pass user values as bound parameters, never via string formatting.",
                    "evidence": "SQL f-string with variable interpolation",
                    "replacement": (
                        "# Safe parameterized query — user input is treated as data, not SQL\n"
                        "cursor.execute(\"SELECT * FROM users WHERE username = ?\", (username,))"
                    ),
                }
                for name in target_names:
                    sql_fstring_variables[name] = preliminary

        # Step 2: when execute() is called with a tainted variable, upgrade to execute-site finding
        if isinstance(node, ast.Call) and _call_name(node.func).split(".")[-1] in {"execute", "executemany"}:
            query_argument = node.args[0] if node.args else None

            # Direct f-string in execute()
            if isinstance(query_argument, ast.JoinedStr):
                sql_injection_issues.append({
                    "line": getattr(node, "lineno", 1),
                    "severity": "critical",
                    "rule_id": "SEC003",
                    "category": "security",
                    "message": "SQL Injection: SQL query built with f-string interpolation passed directly to cursor.execute().",
                    "recommendation": "Use parameterized queries. Pass user values as bound parameters, never via string formatting.",
                    "evidence": "f-string SQL passed to execute()",
                    "replacement": (
                        "# Safe parameterized query — user input is treated as data, not SQL\n"
                        "cursor.execute(\"SELECT * FROM users WHERE username = ?\", (username,))"
                    ),
                })

            # Tainted variable passed to execute()
            elif isinstance(query_argument, ast.Name) and query_argument.id in sql_fstring_variables:
                var_name = query_argument.id
                preliminary = sql_fstring_variables[var_name]
                sql_reported_vars.add(var_name)
                sql_injection_issues.append({
                    **preliminary,
                    "line": getattr(node, "lineno", 1),
                    "evidence": f"Tainted variable `{var_name}` (SQL f-string from line {preliminary['line']}) passed to execute()",
                    "replacement": (
                        "# Safe parameterized query — user input is treated as data, not SQL\n"
                        "cursor.execute(\"SELECT * FROM users WHERE username = ?\", (username,))"
                    ),
                })

    # Add any un-consumed preliminary findings (f-string SQL not fed to execute())
    for var_name, finding in sql_fstring_variables.items():
        if var_name not in sql_reported_vars:
            sql_injection_issues.append(finding)

    issues.extend(sql_injection_issues)

    # -----------------------------------------------------------------
    # SEC005: Path Traversal — os.path.join / open / Path() with tainted argument
    # -----------------------------------------------------------------
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _call_name(node.func)

        # Detect os.path.join(base_dir, user_input) without os.path.basename sanitization
        if func_name in {"os.path.join", "os.path.normpath"}:
            # Flag if any argument is a Name (variable) that could be user-controlled
            non_literal_args = [a for a in node.args if not isinstance(a, ast.Constant)]
            if len(non_literal_args) >= 1:
                issues.append({
                    "line": getattr(node, "lineno", 1),
                    "severity": "critical",
                    "rule_id": "SEC005",
                    "category": "security",
                    "message": (
                        "Path Traversal: User-controlled input is passed to os.path.join() without sanitization. "
                        "An attacker can escape the intended base directory using sequences like ../../etc/passwd."
                    ),
                    "recommendation": (
                        "Sanitize the filename with os.path.basename() to strip any directory components, "
                        "then verify the resolved path is still within the intended base directory using os.path.abspath()."
                    ),
                    "evidence": f"{func_name}(base_dir, filename)",
                    "replacement": (
                        "import os\n"
                        "safe_name = os.path.basename(filename)  # strip any ../ traversal\n"
                        "filepath = os.path.join(base_dir, safe_name)\n"
                        "# Verify path stays inside base_dir\n"
                        "if not os.path.abspath(filepath).startswith(os.path.abspath(base_dir)):\n"
                        "    raise ValueError('Invalid file path')"
                    ),
                })



    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            is_literal_assignment = _is_hardcoded_literal(node.value)
            for target in node.targets:
                target_name = _extract_assignment_target_name(target)
                if target_name and _looks_sensitive_identifier(target_name):
                    issues.append({
                        "line": getattr(node, "lineno", 1),
                        "severity": "critical" if is_literal_assignment else "major",
                        "rule_id": "SEC002",
                        "category": "security",
                        "message": "Sensitive value assigned in code.",
                        "recommendation": "Load secrets from environment variables or a secret manager instead of hardcoding them.",
                        "evidence": target_name,
                    })

        if isinstance(node, ast.AnnAssign):
            target_name = _extract_assignment_target_name(node.target)
            if target_name and _looks_sensitive_identifier(target_name):
                is_literal_assignment = _is_hardcoded_literal(node.value)
                issues.append({
                    "line": getattr(node, "lineno", 1),
                    "severity": "critical" if is_literal_assignment else "major",
                    "rule_id": "SEC002",
                    "category": "security",
                    "message": "Sensitive value assigned in code.",
                    "recommendation": "Load secrets from environment variables or a secret manager instead of hardcoding them.",
                    "evidence": target_name,
                })

    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            issues.append({
                "line": getattr(node, "lineno", 1),
                "severity": "minor",
                "rule_id": "PY002",
                "category": "quality",
                "message": "Use of assert is not recommended in production code.",
                "recommendation": "Replace assert statements with explicit validation and exceptions.",
                "evidence": "assert",
            })

    issues.extend(_business_logic_ast_issues(tree, source))
    issues.extend(_quality_suggestion_issues(tree, source))

    return issues


def _quality_suggestion_issues(tree: ast.AST, source: str) -> list[dict[str, Any]]:
    """Non-blocking code quality suggestions (SUG-series rules)."""
    issues: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue

        func_body_lines = ast.get_source_segment(source, node) or ""
        func_lower = func_body_lines.lower()

        # -----------------------------------------------------------------
        # SUG001: DB connection not using context manager (with statement)
        # -----------------------------------------------------------------
        has_db_connect = ".connect(" in func_lower
        has_context_manager = "with " in func_lower and ".connect(" in func_lower
        has_close_call = ".close()" in func_lower

        if has_db_connect and not has_context_manager and has_close_call:
            issues.append({
                "line": getattr(node, "lineno", 1),
                "severity": "minor",
                "rule_id": "SUG001",
                "category": "quality",
                "message": (
                    "Suggestion: Database connection managed manually with .close() instead of a context manager. "
                    "Manual close() can be skipped if an exception is raised, leaking the connection."
                ),
                "recommendation": (
                    "Use `with sqlite3.connect(...) as conn:` so the connection is always closed, "
                    "even if an exception is raised mid-function."
                ),
                "evidence": ".close()",
                "replacement": (
                    "# Context manager ensures connection is always closed\n"
                    "with sqlite3.connect('users.db') as conn:\n"
                    "    cursor = conn.cursor()\n"
                    "    cursor.execute(\"SELECT * FROM users WHERE username = ?\", (username,))\n"
                    "    return cursor.fetchall()"
                ),
            })

        # -----------------------------------------------------------------
        # SUG002: Function lacks return type annotation
        # -----------------------------------------------------------------
        if node.returns is None:
            issues.append({
                "line": getattr(node, "lineno", 1),
                "severity": "info",
                "rule_id": "SUG002",
                "category": "quality",
                "message": f"Suggestion: Function `{node.name}` is missing a return type annotation.",
                "recommendation": (
                    "Add a return type annotation (e.g. `-> list[dict]` or `-> str`) to improve readability, "
                    "IDE support, and runtime type checking."
                ),
                "evidence": f"def {node.name}(...)",
                "replacement": f"def {node.name}(...) -> <return_type>:",
            })

        # -----------------------------------------------------------------
        # SUG003: subprocess or network call without input validation
        # -----------------------------------------------------------------
        has_subprocess = any(
            isinstance(child, ast.Call) and _call_name(child.func).startswith("subprocess.")
            for child in ast.walk(node)
        )
        # Heuristic: no isinstance/regex/if-guard before the subprocess call
        has_validation = "isinstance(" in func_lower or "re." in func_lower or "validate" in func_lower
        if has_subprocess and not has_validation:
            issues.append({
                "line": getattr(node, "lineno", 1),
                "severity": "minor",
                "rule_id": "SUG003",
                "category": "quality",
                "message": (
                    f"Suggestion: Function `{node.name}` invokes a subprocess without apparent input validation. "
                    "Validate and sanitize arguments before passing them to system calls."
                ),
                "recommendation": (
                    "Validate the input (e.g. with a regex whitelist for IP addresses or hostnames) "
                    "and raise an exception if the input does not match expected patterns."
                ),
                "evidence": "subprocess call with unvalidated argument",
                "replacement": (
                    "import re\n"
                    "# Whitelist: allow only valid IPv4 or hostname\n"
                    "if not re.match(r'^[a-zA-Z0-9._-]+$', host_input):\n"
                    "    raise ValueError(f'Invalid host: {host_input!r}')\n"
                    "output = subprocess.check_output([\"ping\", \"-c\", \"1\", host_input], text=True)"
                ),
            })

    return issues


def _business_logic_ast_issues(tree: ast.AST, source: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    source_lower = source.lower()
    has_global_discount = any(tok in source_lower for tok in ["discount", "promo_code", "coupon", "voucher"])
    has_global_proportional = any(tok in source_lower for tok in [
        "effective_paid_price", "item_discount", "item_share", "proportional", "paid_price", "allocated_discount"
    ])

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            class_text = ast.get_source_segment(source, node) or ""
            class_lower = class_text.lower()
            has_class_discount = any(tok in class_lower for tok in ["discount", "promo_code", "coupon", "voucher"]) or has_global_discount
            has_class_proportional = any(tok in class_lower for tok in [
                "effective_paid_price", "item_discount", "item_share", "proportional", "paid_price", "allocated_discount"
            ]) or has_global_proportional

            for method in node.body:
                if isinstance(method, ast.FunctionDef):
                    # BIZ001: Refund item returns sticker price without proportional attribution
                    if any(term in method.name.lower() for term in ["refund", "return_item", "process_refund"]):
                        for sub in ast.walk(method):
                            if isinstance(sub, ast.Return) and sub.value:
                                is_price_attr = isinstance(sub.value, ast.Attribute) and sub.value.attr == "price"
                                is_raw_price = isinstance(sub.value, ast.Name) and sub.value.id == "price"
                                if (is_price_attr or is_raw_price) and has_class_discount and not has_class_proportional:
                                    issues.append({
                                        "line": getattr(sub, "lineno", method.lineno),
                                        "severity": "critical",
                                        "rule_id": "BIZ001",
                                        "category": "business_logic",
                                        "message": (
                                            "Business Logic Flaw: Sticker Price Refund Exploit (Threshold Abuse / "
                                            "Missing Proportional Discount Attribution). Refunding item sticker price "
                                            "when order-level discounts exist allows customers to buy to discount and return to profit."
                                        ),
                                        "recommendation": (
                                            "Do not refund the item's original sticker price when order-level discounts "
                                            "have been applied. Implement proportional discount attribution across order line-items "
                                            "(e.g., allocating effective_paid_price = price - item_discount) so refunds never exceed net realized revenue."
                                        ),
                                        "evidence": "return item.price",
                                    })

                    # BIZ002: Threshold discount without recalculation/clawback on partial return
                    if any(term in method.name.lower() for term in ["discount", "__init__", "calculate", "apply"]):
                        for stmt in ast.walk(method):
                            if isinstance(stmt, ast.If) and isinstance(stmt.test, ast.Compare):
                                comp = stmt.test
                                left_name = ""
                                if isinstance(comp.left, ast.Attribute):
                                    left_name = comp.left.attr
                                elif isinstance(comp.left, ast.Name):
                                    left_name = comp.left.id

                                if "subtotal" in left_name.lower() or "total" in left_name.lower():
                                    has_clawback = any(tok in class_lower for tok in [
                                        "clawback", "recalculate", "adjust_discount", "threshold_recheck", "remaining"
                                    ])
                                    if not has_clawback and "refund" in class_lower and not has_class_proportional:
                                        issues.append({
                                            "line": getattr(stmt, "lineno", method.lineno),
                                            "severity": "major",
                                            "rule_id": "BIZ002",
                                            "category": "business_logic",
                                            "message": (
                                                "Business Logic Flaw: Threshold Padding / Missing Promotion Recalculation on Partial Return. "
                                                "Cart threshold qualifies for tier discount but partial returns do not recalculate eligibility."
                                            ),
                                            "recommendation": (
                                                "Recalculate order threshold eligibility upon partial return or cancellation. "
                                                "If remaining items drop below the qualifying threshold, claw back or adjust the promotion."
                                            ),
                                            "evidence": f"if {left_name} >= threshold",
                                        })

                    # BIZ003: Unconstrained additive discount stacking without margin floor / COGS check
                    if any(term in method.name.lower() for term in ["discount", "__init__", "apply"]):
                        has_pct_discount = bool("0." in class_lower or "percent" in class_lower)
                        has_flat_coupon = bool("promo_code" in class_lower or "coupon" in class_lower)
                        has_floor_or_cap = any(tok in class_lower for tok in ["min(", "max(", "floor", "cogs", "cost", "margin"])
                        if has_pct_discount and has_flat_coupon and not has_floor_or_cap:
                            issues.append({
                                "line": method.lineno,
                                "severity": "major",
                                "rule_id": "BIZ003",
                                "category": "business_logic",
                                "message": (
                                    "Business Logic Flaw: Unconstrained Additive Discount Stacking without Margin Floor. "
                                    "Percentage discount and flat coupons stack additively without minimum floor or COGS checks."
                                ),
                                "recommendation": (
                                    "Define strict evaluation ordering (apply percentage discount sequentially, or enforce mutual exclusion) "
                                    "and enforce a post-discount basket floor so items cannot be sold below cost."
                                ),
                                "evidence": "additive discount stacking without min/floor",
                            })

    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            if any(term in node.name.lower() for term in ["refund", "return_item", "process_refund"]):
                if has_global_discount and not has_global_proportional:
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Return) and sub.value:
                            is_price_attr = isinstance(sub.value, ast.Attribute) and sub.value.attr == "price"
                            is_raw_price = isinstance(sub.value, ast.Name) and sub.value.id == "price"
                            if is_price_attr or is_raw_price:
                                issues.append({
                                    "line": getattr(sub, "lineno", node.lineno),
                                    "severity": "critical",
                                    "rule_id": "BIZ001",
                                    "category": "business_logic",
                                    "message": (
                                        "Business Logic Flaw: Sticker Price Refund Exploit (Threshold Abuse / "
                                        "Missing Proportional Discount Attribution). Standalone refund handler returns sticker price."
                                    ),
                                    "recommendation": (
                                        "Implement proportional discount attribution across order line items "
                                        "so that refunded amount reflects net realized revenue instead of sticker price."
                                    ),
                                    "evidence": "return item.price",
                                })

    return issues


def _lexical_fallback_issues(source: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for line_no, line in enumerate(source.splitlines(), start=1):
        match = _SENSITIVE_ASSIGNMENT_RE.match(line)
        if not match:
            continue

        identifier = match.group(1)
        if not _looks_sensitive_identifier(identifier):
            continue

        issues.append({
            "line": line_no,
            "severity": "critical",
            "rule_id": "SEC002",
            "category": "security",
            "message": "Sensitive value assigned in code.",
            "recommendation": "Load secrets from environment variables or a secret manager instead of hardcoding them.",
            "evidence": identifier,
        })
    return issues


def _extract_assignment_target_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _normalize_identifier(identifier: str) -> str:
    return re.sub(r"[^a-z0-9]", "", identifier.lower())


def _looks_sensitive_identifier(identifier: str) -> bool:
    normalized = _normalize_identifier(identifier)
    return any(token in normalized for token in _SENSITIVE_NAME_TOKENS)


def _is_hardcoded_literal(node: ast.AST | None) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, bytes, int, float))
    if isinstance(node, ast.JoinedStr):
        return True
    return False


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def run_ruff_scan(file_path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    path = str(file_path)
    if not os.path.exists(path):
        return []

    result: list[dict[str, Any]] = []
    try:
        completed = subprocess.run(
            ["ruff", "check", "--output-format=json", path],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode in (0, 1):
            try:
                payload = json.loads(completed.stdout or "[]")
                for item in payload:
                    result.append({
                        "line": int(item.get("location", {}).get("row", 1)),
                        "severity": _normalize_severity(item.get("severity"), item.get("code"), item.get("message")),
                        "rule_id": item.get("code", "RUF"),
                        "category": "lint",
                        "message": item.get("message", "Lint issue"),
                        "recommendation": "Fix the issue reported by Ruff to keep the codebase consistent and secure.",
                        "evidence": item.get("filename", path),
                    })
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        pass

    return [_with_severity_policy(finding) for finding in result]


def scan_python_source(source: str) -> list[dict[str, Any]]:
    return [_with_severity_policy(finding) for finding in _python_ast_issues(source)]


def _normalize_severity(
    value: object,
    code: object | None = None,
    message: object | None = None,
    category: object | None = None,
) -> str:
    """
    Normalize severity without treating every Ruff error as Critical.

    Security findings are classified separately from normal lint findings.
    """

    severity = str(value or "info").lower()
    code_name = str(code or "").upper()
    message_text = str(message or "").lower()
    category_name = str(category or "").lower()

    # ---------------------------------------------------------
    # 1. Explicit security rules from our AST/security scanner
    # ---------------------------------------------------------
    security_critical_rules = {
        "SEC001",  # Dangerous calls
        "SEC002",  # Hardcoded secret
        "SEC003",  # SQL injection
        "SEC004",  # Command injection
        "SEC005",  # Path traversal
    }

    if code_name in security_critical_rules:
        return "critical"

    # SUG-series rules are always non-blocking suggestions or informational
    if code_name.startswith("SUG"):
        # SUG002 is purely informational (missing type annotations)
        return "info" if code_name == "SUG002" else "minor"

    # ---------------------------------------------------------
    # 2. Security indicators from scanner messages
    # ---------------------------------------------------------
    critical_security_markers = (
        "sql injection",
        "command injection",
        "remote code execution",
        "code execution",
        "hardcoded secret",
        "hardcoded password",
        "unsafe deserialization",
        "pickle.loads",
        "eval(",
        "exec(",
    )

    if any(marker in message_text for marker in critical_security_markers):
        return "critical"

    # ---------------------------------------------------------
    # 3. Other security findings
    # ---------------------------------------------------------
    security_markers = (
        "security",
        "unsafe",
        "subprocess",
        "deserial",
        "shell",
        "path traversal",
        "yaml.load",
        "ssrf",
    )

    if category_name == "security" or any(
        marker in message_text for marker in security_markers
    ):
        return "major"

    # ---------------------------------------------------------
    # 4. Ruff / normal lint findings
    # ---------------------------------------------------------
    # IMPORTANT:
    # Ruff "error" does NOT mean Critical.
    #
    # Examples:
    # F401 = unused import
    # F841 = unused variable
    # E501 = line too long
    # These should generally remain Minor.
    # ---------------------------------------------------------

    ruff_minor_rules = {
        "F401",  # unused import
        "F841",  # local variable assigned but never used
        "E501",  # line too long
        "E302",  # expected 2 blank lines
        "E305",  # expected 2 blank lines after class/function
        "W291",  # trailing whitespace
        "W292",  # no newline at end of file
        "W293",  # whitespace on blank line
        "UP",    # pyupgrade
        "SIM",   # simplify
        "N",     # naming
        "ANN",   # annotations
        "D",     # documentation
    }

    # Handle prefixes such as UP, SIM, etc.
    if (
        code_name in ruff_minor_rules
        or any(code_name.startswith(prefix) for prefix in ruff_minor_rules)
    ):
        return "minor"

    # Ruff correctness issues can be more important than style.
    ruff_major_rules = {
        "F821",  # undefined name
        "F811",  # redefined while unused
        "F822",  # undefined export
    }

    if code_name in ruff_major_rules:
        return "major"

    # ---------------------------------------------------------
    # 5. Generic severity fallback
    # ---------------------------------------------------------
    severity_map = {
        "error": "major",
        "warning": "minor",
        "high": "major",
        "medium": "minor",
        "low": "minor",
        "info": "info",
        "critical": "critical",
        "major": "major",
        "minor": "minor",
    }

    return severity_map.get(severity, "info")

def _with_severity_policy(finding: dict[str, Any]) -> dict[str, Any]:
    severity = _normalize_severity(
        finding.get("severity"),
        finding.get("rule_id"),
        finding.get("message"),
    )
    policy = _SEVERITY_POLICY[severity]
    return {
        **finding,
        "severity": severity,
        "severity_label": policy["label"],
        "pr_blocking": policy["pr_blocking"],
        "comment_prefix": f"### **[{policy['label']}] ({severity.title()})**",
    }


def discover_python_files(repo_path: str | Path) -> list[str]:
    root = Path(repo_path)
    if not root.exists():
        return []
    return [str(path) for path in root.rglob("*.py") if path.is_file()]


def gather_repo_findings(repo_path: str | Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for file_path in discover_python_files(repo_path):
        try:
            source = Path(file_path).read_text(encoding="utf-8")
        except OSError:
            continue
        findings.extend(scan_python_source(source))
        findings.extend(run_ruff_scan(file_path))
    return findings
