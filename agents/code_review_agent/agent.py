import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from google import adk

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

# Load .env
load_dotenv(repo_root / ".env")

# Ensure GOOGLE_API_KEY is populated from GEMINI_API_KEY if needed
gemini_key = os.getenv("GEMINI_API_KEY")
if gemini_key and not os.getenv("GOOGLE_API_KEY"):
    os.environ["GOOGLE_API_KEY"] = gemini_key

# Recommended model from Google Gemini API
model_name = os.getenv("LLM_MODEL") or os.getenv("GEMINI_MODEL") or "gemini-3.6-flash"


def scan_python_code(code_snippet: str) -> str:
    """Scans Python source code using AST analysis for security vulnerabilities (SQL injection, Command injection, Path traversal, and business logic flaws).

    Args:
        code_snippet: Python code text to inspect.

    Returns:
        JSON string containing detected vulnerabilities, severity levels, rule IDs, and remediation guidance.
    """
    import json
    from agent.review_tools import scan_python_source

    findings = scan_python_source(code_snippet)
    return json.dumps({"findings_count": len(findings), "findings": findings}, indent=2)


def check_prompt_safety(text: str) -> str:
    """Checks untrusted input text or instructions against Model Armor guardrails for prompt injection or system prompt extraction.

    Args:
        text: Untrusted user input text.

    Returns:
        JSON string containing threat flags and blocked status.
    """
    import json
    from security.model_armor import ModelArmorService

    result = ModelArmorService().check(text)
    return json.dumps(result, indent=2)


def lookup_owasp_guidance(vulnerability_category: str) -> str:
    """Provides OWASP Top 10 context, CWE mapping, and remediation best practices.

    Args:
        vulnerability_category: Name or type of vulnerability (e.g., 'Injection', 'Broken Access Control').

    Returns:
        Remediation advice and OWASP documentation references.
    """
    from agent.review_tools import OWASP_TOP_10

    matches = [cat for cat in OWASP_TOP_10 if vulnerability_category.lower() in cat.lower()]
    return f"OWASP Top 10 Category Matches: {matches}. Always use parameterized queries, safe execution APIs, and boundary checks."


from google.genai import types

safety_settings = [
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH,
    ),
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH,
    ),
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
        threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH,
    ),
    types.SafetySetting(
        category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
        threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH,
    ),
]

root_agent = adk.Agent(
    name="code_review_agent",
    description="Agentic Code Review & Security Analysis Engine powered by Gemini.",
    model=model_name,
    instruction=(
        "You are an authorized defensive security engineer, static code analyzer, and code quality assistant. "
        "Your role is to help software developers write robust, clean, and defensively protected Python applications. "
        "When code is provided for review or vulnerability assessment: "
        "1. First call the `scan_python_code` tool to run deterministic AST static security analysis. "
        "2. If applicable, call `lookup_owasp_guidance` to correlate OWASP Top 10 categories. "
        "3. Explain the identified security risks constructively, focusing on root causes (such as unescaped input or shell execution). "
        "4. Always provide safe, refactored Python code demonstrating standard defensive remediations: "
        "   - Use parameterized queries (e.g., cursor.execute('SELECT ... ?', (param,))) instead of string formatting. "
        "   - Use safe subprocess execution (e.g., subprocess.run(['cmd', arg], shell=False)) instead of shell=True. "
        "   - Use os.path.realpath / path boundary checks for file paths. "
        "Do not provide weaponized attack payloads or malicious instructions. Focus entirely on constructive remediation and secure development."
    ),
    tools=[scan_python_code, check_prompt_safety, lookup_owasp_guidance],
    generate_content_config=types.GenerateContentConfig(
        safety_settings=safety_settings,
        temperature=0.2,
    ),
)
