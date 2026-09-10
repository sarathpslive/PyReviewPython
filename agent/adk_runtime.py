from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from google import adk

from agent.code_review_orchestrator import CodeReviewOrchestrator


@dataclass(slots=True)
class ADKRuntime:
    project_id: str | None = None
    location: str = "us-central1"
    model_name: str = "gemini-3.6-flash"
    orchestrator: CodeReviewOrchestrator | None = None
    _agent: adk.Agent | None = field(default=None, init=False, repr=False)

    def initialize(self) -> None:
        if self._agent is not None:
            return

        self._agent = adk.Agent(
            name="code_review_agent",
            description="Agentic code review engine for Python repositories and snippets.",
            model=self.model_name,
            instruction=(
                "Review Python code using deterministic checks first. "
                "Use AST and Ruff findings, then reason about OWASP Top 10 risks, "
                "severity, and actionable remediation guidance."
            ),
            mode="single_turn",
        )

    def review(
        self,
        repo_path: str | None = None,
        code_snippet: str | None = None,
        language: str = "python",
        review_id: str | None = None,
        business_documents: list[dict[str, str]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if self._agent is None:
            self.initialize()

        orchestrator = self.orchestrator or CodeReviewOrchestrator()
        if review_id is None and repo_path:
            review_id = f"repo-{abs(hash(repo_path))}"
        elif review_id is None and code_snippet:
            review_id = f"snippet-{abs(hash(code_snippet))}"

        return orchestrator.review(
            repo_path=repo_path,
            code_snippet=code_snippet,
            language=language,
            review_id=review_id,
            business_documents=business_documents,
            **kwargs,
        )

    def run(self, prompt: str) -> str:
        if self._agent is None:
            self.initialize()

        cleaned = prompt.strip()
        if not cleaned:
            return "No prompt provided."

        return (
            "ADK review agent is initialized and ready to orchestrate deterministic and OWASP-aware checks. "
            f"Input length: {len(cleaned)} characters."
        )
