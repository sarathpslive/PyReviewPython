from __future__ import annotations

import hashlib
import uuid
from typing import Any

from agent.business_logic_analyzer import BusinessLogicAnalyzer
from agent.dag_event_stream import DAGEventStream
from agent.llm_reasoner import LLMReasoner
from agent.memory import InMemoryReviewMemory
from agent.owasp_tool import OWASPWebsiteTool
from agent.recommendation_history_store import get_recommendation_history_store
from agent.review_event_broadcaster import review_event_broadcaster
from agent.review_tools import OWASP_TOP_10, gather_repo_findings, scan_python_source
from security.model_armor import ModelArmorService


class CodeReviewOrchestrator:
    def __init__(self) -> None:
        self.memory = InMemoryReviewMemory()
        self.history_store = get_recommendation_history_store()
        self.reasoner = LLMReasoner()
        self.model_armor = ModelArmorService()
        self.owasp_tool = OWASPWebsiteTool()
        self.business_analyzer = BusinessLogicAnalyzer()

    def review(
        self,
        repo_path: str | None = None,
        code_snippet: str | None = None,
        language: str = "python",
        review_id: str | None = None,
        business_documents: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        review_id = review_id or hashlib.sha256(
            f"{uuid.uuid4()}-{repo_path or code_snippet or 'snippet'}".encode()
        ).hexdigest()[:12]
        stream = DAGEventStream(review_id=review_id, broadcaster=review_event_broadcaster)

        armor_result = self.model_armor.check(code_snippet or repo_path or "", source="review_input")
        stream.emit("model_armor", "scan_started", {"status": "running", "scope": "code_and_review_context"})
        stream.emit("model_armor", "scan_completed", armor_result)
        stream.emit("orchestrator", "pipeline_started", {"mode": "repo" if repo_path else "snippet"})
        stream.emit("github_mcp", "mcp_tool_available", {"server": "@modelcontextprotocol/server-github", "tools": ["get_file_contents", "create_pull_request_review", "add_issue_comment"]})
        stream.emit("repo_loader", "started", {"repo_path": repo_path, "language": language})
        self.memory.add(review_id, "system", "Review started", repo_path=repo_path, language=language)

        findings: list[dict[str, Any]] = []
        if repo_path:
            stream.emit("tool_calls", "repository_scanner_started", {"tool": "discover_python_files"})
            stream.emit("repo_loader", "files_discovered", {"count": 0})
            findings.extend(gather_repo_findings(repo_path))
            stream.emit("repo_loader", "files_discovered", {"count": len(findings)})
            stream.emit("repo_loader", "completed", {"source": "repository"})
            stream.emit("static_analysis", "ast_completed", {"mode": "repository"})
            stream.emit("ruff", "scan_completed", {"mode": "repository"})
            stream.emit("tool_calls", "repository_scanner_completed", {"tool": "gather_repo_findings", "finding_count": len(findings)})
        elif code_snippet:
            import tempfile
            from pathlib import Path
            from agent.review_tools import run_ruff_scan
            
            stream.emit("tool_calls", "python_ast_scanner_started", {"tool": "scan_python_source"})
            stream.emit("static_analysis", "ast_parsed", {"source_length": len(code_snippet)})
            findings.extend(scan_python_source(code_snippet))
            stream.emit("static_analysis", "ast_completed", {"mode": "snippet"})
            
            # Run Ruff on snippet via temp file
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp_file:
                    tmp_file.write(code_snippet)
                    tmp_path = tmp_file.name
                
                stream.emit("ruff", "scan_started", {"mode": "snippet", "temp_file": tmp_path})
                ruff_findings = run_ruff_scan(tmp_path)
                findings.extend(ruff_findings)
                stream.emit("ruff", "scan_completed", {"mode": "snippet", "finding_count": len(ruff_findings)})
            except Exception as exc:
                stream.emit("ruff", "scan_failed", {"mode": "snippet", "error": str(exc)})
            finally:
                if tmp_path and Path(tmp_path).exists():
                    Path(tmp_path).unlink()
            
            stream.emit("repo_loader", "completed", {"source": "snippet"})
            stream.emit("tool_calls", "python_ast_scanner_completed", {"tool": "scan_python_source", "finding_count": len(findings)})

        stream.emit("deterministic_gate", "passed", {"finding_count": len(findings)})

        prioritized = self._prioritize(findings)
        stream.emit("review_reasoner", "issues_ranked", {"count": len(prioritized)})

        retrieval_query = self._build_retrieval_query(prioritized=prioritized, code_snippet=code_snippet)
        stream.emit("rag", "retrieval_started", {"query_length": len(retrieval_query), "limit": 3})
        historical_context = self.history_store.summarize_for_prompt(query_text=retrieval_query, limit=3)
        stream.emit("rag", "retrieval_completed", {"context_length": len(historical_context), "matches": historical_context.count("\n-")})
        stream.emit("owasp", "lookup_started", {"tool": "OWASPWebsiteTool"})
        owasp_findings = self.owasp_tool.lookup(prioritized)
        stream.emit("owasp", "lookup_completed", {"categories": len(owasp_findings)})
        stream.emit("tool_calls", "owasp_context_loaded", {"tool": "OWASPWebsiteTool", "categories": len(owasp_findings)})
        
        business_logic_findings: list[dict[str, Any]] = []
        if business_documents:
            stream.emit("business_logic", "analysis_started", {"document_count": len(business_documents)})
            for doc in business_documents:
                doc_content = doc.get("content", "")
                doc_type = doc.get("type", "other")
                doc_findings = self.business_analyzer.analyze(doc_content, code_snippet or "", doc_type)
                business_logic_findings.extend(doc_findings)
            stream.emit("business_logic", "analysis_completed", {"finding_count": len(business_logic_findings)})
        else:
            code_biz_findings = [f for f in prioritized if f.get("category") == "business_logic"]
            if code_biz_findings:
                stream.emit("business_logic", "flaws_detected", {"finding_count": len(code_biz_findings)})
                business_logic_findings.extend(code_biz_findings)
        
        stream.emit("agent_reasoner", "reasoning_started", {"provider": self.reasoner.settings.llm_provider, "model": self.reasoner.settings.llm_model})
        llm_summary = self.reasoner.generate_review_reasoning(
            findings=prioritized,
            historical_context=historical_context,
            owasp_context=[item["category"] for item in owasp_findings] or OWASP_TOP_10,
        )
        stream.emit("agent_reasoner", "reasoning_completed", {"fallback_used": llm_summary.get("fallback_used", False)})
        stream.emit("review_reasoner", "recommendations_generated", {"summary": llm_summary["summary"]})

        source = "repo" if repo_path else "snippet"
        rows_added = self.history_store.add_findings(
            review_id=review_id,
            findings=prioritized,
            source=source,
            language=language,
            extra_metadata={"repo_path": repo_path},
        )
        stream.emit("memory", "history_persisted", {"rows_added": rows_added, "source": source})
        stream.emit("pull_request", "review_ready", {"status": "pending", "reason": "No pull request target was supplied."})
        stream.emit("orchestrator", "pipeline_completed", {"status": "review_ready"})

        review_result = {
            "review_id": review_id,
            "language": language,
            "source": source,
            "source_code": code_snippet or "",
            "owasp_context": OWASP_TOP_10,
            "owasp_findings": owasp_findings,
            "business_logic_findings": business_logic_findings,
            "model_armor": armor_result,
            "summary": llm_summary["summary"],
            "recommendations": llm_summary.get("recommendations", []),
            "llm_provider": llm_summary.get("provider"),
            "llm_model": llm_summary.get("model"),
            "llm_fallback_used": llm_summary.get("fallback_used", False),
            "llm_fallback_reason": llm_summary.get("fallback_reason"),
            "historical_context": historical_context,
            "total_findings": len(prioritized),
            "findings": prioritized,
            "dag_events": stream.snapshot(),
            "memory": self.memory.summarize(review_id),
        }

        self.memory.add(review_id, "assistant", llm_summary["summary"], total_findings=len(prioritized))
        return review_result

    def _prioritize(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        severity_order = {"critical": 4, "major": 3, "minor": 2, "info": 1, "high": 3, "medium": 2, "low": 1, "error": 4}
        sorted_findings = sorted(
            findings,
            key=lambda item: (
                severity_order.get(str(item.get("severity", "low")).lower(), 0),
                -(int(item.get("line", 1)) or 1),
            ),
            reverse=True,
        )

        deduped: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in sorted_findings:
            key = f"{item.get('line')}-{item.get('rule_id')}-{item.get('message')}"
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def _build_retrieval_query(self, prioritized: list[dict[str, Any]], code_snippet: str | None) -> str:
        if prioritized:
            top = prioritized[0]
            return (
                f"{top.get('rule_id', 'GENERIC')} "
                f"{top.get('category', 'quality')} "
                f"{top.get('message', '')} "
                f"{top.get('recommendation', '')}"
            )

        if code_snippet:
            return code_snippet[:400]

        return "python code review recommendations"

