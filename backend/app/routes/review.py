from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect

from agent.adk_runtime import ADKRuntime
from agent.code_review_orchestrator import CodeReviewOrchestrator
from agent.github_pr_review_service import GitHubPRReviewRequest, GitHubPRReviewService
from agent.github_url_resolver import resolve_github_url_async
from agent.recommendation_history_store import get_recommendation_history_store
from agent.story_generator import build_story
from agent.review_event_broadcaster import review_event_broadcaster

router = APIRouter(prefix="/api/v1")
_review_tasks: dict[str, asyncio.Task[None]] = {}


class ReviewRequest:
    def __init__(self, repo_path: str | None = None, code_snippet: str | None = None, language: str = "python") -> None:
        self.repo_path = repo_path
        self.code_snippet = code_snippet
        self.language = language


@router.post("/review")
async def review_code(payload: dict[str, Any]) -> dict[str, object]:
    repo_path = payload.get("repo_path")
    code_snippet = payload.get("code_snippet")
    github_url = payload.get("github_url")
    language = payload.get("language", "python")

    target_url = github_url or (code_snippet if isinstance(code_snippet, str) and code_snippet.strip().startswith(("http://", "https://")) else None)
    if target_url:
        try:
            fetched_code, filename, detected_lang = await resolve_github_url_async(target_url)
            code_snippet = fetched_code
            if detected_lang and language == "python":
                language = detected_lang
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to fetch GitHub URL content: {exc}") from exc

    if not repo_path and not code_snippet:
        raise HTTPException(status_code=400, detail="Either repo_path or code_snippet is required.")

    review_id = f"review-{uuid.uuid4().hex}"
    review_event_broadcaster.create(review_id, asyncio.get_running_loop())
    await review_event_broadcaster.set_status(review_id, "started")
    try:
        runtime = ADKRuntime(orchestrator=CodeReviewOrchestrator())
        result = await asyncio.to_thread(runtime.review, repo_path=repo_path, code_snippet=code_snippet, language=language, review_id=review_id)
        await _execute_pr_review_if_github_url(target_url, review_id, result)
        await review_event_broadcaster.set_status(review_id, "completed", result=result)
        return result
    except Exception as exc:
        await review_event_broadcaster.set_status(review_id, "failed", error=str(exc))
        raise HTTPException(status_code=500, detail="Review processing failed.") from exc


@router.post("/review/start", status_code=202)
async def start_review(payload: dict[str, Any]) -> dict[str, str]:
    repo_path = payload.get("repo_path")
    code_snippet = payload.get("code_snippet")
    github_url = payload.get("github_url")
    language = payload.get("language", "python")
    business_documents = payload.get("business_documents")

    target_url = github_url or (code_snippet if isinstance(code_snippet, str) and code_snippet.strip().startswith(("http://", "https://")) else None)
    if target_url:
        try:
            fetched_code, filename, detected_lang = await resolve_github_url_async(target_url)
            code_snippet = fetched_code
            if detected_lang and language == "python":
                language = detected_lang
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Failed to fetch GitHub URL content: {exc}") from exc

    if not repo_path and not code_snippet:
        raise HTTPException(status_code=400, detail="Either repo_path or code_snippet is required.")

    review_id = f"review-{uuid.uuid4().hex}"
    review_event_broadcaster.create(review_id, asyncio.get_running_loop())
    import inspect
    sig = inspect.signature(_run_review)
    kwargs: dict[str, Any] = {}
    if "target_url" in sig.parameters:
        kwargs["target_url"] = target_url
    if "business_documents" in sig.parameters and business_documents is not None:
        kwargs["business_documents"] = business_documents
    task = asyncio.create_task(_run_review(review_id, repo_path, code_snippet, language, **kwargs))
    _review_tasks[review_id] = task
    task.add_done_callback(lambda _: _review_tasks.pop(review_id, None))
    return {"review_id": review_id, "status": "started"}


async def _execute_pr_review_if_github_url(target_url: str | None, review_id: str, result: dict[str, Any]) -> None:
    if not target_url:
        return
    
    from agent.github_url_resolver import extract_github_metadata
    from agent.github_pr_review_service import GitHubPRReviewService, GitHubPRReviewRequest

    meta = extract_github_metadata(target_url)
    if not meta.get("is_github") or not meta.get("owner") or not meta.get("repo"):
        return

    owner = meta["owner"]
    repo = meta["repo"]
    branch = meta.get("branch")
    pull_number = meta.get("pull_number")

    pr_service = GitHubPRReviewService()
    
    if not pull_number:
        pr = await pr_service.find_open_pull_request(owner, repo, branch)
        if pr:
            pull_number = pr.get("number")
    
    from datetime import datetime, timezone
    
    def emit_event(node: str, event: str, payload: dict[str, Any]) -> Any:
        return review_event_broadcaster.publish(review_id, {
            "review_id": review_id,
            "node": node,
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload
        })

    if pull_number:
        await emit_event("pull_request", "pr_detected", {"pr_number": pull_number, "repo": repo})
        pr_request = GitHubPRReviewRequest(
            owner=owner,
            repo=repo,
            pull_number=pull_number,
            dry_run=False,
            review_event="COMMENT"
        )
        pr_result = await pr_service.review_pull_request(pr_request)
        await emit_event("pull_request", "review_ready", {"review_id": pr_result.get("review_id"), "comments": pr_result.get("inline_comments_count")})
        result["github_pr_review"] = pr_result

        pr_url = pr_result.get("pr_url") or f"https://github.com/{owner}/{repo}/pull/{pull_number}"
        result["pr_url"] = pr_url
        result["github_pr_url"] = pr_url
        result["pr_number"] = pull_number

        pr_findings = pr_result.get("findings", [])
        if pr_findings:
            # Overwrite findings with the actual PR review findings so the website highlights the same issues
            result["findings"] = pr_findings
            result["total_findings"] = len(pr_findings)
            result["summary"] = f"Pull Request #{pull_number} review completed. Found {len(pr_findings)} deterministic issue(s) across changed Python lines."
            
            result["recommendations"] = [
                f"### **[{f.get('severity_label', f.get('severity'))}] ({f.get('severity', '').title()})** Line {f.get('line')}\n{f.get('message')} - {f.get('recommendation')}\nPR Blocking: {'Yes' if f.get('pr_blocking') else 'No'}."
                for f in pr_findings
            ]

        pr_files = pr_result.get("files", [])
        if pr_files:
            result["files"] = pr_files
            result["source_code"] = pr_files[0].get("code", result.get("source_code", ""))
            result["name"] = pr_result.get("pr_title") or f"PR #{pull_number}: {repo}"
        elif pr_result.get("pr_title"):
            result["name"] = pr_result.get("pr_title")
    else:
        await emit_event("pull_request", "review_ready", {"status": "skipped", "reason": "No open PR found"})
        result["github_pr_review"] = {"status": "skipped", "reason": "No open PR found"}


async def _run_review(
    review_id: str,
    repo_path: str | None,
    code_snippet: str | None,
    language: str,
    target_url: str | None = None,
    business_documents: list[dict[str, str]] | None = None
) -> None:
    await review_event_broadcaster.set_status(review_id, "started")
    try:
        runtime = ADKRuntime(orchestrator=CodeReviewOrchestrator())
        result = await asyncio.to_thread(
            runtime.review,
            repo_path=repo_path,
            code_snippet=code_snippet,
            language=language,
            review_id=review_id,
            business_documents=business_documents
        )
        await _execute_pr_review_if_github_url(target_url, review_id, result)
        await review_event_broadcaster.set_status(review_id, "completed", result=result)
    except Exception as exc:
        await review_event_broadcaster.set_status(review_id, "failed", error=str(exc))


@router.get("/review/history")
async def review_history(
    limit: int = Query(default=50, ge=1, le=500),
    source: str | None = Query(default=None),
    query: str | None = Query(default=None),
    n_results: int = Query(default=5, ge=1, le=20),
) -> dict[str, Any]:
    store = get_recommendation_history_store()
    history = store.list_history(limit=limit, source=source)
    similar = store.search_similar(query_text=query, limit=n_results) if query else []

    return {
        "status": "ok",
        "vector_store_enabled": store.vector_store_enabled,
        "count": len(history),
        "history": history,
        "similar": similar,
    }


@router.get("/review/mcp-status")
async def review_mcp_status() -> dict[str, Any]:
    from agent.github_mcp_service import get_github_mcp_service
    service = get_github_mcp_service()
    available = await service.is_available()
    tools = await service.list_tools() if available else []
    return {
        "status": "ok",
        "mcp_enabled": available,
        "server": "@modelcontextprotocol/server-github",
        "tools_count": len(tools),
        "tools": tools,
    }


@router.get("/review/{review_id}")
async def get_review(review_id: str) -> dict[str, Any]:
    state = review_event_broadcaster.status(review_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Review ID not found.")
    return state


@router.post("/review/github-pr")
async def review_github_pr(payload: dict[str, Any]) -> dict[str, Any]:
    owner = payload.get("owner")
    repo = payload.get("repo")
    pull_number = payload.get("pull_number")
    max_findings = int(payload.get("max_findings", 30))
    dry_run = bool(payload.get("dry_run", False))
    review_event = str(payload.get("review_event", "COMMENT"))
    review_body = payload.get("review_body")

    if not owner or not repo or not pull_number:
        raise HTTPException(status_code=400, detail="owner, repo and pull_number are required.")

    service = GitHubPRReviewService()
    request = GitHubPRReviewRequest(
        owner=str(owner),
        repo=str(repo),
        pull_number=int(pull_number),
        max_findings=max_findings,
        dry_run=dry_run,
        review_event=review_event,
        review_body=str(review_body) if review_body is not None else None,
    )
    return await service.review_pull_request(request)


@router.post("/review/story")
async def review_story(payload: dict[str, Any]) -> dict[str, Any]:
    return {"status": "ok", **build_story(payload)}


@router.post("/review/{review_id}/feedback")
async def review_feedback(review_id: str, payload: dict[str, Any]) -> dict[str, str]:
    rating = str(payload.get("rating", "")).strip().lower()
    comment = str(payload.get("comment", "")).strip()
    if rating not in {"helpful", "needs_work"}:
        raise HTTPException(status_code=400, detail="rating must be helpful or needs_work.")
    get_recommendation_history_store().add_feedback(review_id, rating, comment)
    return {"status": "recorded"}


@router.websocket("/ws/reviews/{review_id}")
async def review_stream(websocket: WebSocket, review_id: str) -> None:
    await websocket.accept()
    if not await review_event_broadcaster.attach(review_id, websocket):
        await websocket.send_json({"review_id": review_id, "node": "review_lifecycle", "event": "review_failed", "timestamp": datetime.now(timezone.utc).isoformat(), "payload": {"error": "Unknown review ID"}, "type": "review_failed"})
        await websocket.close(code=1008)
        return

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        review_event_broadcaster.unsubscribe(review_id, websocket)
