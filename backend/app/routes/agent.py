from fastapi import APIRouter, Depends, HTTPException, Request

from agent.manager import AgentManager
from agent.evaluation import AgentEvaluationService
from security.auth import require_api_key
from security.model_armor import ModelArmorService
from security.prompt_injection_guard import get_prompt_injection_guard_service

router = APIRouter(prefix="/api/v1")


@router.post("/agent/invoke")
async def invoke_agent(
    request: Request,
    payload: dict[str, str],
    _api_key: str | None = Depends(require_api_key),
):
    prompt = (payload or {}).get("prompt", "").strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt is required")

    guard = get_prompt_injection_guard_service()
    guard_result = guard.validate(prompt)
    if guard_result.get("blocked"):
        raise HTTPException(status_code=400, detail=guard_result.get("reason") or "Prompt blocked by security policy")

    manager = getattr(request.app.state, "agent_manager", None)
    if manager is None:
        manager = AgentManager()
        await manager.initialize()
        request.app.state.agent_manager = manager

    runtime = await manager.get_runtime()
    response = runtime.run(prompt)
    return {
        "status": "ok",
        "response": response,
        "prompt_guard": guard_result,
    }


@router.get("/agent/evaluate/scenarios")
async def get_evaluation_scenarios() -> dict[str, object]:
    scenarios = AgentEvaluationService().list_scenarios()
    return {
        "status": "ok",
        "docs_url": "https://adk.dev/evaluate/",
        "count": len(scenarios),
        "scenarios": scenarios,
    }


@router.post("/agent/evaluate")
async def evaluate_agent(payload: dict[str, object]) -> dict[str, object]:
    prompt = str(payload.get("prompt", ""))
    code_snippet = str(payload.get("code_snippet", ""))
    expected_keywords = payload.get("expected_keywords", [])
    expected_tools = payload.get("expected_tools")
    scenario_id = payload.get("scenario_id")
    expected_rules = payload.get("expected_rules")

    if not prompt.strip():
        raise HTTPException(status_code=400, detail="prompt is required")
    if not isinstance(expected_keywords, list):
        raise HTTPException(status_code=400, detail="expected_keywords must be a list")

    parsed_tools = [str(item) for item in expected_tools] if isinstance(expected_tools, list) else None
    parsed_rules = [str(item) for item in expected_rules] if isinstance(expected_rules, list) else None

    return AgentEvaluationService().evaluate(
        prompt=prompt,
        code_snippet=code_snippet,
        expected_keywords=[str(item) for item in expected_keywords],
        expected_tools=parsed_tools,
        scenario_id=str(scenario_id) if scenario_id else None,
        expected_rules=parsed_rules,
    )



@router.post("/security/model-armor/check")
async def check_model_armor(payload: dict[str, object]) -> dict[str, object]:
    text = str(payload.get("text", ""))
    return ModelArmorService().check(text, source=str(payload.get("source", "api")))
