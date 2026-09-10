import pytest
from agent.github_url_resolver import extract_github_metadata
from agent.github_pr_review_service import GitHubPRReviewService

def test_extract_github_metadata():
    # 1. PR URL
    url = "https://github.com/Harinath0225/synthetic-code-review/pull/123"
    meta = extract_github_metadata(url)
    assert meta["is_github"] is True
    assert meta["owner"] == "Harinath0225"
    assert meta["repo"] == "synthetic-code-review"
    assert meta["pull_number"] == 123
    assert meta["branch"] is None

    # 2. Blob URL
    url = "https://github.com/Harinath0225/synthetic-code-review/blob/feature/demo-test/app.py"
    meta = extract_github_metadata(url)
    assert meta["is_github"] is True
    assert meta["owner"] == "Harinath0225"
    assert meta["repo"] == "synthetic-code-review"
    assert meta["branch"] == "feature/demo-test/app.py"
    assert meta["pull_number"] is None

    # 3. Raw URL
    url = "https://raw.githubusercontent.com/Harinath0225/synthetic-code-review/feature/demo-test"
    meta = extract_github_metadata(url)
    assert meta["is_github"] is True
    assert meta["owner"] == "Harinath0225"
    assert meta["repo"] == "synthetic-code-review"
    assert meta["branch"] == "feature/demo-test"
    assert meta["pull_number"] is None

    # 4. Repo URL
    url = "https://github.com/Harinath0225/synthetic-code-review.git"
    meta = extract_github_metadata(url)
    assert meta["is_github"] is True
    assert meta["owner"] == "Harinath0225"
    assert meta["repo"] == "synthetic-code-review"
    assert meta["branch"] is None
    assert meta["pull_number"] is None

    # 5. Non-GitHub URL
    url = "https://example.com/test"
    meta = extract_github_metadata(url)
    assert meta["is_github"] is False


@pytest.mark.asyncio
async def test_find_open_pull_request_mocked(mocker):
    pr_service = GitHubPRReviewService()
    
    # Mock _get_json
    async def mock_get_json(client, url):
        if "pulls?state=open&head=Harinath0225:feature/demo" in url:
            return [{"number": 42, "title": "Test PR"}], None
        return [], None
        
    mocker.patch.object(pr_service, "_get_json", side_effect=mock_get_json)
    
    pr = await pr_service.find_open_pull_request("Harinath0225", "synthetic-code-review", "feature/demo")
    assert pr is not None
    assert pr["number"] == 42


@pytest.mark.asyncio
async def test_pr_review_deduplicates_and_updates_existing_comments(mocker):
    from agent.github_pr_review_service import GitHubPRReviewRequest
    pr_service = GitHubPRReviewService()
    pr_service.settings.github_token = "ghp_fake_token_for_testing"

    patched_comments = []
    deleted_comments = []

    async def mock_get_json(client, url):
        if "pulls/10" in url and not url.endswith("/files"):
            return {
                "title": "Fix auth issue",
                "head": {"sha": "c0ffee123"},
            }, None
        if "pulls/10/files" in url:
            return [
                {
                    "filename": "src/routes/auth.py",
                    "patch": "@@ -47,4 +47,4 @@\n+ username = 'admin'\n+ token = hashlib.md5(username.encode()).hexdigest()",
                }
            ], None
        if "issues/10/comments" in url:
            # 3 duplicate comments exist from previous runs
            return [
                {"id": 101, "body": "<!-- pyreview-pr-comment -->\n## Automated Peer Review\nExisting scan 1"},
                {"id": 102, "body": "## Automated Peer Review\nDeterministic scan of changed Python lines"},
                {"id": 103, "body": "## Automated Peer Review\nExisting scan 3"},
            ], None
        return [], None

    async def mock_patch_json(client, url, payload):
        patched_comments.append((url, payload))
        return {"id": 101}, None

    async def mock_delete(client, url):
        deleted_comments.append(url)
        return True, None

    mocker.patch.object(pr_service, "_get_json", side_effect=mock_get_json)
    mocker.patch.object(pr_service, "_patch_json", side_effect=mock_patch_json)
    mocker.patch.object(pr_service, "_delete", side_effect=mock_delete)
    mocker.patch.object(pr_service.mcp_service, "is_available", return_value=False)

    request = GitHubPRReviewRequest(
        owner="Harinath0225",
        repo="synthetic-code-review",
        pull_number=10,
        dry_run=False,
    )
    result = await pr_service.review_pull_request(request)

    assert result["status"] == "ok"
    assert result["pr_url"] == "https://github.com/Harinath0225/synthetic-code-review/pull/10"
    assert len(patched_comments) == 1
    assert "101" in patched_comments[0][0]
    # Older duplicate comments 102 and 103 should be deleted
    assert len(deleted_comments) == 2
    assert "102" in deleted_comments[0]
    assert "103" in deleted_comments[1]
    assert len(result["files"]) == 1
    assert result["files"][0]["path"] == "src/routes/auth.py"


@pytest.mark.asyncio
async def test_execute_pr_review_enriches_result(mocker):
    from backend.app.routes.review import _execute_pr_review_if_github_url

    async def mock_review_pr(self, request):
        return {
            "status": "ok",
            "pr_url": "https://github.com/Harinath0225/synthetic-code-review/pull/5",
            "pull_number": 5,
            "pr_title": "feat: add user auth",
            "findings": [
                {
                    "path": "src/routes/auth.py",
                    "line": 50,
                    "severity": "critical",
                    "severity_label": "Critical / Blocker",
                    "pr_blocking": True,
                    "rule_id": "SEC002",
                    "category": "security",
                    "message": "Sensitive value assigned in code.",
                    "recommendation": "Use env var.",
                    "evidence": "token = hashlib.md5",
                }
            ],
            "files": [
                {"path": "src/routes/auth.py", "name": "auth.py", "code": "# auth code line 50"}
            ],
        }

    mocker.patch("agent.github_pr_review_service.GitHubPRReviewService.review_pull_request", mock_review_pr)

    review_result = {
        "findings": [{"line": 2, "message": "Syntax error on README"}],
        "total_findings": 1,
        "source_code": "bogus readme content",
    }
    await _execute_pr_review_if_github_url("https://github.com/Harinath0225/synthetic-code-review/pull/5", "test-rev", review_result)

    assert review_result["pr_url"] == "https://github.com/Harinath0225/synthetic-code-review/pull/5"
    assert review_result["pr_number"] == 5
    assert review_result["name"] == "feat: add user auth"
    assert len(review_result["findings"]) == 1
    assert review_result["findings"][0]["rule_id"] == "SEC002"
    assert review_result["findings"][0]["path"] == "src/routes/auth.py"
    assert review_result["source_code"] == "# auth code line 50"


