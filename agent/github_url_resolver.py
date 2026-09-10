from __future__ import annotations

import base64
import re
from typing import Any
import httpx

from backend.app.config import get_settings

EXTENSION_TO_LANGUAGE: dict[str, str] = {
    "py": "python",
    "pyw": "python",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "java": "java",
    "go": "go",
    "sql": "sql",
    "json": "json",
    "html": "html",
    "htm": "html",
    "css": "css",
}


def parse_github_url(url: str) -> dict[str, str]:
    cleaned = url.strip()

    # 1. GitHub blob URL: https://github.com/owner/repo/blob/ref/path/to/file
    m_blob = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$", cleaned)
    if m_blob:
        owner, repo, ref, path = m_blob.groups()
        return {
            "type": "file",
            "owner": owner,
            "repo": repo,
            "ref": ref,
            "path": path,
            "raw_url": f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}",
        }

    # 2. GitHub tree URL: https://github.com/owner/repo/tree/ref/path/to/file
    m_tree = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.*)$", cleaned)
    if m_tree:
        owner, repo, ref, path = m_tree.groups()
        return {
            "type": "file",
            "owner": owner,
            "repo": repo,
            "ref": ref,
            "path": path,
            "raw_url": f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}",
        }

    # 3. GitHub raw URL: https://raw.githubusercontent.com/owner/repo/ref/path/to/file
    m_raw = re.match(r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)$", cleaned)
    if m_raw:
        owner, repo, ref, path = m_raw.groups()
        return {
            "type": "file",
            "owner": owner,
            "repo": repo,
            "ref": ref,
            "path": path,
            "raw_url": cleaned,
        }

    # 4. GitHub PR URL: https://github.com/owner/repo/pull/123
    m_pr = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)", cleaned)
    if m_pr:
        owner, repo, pull_number = m_pr.groups()
        return {
            "type": "pr",
            "owner": owner,
            "repo": repo,
            "pull_number": pull_number,
            "patch_url": f"https://github.com/{owner}/{repo}/pull/{pull_number}.patch",
        }

    # 5. GitHub repo URL: https://github.com/owner/repo
    m_repo = re.match(r"^https?://github\.com/([^/]+)/([^/]+)/?$", cleaned)
    if m_repo:
        owner, repo = m_repo.groups()
        return {
            "type": "repo",
            "owner": owner,
            "repo": repo,
        }

    return {"type": "direct_url", "url": cleaned}


def extract_github_metadata(url: str) -> dict[str, Any]:
    """
    Extracts owner, repo, branch, pull_number, and path from a GitHub URL.
    Returns a dictionary with these keys. If it's not a GitHub URL, is_github will be False.
    """
    cleaned = url.strip()
    result: dict[str, Any] = {
        "is_github": False,
        "owner": None,
        "repo": None,
        "branch": None,
        "pull_number": None,
        "path": None,
    }

    if not cleaned.startswith(("http://", "https://")):
        return result

    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]

    # PR URL
    m_pr = re.match(r"^https?://(?:www\.)?github\.com/([^/]+)/([^/]+)/pull/(\d+)", cleaned)
    if m_pr:
        result.update({
            "is_github": True,
            "owner": m_pr.group(1),
            "repo": m_pr.group(2),
            "pull_number": int(m_pr.group(3)),
        })
        return result

    # Blob, Tree, Raw URLs
    m_any = re.match(r"^https?://(?:www\.)?github\.com/([^/]+)/([^/]+)/(?:blob|tree)/(.+)$", cleaned)
    if not m_any:
        m_any = re.match(r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/(.+)$", cleaned)

    if m_any:
        result.update({
            "is_github": True,
            "owner": m_any.group(1),
            "repo": m_any.group(2),
            "branch": m_any.group(3), # Contains both branch and path, caller will need to handle
        })
        return result

    # Repo URL
    m_repo = re.match(r"^https?://(?:www\.)?github\.com/([^/]+)/([^/]+)/?$", cleaned)
    if m_repo:
        result.update({
            "is_github": True,
            "owner": m_repo.group(1),
            "repo": m_repo.group(2),
        })
        return result

    return result


async def _fetch_via_github_api(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    path: str,
    ref: str | None = None,
) -> str | None:
    """Fetch a single file via the GitHub Contents API.
    Works for both public and private repos when an Authorization header is set.
    Returns the decoded file text, or None if the file was not found.
    """
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    params: dict[str, str] = {}
    if ref:
        params["ref"] = ref
    resp = await client.get(api_url, params=params)
    if resp.status_code == 404:
        return None
    if resp.status_code == 401:
        raise ValueError(
            f"GitHub API returned 401 Unauthorized for {owner}/{repo}. "
            f"Check that GITHUB_TOKEN in .env is valid and has 'repo' (private) or 'public_repo' scope."
        )
    if resp.status_code != 200:
        raise ValueError(f"GitHub API error ({resp.status_code}) fetching {owner}/{repo}/{path}")
    data = resp.json()
    # The API returns base64-encoded content for files
    content_b64 = data.get("content", "")
    if not content_b64:
        return None
    # GitHub adds newlines inside the base64 string — strip them before decoding
    return base64.b64decode(content_b64.replace("\n", "")).decode("utf-8", errors="replace")


async def _resolve_file_with_slash_branch(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    raw_ref: str,
    raw_path: str,
) -> tuple[str, str] | None:
    """Handle branch names that contain '/' (e.g. feature/demo-test).

    The regex for raw.githubusercontent.com and blob URLs greedily stops the
    ref capture at the first '/', so `feature/demo-test/file.py` is parsed as
    ref='feature', path='demo-test/file.py'.

    This function probes the GitHub Contents API with increasingly longer
    ref candidates until it finds a valid file, returning (content, path) or None.
    """
    # Reconstruct the full path after the repo segment: ref/path combined
    combined = f"{raw_ref}/{raw_path}"
    segments = combined.split("/")
    # Try all possible split points: ref=segments[:i], path=segments[i:]
    for i in range(1, len(segments)):
        candidate_ref = "/".join(segments[:i])
        candidate_path = "/".join(segments[i:])
        if not candidate_path:
            continue
        content = await _fetch_via_github_api(client, owner, repo, candidate_path, ref=candidate_ref)
        if content is not None:
            return content, candidate_path
    return None


# Common entry-point filenames tried when a URL points to a branch root rather
# than a specific file (e.g. https://github.com/owner/repo/tree/feature/demo-test).
AUTODISCOVER_CANDIDATES: list[str] = [
    "sample_code_review.py",
    "main.py",
    "app.py",
    "src/main.py",
    "src/app.py",
    "index.py",
]


async def _auto_discover_on_branch(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    ref: str,
) -> tuple[str, str] | None:
    """Probe AUTODISCOVER_CANDIDATES on *ref* via the GitHub Contents API.

    Returns (content, path) for the first file that exists, or None if none
    of the candidates are found.  Works for both public and private repos when
    the client carries an Authorization header.
    """
    for candidate in AUTODISCOVER_CANDIDATES:
        content = await _fetch_via_github_api(client, owner, repo, candidate, ref=ref)
        if content is not None:
            return content, candidate
    return None


async def resolve_github_url_async(url: str, timeout_seconds: float = 10.0) -> tuple[str, str, str]:
    """Resolves a GitHub URL and fetches its content.
    Returns (code_snippet, filename, language).
    """
    settings = get_settings()
    headers: dict[str, str] = {"User-Agent": "PyReview-Assistant", "Accept": "application/vnd.github+json"}
    has_token = bool(settings.github_token)
    if has_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    info = parse_github_url(url)
    async with httpx.AsyncClient(timeout=timeout_seconds, headers=headers, follow_redirects=True) as client:
        if info["type"] == "file":
            owner = info["owner"]
            repo = info["repo"]
            ref = info.get("ref", "")
            path = info["path"]

            # --- 1. Try MCP service first (if available) ---
            from agent.github_mcp_service import get_github_mcp_service
            mcp = get_github_mcp_service()
            if await mcp.is_available():
                try:
                    mcp_code = await mcp.get_file_contents(
                        owner=owner, repo=repo, path=path, branch=ref or None,
                    )
                    if mcp_code and mcp_code.strip():
                        filename = path.split("/")[-1] or "github_file.py"
                        ext = filename.split(".")[-1].lower() if "." in filename else ""
                        return mcp_code, filename, EXTENSION_TO_LANGUAGE.get(ext, "python")
                except Exception:
                    pass

            # --- 2. GitHub Contents API (works for private repos with token) ---
            content = await _fetch_via_github_api(client, owner, repo, path, ref=ref or None)
            if content is None and ref:
                # Branch name may contain '/' — probe all possible splits
                result = await _resolve_file_with_slash_branch(client, owner, repo, ref, path)
                if result:
                    content, path = result

            if content is not None:
                filename = path.split("/")[-1] or "github_file.py"
                ext = filename.split(".")[-1].lower() if "." in filename else ""
                return content, filename, EXTENSION_TO_LANGUAGE.get(ext, "python")

            # --- 3. Branch-root auto-discovery ---
            # The URL may point to a branch root rather than a specific file
            # (e.g. https://github.com/owner/repo/tree/feature/demo-test or
            #       https://raw.githubusercontent.com/owner/repo/feature/demo-test).
            # Try treating the full "ref/path" string (and then just "ref") as a
            # branch name and probing common entry-point filenames on that branch.
            branch_candidates: list[str] = []
            if ref and path:
                branch_candidates.append(f"{ref}/{path}".strip("/"))
            if ref:
                branch_candidates.append(ref)
            for branch_ref in branch_candidates:
                auto_result = await _auto_discover_on_branch(client, owner, repo, branch_ref)
                if auto_result:
                    content, path = auto_result
                    filename = path.split("/")[-1] or "github_file.py"
                    ext = filename.split(".")[-1].lower() if "." in filename else ""
                    return content, filename, EXTENSION_TO_LANGUAGE.get(ext, "python")

            # --- 4. Fallback: raw URL (public repos only) ---
            raw_url = info["raw_url"]
            resp = await client.get(raw_url)
            if resp.status_code == 200:
                filename = path.split("/")[-1] or "github_file.py"
                ext = filename.split(".")[-1].lower() if "." in filename else ""
                return resp.text, filename, EXTENSION_TO_LANGUAGE.get(ext, "python")

            # Build a clear, actionable error message
            token_hint = (
                "A GITHUB_TOKEN with 'repo' scope is set — the repo may be private but the "
                "token may lack access, or the branch/file path is wrong."
                if has_token else
                "No GITHUB_TOKEN is set. If this is a private repo, add GITHUB_TOKEN to .env."
            )
            probed = ", ".join(AUTODISCOVER_CANDIDATES)
            raise ValueError(
                f"Could not fetch file from GitHub:\n"
                f"  Owner : {owner}\n"
                f"  Repo  : {repo}\n"
                f"  Ref   : {ref}\n"
                f"  Path  : {path}\n"
                f"  {token_hint}\n"
                f"Branch-root auto-discovery was attempted but none of these files were found "
                f"on the branch: {probed}\n"
                f"Tip: Provide a direct file URL such as "
                f"https://github.com/{owner}/{repo}/blob/{ref}/your_file.py"
            )

        elif info["type"] == "pr":
            api_url = f"https://api.github.com/repos/{info['owner']}/{info['repo']}/pulls/{info['pull_number']}/files"
            api_resp = await client.get(api_url)
            if api_resp.status_code == 200:
                files = api_resp.json()
                py_files = [f for f in files if isinstance(f, dict) and f.get("filename", "").endswith((".py", ".pyw"))]
                target_files = py_files if py_files else files
                combined_code = []
                for file_item in target_files:
                    patch = file_item.get("patch", "")
                    lines = [l[1:] for l in patch.splitlines() if l.startswith("+") and not l.startswith("+++")]
                    if lines:
                        combined_code.append(f"# File: {file_item.get('filename')}\n" + "\n".join(lines))
                first_name = target_files[0].get("filename", "").split("/")[-1] if target_files else f"PR-{info['pull_number']}.py"
                code = "\n\n".join(combined_code) or "# Empty PR diff"
                return code, first_name or f"PR-{info['pull_number']}.py", "python"

            patch_resp = await client.get(info["patch_url"])
            if patch_resp.status_code == 200 and patch_resp.text.strip():
                patch_text = patch_resp.text
                added_lines = [
                    line[1:] for line in patch_text.splitlines()
                    if line.startswith("+") and not line.startswith("+++")
                ]
                code = "\n".join(added_lines) if added_lines else patch_text
                filename = f"PR-{info['pull_number']}.py"
                return code, filename, "python"

            raise ValueError(f"Failed to fetch PR {info['pull_number']} diff from GitHub.")

        elif info["type"] == "repo":
            for ref in ["main", "master"]:
                for candidate in ["sample_code_review.py", "main.py", "app.py", "src/main.py", "src/app.py"]:
                    candidate_raw = f"https://raw.githubusercontent.com/{info['owner']}/{info['repo']}/{ref}/{candidate}"
                    resp = await client.get(candidate_raw)
                    if resp.status_code == 200:
                        filename = candidate.split("/")[-1]
                        ext = filename.split(".")[-1].lower() if "." in filename else ""
                        language = EXTENSION_TO_LANGUAGE.get(ext, "python")
                        return resp.text, filename, language

            raise ValueError(
                f"Could not automatically locate a main file in repository {info['owner']}/{info['repo']}. "
                f"Please provide a direct file URL (e.g. https://github.com/{info['owner']}/{info['repo']}/blob/main/your_file.py)."
            )

        else:
            # direct_url fallback: if it looks like a github.com HTML page, try converting to raw
            direct_url = info["url"]
            raw_attempt: str | None = None
            m_gh_any = re.match(
                r"^https?://github\.com/([^/]+)/([^/]+)/(?:blob|raw|tree)/([^/]+)/(.*)$",
                direct_url,
            )
            if m_gh_any:
                owner, repo, ref, path = m_gh_any.groups()
                raw_attempt = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"

            if raw_attempt:
                resp = await client.get(raw_attempt)
                if resp.status_code == 200:
                    code = resp.text
                    filename = raw_attempt.rstrip("/").split("/")[-1] or "github_file.py"
                    ext = filename.split(".")[-1].lower() if "." in filename else ""
                    language = EXTENSION_TO_LANGUAGE.get(ext, "python")
                    return code, filename, language

            resp = await client.get(direct_url)
            if resp.status_code == 404:
                raise ValueError(
                    f"URL returned 404 Not Found: {direct_url}\n"
                    f"Check that the URL is correct and the resource exists."
                )
            if resp.status_code != 200:
                raise ValueError(f"HTTP request failed with status {resp.status_code}: {direct_url}")
            code = resp.text
            filename = direct_url.rstrip("/").split("/")[-1] or "github_file.py"
            if not filename.endswith(".py"):
                filename = "github_file.py"
            return code, filename, "python"
