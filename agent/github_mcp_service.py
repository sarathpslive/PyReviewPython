from __future__ import annotations

import os
import json
import logging
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from backend.app.config import get_settings

logger = logging.getLogger(__name__)

NODE_EXE = r"C:\latest_node\node-v22.23.2-win-x64\node-v22.23.2-win-x64\node.exe"
GITHUB_MCP_SCRIPT = r"C:\latest_node\node-v22.23.2-win-x64\node-v22.23.2-win-x64\node_modules\@modelcontextprotocol\server-github\dist\index.js"


class GitHubMCPService:
    def __init__(self, node_path: str = NODE_EXE, script_path: str = GITHUB_MCP_SCRIPT) -> None:
        self.node_path = node_path
        self.script_path = script_path
        self.settings = get_settings()

    def _get_server_parameters(self) -> StdioServerParameters:
        token = self.settings.github_token or os.environ.get("GITHUB_TOKEN", "")
        env = os.environ.copy()
        env["GITHUB_PERSONAL_ACCESS_TOKEN"] = token
        env["PATH"] = f"{Path(self.node_path).parent};{env.get('PATH', '')}"
        return StdioServerParameters(command=self.node_path, args=[self.script_path], env=env)

    async def is_available(self) -> bool:
        if not Path(self.node_path).exists() or not Path(self.script_path).exists():
            return False
        token = self.settings.github_token or os.environ.get("GITHUB_TOKEN")
        return bool(token and token.strip())

    async def list_tools(self) -> list[str]:
        if not await self.is_available():
            return []
        params = self._get_server_parameters()
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                return [tool.name for tool in result.tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        params = self._get_server_parameters()
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(name, arguments)
                if result.isError:
                    error_msg = "\n".join(c.text for c in result.content if hasattr(c, "text"))
                    raise RuntimeError(f"MCP tool '{name}' failed: {error_msg}")
                # Parse content
                content_list = []
                for c in result.content:
                    if hasattr(c, "text"):
                        content_list.append(c.text)
                return "\n".join(content_list)

    async def get_file_contents(self, owner: str, repo: str, path: str, branch: str | None = None) -> str:
        args: dict[str, Any] = {"owner": owner, "repo": repo, "path": path}
        if branch:
            args["branch"] = branch
        raw_output = await self.call_tool("get_file_contents", args)
        try:
            parsed = json.loads(raw_output)
            if isinstance(parsed, dict) and "content" in parsed:
                import base64
                if parsed.get("encoding") == "base64":
                    return base64.b64decode(parsed["content"]).decode("utf-8", errors="replace")
                return parsed["content"]
        except Exception:
            pass
        return raw_output

    async def get_pull_request_files(self, owner: str, repo: str, pull_number: int) -> list[dict[str, Any]]:
        raw_output = await self.call_tool("get_pull_request_files", {"owner": owner, "repo": repo, "pull_number": pull_number})
        try:
            data = json.loads(raw_output)
            if isinstance(data, list):
                return data
        except Exception:
            pass
        return []

    async def create_pull_request_review(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        body: str,
        event: str = "COMMENT",
        comments: list[dict[str, Any]] | None = None,
        commit_id: str | None = None,
    ) -> dict[str, Any]:
        args: dict[str, Any] = {
            "owner": owner,
            "repo": repo,
            "pull_number": pull_number,
            "body": body,
            "event": event,
        }
        if comments:
            mcp_comments = []
            for c in comments:
                mcp_comments.append({
                    "path": c["path"],
                    "line": int(c.get("line", 1)),
                    "body": c.get("body", ""),
                })
            args["comments"] = mcp_comments
        if commit_id:
            args["commit_id"] = commit_id

        raw_output = await self.call_tool("create_pull_request_review", args)
        try:
            return json.loads(raw_output)
        except Exception:
            return {"status": "ok", "raw_response": raw_output}

    async def add_issue_comment(self, owner: str, repo: str, pull_number: int, body: str) -> dict[str, Any]:
        raw_output = await self.call_tool("add_issue_comment", {
            "owner": owner,
            "repo": repo,
            "issue_number": pull_number,
            "body": body,
        })
        try:
            return json.loads(raw_output)
        except Exception:
            return {"status": "ok", "raw_response": raw_output}


_github_mcp_service: GitHubMCPService | None = None

def get_github_mcp_service() -> GitHubMCPService:
    global _github_mcp_service
    if _github_mcp_service is None:
        _github_mcp_service = GitHubMCPService()
    return _github_mcp_service
