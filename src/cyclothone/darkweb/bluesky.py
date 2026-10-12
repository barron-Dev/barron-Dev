from __future__ import annotations

import re
from urllib.parse import quote

import httpx

from cyclothone.darkweb.pullers import Finding, normalize


class BlueskyPublicMonitor:
    """Search Bluesky's unauthenticated public AppView for exact target mentions."""

    SOURCE = "bluesky_public"
    ENDPOINT = "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts"
    MAX_PAGES = 3
    PAGE_SIZE = 100

    @staticmethod
    def _exact_mention(text: str, target: str, target_type: str) -> bool:
        if target_type == "email":
            pattern = r"(?<![A-Z0-9._%+-])" + re.escape(target) + r"(?![A-Z0-9._%+-])"
        else:
            # Require hostname boundaries so example.com.evil cannot match example.com.
            pattern = r"(?<![A-Z0-9.-])" + re.escape(target) + r"(?![A-Z0-9.-])"
        return re.search(pattern, text, flags=re.IGNORECASE) is not None

    async def pull_target(self, target: str, target_type: str) -> list[Finding]:
        target = normalize(target)
        if target_type not in {"domain", "email"} or not target:
            raise ValueError("unsupported_bluesky_target")
        findings: list[Finding] = []
        seen_uris: set[str] = set()
        cursor: str | None = None
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
            for _ in range(self.MAX_PAGES):
                params: dict[str, str | int] = {"q": target, "limit": self.PAGE_SIZE, "sort": "latest"}
                if cursor:
                    params["cursor"] = cursor
                response = await client.get(
                    self.ENDPOINT,
                    params=params,
                    headers={"user-agent": "cyclothone-darkweb/1.0"},
                )
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict) or not isinstance(payload.get("feed", []), list):
                    raise RuntimeError("bluesky_public_invalid_response")
                for entry in payload.get("feed", []):
                    if not isinstance(entry, dict):
                        continue
                    post = entry.get("post")
                    if not isinstance(post, dict):
                        continue
                    record = post.get("record")
                    author = post.get("author")
                    if not isinstance(record, dict) or not isinstance(author, dict):
                        continue
                    text = record.get("text")
                    uri = post.get("uri")
                    if not isinstance(text, str) or not isinstance(uri, str) or uri in seen_uris:
                        continue
                    seen_uris.add(uri)
                    if not self._exact_mention(text, target, target_type):
                        continue
                    handle = str(author.get("handle") or "").strip()
                    rkey = uri.rsplit("/", 1)[-1]
                    source_url = f"https://bsky.app/profile/{quote(handle, safe='')}/post/{quote(rkey, safe='')}" if handle and rkey else None
                    indexed_at = post.get("indexedAt")
                    findings.append(Finding(
                        self.SOURCE,
                        target_type,
                        target,
                        "Exact target mention found in a public Bluesky post; post text is not retained.",
                        "medium",
                        source_url,
                        {
                            "author_handle": handle or None,
                            "post_uri": uri,
                            "indexed_at": indexed_at if isinstance(indexed_at, str) else None,
                        },
                    ))
                next_cursor = payload.get("cursor")
                if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
                    break
                cursor = next_cursor
        return findings
