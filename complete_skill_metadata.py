from __future__ import annotations

import csv
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MANIFEST = Path("metadata_manifest.json")
OUT = Path("metadata_completion_output")
OUT.mkdir(exist_ok=True)
TOKEN = os.environ.get("GITHUB_TOKEN", "")


def api_get(url: str, retries: int = 4):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "security-skill-metadata-audit/2026-07-29",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    last_error = ""
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=90) as response:
                return response.status, json.loads(response.read().decode("utf-8")), dict(response.headers)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            last_error = f"HTTP {exc.code}: {body[:500]}"
            if exc.code in (403, 429, 500, 502, 503, 504):
                time.sleep(2 ** attempt)
                continue
            return exc.code, None, {}, last_error
        except Exception as exc:
            last_error = repr(exc)
            time.sleep(2 ** attempt)
    return 0, None, {}, last_error


def commit_history(repo: str, path: str):
    encoded_repo = "/".join(urllib.parse.quote(part, safe="") for part in repo.split("/"))
    current_path = path
    rename_chain = []
    visited = set()
    earliest = None

    for _ in range(12):
        key = current_path.lower()
        if key in visited:
            break
        visited.add(key)
        page = 1
        last_batch = []
        while page <= 50:
            qpath = urllib.parse.quote(current_path, safe="")
            url = f"https://api.github.com/repos/{encoded_repo}/commits?path={qpath}&per_page=100&page={page}"
            status, data, headers, *err = api_get(url)
            if status != 200 or not isinstance(data, list):
                return {
                    "status": "commit_history_error",
                    "error": (err[0] if err else f"HTTP {status}"),
                    "path_examined": current_path,
                    "rename_chain": rename_chain,
                }
            if not data:
                break
            last_batch = data
            if len(data) < 100:
                break
            page += 1
        if not last_batch:
            return {
                "status": "path_history_not_found",
                "path_examined": current_path,
                "rename_chain": rename_chain,
            }

        earliest = last_batch[-1]
        sha = earliest.get("sha", "")
        detail_url = f"https://api.github.com/repos/{encoded_repo}/commits/{sha}"
        dstatus, detail, _, *derr = api_get(detail_url)
        previous = ""
        file_status = ""
        if dstatus == 200 and isinstance(detail, dict):
            for file_info in detail.get("files", []) or []:
                filename = str(file_info.get("filename", ""))
                if filename.lower() == current_path.lower():
                    file_status = str(file_info.get("status", ""))
                    previous = str(file_info.get("previous_filename", "") or "")
                    break
        if file_status == "renamed" and previous:
            rename_chain.append({
                "rename_commit": sha,
                "new_path": current_path,
                "previous_path": previous,
            })
            current_path = previous
            continue
        break

    if not earliest:
        return {"status": "path_history_not_found", "path_examined": current_path, "rename_chain": rename_chain}

    commit_obj = earliest.get("commit", {}) or {}
    author_obj = commit_obj.get("author", {}) or {}
    committer_obj = commit_obj.get("committer", {}) or {}
    created_at = author_obj.get("date") or committer_obj.get("date") or ""
    sha = earliest.get("sha", "")
    return {
        "status": "resolved",
        "skill_file_created_date": created_at,
        "skill_file_created_commit_sha": sha,
        "skill_file_created_commit_url": earliest.get("html_url") or f"https://github.com/{repo}/commit/{sha}",
        "original_path_followed": current_path,
        "rename_chain": rename_chain,
        "earliest_commit_message": (commit_obj.get("message") or "").splitlines()[0][:300],
    }


def main():
    records = json.loads(MANIFEST.read_text(encoding="utf-8"))
    results = []
    repo_cache = {}
    for idx, record in enumerate(records, 1):
        repo = record["repo"]
        path = record["path"]
        print(f"[{idx}/{len(records)}] {repo} :: {path}", flush=True)
        if repo not in repo_cache:
            repo_url = f"https://api.github.com/repos/{repo}"
            status, meta, _, *err = api_get(repo_url)
            if status == 200 and isinstance(meta, dict):
                repo_cache[repo] = {
                    "repo_metadata_status": "resolved",
                    "github_stars": meta.get("stargazers_count"),
                    "github_forks": meta.get("forks_count"),
                    "repo_archived": meta.get("archived"),
                    "repo_disabled": meta.get("disabled"),
                    "repo_fork": meta.get("fork"),
                    "repo_created_at": meta.get("created_at"),
                    "repo_updated_at": meta.get("updated_at"),
                    "repo_pushed_at": meta.get("pushed_at"),
                    "default_branch": meta.get("default_branch"),
                    "github_url": meta.get("html_url") or f"https://github.com/{repo}",
                }
            else:
                repo_cache[repo] = {"repo_metadata_status": "error", "repo_metadata_error": (err[0] if err else f"HTTP {status}")}
        history = commit_history(repo, path)
        result = dict(record)
        result.update(repo_cache[repo])
        result.update(history)
        results.append(result)
        time.sleep(0.05)

    with (OUT / "metadata_results.jsonl").open("w", encoding="utf-8") as handle:
        for row in results:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    keys = []
    for row in results:
        for key in row:
            if key not in keys:
                keys.append(key)
    with (OUT / "metadata_results.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=keys)
        writer.writeheader()
        for row in results:
            flattened = {}
            for key in keys:
                value = row.get(key, "")
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False)
                flattened[key] = value
            writer.writerow(flattened)

    summary = {
        "total": len(results),
        "date_resolved": sum(1 for row in results if row.get("skill_file_created_date")),
        "date_unresolved": sum(1 for row in results if not row.get("skill_file_created_date")),
        "repo_metadata_resolved": sum(1 for row in results if row.get("repo_metadata_status") == "resolved"),
        "renamed_paths_followed": sum(1 for row in results if row.get("rename_chain")),
        "status_counts": {},
    }
    for row in results:
        status = row.get("status", "unknown")
        summary["status_counts"][status] = summary["status_counts"].get(status, 0) + 1
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
