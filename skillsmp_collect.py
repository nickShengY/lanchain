#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any

import requests

API = "https://skillsmp.com/api/v1/skills/search"
OUT = Path("skillsmp_scientific_output")
RAW = OUT / "raw_api"
OUT.mkdir(exist_ok=True)
RAW.mkdir(exist_ok=True)

CATEGORY = "testing-security"
LIMIT = 50
PAGES_PER_FRAME = 25
SLEEP_SECONDS = 6.4
HEADERS = {
    "Accept": "application/json",
    "User-Agent": "skillsmp-scientific-security-audit/2.1",
}


def rows_from(payload: Any) -> list[dict]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("skills", "results", "items", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
        if isinstance(value, dict):
            for nested in ("skills", "results", "items", "data"):
                rows = value.get(nested)
                if isinstance(rows, list):
                    return [x for x in rows if isinstance(x, dict)]
    return []


def pagination_from(payload: Any) -> dict:
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("pagination"), dict):
        return data["pagination"]
    return payload.get("pagination") if isinstance(payload.get("pagination"), dict) else {}


def get_page(sort_by: str, page: int):
    params = {
        "q": "*",
        "category": CATEGORY,
        "sortBy": sort_by,
        "page": page,
        "limit": LIMIT,
    }
    last = ""
    for attempt in range(5):
        try:
            response = requests.get(API, params=params, headers=HEADERS, timeout=60)
            last = f"{response.status_code} {response.text[:800]}"
            if response.status_code == 200:
                payload = response.json()
                return payload, rows_from(payload), response.status_code, response.url, dict(response.headers)
            if response.status_code in (429, 500, 502, 503, 504):
                time.sleep(20 * (attempt + 1))
                continue
            return {"error": last}, [], response.status_code, response.url, dict(response.headers)
        except Exception as exc:
            last = repr(exc)
            time.sleep(15 * (attempt + 1))
    return {"error": last}, [], 0, "", {}


def val(item: dict, *names: str, default: Any = "") -> Any:
    for name in names:
        if item.get(name) not in (None, ""):
            return item[name]
    return default


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


records: list[dict] = []
logs: list[dict] = []
calls = 0

for frame, sort_by in (("stars", "stars"), ("recent", "recent")):
    for page in range(1, PAGES_PER_FRAME + 1):
        payload, items, status, url, headers = get_page(sort_by, page)
        calls += 1
        raw_path = RAW / f"{frame}_page_{page:02d}.json"
        raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        pagination = pagination_from(payload)
        logs.append({
            "frame": frame,
            "query": "*",
            "category": CATEGORY,
            "sort_by": sort_by,
            "page": page,
            "limit": LIMIT,
            "status": status,
            "returned": len(items),
            "reported_total": pagination.get("total", ""),
            "reported_total_pages": pagination.get("totalPages", ""),
            "request_url": url,
            "daily_remaining": headers.get("X-RateLimit-Daily-Remaining", ""),
            "minute_remaining": headers.get("X-RateLimit-Minute-Remaining", ""),
            "raw_file": str(raw_path),
        })
        if status != 200:
            raise RuntimeError(f"SkillsMP request failed for {frame} page {page}: {payload}")
        for position, item in enumerate(items, 1):
            updated = val(item, "updatedAt", "updated_at", default="")
            records.append({
                "skillsmp_id": str(val(item, "id", "skillId", "slug", default="")).strip(),
                "name": str(val(item, "name", "title", default="")).strip(),
                "author": str(val(item, "author", "creator", default="")).strip(),
                "description": str(val(item, "description", "summary", default="")).strip(),
                "content_language": str(val(item, "contentLanguage", "language", default="")).strip(),
                "github_url": str(val(item, "githubUrl", "github_url", "sourceUrl", default="")).strip(),
                "skillsmp_url": str(val(item, "skillUrl", "url", "marketplaceUrl", default="")).strip(),
                "stars": val(item, "stars", "githubStars", "stargazersCount", default=""),
                "updated_at": str(updated).strip(),
                "api_category": str(val(item, "category", "categoryName", default="")).strip(),
                "frame": frame,
                "query": "*",
                "category_filter": CATEGORY,
                "page": page,
                "position": position,
                "frame_rank": (page - 1) * LIMIT + position,
            })
        if calls < PAGES_PER_FRAME * 2:
            time.sleep(SLEEP_SECONDS)

if calls != PAGES_PER_FRAME * 2:
    raise RuntimeError(f"Expected {PAGES_PER_FRAME * 2} API requests, made {calls}")

occurrence_fields = [
    "skillsmp_id", "name", "author", "description", "content_language", "github_url",
    "skillsmp_url", "stars", "updated_at", "api_category", "frame", "query",
    "category_filter", "page", "position", "frame_rank",
]
write_csv(OUT / "ranked_frame_occurrences.csv", records, occurrence_fields)
write_csv(
    OUT / "query_log.csv",
    logs,
    [
        "frame", "query", "category", "sort_by", "page", "limit", "status", "returned",
        "reported_total", "reported_total_pages", "request_url", "daily_remaining",
        "minute_remaining", "raw_file",
    ],
)

union: dict[str, dict] = {}
for row in records:
    key = row["skillsmp_id"] or row["skillsmp_url"] or row["github_url"] or f"{row['name']}|{row['author']}"
    current = union.setdefault(
        key,
        {k: row.get(k, "") for k in occurrence_fields if k not in ("frame", "query", "category_filter", "page", "position", "frame_rank")},
    )
    frame = row["frame"]
    current[f"in_{frame}_frame"] = True
    previous = current.get(f"{frame}_rank")
    current[f"{frame}_rank"] = row["frame_rank"] if previous in (None, "") else min(int(previous), int(row["frame_rank"]))

for row in union.values():
    row.setdefault("in_stars_frame", False)
    row.setdefault("stars_rank", "")
    row.setdefault("in_recent_frame", False)
    row.setdefault("recent_rank", "")

union_rows = list(union.values())
union_fields = [
    "skillsmp_id", "name", "author", "description", "content_language", "github_url",
    "skillsmp_url", "stars", "updated_at", "api_category", "in_stars_frame", "stars_rank",
    "in_recent_frame", "recent_rank",
]
write_csv(OUT / "ranked_frame_union.csv", union_rows, union_fields)

stars_ids = {key for key, value in union.items() if value.get("in_stars_frame")}
recent_ids = {key for key, value in union.items() if value.get("in_recent_frame")}

saturation: list[dict] = []
combined_seen: set[str] = set()
for frame in ("stars", "recent"):
    frame_seen: set[str] = set()
    for page in range(1, PAGES_PER_FRAME + 1):
        page_keys = {
            row["skillsmp_id"] or row["skillsmp_url"] or row["github_url"] or f"{row['name']}|{row['author']}"
            for row in records
            if row["frame"] == frame and int(row["page"]) == page
        }
        new_within = len(page_keys - frame_seen)
        new_combined = len(page_keys - combined_seen)
        frame_seen |= page_keys
        combined_seen |= page_keys
        saturation.append({
            "frame": frame,
            "page": page,
            "returned_unique_on_page": len(page_keys),
            "new_unique_within_frame": new_within,
            "cumulative_unique_within_frame": len(frame_seen),
            "new_unique_to_combined_union": new_combined,
            "cumulative_combined_union": len(combined_seen),
        })
write_csv(
    OUT / "saturation_by_page.csv",
    saturation,
    [
        "frame", "page", "returned_unique_on_page", "new_unique_within_frame",
        "cumulative_unique_within_frame", "new_unique_to_combined_union",
        "cumulative_combined_union",
    ],
)

diagnostics = {
    "design": "Deterministic category-ranked dual frame",
    "query": "*",
    "category": CATEGORY,
    "sort_frames": ["stars", "recent"],
    "pages_per_frame": PAGES_PER_FRAME,
    "limit_per_page": LIMIT,
    "api_requests": calls,
    "stars_frame_unique": len(stars_ids),
    "recent_frame_unique": len(recent_ids),
    "frame_overlap": len(stars_ids & recent_ids),
    "ranked_union_unique": len(union_rows),
    "jaccard_overlap": round(len(stars_ids & recent_ids) / max(1, len(stars_ids | recent_ids)), 6),
    "interpretation": "Reproducible popularity and recency coverage frames; not a probability sample and not a full catalog census.",
}
(OUT / "frame_diagnostics.json").write_text(json.dumps(diagnostics, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(diagnostics, ensure_ascii=False, indent=2))
