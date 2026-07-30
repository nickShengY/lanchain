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
SLEEP_SECONDS = 6.4
HEADERS = {
    "Accept": "application/json",
    "User-Agent": "skillsmp-scientific-security-audit/2.2",
}

# Preregistered equal-budget ontology strata. Each stratum receives one
# top-starred retrieval and one most-recent retrieval under the same category,
# page and result-limit settings. The standards field documents why each
# retrieval stratum exists instead of presenting the query list as ad hoc.
STRATA = [
    ("general_security", "security", "NIST CSF all functions; general security assessment"),
    ("vulnerability_assessment", "vulnerability", "NIST CSF ID.RA; vulnerability discovery and assessment"),
    ("application_code_review", "security audit", "OWASP ASVS; application and source-code review"),
    ("web_api_security", "OWASP", "OWASP Top 10, ASVS and API Security Top 10"),
    ("access_control_identity", "authorization", "OWASP A01; CWE-284/285/862/863"),
    ("injection_input_validation", "injection", "OWASP A03; CWE-20/74/89/79"),
    ("dynamic_pentest", "penetration testing", "OWASP WSTG; active adversarial assessment"),
    ("fuzzing_property_testing", "fuzzing", "CWE discovery through fuzz and property-based testing"),
    ("static_analysis_sast", "static analysis", "SAST and query-based source analysis"),
    ("dataflow_taint", "taint analysis", "Interprocedural source-to-sink and data-flow analysis"),
    ("dependency_sca_sbom", "SBOM", "OWASP A06; SCA, component inventory and advisory mapping"),
    ("software_supply_chain", "supply chain", "SLSA and NIST SSDF supply-chain risk"),
    ("secrets_credentials", "secret scanning", "CWE-798/522; leaked credential and key discovery"),
    ("cloud_security", "cloud security", "CSA CCM and cloud security-posture assessment"),
    ("iac_container_kubernetes", "Kubernetes security", "CIS Kubernetes/Container benchmarks and IaC"),
    ("network_host_infrastructure", "network security", "NIST SP 800-115 network/host assessment"),
    ("mobile_security", "mobile security", "OWASP MASVS and MASTG"),
    ("binary_firmware_memory", "binary analysis", "CWE memory safety; binary and firmware analysis"),
    ("smart_contract_blockchain", "smart contract security", "OWASP Smart Contract Top 10 and SWC"),
    ("malware_reverse_engineering", "malware analysis", "MITRE ATT&CK malware and reverse analysis"),
    ("threat_detection_hunting", "threat detection", "MITRE ATT&CK detection and threat hunting"),
    ("forensics_incident_investigation", "digital forensics", "NIST SP 800-61 and forensic investigation"),
    ("ai_llm_agent_mcp", "prompt injection", "OWASP LLM Top 10 and agent/MCP security"),
    ("detection_engineering", "YARA", "Detection-rule, signature and query engineering"),
    ("vulnerability_intelligence", "CVE", "CVE/NVD/CISA KEV vulnerability intelligence"),
]


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


def get_query(query: str, sort_by: str):
    params = {
        "q": query,
        "category": CATEGORY,
        "sortBy": sort_by,
        "page": 1,
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
    for query_order, (stratum, query, standards_basis) in enumerate(STRATA, 1):
        payload, items, status, url, headers = get_query(query, sort_by)
        calls += 1
        raw_path = RAW / f"{frame}_{query_order:02d}_{stratum}.json"
        raw_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        pagination = pagination_from(payload)
        logs.append({
            "frame": frame,
            "stratum": stratum,
            "query": query,
            "standards_basis": standards_basis,
            "query_order": query_order,
            "category": CATEGORY,
            "sort_by": sort_by,
            "page": 1,
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
            raise RuntimeError(f"SkillsMP request failed for {frame}/{stratum}: {payload}")
        for position, item in enumerate(items, 1):
            records.append({
                "skillsmp_id": str(val(item, "id", "skillId", "slug", default="")).strip(),
                "name": str(val(item, "name", "title", default="")).strip(),
                "author": str(val(item, "author", "creator", default="")).strip(),
                "description": str(val(item, "description", "summary", default="")).strip(),
                "content_language": str(val(item, "contentLanguage", "language", default="")).strip(),
                "github_url": str(val(item, "githubUrl", "github_url", "sourceUrl", default="")).strip(),
                "skillsmp_url": str(val(item, "skillUrl", "url", "marketplaceUrl", default="")).strip(),
                "stars": val(item, "stars", "githubStars", "stargazersCount", default=""),
                "updated_at": str(val(item, "updatedAt", "updated_at", default="")).strip(),
                "api_category": str(val(item, "category", "categoryName", default="")).strip(),
                "frame": frame,
                "stratum": stratum,
                "query": query,
                "standards_basis": standards_basis,
                "query_order": query_order,
                "page": query_order,
                "position": position,
                "frame_rank": position,
            })
        if calls < len(STRATA) * 2:
            time.sleep(SLEEP_SECONDS)

if calls != len(STRATA) * 2:
    raise RuntimeError(f"Expected {len(STRATA) * 2} API requests, made {calls}")

occurrence_fields = [
    "skillsmp_id", "name", "author", "description", "content_language", "github_url",
    "skillsmp_url", "stars", "updated_at", "api_category", "frame", "stratum", "query",
    "standards_basis", "query_order", "page", "position", "frame_rank",
]
write_csv(OUT / "ranked_frame_occurrences.csv", records, occurrence_fields)
write_csv(
    OUT / "query_log.csv",
    logs,
    [
        "frame", "stratum", "query", "standards_basis", "query_order", "category",
        "sort_by", "page", "limit", "status", "returned", "reported_total",
        "reported_total_pages", "request_url", "daily_remaining", "minute_remaining", "raw_file",
    ],
)

union: dict[str, dict] = {}
for row in records:
    key = row["skillsmp_id"] or row["skillsmp_url"] or row["github_url"] or f"{row['name']}|{row['author']}"
    current = union.setdefault(
        key,
        {k: row.get(k, "") for k in occurrence_fields if k not in ("frame", "stratum", "query", "standards_basis", "query_order", "page", "position", "frame_rank")},
    )
    frame = row["frame"]
    current[f"in_{frame}_frame"] = True
    current.setdefault(f"{frame}_query_strata", [])
    current[f"{frame}_query_strata"].append(row["stratum"])
    previous = current.get(f"{frame}_rank")
    current[f"{frame}_rank"] = row["frame_rank"] if previous in (None, "") else min(int(previous), int(row["frame_rank"]))

for row in union.values():
    for frame in ("stars", "recent"):
        row.setdefault(f"in_{frame}_frame", False)
        row.setdefault(f"{frame}_rank", "")
        row[f"{frame}_query_strata"] = "; ".join(sorted(set(row.get(f"{frame}_query_strata", []))))
    row["query_hit_count"] = len([x for x in (row["stars_query_strata"] + "; " + row["recent_query_strata"]).split("; ") if x])

union_rows = list(union.values())
union_fields = [
    "skillsmp_id", "name", "author", "description", "content_language", "github_url",
    "skillsmp_url", "stars", "updated_at", "api_category", "in_stars_frame", "stars_rank",
    "stars_query_strata", "in_recent_frame", "recent_rank", "recent_query_strata",
    "query_hit_count",
]
write_csv(OUT / "ranked_frame_union.csv", union_rows, union_fields)

stars_ids = {key for key, value in union.items() if value.get("in_stars_frame")}
recent_ids = {key for key, value in union.items() if value.get("in_recent_frame")}

marginal_yield: list[dict] = []
combined_seen: set[str] = set()
for frame in ("stars", "recent"):
    frame_seen: set[str] = set()
    for query_order, (stratum, query, standards_basis) in enumerate(STRATA, 1):
        keys = {
            row["skillsmp_id"] or row["skillsmp_url"] or row["github_url"] or f"{row['name']}|{row['author']}"
            for row in records
            if row["frame"] == frame and row["stratum"] == stratum
        }
        marginal_yield.append({
            "frame": frame,
            "query_order": query_order,
            "stratum": stratum,
            "query": query,
            "standards_basis": standards_basis,
            "returned_unique": len(keys),
            "new_unique_within_frame": len(keys - frame_seen),
            "cumulative_unique_within_frame": len(frame_seen | keys),
            "new_unique_to_combined_union": len(keys - combined_seen),
            "cumulative_combined_union": len(combined_seen | keys),
        })
        frame_seen |= keys
        combined_seen |= keys
write_csv(
    OUT / "marginal_yield_by_stratum.csv",
    marginal_yield,
    [
        "frame", "query_order", "stratum", "query", "standards_basis", "returned_unique",
        "new_unique_within_frame", "cumulative_unique_within_frame",
        "new_unique_to_combined_union", "cumulative_combined_union",
    ],
)
# Compatibility with the existing review script; locally this is relabelled as stratum saturation.
write_csv(
    OUT / "saturation_by_page.csv",
    [
        {
            "frame": r["frame"],
            "page": r["query_order"],
            "returned_unique_on_page": r["returned_unique"],
            "new_unique_on_page": r["new_unique_within_frame"],
            "cumulative_unique": r["cumulative_unique_within_frame"],
        }
        for r in marginal_yield
    ],
    ["frame", "page", "returned_unique_on_page", "new_unique_on_page", "cumulative_unique"],
)

diagnostics = {
    "design": "Preregistered equal-budget ontology-stratified paired ranking study",
    "category": CATEGORY,
    "strata": [
        {"stratum": s, "query": q, "standards_basis": basis}
        for s, q, basis in STRATA
    ],
    "sort_frames": ["stars", "recent"],
    "requests_per_frame": len(STRATA),
    "limit_per_query": LIMIT,
    "api_requests": calls,
    "stars_frame_unique": len(stars_ids),
    "recent_frame_unique": len(recent_ids),
    "frame_overlap": len(stars_ids & recent_ids),
    "ranked_union_unique": len(union_rows),
    "jaccard_overlap": round(len(stars_ids & recent_ids) / max(1, len(stars_ids | recent_ids)), 6),
    "interpretation": "Deterministic standards-grounded, ontology-stratified paired rankings; not a probability sample and not a full catalog census.",
    "wildcard_pilot_result": "SkillsMP rejected q=* with INVALID_QUERY because the query must contain a letter or number; therefore a category-wide wildcard census was not technically available.",
}
(OUT / "frame_diagnostics.json").write_text(json.dumps(diagnostics, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(diagnostics, ensure_ascii=False, indent=2))
