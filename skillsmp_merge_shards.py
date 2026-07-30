#!/usr/bin/env python3
from __future__ import annotations
import csv, json, os, re, shutil, difflib
from pathlib import Path
from collections import defaultdict

COLLECTION = Path(os.environ.get("COLLECTION_DIR", "collection"))
SHARDS = Path(os.environ.get("SHARDS_DIR", "shards"))
OUT = Path("skillsmp_scientific_final")
if OUT.exists():
    shutil.rmtree(OUT)
shutil.copytree(COLLECTION, OUT)
(OUT / "source").mkdir(exist_ok=True)
(OUT / "evidence").mkdir(exist_ok=True)

def read_csv(path):
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))

def write_csv(path, rows, fields=None):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields=[]; seen=set()
        for r in rows:
            for k in r:
                if k not in seen:
                    seen.add(k); fields.append(k)
    with open(path,"w",encoding="utf-8-sig",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore")
        w.writeheader(); w.writerows(rows)

def parse_int(v):
    try: return int(float(str(v).replace(",","").strip()))
    except: return 0

def truth(v):
    return str(v).strip().lower() in {"1","true","yes"}

def slug(s):
    return re.sub(r"-+","-",re.sub(r"[^a-z0-9]+","-",str(s or "").lower())).strip("-")

reviews=[]
for shard_csv in sorted(SHARDS.rglob("source_review_all.csv")):
    shard_root=shard_csv.parent
    reviews.extend(read_csv(shard_csv))
    shard_label=shard_root.parent.name if shard_root.name=="skillsmp_scientific_output" else shard_root.name
    for sub in ("source","evidence"):
        src=shard_root/sub
        if src.exists():
            for p in src.glob("*"):
                if p.is_file():
                    shutil.copy2(p,OUT/sub/f"{shard_label}_{p.name}")

union=read_csv(OUT/"ranked_frame_union.csv")
if len(reviews)!=len(union):
    raise RuntimeError(f"review coverage mismatch: reviewed={len(reviews)} union={len(union)}")
ids=[r.get("skillsmp_id") or r.get("skillsmp_url") or r.get("github_url") or f"{r.get('name')}|{r.get('author')}" for r in reviews]
if len(ids)!=len(set(ids)):
    raise RuntimeError("duplicate review IDs across shards")
write_csv(OUT/"source_review_all.csv",reviews)

included=[r for r in reviews if str(r.get("final_decision","")).startswith("INCLUDE") and not truth(r.get("repo_archived")) and not truth(r.get("repo_disabled"))]
parent=list(range(len(included)))
def find(x):
    while parent[x]!=x:
        parent[x]=parent[parent[x]]; x=parent[x]
    return x
def union_set(a,b):
    a,b=find(a),find(b)
    if a!=b: parent[b]=a

by_sha=defaultdict(list); by_repo_path=defaultdict(list); by_name=defaultdict(list)
for i,r in enumerate(included):
    sha=(r.get("source_sha256") or "").strip()
    if sha: by_sha[sha].append(i)
    by_repo_path[(str(r.get("repo","")).lower(),str(r.get("source_path","")).lower())].append(i)
    by_name[slug(r.get("source_name") or r.get("name"))].append(i)
for groups in (by_sha,by_repo_path):
    for ids2 in groups.values():
        for j in ids2[1:]: union_set(ids2[0],j)
for ids2 in by_name.values():
    if len(ids2)>30: continue
    for a in range(len(ids2)):
        for b in range(a+1,len(ids2)):
            ia,ib=ids2[a],ids2[b]
            if find(ia)==find(ib): continue
            ra,rb=included[ia],included[ib]
            ta=re.sub(r"\s+"," ",f"{ra.get('source_description','')} {ra.get('evidence_quote','')}".lower()).strip()
            tb=re.sub(r"\s+"," ",f"{rb.get('source_description','')} {rb.get('evidence_quote','')}".lower()).strip()
            if min(len(ta),len(tb))>=120 and difflib.SequenceMatcher(None,ta,tb).ratio()>=0.97:
                union_set(ia,ib)

groups=defaultdict(list)
for i in range(len(included)): groups[find(i)].append(i)
canonical=[]; duplicates=[]
for gid,ids2 in enumerate(groups.values(),1):
    ids2=sorted(ids2,key=lambda i:(included[i].get("skill_file_created_date") or "9999-99-99",-parse_int(included[i].get("repo_stars_verified") or included[i].get("stars")),str(included[i].get("repo",""))))
    c=included[ids2[0]].copy(); c["duplicate_group"]=f"SMP-DUP-{gid:05d}" if len(ids2)>1 else ""; canonical.append(c)
    for j in ids2[1:]:
        d=included[j].copy(); d["canonical_repo"]=c.get("repo",""); d["canonical_source_path"]=c.get("source_path",""); d["duplicate_reason"]="Exact source SHA, identical repository/path, or conservative same-name evidence similarity >=0.97."; duplicates.append(d)

excluded=[r for r in reviews if not str(r.get("final_decision","")).startswith("INCLUDE") or truth(r.get("repo_archived")) or truth(r.get("repo_disabled"))]
false_neg=[r for r in reviews if str(r.get("final_decision","")).startswith("INCLUDE") and not truth(r.get("description_screen_retain"))]
write_csv(OUT/"canonical_skills.csv",canonical); write_csv(OUT/"duplicates_removed.csv",duplicates); write_csv(OUT/"excluded_unresolved.csv",excluded); write_csv(OUT/"description_screen_false_negatives.csv",false_neg)

diag=json.loads((OUT/"frame_diagnostics.json").read_text(encoding="utf-8"))
source_resolved=sum(r.get("source_status")=="resolved" for r in reviews); source_included=sum(str(r.get("final_decision","")).startswith("INCLUDE") for r in reviews); screen_tp=sum(str(r.get("final_decision","")).startswith("INCLUDE") and truth(r.get("description_screen_retain")) for r in reviews)
diag.update({"source_records_reviewed":len(reviews),"source_resolved":source_resolved,"source_unresolved":len(reviews)-source_resolved,"included_before_deduplication":len(included),"canonical_after_deduplication":len(canonical),"duplicates_removed":len(duplicates),"description_screen_true_positives":screen_tp,"description_screen_false_negatives":len(false_neg),"description_screen_empirical_recall":round(screen_tp/max(1,source_included),6),"review_execution":"8-shard parallel exhaustive source review with global merge"})
(OUT/"scientific_diagnostics.json").write_text(json.dumps(diag,ensure_ascii=False,indent=2),encoding="utf-8")

errors=[]
if diag.get("ranked_union_unique",0)<50: errors.append("ranked union too small")
if len(reviews)!=diag.get("ranked_union_unique"): errors.append("not every union listing reviewed")
if source_resolved/max(1,len(reviews))<0.65: errors.append("source resolution rate below 65%")
if not canonical: errors.append("no canonical included skills")
qlog=read_csv(OUT/"query_log.csv")
if len(qlog)!=50 or any(str(r.get("status"))!="200" for r in qlog): errors.append("query log does not contain 50 successful requests")
completion={"status":"PASS" if not errors else "FAIL","snapshot_date":"2026-07-30","design":"25 preregistered security strata x paired popularity/recency frames in SkillsMP category=security","api_requests":len(qlog),"ranked_occurrences":len(read_csv(OUT/"ranked_frame_occurrences.csv")),"ranked_union_unique":len(union),"source_records_reviewed":len(reviews),"source_resolved":source_resolved,"canonical_after_deduplication":len(canonical),"duplicates_removed":len(duplicates),"excluded_unresolved":len(excluded),"errors":errors}
(OUT/"LOCAL_COMPLETION.json").write_text(json.dumps(completion,ensure_ascii=False,indent=2),encoding="utf-8")
(OUT/"methodology.md").write_text(f"""# SkillsMP structured scientific retrieval

The primary frame uses the actual SkillsMP `security` category and 25 security strata declared before retrieval. Each stratum receives the same maximum budget: up to 100 star-ranked matches and up to 100 recent-ranked matches.

All {len(union)} unique listings in the paired ranked union received source review. The review ran in eight independent shards and was merged globally before deduplication. Keyword screening is diagnostic only and never determines which ranked-frame listing is reviewed.

This is a deterministic standards-grounded multi-frame coverage study. It is not a probability sample, random sample, global ranking, or complete SkillsMP census.
""",encoding="utf-8")
if errors: raise RuntimeError("; ".join(errors))
print(json.dumps(completion,ensure_ascii=False,indent=2))
