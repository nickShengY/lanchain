#!/usr/bin/env python3
from __future__ import annotations
import csv, json, time
from pathlib import Path
from typing import Any
import requests

API="https://skillsmp.com/api/v1/skills/search"
OUT=Path("skillsmp_scientific_output"); RAW=OUT/"raw_api"
OUT.mkdir(exist_ok=True); RAW.mkdir(exist_ok=True)
LIMIT=50; SLEEP=6.4
HEADERS={"Accept":"application/json","User-Agent":"skillsmp-scientific-security-audit/2.0"}

# Preregistered high-recall ontology strata. Every stratum is paired across
# stars and recent ranking, so retrieval is balanced and reproducible.
QUERIES=[
 ("general_security","security"),("vulnerability","vulnerability"),("audit","audit"),
 ("penetration_testing","pentest"),("owasp","OWASP"),("injection","injection"),
 ("sast","SAST"),("dast","DAST"),("fuzzing","fuzzing"),("semgrep","Semgrep"),
 ("codeql","CodeQL"),("cve","CVE"),("dependency","dependency"),
 ("supply_chain","supply chain"),("secrets","secret scanning"),("cloud","cloud security"),
 ("kubernetes","Kubernetes security"),("iac","IaC security"),("mobile","mobile security"),
 ("binary_firmware","binary security"),("smart_contract","smart contract security"),
 ("malware","malware"),("forensics","forensics"),("agent_prompt_injection","prompt injection"),
 ("detection_rules","YARA"),
]

def rows_from(payload:Any)->list[dict]:
    if isinstance(payload,list):return [x for x in payload if isinstance(x,dict)]
    if not isinstance(payload,dict):return []
    for key in ("skills","results","items","data"):
        value=payload.get(key)
        if isinstance(value,list):return [x for x in value if isinstance(x,dict)]
        if isinstance(value,dict):
            for k2 in ("skills","results","items","data"):
                v2=value.get(k2)
                if isinstance(v2,list):return [x for x in v2 if isinstance(x,dict)]
    return []

def get_query(query:str,sort_by:str):
    params={"q":query,"sortBy":sort_by,"page":1,"limit":LIMIT}
    last=""
    for attempt in range(5):
        try:
            r=requests.get(API,params=params,headers=HEADERS,timeout=60)
            last=f"{r.status_code} {r.text[:800]}"
            if r.status_code==200:
                payload=r.json();return payload,rows_from(payload),r.status_code,r.url,dict(r.headers)
            if r.status_code in (429,500,502,503,504):time.sleep(20*(attempt+1));continue
            return {"error":last},[],r.status_code,r.url,dict(r.headers)
        except Exception as e:
            last=repr(e);time.sleep(15*(attempt+1))
    return {"error":last},[],0,"",{}

def val(item,*names,default=""):
    for n in names:
        if item.get(n) not in (None,""):return item[n]
    return default
def write_csv(path,rows,fields):
    with open(path,"w",encoding="utf-8-sig",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore");w.writeheader();w.writerows(rows)

records=[];logs=[];calls=0
for sort_by in ("stars","recent"):
    for q_index,(stratum,query) in enumerate(QUERIES,1):
        payload,items,status,url,headers=get_query(query,sort_by);calls+=1
        raw=RAW/f"{sort_by}_{q_index:02d}_{stratum}.json"
        raw.write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding="utf-8")
        logs.append({"frame":sort_by,"stratum":stratum,"query":query,"query_order":q_index,
                     "page":1,"limit":LIMIT,"status":status,"returned":len(items),
                     "request_url":url,"daily_remaining":headers.get("X-RateLimit-Daily-Remaining",""),
                     "minute_remaining":headers.get("X-RateLimit-Minute-Remaining",""),"raw_file":str(raw)})
        for pos,item in enumerate(items,1):
            records.append({
              "skillsmp_id":str(val(item,"id","skillId","slug",default="")).strip(),
              "name":str(val(item,"name","title",default="")).strip(),
              "author":str(val(item,"author","creator",default="")).strip(),
              "description":str(val(item,"description","summary",default="")).strip(),
              "content_language":str(val(item,"contentLanguage","language",default="")).strip(),
              "github_url":str(val(item,"githubUrl","github_url","sourceUrl",default="")).strip(),
              "skillsmp_url":str(val(item,"skillUrl","url","marketplaceUrl",default="")).strip(),
              "stars":val(item,"stars","githubStars","stargazersCount",default=""),
              "updated_at":str(val(item,"updatedAt","updated_at",default="")).strip(),
              "api_category":str(val(item,"category","categoryName",default="")).strip(),
              "frame":sort_by,"stratum":stratum,"query":query,"query_order":q_index,
              "page":q_index,"position":pos,"frame_rank":pos})
        if calls<50:time.sleep(SLEEP)
if calls!=50:raise RuntimeError(f"Expected 50 paired-stratum requests, made {calls}")

fields=["skillsmp_id","name","author","description","content_language","github_url","skillsmp_url",
"stars","updated_at","api_category","frame","stratum","query","query_order","page","position","frame_rank"]
write_csv(OUT/"ranked_frame_occurrences.csv",records,fields)
write_csv(OUT/"query_log.csv",logs,["frame","stratum","query","query_order","page","limit","status","returned","request_url","daily_remaining","minute_remaining","raw_file"])
union={}
for r in records:
    key=r["skillsmp_id"] or r["skillsmp_url"] or r["github_url"] or f"{r['name']}|{r['author']}"
    u=union.setdefault(key,{k:r.get(k,"") for k in fields if k not in ("frame","stratum","query","query_order","page","position","frame_rank")})
    frame=r["frame"];u[f"in_{frame}_frame"]=True
    u.setdefault(f"{frame}_query_strata",[]);u[f"{frame}_query_strata"].append(r["stratum"])
    rank_key=f"{frame}_rank";old=u.get(rank_key)
    u[rank_key]=r["frame_rank"] if old in (None,"") else min(int(old),int(r["frame_rank"]))
for u in union.values():
    for frame in ("stars","recent"):
        u.setdefault(f"in_{frame}_frame",False);u.setdefault(f"{frame}_rank","")
        u[f"{frame}_query_strata"]="; ".join(sorted(set(u.get(f"{frame}_query_strata",[]))))
    u["query_hit_count"]=len([x for x in (u["stars_query_strata"]+"; "+u["recent_query_strata"]).split("; ") if x])
union_rows=list(union.values())
ufields=["skillsmp_id","name","author","description","content_language","github_url","skillsmp_url",
"stars","updated_at","api_category","in_stars_frame","stars_rank","stars_query_strata",
"in_recent_frame","recent_rank","recent_query_strata","query_hit_count"]
write_csv(OUT/"ranked_frame_union.csv",union_rows,ufields)

star={k for k,v in union.items() if v.get("in_stars_frame")};recent={k for k,v in union.items() if v.get("in_recent_frame")}
per_query=[]
for frame in ("stars","recent"):
    for order,(stratum,query) in enumerate(QUERIES,1):
        rr=[r for r in records if r["frame"]==frame and r["stratum"]==stratum]
        per_query.append({"frame":frame,"query_order":order,"stratum":stratum,"query":query,
                          "returned":len(rr),"unique_within_query":len({r["skillsmp_id"] or r["skillsmp_url"] or r["github_url"] for r in rr})})
write_csv(OUT/"stratum_retrieval_counts.csv",per_query,["frame","query_order","stratum","query","returned","unique_within_query"])
diag={"design":"Preregistered paired stratified-query frame","queries":[{"stratum":s,"query":q} for s,q in QUERIES],
"sort_frames":["stars","recent"],"requests_per_frame":25,"limit_per_query":LIMIT,"api_requests":calls,
"stars_frame_unique":len(star),"recent_frame_unique":len(recent),"frame_overlap":len(star&recent),
"ranked_union_unique":len(union_rows),"jaccard_overlap":round(len(star&recent)/max(1,len(star|recent)),6),
"interpretation":"Deterministic ontology-stratified paired rankings; not a probability sample and not a full catalog census."}
(OUT/"frame_diagnostics.json").write_text(json.dumps(diag,ensure_ascii=False,indent=2),encoding="utf-8")
print(json.dumps(diag,ensure_ascii=False,indent=2))
