#!/usr/bin/env python3
from __future__ import annotations
import csv, json, time
from pathlib import Path
from typing import Any
import requests

API = "https://skillsmp.com/api/v1/skills/search"
OUT = Path("skillsmp_scientific_output")
RAW = OUT / "raw_api"
OUT.mkdir(exist_ok=True)
RAW.mkdir(exist_ok=True)
LIMIT = 50
SLEEP = 6.4
HEADERS = {"Accept":"application/json","User-Agent":"skillsmp-scientific-security-audit/1.0"}

def rows_from(payload: Any) -> list[dict]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("skills","results","items","data"):
        value = payload.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
        if isinstance(value, dict):
            for k2 in ("skills","results","items","data"):
                v2=value.get(k2)
                if isinstance(v2,list):
                    return [x for x in v2 if isinstance(x,dict)]
    return []

def get_page(category:str, sort_by:str, page:int) -> tuple[dict,list[dict],int,str]:
    params={"q":"*","category":category,"sortBy":sort_by,"page":page,"limit":LIMIT}
    last=""
    for attempt in range(5):
        try:
            r=requests.get(API,params=params,headers=HEADERS,timeout=60)
            last=f"{r.status_code} {r.text[:500]}"
            if r.status_code==200:
                payload=r.json()
                return payload, rows_from(payload), r.status_code, r.url
            if r.status_code in (429,500,502,503,504):
                time.sleep(20*(attempt+1))
                continue
            return {},[],r.status_code,r.url
        except Exception as e:
            last=repr(e)
            time.sleep(15*(attempt+1))
    return {"error":last},[],0,""

def write_csv(path:Path, rows:list[dict], fields:list[str]) -> None:
    with path.open("w",encoding="utf-8-sig",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore")
        w.writeheader(); w.writerows(rows)

def val(item:dict,*names,default=""):
    for n in names:
        if item.get(n) not in (None,""):
            return item[n]
    return default

probe={}; calls=0
for sort_by in ("stars","recent"):
    payload,items,status,url=get_page("security",sort_by,1)
    calls+=1; probe[sort_by]=(payload,items,status,url); time.sleep(SLEEP)

category="security" if sum(len(v[1]) for v in probe.values())>0 else "testing-security"
pages=25 if category=="security" else 24
records=[]; query_log=[]; seen_frame=set()

def consume(sort_by,page,payload,items,status,url):
    raw=RAW/f"{sort_by}_page_{page:02d}.json"
    raw.write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding="utf-8")
    query_log.append({"frame":sort_by,"category":category,"q":"*","page":page,"limit":LIMIT,
                      "status":status,"returned":len(items),"request_url":url,"raw_file":str(raw)})
    for pos,item in enumerate(items,1):
        sid=str(val(item,"id","skillId","slug",default="")).strip()
        skill_url=str(val(item,"skillUrl","url","marketplaceUrl",default="")).strip()
        github_url=str(val(item,"githubUrl","github_url","sourceUrl",default="")).strip()
        key=sid or skill_url or github_url or f"{sort_by}:{page}:{pos}"
        fkey=(sort_by,key)
        if fkey in seen_frame: continue
        seen_frame.add(fkey)
        records.append({
            "skillsmp_id":sid,"name":str(val(item,"name","title",default="")).strip(),
            "author":str(val(item,"author","creator",default="")).strip(),
            "description":str(val(item,"description","summary",default="")).strip(),
            "content_language":str(val(item,"contentLanguage","language",default="")).strip(),
            "github_url":github_url,"skillsmp_url":skill_url,
            "stars":val(item,"stars","githubStars","stargazersCount",default=""),
            "updated_at":str(val(item,"updatedAt","updated_at",default="")).strip(),
            "api_category":str(val(item,"category","categoryName",default="")).strip(),
            "frame":sort_by,"page":page,"position":pos,"frame_rank":(page-1)*LIMIT+pos,
        })

if category=="security":
    for sort_by,(payload,items,status,url) in probe.items(): consume(sort_by,1,payload,items,status,url)
    start=2
else:
    start=1
for sort_by in ("stars","recent"):
    for page in range(start,pages+1):
        payload,items,status,url=get_page(category,sort_by,page)
        calls+=1; consume(sort_by,page,payload,items,status,url)
        if calls<50: time.sleep(SLEEP)
if calls != 50: raise RuntimeError(f"Expected exactly 50 SkillsMP requests, made {calls}")

frame_fields=["skillsmp_id","name","author","description","content_language","github_url",
              "skillsmp_url","stars","updated_at","api_category","frame","page","position","frame_rank"]
write_csv(OUT/"ranked_frame_occurrences.csv",records,frame_fields)
write_csv(OUT/"query_log.csv",query_log,["frame","category","q","page","limit","status","returned","request_url","raw_file"])
union={}
for r in records:
    key=r["skillsmp_id"] or r["skillsmp_url"] or r["github_url"] or f"{r['name']}|{r['author']}"
    u=union.setdefault(key,{k:r.get(k,"") for k in frame_fields if k not in ("frame","page","position","frame_rank")})
    u[f"in_{r['frame']}_frame"]=True; u[f"{r['frame']}_rank"]=r["frame_rank"]
for u in union.values():
    u.setdefault("in_stars_frame",False); u.setdefault("stars_rank","")
    u.setdefault("in_recent_frame",False); u.setdefault("recent_rank","")
union_rows=list(union.values())
union_fields=["skillsmp_id","name","author","description","content_language","github_url","skillsmp_url",
              "stars","updated_at","api_category","in_stars_frame","stars_rank","in_recent_frame","recent_rank"]
write_csv(OUT/"ranked_frame_union.csv",union_rows,union_fields)
star_keys={k for k,v in union.items() if v.get("in_stars_frame")}; recent_keys={k for k,v in union.items() if v.get("in_recent_frame")}
diag={"design":"Deterministic dual-ranked category frame","query":"q=*","requested_category":"security",
      "effective_category":category,"sort_frames":["stars","recent"],"pages_per_frame":pages,"limit":LIMIT,
      "api_requests":calls,"stars_frame_unique":len(star_keys),"recent_frame_unique":len(recent_keys),
      "frame_overlap":len(star_keys & recent_keys),"ranked_union_unique":len(union_rows),
      "jaccard_overlap":round(len(star_keys & recent_keys)/max(1,len(star_keys | recent_keys)),6),
      "interpretation":"Rank-defined coverage frame, not a probability sample and not a full category census."}
(OUT/"frame_diagnostics.json").write_text(json.dumps(diag,ensure_ascii=False,indent=2),encoding="utf-8")
print(json.dumps(diag,ensure_ascii=False,indent=2))
