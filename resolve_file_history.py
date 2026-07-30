import json, os, time, urllib.parse, urllib.request, urllib.error
from pathlib import Path
TOKEN=os.environ.get("GITHUB_TOKEN","")
HEADERS={"Accept":"application/vnd.github+json","User-Agent":"security-skill-audit"}
if TOKEN: HEADERS["Authorization"]=f"Bearer {TOKEN}"
items=json.load(open("file_history_manifest.json",encoding="utf-8"))
out=[]
for n,item in enumerate(items,1):
    repo=item["repo"]; path=item["path"]
    commits=[]; page=1; error=""
    while True:
        url=f"https://api.github.com/repos/{repo}/commits?path={urllib.parse.quote(path,safe='/')}&per_page=100&page={page}"
        try:
            req=urllib.request.Request(url,headers=HEADERS)
            with urllib.request.urlopen(req,timeout=60) as resp:
                batch=json.loads(resp.read().decode())
        except Exception as e:
            error=repr(e); break
        if not isinstance(batch,list) or not batch: break
        commits.extend(batch)
        if len(batch)<100: break
        page+=1
        time.sleep(.2)
    earliest=commits[-1] if commits else None
    result={**item,"commit_count":len(commits),"status":"resolved" if earliest else "unresolved","error":error}
    if earliest:
        c=earliest.get("commit",{})
        result.update({
            "skill_file_created_date":(c.get("author") or {}).get("date") or (c.get("committer") or {}).get("date"),
            "skill_file_created_commit_sha":earliest.get("sha"),
            "skill_file_created_commit_url":earliest.get("html_url"),
            "commit_message":c.get("message",""),
        })
    out.append(result)
    print(f"[{n}/{len(items)}] {repo}:{path} -> {result['status']} {result.get('skill_file_created_date','')}")
Path("file_history_output").mkdir(exist_ok=True)
json.dump(out,open("file_history_output/results.json","w",encoding="utf-8"),indent=2,ensure_ascii=False)
