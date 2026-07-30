#!/usr/bin/env python3
from __future__ import annotations
import csv, difflib, hashlib, json, os, re, time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse, unquote
import requests

OUT=Path("skillsmp_scientific_output"); SRC=OUT/"source"; EVID=OUT/"evidence"
SRC.mkdir(exist_ok=True); EVID.mkdir(exist_ok=True)
TOKEN=os.environ.get("GITHUB_TOKEN","")
API_HEADERS={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"skillsmp-scientific-security-audit/1.0"}
if TOKEN: API_HEADERS["Authorization"]=f"Bearer {TOKEN}"
RAW_HEADERS={"User-Agent":"skillsmp-scientific-security-audit/1.0"}
session=requests.Session(); repo_meta_cache={}; tree_cache={}

def read_csv(p):
    with open(p,encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))
def write_csv(p,rows,fields=None):
    if fields is None:
        fields=[]; seen=set()
        for r in rows:
            for k in r:
                if k not in seen:seen.add(k);fields.append(k)
    with open(p,"w",encoding="utf-8-sig",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore");w.writeheader();w.writerows(rows)
def norm(s):return re.sub(r"\s+"," ",str(s or "")).strip()
def slug(s):return re.sub(r"-+","-",re.sub(r"[^a-z0-9]+","-",norm(s).lower())).strip("-")
def sha(s):return hashlib.sha256((s or "").encode("utf-8","ignore")).hexdigest()
def parse_int(x):
    try:return int(str(x).replace(",",""))
    except:return 0
def safe(s):return re.sub(r"[^A-Za-z0-9_.-]+","_",s)[:180]
def gh_get(url,params=None,timeout=60):
    for i in range(5):
        try:
            r=session.get(url,headers=API_HEADERS,params=params,timeout=timeout)
            if r.status_code==200:return r
            if r.status_code in (403,429,500,502,503,504):time.sleep(10*(i+1));continue
            return r
        except Exception:time.sleep(10*(i+1))
    return None
def raw_get(url):
    for i in range(4):
        try:
            r=session.get(url,headers=RAW_HEADERS,timeout=45)
            if r.status_code==200 and len(r.text)>20:return r.text
            if r.status_code in (429,500,502,503,504):time.sleep(8*(i+1));continue
            return ""
        except Exception:time.sleep(8*(i+1))
    return ""
def parse_github(url):
    if not url:return None
    u=urlparse(url); host=u.netloc.lower(); parts=[unquote(x) for x in u.path.strip("/").split("/")]
    if host=="raw.githubusercontent.com" and len(parts)>=4:return {"repo":f"{parts[0]}/{parts[1]}","ref":parts[2],"path":"/".join(parts[3:])}
    if host.endswith("github.com") and len(parts)>=2:
        repo=f"{parts[0]}/{parts[1].removesuffix('.git')}"
        if len(parts)>=5 and parts[2] in ("blob","raw","tree"):return {"repo":repo,"ref":parts[3],"path":"/".join(parts[4:])}
        return {"repo":repo,"ref":"","path":""}
    return None
def repo_meta(repo):
    if repo in repo_meta_cache:return repo_meta_cache[repo]
    r=gh_get(f"https://api.github.com/repos/{repo}"); data=r.json() if r and r.status_code==200 else {}
    repo_meta_cache[repo]=data; return data
def repo_tree(repo,ref):
    key=(repo,ref)
    if key in tree_cache:return tree_cache[key]
    r=gh_get(f"https://api.github.com/repos/{repo}/git/trees/{ref}",{"recursive":"1"},90)
    data=r.json().get("tree",[]) if r and r.status_code==200 else []
    paths=[x.get("path","") for x in data if x.get("type")=="blob"]
    tree_cache[key]=paths; return paths
def raw_url(repo,ref,path):return f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"
def resolve_source(row):
    parsed=parse_github(row.get("github_url",""))
    if not parsed:return {"status":"unresolved_no_github_url"}
    repo=parsed["repo"]; meta=repo_meta(repo)
    if not meta:return {"status":"unresolved_repository","repo":repo}
    ref=parsed["ref"] or meta.get("default_branch","main"); path=parsed["path"]; candidates=[]
    if path:
        if path.lower().endswith("skill.md"):candidates.append(path)
        else:candidates.extend([path.rstrip("/")+"/SKILL.md",path])
    first_ok=bool(candidates and raw_get(raw_url(repo,ref,candidates[0])))
    if not first_ok:
        paths=repo_tree(repo,ref); skills=[p for p in paths if p.lower().endswith("/skill.md") or p.lower()=="skill.md"]
        name_slug=slug(row.get("name","")); toks=set(name_slug.split("-"))
        skills.sort(key=lambda p:(100 if name_slug and name_slug in slug(p) else 0)+10*len(toks & set(slug(p).split("-")))-p.count("/"),reverse=True)
        candidates=skills[:20]+candidates
    seen=set()
    for p in candidates:
        if not p or p in seen:continue
        seen.add(p); text=raw_get(raw_url(repo,ref,p))
        if text and ("name:" in text[:1500].lower() or "# " in text[:2000]):return {"status":"resolved","repo":repo,"ref":ref,"path":p,"text":text,"meta":meta}
    return {"status":"unresolved_skill_file","repo":repo,"ref":ref,"meta":meta}

POS_OBJECTS=["vulnerab","security flaw","weakness","misconfig","cve","cwe","exploit","attack surface","secret","credential","malware","threat","intrusion","injection","xss","ssrf","csrf","idor","bola","auth bypass","privilege escalation","memory corruption","phishing","prompt injection","jailbreak","data exfiltration","supply chain","unsafe","forensic","security posture","risk"]
POS_ACTIONS=["scan","detect","find","identify","audit","assess","review","test","hunt","analy","triage","validate","verify","enumerate","probe","monitor","investigate","fuzz","lint","correlate"]
TOOLS=["semgrep","codeql","sast","dast","sca","gitleaks","trufflehog","zaproxy","owasp zap","nuclei","nessus","openvas","greenbone","kics","checkov","tfsec","trivy","grype","bandit","gosec","yara","sigma","slither","mythril","echidna","burp"]
SUPPORT=["rule author","query author","signature author","false positive","finding triage","variant analysis","exploitability validation","attack surface mapping","vulnerability intelligence","cisa kev","advisory"]
EXCLUDE_MAIN=["hardening","secure implementation","secure coding","best practices","compliance","governance","audit preparation","awareness training","case management","remediation only","patching","architecture diagram","secret management","credential rotation","authentication implementation","oauth implementation"]
METHODS={
"Static Pattern / Query-Based Analysis":["semgrep","codeql","sast","static analysis","ast","bandit","gosec","brakeman"],
"Interprocedural Data-Flow / Taint Analysis":["taint analysis","taint tracking","data flow","dataflow","source-to-sink"],
"Dynamic Application Scanning / Active Probing":["dast","zaproxy","owasp zap","burp","nuclei","active scan","live probing"],
"Fuzzing / Property-Based Testing":["fuzz","libfuzzer","afl","property-based","hypothesis","quickcheck"],
"Dependency Advisory & CVE Correlation (SCA)":["dependency scan","software composition","osv","snyk","npm audit","pip-audit","cisa kev","nvd","sbom"],
"Configuration, IaC & Policy Analysis":["misconfiguration","terraform","cloudformation","kubernetes","dockerfile","checkov","tfsec","kics","security rules","policy-as-code"],
"Secret, Entropy & Git-History Scanning":["gitleaks","trufflehog","detect-secrets","secret scanning","entropy","git history"],
"Network / Service Enumeration & Active Scanning":["nmap","masscan","port scan","service enumeration","openvas","greenbone","nessus"],
"Log, SIEM & EDR Threat Hunting / Correlation":["siem","splunk","elastic security","sentinel","edr","kql","sigma","sysmon","threat hunting"],
"Runtime Interception, Monitoring & Anomaly Detection":["runtime security","intercept","runtime monitoring","input guard","output monitoring","anomaly detection"],
"Detection-Rule, Signature & Query Authoring":["semgrep rule","codeql query","yara rule","sigma rule","detection rule","signature author"],
"Exploit / PoC Validation, FP Triage & Variant Hunting":["proof of concept","proof-of-concept","poc","false positive","variant analysis","exploitability validation"],
"Binary, Reverse-Engineering & Symbolic Analysis":["reverse engineering","binary analysis","disassembly","decompiler","ghidra","ida pro","radare2","symbolic execution","firmware"],
"Smart-Contract-Specific Static / Dynamic Analysis":["smart contract","solidity","solana program","evm","slither","mythril","echidna","foundry"],
"Manual Source Review / Threat-Model-Guided Audit":["manual review","systematic review","security code review","trace data flow","threat model","checklist"]}

def description_screen(text):
    s=norm(text).lower()
    return any(x in s for x in TOOLS) or any(x in s for x in SUPPORT) or (any(x in s for x in POS_OBJECTS) and any(x in s for x in POS_ACTIONS))
def frontmatter(text):
    if not text.startswith("---"):return {}
    block=text.split("---",2)[1]; out={}; key=""
    for line in block.splitlines():
        m=re.match(r"^([A-Za-z0-9_.:-]+)\s*:\s*(.*)$",line)
        if m:key=m.group(1).lower();out[key]=m.group(2).strip(" >|'\"")
        elif key and line.startswith((" ","\t")):out[key]+=" "+line.strip(" >|-")
    return {k:norm(v) for k,v in out.items()}
def evidence(text):
    lines=text.splitlines(); rx=re.compile(r"vulnerab|security (scan|audit|review|assessment|test)|penetration|pentest|detect|semgrep|codeql|sast|dast|fuzz|gitleaks|yara|sigma|malware|threat hunt|secret|misconfig|cve|cwe|injection|idor|ssrf|proof.of.concept|false positive",re.I)
    for i,l in enumerate(lines):
        if rx.search(l):
            a=max(0,i-1);b=min(len(lines),i+3)
            return f"L{a+1}-L{b}","\n".join(f"L{j+1}: {lines[j].strip()}" for j in range(a,b) if lines[j].strip())[:2000]
    return "L1-L5","\n".join(f"L{i+1}: {l.strip()}" for i,l in enumerate(lines[:5]) if l.strip())[:2000]
def classify(row,res):
    text=res.get("text",""); fm=frontmatter(text); name=fm.get("name") or row.get("name",""); desc=fm.get("description") or row.get("description","")
    headings=" ".join(re.findall(r"(?m)^#{1,4}\s+(.+)$",text)[:20]); lead=f"{name} {desc} {headings}".lower(); full=f"{lead} {text[:60000].lower()}"
    objects=sum(x in full for x in POS_OBJECTS); actions=sum(x in full for x in POS_ACTIONS); tools=[x for x in TOOLS if x in full]; support=[x for x in SUPPORT if x in full]
    strong=bool(tools) or (objects>=1 and actions>=1) or bool(re.search(r"penetration test|pentest|security assessment|security audit|security scan|threat hunt|malware analysis",full))
    exclusion=sum(x in lead for x in EXCLUDE_MAIN); direct_name=bool(re.search(r"vuln|security-(scan|audit|review|test)|pentest|fuzz|semgrep|codeql|yara|sigma|secret-scan|threat-hunt|malware|forensic|sast|dast|scanner|detect",slug(name)))
    if res.get("meta",{}).get("archived") or res.get("meta",{}).get("disabled"):decision="EXCLUDE_INACTIVE";why="Repository is archived or disabled."
    elif strong and (direct_name or objects+actions+len(tools)>=4):
        if exclusion>=2 and not direct_name:decision="INCLUDE_MIXED";why="Concrete detection/assessment is present but combined with hardening, implementation, administration, or remediation."
        else:decision="INCLUDE_DIRECT";why="Source explicitly performs vulnerability discovery, security assessment, scanning, adversarial testing, threat detection, or evidence-based validation."
    elif support and (objects or tools):decision="INCLUDE_SUPPORT";why="Source directly supports detection through rules, queries, finding validation, variant analysis, attack-surface mapping, or vulnerability intelligence."
    else:decision="EXCLUDE_NOT_DETECTION";why="Source review did not establish vulnerability/security detection, assessment, threat detection, or direct detection support as a main function."
    return name,desc,decision,why,full
def primary(full,decision):
    if re.search(r"rule.*author|query.*author|signature.*author|semgrep-rule|yara-author|sigma-rule",full):return "Detection Engineering & Security-Rule Authoring"
    if re.search(r"false positive|variant analysis|finding validation|exploitability validation",full):return "Finding Validation, Triage & Variant Analysis"
    if re.search(r"prompt injection|jailbreak|llm security|agent security|mcp security|openclaw|claude code.*security",full):return "AI, LLM, Agent & MCP Security Assessment"
    if re.search(r"smart contract|solidity|solana program|web3|blockchain|token risk|honeypot",full):return "Smart-Contract & Blockchain Security Assessment"
    if re.search(r"threat hunt|threat detection|malware|forensic|siem|edr|ioc|webshell|cryptomining|lolbin",full):return "Threat Detection, Hunting, Malware & Forensics"
    if re.search(r"mobile|android|ios|apk|firmware|binary|reverse engineering|memory corruption|c/c\+\+|rust.*unsafe",full):return "Mobile, Endpoint, Binary & Firmware Security Assessment"
    if re.search(r"cloud|aws|azure|gcp|terraform|kubernetes|container|docker|iac|firebase security rules|serverless",full):return "Cloud, IaC, Container & Kubernetes Security Assessment"
    if re.search(r"dependency|supply chain|sbom|sca|osv|advisory|cisa kev|npm audit|trivy|grype",full):return "Dependency & Software Supply-Chain Risk Assessment"
    if re.search(r"secret scan|credential leak|gitleaks|trufflehog|detect-secrets|hardcoded secret",full):return "Secrets & Credential Exposure Detection"
    if re.search(r"network scan|nmap|masscan|openvas|greenbone|nessus|port scan|service enumeration",full):return "Network, Host & Infrastructure Vulnerability Assessment"
    if re.search(r"web application|api security|owasp zap|burp|dast|ssrf|idor|xss|csrf|sql injection|request smuggling",full):return "Web/API & Dynamic Penetration Testing"
    if len([m for m,terms in METHODS.items() if any(t in full for t in terms)])>=3:return "Multi-Domain Security Posture Assessment"
    if decision=="INCLUDE_MIXED":return "Mixed Security Detection Capability"
    return "Application & Source-Code Vulnerability Assessment"
def method(full):
    hits={m:sum(t in full for t in terms) for m,terms in METHODS.items()}; active=[m for m,n in hits.items() if n]
    if hits["Detection-Rule, Signature & Query Authoring"]:return "Detection-Rule, Signature & Query Authoring"
    if hits["Exploit / PoC Validation, FP Triage & Variant Hunting"]:return "Exploit / PoC Validation, FP Triage & Variant Hunting"
    if hits["Smart-Contract-Specific Static / Dynamic Analysis"] and (hits["Static Pattern / Query-Based Analysis"] or hits["Fuzzing / Property-Based Testing"]):return "Smart-Contract-Specific Static / Dynamic Analysis"
    if len(active)>=3:return "Multi-Method Security Orchestration"
    for m in METHODS:
        if hits[m]:return m
    return "Manual Source Review / Threat-Model-Guided Audit"
def linked_files(repo,ref,path,text,maxn=8):
    base=path.rsplit("/",1)[0] if "/" in path else ""; out=[]
    for target in re.findall(r"\]\(([^)#?]+)",text):
        if target.startswith(("http:","https:","mailto:","#")):continue
        p="/".join(x for x in (base,target) if x); parts=[]
        for x in p.split("/"):
            if x=="..":
                if parts:parts.pop()
            elif x not in ("","."):parts.append(x)
        p="/".join(parts)
        if p and p not in out:out.append(p)
        if len(out)>=maxn:break
    return [p for p in out if raw_get(raw_url(repo,ref,p))]
def file_created(repo,path):
    r=gh_get(f"https://api.github.com/repos/{repo}/commits",{"path":path,"per_page":100},90)
    if not r or r.status_code!=200:return "",""
    arr=r.json()
    if not isinstance(arr,list) or not arr:return "",""
    last=arr[-1]; date=((last.get("commit") or {}).get("author") or {}).get("date","")
    return date[:10],last.get("html_url","")

rows=read_csv(OUT/"ranked_frame_union.csv"); reviews=[]; source_text_by_key={}
for idx,row in enumerate(rows,1):
    res=resolve_source(row)
    base={**row,"source_status":res.get("status",""),"repo":res.get("repo",""),"source_ref":res.get("ref",""),"source_path":res.get("path",""),"source_sha256":"","source_name":"","source_description":"","final_decision":"UNRESOLVED","decision_rationale":"","primary_functional_category":"","methods_technique_category":"","evidence_range":"","evidence_quote":"","files_reviewed":"","repo_archived":"","repo_disabled":"","repo_stars_verified":"","skill_file_created_date":"","skill_file_creation_commit_url":"","description_screen_retain":description_screen(row.get("description",""))}
    if res.get("status")=="resolved":
        text=res["text"]; base["source_sha256"]=sha(text); name,desc,decision,why,full=classify(row,res)
        base.update({"source_name":name,"source_description":desc,"final_decision":decision,"decision_rationale":why,"repo_archived":bool(res["meta"].get("archived")),"repo_disabled":bool(res["meta"].get("disabled")),"repo_stars_verified":res["meta"].get("stargazers_count","")})
        rng,quote=evidence(text);base["evidence_range"]=rng;base["evidence_quote"]=quote
        if decision.startswith("INCLUDE"):
            base["primary_functional_category"]=primary(full,decision);base["methods_technique_category"]=method(full)
            created,commit=file_created(res["repo"],res["path"]);base["skill_file_created_date"]=created;base["skill_file_creation_commit_url"]=commit
            links=linked_files(res["repo"],res["ref"],res["path"],text);base["files_reviewed"]="; ".join([res["path"]]+links)
        sid=safe(f"{idx:05d}_{res['repo']}_{name}");(SRC/f"{sid}_SKILL.md").write_text(text,encoding="utf-8");source_text_by_key[(res["repo"],res["path"])]=text
        (EVID/f"{sid}.md").write_text("\n".join([f"# {name}",f"- SkillsMP: {row.get('skillsmp_url','')}",f"- GitHub: https://github.com/{res['repo']}",f"- Source: {res['path']}",f"- Decision: {decision}",f"- Why: {why}",f"- Primary category: {base['primary_functional_category']}",f"- Method: {base['methods_technique_category']}",f"- Evidence: {rng}","```text",quote,"```",f"- Files reviewed: {base['files_reviewed']}"]),encoding="utf-8")
    else:base["decision_rationale"]="The advertised GitHub source or actual SKILL.md could not be resolved; it is not promoted to the verified canonical set."
    reviews.append(base)
    if idx%100==0:print(f"reviewed {idx}/{len(rows)}",flush=True)
write_csv(OUT/"source_review_all.csv",reviews)
included=[r for r in reviews if r["final_decision"].startswith("INCLUDE") and str(r["repo_archived"]).lower()!="true" and str(r["repo_disabled"]).lower()!="true"]
parent=list(range(len(included)))
def find(x):
    while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
    return x
def union(a,b):
    a,b=find(a),find(b)
    if a!=b:parent[b]=a
normtext=[]
for r in included:
    t=source_text_by_key.get((r["repo"],r["source_path"]),"");t=re.sub(r"(?s)^---.*?---"," ",t,count=1);normtext.append(re.sub(r"\s+"," ",re.sub(r"[^a-z0-9]+"," ",t.lower())).strip())
byhash=defaultdict(list);byname=defaultdict(list)
for i,t in enumerate(normtext):byhash[sha(t)].append(i);byname[slug(included[i]["source_name"])].append(i)
for ids in byhash.values():
    for j in ids[1:]:union(ids[0],j)
for ids in byname.values():
    if len(ids)>25:continue
    for a in range(len(ids)):
        for b in range(a+1,len(ids)):
            if find(ids[a])==find(ids[b]):continue
            if difflib.SequenceMatcher(None,normtext[ids[a]][:40000],normtext[ids[b]][:40000]).ratio()>=.94:union(ids[a],ids[b])
groups=defaultdict(list)
for i in range(len(included)):groups[find(i)].append(i)
canonical=[];dups=[]
for gid,ids in enumerate(groups.values(),1):
    ids=sorted(ids,key=lambda i:(str(included[i]["repo_archived"]).lower()=="true",included[i]["skill_file_created_date"] or "9999-99-99",-parse_int(included[i]["repo_stars_verified"] or included[i]["stars"])))
    c=included[ids[0]].copy();c["duplicate_group"]=f"SMP-DUP-{gid:04d}" if len(ids)>1 else "";canonical.append(c)
    for j in ids[1:]:
        d=included[j].copy();d["canonical_repo"]=c["repo"];d["canonical_source_path"]=c["source_path"];d["duplicate_reason"]="Exact normalized SKILL.md or same-name source with >=0.94 text similarity.";dups.append(d)
write_csv(OUT/"canonical_skills.csv",canonical);write_csv(OUT/"duplicates_removed.csv",dups);write_csv(OUT/"excluded_unresolved.csv",[r for r in reviews if not r["final_decision"].startswith("INCLUDE")])
false_neg=[r for r in reviews if r["final_decision"].startswith("INCLUDE") and str(r["description_screen_retain"]).lower()!="true"];write_csv(OUT/"description_screen_false_negatives.csv",false_neg)
source_included=sum(r["final_decision"].startswith("INCLUDE") for r in reviews);screen_tp=sum(r["final_decision"].startswith("INCLUDE") and str(r["description_screen_retain"]).lower()=="true" for r in reviews)
occ=read_csv(OUT/"ranked_frame_occurrences.csv");sat=[]
for frame in ("stars","recent"):
    seen=set()
    for page in sorted({int(r["page"]) for r in occ if r["frame"]==frame}):
        pagekeys={r["skillsmp_id"] or r["skillsmp_url"] or r["github_url"] for r in occ if r["frame"]==frame and int(r["page"])==page};new=len(pagekeys-seen);seen|=pagekeys
        sat.append({"frame":frame,"page":page,"returned_unique_on_page":len(pagekeys),"new_unique_on_page":new,"cumulative_unique":len(seen)})
write_csv(OUT/"saturation_by_page.csv",sat)
diag=json.loads((OUT/"frame_diagnostics.json").read_text(encoding="utf-8"));diag.update({"source_records_reviewed":len(reviews),"source_resolved":sum(r["source_status"]=="resolved" for r in reviews),"source_unresolved":sum(r["source_status"]!="resolved" for r in reviews),"included_before_deduplication":len(included),"canonical_after_deduplication":len(canonical),"duplicates_removed":len(dups),"description_screen_true_positives":screen_tp,"description_screen_false_negatives":len(false_neg),"description_screen_empirical_recall":round(screen_tp/max(1,source_included),6)})
(OUT/"scientific_diagnostics.json").write_text(json.dumps(diag,ensure_ascii=False,indent=2),encoding="utf-8")
(OUT/"methodology.md").write_text("""# SkillsMP scientific retrieval design

The collection uses two deterministic ranked frames from the same preregistered category query:

1. **Top-starred frame** — `q=*`, Security category, `sortBy=stars`.
2. **Most-recent frame** — the same query and category, `sortBy=recent`.

The first 25 pages of each frame are requested at 50 records per page. If the `security` subcategory slug is not accepted, the preregistered fallback is the parent `testing-security` slug with 24 pages per frame, preserving the anonymous 50-request budget.

Every unique result in the ranked union is source-resolved and reviewed. The broad description screen is evaluated diagnostically against source review; it does not determine which ranked-frame records receive source review. Exact/near-copy deduplication is applied only after source review.

This is a reproducible, rank-defined multi-frame coverage study. It is not a probability sample, not a random sample, and not a complete census of the full SkillsMP Security category. GitHub stars are repository-level popularity, not skill-level usage.
""",encoding="utf-8")
print(json.dumps(diag,ensure_ascii=False,indent=2))
