#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import time
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import requests

INPUT = Path('input')
OUT = Path('skillsmp_enhanced_output')
SUPPORT = OUT / 'supporting_files'
EVIDENCE = OUT / 'implementation_evidence'
OUT.mkdir(exist_ok=True)
SUPPORT.mkdir(exist_ok=True)
EVIDENCE.mkdir(exist_ok=True)
TOKEN = os.environ.get('GITHUB_TOKEN','')
HEADERS = {
    'Accept':'application/vnd.github+json',
    'X-GitHub-Api-Version':'2022-11-28',
    'User-Agent':'skillsmp-implementation-evidence/1.0',
}
if TOKEN: HEADERS['Authorization'] = f'Bearer {TOKEN}'
RAW_HEADERS = {'User-Agent':'skillsmp-implementation-evidence/1.0'}
session = requests.Session()
repo_meta_cache: dict[str,dict] = {}
tree_cache: dict[tuple[str,str],list[str]] = {}
raw_cache: dict[tuple[str,str,str],str] = {}

TEXT_EXT = {'.md','.txt','.py','.js','.jsx','.ts','.tsx','.sh','.bash','.zsh','.ps1','.go','.rs','.java','.kt','.rb','.php','.cs','.c','.cc','.cpp','.h','.hpp','.swift','.sol','.move','.ql','.qll','.yaml','.yml','.json','.toml','.ini','.cfg','.conf','.rules','.semgrep','.rego'}
EXCLUDE_PARTS = {'node_modules','vendor','dist','build','coverage','.git','target','__pycache__','.venv','venv','fixtures','snapshots'}
SEC_RX = re.compile(r'vulnerab|security|exploit|attack|threat|malware|secret|credential|cve|cwe|injection|xss|ssrf|csrf|idor|bola|privilege|auth(?:entication|orization)|taint|data.?flow|semgrep|codeql|sast|dast|fuzz|gitleaks|trufflehog|yara|sigma|nuclei|zap|burp|nessus|openvas|checkov|tfsec|kics|trivy|grype|bandit|gosec|slither|mythril|echidna|sanitize|finding|severity|risk|misconfig|phishing|jailbreak|prompt injection|exfiltration', re.I)
CODE_RX = re.compile(r'(^|\s)(def |class |function |const |let |var |fn |func |pub fn |package |import |from |use |SELECT |MATCH |rules:|pattern:|patterns:|sources:|sinks:|severity:|id:)', re.I)


def read_csv(path: Path) -> list[dict[str,str]]:
    with path.open(encoding='utf-8-sig',newline='') as f:
        return list(csv.DictReader(f))

def write_csv(path: Path, rows: list[dict[str,Any]], fields: list[str]|None=None) -> None:
    if fields is None:
        fields=[]; seen=set()
        for r in rows:
            for k in r:
                if k not in seen: seen.add(k); fields.append(k)
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader()
        for r in rows:
            w.writerow({k:(json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v) for k,v in r.items()})

def norm(s: Any) -> str:
    return re.sub(r'\s+',' ',str(s or '')).strip()

def safe(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]+','_',s)[:180]

def sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8','ignore')).hexdigest()

def request(url: str, *, params=None, raw=False, timeout=60) -> requests.Response|None:
    headers=RAW_HEADERS if raw else HEADERS
    for i in range(5):
        try:
            r=session.get(url,headers=headers,params=params,timeout=timeout)
            if r.status_code==200:return r
            if r.status_code in (403,429,500,502,503,504):
                time.sleep(5*(i+1)); continue
            return r
        except Exception:
            time.sleep(5*(i+1))
    return None

def repo_meta(repo: str) -> dict:
    if repo not in repo_meta_cache:
        r=request(f'https://api.github.com/repos/{repo}')
        repo_meta_cache[repo]=r.json() if r and r.status_code==200 else {}
    return repo_meta_cache[repo]

def repo_tree(repo: str, ref: str) -> list[str]:
    key=(repo,ref)
    if key not in tree_cache:
        r=request(f'https://api.github.com/repos/{repo}/git/trees/{quote(ref,safe="")}',params={'recursive':'1'},timeout=120)
        data=r.json().get('tree',[]) if r and r.status_code==200 else []
        tree_cache[key]=[x.get('path','') for x in data if x.get('type')=='blob']
    return tree_cache[key]

def raw_text(repo: str, ref: str, path: str) -> str:
    key=(repo,ref,path)
    if key in raw_cache:return raw_cache[key]
    url=f'https://raw.githubusercontent.com/{repo}/{quote(ref,safe="")}/{quote(path,safe="/")}'
    r=request(url,raw=True,timeout=60)
    text=''
    if r and r.status_code==200:
        try:
            content=r.content[:250000]
            if b'\x00' not in content:
                text=content.decode('utf-8','replace')
        except Exception:
            text=''
    raw_cache[key]=text
    return text

def source_index() -> dict[str,tuple[Path,str]]:
    idx={}
    for p in INPUT.rglob('*SKILL.md'):
        if p.is_file():
            try:t=p.read_text(encoding='utf-8',errors='replace')
            except:continue
            idx[sha(t)]=(p,t)
    return idx

def resolve_relative(base: str, target: str) -> str:
    target=target.split('#',1)[0].split('?',1)[0]
    if not target or re.match(r'^[a-z]+:',target,re.I) or target.startswith('#'):return ''
    parts=[]
    base_dir=PurePosixPath(base).parent
    for part in (base_dir / target).parts:
        if part in ('','.'):continue
        if part=='..':
            if parts:parts.pop()
        else:parts.append(part)
    return '/'.join(parts)

def linked_paths(skill_path: str, skill_text: str) -> list[str]:
    out=[]
    for target in re.findall(r'\]\(([^)]+)\)',skill_text):
        p=resolve_relative(skill_path,target.strip())
        if p and p not in out:out.append(p)
    for target in re.findall(r'`([^`]+\.(?:py|js|ts|sh|go|rs|java|rb|sol|ql|yaml|yml|json|md|rego))`',skill_text,re.I):
        p=resolve_relative(skill_path,target.strip())
        if p and p not in out:out.append(p)
    return out

def relevant_sibling_paths(repo: str, ref: str, skill_path: str) -> list[str]:
    base=str(PurePosixPath(skill_path).parent)
    base_parts=base.count('/')
    out=[]
    for p in repo_tree(repo,ref):
        pp=PurePosixPath(p)
        if not (p==base or p.startswith(base+'/')):continue
        if p.lower().endswith('/skill.md') or p.lower()=='skill.md':continue
        if any(x in EXCLUDE_PARTS for x in pp.parts):continue
        if pp.suffix.lower() not in TEXT_EXT:continue
        if p.count('/')>base_parts+4:continue
        priority=0
        lower=p.lower()
        if any(seg in lower for seg in ('/scripts/','/rules/','/queries/','/workflows/','/references/','/prompts/','/config','/tests/')):priority+=30
        if pp.suffix.lower() in {'.py','.js','.ts','.sh','.go','.rs','.ql','.qll','.semgrep','.yml','.yaml','.rego','.sol'}:priority+=20
        if any(x in lower for x in ('security','scan','audit','detect','vuln','rule','query','taint','fuzz','secret','exploit','finding')):priority+=20
        out.append((priority,-p.count('/'),p))
    out.sort(reverse=True)
    return [p for _,__,p in out]

def evidence_from_files(files: list[tuple[str,str]]) -> tuple[str,int]:
    excerpts=[]; code_files=0
    for path,text in files:
        lines=text.splitlines()
        file_has_code=any(CODE_RX.search(l) for l in lines[:300])
        if file_has_code:code_files+=1
        hits=[]
        for i,line in enumerate(lines):
            if SEC_RX.search(line) and (file_has_code or CODE_RX.search(line) or path.lower().endswith(('.md','.txt'))):
                a=max(0,i-1); b=min(len(lines),i+2)
                snippet='\n'.join(f'{path}:L{j+1}: {lines[j].strip()}' for j in range(a,b) if lines[j].strip())
                if snippet and snippet not in hits:hits.append(snippet)
            if len(hits)>=3:break
        excerpts.extend(hits)
        if len(excerpts)>=18:break
    return '\n\n'.join(excerpts)[:24000],code_files

reviews=read_csv(INPUT/'source_review_all.csv')
canonical=read_csv(INPUT/'canonical_skills.csv')
idx=source_index()
updated=[]
all_file_index=[]
for n,row in enumerate(reviews,1):
    r=dict(row)
    repo=r.get('repo',''); ref=r.get('source_ref','') or (repo_meta(repo).get('default_branch') if repo else '') or 'main'; path=r.get('source_path','')
    skill_text=idx.get(r.get('source_sha256',''),(None,''))[1]
    reviewed=[]
    if repo and path and r.get('source_status')=='resolved' and skill_text:
        link_candidates=linked_paths(path,skill_text)
        sibling_candidates=relevant_sibling_paths(repo,ref,path)
        ordered=[]
        for p in link_candidates+sibling_candidates:
            if p and p not in ordered:ordered.append(p)
        max_files=10 if r.get('final_decision','').startswith('INCLUDE') else 3
        record_dir=SUPPORT/safe(f'{n:05d}_{repo}_{r.get("source_name") or r.get("name")}')
        record_dir.mkdir(parents=True,exist_ok=True)
        for p in ordered:
            if len(reviewed)>=max_files:break
            text=raw_text(repo,ref,p)
            if not text:continue
            reviewed.append((p,text))
            dest=record_dir/safe(p.replace('/','__'))
            dest.write_text(text,encoding='utf-8')
            all_file_index.append({'skillsmp_id':r.get('skillsmp_id',''),'repo':repo,'skill_source_path':path,'supporting_path':p,'local_path':str(dest),'sha256':sha(text),'chars':len(text)})
    impl,code_count=evidence_from_files(reviewed)
    existing=norm(r.get('files_reviewed',''))
    all_reviewed=[path] if path else []
    all_reviewed += [p for p,_ in reviewed]
    if existing:
        for p in existing.split(';'):
            p=p.strip()
            if p and p not in all_reviewed:all_reviewed.append(p)
    r['files_reviewed']='; '.join(all_reviewed)
    r['supporting_files_materialized']=len(reviewed)
    r['supporting_code_files_reviewed']=code_count
    r['implementation_review_depth']=('SKILL.md + adjacent implementation/rule/config/reference files' if reviewed else 'SKILL.md only; no retrievable adjacent text files selected')
    r['implementation_evidence']=impl
    r['implementation_evidence_status']='evidence_found' if impl else ('supporting_files_reviewed_no_security_excerpt' if reviewed else 'no_supporting_files')
    evidence_file=EVIDENCE/f'{n:05d}_{safe(repo)}_{safe(r.get("source_name") or r.get("name",""))}.md'
    evidence_file.write_text('\n'.join([
        f'# {r.get("source_name") or r.get("name","")}',
        f'- Repository: https://github.com/{repo}',
        f'- SKILL.md: {path}',
        f'- Final decision: {r.get("final_decision","")}',
        f'- Implementation review depth: {r["implementation_review_depth"]}',
        f'- Supporting files materialized: {len(reviewed)}',
        f'- Supporting code files reviewed: {code_count}',
        f'- Files reviewed: {r["files_reviewed"]}',
        '', '## Implementation evidence', '', '```text', impl or 'No additional security-relevant implementation excerpt was found in selected adjacent files.', '```'
    ]),encoding='utf-8')
    r['implementation_evidence_file']=str(evidence_file)
    updated.append(r)
    if n%100==0:print(f'enhanced {n}/{len(reviews)}',flush=True)

by_key={(r.get('repo',''),r.get('source_path','')):r for r in updated}
canonical_updated=[]
for r in canonical:
    x=dict(r); e=by_key.get((r.get('repo',''),r.get('source_path','')))
    if e:
        for k in ('files_reviewed','supporting_files_materialized','supporting_code_files_reviewed','implementation_review_depth','implementation_evidence','implementation_evidence_status','implementation_evidence_file'):
            x[k]=e.get(k,'')
    canonical_updated.append(x)

for p in INPUT.rglob('*'):
    if p.is_file():
        rel=p.relative_to(INPUT); dest=OUT/rel; dest.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(p,dest)
write_csv(OUT/'source_review_all.csv',updated)
write_csv(OUT/'canonical_skills.csv',canonical_updated)
write_csv(OUT/'supporting_file_index.csv',all_file_index)
diag=json.loads((INPUT/'scientific_diagnostics.json').read_text(encoding='utf-8'))
diag.update({
    'implementation_records_reviewed':len(updated),
    'records_with_supporting_files':sum(int(r.get('supporting_files_materialized') or 0)>0 for r in updated),
    'supporting_files_materialized':sum(int(r.get('supporting_files_materialized') or 0) for r in updated),
    'supporting_code_files_reviewed':sum(int(r.get('supporting_code_files_reviewed') or 0) for r in updated),
    'records_with_implementation_evidence':sum(bool(r.get('implementation_evidence')) for r in updated),
})
(OUT/'scientific_diagnostics.json').write_text(json.dumps(diag,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(diag,ensure_ascii=False,indent=2))
