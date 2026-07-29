from __future__ import annotations
import json, os, re, subprocess, shutil, hashlib, difflib, unicodedata
from pathlib import Path

ROOT=Path('mismatch_resolution_output'); ROOT.mkdir(exist_ok=True)
SRC=ROOT/'source'; SRC.mkdir(exist_ok=True)
EVD=ROOT/'evidence'; EVD.mkdir(exist_ok=True)
manifest=[]
for _p in sorted(Path('.').glob('mismatch_manifest_part_*.json')):
    manifest.extend(json.load(open(_p,encoding='utf-8')))

def sh(cmd,cwd=None,timeout=300):
    p=subprocess.run(cmd,cwd=cwd,text=True,capture_output=True,timeout=timeout)
    return p.returncode,p.stdout,p.stderr

def norm(s):
    s=unicodedata.normalize('NFKD',s or '').encode('ascii','ignore').decode().lower()
    s=re.sub(r'%3a',':',s); s=re.sub(r'%20',' ',s)
    return re.sub(r'[^a-z0-9]+','',s)

def parse_fm(txt):
    m=re.match(r'^\ufeff?---\s*\n(.*?)\n---\s*\n',txt,re.S)
    if not m:return {},''
    block=m.group(1)
    out={}
    for key in ('name','description'):
        mm=re.search(rf'(?mi)^{key}:\s*(.*)$',block)
        if mm:
            val=mm.group(1).strip().strip('"\'')
            if val in ('>-','>','|-','|'):
                rest=block[mm.end():].splitlines(); vals=[]
                for line in rest:
                    if re.match(r'^\S',line):break
                    vals.append(line.strip())
                val=' '.join(vals)
            out[key]=re.sub(r'\s+',' ',val).strip()
    return out,block

def toks(s):
    return set(re.findall(r'[a-z0-9]{3,}',(s or '').lower()))

def score_candidate(rec,path,txt):
    fm,_=parse_fm(txt); req=rec['skill_name']; slug=rec.get('skill_slug') or req
    parent=path.parent.name; stem=path.parent.name if path.name.lower()=='skill.md' else path.stem
    names=[fm.get('name',''),parent,stem,str(path)]
    nr=norm(req); ns=norm(slug)
    sc=0; reasons=[]
    for label,nm in [('frontmatter',names[0]),('parent',names[1]),('path',names[3])]:
        nn=norm(nm)
        if nn and nn in {nr,ns}:
            pts=120 if label=='frontmatter' else 100 if label=='parent' else 80
            sc+=pts; reasons.append(f'{label}-exact')
        elif nn and (nr in nn or nn in nr or ns in nn or nn in ns):
            pts=45 if label=='frontmatter' else 30
            sc+=pts; reasons.append(f'{label}-contains')
        elif nn:
            sim=max(difflib.SequenceMatcher(None,nr,nn).ratio(),difflib.SequenceMatcher(None,ns,nn).ratio())
            if sim>=.78:sc+=int(25*sim);reasons.append(f'{label}-similar:{sim:.2f}')
    mdesc=rec.get('marketplace_description',''); fdesc=fm.get('description','')
    a,b=toks(mdesc),toks(fdesc)
    if a and b:
        jac=len(a&b)/max(1,len(a|b)); contain=len(a&b)/max(1,min(len(a),len(b)))
        sc+=int(90*jac+35*contain)
        if jac>.15 or contain>.35:reasons.append(f'desc-overlap:{jac:.2f}/{contain:.2f}')
    body=txt[:15000].lower(); unique=[x for x in a if len(x)>5]
    hit=sum(1 for x in unique if x in body)
    if unique:sc+=min(30,int(30*hit/len(unique)))
    return sc,reasons,fm

def creation(repo_dir,path):
    rc,out,err=sh(['git','log','--follow','--diff-filter=A','--format=%H|%aI','--',str(path)],cwd=repo_dir,timeout=180)
    lines=[x for x in out.splitlines() if '|' in x]
    if not lines:return '', ''
    sha,date=lines[-1].split('|',1); return sha,date

byrepo={}
for rec in manifest:byrepo.setdefault(rec['verified_repo'],[]).append(rec)
results=[]
for idx,(repo,recs) in enumerate(byrepo.items(),1):
    print(f'[{idx}/{len(byrepo)}] {repo}',flush=True)
    repo_dir=Path('_repos')/(repo.replace('/','__'))
    repo_dir.parent.mkdir(exist_ok=True)
    rc,out,err=sh(['git','clone','--filter=blob:none','--no-tags','https://github.com/'+repo+'.git',str(repo_dir)],timeout=600)
    if rc:
        for rec in recs:results.append({**rec,'resolution_status':'repo_clone_failed','error':err[-1000:]})
        continue
    paths=[p for p in repo_dir.rglob('*') if p.is_file() and p.name.lower()=='skill.md' and '.git' not in p.parts]
    candidates=[]
    for p in paths:
        try:txt=p.read_text(encoding='utf-8',errors='replace')
        except:continue
        candidates.append((p.relative_to(repo_dir),txt))
    for rec in recs:
        scored=[]
        for path,txt in candidates:
            sc,reasons,fm=score_candidate(rec,path,txt)
            scored.append((sc,path,txt,reasons,fm))
        scored.sort(key=lambda x:(-x[0],str(x[1])))
        best=scored[0] if scored else None; second=scored[1] if len(scored)>1 else None
        accept=bool(best and best[0]>=70 and (not second or best[0]-second[0]>=12 or best[0]>=120))
        if not accept:
            req=norm(rec['skill_name']); hist=[]
            rc2,ls,_=sh(['git','log','--all','--name-only','--pretty=format:%H'],cwd=repo_dir,timeout=300)
            current=''
            for line in ls.splitlines():
                if re.fullmatch(r'[0-9a-f]{40}',line):current=line
                elif line.lower().endswith('skill.md') and req and (req in norm(line) or norm(Path(line).parent.name) in req):
                    hist.append((current,line))
            for commit,pathstr in hist[:50]:
                rc3,txt,_=sh(['git','show',f'{commit}:{pathstr}'],cwd=repo_dir,timeout=90)
                if rc3==0:
                    sc,reasons,fm=score_candidate(rec,Path(pathstr),txt)
                    scored.append((sc,Path(pathstr),txt,reasons+['history'],fm))
            scored.sort(key=lambda x:(-x[0],str(x[1])))
            best=scored[0] if scored else None; second=scored[1] if len(scored)>1 else None
            accept=bool(best and best[0]>=70 and (not second or best[0]-second[0]>=12 or best[0]>=120))
        if not accept:
            top=[{'score':s,'path':str(p),'reasons':rs,'frontmatter_name':fm.get('name',''),'description':fm.get('description','')[:300]} for s,p,t,rs,fm in scored[:8]]
            results.append({**rec,'resolution_status':'unresolved_no_confident_match','top_candidates':top})
            continue
        sc,path,txt,reasons,fm=best
        safe=hashlib.sha1((repo+'::'+rec['skill_name']).encode()).hexdigest()[:16]
        od=SRC/safe;od.mkdir(exist_ok=True)
        (od/'SKILL.md').write_text(txt,encoding='utf-8')
        commit,date=creation(repo_dir,path)
        result={**rec,'resolution_status':'resolved','resolved_skill_file_path':str(path),'resolved_frontmatter_name':fm.get('name',''),
                'resolved_description':fm.get('description',''),'resolution_score':sc,'resolution_reasons':reasons,
                'skill_file_sha256':hashlib.sha256(txt.encode()).hexdigest(),'skill_file_created_commit_sha':commit,
                'skill_file_created_commit_url':f'https://github.com/{repo}/commit/{commit}' if commit else '',
                'skill_file_created_date':date,'source_dir':str(od)}
        (EVD/(safe+'.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        results.append(result)
    shutil.rmtree(repo_dir,ignore_errors=True)

with open(ROOT/'resolution_results.jsonl','w',encoding='utf-8') as f:
    for r in results:f.write(json.dumps(r,ensure_ascii=False)+'\n')
import csv
keys=[]
for r in results:
    for k in r:
        if k not in keys and k not in ('top_candidates',):keys.append(k)
with open(ROOT/'resolution_results.csv','w',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=keys);w.writeheader()
    for r in results:
        x={k:r.get(k,'') for k in keys}
        for k,v in x.items():
            if isinstance(v,(dict,list)):x[k]=json.dumps(v,ensure_ascii=False)
        w.writerow(x)
summary={}
for r in results:summary[r['resolution_status']]=summary.get(r['resolution_status'],0)+1
(ROOT/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
print(summary)
