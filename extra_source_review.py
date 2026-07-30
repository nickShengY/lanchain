from __future__ import annotations
import base64,csv,json,os,re,time,unicodedata,urllib.error,urllib.parse,urllib.request,hashlib
from pathlib import Path

MANIFEST=Path('extra_source_manifest.json')
OUT=Path('extra_source_review_output');OUT.mkdir(exist_ok=True)
SRC=OUT/'source';SRC.mkdir(exist_ok=True)
EVD=OUT/'evidence';EVD.mkdir(exist_ok=True)
TOKEN=os.environ.get('GITHUB_TOKEN','')

def api(url,retries=4):
 h={'Accept':'application/vnd.github+json','User-Agent':'security-skill-extra-review/2026-07-29','X-GitHub-Api-Version':'2022-11-28'}
 if TOKEN:h['Authorization']=f'Bearer {TOKEN}'
 err=''
 for a in range(retries):
  try:
   with urllib.request.urlopen(urllib.request.Request(url,headers=h),timeout=90) as r:return r.status,json.loads(r.read().decode()),dict(r.headers),''
  except urllib.error.HTTPError as e:
   err=f'HTTP {e.code}: '+e.read().decode(errors='replace')[:500]
   if e.code in (403,429,500,502,503,504):time.sleep(2**a);continue
   return e.code,None,{},err
  except Exception as e:err=repr(e);time.sleep(2**a)
 return 0,None,{},err

def norm(s):
 s=unicodedata.normalize('NFKD',str(s or '')).encode('ascii','ignore').decode().lower()
 return re.sub(r'[^a-z0-9]+','',s)
def toks(s):return set(re.findall(r'[a-z0-9]{3,}',str(s or '').lower()))
def frontmatter(txt):
 m=re.match(r'^\ufeff?---\s*\n(.*?)\n---\s*\n',txt,re.S)
 if not m:return {}
 b=m.group(1);o={}
 for k in ('name','description'):
  mm=re.search(rf'(?mi)^{k}:\s*(.*)$',b)
  if mm:
   v=mm.group(1).strip().strip('"\'')
   if v in ('>','>-','|','|-'):
    vv=[]
    for line in b[mm.end():].splitlines():
     if re.match(r'^\S',line):break
     vv.append(line.strip())
    v=' '.join(vv)
   o[k]=re.sub(r'\s+',' ',v).strip()
 return o

def get_content(repo,path,ref):
 u=f'https://api.github.com/repos/{repo}/contents/{urllib.parse.quote(path,safe="/")}?ref={urllib.parse.quote(ref,safe="")}'
 st,d,h,e=api(u)
 if st==200 and isinstance(d,dict) and d.get('content'):
  return base64.b64decode(d['content']).decode('utf-8',errors='replace'),d,''
 return None,d,e or f'HTTP {st}'

def get_tree(repo,ref):
 u=f'https://api.github.com/repos/{repo}/git/trees/{urllib.parse.quote(ref,safe="")}?recursive=1'
 st,d,h,e=api(u)
 if st==200 and isinstance(d,dict):return [x['path'] for x in d.get('tree',[]) if x.get('type')=='blob'],''
 return [],e or f'HTTP {st}'

def score(rec,path,txt):
 fm=frontmatter(txt);n=norm(rec['skill_name']);p=norm(Path(path).parent.name);fn=norm(fm.get('name'))
 sc=0;why=[]
 if fn==n:sc+=150;why.append('frontmatter exact')
 elif fn and (n in fn or fn in n):sc+=70;why.append('frontmatter contains')
 if p==n:sc+=120;why.append('parent exact')
 elif p and (n in p or p in n):sc+=50;why.append('parent contains')
 if n and n in norm(path):sc+=50;why.append('path contains')
 a=toks(rec.get('marketplace_description'));b=toks(fm.get('description')+' '+txt[:12000])
 if a and b:
  contain=len(a&b)/max(1,min(len(a),len(b)));jac=len(a&b)/max(1,len(a|b));sc+=int(80*contain+80*jac)
  why.append(f'text overlap {contain:.2f}/{jac:.2f}')
 return sc,why,fm

def resolve(rec,meta):
 ref=rec.get('ref') or meta.get('default_branch') or 'main';hint=(rec.get('path_hint') or '').strip('/')
 tries=[]
 if hint:
  if hint.lower().endswith('.md'):tries.append(hint)
  else:tries += [hint+'/SKILL.md',hint+'/skill.md']
 for path in tries:
  txt,obj,err=get_content(rec['repo'],path,ref)
  if txt is not None:return path,txt,ref,['exact path hint'],frontmatter(txt)
 paths,err=get_tree(rec['repo'],ref)
 cands=[]
 for p in paths:
  if not p.lower().endswith('/skill.md') and p.lower()!='skill.md':continue
  pn=norm(Path(p).parent.name);n=norm(rec['skill_name'])
  if not (n in norm(p) or pn in n or n in pn):continue
  txt,obj,e=get_content(rec['repo'],p,ref)
  if txt is None:continue
  sc,why,fm=score(rec,p,txt);cands.append((sc,p,txt,why,fm))
 cands.sort(key=lambda x:(-x[0],x[1]))
 if cands and cands[0][0]>=80:
  sc,p,txt,why,fm=cands[0];return p,txt,ref,why+[f'score={sc}'],fm
 return '',None,ref,[err or 'no confident SKILL.md match'],{}

def history(repo,path):
 current=path;chain=[];earliest=None
 for _ in range(10):
  last=[]
  for page in range(1,51):
   u=f'https://api.github.com/repos/{repo}/commits?path={urllib.parse.quote(current,safe="")}&per_page=100&page={page}'
   st,d,h,e=api(u)
   if st!=200 or not isinstance(d,list):return {},chain,e or f'HTTP {st}'
   if not d:break
   last=d
   if len(d)<100:break
  if not last:break
  earliest=last[-1];sha=earliest['sha']
  st,detail,h,e=api(f'https://api.github.com/repos/{repo}/commits/{sha}')
  prev='';status=''
  if st==200:
   for f in detail.get('files',[]) or []:
    if str(f.get('filename','')).lower()==current.lower():status=f.get('status','');prev=f.get('previous_filename','') or '';break
  if status=='renamed' and prev:chain.append({'sha':sha,'new':current,'old':prev});current=prev;continue
  break
 if not earliest:return {},chain,'history not found'
 co=earliest.get('commit',{});date=(co.get('author') or {}).get('date') or (co.get('committer') or {}).get('date') or ''
 return {'skill_file_created_date':date,'skill_file_created_commit_sha':earliest.get('sha',''),'skill_file_created_commit_url':earliest.get('html_url',''),'original_path_followed':current},chain,''

def snippets(txt,limit=8):
 pats=re.compile(r'(?i)(vulnerab|security|scan|audit|test|detect|finding|semgrep|codeql|trivy|fuzz|penetration|threat|secret|misconfig|taint|owasp)')
 out=[]
 for i,line in enumerate(txt.splitlines(),1):
  if pats.search(line) and line.strip():out.append({'line':i,'text':line.strip()[:500]})
  if len(out)>=limit:break
 return out

def main():
 recs=json.load(open(MANIFEST));results=[];cache={}
 for idx,r in enumerate(recs,1):
  print(f'[{idx}/{len(recs)}] {r["repo"]} {r["skill_name"]}',flush=True)
  repo=r['repo']
  if repo not in cache:
   st,m,h,e=api(f'https://api.github.com/repos/{repo}')
   cache[repo]=m if st==200 and isinstance(m,dict) else {'_error':e or f'HTTP {st}'}
  m=cache[repo]
  path,txt,ref,why,fm=resolve(r,m)
  base={**r,'github_url':m.get('html_url',f'https://github.com/{repo}'),'github_stars':m.get('stargazers_count'),'repo_archived':m.get('archived'),'repo_fork':m.get('fork'),'repo_created_at':m.get('created_at'),'repo_pushed_at':m.get('pushed_at'),'default_branch':m.get('default_branch'),'resolved_ref':ref,'resolution_reasons':why}
  if txt is None:
   base.update({'status':'unresolved','skill_file_path':'','error':'; '.join(why)});results.append(base);continue
  hist,chain,herr=history(repo,path)
  key=hashlib.sha1((repo+'::'+path).encode()).hexdigest()[:16];od=SRC/key;od.mkdir(exist_ok=True)
  (od/'SKILL.md').write_text(txt,encoding='utf-8')
  files=[path]
  directory=str(Path(path).parent);st,listing,h,e=api(f'https://api.github.com/repos/{repo}/contents/{urllib.parse.quote(directory,safe="/")}?ref={urllib.parse.quote(ref,safe="")}')
  if st==200 and isinstance(listing,list):
   for item in listing:
    if len(files)>=13:break
    if item.get('type')!='file' or item.get('path')==path:continue
    if not re.search(r'\.(md|py|js|ts|tsx|jsx|json|ya?ml|toml|sh)$',item.get('name',''),re.I):continue
    atxt,aobj,aerr=get_content(repo,item['path'],ref)
    if atxt is None:continue
    (od/('adjacent__'+item['name'])).write_text(atxt,encoding='utf-8');files.append(item['path'])
  base.update({'status':'reviewed','skill_file_path':path,'frontmatter':fm,'description_source':fm.get('description',''),'skill_file_sha256':hashlib.sha256(txt.encode()).hexdigest(),'skill_chars':len(txt),'files_reviewed':files,'source_evidence_snippets':snippets(txt),'local_source_dir':str(od),'rename_chain':chain,'history_error':herr,**hist})
  (EVD/(key+'.json')).write_text(json.dumps(base,ensure_ascii=False,indent=2),encoding='utf-8')
  results.append(base)
 with (OUT/'extra_source_reviews.jsonl').open('w',encoding='utf-8') as f:
  for r in results:f.write(json.dumps(r,ensure_ascii=False)+'\n')
 keys=[]
 for r in results:
  for k in r:
   if k not in keys:keys.append(k)
 with (OUT/'extra_source_reviews.csv').open('w',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=keys);w.writeheader()
  for r in results:
   x={k:(json.dumps(r.get(k),ensure_ascii=False) if isinstance(r.get(k),(dict,list)) else r.get(k,'')) for k in keys};w.writerow(x)
 summary={'total':len(results),'reviewed':sum(r['status']=='reviewed' for r in results),'unresolved':sum(r['status']!='reviewed' for r in results)}
 (OUT/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8');print(summary)
if __name__=='__main__':main()
