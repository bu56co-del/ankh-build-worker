#!/usr/bin/env python3
"""Create the one deterministic manifest-plus-four-binary release bundle."""
import argparse,hashlib,json,os,re,zipfile
from pathlib import Path
NAMES=('ankh-opener-daemon.exe','ankh-pet.exe','ankh-opener-daemon','ankh-pet')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def canon(x): return (json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode()
p=argparse.ArgumentParser(); p.add_argument('--request',required=True); p.add_argument('--windows',required=True); p.add_argument('--macos',required=True); p.add_argument('--public-commit',required=True); p.add_argument('--run-id',required=True); p.add_argument('--run-attempt',required=True); p.add_argument('--output',required=True); a=p.parse_args()
r=json.loads(Path(a.request).read_text());
if not re.fullmatch('[0-9a-f]{40}',a.public_commit): raise SystemExit('[ERROR] invalid public commit')
roots=[Path(a.windows),Path(a.windows),Path(a.macos),Path(a.macos)]; paths=[roots[i]/NAMES[i] for i in range(4)]
if any(not q.is_file() or q.is_symlink() for q in paths): raise SystemExit('[ERROR] exact binary set is missing')
manifest={'schema':2,'build_id':r['build_id'],'private_source_commit':r['private_source_commit'],'public_source_commit':a.public_commit,'public_ref':'refs/heads/request/'+r['build_id'],'worker_commit':r['worker_commit'],'workflow_sha256':r['workflow_sha256'],'toolchain':r['toolchain'],'semantic_version':r['semantic_version'],'workflow_run_id':int(a.run_id),'workflow_run_attempt':int(a.run_attempt),'files':[{'name':q.name,'size':q.stat().st_size,'sha256':sha(q)} for q in paths]}
out=Path(a.output); temp=out.with_suffix(out.suffix+'.tmp')
with zipfile.ZipFile(temp,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for name,data,mode in [('BUILD_MANIFEST.json',canon(manifest),0o644)]+[(q.name,q.read_bytes(),0o755 if not q.name.endswith('.exe') else 0o644) for q in paths]:
  i=zipfile.ZipInfo(name,(1980,1,1,0,0,0)); i.create_system=3; i.external_attr=((0o100000|mode)&0xffff)<<16; i.compress_type=zipfile.ZIP_DEFLATED; z.writestr(i,data)
os.replace(temp,out); print(json.dumps(manifest,sort_keys=True))
