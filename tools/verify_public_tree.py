#!/usr/bin/env python3
"""Fail closed unless the public checkout is the static factory plus reviewed Rust inputs."""
import hashlib,json,re,stat,subprocess
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
STATIC={'.github/workflows/build.yml','.gitignore','README.md','rust-toolchain.toml','tools/package_bundle.py','tools/verify_public_tree.py'}
ROOT_SOURCE={'daemon/Cargo.toml','daemon/Cargo.lock','pet/Cargo.toml','pet/Cargo.lock','BUILD_REQUEST.json'}
PREFIX=('daemon/src/','pet/src/')
SECRET=re.compile(rb'github_' rb'pat_|gh[pousr]_[A-Za-z0-9_]{20,}|BEGIN [A-Z ]*PRIVATE' rb' KEY|client_' rb'secret|refresh_' rb'token|access_' rb'token|api[_-]?' rb'key|pass' rb'word\s*[:=]\s*[^\s]+',re.I)
PRIVATE=re.compile(rb'(?:https?://)?(?:[a-z0-9-]+\.)+(?:loc' rb'al|intern' rb'al)(?:[/:]|$)|/Us' rb'ers/[^/\s]+/|/ho' rb'me/[^/\s]+/|[A-Za-z]:\\Us' rb'ers\\[^\\\s]+\\',re.I)
def die(m): raise SystemExit('[ERROR] '+m)
raw=subprocess.run(['git','-C',str(ROOT),'ls-tree','-rz','--full-tree','HEAD'],capture_output=True,check=True).stdout
seen=[]
for item in raw.split(b'\0'):
 if not item: continue
 meta,name=item.split(b'\t',1); mode,kind,_=meta.split(); rel=name.decode(); seen.append(rel)
 p=PurePosixPath(rel)
 if p.is_absolute() or '..' in p.parts or '\\' in rel or (rel!='.gitignore' and any(x.startswith('.') for x in p.parts if x!='.github')): die('unsafe or hidden path: '+rel)
 if SECRET.search(name) or PRIVATE.search(name): die('forbidden public path: '+rel)
 if kind!=b'blob' or mode==b'120000' or (ROOT/rel).is_symlink(): die('symlink or non-file forbidden: '+rel)
 if rel not in STATIC|ROOT_SOURCE and not rel.startswith(PREFIX): die('path outside public allowlist: '+rel)
 data=(ROOT/rel).read_bytes()
 if len(data)>10*1024*1024: die('oversized public file: '+rel)
 if SECRET.search(data) or PRIVATE.search(data): die('forbidden content: '+rel)
if len(seen)!=len(set(seen)): die('duplicate tracked path')
if not STATIC|ROOT_SOURCE <= set(seen): die('required public file missing')
request=json.loads((ROOT/'BUILD_REQUEST.json').read_text())
required={'schema','build_id','private_source_commit','semantic_version','worker_commit','workflow_sha256','toolchain','files'}
if set(request)!=required or request['schema']!=2: die('invalid request schema')
if not re.fullmatch('[0-9a-f]{40}',str(request['private_source_commit'])) or not re.fullmatch('[0-9a-f]{64}',str(request['build_id'])): die('invalid request identity')
parent=subprocess.run(['git','-C',str(ROOT),'rev-parse','HEAD^'],capture_output=True,text=True,check=True).stdout.strip()
if request['worker_commit']!=parent: die('request is not based on the reviewed worker commit')
workflow_hash=hashlib.sha256((ROOT/'.github/workflows/build.yml').read_bytes()).hexdigest()
if request['workflow_sha256']!=workflow_hash: die('request workflow identity mismatch')
static_changed=subprocess.run(['git','-C',str(ROOT),'diff','--name-only','HEAD^','HEAD','--',*sorted(STATIC)],capture_output=True,text=True,check=True).stdout
if static_changed.strip(): die('routine request modified static worker tooling')
actual=[]
for rel in sorted(set(seen)-STATIC-{'BUILD_REQUEST.json'}):
 data=(ROOT/rel).read_bytes(); actual.append({'path':rel,'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)})
if request['toolchain']!='rustc 1.85.0 (4d91de4e4 2025-02-17); windows-2022; macos-14': die('toolchain identity mismatch')
identity={k:request[k] for k in ('schema','private_source_commit','semantic_version','worker_commit','workflow_sha256','toolchain')}; identity['files']=actual
canonical=(json.dumps(identity,sort_keys=True,separators=(',',':'))+'\n').encode()
if request['files']!=actual or request['build_id']!=hashlib.sha256(canonical).hexdigest(): die('request does not bind exact public source')
print(request['build_id'])
