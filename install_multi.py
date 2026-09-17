#!/usr/bin/env python3
"""Back up and extend local CLI hooks. No approval, sandbox or trust bypass changes."""
import copy
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
import guard
from policies import PRESETS

SOURCE = Path(__file__).resolve().parent
CONFIGS = { 'codex':'.codex/hooks.json', 'claude':'.claude/settings.json',
            'devin':'.config/devin/config.json' }

def write_atomic(path, data, mode=0o600):
    if path.is_symlink():
        raise RuntimeError('Refusing symlink destination: '+str(path))
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp = tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),mode)
            f.write(data)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def hook_command(root):
    # If the adapter cannot even start, map the error to a blocking exit (2),
    # rather than letting clients treat an arbitrary nonzero exit as advisory.
    return (shlex.quote(sys.executable)+' -I '+shlex.quote(str(root/'hook.py'))+
            " || { printf '%s\\n' 'Jev guard blocked the action or could not run.' >&2; exit 2; }")

def merge_config(existing, root):
    d=copy.deepcopy(existing)
    if d.get('disableAllHooks') is True:
        raise RuntimeError('Client has disableAllHooks enabled; cannot install an effective guard.')
    groups=d.setdefault('hooks',{}).setdefault('PreToolUse',[])
    if not isinstance(groups,list): raise RuntimeError('Unrecognized hook configuration')
    new=[]
    for group in groups:
        g=copy.deepcopy(group)
        # Replace only our previous guard handler. Preserve every unrelated hook.
        g['hooks']=[h for h in g.get('hooks',[]) if not (
            str(root/'guard.py') in h.get('command','') or str(root/'hook.py') in h.get('command',''))]
        if g['hooks']: new.append(g)
    new.append({'matcher':'','hooks':[{'type':'command','command':hook_command(root),'timeout':20}]})
    d['hooks']['PreToolUse']=new
    return d

def install(home, clients=None, dry_run=False, preset=None, packs=None):
    clients=list(CONFIGS) if clients is None else list(dict.fromkeys(clients))
    if not clients or any(c not in CONFIGS for c in clients):
        raise ValueError('Select at least one supported client.')
    root=home/'.codex/guards/jev'
    if root.is_symlink(): raise RuntimeError('Symlink guard directory')
    policy_path=root/'policy.json'
    policy=json.loads((policy_path if policy_path.exists() else SOURCE/'policy.json').read_text())
    if policy_path.exists() and (preset is not None or packs):
        raise ValueError('Existing policy is preserved. Edit it explicitly in your own editor to change presets/packs.')
    if preset is not None:
        policy['preset']=preset
        policy['minimum_allow_probability']=0.95 if preset in ('machine-safety','general-development') else 0.99
        policy['inspect_scripts']=preset=='machine-safety'
    if packs: policy['packs']=packs
    guard.validate_policy(policy)
    key=policy['key_file']
    plan={}
    for client in clients:
        relative=CONFIGS[client]
        path=home/relative
        if path.is_symlink(): raise RuntimeError('Symlink client config')
        original=path.read_bytes() if path.exists() else None
        content=json.loads(original) if original is not None else {}
        plan[client]=(path,original,merge_config(content,root))
    if dry_run:
        return {'dry_run':True,'scope':policy['session_ids'] or 'all local sessions','policy_preserved':policy_path.exists(),'preset':policy.get('preset','legacy-strict'),'configs':{c:str(p[0]) for c,p in plan.items()},
                'guard_directory':str(root),'key_value':'never read by installer'}
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    backup=root/'backups'/stamp
    backup.mkdir(parents=True,mode=0o700)
    names=('guard.py','hook.py','policies.py','inspection.py','packs.json','set_key.py','README.md','INTEGRATIONS.md')
    for name in (*names,'policy.json','installation.json'):
        if (root/name).exists(): shutil.copy2(root/name,backup/name)
    for client,(path,original,_) in plan.items():
        if original is not None: write_atomic(backup/(client+'.json'),original)
    completed=[]
    try:
        for name in names: write_atomic(root/name,(SOURCE/name).read_bytes())
        if not policy_path.exists():
            write_atomic(policy_path,(json.dumps(policy,indent=2)+'\n').encode())
        for client,(path,original,merged) in plan.items():
            write_atomic(path,(json.dumps(merged,indent=2)+'\n').encode())
            completed.append(client)
        manifest={'installed_at':stamp,'backup':str(backup),'scope':policy['session_ids'] or 'all local sessions',
                  'configs':{client:str(item[0]) for client,item in plan.items()},
                  'files':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in (*names,'policy.json')},
                  'activation':'Client reload/restart required; Codex hook review required.'}
        write_atomic(root/'installation.json',(json.dumps(manifest,indent=2)+'\n').encode())
    except Exception:
        for client in completed:
            path,original,_=plan[client]
            if original is not None: write_atomic(path,original)
            else: path.unlink(missing_ok=True)
        for name in (*names,'policy.json','installation.json'):
            if (backup/name).exists(): write_atomic(root/name,(backup/name).read_bytes())
            else: (root/name).unlink(missing_ok=True)
        raise
    assert policy['key_file']==key
    return manifest

def uninstall(home,clients,dry_run=False):
    root=home/'.codex/guards/jev'
    changed=[]
    for client in clients:
        path=home/CONFIGS[client]
        if not path.exists(): continue
        if path.is_symlink(): raise RuntimeError('Refusing symlink config')
        original=path.read_bytes()
        data=json.loads(original)
        if 'PreToolUse' not in data.get('hooks',{}): continue
        groups=[]
        for group in data['hooks']['PreToolUse']:
            group['hooks']=[h for h in group.get('hooks',[]) if not any(str(root/n) in h.get('command','') for n in ('guard.py','hook.py'))]
            if group['hooks']:groups.append(group)
        data['hooks']['PreToolUse']=groups
        if json.loads(original)==data: continue
        changed.append(str(path))
        if not dry_run:
            stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
            write_atomic(root/'backups'/stamp/(client+'.json'),original)
            write_atomic(path,(json.dumps(data,indent=2)+'\n').encode())
    return {'uninstalled_from':changed,'dry_run':dry_run,'retained':'Guard files, key and backups are retained; restart clients.'}

def main():
    parser=argparse.ArgumentParser(description='Install a Jev pre-tool guard for local coding agents (macOS/Linux).')
    parser.add_argument('--clients',nargs='+',choices=list(CONFIGS),help='Clients to configure; default: detected installed CLIs.')
    parser.add_argument('--dry-run',action='store_true',help='Show changes without writing files or reading the API key.')
    parser.add_argument('--uninstall',action='store_true',help='Remove only this guard\'s hooks; keep files and key.')
    parser.add_argument('--preset',choices=list(PRESETS),help='Fresh installs only; default: machine-safety.')
    parser.add_argument('--pack',action='append',default=[],help='Fresh installs only; add a built-in pack (repeatable).')
    args=parser.parse_args()
    if os.name!='posix':parser.error('Only macOS and Linux are supported.')
    clients=args.clients or [c for c,b in [('codex','codex'),('claude','claude'),('devin','devin')] if shutil.which(b)]
    if not clients:parser.error('No supported CLI detected; specify --clients explicitly.')
    if args.uninstall and (args.preset or args.pack):parser.error('Preset/pack options cannot be used with uninstall.')
    output=uninstall(Path.home(),clients,args.dry_run) if args.uninstall else install(Path.home(),clients,args.dry_run,args.preset,args.pack)
    print(json.dumps(output,indent=2))

if __name__=='__main__': main()
