#!/usr/bin/env python3
"""Run manually in your own terminal. Never put a key in a chat or shell argument."""
import getpass
import os
from pathlib import Path

def main():
    target=Path.home()/'.codex/guards/jev/typesafe.key'
    key=getpass.getpass('TypeSafe API key (hidden): ').strip()
    if not key or '\n' in key:
        raise SystemExit('No valid key supplied; nothing changed.')
    target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    os.fchmod(fd,0o600)
    with os.fdopen(fd,'w') as f:
        f.write(key+'\n')
    print('Key saved with owner-only permissions. Key value was not printed.')

if __name__=='__main__': main()
