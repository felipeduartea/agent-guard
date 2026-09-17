"""Bounded, read-only collection of local execution context. Never execute code."""
import hashlib
import os
from pathlib import Path
import re
import shlex
import stat

MAX_SOURCE=32768
MAX_FILES=3
SENSITIVE={'.ssh','.aws','.codex','.claude','.config','.git','.gnupg'}

class Uninspectable(ValueError):pass

def collect(event, secret_pattern):
    if event['tool_name'] not in {'Bash','exec_command','shell','shell_command'}:
        return {'sources':[], 'coverage':'tool arguments only'}
    command=event['tool_input'].get('command',event['tool_input'].get('cmd'))
    if not isinstance(command,str):raise Uninspectable('Missing command')
    cwd=Path(event['cwd']).resolve()
    sources=[]
    def read_source(name):
        if len(sources)>=MAX_FILES:raise Uninspectable('Too many source files')
        raw=Path(name).expanduser()
        raw=raw if raw.is_absolute() else cwd/raw
        path=raw.resolve()
        if not (path==cwd or cwd in path.parents):raise Uninspectable('Script is outside the working directory')
        if raw.is_symlink():raise Uninspectable('Script symlinks are not inspected')
        if any(part in SENSITIVE or part.startswith('.env') for part in path.parts) or path.suffix in {'.key','.pem'}:
            raise Uninspectable('Sensitive file is not inspected')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_SOURCE:
                raise Uninspectable('Script must be a small regular file')
            data=f.read(MAX_SOURCE+1)
        if len(data)>MAX_SOURCE:raise Uninspectable('Script exceeds inspection limit')
        content=data.decode('utf-8')
        if '\0' in content:raise Uninspectable('Binary script is not inspectable')
        if secret_pattern.search(content):raise Uninspectable('Potential secret in script; not sent to Jev')
        sources.append({'path':str(path.relative_to(cwd)),'sha256':hashlib.sha256(data).hexdigest(),'content':content})

    def inspect(text,depth=0):
        if depth>3:raise Uninspectable('Too many nested commands')
        lexer=shlex.shlex(text,posix=True,punctuation_chars=';&|()<>')
        lexer.whitespace_split=True
        tokens=list(lexer)
        chunks=[];chunk=[]
        for token in tokens:
            if token in {';','&&','||','|'}:
                if chunk:chunks.append(chunk)
                chunk=[]
            else:chunk.append(token)
        if chunk:chunks.append(chunk)
        for args in chunks:
            exe=Path(args[0]).name
            if exe in {'env','eval','source','.','xargs','ssh','sudo','command','exec'} or '=' in args[0]:
                raise Uninspectable('Indirect execution cannot be inspected')
            if exe=='cd':raise Uninspectable('Use an explicit action working directory instead of cd')
            if exe in {'npm','npx','pnpm','yarn','make','just','task','uv','uvx','cargo','go','docker','podman'}:
                raise Uninspectable('Build/package/container execution needs dependency inspection that is not implemented')
            interpreter=bool(re.fullmatch(r'python(?:\d+(?:\.\d+)?)?',exe)) or exe in {'node','ruby','perl','bash','sh','zsh','dash'}
            if interpreter:
                if len(args)<2:raise Uninspectable('Interactive interpreter has no inspectable source')
                if args[1] in {'-c','-lc','-e'}:
                    if len(args)<3:raise Uninspectable('Inline source is missing')
                    if secret_pattern.search(args[2]):raise Uninspectable('Potential secret in inline source')
                    if exe in {'bash','sh','zsh','dash'}:inspect(args[2],depth+1)
                    # Inline source is already present in tool arguments.
                elif args[1].startswith('-'):
                    raise Uninspectable('Interpreter module/options cannot be resolved safely')
                else:read_source(args[1])
            elif '/' in args[0] or args[0].endswith(('.py','.js','.sh','.rb','.pl')):
                # System binaries are reviewed by their visible operation, not uploaded.
                if str(Path(args[0]).parent) not in {'/bin','/usr/bin','/usr/local/bin','/opt/homebrew/bin'}:
                    read_source(args[0])
    inspect(command)
    return {'sources':sources,'coverage':'entrypoint source and visible arguments only; imports, dependencies, runtime inputs, shell startup and subprocesses are not resolved',
            'source_is_untrusted':True,'source_can_change_after_check':True}
