"""Bounded, read-only collection of local execution context. Never execute code."""
import ast
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
class SensitiveSource(Uninspectable):pass

def collect(event, secret_pattern):
    if event['tool_name'] not in {'Bash','exec_command','shell','shell_command'}:
        return {'sources':[], 'coverage':'tool arguments only'}
    command=event['tool_input'].get('command',event['tool_input'].get('cmd'))
    if not isinstance(command,str):raise Uninspectable('Missing command')
    cwd=Path(event['cwd']).resolve()
    sources=[]
    read_targets=[]
    gaps=[]
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
        if secret_pattern.search(content):raise SensitiveSource('Potential secret in script; not sent to Jev')
        sources.append({'path':str(path.relative_to(cwd)),'sha256':hashlib.sha256(data).hexdigest(),'content':content})
        if path.suffix == '.py':
            try: tree=ast.parse(content)
            except (SyntaxError,RecursionError):return
            # Syntactic candidates only: no execution, dependency resolution or target-content upload.
            for node in ast.walk(tree):
                if len(read_targets)>=12:break
                if not (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
                        and node.func.attr in {'read_text','read_bytes'}):continue
                ctor=node.func.value
                if not (isinstance(ctor,ast.Call) and isinstance(ctor.func,ast.Name) and ctor.func.id=='Path'
                        and len(ctor.args)==1 and isinstance(ctor.args[0],ast.Constant)
                        and isinstance(ctor.args[0].value,str)):continue
                literal=ctor.args[0].value
                candidate=Path(literal)
                candidate=candidate if candidate.is_absolute() else cwd/candidate
                try:
                    resolved=candidate.resolve()
                    within=resolved==cwd or cwd in resolved.parents
                    sensitive=any(part in SENSITIVE or part.startswith('.env') for part in resolved.parts) or resolved.suffix in {'.key','.pem'}
                    item={'source':str(path.relative_to(cwd)),'literal_path':literal,
                          'within_working_directory':within,'sensitive_path':sensitive,
                          'symlink_component':any(x.is_symlink() for x in [candidate,*candidate.parents]),
                          'target_contents_inspected':False}
                    if within and not sensitive:
                        info=resolved.stat()
                        item.update(exists=True,regular_file=stat.S_ISREG(info.st_mode),size_bytes=info.st_size)
                        if stat.S_ISREG(info.st_mode) and info.st_size<=MAX_SOURCE and not item['symlink_component']:
                            fd=os.open(resolved,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                            with os.fdopen(fd,'rb') as target:
                                opened=os.fstat(target.fileno())
                                if stat.S_ISREG(opened.st_mode) and (opened.st_dev,opened.st_ino)==(info.st_dev,info.st_ino):
                                    sample=target.read(MAX_SOURCE+1)
                                    if len(sample)<=MAX_SOURCE:
                                        try: text=sample.decode('utf-8')
                                        except UnicodeError:pass
                                        else:
                                            item.update(target_contents_inspected=True,
                                                        secret_pattern_detected=bool(secret_pattern.search(text)),
                                                        scan_limits='Known secret patterns only; contents are never uploaded; not a guarantee of non-sensitive data.')
                    read_targets.append(item)
                except (OSError,ValueError):
                    read_targets.append({'source':str(path.relative_to(cwd)),'literal_path':literal,'metadata_unavailable':True})


    def collect_source(name):
        try:read_source(name)
        except SensitiveSource:raise
        except (OSError,ValueError,UnicodeError):
            gaps.append('An entrypoint could not be read within source collection limits. No safety conclusion follows from this alone.')

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
                gaps.append('Indirect execution: review visible arguments; source was not resolved.')
                continue
            if exe=='cd':
                gaps.append('Command changes directory; following script paths were not resolved.')
                return
            if exe in {'npm','npx','pnpm','yarn','make','just','task','uv','uvx','cargo','go','docker','podman'}:
                gaps.append('Build/package/container dependencies are not expanded; assess the requested operation and target.')
                continue
            interpreter=bool(re.fullmatch(r'python(?:\d+(?:\.\d+)?)?',exe)) or exe in {'node','ruby','perl','bash','sh','zsh','dash'}
            if interpreter:
                if len(args)<2:
                    gaps.append('Interactive interpreter: source unavailable.')
                    continue
                if args[1] in {'-c','-lc','-e'}:
                    if len(args)<3:raise Uninspectable('Inline source is missing')
                    if secret_pattern.search(args[2]):raise SensitiveSource('Potential secret in inline source')
                    if exe in {'bash','sh','zsh','dash'}:inspect(args[2],depth+1)
                    # Inline source is already present in tool arguments.
                elif args[1].startswith('-'):
                    gaps.append('Interpreter module/options: dependency source unavailable.')
                else:collect_source(args[1])
            elif '/' in args[0] or args[0].endswith(('.py','.js','.sh','.rb','.pl')):
                # System binaries are reviewed by their visible operation, not uploaded.
                if str(Path(args[0]).parent) not in {'/bin','/usr/bin','/usr/local/bin','/opt/homebrew/bin'}:
                    collect_source(args[0])
    try:inspect(command)
    except SensitiveSource:raise
    except (Uninspectable,ValueError):gaps.append('Shell syntax exceeds source collector support; assess the visible command.')
    return {'sources':sources,'collection_gaps':gaps,'literal_read_target_metadata':read_targets,
            'metadata_limits':'Syntactic Path literal read candidates only; names may be rebound and metadata may change. Not a safety verdict. Eligible small regular local targets are scanned for known secret patterns; only scan flags, never contents, are included.',
            'coverage':'entrypoint source and visible arguments only; imports, dependencies, runtime inputs, shell startup and subprocesses are not resolved',
            'source_is_untrusted':True,'source_can_change_after_check':True}
