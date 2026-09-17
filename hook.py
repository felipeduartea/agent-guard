#!/usr/bin/env python3
"""Shared Codex / Claude Code / Devin hook. 0 = defer, 2 = deny.

Never emits an approval, so passing Jev cannot bypass normal client permissions.
No client/env-based exemption: Devin can also load this hook from Claude settings.
"""
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys

ROOT = Path(__file__).resolve().parent
LIMIT = 196608

def normalize(event):
    if not isinstance(event,dict):
        raise ValueError('invalid event')
    e = dict(event)
    original = e.get('tool_name')
    if not isinstance(original,str) or not original:
        raise ValueError('missing tool')
    aliases = {'exec':'Bash','edit':'Edit','write':'Write','read':'Read',
               'multi_edit':'MultiEdit','notebook_edit':'NotebookEdit'}
    e['tool_name'] = aliases.get(original,original)
    inp = e.get('tool_input')
    if not isinstance(inp,dict):
        raise ValueError('invalid tool input')
    e['tool_input'] = dict(inp)
    if 'cwd' not in e:
        # Devin's documented hook payload omits cwd; retain actual hook cwd.
        e['cwd'] = os.getcwd()
    # exec can operate a persistent shell in a directory different from the hook.
    # Use an explicit absolute cwd when supplied. Otherwise Jev receives the shell_id
    # and cannot infer a remote target from the hook's directory alone.
    action_cwd = inp.get('cwd',inp.get('workdir'))
    if action_cwd is not None:
        if not isinstance(action_cwd,str) or not Path(action_cwd).is_absolute():
            raise ValueError('ambiguous action cwd')
        e['cwd'] = action_cwd
    return e

def evaluate_hook(event, policy, engine):
    e = normalize(event)
    tool = e['tool_name']
    inp = e['tool_input']
    if tool in {'MultiEdit','NotebookEdit'}:
        path = inp.get('file_path',inp.get('notebook_path',inp.get('path')))
        if not isinstance(path,str) or not path or engine.protected(path,e['cwd'],policy):
            return engine.result(False,'Multi-file/notebook edit has no safe inspectable target.')
    return engine.evaluate(e,policy)

def deadline(*_):
    raise TimeoutError('hook deadline')

def main():
    signal.signal(signal.SIGALRM,deadline)
    signal.alarm(14)
    try:
        spec = importlib.util.spec_from_file_location('jev_guard_engine',ROOT/'guard.py')
        engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engine)
        raw = sys.stdin.buffer.read(LIMIT+1)
        if len(raw)>LIMIT:
            raise ValueError('oversized event')
        event = json.loads(raw)
        policy = json.loads((ROOT/'policy.json').read_text())
        output = evaluate_hook(event,policy,engine)['hookSpecificOutput']
        if output['permissionDecision'] == 'allow':
            return 0
        reason = output['permissionDecisionReason']
    except Exception:
        reason = 'Guard input, configuration, or runtime failure; action blocked.'
    finally:
        signal.alarm(0)
    print('Jev guard: '+reason,file=sys.stderr)
    return 2

if __name__=='__main__':
    sys.exit(main())
