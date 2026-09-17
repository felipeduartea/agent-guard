import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import guard
import hook
import install_multi
from test_guard import POLICY, event, good_response

class AdapterTests(unittest.TestCase):
    def engine(self):
        return types.SimpleNamespace(protected=guard.protected,result=guard.result,
            evaluate=lambda e,p:guard.evaluate(e,p,lambda *a:good_response(),lambda *a:'mock'))

    def test_native_tool_names(self):
        for name in ('Bash','exec','exec_command'):
            e=event('gcloud auth login',tool_name=name)
            self.assertEqual(hook.evaluate_hook(e,POLICY,self.engine())['hookSpecificOutput']['permissionDecision'],'deny')
        for name in ('Edit','Write','edit','write'):
            e=event(tool_name=name,tool_input={'path':'/etc/passwd','content':'unsafe'})
            self.assertEqual(hook.evaluate_hook(e,POLICY,self.engine())['hookSpecificOutput']['permissionDecision'],'deny')

    def test_devin_missing_cwd(self):
        e=event('pwd',tool_name='exec');del e['cwd']
        self.assertTrue(Path(hook.normalize(e)['cwd']).is_absolute())
        self.assertEqual(hook.evaluate_hook(e,POLICY,self.engine())['hookSpecificOutput']['permissionDecision'],'allow')

    def test_action_workdir(self):
        e=event(tool_name='edit',tool_input={'path':'passwd','cwd':'/etc'})
        self.assertEqual(hook.evaluate_hook(e,POLICY,self.engine())['hookSpecificOutput']['permissionDecision'],'deny')
        e['tool_input']['cwd']='relative'
        with self.assertRaises(ValueError):hook.normalize(e)

    def test_multi_and_notebook_edits(self):
        for name in ('MultiEdit','multi_edit','NotebookEdit','notebook_edit'):
            for path in ('/System/file',str(Path.home()/'.claude/settings.json'),str(Path.home()/'.config/devin/config.json')):
                e=event(tool_name=name,tool_input={'file_path':path})
                self.assertEqual(hook.evaluate_hook(e,POLICY,self.engine())['hookSpecificOutput']['permissionDecision'],'deny')

    def test_cli_contract(self):
        for e in (event('rm -rf /System'),event('rm -rf /System',tool_name='exec'),{}):
            p=subprocess.run([sys.executable,'-I',str(Path(hook.__file__))],input=json.dumps(e),capture_output=True,text=True)
            self.assertEqual(p.returncode,2)
            self.assertEqual(p.stdout,'')
            self.assertIn('Jev guard:',p.stderr)

    def test_passing_output_never_grants_permission(self):
        fake_engine=types.SimpleNamespace(evaluate=lambda e,p:guard.result(True,'passed'))
        spec=types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=lambda m:None))
        stdin=types.SimpleNamespace(buffer=io.BytesIO(json.dumps(event('pwd')).encode()))
        with patch.object(hook.importlib.util,'spec_from_file_location',return_value=spec), \
             patch.object(hook.importlib.util,'module_from_spec',return_value=fake_engine), \
             patch.object(hook.sys,'stdin',stdin),patch('sys.stdout',new_callable=io.StringIO) as out:
            self.assertEqual(hook.main(),0)
            self.assertEqual(out.getvalue(),'')

class MultiInstallTests(unittest.TestCase):
    def prepare(self,home):
        root=home/'.codex/guards/jev';root.mkdir(parents=True)
        p=copy.deepcopy(POLICY);p['session_ids']=['old-session'];p['production_identifiers']=['keep-me']
        (root/'policy.json').write_text(json.dumps(p))
        (root/'typesafe.key').write_text('sentinel-not-real')
        original={}
        for client,relative in install_multi.CONFIGS.items():
            path=home/relative;path.parent.mkdir(parents=True,exist_ok=True)
            d={'other':'preserve','hooks':{'PreToolUse':[{'matcher':'','hooks':[{'type':'command','command':'existing-'+client}]}]}}
            if client=='codex':d['hooks']['PreToolUse'].append({'matcher':'*','hooks':[{'command':'python '+str(root/'guard.py')}]})
            path.write_text(json.dumps(d));original[client]=d
        return root,original

    def test_install_preserve_and_idempotence(self):
        with tempfile.TemporaryDirectory() as td:
            home=Path(td);root,original=self.prepare(home)
            manifest=install_multi.install(home)
            for client,relative in install_multi.CONFIGS.items():
                d=json.loads((home/relative).read_text())
                self.assertEqual(d['other'],'preserve')
                self.assertEqual(d['hooks']['PreToolUse'][0],original[client]['hooks']['PreToolUse'][0])
                self.assertEqual(len(d['hooks']['PreToolUse']),2)
            policy=json.loads((root/'policy.json').read_text())
            self.assertEqual(policy['session_ids'],['old-session'])
            self.assertEqual(policy['production_identifiers'],['keep-me'])
            self.assertEqual((root/'typesafe.key').read_text(),'sentinel-not-real')
            self.assertEqual(len(list(Path(manifest['backup']).glob('*key*'))),0)
            install_multi.install(home)
            for relative in install_multi.CONFIGS.values():
                self.assertEqual(len(json.loads((home/relative).read_text())['hooks']['PreToolUse']),2)
            # Launcher denies a missing runtime rather than failing open with exit 1.
            (root/'hook.py').unlink()
            p=subprocess.run(['/bin/sh','-c',install_multi.hook_command(root)],input='{}',capture_output=True,text=True)
            self.assertEqual(p.returncode,2)

    def test_disabled_hooks_abort_before_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            home=Path(td);root,_=self.prepare(home)
            p=home/'.claude/settings.json';d=json.loads(p.read_text());d['disableAllHooks']=True;p.write_text(json.dumps(d))
            before=(home/'.codex/hooks.json').read_bytes()
            with self.assertRaises(RuntimeError):install_multi.install(home)
            self.assertEqual((home/'.codex/hooks.json').read_bytes(),before)
            self.assertFalse((root/'hook.py').exists())

if __name__=='__main__':unittest.main(verbosity=2)
