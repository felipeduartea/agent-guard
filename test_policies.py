import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import guard
import install_multi
import policies
from test_guard import event

DEFAULT=json.loads((Path(__file__).parent/'policy.json').read_text())

def config(preset='general-development',**values):
    p=copy.deepcopy(DEFAULT);p['preset']=preset;p.update(values);return p

def permitted(e,p):
    resolved=guard.validate_policy(p)
    response={'answers':{name:{'type':'choice','choice':'allow','confidence':1,
              'probabilities':{'allow':1,'deny':0,'uncertain':0}} for name in resolved['_questions']}}
    return guard.evaluate(e,p,lambda *a:response,lambda *a:'mock')['hookSpecificOutput']['permissionDecision']=='allow'

class PolicyTests(unittest.TestCase):
    def test_general_development_eligible(self):
        for command in ['python3 -m pytest','npm test','npm run build','make test','node script.js','gcloud auth login','rm -rf build']:
            with self.subTest(command=command):
                self.assertIsNone(guard.hard_reason(event(command),config()))
                self.assertTrue(permitted(event(command),config()))

    def test_baseline_always_wins(self):
        for preset in policies.PRESETS:
            for command in ['rm -rf /System','dd if=/dev/zero of=/dev/disk0','sudo shutdown now']:
                self.assertFalse(permitted(event(command),config(preset)))
        self.assertFalse(permitted(event(tool_name='Edit',tool_input={'path':str(Path.home()/'.codex/hooks.json')}),config()))

    def test_presets_and_independent_packs(self):
        self.assertFalse(permitted(event('gcloud auth login'),config('production-safe')))
        self.assertTrue(permitted(event('npm test'),config('production-safe')))
        self.assertFalse(permitted(event('npm test'),config('strict')))
        p=config(packs=['no-auth-changes'])
        self.assertFalse(permitted(event('aws configure'),p))
        self.assertTrue(permitted(event('python3 -m pytest'),p))
        self.assertFalse(permitted(event('gcloud sql databases create app --project mystery'),config(packs=['production-read-only'])))

    def test_enabled_questions_only(self):
        general=guard.validate_policy(config())
        self.assertEqual(set(general['_questions']),{'baseline'})
        auth=guard.validate_policy(config(packs=['no-auth-changes']))
        self.assertEqual(set(auth['_questions']),{'baseline','no-auth-changes'})
        with patch('urllib.request.build_opener') as op:
            op.return_value.open.return_value.__enter__.return_value.read.return_value=b'{}'
            guard.request_jev(event('npm test'),config(),'fake')
            payload=json.loads(op.return_value.open.call_args.args[0].data)
            self.assertEqual(set(payload['questions']),{'baseline'})

    def test_declarative_addons_fixed_deny(self):
        p=config(addons=[{'name':'team','deny_tools':['mcp__deploy'],
                         'deny_command_prefixes':[['git','push']],
                         'instructions':'Never publish changes.'}])
        for command in ['git push origin main','git status && /usr/bin/git push origin main',"bash -lc 'git push origin main'"]:
            self.assertFalse(permitted(event(command),p))
        self.assertFalse(permitted(event(tool_name='mcp__deploy',tool_input={}),p))

    def test_path_modes_and_conflict_deny_wins(self):
        p=config(protected_paths=[{'path':'/srv/customer','access':'read-only'}])
        self.assertTrue(permitted(event(tool_name='Read',tool_input={'path':'/srv/customer/data'}),p))
        self.assertFalse(permitted(event(tool_name='Edit',tool_input={'path':'/srv/customer/data'}),p))
        p['addons']=[{'name':'secret','protected_paths':[{'path':'/srv/customer','access':'deny'}]}]
        self.assertFalse(permitted(event(tool_name='Read',tool_input={'path':'/srv/customer/data'}),p))
        self.assertFalse(permitted(event('cat /srv/customer/data'),p))

    def test_invalid_config(self):
        invalid=[{'preset':'typo'},{'packs':['typo']},{'allow_all':True},
                 {'addons':[{'name':'oops','allow_tools':['Bash']}]},
                 {'protected_paths':[{'path':'relative','access':'deny'}]},
                 {'addons':[{'name':'x','deny_command_prefixes':[[]]}]},
                 {'addons':[{'name':'x'},{'name':'x'}]}]
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):guard.validate_policy(config(**values))

    def test_installer_preserves_legacy_bytes_and_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);root=home/'.codex/guards/jev';root.mkdir(parents=True)
            legacy=(Path(__file__).parent/'legacy-policy.json').read_bytes()+b'\n'
            (root/'policy.json').write_bytes(legacy)
            install_multi.install(home,['claude'])
            self.assertEqual((root/'policy.json').read_bytes(),legacy)
            with self.assertRaises(ValueError):install_multi.install(home,['claude'],preset='general-development')

    def test_fresh_preset_and_pack(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp)
            install_multi.install(home,['claude'],preset='production-safe',packs=['strict-execution'])
            p=json.loads((home/'.codex/guards/jev/policy.json').read_text())
            self.assertEqual(p['preset'],'production-safe')
            self.assertFalse(permitted(event('npm test'),p))

if __name__=='__main__':unittest.main(verbosity=2)
