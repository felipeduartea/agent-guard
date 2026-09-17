import copy
import json
from pathlib import Path
import tempfile
import unittest
import guard
import install_multi
from test_guard import POLICY

def config(**values):
    p=copy.deepcopy(POLICY);p['rules']=[];p['examples']={};p.update(values);return p

class PolicyTests(unittest.TestCase):
    def test_one_policy_and_always_on_baseline(self):
        self.assertEqual(set(guard.validate_policy(config())['_questions']),{'baseline'})

    def test_reject_old_formats_and_removed_configuration(self):
        for values in [{'version':1},{'version':2},{'preset':'strict'},{'packs':[]},{'addons':[]},
                       {'protected_paths':[]},{'inspect_scripts':False},{'_questions':{}},{'minimum_allow_probability':.5}]:
            with self.subTest(values=values),self.assertRaises(ValueError):guard.validate_policy(config(**values))

    def test_older_installation_rejected_before_any_write(self):
        for version in (1,2):
            with tempfile.TemporaryDirectory() as tmp:
                home=Path(tmp);root=home/'.codex/guards/jev';root.mkdir(parents=True)
                (root/'policy.json').write_text(json.dumps({'version':version}))
                (root/'guard.py').write_text('old-runtime')
                before={str(p.relative_to(home)):p.read_bytes() for p in home.rglob('*') if p.is_file()}
                with self.assertRaisesRegex(ValueError,'version 3'):install_multi.install(home,['codex'])
                after={str(p.relative_to(home)):p.read_bytes() for p in home.rglob('*') if p.is_file()}
                self.assertEqual(before,after)

if __name__=='__main__':unittest.main()
