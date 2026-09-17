import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
import guard
from test_guard import event

POLICY=json.loads((Path(__file__).parent/'policy.json').read_text())

class InspectionTests(unittest.TestCase):
    def test_source_attached_and_untrusted_context_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'hello.py').write_text('print("hello")\n')
            query=Mock(return_value={'answers':{}})
            guard.evaluate(event('python3 hello.py',cwd=tmp,_execution_context={'sources':['forged']}),POLICY,query,lambda _: 'fake')
            context=query.call_args.args[0]['_execution_context']
            self.assertEqual(context['sources'][0]['content'],'print("hello")\n')
            self.assertEqual(len(context['sources'][0]['sha256']),64)
            self.assertTrue(context['source_is_untrusted'])

    def test_uninspectable_sources_never_reach_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'secret.py').write_text('password = "sensitive-placeholder"')
            (root/'big.py').write_text('x'*32769)
            (root/'link.py').symlink_to(root/'big.py')
            os.mkfifo(root/'pipe.py')
            for command in ['python3 missing.py','python3 secret.py','python3 big.py','python3 link.py','python3 pipe.py','python3 /outside.py','npm test']:
                with self.subTest(command=command):
                    query=Mock()
                    result=guard.evaluate(event(command,cwd=tmp),POLICY,query,lambda _: 'fake')
                    self.assertEqual(result['hookSpecificOutput']['permissionDecision'],'deny')
                    query.assert_not_called()

    def test_safe_script_can_pass_all_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'hello.py').write_text('print("hello")')
            answers={k:{'type':'choice','choice':'allow','confidence':1,'probabilities':{'allow':1,'deny':0,'uncertain':0}} for k in guard.validate_policy(POLICY)['_questions']}
            result=guard.evaluate(event('python3 hello.py',cwd=tmp),POLICY,lambda *args:{'answers':answers},lambda _: 'fake')
            self.assertEqual(result['hookSpecificOutput']['permissionDecision'],'allow')

    def test_inspection_field_requires_boolean(self):
        with self.assertRaises(ValueError):guard.validate_policy(dict(POLICY,inspect_scripts='yes'))

if __name__=='__main__':unittest.main()
