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

    def test_literal_read_metadata_does_not_upload_target_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'notes.txt').write_text('private fixture data')
            (root/'read.py').write_text('from pathlib import Path\nprint(Path("notes.txt").read_text())\n')
            context=guard.inspection.collect(event('python3 read.py',cwd=tmp),guard.SECRET)
            item=context['literal_read_target_metadata'][0]
            self.assertTrue(item['within_working_directory'])
            self.assertTrue(item['regular_file'])
            self.assertTrue(item['target_contents_inspected'])
            self.assertFalse(item['secret_pattern_detected'])
            self.assertNotIn('private fixture data',json.dumps(context))

    def test_read_target_secret_scan_does_not_expose_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'notes.txt').write_text('password = private-fixture-value')
            (root/'read.py').write_text('from pathlib import Path\nprint(Path("notes.txt").read_text())\n')
            context=guard.inspection.collect(event('python3 read.py',cwd=tmp),guard.SECRET)
            self.assertTrue(context['literal_read_target_metadata'][0]['secret_pattern_detected'])
            self.assertNotIn('private-fixture-value',json.dumps(context))

    def test_read_target_symlink_is_not_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'data.txt').write_text('fixture')
            (root/'notes.txt').symlink_to(root/'data.txt')
            (root/'read.py').write_text('from pathlib import Path\nprint(Path("notes.txt").read_text())\n')
            item=guard.inspection.collect(event('python3 read.py',cwd=tmp),guard.SECRET)['literal_read_target_metadata'][0]
            self.assertTrue(item['symlink_component'])
            self.assertFalse(item['target_contents_inspected'])

    def test_sensitive_and_outside_read_targets_not_marked_ordinary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'read.py').write_text('from pathlib import Path\nprint(Path(".env").read_text())\nprint(Path("/outside.txt").read_text())\n')
            context=guard.inspection.collect(event('python3 read.py',cwd=tmp),guard.SECRET)
            first,second=context['literal_read_target_metadata']
            self.assertTrue(first['sensitive_path'])
            self.assertFalse(second['within_working_directory'])
            self.assertNotIn('regular_file',first)
            self.assertNotIn('regular_file',second)

    def test_removed_inspection_toggle_is_rejected(self):
        with self.assertRaises(ValueError):guard.validate_policy(dict(POLICY,inspect_scripts='yes'))

if __name__=='__main__':unittest.main()
