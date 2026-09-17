import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import install_multi

class FreshInstallTests(unittest.TestCase):
    def test_fresh_machine_selected_client(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp)
            result=install_multi.install(home,['claude'])
            self.assertEqual(set(result['configs']),{'claude'})
            self.assertFalse((home/'.config/devin/config.json').exists())
            self.assertFalse((home/'.codex/hooks.json').exists())
            self.assertTrue((home/'.codex/guards/jev/set_key.py').exists())
            self.assertEqual(json.loads((home/'.codex/guards/jev/policy.json').read_text())['session_ids'],[])

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp)
            result=install_multi.install(home,['codex','devin'],True)
            self.assertTrue(result['dry_run'])
            self.assertEqual(list(home.iterdir()),[])

    def test_uninstall_preserves_other_hooks_and_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp);settings=home/'.claude/settings.json';settings.parent.mkdir()
            existing={'theme':'dark','hooks':{'PreToolUse':[{'hooks':[{'type':'command','command':'other-hook'}]}]}}
            settings.write_text(json.dumps(existing))
            install_multi.install(home,['claude'])
            key=home/'.codex/guards/jev/typesafe.key';key.write_text('fake')
            before=settings.read_bytes()
            install_multi.uninstall(home,['claude'],True)
            self.assertEqual(before,settings.read_bytes())
            install_multi.uninstall(home,['claude'])
            self.assertEqual(json.loads(settings.read_text()),existing)
            self.assertEqual(key.read_text(),'fake')
            self.assertEqual(install_multi.uninstall(home,['claude'])['uninstalled_from'],[])

    def test_partial_failure_rolls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            home=Path(tmp);real=install_multi.write_atomic
            def fail(path,*args,**kwargs):
                if path==home/'.claude/settings.json':raise OSError('simulated')
                return real(path,*args,**kwargs)
            with patch.object(install_multi,'write_atomic',side_effect=fail):
                with self.assertRaises(OSError):install_multi.install(home,['codex','claude'])
            self.assertFalse((home/'.codex/hooks.json').exists())
            self.assertFalse((home/'.codex/guards/jev/policy.json').exists())
            self.assertFalse((home/'.codex/guards/jev/hook.py').exists())

if __name__=='__main__':unittest.main(verbosity=2)
