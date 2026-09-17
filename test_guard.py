import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
import guard

POLICY=json.loads((Path(__file__).parent/'policy.json').read_text())

def event(command='pwd',**updates):
    e={'session_id':'test-session','hook_event_name':'PreToolUse','tool_name':'Bash',
       'tool_input':{'command':command},'cwd':'/private/tmp/example-project'}
    e.update(updates);return e

def good_response(policy=POLICY):
    return {'answers':{name:{'type':'choice','choice':'allow','confidence':.99,
        'probabilities':{'allow':.999,'deny':.0005,'uncertain':.0005}}
        for name in guard.validate_policy(policy)['_questions']}}

def decision(e,query=lambda *a:good_response(),policy=None):
    return guard.evaluate(e,policy or copy.deepcopy(POLICY),query,lambda p:'mock')['hookSpecificOutput']['permissionDecision']

class GuardTests(unittest.TestCase):
    def test_emergency_blocks_before_api(self):
        for cmd in ['rm -rf /System','dd if=/dev/zero of=/dev/disk0','sudo shutdown now',"bash -lc 'rm -rf /System'",'echo api_key=secretvalue']:
            query=Mock(side_effect=AssertionError('must not reach API'))
            self.assertEqual(decision(event(cmd),query),'deny');query.assert_not_called()

    def test_login_and_production_reach_jev(self):
        for e in [event('gcloud auth login'),event(tool_name='mcp__db__execute',tool_input={'sql':'DELETE FROM customers','environment':'production'})]:
            self.assertIsNone(guard.hard_reason(e,POLICY))
            response=good_response();response['answers']['baseline']['choice']='deny'
            query=Mock(return_value=response)
            self.assertEqual(decision(e,query),'deny');query.assert_called_once()

    def test_protected_paths_and_symlinks(self):
        for path in ['/etc/passwd','/System/file',str(Path.home()/'.codex/hooks.json')]:
            self.assertEqual(decision(event(tool_name='Edit',tool_input={'path':path})),'deny')
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/'system').symlink_to('/etc',target_is_directory=True)
            self.assertTrue(guard.protected('system/passwd',tmp,POLICY))

    def test_scope_and_malformed_input(self):
        p=copy.deepcopy(POLICY);p['session_ids']=['different']
        self.assertEqual(decision(event(),policy=p),'allow')
        for changes in [{'session_id':None},{'session_id':''},{'tool_input':[]},{'cwd':None},{'hook_event_name':'wrong'}]:
            self.assertEqual(decision(event(**changes)),'deny')
        self.assertEqual(decision(event(tool_name='write_stdin',tool_input={'chars':'anything'})),'deny')

    def test_any_failed_check_blocks(self):
        for name in good_response()['answers']:
            for change in [{'choice':'deny'},{'choice':'uncertain'},{'confidence':.5},{'confidence':float('nan')},
                           {'confidence':True},{'probabilities':{'allow':1,'deny':1,'uncertain':0}}]:
                response=good_response();response['answers'][name].update(change)
                self.assertEqual(decision(event(),lambda *a:response),'deny')

    def test_api_payload_and_no_target_read(self):
        with patch('urllib.request.build_opener') as op,patch.object(Path,'read_text',side_effect=AssertionError('unexpected read')):
            op.return_value.open.return_value.__enter__.return_value.read.return_value=b'{}'
            guard.request_jev(event('cat README.md'),POLICY,'fake')
            payload=json.loads(op.return_value.open.call_args.args[0].data)
            self.assertEqual(set(payload['questions']),set(good_response()['answers']))
            self.assertNotIn('session_id',payload['state']['proposed_action'])

if __name__=='__main__':unittest.main()
