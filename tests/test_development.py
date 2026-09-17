import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from runtime import guard,hook
from scripts import install_multi
from .test_guard import POLICY,event,good_response

class DevelopmentTests(unittest.TestCase):
    def test_builds_are_reviewed_not_automatically_allowed(self):
        for command in ['go test ./...','make test','npm test','python3 -m pytest','cd subdir && go test ./...']:
            for deny in (False,True):
                response=good_response()
                if deny:response['answers']['baseline']['choice']='deny'
                query=Mock(return_value=response)
                result=guard.evaluate(event(command),POLICY,query,lambda _: 'fake')['hookSpecificOutput']
                self.assertEqual(result['permissionDecision'],'deny' if deny else 'allow')
                query.assert_called_once()

    def test_missing_source_does_not_erase_visible_destruction(self):
        response=good_response();response['answers']['baseline']['choice']='deny'
        query=Mock(return_value=response)
        result=guard.evaluate(event('npm test && gcloud sql databases delete customers --instance production'),POLICY,query,lambda _: 'fake')
        self.assertEqual(result['hookSpecificOutput']['permissionDecision'],'deny')
        self.assertIn('databases delete',query.call_args.args[0]['tool_input']['command'])

    def test_later_denial_overrides_earlier_uncertainty(self):
        response=good_response()
        response['answers']['baseline']['choice']='uncertain'
        response['answers']['rule_4']['choice']='deny'
        result=guard.evaluate(event(),POLICY,lambda *a:response,lambda _: 'fake')['hookSpecificOutput']
        self.assertEqual(result['permissionDecision'],'deny')
        self.assertIn('rule_4',result['permissionDecisionReason'])

    def test_invalid_later_answer_cannot_be_overridden(self):
        response=good_response();response['answers']['baseline']['choice']='uncertain'
        del response['answers']['rule_4']
        result=guard.evaluate(event(),POLICY,lambda *a:response,lambda _: 'fake')['hookSpecificOutput']
        self.assertEqual(result['permissionDecision'],'deny')
        self.assertIn('validation failed',result['permissionDecisionReason'])

    def test_ask_only_emitted_for_explicit_claude_adapter(self):
        output=guard.result('ask','Specific target needs review')['hookSpecificOutput']
        for client,e,expected in [('claude',event(permission_mode='default'),0),
                                  ('codex',event(permission_mode='default'),2),
                                  ('devin',event(),2),('unknown',event(),2),
                                  ('claude',event(),2),('claude',event(tool_name='exec',permission_mode='default'),2)]:
            with patch('sys.stdout',new_callable=io.StringIO) as out,patch('sys.stderr',new_callable=io.StringIO) as err:
                self.assertEqual(hook.emit_decision(output,client,e),expected)
                if expected==0:
                    result=json.loads(out.getvalue())
                    self.assertEqual(result['hookSpecificOutput']['permissionDecision'],'ask')
                    self.assertNotIn('updatedInput',result['hookSpecificOutput'])
                else:
                    self.assertEqual(out.getvalue(),'')
                    self.assertIn('Human review needed',err.getvalue())

    def test_deny_and_failure_never_prompt_for_override(self):
        with patch('sys.stdout',new_callable=io.StringIO) as out,patch('sys.stderr',new_callable=io.StringIO):
            self.assertEqual(hook.emit_decision(guard.result(False,'HTTP error')['hookSpecificOutput'],'claude',event(permission_mode='default')),2)
            self.assertEqual(out.getvalue(),'')

    def test_installer_selects_adapter_without_touching_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            home=Path(temp);install_multi.install(home)
            for client,relative in install_multi.CONFIGS.items():
                data=json.loads((home/relative).read_text())
                self.assertEqual(set(data),{'hooks'})
                command=data['hooks']['PreToolUse'][0]['hooks'][0]['command']
                self.assertIn('--client '+client,command)

if __name__=='__main__':unittest.main()
