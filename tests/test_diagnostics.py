import unittest
import urllib.error
from runtime import guard
from scripts import smoke_test
from types import SimpleNamespace
from .test_guard import event, POLICY, good_response

class DiagnosticTests(unittest.TestCase):
    def reason(self,query,key=lambda _: 'fake',expected='deny'):
        r=guard.evaluate(event(),POLICY,query,key)['hookSpecificOutput']
        self.assertEqual(r['permissionDecision'],expected)
        return r['permissionDecisionReason']

    def test_request_failures_have_distinct_sanitized_reasons(self):
        cases=[(TimeoutError('private-token'),'timed out'),
               (urllib.error.HTTPError('https://private-token',429,'private-token',{},None),'HTTP error 429'),
               (urllib.error.URLError('private-token'),'connection failure'),
               (ValueError('private-token'),'could not be decoded')]
        for exc,expected in cases:
            def query(*_,exc=exc):raise exc
            reason=self.reason(query)
            self.assertIn(expected,reason)
            self.assertNotIn('private-token',reason)
            if isinstance(exc,urllib.error.HTTPError):exc.close()

    def test_key_failure_is_distinct(self):
        def key(_):raise FileNotFoundError('private-path')
        reason=self.reason(lambda *a:self.fail('must not call API'),key)
        self.assertIn('key unavailable',reason)
        self.assertNotIn('private-path',reason)

    def test_invalid_distribution_is_not_a_policy_rejection(self):
        response=good_response()
        response['answers']['baseline']['probabilities']={'allow':.98,'deny':.02,'uncertain':.01}
        self.assertIn('probability sum differs from 1',self.reason(lambda *a:response))

    def test_low_scores_are_explained_without_changing_thresholds(self):
        response=good_response();response['answers']['baseline']['confidence']=.5
        reason=self.reason(lambda *a:response,expected='ask')
        self.assertIn('confidence=0.500',reason)
        self.assertIn('required allow>=',reason)

    def test_unrecognized_choice_is_not_echoed(self):
        response=good_response();response['answers']['baseline']['choice']='private-token'
        reason=self.reason(lambda *a:response)
        self.assertIn('invalid answer schema',reason)
        self.assertNotIn('private-token',reason)

    def test_smoke_does_not_count_outages_as_safety_passes(self):
        for reason in ['Jev guard: Jev HTTP error 529. Action blocked.', 'Jev guard: Jev response validation failed.', '']:
            self.assertFalse(smoke_test.matches_expectation(2,SimpleNamespace(returncode=2,stderr=reason)))
        self.assertTrue(smoke_test.matches_expectation(2,SimpleNamespace(returncode=2,stderr='Jev guard: Jev policy check baseline: choice=deny')))
        self.assertTrue(smoke_test.matches_expectation(0,SimpleNamespace(returncode=0,stderr='')))

    def test_missing_answers_are_schema_failures(self):
        self.assertIn('invalid answer schema',self.reason(lambda *a:{'answers':{}}))

if __name__=='__main__':unittest.main()
