import json
import unittest
import urllib.error
from unittest.mock import Mock,patch
import guard
from test_guard import event,POLICY,good_response

class RetryTests(unittest.TestCase):
    def run_request(self,outcomes,clock=None):
        with patch('urllib.request.build_opener') as build,patch('guard.time.sleep') as sleep:
            build.return_value.open.side_effect=outcomes
            try:
                result=guard.request_jev(event(),POLICY,'fake')
            except Exception as exc:result=exc
            return result,build.return_value.open,sleep

    def response(self,body=None):
        response=Mock()
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        response.read.return_value=body if body is not None else json.dumps(good_response()).encode()
        return response

    def error(self,code,headers=None):
        return urllib.error.HTTPError('https://example.invalid',code,'test',headers or {},None)

    def test_transient_error_retries_once(self):
        for exc in [self.error(529),self.error(503),TimeoutError(),urllib.error.URLError(ConnectionResetError())]:
            result,op,sleep=self.run_request([exc,self.response()])
            self.assertIsInstance(result,dict)
            self.assertEqual(op.call_count,2)
            sleep.assert_called_once_with(.2)
            self.assertLess(op.call_args_list[0].kwargs['timeout'],POLICY['api_timeout_seconds'])

    def test_second_failure_stops(self):
        result,op,_=self.run_request([self.error(529),self.error(529)])
        self.assertIsInstance(result,urllib.error.HTTPError)
        self.assertEqual(op.call_count,2)

    def test_nontransient_and_long_retry_after_do_not_retry(self):
        for exc in [self.error(401),self.error(403),self.error(429,{'Retry-After':'60'}),urllib.error.URLError('certificate verification failed')]:
            result,op,sleep=self.run_request([exc])
            self.assertIsInstance(result,Exception)
            self.assertEqual(op.call_count,1)
            sleep.assert_not_called()

    def test_invalid_json_and_denials_do_not_retry(self):
        r=good_response();r['answers']['production']['choice']='deny'
        for body in [b'not-json',json.dumps(r).encode()]:
            _,op,sleep=self.run_request([self.response(body)])
            self.assertEqual(op.call_count,1)
            sleep.assert_not_called()

    def test_expired_budget_prevents_retry(self):
        with patch('guard.time.monotonic',side_effect=[0,0,100]):
            result,op,sleep=self.run_request([self.error(529)])
        self.assertIsInstance(result,urllib.error.HTTPError)
        self.assertEqual(op.call_count,1)
        sleep.assert_not_called()

if __name__=='__main__':unittest.main()
