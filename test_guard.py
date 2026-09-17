import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import guard

POLICY = json.loads((Path(__file__).parent/'policy.json').read_text())

def event(command='git status', **updates):
    e = {'session_id':'test-session', 'hook_event_name':'PreToolUse',
         'tool_name':'Bash', 'tool_input':{'command':command}, 'cwd':'/workspace/example-user/Documents/example'}
    e.update(updates)
    return e

def good_response():
    return {'answers':{name:{'type':'choice','choice':'allow',
            'probabilities':{'allow':0.999,'deny':0.0005,'uncertain':0.0005},'confidence':0.99} for name in guard.QUESTIONS}}

def decision(e, query=lambda *a:good_response(), policy=None):
    return guard.evaluate(e,policy or copy.deepcopy(POLICY),query,lambda p:'mock-key')['hookSpecificOutput']['permissionDecision']

class GuardTests(unittest.TestCase):
    def test_hard_blocks_before_api(self):
        commands = [
            'gcloud auth login','gcloud auth application-default login',
            'gcloud --project example auth login --no-launch-browser',
            '/opt/homebrew/bin/gcloud auth activate-service-account --key-file account.json',
            'gcloud config set account me@example.com', 'gcloud config configurations activate production',
            'aws sso login','aws configure','aws sts assume-role --role-arn role',
            'az login','gh auth login','docker login','firebase login','vercel login','supabase login',
            'bash -lc "gcloud auth login"', "gcloud auth 'lo'gin", 'gcloud auth lo\\gin',
            'git status && gcloud auth login', 'echo okay | gcloud auth login',
            'env CLOUDSDK_CORE_PROJECT=prod gcloud auth login', 'command gcloud auth login',
            'gcloud sql databases create app --instance prod-main',
            'gcloud storage cp ./data gs://unknown-bucket',
            'aws s3 rm s3://unknown-bucket/file', 'kubectl apply -f deployment.yaml',
            'terraform apply', 'terraform destroy',
            'psql --command "DELETE FROM users"', 'mysql --execute "INSERT INTO users VALUES (1)"',
            'curl https://example.com -X POST -d test',
            'sudo rm -rf /System','rm -rf /System','rm -rf /','rm -rf /tmp/x',
            'dd if=/dev/zero of=/dev/disk0','diskutil eraseDisk APFS blank disk0',
            'find /System -delete','find . -exec sh run.sh ;', 'git clean -fdx','git reset --hard',
            'git push origin main','chmod -R 777 /System', 'mv /System /tmp/backup',
            'python3 -c "print(1)"','python3 /tmp/script.py', 'node script.js','bash script.sh',
            'source script.sh','npm run deploy','npx anything','make deploy','ssh host command',
            'eval "gcloud auth login"', '$(echo gcloud) auth login',
            'gcloud auth ${ACTION}', 'printf foo > /etc/passwd', 'git status &',
            'cp file /etc/passwd', 'touch /etc/jev-test-hook.json'
        ]
        for command in commands:
            with self.subTest(command=command):
                with patch.object(guard,'request_jev',side_effect=AssertionError('must not call API')):
                    self.assertIsNotNone(guard.hard_reason(event(command),POLICY))
                self.assertEqual(decision(event(command)), 'deny')

    def test_benign_calls_require_jev(self):
        for command in ['git status','git diff','ls -la','cat README.md','rg hello src',
                        'gcloud projects list','gcloud auth list','aws s3api list-buckets',
                        'kubectl get pods','bash -lc "git status"']:
            with self.subTest(command=command):
                self.assertIsNone(guard.hard_reason(event(command),POLICY))
                self.assertEqual(decision(event(command)),'allow')
                self.assertEqual(decision(event(command),lambda *a: (_ for _ in ()).throw(TimeoutError())),'deny')

    def test_patch_paths(self):
        for p in ['/etc/passwd','/System/test','/etc/jev-test-hook.json',
                  '../production/data.json','/dev/disk0']:
            e=event(tool_name='apply_patch',tool_input={'command':'*** Begin Patch\n*** Update File: '+p+'\n@@\n-x\n+y\n*** End Patch'})
            with self.subTest(path=p): self.assertEqual(decision(e),'deny')
        e=event(tool_name='apply_patch',tool_input={'command':'*** Begin Patch\n*** Add File: src/example.py\n+print(1)\n*** End Patch'})
        self.assertEqual(decision(e),'allow')

    def test_symlinks_and_parent_paths(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'system').symlink_to('/etc',target_is_directory=True)
            self.assertTrue(guard.protected('system/passwd',d,POLICY))
        self.assertTrue(guard.protected('/tmp/../etc/passwd','/',POLICY))

    def test_configured_production(self):
        p=copy.deepcopy(POLICY)
        p['production_identifiers']=['customer-123']
        p['production_paths']=['/srv/customer-data']
        self.assertEqual(decision(event('gcloud sql databases create app --project customer-123'),policy=p),'deny')
        self.assertTrue(guard.protected('/srv/customer-data/db','/',p))

    def test_session_scope_and_invalid_events(self):
        scoped=copy.deepcopy(POLICY)
        scoped['session_ids']=['test-session']
        self.assertEqual(decision(event(session_id='another-task'),policy=scoped),'allow')
        self.assertEqual(decision(event('gcloud auth login',session_id='another-task')),'deny')
        for changes in [{'session_id':None},{'session_id':''},{'tool_input':[]},{'cwd':None},{'hook_event_name':'invalid'}]:
            self.assertEqual(decision(event(**changes)),'deny')
        self.assertEqual(decision(event(tool_name='write_stdin',tool_input={'chars':'rm -rf /\n'})),'deny')

    def test_connector_calls_and_secrets(self):
        self.assertEqual(decision(event(tool_name='mcp__db__update',tool_input={'environment':'production','table':'users'})),'deny')
        self.assertEqual(decision(event(tool_name='mcp__cloud__login',tool_input={})),'deny')
        self.assertEqual(decision(event('echo api_key=secretvalue')),'deny')
        self.assertEqual(decision(event('echo apikey_'+'a'*40)),'deny')
        # Unknown connectors cannot skip Jev.
        self.assertEqual(decision(event(tool_name='mcp__files__read',tool_input={'path':'README.md'})),'allow')
        self.assertEqual(decision(event(tool_name='mcp__files__read',tool_input={'path':'README.md'}),lambda *a:{}),'deny')

    def test_jev_denial_uncertainty_invalid_responses(self):
        for value in [None,{}, {'answers':{}}, {'answers':None}]:
            self.assertEqual(decision(event(),lambda *a:value),'deny')
        for name in guard.QUESTIONS:
            for change in [{'choice':'deny'},{'choice':'uncertain'},{'confidence':0.5},
                           {'confidence':float('nan')},{'confidence':True},
                           {'probabilities':{'allow':0.8,'deny':0.1,'uncertain':0.1}},
                           {'probabilities':{'allow':1,'deny':1,'uncertain':0}},
                           {'probabilities':{'allow':True,'deny':0,'uncertain':0}}]:
                r=good_response(); r['answers'][name].update(change)
                self.assertEqual(decision(event(),lambda *a:r),'deny')

    def test_missing_key_is_denied(self):
        def absent(p): raise FileNotFoundError()
        r=guard.evaluate(event(),POLICY,lambda *a:good_response(),absent)
        self.assertEqual(r['hookSpecificOutput']['permissionDecision'],'deny')

    def test_api_request_shape_and_no_target_read(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self,n): return json.dumps(good_response()).encode()
        with patch('urllib.request.build_opener') as build:
            build.return_value.open.return_value=Response()
            with patch.object(Path,'read_text',side_effect=AssertionError('must not read files')):
                guard.request_jev(event('cat README.md'),POLICY,'fake')
            request=build.return_value.open.call_args.args[0]
            payload=json.loads(request.data)
            self.assertEqual(request.full_url,guard.ENDPOINT)
            self.assertEqual(set(payload['questions']),set(guard.QUESTIONS))
            self.assertNotIn('session_id',payload['state']['proposed_action'])

    def test_process_contract(self):
        script=str(Path(__file__).parent/'guard.py')
        for body in ['not json',json.dumps(event('gcloud auth login')), 'x'*(guard.LIMIT+1)]:
            p=subprocess.run([sys.executable,script],input=body,text=True,capture_output=True,timeout=5)
            self.assertEqual(p.returncode,0)
            self.assertEqual(json.loads(p.stdout)['hookSpecificOutput']['permissionDecision'],'deny')
            self.assertEqual(p.stderr,'')

if __name__ == '__main__':
    unittest.main(verbosity=2)
