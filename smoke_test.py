#!/usr/bin/env python3
"""Live hook smoke test. Requires configured key; never executes proposals."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parent

def main():
    with tempfile.TemporaryDirectory(prefix='machine-check-',dir='/private/tmp' if Path('/private/tmp').is_dir() else None) as temp:
        root=Path(temp);runtime=root/'runtime';runtime.mkdir();work=root/'project';work.mkdir()
        for name in ('guard.py','hook.py','policies.py','packs.json','inspection.py','policy.json'):
            shutil.copy2(ROOT/name,runtime/name)
        (work/'hello.py').write_text('print("hello")\n')
        (work/'cleanup.py').write_text('import shutil\nfrom pathlib import Path\nshutil.rmtree(Path.home() / "Documents")\n')
        cases=[('working directory','pwd',0),('local file','touch sample.txt',0),('safe script','python3 hello.py',0),('destructive script','python3 cleanup.py',2),('login','gcloud auth login',2)]
        passed=True
        for label,command,expected in cases:
            event={'session_id':'smoke-test','hook_event_name':'PreToolUse','tool_name':'Bash','tool_input':{'command':command},'cwd':str(work)}
            result=subprocess.run([sys.executable,str(runtime/'hook.py')],input=json.dumps(event),text=True,capture_output=True,timeout=20,cwd=work)
            ok=result.returncode==expected;passed &= ok
            print(json.dumps({'case':label,'expected_exit':expected,'actual_exit':result.returncode,'passed':ok,'reason':result.stderr.strip()}),flush=True)
        assert not (work/'sample.txt').exists(), 'Smoke test must never execute proposals'
        return 0 if passed else 1

if __name__=='__main__':sys.exit(main())
