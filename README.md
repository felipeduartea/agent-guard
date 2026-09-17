# Agent Guard

Agent Guard uses TypeSafe's Jev to check actions before supported tools run in Codex,
Claude Code or Devin CLI. It also works when you launch those agents inside cmux.

You configure it with plain-language rules and examples. The default policy protects
important files, credentials and system security, blocks login/account changes and
production writes, and allows local development work whose effects can be assessed.
Fixed emergency checks run first. Jev then reviews the command, tool arguments and
available script context.

The guard is experimental and can reject harmless actions. It cannot intercept every
file access or subprocess, so keep the agent's permissions and OS sandbox enabled.

## Install

You need macOS or Linux, Python 3.10+, a supported agent CLI, access to this repository,
and a [TypeSafe API key](https://console.typesafe.ai). The guard uses Python's standard
library.

```sh
git clone https://github.com/felipeduartea/agent-guard.git
cd agent-guard

python3 scripts/install_multi.py --clients codex --dry-run
python3 scripts/install_multi.py --clients codex

# Enter the key privately; it is not printed or stored in shell history.
python3 ~/.codex/guards/jev/set_key.py
```

Use `--clients codex claude devin` to install for all three agents, or omit `--clients`
to detect installed CLIs. Agents inside cmux use the same configuration. Commands you
type directly into a terminal are unaffected.

Restart the agent. In Codex, open `/hooks` and review and trust the Jev `PreToolUse`
hook; Codex skips untrusted hooks. Client configuration paths and activation details
are in [INTEGRATIONS.md](docs/INTEGRATIONS.md).

The installer copies the runtime to `~/.codex/guards/jev/`, preserves unrelated hooks,
and backs up files it changes. The key is stored at
`~/.codex/guards/jev/typesafe.key` with owner-only permissions. Alternatively, supply
`TYPESAFE_API_KEY` in the agent's environment; GUI apps may not inherit shell variables.

## Customize the policy

Edit `~/.codex/guards/jev/policy.json`. Add restrictions to `rules` and examples to
`examples.allowed` or `examples.blocked`. Keep the other fields. For example, merge
these entries into the existing lists:

```json
{
  "rules": [
    "Never modify the customer data stored under /srv/customers.",
    "Do not publish releases or push commits to a remote repository."
  ],
  "examples": {
    "allowed": ["Read application source and edit local tests."],
    "blocked": ["Upload a release artifact to a public registry."]
  }
}
```

The full configuration is in [policy.json](config/policy.json). `session_ids: []` applies
to all local sessions; fill the list to limit the guard to specific session IDs.

Rules take precedence over allowed examples and instructions embedded in commands or
source code. Every Jev check must meet the configured allow probability and confidence
thresholds. Denial, uncertainty, invalid responses or exhausted API retries block the
action. A passing result still leaves the agent's own permissions in effect.

## Test

```sh
# Offline validation; no API key required.
python3 -m unittest discover -v

# Live checks through an isolated copy of the hook; uses your Jev API key.
python3 scripts/smoke_test.py --extended
```

The live test sends twelve proposals through a copy of the hook without executing
them. It reports each result and exits nonzero if any expectation fails. Service
outages count as failures, even if they prevent a dangerous proposal from running.

To verify that an agent loads the hook, use a disposable workspace. Add a temporary
rule forbidding one harmless filename, then ask the agent to create that file and a
permitted file in separate calls. Look for a hook rejection in the tool result. The
agent refusing on its own does not prove interception. Use harmless probes only.

[EVALUATION.md](docs/EVALUATION.md) records the results, including a harmless file read that
still gets blocked. These tests do not establish a security error rate.

## What leaves your machine

TypeSafe receives the policy, tool arguments, working directory and collected context.
Arguments can contain private source or patches. The guard also reads up to three local
entrypoint scripts, at most 32 KiB each, and sends their contents and hashes. It blocks
missing, oversized, sensitive-looking or outside-workspace scripts before contacting Jev.

For literal Python `Path(...).read_text()` / `read_bytes()` calls, the guard can collect
path metadata and scan up to twelve small local files for known secret patterns.
Only metadata and scan results are sent; those files' contents stay local. The scanner
skips sensitive paths, symlinks, oversized files and files that are not regular files.
It cannot detect every secret or fully analyze Python behavior.

The guard does not fully resolve imports, shell startup files, runtime inputs or
subprocess dependencies. It currently blocks package, build and container launchers
such as `npm test` because it cannot inspect everything they execute. For other unclear
behavior, it relies on Jev recognizing uncertainty. [SECURITY.md](docs/SECURITY.md) describes
these limits.

Transient API errors get one retry at most, within the existing time budget. Policy
decisions are not retried. Error messages distinguish HTTP, network, timeout, key,
response-validation and policy-score failures without logging raw API bodies or
credentials. TypeSafe bills API usage to your account.

## Update or uninstall

For a version-3 installation, pull the repository and rerun the installer with the
same clients. It preserves your policy and key. Restart the agent and review its hooks.

The installer stops before changing a version-1/2 installation, which continues to
run its existing copy. To migrate, back up the guard directory and client configs.
Review the current [policy.json](config/policy.json), transfer your custom requirements into
its rules and examples, then use it to replace the installed policy and rerun the
installer. Changing the version number alone is not enough. Older implementations
are available in Git history.

```sh
python3 scripts/install_multi.py --uninstall --clients codex --dry-run
python3 scripts/install_multi.py --uninstall --clients codex
```

Uninstall removes only this guard's hooks. It retains the runtime, key and backups;
restart the client afterward. Remote/cloud agent environments and Windows are not
supported by this installer.

## Repository layout

- `runtime/`: hook, evaluator and inspection code copied into an installation.
- `scripts/`: installer, key setup and live smoke test.
- `config/`: default policy.
- `tests/`: offline tests.
- `docs/`: integration details, security limits and evaluation results.
