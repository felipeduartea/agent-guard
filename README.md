# Agent Guard

Agent Guard checks proposed actions with TypeSafe's Jev before supported agent tools
run. It works with Codex, Claude Code and Devin CLI, including agents launched inside
cmux.

**One safety policy, customized with plain-language rules and examples.** There are
no presets or policy packs to choose from.

The default protects important files, credentials and system security, prohibits
login/account changes and production writes, and permits bounded local development.
Small fixed emergency checks run first; Jev then evaluates the command, tool arguments
and available script context. An allowed example never overrides a prohibition.

This is experimental. It is not an OS sandbox, and it cannot intercept every file
access or subprocess. Keep native permissions and sandboxing enabled.

## Install from scratch

Requirements: macOS or Linux, Python 3.10+, a supported agent CLI, repository access,
and a [TypeSafe API key](https://console.typesafe.ai). No Python dependencies to install.

```sh
git clone https://github.com/felipeduartea/agent-guard.git
cd agent-guard

python3 install_multi.py --clients codex --dry-run
python3 install_multi.py --clients codex

# Enter the key privately; it is not printed or stored in shell history.
python3 ~/.codex/guards/jev/set_key.py
```

For all three agents use `--clients codex claude devin`. Omit `--clients` to select
installed CLIs automatically. cmux needs no separate installation; its agents use
these configurations. Manual terminal commands are not intercepted.

Restart the agent after installation. In Codex, open `/hooks` and review/trust the
Jev `PreToolUse` hook before testing. Untrusted hooks are skipped. See
[INTEGRATIONS.md](INTEGRATIONS.md) for client configuration paths and activation.

The installer copies the runtime to `~/.codex/guards/jev/`, preserves unrelated hooks,
and backs up files it changes. The key is stored at
`~/.codex/guards/jev/typesafe.key` with owner-only permissions. Alternatively, supply
`TYPESAFE_API_KEY` in the agent's environment; GUI apps may not inherit shell variables.

## Customize the policy

Edit `~/.codex/guards/jev/policy.json`. Add your requirements to `rules` and your
illustrative outcomes to `examples.allowed` or `examples.blocked`, keeping the rest
of the file. For example, append:

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

This is a fragment to merge, not a replacement policy file. Rules and examples are
trusted configuration; instructions inside proposed commands or source code cannot
override them. Every enabled Jev check must meet the configured allow probability
and confidence thresholds. Denial, uncertainty, invalid responses or exhausted API
retries block the action. Passing the guard does not override the agent's own permissions.

The complete starting configuration is [policy.json](policy.json). `session_ids: []`
applies to all local sessions; a nonempty list limits the guard to those session IDs.
There are no command-list add-ons. Describe custom restrictions in your rules.

## Test

```sh
# Offline validation; no API key required.
python3 -m unittest discover -v

# Live checks through an isolated copy of the hook; uses your Jev API key.
python3 smoke_test.py --extended
```

The live test submits twelve proposals but **never executes them**. It prints a result
for each case and exits nonzero if any expectation fails. A service outage does not
count as a successful dangerous-action rejection.

This tests the hook subprocess, not whether your agent loads it. To check actual
interception, use a disposable workspace, add a temporary natural-language rule that
forbids creating one harmless filename, then ask the agent to create that file and a
permitted file separately. Check for an actual hook rejection; the agent declining
on its own is not evidence. Never use real destructive operations as live probes.

See [EVALUATION.md](EVALUATION.md) for recorded results and the known harmless-read
false positive. The tests do not establish a security error rate.

## What is inspected and sent to Jev

Eligible requests send the policy, tool arguments, working directory and collected
context to TypeSafe. Arguments may already contain private source or patch text.
The guard inspects up to three local entrypoint scripts, 32 KiB each, and sends their
contents and hashes. Sensitive-looking, missing, oversized and outside-workspace
scripts block before contacting Jev.

Literal Python `Path(...).read_text()` / `read_bytes()` candidates may contribute
path metadata. Up to twelve small ordinary local targets can also be scanned locally
for known secret patterns; only scan flags and metadata are sent, never target data.
The scanner excludes sensitive paths, symlinks and nonregular or oversized targets.
It does not detect every secret or fully analyze Python behavior.

Imports, shell startup files, runtime inputs and subprocess dependencies are not
fully resolved. Package/build/container launchers such as `npm test` currently block
because the guard cannot inspect their dependency execution. Other opaque behavior
still relies on Jev recognizing uncertainty. See [SECURITY.md](SECURITY.md).

Transient API errors get at most one retry sharing the existing API budget. There is
no retry of a policy decision to seek approval. Errors distinguish HTTP status,
network/timeout, key, response validation and policy-score failures without logging
raw API bodies or credentials. API usage is billed to your TypeSafe account.

## Update or uninstall

For an existing **version-3 policy**, pull the repository and rerun the installer with
the same clients. Your policy and key are preserved. Restart/review hooks afterward.

**Older version-1/2 installations are not automatically migrated.** The installer
stops before changing any files. Their installed runtime continues to work unchanged.
Before updating one, back up its guard directory and client configurations, explicitly
review the current [policy.json](policy.json), carry custom requirements into rules
and examples, and replace the installed policy with that reviewed version-3 policy.
Then rerun the installer. Changing only the version number is not a migration.
Previous implementations remain available in Git history, not the current runtime.

```sh
python3 install_multi.py --uninstall --clients codex --dry-run
python3 install_multi.py --uninstall --clients codex
```

Uninstall removes only this guard's hooks. It retains the runtime, key and backups;
restart the client afterward. Remote/cloud agent environments and Windows are not
supported by this installer.
