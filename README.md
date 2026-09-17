# Jev Agent Guard

A conservative pre-tool guard for **Codex, Claude Code and Devin CLI**, including
these agents launched inside **cmux**. It combines fixed rules with TypeSafe's Jev
API to check proposed actions before supported tools run.

**Experimental guardrail, not an OS security boundary.** It cannot intercept every
file access, existing terminal input, hosted tool or subprocess. Jev can make an
incorrect decision. Use read-only production credentials and an OS sandbox for
stronger enforcement.

## What it blocks

- Production mutations and remote writes with an unknown target environment.
- Login, logout and identity changes, including `gcloud auth login`, application-default
  login, AWS SSO, Azure login and similar operations.
- Known destructive commands and edits to system, credential and guard paths.
- Opaque execution: Python, Node, shell scripts, npm, make, raw database/HTTP clients,
  and similar tools whose effects the hook cannot inspect.
- Actions Jev rejects or considers uncertain, plus handled API/key/runtime errors.

The opaque-execution restriction is intentionally broad and **will interrupt normal
development workflows**, including tests and builds. This is a conservative starting
policy, not a transparent drop-in security product. Supported local reads and edits
remain eligible for Jev review.

## Install

Requirements: macOS or Linux, Python **3.10+**, one of the supported CLIs, and a
[TypeSafe API key](https://console.typesafe.ai). No third-party Python packages.
Windows and remote/cloud agent environments are not supported by this installer.

Clone this repository and enter its directory. For a private repository, other
people first need repository access.

```sh
# Run the offline tests.
python3 -m unittest discover -v

# Preview which installed CLIs would be configured.
python3 install_multi.py --dry-run

# Install for detected CLIs, or select them explicitly:
python3 install_multi.py --clients codex claude devin

# Enter the key privately; it is not displayed or put in command history.
python3 ~/.codex/guards/jev/set_key.py
```

The installer preserves unrelated settings/hooks, backs up modified files, and
copies the runtime outside the cloned repository to `~/.codex/guards/jev/`.
It works on a fresh machine; no previous guard installation is required.
The key remains in an owner-only file. Alternatively, supply `TYPESAFE_API_KEY`
to the agent's environment. GUI applications may not inherit terminal variables.

**Activation is a separate step:** restart/reload the agents. In Codex, review and
trust the new hook using `/hooks`; untrusted hooks are skipped. Use `/hooks` in
Claude and Devin to inspect loaded hooks. The installer cannot prove that a running
agent has reloaded its configuration. Until activation is verified, do not assume
the guard is protecting that session. A loaded guard without a working key blocks
all otherwise-eligible calls.

cmux needs no separate hook: the agents inside it load the above user settings.
Commands you type manually in the terminal are unaffected.

## Configure your production targets

Edit the **installed** `~/.codex/guards/jev/policy.json` in your own editor:

```json
{
  "production_identifiers": ["company-prod-project", "db.production.example.com"],
  "production_paths": ["/srv/production-data"],
  "session_ids": []
}
```

These are fields to change in the existing policy, not a replacement policy file.
An empty session list covers all local sessions. Exact identifiers strengthen fixed
matching; names containing `prod`, `production`, `prd` or `live` are also checked.
Unknown remote writes are conservatively blocked even without identifiers.
Updates preserve your installed policy and key; the installer enables all-session
scope by clearing `session_ids`.

The initial Jev thresholds are allow probability 0.99 and confidence 0.90 for every
question. These are starting values, **not calibrated security error rates**.

## What leaves your machine

Eligible calls send their tool name, proposed arguments, working directory and policy
to `https://api.typesafe.ai/v1/systemone`. Arguments may contain source/patch text or
other private information. The guard does not read target files or chat transcripts
for evaluation. Basic secret-pattern detection blocks some obvious credentials;
it cannot identify every secret. There is no raw-command audit log or decision cache.
Jev requests incur your account's API usage.

## Update and uninstall

After updating your clone, rerun the installer with the same client selection.
Review changed hooks and restart clients again as needed. Backups and a file-hash
manifest live under the installed guard directory.

```sh
python3 install_multi.py --uninstall --clients codex claude devin --dry-run
python3 install_multi.py --uninstall --clients codex claude devin
```

Uninstall removes only this guard's configured handlers, preserving unrelated
hooks. It deliberately retains the guard directory, API key and backups for manual
cleanup. Restart the agents after uninstalling.

## How it works

`PreToolUse → normalize tool input → fixed rules → Jev → deny or defer`

The handler never executes the proposed command. A denial exits 2 with a reason on
stderr. Passing exits 0 without an explicit approval, preserving the client's own
permission/sandbox checks. Missing/invalid input and handled failures deny. The
launcher converts startup failure to a blocking exit, but a client that skips a
hook or ignores its timeout can still bypass this layer.

See [integration details](INTEGRATIONS.md) and [security limitations](SECURITY.md).
The tests simulate dangerous actions; they never execute them. They validate rules,
adapters and installers, not complete enforcement by every agent version.

Sources: [TypeSafe API](https://docs.typesafe.ai/api),
[Codex hooks](https://learn.chatgpt.com/docs/hooks),
[Claude hooks](https://code.claude.com/docs/en/hooks),
[Devin hooks](https://docs.devin.ai/cli/extensibility/hooks/overview).
