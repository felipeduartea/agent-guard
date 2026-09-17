# Agent Guard

A conservative pre-tool guard for **Codex, Claude Code and Devin CLI**, including
these agents launched inside **cmux**. It combines fixed rules with TypeSafe's Jev
API to check proposed actions before supported tools run.

**Experimental guardrail, not an OS security boundary.** It cannot intercept every
file access, existing terminal input, hosted tool or subprocess. Jev can make an
incorrect decision. Use read-only production credentials and an OS sandbox for
stronger enforcement.

## Choose a policy

New installations default to **general-development**. Every preset includes a baseline
against system destruction, credential exposure and guard tampering. Passing fixed checks
still requires Jev evaluation and the agent's normal permissions.

| Preset | Optional restrictions included | Ordinary Python/npm/make |
| --- | --- | --- |
| `general-development` (default) | None | Eligible for Jev review |
| `production-safe` | Production read-only; no authentication changes | Eligible for Jev review |
| `strict` | Production read-only; no authentication changes; strict execution | Blocked |

Packs are additive: `production-read-only`, `no-auth-changes`, `strict-execution`,
and `protected-paths`. The baseline always applies. Configurable add-ons can deny
specific tools, command prefixes and paths, and add Jev instructions. There are no
allow overrides: any fixed denial wins, even if Jev would approve.

General development trades strict execution restrictions for usability. Allowing a
script does not prove that everything it does is safe. It is not a syscall sandbox.
Existing version-1 installations retain their strict behavior and policy unchanged.

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
python3 install_multi.py --clients codex claude devin --preset general-development

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

## Customize with policy packs and add-ons

Edit the **installed** `~/.codex/guards/jev/policy.json` in your own editor:

```json
{
  "preset": "general-development",
  "packs": ["production-read-only", "no-auth-changes", "protected-paths"],
  "production_identifiers": ["company-prod-project", "db.production.example.com"],
  "production_paths": ["/srv/production-data"],
  "protected_paths": [{"path": "/srv/customer-data", "access": "read-only"}],
  "addons": [{
    "name": "team-publishing",
    "instructions": "Never publish packages or push repository changes.",
    "deny_command_prefixes": [["git", "push"], ["npm", "publish"]],
    "deny_tools": ["mcp__deployment__publish"]
  }]
}
```

Merge these fields into the installed version-2 policy; do not replace the entire file.
Complete configurations are in [examples](examples). Only enabled packs contribute
Jev questions and restrictions. Protected paths also apply when specified directly or
inside an add-on: `read-only` denies writes, while `deny` denies reads and writes.
Overlapping path rules take the most restrictive result. Paths must be absolute or
start with `~/`. Command prefixes are arrays of literal command/argument tokens;
no executable plugin or arbitrary regex is loaded. Fixed matching is best-effort,
not a complete shell parser. Unknown fields/packs and invalid values are rejected.

For a fresh installation, select presets/packs on the command line:

```sh
python3 install_multi.py --clients claude --preset production-safe
python3 install_multi.py --clients codex --preset general-development --pack no-auth-changes
python3 install_multi.py --clients devin --preset strict
```

Existing policies are preserved **byte-for-byte**, including session scope and key
location. The installer refuses preset/pack flags when a policy already exists;
change that policy explicitly in your editor instead. Version 1 remains supported
with its original strict semantics. To adopt version 2 deliberately, start from a
complete example and retain your key location, session IDs and production targets.

An empty `session_ids` array means all local sessions. Production targets are enforced
when `production-read-only` is enabled; that pack also conservatively blocks unknown
remote mutations. User instructions in add-ons cannot override fixed prohibitions.

New general-development installations start at allow probability 0.95 and confidence
0.90 for every question. The installer uses 0.99 allow probability when selecting
production-safe or strict; their complete examples also use 0.99. Edit these fields
explicitly to customize them. These are starting values, **not calibrated security error rates**.

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
