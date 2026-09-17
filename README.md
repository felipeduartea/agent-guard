# Agent Guard

A conservative pre-tool guard for **Codex, Claude Code and Devin CLI**, including
these agents launched inside **cmux**. It combines fixed rules with TypeSafe's Jev
API to check proposed actions before supported tools run.

**Experimental guardrail, not an OS security boundary.** It cannot intercept every
file access, existing terminal input, hosted tool or subprocess. Jev can make an
incorrect decision. Use read-only production credentials and an OS sandbox for
stronger enforcement.

## Describe outcomes, not command names

New users can write plain-language rules and examples in their installed `policy.json`.
No command list is required. For example, merge these fields into your version-2 policy:

```json
{
  "rules": [
    "Never change production data.",
    "Never initiate login or switch identities."
  ],
  "examples": {
    "allowed": [
      "Read production logs using an existing session.",
      "Edit local application code.",
      "Run local tests."
    ],
    "blocked": [
      "Delete customer records from production.",
      "Upload replacement data to a production database.",
      "Start a Google Cloud login flow."
    ]
  }
}
```

Jev evaluates the proposed outcome against the rules and examples, including unfamiliar
commands and non-shell tools. Examples are illustrative, not exact string matches.
Each written rule gets a separate check, plus a check against the examples. Every check
must pass the configured thresholds. An allowed example never overrides a prohibition;
conflicting interpretations are blocked or marked uncertain. Exactly identical allowed
and blocked examples are rejected during configuration validation.

The fresh-install default protects personal files, system security and credentials, blocks login/account changes and production writes, and permits bounded local development. Customize its outcome rules and examples without maintaining a command list.
The production/authentication restrictions above are **optional**, not silently enabled
for everyone. [outcomes-only.json](examples/outcomes-only.json) is a complete example of
that policy with no command denylist or fixed production/authentication pack.

A small built-in safety layer still rejects obvious dangerous system operations,
guard tampering and detected credential material before calling Jev. Outcome matching
is probabilistic and cannot reveal a script's hidden behavior. Eligible actions are
sent to Jev; this is not a rules-only or zero-API mode.

Known limitation: the live smoke check still falsely blocked an allowed production-log
read. See [evaluation results](EVALUATION.md). Examples improve configuration ergonomics;
they do not eliminate false positives or prove enforcement accuracy.

## Optional presets and deterministic restrictions

New installations default to **machine-safety**, using outcome rules and examples plus bounded local script inspection. Every preset includes a baseline
against system destruction, credential exposure and guard tampering. Passing fixed checks
still requires Jev evaluation and the agent's normal permissions.

| Preset | Optional restrictions included | Ordinary Python/npm/make |
| --- | --- | --- |
| `machine-safety` (default) | None | Inspected entrypoint scripts eligible; unresolved build/package execution blocked |
| `general-development` | None | Eligible for Jev review without source inspection |
| `production-safe` | Production read-only; no authentication changes | Eligible for Jev review |
| `strict` | Production read-only; no authentication changes; strict execution | Blocked |

Packs are additive: `production-read-only`, `no-auth-changes`, `strict-execution`,
and `protected-paths`. The baseline always applies. These packs are optional; ordinary users can stay with
plain-language rules and examples. Advanced add-ons can deny
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

## Advanced: policy packs and deterministic add-ons

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
Complete configurations are in [examples](examples). Only enabled packs contribute pack-specific Jev questions and restrictions. Written
rules and examples contribute their own questions regardless of the chosen preset. Protected paths also apply when specified directly or
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

New machine-safety and general-development installations start at allow probability 0.95 and confidence
0.90 for every question. The installer uses 0.99 allow probability when selecting
production-safe or strict; their complete examples also use 0.99. Edit these fields
explicitly to customize them. These are starting values, **not calibrated security error rates**.

## What leaves your machine

Eligible calls send their tool name, proposed arguments, working directory and policy
to `https://api.typesafe.ai/v1/systemone`. Arguments may contain source/patch text or
other private information. With `inspect_scripts: true` (the new default), the guard
reads and sends up to three local entrypoint scripts, at most 32 KiB each, with their
hashes. It rejects missing, oversized, sensitive-looking and outside-workspace scripts
before contacting Jev. It does not read chat transcripts. Basic secret-pattern detection blocks some obvious credentials;
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

## Machine-safety inspection limits

The default judges effects from rules and examples, with a small fixed emergency
baseline. You do not need to enumerate every dangerous command. The source collector
recognizes common interpreters; its command dispatch is implementation plumbing,
not your safety policy.

Only entrypoint source is inspected. Imports, shell startup files, PATH replacements,
runtime inputs and subprocess dependencies are not resolved or attested. Package,
build and container launchers currently block before Jev because their dependencies
cannot be inspected; this includes `npm test`. This conservative first version is
not yet transparent for every development workflow. Other opaque commands still
depend on Jev recognizing insufficient context; no model can guarantee that.

The hook cannot prevent a permitted process from performing unobserved operations,
and files can change between checking and execution. Keep OS sandboxing and native
agent permissions enabled. Existing installed policies are preserved during updates;
the machine-safety default applies to fresh installs.

## Try the hook safely

Run `python3 smoke_test.py` after configuring your key. It calls Jev through an
isolated copy of the hook and prints pass/fail for five proposals; it never runs
those commands. It does not prove that your agent is loading the hook.

**Current status:** 59 offline tests pass. The latest live extended run matched 11/12
expectations, including all five original smoke cases. A harmless Python file read
still over-blocked; an earlier run encountered HTTP 529 from Jev. This remains an
experimental gate. See [EVALUATION.md](EVALUATION.md) for the full results.

Use `python3 smoke_test.py --extended` for additional source and outcome variations.
Service failures do not count as successful dangerous-action rejections. Hook errors
now distinguish missing/invalid keys, HTTP status, timeout, network and response
validation failures. Policy rejections show the evaluated rule, choice, allow score,
confidence and required thresholds. No raw API response or exception text is logged.

## Transient errors and local read context

The API client makes at most two attempts for HTTP 429/500/502/503/504/529,
timeouts and connection failures represented as transient transport errors. Attempts
share the configured API time budget; retry delay starts at 0.2 seconds. A numeric
Retry-After is honored only when it fits the remaining budget. Authentication errors,
invalid responses and policy judgments are never retried. Exhaustion still blocks.

For literal `Path("...").read_text()` / `read_bytes()` candidates in Python source,
the collector supplies path locality and file metadata. Up to 12 small ordinary
regular local targets (32 KiB each) can also be scanned locally for known secret
patterns. Their contents are never uploaded; only metadata and scan flags are sent.
Sensitive paths, symlinks, oversized and nonregular targets are not scanned. This
is limited syntactic inspection, not complete Python analysis or proof that data
is non-sensitive. Rebound names and source behavior still require Jev review.

The latest local-read fixture still blocked at allow probability 0.94 (required 0.95),
with confidence 0.91. Better context improved its scores but has not eliminated this
false positive. Thresholds remain unchanged.
