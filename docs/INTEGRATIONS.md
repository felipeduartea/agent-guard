# Integrations

| Client | Configuration | Event |
| --- | --- | --- |
| Codex CLI / desktop | `~/.codex/hooks.json` | `PreToolUse`, all tools |
| Claude Code | `~/.claude/settings.json` | `PreToolUse`, all tools |
| Devin CLI | `~/.config/devin/config.json` | `PreToolUse`, all tools |
| cmux | Agent configurations above | No terminal-wide interceptor |

The shared `hook.py` adapts Devin's lowercase `exec`, `edit`, `write` and `read`
names to the common engine. Devin events without cwd use the actual hook working
directory; explicit absolute action cwd/workdir takes precedence. A persistent
shell's directory and environment may differ and are not fully visible.

Passing actions use exit 0 with no approval output, leaving normal client permissions
in place. Denied actions and evaluation failures use exit 2. The installer selects a
client adapter through `--client` on the hook command. Client hook configuration uses a 20-second timeout;
the adapter sets a 14-second internal deadline. Engine/API failures are caught;
client-level hook failure/skip semantics remain outside its control.

Devin imports Claude configuration by default. The same compatible command can be
present in both locations; clients that do not deduplicate it may check an action
twice. The installer does not disable imports or create a cache to bypass checks.

Installed cmux wrappers merge their lifecycle hooks with agent user configuration.
No bundled wrapper is patched and no permission/trust bypass flag is added by this
project. Existing cmux or user bypass settings remain the user's responsibility.

Restart clients after installing/updating. Codex requires hook trust review; use
`/hooks` to inspect loaded handlers. Nothing here installs into remote containers,
Devin Cloud or other hosts automatically.

Custom config roots, alternative CODEX_HOME values, managed-only hook policies and
configuration overrides can prevent these default user files from being loaded.
Verify the effective hook list in the specific client you use.

## Existing installations

The current runtime uses one version-3 outcome policy. The installer refuses older
policy versions before writing anything; it does not silently migrate or relax them.
Existing installed copies keep working independently of this repository. Review and
migrate explicitly using the README before updating an older installation.

## Human review

Uncertain or below-threshold decisions are distinct from explicit denials. All checks
are validated first; a later denial overrides an earlier request for review. Invalid
responses remain errors and cannot be approved through this hook.

For Claude Code, the adapter returns `permissionDecision: "ask"` for the proposed tool
call. It does not change tool arguments, grant approval, or write a remembered allow
rule. Use the native prompt's one-time approval when that is what you intend. This
requires the explicit Claude adapter and Claude's `permission_mode` input; lowercase
Devin tool aliases are excluded because Devin can import Claude settings. Calls that
cannot be identified conservatively stay blocked.

Codex currently parses `ask` but does not support it and may continue the tool call
as a failed hook. The Codex adapter therefore never emits `ask`; review requests exit
2 with the violated rule and scores. Devin and unknown clients use the same blocking
fallback. There is no custom chat-based approval or bypass-token mechanism.

Sources: [Codex hooks](https://learn.chatgpt.com/docs/hooks) and
[Claude PreToolUse decisions](https://code.claude.com/docs/en/hooks#pretooluse-decision-control).
The Claude output contract is tested offline; a live Claude approval prompt has not
been exercised by the test suite.
