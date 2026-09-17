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

Every handler uses exit 2 to block, or exit 0 with no approval output to defer to
normal client permissions. Client hook configuration uses a 20-second timeout;
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
