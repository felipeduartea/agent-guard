# Security model and limitations

This is an experimental policy gate, not an adversarially proven reference monitor.

- Shell parsing is deliberately limited and executable behavior is not attested.
  General-development and production-safe permit scripts and build tools to reach
  Jev even without their source. Only strict-execution blocks them categorically.
  Shell startup files, PATH resolution, Git helpers/configuration, symlink races and
  persistent sessions can change an operation's effects after evaluation.
- Tool hooks are not filesystem/syscall hooks. A permitted program may read files
  internally. Hosted tools, injected terminal input and specialized paths may not
  call PreToolUse. Other configured hooks execute independently.
- Jev decisions are probabilistic. Structured types guarantee neither accuracy nor
  resistance to prompt injection. Four passing examples do not establish a security
  error rate. Test with your own policies and workloads before relying on it.
- Handled runtime/API failures deny, but some agent runtimes skip untrusted hooks
  or proceed after engine-level errors/timeouts. Keep platform safeguards enabled.
- The guard and policy are owned by the same OS user as the agents. The fixed path
  protections are best-effort; they do not make the files tamperproof.
- Proposed tool arguments are sent to TypeSafe. Secret detection is incomplete.
  Review their data handling terms for your use case before enabling the integration.
- Production identities are user-supplied and heuristically matched. Read-only
  production credentials are stronger protection than a command classifier.

For stronger guarantees use a separate identity, least-privilege credentials, an OS
sandbox and an exclusive broker for file/command operations. Do not weaken those
controls because this hook is installed.

Report issues to the repository owner without attaching API keys, customer data or
unredacted tool arguments. Rotate an exposed key through your provider's console.
