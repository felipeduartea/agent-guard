# Security model and limitations

This is an experimental policy gate, not an adversarially proven reference monitor.

- The guard inspects bounded local entrypoint source, not imports or complete
  transitive behavior. Missing source is recorded as a collection gap, not an automatic
  block. Tests/builds are evaluated by visible intent and arguments. This deliberately
  accepts the risk of hidden behavior in dependencies; keep OS restrictions and
  least-privilege credentials in place.
- Shell parsing is deliberately limited and executable behavior is not attested.
  Shell startup files, PATH resolution, Git helpers/configuration, symlink races and
  persistent sessions can change an operation's effects after evaluation.
- Tool hooks are not filesystem/syscall hooks. A permitted program may read files
  internally. Hosted tools, injected terminal input and specialized paths may not
  call PreToolUse. Other configured hooks execute independently.
- Outcome examples are model guidance, not deterministic enforcement. Semantically
  conflicting examples cannot be fully validated locally; the evaluator is instructed
  to prioritize prohibitions and flag concrete ambiguous hazards. Allowed examples never skip fixed checks.
- Jev decisions are probabilistic. Structured types guarantee neither accuracy nor
  resistance to prompt injection. Four passing examples do not establish a security
  error rate. Test with your own policies and workloads before relying on it.
- Handled runtime/API failures deny, but some agent runtimes skip untrusted hooks
  or proceed after engine-level errors/timeouts. Keep platform safeguards enabled.
- The guard and policy are owned by the same OS user as the agents. The fixed path
  protections are best-effort; they do not make the files tamperproof.
- Proposed tool arguments, inspected entrypoint source, and literal read-target
  metadata/secret-scan flags are sent to TypeSafe. Small ordinary local read targets
  may be scanned locally; target contents are not uploaded. The scan recognizes
  only known patterns and cannot establish that a file contains no secrets. Secret detection is incomplete.
  Review their data handling terms for your use case before enabling the integration.
- Production targets and restrictions must be described in the trusted policy.
  Read-only production credentials provide stronger protection than a classifier.

For stronger guarantees use a separate identity, least-privilege credentials, an OS
sandbox and an exclusive broker for file/command operations. Do not weaken those
controls because this hook is installed.

Report issues to the repository owner without attaching API keys, customer data or
unredacted tool arguments. Rotate an exposed key through your provider's console.

Uncertainty can reach a native Claude permission prompt. An explicit policy denial,
fixed emergency check or evaluation failure cannot. Codex/Devin receive a blocking
fallback for review requests; an unsupported `ask` response is never sent to them.
