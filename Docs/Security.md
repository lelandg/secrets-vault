# Security model

This document is the threat model for secrets-vault: what it protects
against, what it explicitly does not, and the invariants the code enforces
to back that up. It's written for anyone deciding whether to trust
secrets-vault with real credentials — read it before you do.

## What secrets-vault protects against

### 1. AI agent exfiltration

An AI coding agent (Claude Code or similar) working in a repo, or invoked
to help configure secrets-vault itself, can never read a secret value —
not through the CLI, not through the files on disk, not through logs.

- `registry.toml` and `state.toml`, the two files an agent can freely read
  and edit, contain **no secret material by construction** — names,
  descriptions, tags, target locations, and salted push-state hashes only.
- Every command an agent can meaningfully run non-interactively (`sv list`,
  `sv show`, `sv targets`, `sv plan`, `sv config check`, `sv apply
  --dry-run`) passes all of its output through a central redactor
  (`redact.py`) that strips any string that has ever been seen as a real
  secret value, in-process, before it reaches stdout, stderr, or a log
  file — even if a future code change accidentally tried to print one.
- Commands that touch real values (`sv set`, `sv apply` for a real push,
  entering a value in `sv tui`) require a passphrase read via `getpass()`
  gated on `sys.stdin.isatty()`. There is no flag, environment variable, or
  stdin-pipe path to supply the passphrase. An agent driving `sv`
  non-interactively hits `TTYRequiredError` before any prompt is even
  shown — it cannot unlock the vault by construction, not by convention.
- `sv generate` is the one deliberate exception: it prints a value, but
  that value is freshly random and was never stored anywhere before being
  printed. It is not a secret being retrieved — it's closer to `openssl
  rand`. If you don't want a generated value to enter an agent's context at
  all, generate it interactively in `sv tui` or `sv set --generate`
  instead.

This is covered by an executable audit test
(`tests/test_redaction_audit.py`) that seeds a real secret value and
asserts it never appears in the combined stdout+stderr of every
agent-reachable command.

### 2. Shoulder-surfing / casual over-the-shoulder exposure

- The TUI masks every value by default (`••••••••`). Revealing a value
  requires an explicit keypress (`r`), shows exactly one field at a time,
  and hides again on `Escape` or when you move the selection.
- Freshly generated values are shown once, deliberately, with a warning —
  after that they revert to masked, and re-revealing requires the same
  explicit action. This one-time display can be disabled entirely
  (`show_generated_secrets = false`), which requires interactive
  confirmation and a warning that generated values will then never be
  displayed anywhere, only retrievable via manual reveal.

### 3. Public-repo leaks

secrets-vault itself is designed to be developed and shared as a public
repository. All user-specific state — the registry, the vault, push state,
settings, logs — lives under `~/.config/secrets-vault/`, entirely outside
any git clone of the tool. As defense in depth (in case someone runs it
from an unusual working directory or copies files around), `.gitignore`
also blocks `.env*` (except `.env.example`), `*.age`, `registry.toml`,
`state.toml`, and `settings.toml` at the repo root.

### 4. Plaintext at rest

Secret values are stored exactly once at rest: in `vault.age`, encrypted
with a user-chosen passphrase using the age v1 format (via the `pyrage`
library — no external `age` binary required to read or write it, though
one can be used to inspect the file manually). The plaintext dict is
decrypted only in-process, on demand, and:

- In the CLI, it exists only for the duration of a single `sv set` / `sv
  apply` invocation, then the process exits.
- In the TUI, it's held in memory only for the session, dropped on exit,
  and only ever unlocked on the first operation that actually needs a
  value (not on TUI startup).

Writes to the vault go through a temp-file-then-atomic-rename
(`os.replace`), created with `0600` from the first `open()` call — there is
no window where a partially-written or world-readable vault file exists.

### 5. Insecure transit to remote hosts

Pushing a value to a remote target never touches a local plaintext file.
Env-file and systemd targets write over SSH stdin —
`ssh host 'umask 077 && cat > path.tmp && mv path.tmp path'` — so the
value travels only through the SSH-encrypted pipe and lands via an atomic
rename on the far end, at the configured mode (default `600`) and optional
owner. Command targets receive the value on the command's **stdin only**,
never as an argument — arguments are visible to every other process on the
machine via `ps`; stdin is not.

### 6. Accidental logging of values

All application errors are logged (per the project's own error-logging
rule), but the log handler is wrapped in a redacting filter
(`_RedactingFilter` in `redact.py`) that scrubs the message, any exception
text, and any stack-info text through the same value registry used for CLI
output, before a line is ever written to `logs/sv.log`.

## What secrets-vault does not protect against

Be clear-eyed about the boundary. secrets-vault raises the bar against
*structural* leakage (an agent, a script, a log file, a repo) — it is not a
defense against your own account or the machines you push to being
compromised.

- **A compromised user account.** If an attacker has your shell — your own
  session, not an agent operating within a boundary — they can run `sv set`
  or `sv tui` and type the passphrase themselves, or read the passphrase
  out of your terminal scrollback, shell history (it is never passed as an
  argument, so it won't land in `.bash_history`, but a compromised account
  can still just watch you type it), or a keylogger. TTY-gating stops
  *agents* and *non-interactive automation*; it does not stop a human (or
  malware acting as one) with control of your interactive session.
- **A keylogger or screen-recorder on your machine.** Nothing in
  secrets-vault defends against input/output capture at the OS level. If
  your machine is that compromised, the passphrase and any revealed value
  are visible the moment you type or view them, same as any other secret
  manager, browser password store, or `sudo` prompt.
- **A malicious or compromised remote host.** `sv apply` writes values to
  hosts you've configured as targets, over SSH you already trust (your own
  `~/.ssh/config`, your own keys). secrets-vault does not add any
  additional verification of a remote host's integrity beyond normal SSH
  host-key checking — if a target host is itself compromised, whatever
  value is written to it is exposed to whatever compromised it, exactly as
  it would be for any other tool that deploys secrets there.
- **Root or physical access to your machine.** Anyone with root (or disk
  access) on the machine running `sv` can, in principle, attach to the
  process while a value is decrypted in memory, or read `vault.age` and
  brute-force/guess a weak passphrase offline. Use a strong, unique
  passphrase; secrets-vault does not rate-limit or lock out passphrase
  attempts against the vault file itself (there is no server to do that
  against — it's a local encrypted file, same tradeoff as any passphrase-
  protected file format).
- **Vault backup exposure.** `vault_path` can point anywhere (Dropbox,
  etc.) because the file is encrypted — but that only holds as long as the
  passphrase itself stays secret and strong. Back up the encrypted file
  freely; don't back up the passphrase in the same place.

## Security invariants (enforced in code)

These are the concrete rules the implementation guarantees, summarized:

1. **TTY-only passphrase.** `read_passphrase()` (`vault.py`) checks
   `sys.stdin.isatty()` before ever calling `getpass()`; failing that check
   raises `TTYRequiredError` immediately. This is the single mechanism that
   makes agents structurally unable to unlock the vault or run `sv
   apply`/`sv set`.
2. **Values never leak.** Never in argv, logs, exceptions, CLI output, or
   temp files. Central redaction (`redact.py`) is exercised by
   `tests/test_redaction_audit.py`, which is the executable form of this
   invariant. Transit to remotes is SSH stdin, never `scp` of a plaintext
   local file. Command targets receive the value on stdin only.
3. **TUI masks by default.** Explicit keypress (`r`) reveals one field at a
   time; `Escape` or moving selection re-masks it.
4. **File hygiene.** Config dir `0700`; written files `0600` (or the
   configured `mode`); remote writes go through a temp file + atomic
   rename, never a partial write.
5. **Public-repo safety.** The clone contains only code, examples, docs,
   and the Claude Code skill. `.gitignore` blocks `.env*` (except
   `.env.example`), `*.age`, `registry.toml`, `state.toml`, and
   `settings.toml` as defense in depth, on top of all real state living
   outside the repo in `~/.config/secrets-vault/` in the first place.

## Reporting a concern

If you find a way for a secret value to reach CLI output, logs, or an
agent-visible file that isn't caught by `tests/test_redaction_audit.py`,
treat it as the leak it is: that test is meant to be the executable
contract for invariant 2 above, and a gap in it is a bug worth fixing in
both the code and the test.
