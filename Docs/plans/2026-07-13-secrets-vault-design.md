# secrets-vault — Design Spec

**Date:** 2026-07-13
**Status:** Approved (brainstorming session with Leland)
**Repo:** public; all user-specific data lives outside the clone

## 1. Purpose

A secure, central TUI app + registry for managing secrets across machines.
Leland (or any user of the public repo) edits secret values in one place,
then pushes them to every location that needs them — remote env files over
SSH, systemd-managed services (with restart), and command-based targets like
`gh secret set` — via an explicit plan → confirm → apply flow.

AI agents (Claude Code etc.) participate with a hard boundary: **structure
yes, values never.** Agents can discover and register where secrets live,
inspect staleness, and compute plans — but can never read, set, or deploy
secret values.

## 2. Decisions made

| Decision | Choice |
|---|---|
| Storage at rest | Single `age` passphrase-encrypted vault file |
| Stack | Python 3.10+ / Textual TUI; `age` as system binary via subprocess |
| Push targets (v1) | Remote env files via SSH, systemd EnvironmentFile+restart, stdin command targets |
| Push flow | Plan → single confirm → apply (restarts included in the plan) |
| Agent access | Structure/plan only; values and apply require an interactive TTY |
| Config location | `~/.config/secrets-vault/` (XDG); nothing user-specific in the repo |
| Architecture | One Python package, three faces: `sv` CLI, `sv tui`, bundled Claude skill |

Rejected alternatives: GPG/pass-style per-file encryption (heavier key
management), OS keyring (flaky under WSL/headless), plaintext+perms (no
protection from same-user processes), glue over sops (weak UX, poor
public-repo reuse), unlock daemon (long-lived plaintext memory next to an
agent boundary; 2x code).

## 3. Data model

All under `~/.config/secrets-vault/` (created 0700):

### 3.1 `registry.toml` — plaintext structure, NO values (agent-read/writable)

```toml
[secrets.OPENAI_API_KEY]
description = "OpenAI key used by ImageAI and Maestro"
tags = ["ai", "chameleonlabs"]

[targets.hermes-maestro]
type = "env-file"                 # env-file | systemd | command
host = "hermes"                   # ssh alias from ~/.ssh/config
path = "/opt/maestro/.env"
format = "dotenv"                 # dotenv | env (KEY="value")
owner = "maestro:maestro"         # optional; chown after write
mode = "600"
keys = ["OPENAI_API_KEY", "DATABASE_URL"]
restart = ["sudo systemctl restart maestro"]   # optional, any commands

[targets.devbox-worker]
type = "systemd"
host = "devbox"
unit = "worker.service"           # apply = write EnvironmentFile + restart unit
path = "/etc/worker/env"
keys = ["QUEUE_TOKEN"]

[targets.gh-repo-secret]
type = "command"
host = "local"                    # "local" or an ssh alias
command = ["gh", "secret", "set", "OPENAI_API_KEY", "-R", "owner/repo"]
keys = ["OPENAI_API_KEY"]         # exactly one key; value piped on stdin
```

### 3.2 `vault.age` — age passphrase-encrypted JSON

```json
{ "OPENAI_API_KEY": { "value": "…", "updated_at": "2026-07-13T10:00:00Z" } }
```

Decrypted only in-process, on demand. Safe to back up anywhere (Dropbox etc.)
because it is encrypted; `vault_path` is configurable in `settings.toml`,
defaulting to the config dir.

### 3.3 `state.toml` — push state, no values

Per `(secret, target)`: a salted hash (HMAC-SHA256, random per-install salt
stored beside it) of the last-pushed value + timestamp. Enables "stale"
badges and `sv plan` without plaintext. Losing/deleting state is safe — the
worst case is everything shows stale.

### 3.4 `settings.toml` + `logs/`

Small app settings: `vault_path`, ssh options, generation defaults
(`generate_preset`, `generate_length`), and `show_generated_secrets`
(§7.1). Errors logged per-run to `logs/` with values redacted
(all-errors-logged rule).

## 4. Security invariants (enforced in code, documented in README)

1. **TTY-only passphrase.** The vault passphrase is read exclusively from an
   interactive TTY (`getpass` after an `isatty` check). No flag, no env var,
   no stdin pipe. This is the mechanism that makes agents structurally
   unable to unlock the vault or run `sv apply`/`sv set`.
2. **Values never leak.** Never in argv, logs, exceptions, CLI output, or
   temp files. Redaction is centralized and tested. Transit to remotes is
   SSH stdin (`ssh host 'umask 077 && cat > path.tmp && mv path.tmp path'`),
   never scp of a plaintext local file. Command targets receive the value on
   stdin only.
3. **TUI masks by default.** Explicit keypress reveals one field at a time.
4. **File hygiene.** Config dir 0700; written files 0600 (or configured
   mode); remote writes go through a temp file + atomic rename.
5. **Public-repo safety.** The clone contains only code, examples, docs, and
   the skill. `.gitignore` blocks `.env*` (except `.env.example`), `*.age`,
   `registry.toml`, `state.toml`, `settings.toml` as defense in depth.

## 5. Components

```
src/secrets_vault/
├── registry.py     # load/validate/save registry.toml (tomlkit, round-trip safe)
├── vault.py        # age subprocess wrapper: decrypt→dict, dict→encrypt; TTY passphrase
├── state.py        # salted-hash push state
├── planner.py      # (changed secrets, selection) → Plan{host → steps}
├── executor.py     # runs a Plan: ssh/local subprocesses, per-step results
├── render.py       # dotenv / env-file rendering
├── generate.py     # CSPRNG secret generation (stdlib `secrets`), presets
├── clipboard.py    # pyperclip wrapper + WSL clip.exe fallback
├── redact.py       # central redaction; wraps logging + exceptions
├── cli.py          # `sv` entry point (stdlib argparse; no extra CLI dep)
└── tui/            # Textual app: screens, widgets, plan view
```

Each module is independently testable; `planner` is pure (no I/O), `executor`
takes a Plan and a value-provider callback so tests can inject fakes.

## 6. CLI surface (`sv`)

| Command | Purpose | Values? |
|---|---|---|
| `sv list` / `sv show <secret>` | structure + staleness | redacted |
| `sv targets` | list targets | redacted |
| `sv plan [--secret X] [--target Y] [--json]` | what would be pushed where | redacted |
| `sv config check` | validate registry, probe SSH reachability | redacted |
| `sv config set <key> <value>` | change settings.toml (warns on `show_generated_secrets=false`) | redacted |
| `sv import <file.env> [--host H --path P]` | register keys + target from an env file | prompts only if TTY |
| `sv generate [--length N] [--preset P]` | generate a random secret and print it | printed by design |
| `sv set <secret>` | set value — interactive TTY prompt | user types |
| `sv set <secret> --generate [--length N] [--preset P]` | generate + store in one step; one-time display rules apply (§7.1) | shown once / hidden |
| `sv apply [--dry-run] [--secret X] [--target Y]` | execute plan; TTY passphrase required | unlocked by user |
| `sv tui` | launch the Textual app | masked/reveal |

`--json` output on `list/show/plan/targets` is the agent API.

### 6.1 Secret generation

Generation uses Python's stdlib `secrets` module (CSPRNG) — no external
binary. Presets: `urlsafe` (default, `secrets.token_urlsafe`), `hex`,
`alphanum`, `ascii` (printable, no quotes/backslash); default length 32
bytes of entropy. Notes:

- `sv generate` intentionally prints the value — it is a *fresh random
  string*, not a stored secret, so it is exempt from redaction. The docs
  note that a value generated by an agent is known to that agent; to keep a
  generated value out of agent context entirely, generate it in the TUI or
  via `sv set --generate` yourself.
- `sv set --generate` requires an interactive TTY like `sv set` (it writes
  to the vault), and follows the one-time display rules in §7.1.

## 7. TUI design

- **Three panes:** secrets list (stale badges) · detail (masked value,
  consuming targets, last-pushed) · status/log footer.
- Unlock on first value operation via passphrase modal; unlocked for the
  TUI session only (plaintext dict held in process memory, dropped on exit).
- Multi-select secrets → **Push** → plan screen: tree of
  `host → files / commands / restarts`, stale vs current marked.
- One confirmation executes the plan; live ✓/✗ per step; one host failing
  never aborts others; final summary lists exactly what succeeded/failed.

### 7.1 Generate-and-use (one-time display)

Any value field (add/edit secret, `sv set --generate`) offers **Generate**
(preset + length selectable, defaults from `settings.toml`). On generation:

- The value is stored in the vault immediately, then shown **once** in a
  modal with a warning ("this will not be shown again unless you reveal it
  manually") and a **Copy to clipboard** action.
- Clipboard: `pyperclip`, with a WSL fallback to `clip.exe`; if no clipboard
  backend is available the modal says so instead of failing silently.
- `settings.toml: show_generated_secrets = true` (default). Setting it to
  `false` — via the TUI settings screen or `sv config set` — suppresses the
  one-time display app-wide (value goes straight to the vault). Flipping it
  to `false` requires acknowledging an explicit warning that generated
  values will never be displayed and are retrievable only via manual reveal
  in the TUI.

## 8. Claude Code skill — `skills/import-secrets/`

Invoked as `/import-secrets` in any project. Instructs the agent to:

1. Scan the project for secret **locations**: `.env*`, `EnvironmentFile=` in
   unit files, docker-compose `env_file:`, CI secret references.
2. Use its knowledge of the user's machines (`~/.ssh/config` aliases,
   deployment layout) to propose `host`/`path` per target; use
   AskUserQuestion when ambiguous.
3. Register structure via `sv import` / editing `registry.toml`.
4. **Never read or echo secret values** — key names only.
5. Finish by telling the user to run `sv tui` to enter values and push.

## 9. Error handling

- Per-target isolation: SSH/command failures recorded in plan results,
  execution continues for other targets.
- `sv apply --dry-run` renders everything, writes nothing.
- Startup checks: `age` binary present (clear install hint if not), config
  dir perms, registry schema validation with precise messages.
- All errors logged (redacted) to `~/.config/secrets-vault/logs/`.

## 10. Testing

- **Unit (pytest):** registry parse/validate round-trips, planner outputs,
  dotenv/env rendering, state hashing, generation presets/lengths, and a
  redaction suite asserting no value string ever appears in CLI output,
  logs, or exception text (`sv generate` being the sole, deliberate
  exception).
- **Integration:** apply against `localhost` SSH (or sshd-in-Docker in CI)
  exercising the real ssh path: temp-file+rename, mode/owner, restart
  command execution, command-target stdin.
- **TUI:** Textual's pilot/snapshot testing for the plan screen and
  unlock modal.

## 11. Distribution

`pyproject.toml`, installable via `pipx install secrets-vault` / `uv tool
install`. Deps: `textual`, `tomlkit`, `pyperclip`. System requirement:
`age`, `ssh`.
Dev on this machine uses `.venv_linux` + `python3` per house rules.

## 12. Out of scope (v1)

- Local-file targets (workaround: `host = "local"` command targets; native
  support can come later).
- Multi-user/team sharing, secret versioning/history, rotation scheduling.
- Windows-native support (WSL is the supported environment; the code avoids
  gratuitous Linux-isms so a later port is feasible).
