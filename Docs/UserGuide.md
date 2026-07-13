# User Guide

secrets-vault is a single `sv` command with subcommands, plus a Textual TUI
(`sv tui`). This guide covers every subcommand, the TUI keybindings, the
settings you can configure, and how the target types work — with real
`registry.toml` snippets.

All application data lives under `~/.config/secrets-vault/` (XDG config
dir), created with `0700` permissions on first use:

| File | Contents | Agent-readable? |
|---|---|---|
| `registry.toml` | secret names, descriptions, tags, targets — no values | yes |
| `vault.age` | age-passphrase-encrypted secret values | no (opaque without passphrase) |
| `state.toml` | per-`(secret, target)` salted push hash + timestamp, no values | yes |
| `settings.toml` | app settings (below) | yes |
| `logs/sv.log` | per-run error log, values redacted before write | yes |

You can override the config directory entirely (mainly for tests/CI) with
the `SECRETS_VAULT_HOME` environment variable.

---

## Commands

### `sv list`

Lists every registered secret: whether a value is set, how many targets
consume it, how many of those are stale, and its description.

```bash
$ sv list
• OPENAI_API_KEY                          targets=3 stale=0  OpenAI key used by ImageAI and Maestro
○ maestro/DATABASE_URL                    targets=1 stale=1  Maestro production Postgres
```

`•` = value set in the vault, `○` = no value yet. `--json` prints the same
rows as JSON (this is the agent-facing form):

```bash
sv list --json
```

### `sv show <secret>`

Shows one secret's consuming targets, grouped by project — this is the
command that answers "where does this key live" during a rotation.

```bash
$ sv show OPENAI_API_KEY
OPENAI_API_KEY — OpenAI key used by ImageAI and Maestro
value set: yes
  imageai:
    prod-imageai [env-file] on hermes — current (pushed 2026-07-01T09:00:00)
  maestro:
    prod-maestro [env-file] on hermes — current (pushed 2026-07-01T09:00:00)
    worker [systemd] on hermes — stale
```

`sv show <secret> --json` gives the same data as structured JSON, keyed by
project.

### `sv targets`

Lists every registered target (push destination) across all projects.

```bash
$ sv targets
prod-imageai                  env-file  host=hermes      project=imageai keys=1
worker                        systemd   host=hermes      project=maestro keys=1
github-actions                command   host=local       project=maestro keys=1
```

`--json` for the machine-readable form.

### `sv plan [--secret X] [--target Y] [--force] [--json]`

Computes what would be pushed, without pushing anything. `--secret` and
`--target` may be repeated to narrow the plan to specific secrets or
targets; `--force` includes targets that are already current (not just
stale ones).

```bash
$ sv plan
hermes:
  write /opt/maestro/.env (stale: maestro/DATABASE_URL)
  exec  systemctl restart maestro-worker

$ sv plan --secret OPENAI_API_KEY --json
[
  {
    "kind": "write-file",
    "target": "prod-imageai",
    "host": "hermes",
    "detail": { "path": "/opt/imageai/.env", "stale": ["OPENAI_API_KEY"], "missing": [] }
  }
]
```

`sv plan` never opens the vault, so there is no values-in-a-plan code
path — not because output is filtered, but because a value is never loaded
into memory to print in the first place. See
[Docs/Security.md](Security.md) for the full guarantee.

### `sv generate [--preset P] [--length N]`

Generates a random secret using the stdlib `secrets` module (CSPRNG — no
external binary) and **prints it**. Presets: `urlsafe` (default,
`secrets.token_urlsafe`), `hex`, `alphanum`, `ascii` (printable, excludes
`" ' \ `` $` to stay quoting-safe). Length defaults to 32 (bytes of entropy
for `urlsafe`/`hex`; output characters for `alphanum`/`ascii`), or your
`generate_preset`/`generate_length` settings if unset.

```bash
$ sv generate --preset hex --length 16
3f9a2c7e1b6d4085f0a1e2c3b4d5e6f7
```

This is the one deliberate exception to "values never appear in CLI
output" — the printed string is a **fresh random value that was never
stored**, not something retrieved from the vault. If you want a generated
value to stay fully out of an agent's context, generate it in `sv tui` or
via `sv set --generate` instead of `sv generate`.

### `sv config check`

Validates the registry (unknown target types, missing required fields,
targets referencing secrets that don't exist) and probes SSH reachability
for every remote host referenced by a target (`ssh -o BatchMode=yes -o
ConnectTimeout=5 <host> true`). Exits non-zero if anything failed.

```bash
$ sv config check
ssh hermes: ok
ssh devbox: FAILED
registry: ok
```

### `sv config set <key> <value>`

Sets a `settings.toml` key. Booleans accept `true/1/yes` (anything else is
`false`); lists are comma-separated.

```bash
sv config set generate_preset hex
sv config set project_roots /home/me/code,/home/me/work
```

Setting `show_generated_secrets` to `false` requires an interactive
terminal and an explicit `YES` confirmation — it permanently suppresses the
one-time reveal of generated values app-wide (see §Settings below).

### `sv set <secret> [--generate [--preset P] [--length N]]`

Sets a secret's value. **Requires an interactive TTY** — this is the vault
unlock/create path and cannot be scripted or piped. Without `--generate` it
prompts twice (value + confirm) via `getpass` (never echoed). With
`--generate`, a value is generated and stored immediately; if
`show_generated_secrets` is true (the default) it is then printed once with
a warning and copied to the clipboard.

```bash
$ sv set OPENAI_API_KEY
Value for OPENAI_API_KEY: ****
Confirm value: ****
stored OPENAI_API_KEY

$ sv set OPENAI_API_KEY --generate --preset urlsafe --length 32
Vault passphrase: ****
WARNING: this value will not be shown again unless revealed in the TUI.
  OPENAI_API_KEY = kx7f...    (copied to clipboard)
```

If the secret isn't already registered, `sv set` registers it automatically.

### `sv import <file.env> --project P [--host H] [--remote-path P] [--target-name N] [--scoped] [--map LOGICAL=ENVVAR]`

Registers key **names** (never values) plus a target from an env file. Reads
`KEY=value` / `export KEY=value` lines and keeps only the keys.

```bash
# Register every key in ./api/.env under the "myapp" project, targeting
# the same path on the remote host "hermes":
sv import ./api/.env --project myapp --host hermes --remote-path /opt/myapp/.env

# App-scoped identities: a DATABASE_URL that's per-app, not shared, becomes
# myapp/DATABASE_URL instead of colliding with another app's DATABASE_URL:
sv import ./api/.env --project myapp --scoped

# Map an env var name in this file to an existing logical secret (e.g. this
# file calls it OPENAI_KEY but the registry's logical name is OPENAI_API_KEY):
sv import ./api/.env --project myapp --map OPENAI_API_KEY=OPENAI_KEY
```

`--host` defaults to `local` (registers a target on this machine); omit
`--remote-path` to target the same path as the source file. Running
`sv import` again against the same file/project is safe — it deduplicates.

### `sv apply [--dry-run] [--secret X] [--target Y] [--force] [--yes]`

Executes the plan: writes remote/local env files, runs restart commands,
runs command targets with the value piped to stdin. Requires the vault
passphrase from an interactive TTY (unless `--dry-run`, which never opens
the vault). Prompts `Push? [y/N]` unless `--yes` is given. Per-target
failures (e.g. one host unreachable) don't abort the rest — each step's
result is reported, and only successful writes update `state.toml`.

```bash
$ sv apply --dry-run
hermes:
  write /opt/maestro/.env (stale: maestro/DATABASE_URL)
  ✓ [dry-run] write-file prod-maestro

$ sv apply
hermes:
  write /opt/maestro/.env (stale: maestro/DATABASE_URL)
Push? [y/N] y
Vault passphrase: ****
  ✓ write-file prod-maestro on hermes: wrote /opt/maestro/.env
  ✓ restart worker on hermes: ok
2/2 steps succeeded
```

Remote writes always go through SSH stdin — `ssh host 'umask 077 && cat >
path.tmp && mv path.tmp path'` — never `scp` of a plaintext local file, so
the value is never written to a local temp file at any point.

### `sv tui`

Launches the Textual TUI (see below).

---

## TUI

`sv tui` opens a two-pane app: a secrets table on the left (name, masked
value indicator, target/staleness summary, description) and a detail pane
on the right (consuming targets grouped by project). The vault stays locked
until the first operation that needs a value; once unlocked, decrypted
values are held only in memory for the session and dropped on exit.

### Keybindings

| Key | Action |
|---|---|
| `n` | New secret — prompts for a name (use `project/KEY` for app-scoped secrets), then opens the value editor |
| `e` | Edit the selected secret's value |
| `r` | Reveal the selected secret's value in the detail pane (unlocks the vault if needed) |
| `g` | Generate a value for the selected secret (same modal as `e`, with a Generate button) |
| `p` | Build a push plan and open the plan screen to review and confirm |
| `s` | Open the settings screen |
| `Escape` | Hide a revealed value |
| `q` | Quit |

Values are masked (`••••••••`) everywhere by default; `r` is the only way
to see one, and it's per-field, one secret at a time, until you press
`Escape` or move the selection.

### Generate-and-use (one-time display)

Pressing `g` (or **Generate** inside the value editor) stores a freshly
generated value in the vault immediately, then — if `show_generated_secrets`
is `true` (the default) — shows it once in a modal with a **Copy to
clipboard** button and a warning that it won't be shown again outside of a
manual reveal. Clipboard copy uses `pyperclip`, with a WSL fallback to
`clip.exe`; if no clipboard backend is available, the modal says so instead
of silently failing.

### Push flow

`p` builds a plan from every stale (secret, target) pair and opens a plan
screen showing a tree of `host → files / commands / restarts`. One
confirmation executes the whole plan; each step reports ✓/✗ live, one
host failing never aborts the others, and a final summary lists exactly
what succeeded and what failed.

---

## Settings reference (`settings.toml`)

```toml
# ~/.config/secrets-vault/settings.toml
vault_path = ""                    # empty = ~/.config/secrets-vault/vault.age
project_roots = ["/home/me/code"]  # where /import-secrets sweeps
generate_preset = "urlsafe"
generate_length = 32
show_generated_secrets = true
ssh_options = []
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `vault_path` | string | `""` | Overrides where the encrypted vault file lives. Empty means `~/.config/secrets-vault/vault.age`. Safe to point at a synced location (e.g. Dropbox) because the file is always encrypted at rest. |
| `project_roots` | list of strings | `[]` | Directories the `import-secrets` Claude Code skill sweeps when scanning for secret locations. |
| `generate_preset` | string | `"urlsafe"` | Default preset for `sv generate` / `sv set --generate` / TUI Generate, when `--preset` isn't given. One of `urlsafe`, `hex`, `alphanum`, `ascii`. |
| `generate_length` | int | `32` | Default length for generation, when `--length` isn't given. |
| `show_generated_secrets` | bool | `true` | Whether a freshly generated value is shown once (with copy-to-clipboard) after being stored. Setting this to `false` (via `sv config set show_generated_secrets false` or the TUI settings screen) requires interactive confirmation and means generated values are never displayed anywhere again — only retrievable via manual reveal in the TUI. |
| `ssh_options` | list of strings | `[]` | Extra options passed to every `ssh` invocation (e.g. `["-i", "/path/to/key"]`). |

Edit via `sv config set <key> <value>`, the TUI settings screen (`s`), or by
hand-editing `settings.toml` (it's plain TOML, `0600`).

---

## Target types (`registry.toml`)

`registry.toml` holds two tables: `[secrets.*]` (logical secret identities —
name, description, tags, no values) and `[targets.*]` (push destinations).
There are three target types.

### `env-file` — write a dotenv-style file (local or remote)

```toml
[targets.prod-myapp]
type = "env-file"
project = "myapp"
host = "prodbox"                 # ssh alias from ~/.ssh/config, or "local"
path = "/opt/myapp/.env"
format = "dotenv"                # dotenv | env (KEY="value")
mode = "600"
owner = "myapp:myapp"            # optional; chown after write
keys = ["OPENAI_API_KEY"]
restart = ["sudo systemctl restart myapp"]   # optional, any commands
[targets.prod-myapp.key_map]     # logical name -> env-var name in the file
"myapp/DATABASE_URL" = "DATABASE_URL"
```

`keys` lists logical secret names whose env-var name in the file is
identical to the logical name; `key_map` handles cases where they differ
(shared secrets that a project-scoped file still expects under its own
env-var name) or where the logical name is app-scoped (`project/KEY`).

### `systemd` — write an `EnvironmentFile` and restart a unit

```toml
[targets.worker]
type = "systemd"
project = "myapp"
host = "prodbox"
unit = "myapp-worker.service"
path = "/etc/myapp/worker.env"
keys = ["OPENAI_API_KEY"]
```

Writes the env file the same way as `env-file`, then restarts the named
`unit` as part of the plan.

### `command` — pipe a single value to a command's stdin

```toml
[targets.github-actions]
type = "command"
project = "myapp"
host = "local"                    # "local" or an ssh alias
command = ["gh", "secret", "set", "OPENAI_API_KEY", "-R", "me/myapp"]
keys = ["OPENAI_API_KEY"]         # exactly one key; value piped on stdin
```

Command targets take **exactly one** key — the value is piped to the
command's stdin, never passed as an argument (arguments would leak into
`ps`, shell history, and process listings).

### Full example

See [`examples/registry.example.toml`](../examples/registry.example.toml)
and [`examples/settings.example.toml`](../examples/settings.example.toml)
for complete, runnable-shaped examples covering all three target types
side by side.
