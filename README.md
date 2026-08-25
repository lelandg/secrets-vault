# secrets-vault

A central TUI app and registry for managing secrets across all of your
machines and projects — edit a value once, push it everywhere that needs it.

## What it is

secrets-vault is a single Python app that keeps one encrypted vault of secret
*values* and one plaintext registry describing *where those values need to
go*: remote env files over SSH, systemd-managed services (with a restart),
and command-based targets like `gh secret set`. You edit a secret in one
place — the `sv tui` — and push it to every location that consumes it via an
explicit plan → confirm → apply flow. Nothing is pushed until you say so, and
every push is shown to you first as a plan you can read.

The registry is not per-repo. It is **central**: one instance on your machine
models every project you have, and each *logical* secret — a real-world
credential like "the OpenAI API key" — is recorded exactly once no matter how
many apps consume it. This is what makes rotation tractable.

### The rotation story

An API key gets compromised. Without a central registry, you now have to
remember every place that key lives — three apps, two servers, a GitHub
Actions secret — and hope you didn't miss one. With secrets-vault:

```
$ sv show OPENAI_API_KEY
OPENAI_API_KEY — OpenAI key used by ImageAI and Maestro
value set: yes
  imageai:
    prod-imageai [env-file] on hermes — current (pushed 2026-07-01T09:00:00)
  maestro:
    prod-maestro [env-file] on hermes — current (pushed 2026-07-01T09:00:00)
    worker [systemd] on hermes — current (pushed 2026-07-01T09:00:00)
  (no project):
    github-actions [command] on local — current (pushed 2026-07-01T09:00:00)
```

`sv show` answers "this key is also used by apps X, Y and Z" in one command
— every consuming target, grouped by project. You rotate the key at the
provider, enter the new value once in `sv tui`, review the plan (every
affected host, file, and service, with restarts included), and confirm once.
One apply pushes the new value everywhere and restarts what needs restarting.
Nothing gets missed because nothing requires you to remember it.

## Install

```bash
pipx install secrets-vault-tui
```

(or `uv tool install secrets-vault-tui`, or install from a local clone with
`pip install .` in a virtualenv of your own). The PyPI package is
`secrets-vault-tui`; the command it installs is `sv`.

**Requirements:**
- `ssh` on your `PATH`, with working host aliases in `~/.ssh/config` for any
  remote targets. Local-only targets (`host = "local"`) don't need SSH at
  all.
- The `age` CLI is **optional** — secrets-vault encrypts and decrypts its
  vault in-process via the `pyrage` library (installed automatically as a
  dependency), so `age` is never required to run the tool. Install it
  separately only if you want to inspect or decrypt `vault.age` by hand:
  `age -d -i - vault.age` (passphrase-decrypt) will read the same file
  secrets-vault writes, since `pyrage` produces byte-identical age-v1
  ciphertext.

All app data lives under `~/.config/secrets-vault/` (created with `0700`
permissions). The public repo never contains anything user-specific.

## Quickstart

```bash
# 1. Register keys from an existing project's .env file — structure only,
#    no values are read or stored by this step.
sv import ~/code/myapp/.env --project myapp

# 2. Open the TUI to enter the actual secret values.
sv tui
#   n  — new secret          e — edit/enter a value
#   g  — generate a value    r — reveal the selected value
#   p  — build & review a push plan, then confirm to push everywhere

# 3. Or push from the command line once values are set:
sv plan            # see what would change, and where
sv apply            # confirm once, pushes to every stale target
```

`sv apply --dry-run` renders the full plan and touches nothing — safe to run
any time, including from a script or an agent.

**Caveat: env-file targets are fully overwritten.** Every `env-file` /
`systemd` target is rewritten from scratch on each apply — a
`# managed by secrets-vault` file containing only the keys registered for
that target. Any pre-existing key in that file that isn't registered is
dropped the first time secrets-vault writes to it. `sv import` registers all
keys in an existing `.env` for you, so importing first avoids this; or point
the target at a dedicated file that secrets-vault alone manages. See
[Docs/UserGuide.md](Docs/UserGuide.md#env-file--write-a-dotenv-style-file-local-or-remote)
for details.

## The agent-safety model

AI coding agents (Claude Code and similar) are meant to help you set
secrets-vault up — registering where secrets live across your projects — but
they must never be able to see or move a secret *value*. The design draws a
hard line: **structure yes, values never.**

| Surface | Agent-visible? | Why |
|---|---|---|
| `registry.toml` (secret names, targets, hosts, paths) | Yes — plaintext, agent-readable/writable | Structure only; no secret material lives here |
| `state.toml` (salted hashes, staleness, timestamps) | Yes | Salted HMAC hashes, not reversible to a value |
| `sv list`, `sv show`, `sv targets`, `sv plan` (incl. `--json`) | Yes | These commands never open the vault and never load a secret value into memory — they only read `registry.toml`/`state.toml`, which by construction hold no values. Redaction (`redact.py`) is a separate backstop for the paths that *do* handle values — see below |
| `sv apply --dry-run` | Yes | Renders the plan, writes nothing, prompts for nothing |
| `vault.age` (encrypted secret values) | No | age-passphrase-encrypted; opaque without the passphrase |
| `sv set`, `sv apply` (real push), `sv tui` value entry | No | All require a passphrase read via `getpass` **from an interactive TTY**; there is no flag, environment variable, or stdin-pipe way to supply it |

That TTY requirement is the actual enforcement mechanism, not a convention:
`read_passphrase()` calls `sys.stdin.isatty()` and raises before ever
prompting if the caller isn't an interactive terminal. An agent driving `sv`
through a non-interactive shell is structurally unable to unlock the vault —
there's no code path that would let it. `tests/test_redaction_audit.py`
(`sv generate` excepted — see below) seeds a real secret value and asserts
it never appears in the stdout/stderr of `list`, `show`, `targets`, `plan`,
or `apply --dry-run` — an executable regression guard for the value-free
guarantee above, not the mechanism that makes those commands safe. Values
that do reach a live code path — logs, exceptions, executor error output
from `set`/`apply`/`tui` — are scrubbed by a redactor (`redact.py`) as a
separate backstop; see [Docs/Security.md](Docs/Security.md).

The one deliberate exception is `sv generate`, which prints a **freshly
generated random string that was never stored** — not a secret retrieved
from the vault. If you want a generated value to never enter agent context at
all, generate it interactively in `sv tui` or via `sv set --generate`
yourself instead.

See [`Docs/Security.md`](Docs/Security.md) for the full threat model.

## Setting up an AI agent to help configure it

secrets-vault ships a Claude Code skill, `skills/import-secrets/`, that scans
your projects for secret *locations* (`.env*` files, `EnvironmentFile=` in
systemd units, `env_file:` in docker-compose, CI secret references) and
registers them — key names and target locations only, never values. Install
it by copying the skill directory into your Claude Code skills folder:

```bash
cp -r skills/import-secrets ~/.claude/skills/
```

Then in Claude Code, run:

```
/import-secrets            # sweep every project you have
/import-secrets ~/code/x   # or scope it to one project
```

The skill is idempotent — re-running it adds newly discovered secrets and
targets without duplicating what's already registered — and it hands off to
you at the end with a reminder to run `sv tui` to actually enter values.

## Documentation

- [`Docs/UserGuide.md`](Docs/UserGuide.md) — every subcommand, the TUI
  keybindings, the settings reference, and target-type examples.
- [`Docs/Security.md`](Docs/Security.md) — the full threat model: what
  secrets-vault protects against and what it explicitly does not.

## License

MIT.
