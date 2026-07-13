---
name: import-secrets
description: Scan the user's projects for secret locations (.env files, systemd EnvironmentFile, docker-compose env_file, CI secrets) and register them in the central secrets-vault registry. Never reads or echoes secret values. Use when the user wants secrets-vault configured for one project or all of them.
---

# Import secrets into secrets-vault

You are configuring the user's **central** secrets-vault registry. Central
means all projects at once: one logical secret entry per real-world secret,
no matter how many apps consume it.

## Hard rules

1. **NEVER read, print, or store secret VALUES.** You may read env files
   only to extract KEY names (`sv import` does this safely for you —
   prefer it). If you must open a file that contains values, extract key
   names only and never echo a line containing `=` plus a value.
2. Never run `sv set`, `sv apply` (without `--dry-run`), or anything that
   prompts for the vault passphrase. Those are the user's alone.
3. Registry edits must be idempotent — check `sv list --json` and
   `sv targets --json` before adding.

## Procedure

1. **Scope.** If the user gave a path, scan that project. Otherwise scan
   all projects: get roots from `sv config` settings (`project_roots`) or
   the user's known code directories; list each project directory.
2. **Discover locations** in each project: `.env*` files (skip
   `.env.example`), `EnvironmentFile=` lines in `*.service`/unit files,
   `env_file:` in docker-compose files, CI secret references
   (`secrets.FOO` in GitHub workflows).
3. **Resolve identity across projects** — the step that makes rotation
   work:
   - Same provider credential reused in several projects (e.g.
     `OPENAI_API_KEY`) → ONE logical secret; add each project's target,
     using `--map LOGICAL=ENVVAR` if the env var name differs.
   - Same env var NAME but per-app values (e.g. `DATABASE_URL`) →
     app-scoped secrets via `--scoped` (registers `project/KEY`).
   - Unsure? Ask the user with AskUserQuestion (one question per key
     group, batched sensibly).
4. **Propose hosts.** Use what you know of the user's machines
   (`~/.ssh/config` aliases, deployment layout) to fill `--host` and
   `--remote-path` for deployed targets; the local project `.env` target
   uses the default `--host local`. Ask when ambiguous.
5. **Register** with `sv import <file> --project <name> [flags]` per
   discovered file, and `sv targets --json` to verify.
6. **Report**: list registered secrets/targets (names only) and finish
   with: run `sv tui` to enter values, then push.
