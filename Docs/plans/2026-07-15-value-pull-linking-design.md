# Design: bulk value pull, identity merge/link, Amplify targets, theme preview

**Date:** 2026-07-15
**Status:** approved (design); implementation plan to follow
**Branch:** feat/initial-implementation

## Context

`sv import` (and the import-secrets Claude skill) registers secret *names* and
targets only — values are never read by design. After an import the vault is
empty and every secret shows "(no value set)". Typing each value by hand does
not scale. Meanwhile the values already exist in deployed locations (Amplify
env vars, remote host env files) and in (often outdated) local `.env` files.

Two security boundaries apply, and they are different:

1. **Agent boundary (unchanged):** agents must never be able to read values.
   Enforced by the TTY + passphrase gate (`vault.read_passphrase`).
2. **Display boundary (unchanged):** the app itself never prints values to
   stdout/CLI except explicit one-time reveal flows.

Within those boundaries, the *app* — running interactively for the user — may
read values from files and services, compare them, and store them.

## Decisions (user-confirmed)

- Identical values across secrets → propose **merge**; if declined, offer
  **link**; members can **unlink at any time**.
- Pull sources: **deployed sources are the truth** — Amplify env vars (set
  via aws-admin) and remote host files. Local `.env` files are outdated and
  excluded by default.
- Vault-vs-incoming conflicts: **ask per conflict** (names only, never values).
- Amplify is a **full target**: pull *and* push. Push must read ALL current
  env vars and write the full merged set back (Amplify update replaces the
  entire map — partial writes destroy other keys).

## A. Bulk value pull — `sv pull` + TUI action

New TTY-gated subcommand (and TUI action) that fills the vault from the
registered targets themselves.

### Sources and trust tiers

| Tier | Source | How read | Default |
|------|--------|----------|---------|
| 1 (deployed) | `amplify` targets | `aws amplify get-app` / `get-branch`, JSON parsed in memory | on |
| 1 (deployed) | remote `env-file` / `systemd` targets (`host != local`) | `ssh <host> cat <path>`, captured, never echoed | on |
| 2 (local) | local `env-file` targets (`host == local`) | read file | **off**; `--include-local` / TUI checkbox |

### Resolution per logical key

1. Collect candidate values from all selected sources that carry the key
   (via each target's `all_keys()` mapping, env var → logical name).
2. Highest tier wins. Two tier-1 sources that disagree → ask (secret name +
   which hosts/apps differ; values never shown).
3. Winner vs existing vault value:
   - no vault value → store;
   - identical (compare via `StateStore.hash_value`) → no-op;
   - different → **ask**: keep vault / take incoming / skip. Show file mtime
     (or "deployed") vs vault `updated_at` so the user sees which is newer.
4. After storing, `record_push(secret, target)` for every selected source
   target whose current content equals the stored value — those show
   *current*; all other consumers of the secret flag stale naturally.

### Output

Names and statuses only: `new / updated / same / skipped / conflict`.
Summary counts at the end. Never a value, never a value fragment.

### CLI / TUI surface

- `sv pull [--include-local] [--project P] [--target T] [--secret S]`
- TUI binding `u` ("pUll", shown in footer; `l`/`L` reserved for link/unlink) → source-selection modal
  (checkboxes per source group, local off by default) → conflict modals →
  summary notification. Requires unlock (`ensure_unlocked`).

## B. Value identity — merge first, link fallback, unlink anytime

### Detection

Equality = equality of the existing salted HMAC-SHA256 hashes in
`state.toml` (`StateStore.hash_value`). No new crypto; works with the vault
locked. Caveats (document in Security.md):

- Equality *metadata* (that two secrets share a value) is visible to anything
  that can read `state.toml`, including agents. Values are not.
- The salt lives beside the hashes, so a low-entropy value could be
  dictionary-attacked offline. Fine for API keys; noted for humans.

### Merge (preferred)

Trigger: after `sv pull`, or on demand `sv dupes`. For each identical-value
group:

1. Propose a merge with a suggested canonical name (user can rename).
2. On approval: rewrite every consuming target's `key_map` entry to point the
   env var at the canonical logical name; delete the redundant `Secret`
   entries; keep one vault entry under the canonical name; drop stale vault
   entries and `state.toml` rows for deleted names; migrate `pushes` records
   where hash matches.
3. Idempotent and per-group approval; declining leaves everything untouched.

### Link (fallback)

- Registry gains a plaintext `[links]` section: named groups of secret names
  (no values, no hashes).
- Propagation: whenever a member's value is stored (TUI edit, `sv set`,
  `sv pull`), the app writes the same value to all other members' vault
  entries, updates their hashes, and their targets flag stale until push.
- `sv link A B [C...]` creates/extends a group; `sv unlink NAME` removes a
  member at any time (a group of one dissolves). TUI: link/unlink actions;
  the detail pane shows "linked with: ..." so state is never hidden.
- A secret may belong to at most one link group. Merged secrets leave any
  group they were in.

### Name-similarity suggestions

Same env-var basename across projects with *different* values (e.g.
`chameleonlabs/DATABASE_URL` vs `quickstock/DATABASE_URL`) is listed under
"possible same credential — review" in `sv dupes` output. Informational
only; no action without explicit approval.

## C. Amplify target type — pull and push

### Registry

New target `type = "amplify"` with fields:

- `app` (Amplify app name or appId; required — validate in
  `Registry.validate`)
- `branch` (optional; empty = app-level env vars)
- `keys` / `key_map` as for other types; `host` unused (set `"aws"` for
  display), `path`/`unit`/`command` unused.

### Pull

`aws amplify get-app --app-id ...` (resolve name → id via `list-apps` once,
cached in the registry entry) or `get-branch`; parse
`environmentVariables` from JSON in memory. Output of the subprocess is
never printed; stderr surfaced only through the redacting logger.

### Push (executor step kind: `amplify-update`)

1. Read ALL current env vars for the app/branch (fresh read at push time).
2. Merge only the changed managed keys into that full map.
3. Write the **complete** map back via `update-app` / `update-branch` using
   `--cli-input-json file://<tmp>`: temp file created `0o600` in a private
   tmpdir, deleted in a `finally`. Values never appear in argv (visible in
   `/proc/*/cmdline`) and never in logs.
4. `record_push` per pushed logical key, same as env-file targets.
5. Failure mode: if the pre-read fails, abort the step (never write a map
   we didn't fully read). Post-write verify: re-read and compare hashes of
   managed keys; report per-key ✓/✗.

`sv config check` extends to Amplify targets: verify AWS CLI presence and
`get-app` access (exit code only; output discarded).

## D. Theme picker with live preview

- `Settings.theme: str = ""` (empty = Textual default). Applied in
  `SvApp.on_mount` when set and valid; invalid/unknown names fall back to
  default with a notify, never crash.
- `ThemeModal(ModalScreen[str | None])`: `OptionList` of
  `app.available_themes` (sorted, current theme pre-highlighted).
  - Highlight change → `app.theme = highlighted` (live preview).
  - Enter / OK → dismiss with the name; caller persists via
    `save_settings` and notifies.
  - Escape / Cancel → restore the exact theme captured when the modal
    opened, dismiss None, nothing persisted.
- Entry points: command palette command "Change theme" (replacing Textual's
  stock `ThemeProvider`, which applies-on-select with no preview/revert —
  override `get_system_commands`/`COMMANDS` so only ours appears) and a
  `t` key binding.

## Security model deltas (Docs/Security.md)

- `sv pull` sits behind the same TTY + passphrase gate as `sv set`; agents
  cannot invoke it.
- Pull reads remote/Amplify values into process memory; they are added to
  `REDACTOR` immediately (same as vault load) before any logging can occur.
- New metadata visible to agents: link groups (names) and value-equality
  inferable from `state.toml` hashes (pre-existing, now documented).
- Amplify values transit: AWS CLI stdout → app memory → vault; and vault →
  0600 temp JSON → AWS CLI. No argv, no logs, no terminal output.

## Testing

- `pull`: fake source layer (no ssh/aws in unit tests) — tier precedence,
  same-tier conflict prompts, vault-conflict prompts, record_push of source
  targets, `--include-local` gating.
- merge: key_map rewriting, vault consolidation, state/pushes migration,
  idempotency, decline-leaves-untouched.
- link: propagation on set/pull, staleness fan-out, unlink dissolution,
  single-group membership, merge-removes-from-group.
- amplify: mocked subprocess — read-merge-write preserves unmanaged keys,
  aborts on failed pre-read, temp file mode/cleanup, argv contains no
  values, post-write verify.
- theme: persistence round-trip, revert-on-cancel, invalid saved theme
  fallback. TUI flows via Textual pilot where practical.
- redaction audit: extend existing test to cover `sv pull` output paths.

## Docs

- `Docs/UserGuide.md`: pull workflow, dupes/merge/link/unlink, Amplify
  targets, theme picker.
- `Docs/Security.md`: deltas above.
- `skills/import-secrets/SKILL.md`: final report step now says "run
  `sv tui` or `sv pull` to load values (you'll be prompted per conflict),
  then push." The skill itself still never touches values; `sv pull` is
  for the user's own terminal (it will refuse without a TTY).

## Out of scope (v1)

- Pushing to other cloud secret stores (SSM, Secrets Manager, GitHub
  Actions secrets).
- Automatic rotation scheduling.
- Branch-level vs app-level Amplify var *migration* (we write back at the
  level we read from).
