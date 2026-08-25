# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.17.2] - 2026-08-25

### Changed
- First PyPI release. The distribution name is `secrets-vault-tui` because
  `secrets-vault` is taken on PyPI. The import package stays `secrets_vault`
  and the command stays `sv`. Install with `pipx install secrets-vault-tui`.
- Add PyPI metadata to `pyproject.toml`: authors, keywords, classifiers, and
  project URLs.
- Point the install instructions in `README.md` and the Discord release post
  at the PyPI package instead of the GitHub URL.

## [0.17.1] - 2026-08-24

### Fixed
- README install instructions now install from GitHub (`pipx install git+...`); the package is not on PyPI

### Added
- Discord release-announcement post under `Discord/`

## [0.17.0] - 2026-07-13

### Added
- feat: import-secrets Claude skill and example configs

### Changed
- test: end-to-end push over real ssh to localhost

## [0.16.0] - 2026-07-13

### Added
- feat: TUI plan/apply screen with live results and settings screen

### Fixed
- fix: escape markup on revealed/generated values, Escape re-masks reveal, centralize display guard

## [0.15.0] - 2026-07-13

### Added
- feat: TUI unlock/edit/reveal/generate with one-time display

## [0.14.0] - 2026-07-13

### Added
- feat: TUI skeleton with secrets table, detail pane, staleness badges

## [0.13.0] - 2026-07-13

### Added
- feat: sv set/import/apply with TTY-gated value operations

### Fixed
- fix: redact exception tracebacks and stack info in log records

## [0.12.0] - 2026-07-13

### Added
- feat: agent-safe sv CLI (list/show/targets/plan/generate/config)

## [0.11.0] - 2026-07-13

### Added
- feat: clipboard helper with WSL fallback

### Fixed
- fix: create local env files with final mode atomically (no perm window)

### Changed
- test: regression test asserts mode set at creation, chmod forbidden

## [0.10.0] - 2026-07-13

### Added
- feat: plan executor with ssh stdin transport and per-target isolation

## [0.9.0] - 2026-07-13

### Added
- feat: pure push planner with staleness and filters

### Fixed
- fix: anchor plain-value regex with \A..\Z and escape newlines in quoted values

## [0.8.0] - 2026-07-13

### Added
- feat: dotenv/env rendering with safe quoting

### Fixed
- fix: atomic 0600 vault creation, mode test, untrack .idea

## [0.7.0] - 2026-07-13

### Added
- feat: pyrage vault with TTY-only passphrase boundary

## [0.6.0] - 2026-07-13

### Added
- feat: salted push-state store for lock-free staleness

### Fixed
- fix: add_secret merges changed metadata like add_target

## [0.5.0] - 2026-07-13

### Added
- feat: registry model with validation and idempotent merge

## [0.4.0] - 2026-07-13

### Added
- feat: CSPRNG secret generation with presets

### Fixed
- fix: get_logger follows SECRETS_VAULT_HOME changes; explicit propagate=False

## [0.3.0] - 2026-07-13

### Added
- feat: central redaction with logging filter

## [0.2.0] - 2026-07-13

_No recorded changes._

## [0.1.0] - 2026-07-13

### Added
- feat: scaffold package with paths and settings modules

### Changed
- docs(plans): add implementation plan (18 TDD tasks); spec: pyrage + local targets amendments
- docs(plans): make all-projects central model explicit — logical secret identity, key_map, multi-project import sweep
- docs(plans): add secret generation (CLI + one-time display) to design spec
- docs(plans): add design spec for secrets-vault
