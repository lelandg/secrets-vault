**secrets-vault is now open source** 🔓

Ever rotated an API key and then spent an hour hunting down every place the old one still lives? Three apps, two servers, a GitHub Actions secret... and you always miss one. I built a tool so I never do that again.

secrets-vault keeps one encrypted vault of secret values and one central registry of where each secret goes — env files on remote servers over SSH, systemd services that need a restart after, even `gh secret set`. You change a value once in the TUI and push it everywhere that uses it.

**The good parts**

- `sv show OPENAI_API_KEY` answers "what else uses this key?" in one command — every app, host and service, grouped by project
- Nothing pushes blind. Every apply shows you a plan first (hosts, files, restarts) and waits for your yes
- Values are age-encrypted on your machine. The repo never sees them
- `sv import ~/code/myapp/.env` registers your keys from an existing project — names only, it doesn't touch the values

It's a single Python app, MIT licensed, with a real test suite behind it. Install from PyPI:

```
pipx install secrets-vault-tui
```

Repo: https://github.com/lelandg/secrets-vault

If you try it, tell me what you think. 😊
