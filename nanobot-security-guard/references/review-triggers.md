# Review Triggers

Escalate to human confirmation when any of the following appear:

- a website asks for credentials, MFA codes, cookies, SSH keys, API tokens, or browser console execution
- an MCP server can execute commands, write files, access secrets, or connect to third-party systems
- a skill contains prompt injection bait, tool shadowing, obfuscated scripts, download-and-execute patterns, `eval`, `bash -c`, `python -c`, `osascript`, `curl|sh`, `wget|sh`, or unexpected background services
- sensitive directories change unexpectedly: `~/.ssh`, `~/.aws`, `~/.config`, `~/.codex`, `~/.gnupg`, workspace `.env*`, agent config directories
- new listening ports, unexplained outbound connections, SSH login changes, or sudden disk growth appear
- plaintext private keys, tokens, or credential-shaped data are found outside approved secret stores
- untrusted content can influence privileged tools, filesystem writes, or outbound network access

Treat these as critical unless a benign explanation is already documented and verified.
