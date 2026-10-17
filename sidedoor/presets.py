"""Preset agent profiles: non-interactive command, auto-approve flags, env and copy-in defaults."""

PRESETS = {
    "claude": dict(exe="claude", command="claude -p {prompt} --dangerously-skip-permissions", env=["ANTHROPIC_API_KEY"], copyin=[".claude.json", ".claude/.credentials.json"]),
    "codex": dict(exe="codex", command="codex exec --dangerously-bypass-approvals-and-sandbox {prompt}", env=["OPENAI_API_KEY"], copyin=[".codex/auth.json", ".codex/config.toml"]),
    "gemini": dict(exe="gemini", command="gemini --yolo --prompt {prompt}", env=["GEMINI_API_KEY", "GOOGLE_API_KEY"], copyin=[".gemini/settings.json", ".gemini/oauth_creds.json"]),
    "aider": dict(exe="aider", command="aider --yes-always --no-auto-commits --message {prompt}", env=["OPENAI_API_KEY", "ANTHROPIC_API_KEY"], copyin=[".aider.conf.yml"]),
    "cursor": dict(exe="cursor-agent", command="cursor-agent -p {prompt} --force", env=["CURSOR_API_KEY"], copyin=[".cursor/cli-config.json"]),
    "opencode": dict(exe="opencode", command="opencode run {prompt}", env=["ANTHROPIC_API_KEY", "OPENAI_API_KEY"], copyin=[".local/share/opencode/auth.json", ".config/opencode/opencode.json"]),
    "goose": dict(exe="goose", command="goose run --text {prompt}", env=["GOOSE_PROVIDER", "GOOSE_MODEL", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"], copyin=[".config/goose/config.yaml"]),
    "copilot": dict(exe="copilot", command="copilot --allow-all-tools --prompt {prompt}", env=["COPILOT_GITHUB_TOKEN"], copyin=[".copilot/config.json"]),
}
