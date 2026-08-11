# Mr. Nope

Deterministic guardrail tool that prevents AI coding agents from executing forbidden operations. Mr. Nope sits between the AI agent and tool execution, intercepting shell commands and MCP tool calls before they reach the system.

## Why?

AI coding agents (Cursor, Claude Code, Codex, etc.) can execute shell commands and tool calls on your behalf. Sometimes you want hard limits — operations that should *never* happen regardless of what the LLM decides. Mr. Nope gives you a deterministic deny-list that can't be talked around, reasoned away, or bypassed through prompt injection.

The default policy blocks `git commit`, `git push`, `git merge`, `git rebase`, `git reset`, `git cherry-pick`, `git revert`, and `git tag` — keeping version control decisions in human hands.

## How it works

```
AI Agent → Hook → Mr. Nope → ALLOW / DENY
                     ↓
         Normalizer → Parser → Policy Engine
```

1. The AI agent triggers a hook (shell command or MCP tool call)
2. Mr. Nope normalizes the input (URL decoding, whitespace, path extraction)
3. Parses the command structure (pipes, nested shells, substitutions, prefixes)
4. Matches against the deny-list policy
5. Returns ALLOW or DENY — no network, no LLM, no randomness

Same input always produces the same result.

## Installation

### Via npm (recommended)

```bash
npm install -g @mr-nope/cli
mr-nope install cursor --global
```

### Via Cargo (if you have Rust installed)

```bash
cargo install --git https://github.com/lipoe/mr-nope
mr-nope install cursor --global
```

### From source

```bash
git clone https://github.com/lipoe/mr-nope
cd mr-nope
cargo install --path .
mr-nope install cursor --global
```

### Scopes

```bash
# Global (user-level, applies to all projects)
mr-nope install cursor --global

# Project-level (current directory only)
mr-nope install cursor --project
```

## Usage

Once installed, Mr. Nope runs automatically via Cursor's hook system. No manual invocation needed.

### CLI Commands

```bash
mr-nope status              # Show installation state
mr-nope policy              # Display effective (merged) deny rules
mr-nope policy --scope global  # Show global policy location and rules
mr-nope test                # Self-test: verify all deny rules work
mr-nope install             # Install hooks for an adapter
mr-nope uninstall           # Remove hooks for an adapter
```

### Policy Hierarchy

Mr. Nope uses a three-level policy lookup:

1. **Project-level** — `.mr-nope.yml` in workspace root
2. **Global (user-level)** — `~/.config/mr-nope/policy.yml`
3. **Built-in default** — hardcoded in the binary

The first level found wins, unless `mode: extend` is used (see below).

### Global Policy

Set your personal defaults by creating `~/.config/mr-nope/policy.yml`:

```bash
# Show where the file is expected
mr-nope policy --scope global
```

```yaml
# ~/.config/mr-nope/policy.yml
rules:
  - deny:
      command: "git"
      subcommands:
        - "push"
        - "merge"
        - "rebase"
        - "reset"
```

This replaces the hardcoded default for all projects that don't have their own `.mr-nope.yml`.

### Project Policy

Create `.mr-nope.yml` in your project root. Two modes available:

**`mode: replace`** (default) — completely replaces the global/default policy:

```yaml
rules:
  - deny:
      command: "git"
      subcommands:
        - "push"
  - deny:
      command: "docker"
      subcommands:
        - "push"
```

**`mode: extend`** — extends the global policy. Same command = project's subcommands override global's for that command. New commands are added:

```yaml
mode: extend

rules:
  - deny:
      command: "git"
      subcommands:
        - "push"
        - "merge"
  - deny:
      command: "docker"
      subcommands:
        - "push"
```

If the global policy denies `git [commit, push, merge, rebase]` and the project extends with `git [push, merge]`, then only `git push` and `git merge` are blocked for git — `commit` and `rebase` are no longer blocked in this project. The `docker push` rule is added on top.

### Default Policy

Without any custom policy file, Mr. Nope blocks:

- `git commit`
- `git push`
- `git merge`
- `git rebase`
- `git reset`
- `git cherry-pick`
- `git revert`
- `git tag`

All other commands pass through.

### Self-Protection

Mr. Nope protects its own configuration files from being modified by the AI agent. Any command that mentions protected file paths or attempts to use `mr-nope` CLI for write operations is blocked. This is hardcoded in the binary and cannot be disabled via policy configuration.

## Evasion Prevention (Command Level)

Mr. Nope detects forbidden commands even when disguised through these techniques:

| Evasion Technique | Example | Detected? |
|---|---|---|
| Plain command | `git push` | ✅ Blocked |
| URL-encoded space | `git%20push` | ✅ Decoded then matched |
| Double URL-encoding | `git%2520push` | ✅ Iterative decoding (up to 3 passes) |
| Triple URL-encoding | `git%252520push` | ✅ 3 passes decodes it |
| Quadruple+ encoding | `git%25252520push` | ⚠️ Partially decoded, may pass through |
| Full URL-encoded binary | `%67%69%74 push` | ✅ Each byte decoded |
| Path-qualified (Unix) | `/usr/bin/git push` | ✅ Path stripped, `git` extracted |
| Path-qualified (Windows) | `C:\Program Files\Git\git.exe push` | ✅ Final segment extracted |
| Relative path | `../../bin/git push` | ✅ Path stripped |
| Compound (`&&`) | `echo ok && git push` | ✅ Each sub-command evaluated |
| Compound (`\|\|`) | `false \|\| git push` | ✅ Each sub-command evaluated |
| Pipe (`\|`) | `echo x \| git push` | ✅ Each segment evaluated |
| Semicolon | `ls; git push` | ✅ Each segment evaluated |
| Nested shell (1 level) | `sh -c "git push"` | ✅ Inner command extracted |
| Nested shell (2 levels) | `bash -c "sh -c 'git push'"` | ✅ Recursive extraction |
| Nested shell (3 levels) | `sh -c "bash -c 'zsh -c git push'"` | ✅ Max depth supported |
| Nested shell (4+ levels) | 4+ layers of sh -c | ❌ Denied (NestingTooDeep = fail-closed) |
| Prefix: `command` | `command git push` | ✅ Prefix stripped |
| Prefix: `exec` | `exec git push` | ✅ Prefix stripped |
| Prefix: `env` | `env FOO=bar git push` | ✅ Prefix + vars stripped |
| Chained prefixes | `env command exec git push` | ✅ All stripped |
| Command substitution `$()` | `echo $(git push)` | ✅ Inner command extracted and evaluated |
| Command substitution backtick | `` echo `git push` `` | ✅ Inner command extracted |
| Whitespace padding | `git    push` | ✅ Collapsed to single space |
| Tabs | `git\tpush` | ✅ Collapsed |
| Leading/trailing spaces | `  git push  ` | ✅ Trimmed |
| MCP tool call (shell in param) | `{"command": "git push"}` | ✅ All string values scanned |
| MCP nested JSON | `{"a": {"b": "git push"}}` | ✅ Recursive string extraction |
| Quoted string (not a command) | `echo "git push"` | ✅ Allowed (not executable) |
| Comment after command | `echo hi # git push` | ✅ Allowed (comment stripped) |
| Substring in filename | `cat git-push-docs.md` | ✅ Allowed (whole-token matching) |
| Variable name | `echo $git_push_count` | ✅ Allowed (not a command token) |

## Self-Protection Details

| Action | Example | Result |
|---|---|---|
| Agent runs `mr-nope install` | `mr-nope install cursor --global` | ❌ Blocked |
| Agent runs `mr-nope uninstall` | `mr-nope uninstall cursor` | ❌ Blocked |
| Agent reads policy (CLI) | `mr-nope policy` | ✅ Allowed |
| Agent checks status | `mr-nope status` | ✅ Allowed |
| Agent runs self-test | `mr-nope test` | ✅ Allowed |
| Agent reads config via shell | `cat .mr-nope.yml` | ❌ Blocked |
| Agent deletes config | `rm .mr-nope.yml` | ❌ Blocked |
| Agent overwrites config | `echo "rules: []" > .mr-nope.yml` | ❌ Blocked |
| Agent edits config | `sed -i 's/push//' .mr-nope.yml` | ❌ Blocked |
| Agent deletes hooks | `rm ~/.cursor/hooks.json` | ❌ Blocked |
| Agent empties hooks | `truncate -s 0 hooks.json` | ❌ Blocked |
| Agent uses PowerShell | `Set-Content hooks.json '{}'` | ❌ Blocked |
| Agent edits global policy | `echo '' > ~/.config/mr-nope/policy.yml` | ❌ Blocked |
| Hook entry point (internal) | `mr-nope evaluate` | ✅ Allowed (required for operation) |

**What self-protection does NOT prevent:**

| Bypass Vector | Why it's not caught | Difficulty |
|---|---|---|
| Agent creates and runs a custom script | `./cleanup.sh` — if the script name contains no protected patterns | High — agent must first create a file (likely caught by file-write MCP tool scan), then invoke it |
| Agent uses base64-encoded path | `echo Lm1yLW5vcGUueW1s \| base64 -d \| xargs rm` — no literal "mr-nope" or filenames | High — requires non-trivial obfuscation the agent must plan deliberately |
| Agent uses hex/octal escapes | `printf '\x2e\x6d\x72...' \| xargs rm` — path built from escape codes | High — requires character-level construction |
| Human disables it manually | Direct terminal access bypasses hooks entirely | N/A — by design, not a threat model |

**What IS caught despite looking like a bypass:**

| Looks like a bypass | Why it's still caught |
|---|---|
| `rm $(echo .mr-nope.yml)` | `.mr-nope.yml` appears as literal substring in the full command |
| `python -c "os.remove('.mr-nope.yml')"` | `.mr-nope.yml` appears as literal substring |
| `f=".mr-nope"; rm "${f}.yml"` | `mr-nope` appears literally → CLI invocation check triggers |
| `python -c "os.remove(chr(46)+'mr-nope'+chr(46)+'yml')"` | `mr-nope` appears literally in the command string |
| `sh -c "rm .mr-nope.yml"` | Nested shell content still contains the literal path |
| `cat .mr-nope.yml \| xargs rm` | `.mr-nope.yml` appears in the command string |
| `base64 -d <<< "..." > .mr-nope.yml` | `.mr-nope.yml` appears as the redirect target |
| `mr-nope install cursor` | CLI write subcommand → blocked regardless of context |
| `Set-Content hooks.json '{}'` | `hooks.json` appears as literal substring |

**Bottom line:** Self-protection raises the bar significantly. Any bypass that still mentions "mr-nope", ".mr-nope.yml", or "hooks.json" anywhere in the command string is caught. Only obfuscation that completely avoids these literals (base64, hex escapes, pre-written scripts) can bypass it — and those require multi-step deliberate evasion that would be obvious in the conversation history.

## Limitations

**Mr. Nope is not a security sandbox.** It is a policy enforcement layer that depends on the host AI coding agent's hook implementation.

- Enforcement relies on the agent honoring the deny response. Mr. Nope guarantees deterministic decision-making but cannot guarantee that the host agent will respect the deny.
- It only intercepts operations via supported hook paths (`beforeShellExecution`, `beforeMCPExecution`).
- It does not prevent a human user from running forbidden commands directly.
- It is not a replacement for OS-level access controls, sandboxing, or permission systems.
- Maximum 3 levels of URL decoding and shell nesting are analyzed. Deeper obfuscation passes through as partially decoded.

## Supported Platforms

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | x86_64 | `mr-nope-linux-x64` |
| macOS | x86_64 | `mr-nope-darwin-x64` |
| macOS | ARM64 (Apple Silicon) | `mr-nope-darwin-arm64` |
| Windows | x86_64 | `mr-nope-win32-x64.exe` |

Requires Node.js 18+ for the npx wrapper. The binary itself has no runtime dependencies.

## Supported Adapters

- **Cursor** — via `beforeShellExecution` and `beforeMCPExecution` hooks

More adapters can be added by implementing the `Adapter` trait without modifying core logic.

## Development

```bash
cargo build          # Build debug binary
cargo test           # Run all 447 tests
cargo test --test properties   # Property-based tests only
cargo test --test integration  # End-to-end tests only
cargo build --release          # Optimized release build
```

## Architecture

```
src/
├── normalizer.rs      # URL decoding, whitespace, path extraction
├── parser.rs          # Command structure analysis
├── engine.rs          # Policy loading, matching, evaluation, merge logic
├── self_protection.rs # Hardcoded protection of config files
├── adapter/
│   ├── mod.rs         # Adapter trait
│   └── cursor.rs      # Cursor hook handler
├── cli/
│   ├── mod.rs         # CLI argument parsing (clap)
│   ├── install.rs     # Install/uninstall commands
│   ├── status.rs      # Status display
│   ├── test_cmd.rs    # Policy self-test
│   ├── policy.rs      # Policy display (with --scope global)
│   └── evaluate.rs    # Hook entry point + policy discovery + merge
└── main.rs            # Binary entry point
```

## License

MIT
