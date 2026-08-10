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

### Via npx (recommended)

```bash
npx @mr-nope/cli install cursor
```

### From source

```bash
git clone https://github.com/mr-nope/mr-nope
cd mr-nope
cargo build --release
./target/release/mr-nope install cursor
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
mr-nope status      # Show installation state
mr-nope policy      # Display active deny rules
mr-nope test        # Self-test: verify all deny rules work
mr-nope install     # Install hooks for an adapter
mr-nope uninstall   # Remove hooks for an adapter
```

### Custom Policy

Create `.mr-nope.yml` in your project root:

```yaml
rules:
  - deny:
      command: "git"
      subcommands:
        - "commit"
        - "push"
        - "rebase"
  - deny:
      command: "rm"
      subcommands:
        - "-rf"
  - deny:
      command: "docker"
      subcommands:
        - "push"
```

A custom policy **fully replaces** the default — there's no merging. If you want the default git protections plus your own rules, include them explicitly.

### Default Policy

Without a custom `.mr-nope.yml`, Mr. Nope blocks:

- `git commit`
- `git push`
- `git merge`
- `git rebase`
- `git reset`
- `git cherry-pick`
- `git revert`
- `git tag`

All other commands pass through.

## What it catches

Mr. Nope handles common bypass attempts:

- **URL encoding:** `git%20push`, `%67%69%74%20push`, double/triple encoding
- **Path-qualified binaries:** `/usr/bin/git push`, `..\..\bin\git push`
- **Compound commands:** `echo ok && git push`, `ls | git push`
- **Nested shells:** `sh -c "git push"`, `bash -c "zsh -c 'git push'"`
- **Prefix builtins:** `command git push`, `env FOO=bar git push`
- **Command substitutions:** `echo $(git push)`, `` echo `git push` ``
- **MCP tool calls:** Scans all string parameters in tool input JSON

## What it does NOT catch

- Commands run directly by a human in a terminal
- Operations that don't go through the agent's hook system
- Agent behaviors that don't involve shell commands or MCP tool calls
- Semantic equivalents not in the deny list (e.g., using a git library directly)

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
├── engine.rs          # Policy loading, matching, evaluation
├── adapter/
│   ├── mod.rs         # Adapter trait
│   └── cursor.rs      # Cursor hook handler
├── cli/
│   ├── mod.rs         # CLI argument parsing (clap)
│   ├── install.rs     # Install/uninstall commands
│   ├── status.rs      # Status display
│   ├── test_cmd.rs    # Policy self-test
│   ├── policy.rs      # Policy display
│   └── evaluate.rs    # Hook entry point + policy discovery
└── main.rs            # Binary entry point
```

## License

MIT
