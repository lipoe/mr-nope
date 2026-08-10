# Implementation Plan: Mr. Nope

## Overview

Implement Mr. Nope as a Rust CLI tool that intercepts AI coding agent operations and evaluates them against a YAML-based deny-list policy. The implementation follows a bottom-up approach: core pipeline components first (Normalizer → Parser → Policy Engine), then the Cursor adapter layer, and finally the CLI commands and distribution setup.

## Tasks

- [x] 1. Set up project structure and core interfaces
  - [x] 1.1 Initialize Rust project with Cargo workspace and dependencies
    - Run `cargo init` with binary target named `mr-nope`
    - Add dependencies: `serde`, `serde_json`, `serde_yaml`, `clap` (CLI), `percent-encoding`, `proptest` (dev)
    - Create module structure: `src/normalizer.rs`, `src/parser.rs`, `src/engine.rs`, `src/adapter/mod.rs`, `src/adapter/cursor.rs`, `src/cli/mod.rs`
    - Create test directories: `tests/properties/`, `tests/unit/`, `tests/integration/`
    - _Requirements: 13.3_

  - [x] 1.2 Define core types, traits, and data models
    - Implement `Decision`, `DenyRule`, `EvaluationResult`, `ParsedCommand`, `NormalizedOutput` structs/enums
    - Define `PolicyEvaluator` trait with `fn evaluate(&self, raw_command: &str) -> EvaluationResult`
    - Define `Adapter` trait with `fn handle_hook(&self, input: &HookInput) -> HookResponse`
    - Implement `HookInput`, `HookResponse`, `Permission` types with serde Serialize/Deserialize
    - Define error types: `PolicyError`, `ParseError`, `NormalizationError`, `AdapterError`
    - _Requirements: 13.1, 13.2, 13.4_

- [x] 2. Implement the Normalizer
  - [x] 2.1 Implement URL decoding with iterative passes
    - Implement percent-decoding that handles case-insensitive hex sequences
    - Apply decoding iteratively up to 3 passes, stopping early if no change detected
    - After 3 passes, pass partially-decoded result through as final form
    - Invalid percent-encoding sequences (e.g., `%ZZ`) pass through as-is without error
    - _Requirements: 2.2, 2.3, 2.4_

  - [x] 2.2 Implement whitespace collapsing
    - Collapse multiple consecutive spaces and tabs into a single space
    - Trim leading and trailing whitespace from the result
    - _Requirements: 2.1_

  - [x] 2.3 Implement path extraction
    - Detect path-qualified binary references (forward slash, backslash, relative paths)
    - Extract the final path segment as the base binary name
    - Handle both `/usr/bin/git` and `..\..\bin\git` patterns
    - _Requirements: 2.5, 10.4_

  - [x] 2.4 Wire normalization pipeline in correct order
    - Apply steps in order: URL-decode → whitespace-collapse → path-extract
    - Expose `Normalizer::normalize(&self, input: &str) -> NormalizedOutput` method
    - _Requirements: 2.6_

  - [x] 2.5 Write property tests for Normalizer
    - **Property 3: Whitespace Normalization**
    - **Property 4: URL Decoding Round-Trip**
    - **Property 5: Path Extraction with Any Separator**
    - **Property 6: Normalization Order Correctness**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.5, 2.6, 10.4**

  - [x] 2.6 Write unit tests for Normalizer
    - Test specific examples: encoded git commands, double-encoded paths, mixed separators
    - Test edge cases: 4+ encoding levels (stops at 3), empty input, whitespace-only input
    - Test invalid encoding sequences pass through unchanged
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

- [x] 3. Implement the Parser
  - [x] 3.1 Implement compound command splitting
    - Split on unquoted `&&`, `||`, `;`, and `|` operators
    - Preserve quote awareness (single, double quotes) during splitting
    - Return each segment as an independent command for evaluation
    - _Requirements: 3.1, 3.4_

  - [x] 3.2 Implement nested shell extraction
    - Detect `sh -c`, `bash -c`, `zsh -c` patterns
    - Extract the inner command string (handling quoted arguments)
    - Support up to 3 levels of nesting depth
    - _Requirements: 3.2_

  - [x] 3.3 Implement builtin prefix stripping
    - Detect and strip `command`, `exec`, `env` prefixes
    - Identify the actual command and subcommand after stripping
    - _Requirements: 3.3_

  - [x] 3.4 Implement command and subcommand identification
    - Identify binary name as the command
    - Identify first non-flag argument (not starting with `-`) as the subcommand
    - Handle edge cases: flags before subcommand, no subcommand present
    - _Requirements: 3.5_

  - [x] 3.5 Implement command substitution extraction
    - Detect `$(...)` syntax and extract inner commands
    - Detect backtick syntax and extract inner commands
    - Add extracted commands to the set of commands evaluated against policy
    - _Requirements: 3.6, 9.4_

  - [x] 3.6 Implement quote awareness and comment handling
    - Track single-quoted and double-quoted regions; do not treat quoted content as commands
    - Detect unquoted `#` and ignore all text following it as a shell comment
    - Ensure forbidden command names inside quotes or comments are not matched
    - _Requirements: 9.2, 9.5_

  - [x] 3.7 Implement substring matching avoidance
    - Match deny rules only against whole command tokens separated by whitespace
    - Do not match substrings within larger tokens (e.g., filenames, variable names)
    - _Requirements: 9.3_

  - [x] 3.8 Write property tests for Parser
    - **Property 7: Compound Command Splitting**
    - **Property 8: Nested Shell Extraction**
    - **Property 9: Builtin Prefix Stripping**
    - **Property 10: Command and Subcommand Identification**
    - **Property 11: Command Substitution Extraction**
    - **Property 18: Quoted Strings Not Treated as Commands**
    - **Property 19: Substring Matching Avoidance**
    - **Property 20: Comments Not Treated as Commands**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 9.2, 9.3, 9.4, 9.5**

  - [x] 3.9 Write unit tests for Parser
    - Test specific examples from requirements: `echo "git push"`, `git-push-docs.md`, `$(git push)`
    - Test edge cases: deeply nested shells (4+ levels rejected), unclosed quotes, empty segments
    - Test compound commands with mixed operators
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 9.2, 9.3, 9.4, 9.5_

- [x] 4. Checkpoint - Core parsing pipeline
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement the Policy Engine
  - [x] 5.1 Implement YAML policy file loading and validation
    - Parse YAML using `serde_yaml` into policy data structures
    - Validate schema: `rules` array required, each entry needs `deny` with `command` (1–128 chars, non-whitespace-only) and `subcommands` (non-empty array, each 1–128 chars, non-whitespace-only)
    - Return `PolicyError` for any schema violation with specific error description
    - _Requirements: 4.1, 4.4, 4.5, 4.6_

  - [x] 5.2 Implement built-in default policy
    - Embed default policy (deny git commit, push) as a compiled-in fallback
    - Load default when no custom policy file exists at expected location
    - Track whether loaded policy is default or custom (via `is_default` field)
    - _Requirements: 14.1, 14.2_

  - [x] 5.3 Implement policy matching logic
    - Match parsed command name against deny rule `command` field (case-sensitive exact match)
    - Match parsed subcommand against deny rule `subcommands` array entries (case-sensitive exact match)
    - Return DENY with matched rule if both command and subcommand match; ALLOW otherwise
    - Handle empty/whitespace-only input by returning ALLOW without evaluation
    - _Requirements: 4.2, 4.3, 1.5, 9.1_

  - [x] 5.4 Implement full PolicyEvaluator trait
    - Wire Normalizer → Parser → PolicyEngine into the `evaluate` method
    - Return `EvaluationResult` with decision, raw input, normalized form, and parsed commands
    - Handle malformed policy (deny all) and parse errors (deny specific command)
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 13.1_

  - [x] 5.5 Write property tests for Policy Engine
    - **Property 1: Evaluation Determinism**
    - **Property 2: Empty and Whitespace-Only Inputs Are Allowed**
    - **Property 12: Policy Matching Correctness**
    - **Property 13: Malformed Policy Denies All**
    - **Property 14: Valid Policy Schema Acceptance**
    - **Property 21: Custom Policy Fully Replaces Default**
    - **Validates: Requirements 1.2, 1.5, 4.2, 4.3, 4.4, 4.5, 4.6, 5.4, 9.1, 14.2**

  - [x] 5.6 Write unit tests for Policy Engine
    - Test `git status` → ALLOW, `git push` → DENY, `git commit` → DENY
    - Test custom policy replaces default: custom allows push but denies other commands
    - Test malformed YAML variants: missing rules, empty command, empty subcommands array
    - Test 100-rule policy still evaluates correctly
    - _Requirements: 1.1, 1.2, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 9.1, 14.1, 14.2_

- [x] 6. Implement the Cursor Adapter
  - [x] 6.1 Implement shell execution hook handler
    - Parse stdin JSON for `beforeShellExecution` events
    - Extract `command` field and pass through Normalizer → Parser → PolicyEngine
    - Return `{"permission": "allow"}` or `{"permission": "deny", "userMessage": "...", "agentMessage": "..."}` on stdout
    - Short-circuit: empty/whitespace-only command → permit without evaluation
    - On parse/normalization error → deny with error message
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 6.2 Implement MCP tool call hook handler
    - Parse stdin JSON for `beforeMCPExecution` events
    - Extract all string-valued fields from `tool_input` JSON (recursive scan)
    - Evaluate each string value through Normalizer → Parser → PolicyEngine
    - If ANY string triggers DENY → reject entire MCP call with matched rule info
    - If none match → permit with unmodified input data
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [x] 6.3 Implement denial message formatting
    - Format user message: `🚫 Mr. Nope blocked: {cmd} {subcmd} (matched deny rule: {command} [{subcommands}])`
    - Append transparency notice to all denial messages
    - Format agent message: `Command '{cmd} {subcmd}' is blocked by Mr. Nope policy...`
    - _Requirements: 5.2, 12.4_

  - [x] 6.4 Write property tests for Cursor Adapter
    - **Property 15: Adapter Response Correctness**
    - **Property 16: Parse Error Results in Denial**
    - **Property 17: MCP Tool Call Scanning**
    - **Validates: Requirements 5.2, 5.3, 5.5, 5.6, 6.1, 6.2, 6.3**

  - [x] 6.5 Write unit tests for Cursor Adapter
    - Test specific Cursor hook JSON payloads from design document
    - Test MCP tool call with forbidden command in nested input parameters
    - Test error conditions: malformed JSON input, missing fields
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 6.1, 6.2, 6.3, 6.4_

- [x] 7. Checkpoint - Core evaluation pipeline complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Implement CLI commands
  - [x] 8.1 Set up CLI argument parsing with clap
    - Define subcommands: `install`, `uninstall`, `status`, `test`, `policy`, `evaluate`
    - `install`/`uninstall` take adapter name (e.g., `cursor`) and `--project`/`--global` flags
    - `evaluate` is the hook entry point (reads stdin, writes stdout)
    - Add `--help` with security scope transparency statements
    - _Requirements: 7.1, 7.2, 7.3, 12.1, 12.2, 12.3_

  - [x] 8.2 Implement install and uninstall commands
    - Determine OS-specific hook configuration path (project-level or user-level)
    - Read existing `hooks.json` if present, preserve existing hooks
    - Add/remove Mr. Nope hook entries for `beforeShellExecution` and `beforeMCPExecution`
    - Write updated `hooks.json`, create directories as needed
    - Handle errors: unsupported adapter name, permission failures, missing directories
    - Display confirmation messages with adapter name and installation scope
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.8, 7.9, 10.3_

  - [x] 8.3 Implement status command
    - Detect installed adapters by checking hook configuration file locations
    - Display installation state (installed/not installed), adapter name, and scope (global/project)
    - Include security scope transparency statements in output
    - _Requirements: 7.7, 12.1, 12.2, 12.3_

  - [x] 8.4 Implement test command
    - Load active policy (custom or default)
    - For each deny rule, synthesize a command string (`{command} {subcommand}`) and evaluate
    - Verify each returns DENY; report pass/fail per rule
    - Exit code 0 if all pass, non-zero if any fail
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 8.5 Implement policy command
    - Load and display active policy rules (command + subcommands for each deny rule)
    - Indicate whether default built-in policy or custom policy is active
    - If no policy found and no default available, report expected file location
    - _Requirements: 8.4, 8.5, 14.3, 14.4_

  - [x] 8.6 Write unit tests for CLI commands
    - Test install/uninstall with temporary directories
    - Test status output format
    - Test test command with passing and failing policies
    - Test policy display for default and custom policies
    - _Requirements: 7.1, 7.4, 7.5, 7.7, 7.8, 7.9, 8.1, 8.2, 8.3, 8.4, 8.5_

- [x] 9. Implement the evaluate entry point and wire everything together
  - [x] 9.1 Implement the `evaluate` subcommand as the hook entry point
    - Read JSON from stdin, detect hook event type (`beforeShellExecution` or `beforeMCPExecution`)
    - Route to appropriate Cursor adapter handler
    - Write JSON response to stdout
    - Fail-closed: unknown hook event → deny; malformed input → deny
    - _Requirements: 5.1, 6.1, 13.4_

  - [x] 9.2 Implement policy file discovery
    - Search for `.mr-nope.yml` in workspace root (from `workspace_roots` in hook input)
    - Fall back to built-in default policy if no custom file found
    - Custom policy fully replaces default (no merging)
    - _Requirements: 14.1, 14.2_

  - [x] 9.3 Write integration tests for end-to-end hook flow
    - Pipe Cursor hook JSON to binary stdin, verify stdout response
    - Test shell command deny/allow scenarios end-to-end
    - Test MCP tool call deny/allow scenarios end-to-end
    - Test malformed input handling
    - _Requirements: 5.1, 5.2, 5.3, 6.1, 6.2, 6.3_

- [x] 10. Cross-platform support and distribution
  - [x] 10.1 Set up cross-compilation targets and CI build configuration
    - Configure Cargo targets: `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`
    - Create build script or CI configuration for compiling all targets
    - Verify binary size stays under 20 MB per target
    - _Requirements: 10.1, 11.4_

  - [x] 10.2 Create npx wrapper package
    - Create `npm/` directory with `package.json` for `@mr-nope/cli`
    - Implement platform detection and binary download/extraction in a Node.js wrapper script
    - Handle unsupported platform with clear error message and supported platform list
    - Handle download/extraction failures with descriptive error messages
    - _Requirements: 10.2, 10.5, 10.6_

  - [x] 10.3 Write integration tests for CLI install/uninstall
    - Test installation writes correct hooks.json for project and global scope
    - Test uninstallation removes only Mr. Nope entries, preserving other hooks
    - Test cross-platform path handling in hook configuration
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 10.3_

- [x] 11. Final checkpoint - All tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The implementation language is Rust as specified in the design document
- The `proptest` crate is used for property-based testing
- Performance requirements (sub-10ms evaluation, sub-50ms startup) are validated by integration benchmarks

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2"] },
    { "id": 2, "tasks": ["2.1", "3.1", "5.1"] },
    { "id": 3, "tasks": ["2.2", "3.2", "3.3", "5.2"] },
    { "id": 4, "tasks": ["2.3", "3.4", "3.5", "5.3"] },
    { "id": 5, "tasks": ["2.4", "3.6", "3.7"] },
    { "id": 6, "tasks": ["2.5", "2.6", "3.8", "3.9", "5.4"] },
    { "id": 7, "tasks": ["5.5", "5.6"] },
    { "id": 8, "tasks": ["6.1", "6.2"] },
    { "id": 9, "tasks": ["6.3", "6.4", "6.5"] },
    { "id": 10, "tasks": ["8.1"] },
    { "id": 11, "tasks": ["8.2", "8.3", "8.4", "8.5"] },
    { "id": 12, "tasks": ["8.6", "9.1", "9.2"] },
    { "id": 13, "tasks": ["9.3", "10.1"] },
    { "id": 14, "tasks": ["10.2", "10.3"] }
  ]
}
```
