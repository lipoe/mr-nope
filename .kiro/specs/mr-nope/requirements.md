# Requirements Document

## Introduction

Mr. Nope is an open-source deterministic guardrail tool that prevents AI coding agents from executing explicitly forbidden operations. It sits between the AI agent and tool execution, intercepting shell commands and MCP tool calls before they reach the system. The first concrete use case is preventing `git commit` and `git push` operations while allowing all other git and shell commands to pass through.

The core principle is that policy enforcement happens outside the LLM on a deterministic layer — the same input always produces the same result, with no network access, no LLM inference, and no probabilistic classification involved in the decision.

## Glossary

- **Policy_Engine**: The core component that evaluates commands against a set of deny rules and returns ALLOW or DENY decisions deterministically.
- **Normalizer**: The component that transforms raw command input into a canonical form by decoding URL-encoding, normalizing whitespace, and resolving path prefixes before evaluation.
- **Parser**: The component that performs structural analysis of shell commands to extract the effective command and subcommand, handling pipes, logical operators, nested invocations, and path-qualified binaries.
- **Adapter**: A plugin component that integrates Mr. Nope with a specific AI coding agent (e.g., Cursor, Claude Code, Codex) by hooking into that agent's execution lifecycle.
- **Cursor_Adapter**: The first adapter implementation that uses Cursor's `beforeShellExecution` and `beforeMCPExecution` hooks to intercept operations.
- **CLI**: The command-line interface that provides installation, status, uninstallation, testing, and policy management commands.
- **Policy_File**: A YAML-based configuration file that defines the set of deny rules specifying which command and subcommands combinations are forbidden, where each deny rule maps a command to an array of subcommands.
- **DenyRule**: A single entry in the Policy_File consisting of a `command` (string) and a `subcommands` (array of strings). A command is denied if its parsed command name matches the rule's `command` and its parsed subcommand matches ANY entry in the rule's `subcommands` array.
- **MCP_Tool_Call**: A Model Context Protocol tool invocation that an AI agent may use to execute operations, which must also be inspected for forbidden commands in its input data.
- **Hook**: An integration point provided by an AI coding agent that allows external tools to intercept and approve or reject operations before execution.

## Requirements

### Requirement 1: Deterministic Policy Evaluation

**User Story:** As a developer using an AI coding agent, I want forbidden operations to be deterministically blocked, so that the same command always produces the same allow/deny result regardless of LLM context or conversation state.

#### Acceptance Criteria

1. WHEN a command string is submitted for evaluation, THE Policy_Engine SHALL return either ALLOW or DENY without invoking any LLM, network call, or external API.
2. WHEN the same command string is submitted multiple times against the same Policy_File, THE Policy_Engine SHALL return the same result every time, regardless of prior evaluations or ordering of requests.
3. THE Policy_Engine SHALL make decisions based solely on the Policy_File rules and the normalized/parsed command input.
4. THE Policy_Engine SHALL operate without requiring network access at any point during evaluation.
5. IF a command string is empty, contains only whitespace, or is null, THEN THE Policy_Engine SHALL return ALLOW without error.

### Requirement 2: Input Normalization

**User Story:** As a developer, I want Mr. Nope to detect bypass attempts through encoding and whitespace manipulation, so that forbidden commands cannot be disguised by trivial obfuscation.

#### Acceptance Criteria

1. WHEN a command string contains multiple consecutive whitespace characters or tab characters between tokens, THE Normalizer SHALL collapse them into a single space and trim leading and trailing whitespace from the result.
2. WHEN a command string contains URL-encoded characters (e.g., `%20`, `%09`), THE Normalizer SHALL decode all percent-encoded sequences (case-insensitive) to their character equivalents before further normalization steps.
3. WHEN a command string contains double-encoded URL sequences (e.g., `%2520`), THE Normalizer SHALL decode iteratively until no further URL-encoded sequences remain, up to a maximum of 3 decoding passes.
4. IF URL-encoded sequences still remain after 3 decoding passes, THEN THE Normalizer SHALL treat the partially-decoded result as the final normalized form and pass it to the Parser without further decoding.
5. WHEN a command string contains a path-qualified reference to a binary (e.g., `/usr/bin/git`, `./git`, `../../bin/git`), THE Normalizer SHALL extract the final path segment as the base binary name for evaluation.
6. THE Normalizer SHALL apply normalization steps in this order: URL-decoding first, then whitespace collapsing, then path extraction, ensuring that encoded whitespace or path separators are decoded before subsequent normalization.

### Requirement 3: Shell Command Structural Analysis

**User Story:** As a developer, I want Mr. Nope to understand shell command structure, so that forbidden commands are detected even when embedded in compound shell expressions.

#### Acceptance Criteria

1. WHEN a shell command contains logical operators (`&&`, `||`, `;`), THE Parser SHALL evaluate each sub-command independently against the policy rules.
2. WHEN a shell command uses a nested shell invocation via `sh`, `bash`, or `zsh` with the `-c` flag (e.g., `sh -c "git push"`, `bash -c "git commit -m test"`), THE Parser SHALL extract and evaluate the inner command string, supporting up to 3 levels of nesting depth.
3. WHEN a shell command uses the `command`, `exec`, or `env` builtin prefix before the target command (e.g., `command git push`, `env git push`), THE Parser SHALL strip the prefix and identify the actual command and subcommand for evaluation.
4. WHEN a shell command contains pipe operators (`|`), THE Parser SHALL evaluate each command segment independently against the policy rules.
5. THE Parser SHALL identify the command name and the first non-flag argument (argument not starting with `-`) from each parsed command segment as the subcommand for policy matching.
6. WHEN a shell command contains command substitutions using `$(...)` or backtick syntax, THE Parser SHALL extract and evaluate the substituted command string against the policy rules.

### Requirement 4: Policy File Configuration

**User Story:** As a developer, I want to define forbidden operations in a YAML configuration file, so that policies are extensible and easy to understand.

#### Acceptance Criteria

1. WHEN the Policy_Engine is initialized, THE Policy_Engine SHALL load deny rules from a YAML-formatted Policy_File and retain them in memory for all subsequent evaluations until the process exits.
2. WHEN a Policy_File contains a deny rule with a `command` and `subcommands` field, THE Policy_Engine SHALL deny any parsed command whose command name matches the rule's `command` value and whose parsed subcommand matches ANY entry in the rule's `subcommands` array using case-sensitive exact string comparison.
3. WHEN no deny rule matches a parsed command, THE Policy_Engine SHALL return ALLOW.
4. IF the Policy_File is missing or contains invalid YAML syntax or does not conform to the expected structure (missing `rules` array, missing required `command` or `subcommands` fields in a deny entry), THEN THE Policy_Engine SHALL deny all operations and return an error indication describing which configuration problem was detected.
5. THE Policy_File SHALL support the following structure for deny rules: a `rules` array where each entry contains a `deny` object with required `command` (string, 1–128 characters) and required `subcommands` (non-empty array of strings, each entry 1–128 characters) fields.
6. WHEN a Policy_File contains a deny rule where the `command` field is empty or contains only whitespace, or the `subcommands` field is an empty array, or any entry within the `subcommands` array is empty or contains only whitespace, THEN THE Policy_Engine SHALL treat the Policy_File as malformed.

### Requirement 5: Cursor Adapter — Shell Execution Hook

**User Story:** As a Cursor user, I want Mr. Nope to intercept shell commands before execution, so that forbidden git operations are blocked before they can run.

#### Acceptance Criteria

1. WHEN Cursor triggers a `beforeShellExecution` hook, THE Cursor_Adapter SHALL pass the command string through the Normalizer, then the Parser, then the Policy_Engine, in that order, before returning a decision.
2. WHEN the Policy_Engine returns DENY for a shell command, THE Cursor_Adapter SHALL reject the execution and provide a message indicating which deny rule (command and matched subcommand) was matched.
3. WHEN the Policy_Engine returns ALLOW for a shell command, THE Cursor_Adapter SHALL permit the execution to proceed with the original command string unmodified (byte-for-byte identical to the input received from the hook).
4. IF the command string received from the `beforeShellExecution` hook is empty or contains only whitespace, THEN THE Cursor_Adapter SHALL permit the execution to proceed without invoking the Normalizer, Parser, or Policy_Engine.
5. IF the Normalizer or Parser raises an error during processing of a shell command, THEN THE Cursor_Adapter SHALL deny the execution and provide a message indicating that the command could not be parsed for policy evaluation.
6. THE Cursor_Adapter SHALL not add, remove, or reorder arguments in the command string when permitting execution.

### Requirement 6: Cursor Adapter — MCP Tool Call Hook

**User Story:** As a Cursor user, I want Mr. Nope to inspect MCP tool call input data for forbidden commands, so that git operations cannot bypass shell-level blocking through MCP tools.

#### Acceptance Criteria

1. WHEN Cursor triggers a `beforeMCPExecution` hook, THE Cursor_Adapter SHALL scan all string-valued input parameters of the tool call for command strings by passing each through the Normalizer, Parser, and Policy_Engine.
2. WHEN any string-valued input parameter of an MCP tool call contains a command string that matches a deny rule after normalization and parsing, THE Cursor_Adapter SHALL reject the MCP tool call and provide a message indicating which deny rule (command and matched subcommand) was matched.
3. WHEN no forbidden command is detected in any string-valued input parameter of the MCP tool call, THE Cursor_Adapter SHALL permit the tool call to proceed without modifying the input data.
4. THE Cursor_Adapter SHALL examine the actual input parameters of the MCP tool call, not only the tool name, to detect forbidden operations.

### Requirement 7: CLI — Installation Commands

**User Story:** As a developer, I want a CLI that automatically installs Mr. Nope hooks into my AI coding agent, so that setup is quick and does not require manual configuration.

#### Acceptance Criteria

1. WHEN a user runs `mr-nope install cursor`, THE CLI SHALL configure the Cursor hooks for the current user at the user level (global) and display a confirmation message indicating the adapter name and installation scope.
2. WHEN a user runs `mr-nope install cursor --project`, THE CLI SHALL configure the Cursor hooks for the current project directory only and display a confirmation message indicating the adapter name and installation scope.
3. WHEN a user runs `mr-nope install cursor --global`, THE CLI SHALL configure the Cursor hooks at the user level and display a confirmation message indicating the adapter name and installation scope.
4. IF Cursor hooks already exist at the target location, THEN THE CLI SHALL add Mr. Nope hook entries to the existing configuration while preserving all previously configured hooks unchanged.
5. WHEN a user runs `mr-nope uninstall cursor`, THE CLI SHALL remove Mr. Nope hook configurations from the user-level (global) location without affecting other hooks, and display a confirmation message indicating successful removal.
6. WHEN a user runs `mr-nope uninstall cursor --project`, THE CLI SHALL remove Mr. Nope hook configurations from the current project directory without affecting other hooks.
7. WHEN a user runs `mr-nope status`, THE CLI SHALL display the installation state (installed or not installed) and for each installed adapter display the adapter name and scope (global or project).
8. IF the user runs `mr-nope install` with an unsupported adapter name, THEN THE CLI SHALL reject the command and display an error message listing the supported adapter names.
9. IF the CLI cannot write to the target configuration location due to missing directory or insufficient permissions, THEN THE CLI SHALL exit with a non-zero exit code and display an error message indicating the reason for failure.

### Requirement 8: CLI — Testing and Policy Commands

**User Story:** As a developer, I want to test my policy configuration and view active rules, so that I can verify Mr. Nope is correctly configured before relying on it.

#### Acceptance Criteria

1. WHEN a user runs `mr-nope test`, THE CLI SHALL execute each deny rule from the active policy as a test case by submitting the denied command to the Policy_Engine and verifying it returns DENY, and SHALL report the result (pass or fail) for each rule individually.
2. WHEN all test cases pass during `mr-nope test`, THE CLI SHALL exit with code 0.
3. IF one or more test cases fail during `mr-nope test`, THEN THE CLI SHALL exit with a non-zero exit code and list which deny rules did not produce the expected DENY result.
4. WHEN a user runs `mr-nope policy`, THE CLI SHALL display each deny rule from the active policy (including the default policy if no custom Policy_File is present), showing the command and subcommands fields for each rule.
5. IF no Policy_File is found and no default policy is available, THEN THE CLI SHALL report that no policy is configured and indicate the expected file location.

### Requirement 9: False Positive Avoidance

**User Story:** As a developer, I want Mr. Nope to only block genuinely forbidden operations, so that safe commands like `git status`, `git diff`, or strings containing forbidden command names in non-executable context are not blocked.

#### Acceptance Criteria

1. WHEN a command uses git with a subcommand not listed in the deny rules (e.g., `git status`, `git diff`, `git log`), THE Policy_Engine SHALL return ALLOW.
2. WHEN a forbidden command name appears only inside a single-quoted or double-quoted string argument that is not a command substitution (e.g., `echo "git push"`, `echo 'git push'`), THE Parser SHALL not treat the quoted content as an executable command.
3. WHEN a command contains a forbidden command name as a substring within a larger token (e.g., a filename `git-push-docs.md`, a variable `git_push_count`), THE Parser SHALL match deny rules only against whole command tokens and subcommand tokens separated by whitespace, not against substrings within tokens.
4. WHEN a forbidden command appears inside a command substitution (e.g., `$(git push)` or backtick-enclosed `` `git push` ``), THE Parser SHALL treat the content as an executable command and evaluate it against deny rules.
5. WHEN a forbidden command name appears only in a shell comment (text following an unquoted `#`), THE Parser SHALL not treat the commented content as an executable command.

### Requirement 10: Cross-Platform Support

**User Story:** As a developer, I want Mr. Nope to work on Windows, macOS, and Linux, so that all team members can use it regardless of their operating system.

#### Acceptance Criteria

1. THE CLI SHALL provide pre-compiled binaries for Windows (x86_64), macOS (x86_64 and ARM64), and Linux (x86_64).
2. THE CLI SHALL be installable via `npx @mr-nope/cli` without requiring a pre-installed runtime beyond Node.js (version 18.0 or later) for the npx wrapper.
3. WHEN installing hooks, THE CLI SHALL write hook configurations to the operating-system-specific user-level configuration directory for the target AI coding agent (e.g., Cursor's user settings location on each OS).
4. THE Normalizer SHALL handle both forward-slash and backslash path separators when extracting binary names from fully qualified paths.
5. IF the CLI is run on a platform or architecture for which no pre-compiled binary is available, THEN THE CLI SHALL exit with a non-zero status code and display an error message indicating the unsupported platform and listing the supported platforms.
6. IF the platform-appropriate binary fails to download or extract during installation via npx, THEN THE CLI SHALL exit with a non-zero status code and display an error message describing the failure.

### Requirement 11: Performance

**User Story:** As a developer, I want Mr. Nope to evaluate commands with minimal latency, so that it does not noticeably slow down the AI agent's workflow.

#### Acceptance Criteria

1. THE Policy_Engine SHALL complete command evaluation (normalization, parsing, and policy matching) within 10 milliseconds for a single command string of up to 1024 characters containing up to 10 piped or chained sub-commands, when measured on a machine with at least a 2 GHz dual-core CPU and 4 GB RAM.
2. THE CLI SHALL start and complete a single evaluation operation within 50 milliseconds including process startup time, when measured on a machine with at least a 2 GHz dual-core CPU and 4 GB RAM.
3. THE Policy_Engine SHALL operate without requiring network access, ensuring evaluation works in offline environments.
4. THE compiled binary SHALL have no more than 10 external runtime dependencies and SHALL produce a distributable artifact no larger than 20 MB per platform target.
5. WHEN the Policy_File contains up to 100 deny rules, THE Policy_Engine SHALL still complete command evaluation within 10 milliseconds for a single command string of up to 1024 characters.

### Requirement 12: Security Scope Transparency

**User Story:** As a developer, I want clear documentation about what Mr. Nope does and does not protect against, so that I do not have a false sense of security.

#### Acceptance Criteria

1. WHEN a user runs `mr-nope --help` or `mr-nope status`, THE CLI SHALL display a statement that Mr. Nope only prevents execution via supported hook paths of the integrated AI coding agent.
2. WHEN a user runs `mr-nope --help` or `mr-nope status`, THE CLI SHALL display a statement that Mr. Nope does not prevent a human user from running forbidden commands directly in a terminal.
3. WHEN a user runs `mr-nope --help` or `mr-nope status`, THE CLI SHALL display a statement that Mr. Nope is not a system-wide sandbox or a replacement for OS-level access controls.
4. WHEN Mr. Nope denies an operation, THE Cursor_Adapter SHALL append to the denial message a notice that this protection applies only to AI agent execution via hooks, not to direct terminal usage.
5. THE project README SHALL document that enforcement of deny decisions depends on the host AI coding agent's hook implementation, that Mr. Nope guarantees deterministic decision-making but cannot guarantee that the host agent will honor the deny response, and that this is a known architectural limitation.

### Requirement 13: Extensible Architecture

**User Story:** As a maintainer, I want Mr. Nope's architecture to separate the policy engine from agent-specific adapters, so that new AI coding agents can be supported without modifying core logic.

#### Acceptance Criteria

1. THE Policy_Engine SHALL expose a public interface that accepts a raw command string and returns an ALLOW or DENY decision along with the matched rule identifier (if DENY), independent of any specific adapter implementation.
2. THE Adapter interface SHALL be defined such that implementing a new adapter requires only implementing the Adapter interface methods without modifying the Policy_Engine, Normalizer, or Parser components.
3. THE project structure SHALL separate core components (normalization, parsing, policy) from adapter components in distinct modules or packages.
4. Each Adapter SHALL accept a command or input string, invoke the Policy_Engine interface, and return the decision to the calling agent's hook mechanism.

### Requirement 14: Default Policy

**User Story:** As a new user, I want Mr. Nope to ship with a sensible default policy, so that git commit and git push are blocked immediately after installation without additional configuration.

#### Acceptance Criteria

1. WHEN Mr. Nope is installed without a custom Policy_File present at the expected file location, THE Policy_Engine SHALL load a built-in default policy that denies `git` with subcommands `["commit", "push"]`.
2. WHEN a custom Policy_File is present at the expected file location, THE Policy_Engine SHALL use only the custom policy rules, fully replacing the default policy rather than merging with it.
3. WHEN the user runs `mr-nope policy` and the default policy is active, THE CLI SHALL display the deny rules of the default policy and indicate that the default built-in policy is in use.
4. WHEN the user runs `mr-nope policy` and a custom Policy_File is active, THE CLI SHALL display the custom deny rules and indicate that a custom policy is in use.
