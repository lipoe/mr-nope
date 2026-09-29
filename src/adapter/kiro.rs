// Mr. Nope - Kiro Adapter
// Implements the Adapter trait for Kiro's agent hook system.
//
// Unlike Cursor (which passes `tool_input` as a JSON *string* and reads the
// decision back from a JSON response on stdout), Kiro's `PreToolUse` hook:
//   * receives a JSON payload on stdin with `tool_name` (string) and
//     `tool_input` (an arbitrary JSON *object*, not a stringified blob);
//   * communicates the decision through the process exit code — `0` allows the
//     tool call, `2` blocks it and forwards stderr to the agent.
//
// This adapter converts a Kiro payload into the shared `HookInput`/`HookResponse`
// model so the policy pipeline (Normalizer -> Parser -> PolicyEngine) is reused
// unchanged. The `evaluate` entry point is responsible for translating the
// resulting `HookResponse` into Kiro's exit-code contract.

use crate::adapter::{Adapter, HookInput, HookResponse, Permission};
use crate::engine::{Decision, DenyRule, ParseContext, PolicyEngine, PolicyEvaluator};
use serde::Deserialize;
use serde_json::Value;

/// Kiro tool names that carry a shell command in `tool_input.command`.
///
/// Kiro's built-in shell tool has been seen as both `execute_bash` and `shell`
/// across CLI/IDE surfaces; we treat both as shell-execution tools.
const KIRO_SHELL_TOOLS: &[&str] = &["execute_bash", "shell"];

/// The raw `PreToolUse` payload Kiro writes to a hook command's stdin.
///
/// `tool_input` is kept as a generic `serde_json::Value` because its shape
/// depends entirely on which tool the agent invoked.
#[derive(Debug, Clone, Deserialize)]
pub struct KiroHookPayload {
    /// The tool the agent is about to invoke (e.g. `execute_bash`, `fs_write`).
    #[serde(default)]
    pub tool_name: Option<String>,
    /// The tool's parameters. Arbitrary JSON — a command string for shell
    /// tools, a `{path, text}` object for file writes, etc.
    #[serde(default)]
    pub tool_input: Option<Value>,
    /// Optional hook event name; informational only for Kiro (the trigger is
    /// already encoded by which hook file fired), but accepted if present.
    #[serde(default)]
    pub hook_event_name: Option<String>,
    /// Workspace roots, used for project-level policy discovery when present.
    #[serde(default)]
    pub workspace_roots: Vec<String>,
}

impl KiroHookPayload {
    /// Convert the native Kiro payload into the shared [`HookInput`] model.
    ///
    /// Shell tools (`execute_bash`, `shell`) surface their command string in the
    /// `command` field; every other tool has its entire `tool_input` serialized
    /// back into a JSON string so the adapter can scan all string values.
    pub fn into_hook_input(self) -> HookInput {
        let tool_name = self.tool_name.clone();
        let is_shell = tool_name
            .as_deref()
            .map(|name| KIRO_SHELL_TOOLS.contains(&name))
            .unwrap_or(false);

        let (command, tool_input) = if is_shell {
            // Pull the command string out of tool_input.command for shell tools.
            let command = self
                .tool_input
                .as_ref()
                .and_then(|v| v.get("command"))
                .and_then(|c| c.as_str())
                .map(|s| s.to_string());
            (command, None)
        } else {
            // Non-shell tool: re-serialize the whole tool_input for string scan.
            let tool_input = self.tool_input.as_ref().map(|v| v.to_string());
            (None, tool_input)
        };

        HookInput {
            hook_event_name: self
                .hook_event_name
                .unwrap_or_else(|| "PreToolUse".to_string()),
            command,
            tool_name,
            tool_input,
            workspace_roots: self.workspace_roots,
        }
    }
}

/// The Kiro adapter integrates Mr. Nope with Kiro's agent hook system.
///
/// It handles `PreToolUse` events, routing shell commands and tool inputs
/// through the policy evaluation pipeline.
pub struct KiroAdapter {
    engine: PolicyEngine,
}

impl KiroAdapter {
    /// Create a new KiroAdapter with the given PolicyEngine.
    pub fn new(engine: PolicyEngine) -> Self {
        Self { engine }
    }

    /// Evaluate a shell command from a shell tool (`execute_bash`/`shell`).
    ///
    /// - Empty/whitespace-only command → permit without evaluation.
    /// - Otherwise evaluate through Normalizer → Parser → PolicyEngine.
    pub fn handle_shell_execution(&self, command: &str) -> HookResponse {
        if command.trim().is_empty() {
            return allow(Vec::new());
        }

        let result = self.engine.evaluate(command);
        let notices = result.notice.into_iter().collect();
        match result.decision {
            Decision::Allow => allow(notices),
            Decision::Deny {
                rule,
                matched_subcommand,
            } => Self::deny_response(&rule, &matched_subcommand, notices),
        }
    }

    /// Evaluate an arbitrary tool input by scanning every string value.
    ///
    /// - Empty/absent input → permit.
    /// - JSON parse failure → deny (fail-closed).
    /// - If ANY string value triggers DENY → block the whole tool call.
    pub fn handle_tool_input(&self, tool_input: &str) -> HookResponse {
        if tool_input.trim().is_empty() {
            return allow(Vec::new());
        }

        let json_value: Value = match serde_json::from_str(tool_input) {
            Ok(v) => v,
            Err(_) => {
                let reason = "Kiro tool input could not be parsed as JSON for policy evaluation";
                return Self::deny_response(
                    &DenyRule {
                        command: "__parse_error__".to_string(),
                        subcommands: vec![reason.to_string()],
                    },
                    reason,
                    Vec::new(),
                );
            }
        };

        let mut strings: Vec<String> = Vec::new();
        Self::extract_strings(&json_value, &mut strings);

        let mut notices = Vec::new();
        for string_value in &strings {
            if string_value.trim().is_empty() {
                continue;
            }
            let result = self
                .engine
                .evaluate_in(string_value, ParseContext::ToolInput);
            if let Some(notice) = result.notice {
                notices.push(notice);
            }
            if let Decision::Deny {
                rule,
                matched_subcommand,
            } = result.decision
            {
                return Self::deny_response(&rule, &matched_subcommand, notices);
            }
        }

        allow(notices)
    }

    /// Recursively collect all string values from a JSON value tree.
    fn extract_strings(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::String(s) => out.push(s.clone()),
            Value::Array(arr) => {
                for item in arr {
                    Self::extract_strings(item, out);
                }
            }
            Value::Object(map) => {
                for (_key, val) in map {
                    Self::extract_strings(val, out);
                }
            }
            _ => {}
        }
    }

    /// Build a deny response with rule information.
    fn deny_response(
        rule: &DenyRule,
        matched_subcommand: &str,
        notices: Vec<String>,
    ) -> HookResponse {
        let user_message = format!(
            "🚫 Mr. Nope blocked: {} {} (matched deny rule: {} [{}]). \
             Note: this protection applies only to AI agent execution via hooks, \
             not to direct terminal usage.",
            rule.command,
            matched_subcommand,
            rule.command,
            rule.subcommands.join(", ")
        );

        let agent_message = format!(
            "BLOCKED: The user has explicitly forbidden the action '{} {}'. \
             You must not execute this command or attempt to bypass this restriction. \
             The user configured Mr. Nope to deny '{} {}' operations. \
             Use 'mr-nope policy' to see all active deny rules.",
            rule.command, matched_subcommand, rule.command, matched_subcommand
        );

        HookResponse {
            permission: Permission::Deny,
            user_message: Some(user_message),
            agent_message: Some(agent_message),
            notices,
        }
    }
}

/// A plain allow response with no block message. Parse-error notes ride along.
fn allow(notices: Vec<String>) -> HookResponse {
    HookResponse {
        permission: Permission::Allow,
        user_message: None,
        agent_message: None,
        notices,
    }
}

impl Adapter for KiroAdapter {
    /// Process a hook event and return a response.
    ///
    /// Kiro fires a single `PreToolUse` trigger; routing is by `tool_name`:
    /// - shell tools (`execute_bash`/`shell`) → evaluate the command string.
    /// - any other tool with `tool_input` → scan all string values.
    /// - a shell tool with no command, or a tool with no input → permit.
    fn handle_hook(&self, input: &HookInput) -> HookResponse {
        let is_shell = input
            .tool_name
            .as_deref()
            .map(|name| KIRO_SHELL_TOOLS.contains(&name))
            .unwrap_or(false);

        if is_shell {
            return match &input.command {
                Some(cmd) => self.handle_shell_execution(cmd),
                None => allow(Vec::new()),
            };
        }

        match &input.tool_input {
            Some(tool_input) => self.handle_tool_input(tool_input),
            None => allow(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_adapter() -> KiroAdapter {
        KiroAdapter::new(PolicyEngine::default_policy())
    }

    // --- payload conversion tests ---

    #[test]
    fn test_payload_shell_tool_extracts_command() {
        let payload: KiroHookPayload = serde_json::from_str(
            r#"{"tool_name": "execute_bash", "tool_input": {"command": "git push"}}"#,
        )
        .unwrap();
        let input = payload.into_hook_input();
        assert_eq!(input.command.as_deref(), Some("git push"));
        assert!(input.tool_input.is_none());
        assert_eq!(input.tool_name.as_deref(), Some("execute_bash"));
    }

    #[test]
    fn test_payload_shell_alias_tool_extracts_command() {
        let payload: KiroHookPayload =
            serde_json::from_str(r#"{"tool_name": "shell", "tool_input": {"command": "echo hi"}}"#)
                .unwrap();
        let input = payload.into_hook_input();
        assert_eq!(input.command.as_deref(), Some("echo hi"));
    }

    #[test]
    fn test_payload_non_shell_tool_serializes_input() {
        let payload: KiroHookPayload = serde_json::from_str(
            r#"{"tool_name": "fs_write", "tool_input": {"path": "a.txt", "text": "git push"}}"#,
        )
        .unwrap();
        let input = payload.into_hook_input();
        assert!(input.command.is_none());
        assert!(input.tool_input.is_some());
        assert!(input.tool_input.unwrap().contains("git push"));
    }

    #[test]
    fn test_payload_defaults_hook_event_name() {
        let payload: KiroHookPayload =
            serde_json::from_str(r#"{"tool_name": "fs_read", "tool_input": {}}"#).unwrap();
        let input = payload.into_hook_input();
        assert_eq!(input.hook_event_name, "PreToolUse");
    }

    // --- handle_shell_execution tests ---

    #[test]
    fn test_shell_empty_command_allows() {
        let adapter = default_adapter();
        assert_eq!(
            adapter.handle_shell_execution("").permission,
            Permission::Allow
        );
        assert_eq!(
            adapter.handle_shell_execution("   \t ").permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_shell_allowed_command() {
        let adapter = default_adapter();
        assert_eq!(
            adapter.handle_shell_execution("git status").permission,
            Permission::Allow
        );
    }

    #[test]
    fn test_shell_denied_command() {
        let adapter = default_adapter();
        let response = adapter.handle_shell_execution("git push origin main");
        assert_eq!(response.permission, Permission::Deny);
        assert!(response.user_message.unwrap().contains("git"));
    }

    // --- handle_tool_input tests ---

    #[test]
    fn test_tool_input_empty_allows() {
        let adapter = default_adapter();
        assert_eq!(adapter.handle_tool_input("").permission, Permission::Allow);
    }

    #[test]
    fn test_tool_input_invalid_json_denies() {
        let adapter = default_adapter();
        assert_eq!(
            adapter.handle_tool_input("not json {{{").permission,
            Permission::Deny
        );
    }

    #[test]
    fn test_tool_input_safe_values_allow() {
        let adapter = default_adapter();
        let response = adapter.handle_tool_input(r#"{"path": "/tmp/a", "text": "hello world"}"#);
        assert_eq!(response.permission, Permission::Allow);
    }

    #[test]
    fn test_tool_input_forbidden_string_denies() {
        let adapter = default_adapter();
        let response = adapter.handle_tool_input(r#"{"text": "git commit -m x"}"#);
        assert_eq!(response.permission, Permission::Deny);
    }

    #[test]
    fn test_tool_input_unparsed_text_allows_by_default() {
        let adapter = default_adapter();
        let response = adapter.handle_tool_input(r#"{"path":"a.txt","text":"don't write this"}"#);
        assert_eq!(response.permission, Permission::Allow);
        assert!(response.agent_message.is_none());
        assert!(
            response
                .notices
                .iter()
                .any(|n| n.contains("action=allow") && n.contains("kind=UnclosedQuote")),
            "the allow response carries the parse-error notice: {:?}",
            response.notices
        );
    }

    #[test]
    fn test_tool_input_unparsed_text_does_not_hide_another_deny() {
        let adapter = default_adapter();
        let response = adapter.handle_tool_input(r#"{"items":["don't write this","git push"]}"#);
        assert_eq!(response.permission, Permission::Deny);
        assert!(
            response
                .notices
                .iter()
                .any(|n| n.contains("kind=UnclosedQuote")),
            "a later deny keeps the earlier parse-error notice"
        );
        assert!(response.agent_message.unwrap().contains("BLOCKED"));
    }

    #[test]
    fn test_shell_unclosed_quote_denies_by_default() {
        let adapter = default_adapter();
        let response = adapter.handle_shell_execution("git push \"");
        assert_eq!(response.permission, Permission::Deny);
        let message = response.agent_message.unwrap();
        assert!(message.contains("UnclosedQuote"));
        assert!(message.contains("BLOCKED"));
        assert!(
            response.notices.iter().any(|n| n.contains("action=deny")),
            "the deny response carries the parse-error notice"
        );
    }

    #[test]
    fn test_tool_input_nested_forbidden_denies() {
        let adapter = default_adapter();
        let response = adapter.handle_tool_input(r#"{"outer": {"inner": ["git push"]}}"#);
        assert_eq!(response.permission, Permission::Deny);
    }

    // --- handle_hook routing tests ---

    #[test]
    fn test_handle_hook_shell_deny() {
        let adapter = default_adapter();
        let input = KiroHookPayload {
            tool_name: Some("execute_bash".to_string()),
            tool_input: Some(serde_json::json!({"command": "git push"})),
            hook_event_name: Some("PreToolUse".to_string()),
            workspace_roots: vec![],
        }
        .into_hook_input();
        assert_eq!(adapter.handle_hook(&input).permission, Permission::Deny);
    }

    #[test]
    fn test_handle_hook_shell_allow() {
        let adapter = default_adapter();
        let input = KiroHookPayload {
            tool_name: Some("execute_bash".to_string()),
            tool_input: Some(serde_json::json!({"command": "ls -la"})),
            hook_event_name: None,
            workspace_roots: vec![],
        }
        .into_hook_input();
        assert_eq!(adapter.handle_hook(&input).permission, Permission::Allow);
    }

    #[test]
    fn test_handle_hook_shell_no_command_allows() {
        let adapter = default_adapter();
        let input = KiroHookPayload {
            tool_name: Some("execute_bash".to_string()),
            tool_input: Some(serde_json::json!({})),
            hook_event_name: None,
            workspace_roots: vec![],
        }
        .into_hook_input();
        assert_eq!(adapter.handle_hook(&input).permission, Permission::Allow);
    }

    #[test]
    fn test_handle_hook_non_shell_tool_scans_input() {
        let adapter = default_adapter();
        let input = KiroHookPayload {
            tool_name: Some("fs_write".to_string()),
            tool_input: Some(serde_json::json!({"path": "x", "text": "git push"})),
            hook_event_name: None,
            workspace_roots: vec![],
        }
        .into_hook_input();
        assert_eq!(adapter.handle_hook(&input).permission, Permission::Deny);
    }

    #[test]
    fn test_handle_hook_non_shell_tool_safe_allows() {
        let adapter = default_adapter();
        let input = KiroHookPayload {
            tool_name: Some("fs_read".to_string()),
            tool_input: Some(serde_json::json!({"path": "README.md"})),
            hook_event_name: None,
            workspace_roots: vec![],
        }
        .into_hook_input();
        assert_eq!(adapter.handle_hook(&input).permission, Permission::Allow);
    }

    #[test]
    fn test_handle_hook_no_tool_input_allows() {
        let adapter = default_adapter();
        let input = KiroHookPayload {
            tool_name: Some("some_tool".to_string()),
            tool_input: None,
            hook_event_name: None,
            workspace_roots: vec![],
        }
        .into_hook_input();
        assert_eq!(adapter.handle_hook(&input).permission, Permission::Allow);
    }

    // --- extract_strings tests ---

    #[test]
    fn test_extract_strings_nested() {
        let json: Value = serde_json::from_str(r#"{"a": [{"b": "found"}], "c": 3}"#).unwrap();
        let mut strings = Vec::new();
        KiroAdapter::extract_strings(&json, &mut strings);
        assert_eq!(strings, vec!["found".to_string()]);
    }
}
