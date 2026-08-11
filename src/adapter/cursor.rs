// Mr. Nope - Cursor Adapter
// Implements the Adapter trait for Cursor's hook system.

use crate::adapter::{Adapter, HookInput, HookResponse, Permission};
use crate::engine::{Decision, DenyRule, PolicyEngine, PolicyEvaluator};
use serde_json::Value;

/// The Cursor adapter integrates Mr. Nope with Cursor's hook system.
///
/// It handles `beforeShellExecution` and `beforeMCPExecution` events,
/// routing them through the policy evaluation pipeline.
pub struct CursorAdapter {
    engine: PolicyEngine,
}

impl CursorAdapter {
    /// Create a new CursorAdapter with the given PolicyEngine.
    pub fn new(engine: PolicyEngine) -> Self {
        Self { engine }
    }

    /// Handle `beforeShellExecution`: evaluate the command field.
    ///
    /// - Empty/whitespace-only command → permit without evaluation.
    /// - On parse/normalization error → deny (fail-closed).
    /// - Otherwise evaluate through Normalizer → Parser → PolicyEngine.
    pub fn handle_shell_execution(&self, command: &str) -> HookResponse {
        // Short-circuit: empty/whitespace-only → permit
        if command.trim().is_empty() {
            return HookResponse {
                permission: Permission::Allow,
                user_message: None,
                agent_message: None,
            };
        }

        let result = self.engine.evaluate(command);

        match result.decision {
            Decision::Allow => HookResponse {
                permission: Permission::Allow,
                user_message: None,
                agent_message: None,
            },
            Decision::Deny {
                rule,
                matched_subcommand,
            } => Self::deny_response(&rule, &matched_subcommand),
        }
    }

    /// Handle `beforeMCPExecution`: scan all string values in tool_input JSON.
    ///
    /// - If `tool_input` is None or empty → permit.
    /// - If JSON parsing fails → deny (fail-closed).
    /// - Recursively extract all string values from the JSON tree.
    /// - Evaluate each string through the policy engine.
    /// - If ANY string triggers DENY → reject entire MCP call.
    /// - If none match → permit with unmodified input data.
    pub fn handle_mcp_execution(&self, tool_input: &str) -> HookResponse {
        // Empty tool_input → permit
        if tool_input.trim().is_empty() {
            return HookResponse {
                permission: Permission::Allow,
                user_message: None,
                agent_message: None,
            };
        }

        // Parse tool_input as JSON; fail-closed on parse failure
        let json_value: Value = match serde_json::from_str(tool_input) {
            Ok(v) => v,
            Err(_) => {
                return Self::deny_response(
                    &DenyRule {
                        command: "__parse_error__".to_string(),
                        subcommands: vec!["MCP tool input could not be parsed as JSON for policy evaluation"
                            .to_string()],
                    },
                    "MCP tool input could not be parsed as JSON for policy evaluation",
                );
            }
        };

        // Recursively extract all string values and evaluate each
        let mut strings: Vec<String> = Vec::new();
        Self::extract_strings(&json_value, &mut strings);

        for string_value in &strings {
            // Skip empty/whitespace-only strings
            if string_value.trim().is_empty() {
                continue;
            }

            let result = self.engine.evaluate(string_value);

            if let Decision::Deny {
                rule,
                matched_subcommand,
            } = result.decision
            {
                return Self::deny_response(&rule, &matched_subcommand);
            }
        }

        // No strings matched → permit
        HookResponse {
            permission: Permission::Allow,
            user_message: None,
            agent_message: None,
        }
    }

    /// Recursively extract all string values from a JSON value tree.
    ///
    /// - `Value::String(s)` → collect s
    /// - `Value::Array(arr)` → recurse into each element
    /// - `Value::Object(map)` → recurse into each value
    /// - `Value::Number`, `Value::Bool`, `Value::Null` → skip
    fn extract_strings(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::String(s) => {
                out.push(s.clone());
            }
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
            // Number, Bool, Null → skip
            _ => {}
        }
    }

    /// Build a deny response with rule information.
    ///
    /// - `rule`: The deny rule that matched.
    /// - `matched_subcommand`: The specific subcommand that triggered the deny.
    fn deny_response(rule: &DenyRule, matched_subcommand: &str) -> HookResponse {
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
            rule.command,
            matched_subcommand,
            rule.command,
            matched_subcommand
        );

        HookResponse {
            permission: Permission::Deny,
            user_message: Some(user_message),
            agent_message: Some(agent_message),
        }
    }
}

impl Adapter for CursorAdapter {
    /// Process a hook event and return a response.
    ///
    /// Routes to the appropriate handler based on `hook_event_name`:
    /// - `beforeShellExecution` → handle_shell_execution
    /// - `beforeMCPExecution` → handle_mcp_execution
    /// - Unknown event → deny (fail-closed)
    fn handle_hook(&self, input: &HookInput) -> HookResponse {
        match input.hook_event_name.as_str() {
            "beforeShellExecution" => {
                match &input.command {
                    Some(cmd) => self.handle_shell_execution(cmd),
                    None => {
                        // Missing command field → permit (empty command)
                        HookResponse {
                            permission: Permission::Allow,
                            user_message: None,
                            agent_message: None,
                        }
                    }
                }
            }
            "beforeMCPExecution" => {
                match &input.tool_input {
                    Some(tool_input) => self.handle_mcp_execution(tool_input),
                    None => {
                        // No tool_input → permit
                        HookResponse {
                            permission: Permission::Allow,
                            user_message: None,
                            agent_message: None,
                        }
                    }
                }
            }
            _ => {
                // Unknown hook event → deny (fail-closed)
                let subcmd = format!("unknown hook event: {}", input.hook_event_name);
                Self::deny_response(
                    &DenyRule {
                        command: "__unknown_event__".to_string(),
                        subcommands: vec![subcmd.clone()],
                    },
                    &subcmd,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_adapter() -> CursorAdapter {
        CursorAdapter::new(PolicyEngine::default_policy())
    }

    // --- handle_mcp_execution tests ---

    #[test]
    fn test_mcp_empty_tool_input_allows() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution("");
        assert_eq!(response.permission, Permission::Allow);
        assert!(response.user_message.is_none());
    }

    #[test]
    fn test_mcp_whitespace_only_tool_input_allows() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution("   \t  ");
        assert_eq!(response.permission, Permission::Allow);
    }

    #[test]
    fn test_mcp_invalid_json_denies() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution("not valid json {{{");
        assert_eq!(response.permission, Permission::Deny);
        assert!(response.user_message.is_some());
    }

    #[test]
    fn test_mcp_no_string_values_allows() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution(r#"{"count": 42, "flag": true}"#);
        assert_eq!(response.permission, Permission::Allow);
    }

    #[test]
    fn test_mcp_safe_string_values_allows() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution(
            r#"{"command": "echo hello", "path": "/tmp/test"}"#,
        );
        assert_eq!(response.permission, Permission::Allow);
    }

    #[test]
    fn test_mcp_forbidden_command_in_string_denies() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution(
            r#"{"command": "git push origin main"}"#,
        );
        assert_eq!(response.permission, Permission::Deny);
        assert!(response.user_message.is_some());
        let msg = response.user_message.unwrap();
        assert!(msg.contains("git"));
    }

    #[test]
    fn test_mcp_forbidden_command_in_nested_object_denies() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution(
            r#"{"outer": {"inner": {"cmd": "git commit -m test"}}}"#,
        );
        assert_eq!(response.permission, Permission::Deny);
    }

    #[test]
    fn test_mcp_forbidden_command_in_array_denies() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution(
            r#"{"commands": ["echo hello", "git push"]}"#,
        );
        assert_eq!(response.permission, Permission::Deny);
    }

    #[test]
    fn test_mcp_safe_nested_structure_allows() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution(
            r#"{"args": {"path": "/home/user", "items": ["file.txt", "readme.md"]}, "count": 5}"#,
        );
        assert_eq!(response.permission, Permission::Allow);
    }

    #[test]
    fn test_mcp_mixed_types_only_checks_strings() {
        let adapter = default_adapter();
        // Numbers, bools, nulls are skipped; only the string "ls -la" is checked
        let response = adapter.handle_mcp_execution(
            r#"{"a": 123, "b": null, "c": true, "d": "ls -la"}"#,
        );
        assert_eq!(response.permission, Permission::Allow);
    }

    #[test]
    fn test_mcp_deeply_nested_array_denies() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution(
            r#"[[[["git push"]]]]"#,
        );
        assert_eq!(response.permission, Permission::Deny);
    }

    #[test]
    fn test_mcp_whitespace_only_string_values_allows() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution(
            r#"{"a": "   ", "b": ""}"#,
        );
        assert_eq!(response.permission, Permission::Allow);
    }

    #[test]
    fn test_mcp_git_status_in_string_allows() {
        let adapter = default_adapter();
        let response = adapter.handle_mcp_execution(
            r#"{"command": "git status"}"#,
        );
        assert_eq!(response.permission, Permission::Allow);
    }

    #[test]
    fn test_mcp_first_deny_short_circuits() {
        let adapter = default_adapter();
        // First string is forbidden, should deny without needing to check second
        let response = adapter.handle_mcp_execution(
            r#"{"a": "git push", "b": "git commit"}"#,
        );
        assert_eq!(response.permission, Permission::Deny);
    }

    // --- handle_hook routing tests ---

    #[test]
    fn test_handle_hook_routes_mcp_execution() {
        let adapter = default_adapter();
        let input = HookInput {
            hook_event_name: "beforeMCPExecution".to_string(),
            command: None,
            tool_name: Some("run_command".to_string()),
            tool_input: Some(r#"{"command": "git push"}"#.to_string()),
            workspace_roots: vec![],
        };
        let response = adapter.handle_hook(&input);
        assert_eq!(response.permission, Permission::Deny);
    }

    #[test]
    fn test_handle_hook_mcp_no_tool_input_allows() {
        let adapter = default_adapter();
        let input = HookInput {
            hook_event_name: "beforeMCPExecution".to_string(),
            command: None,
            tool_name: Some("some_tool".to_string()),
            tool_input: None,
            workspace_roots: vec![],
        };
        let response = adapter.handle_hook(&input);
        assert_eq!(response.permission, Permission::Allow);
    }

    #[test]
    fn test_handle_hook_unknown_event_denies() {
        let adapter = default_adapter();
        let input = HookInput {
            hook_event_name: "unknownEvent".to_string(),
            command: None,
            tool_name: None,
            tool_input: None,
            workspace_roots: vec![],
        };
        let response = adapter.handle_hook(&input);
        assert_eq!(response.permission, Permission::Deny);
    }

    #[test]
    fn test_handle_hook_shell_execution_allow() {
        let adapter = default_adapter();
        let input = HookInput {
            hook_event_name: "beforeShellExecution".to_string(),
            command: Some("echo hello".to_string()),
            tool_name: None,
            tool_input: None,
            workspace_roots: vec![],
        };
        let response = adapter.handle_hook(&input);
        assert_eq!(response.permission, Permission::Allow);
    }

    #[test]
    fn test_handle_hook_shell_execution_deny() {
        let adapter = default_adapter();
        let input = HookInput {
            hook_event_name: "beforeShellExecution".to_string(),
            command: Some("git push".to_string()),
            tool_name: None,
            tool_input: None,
            workspace_roots: vec![],
        };
        let response = adapter.handle_hook(&input);
        assert_eq!(response.permission, Permission::Deny);
    }

    #[test]
    fn test_handle_hook_shell_no_command_allows() {
        let adapter = default_adapter();
        let input = HookInput {
            hook_event_name: "beforeShellExecution".to_string(),
            command: None,
            tool_name: None,
            tool_input: None,
            workspace_roots: vec![],
        };
        let response = adapter.handle_hook(&input);
        assert_eq!(response.permission, Permission::Allow);
    }

    // --- extract_strings tests ---

    #[test]
    fn test_extract_strings_from_simple_object() {
        let json: Value = serde_json::from_str(r#"{"a": "hello", "b": "world"}"#).unwrap();
        let mut strings = Vec::new();
        CursorAdapter::extract_strings(&json, &mut strings);
        assert!(strings.contains(&"hello".to_string()));
        assert!(strings.contains(&"world".to_string()));
        assert_eq!(strings.len(), 2);
    }

    #[test]
    fn test_extract_strings_skips_non_string_types() {
        let json: Value =
            serde_json::from_str(r#"{"a": 42, "b": true, "c": null, "d": "yes"}"#).unwrap();
        let mut strings = Vec::new();
        CursorAdapter::extract_strings(&json, &mut strings);
        assert_eq!(strings, vec!["yes".to_string()]);
    }

    #[test]
    fn test_extract_strings_nested_objects() {
        let json: Value =
            serde_json::from_str(r#"{"outer": {"inner": "deep"}}"#).unwrap();
        let mut strings = Vec::new();
        CursorAdapter::extract_strings(&json, &mut strings);
        assert_eq!(strings, vec!["deep".to_string()]);
    }

    #[test]
    fn test_extract_strings_arrays() {
        let json: Value =
            serde_json::from_str(r#"["first", 2, "third"]"#).unwrap();
        let mut strings = Vec::new();
        CursorAdapter::extract_strings(&json, &mut strings);
        assert_eq!(strings, vec!["first".to_string(), "third".to_string()]);
    }

    #[test]
    fn test_extract_strings_deeply_nested() {
        let json: Value =
            serde_json::from_str(r#"{"a": [{"b": [{"c": "found"}]}]}"#).unwrap();
        let mut strings = Vec::new();
        CursorAdapter::extract_strings(&json, &mut strings);
        assert_eq!(strings, vec!["found".to_string()]);
    }

    #[test]
    fn test_extract_strings_empty_object() {
        let json: Value = serde_json::from_str(r#"{}"#).unwrap();
        let mut strings = Vec::new();
        CursorAdapter::extract_strings(&json, &mut strings);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_strings_empty_array() {
        let json: Value = serde_json::from_str(r#"[]"#).unwrap();
        let mut strings = Vec::new();
        CursorAdapter::extract_strings(&json, &mut strings);
        assert!(strings.is_empty());
    }
}
