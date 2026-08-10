// Integration tests for end-to-end hook flow
// Validates: Requirements 5.1, 5.2, 5.3, 6.1, 6.2, 6.3
//
// These tests spawn the `mr-nope evaluate` binary, pipe hook JSON to stdin,
// and verify the stdout JSON response matches expected behavior.

use std::io::Write;
use std::process::{Command, Stdio};

/// Helper: run `mr-nope evaluate` with the given stdin input and return stdout as a String.
fn run_evaluate(input: &str) -> String {
    let binary = env!("CARGO_BIN_EXE_mr-nope");

    let mut child = Command::new(binary)
        .arg("evaluate")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mr-nope binary");

    // Write input to stdin
    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all(input.as_bytes())
            .expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait on child");
    String::from_utf8(output.stdout).expect("stdout is not valid UTF-8")
}

/// Helper: parse stdout JSON and return the "permission" field value.
fn get_permission(stdout: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("failed to parse stdout as JSON: {e}\nstdout: {stdout}"));
    v["permission"]
        .as_str()
        .expect("missing 'permission' field in response")
        .to_string()
}

/// Helper: parse stdout JSON and return the "userMessage" field value if present.
fn get_user_message(stdout: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    v["userMessage"].as_str().map(|s| s.to_string())
}

// =============================================================================
// Shell Execution Hook Tests
// =============================================================================

#[test]
fn test_shell_deny_git_push() {
    let input = r#"{"command": "git push origin main", "hook_event_name": "beforeShellExecution", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "deny");

    let user_message = get_user_message(&stdout).expect("deny response should have userMessage");
    assert!(
        user_message.contains("git"),
        "userMessage should mention 'git', got: {user_message}"
    );
}

#[test]
fn test_shell_deny_git_commit() {
    let input = r#"{"command": "git commit -m 'test'", "hook_event_name": "beforeShellExecution", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "deny");

    let user_message = get_user_message(&stdout).expect("deny response should have userMessage");
    assert!(user_message.contains("git"));
    assert!(user_message.contains("commit"));
}

#[test]
fn test_shell_allow_git_status() {
    let input = r#"{"command": "git status", "hook_event_name": "beforeShellExecution", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "allow");

    // Allow responses should not have userMessage
    assert!(
        get_user_message(&stdout).is_none(),
        "allow response should not have userMessage"
    );
}

#[test]
fn test_shell_allow_safe_command() {
    let input = r#"{"command": "echo hello world", "hook_event_name": "beforeShellExecution", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "allow");
}

#[test]
fn test_shell_allow_git_diff() {
    let input = r#"{"command": "git diff --cached", "hook_event_name": "beforeShellExecution", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "allow");
}

// =============================================================================
// MCP Tool Call Hook Tests
// =============================================================================

#[test]
fn test_mcp_deny_forbidden_command_in_tool_input() {
    let input = r#"{"hook_event_name": "beforeMCPExecution", "tool_name": "run_cmd", "tool_input": "{\"command\": \"git push\"}", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "deny");

    let user_message = get_user_message(&stdout).expect("deny response should have userMessage");
    assert!(
        user_message.contains("git"),
        "userMessage should mention 'git', got: {user_message}"
    );
}

#[test]
fn test_mcp_deny_git_commit_in_tool_input() {
    let input = r#"{"hook_event_name": "beforeMCPExecution", "tool_name": "execute", "tool_input": "{\"cmd\": \"git commit -m fix\"}", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "deny");
}

#[test]
fn test_mcp_allow_safe_tool_input() {
    let input = r#"{"hook_event_name": "beforeMCPExecution", "tool_name": "read_file", "tool_input": "{\"path\": \"/tmp/test.txt\"}", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "allow");
}

#[test]
fn test_mcp_allow_git_status_in_tool_input() {
    let input = r#"{"hook_event_name": "beforeMCPExecution", "tool_name": "run_cmd", "tool_input": "{\"command\": \"git status\"}", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "allow");
}

#[test]
fn test_mcp_allow_no_tool_input() {
    let input = r#"{"hook_event_name": "beforeMCPExecution", "tool_name": "some_tool", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "allow");
}

// =============================================================================
// Malformed Input / Error Handling Tests
// =============================================================================

#[test]
fn test_malformed_json_input_denies() {
    let input = "not valid json";
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "deny");

    let user_message = get_user_message(&stdout).expect("malformed input deny should have userMessage");
    assert!(
        user_message.contains("Mr. Nope"),
        "userMessage should mention Mr. Nope, got: {user_message}"
    );
}

#[test]
fn test_empty_input_denies() {
    let input = "";
    let stdout = run_evaluate(input);

    // Empty string is not valid JSON → fail-closed → deny
    assert_eq!(get_permission(&stdout), "deny");
}

#[test]
fn test_partial_json_denies() {
    let input = r#"{"hook_event_name": "beforeShell"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "deny");
}

// =============================================================================
// Unknown Hook Event Tests
// =============================================================================

#[test]
fn test_unknown_hook_event_denies() {
    let input = r#"{"hook_event_name": "unknownEvent", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "deny");

    let user_message = get_user_message(&stdout).expect("unknown event deny should have userMessage");
    assert!(
        user_message.contains("Mr. Nope") || user_message.contains("unknown"),
        "userMessage should indicate error, got: {user_message}"
    );
}

#[test]
fn test_unknown_hook_event_after_execution_denies() {
    let input = r#"{"hook_event_name": "afterShellExecution", "command": "git status", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);

    assert_eq!(get_permission(&stdout), "deny");
}

// =============================================================================
// Response Format Validation Tests
// =============================================================================

#[test]
fn test_allow_response_format() {
    let input = r#"{"command": "ls -la", "hook_event_name": "beforeShellExecution", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .expect("response should be valid JSON");

    assert_eq!(v["permission"], "allow");
    // Allow responses should not include userMessage or agentMessage
    assert!(v.get("userMessage").is_none() || v["userMessage"].is_null());
    assert!(v.get("agentMessage").is_none() || v["agentMessage"].is_null());
}

#[test]
fn test_deny_response_format() {
    let input = r#"{"command": "git push", "hook_event_name": "beforeShellExecution", "workspace_roots": ["/tmp"]}"#;
    let stdout = run_evaluate(input);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .expect("response should be valid JSON");

    assert_eq!(v["permission"], "deny");
    // Deny responses must include userMessage and agentMessage
    assert!(
        v["userMessage"].is_string(),
        "deny response must have userMessage string"
    );
    assert!(
        v["agentMessage"].is_string(),
        "deny response must have agentMessage string"
    );

    // Verify transparency notice in userMessage (Requirement 12.4)
    let user_msg = v["userMessage"].as_str().unwrap();
    assert!(
        user_msg.contains("hook") || user_msg.contains("AI agent"),
        "deny userMessage should contain transparency notice"
    );
}
