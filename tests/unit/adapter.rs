// Unit tests for the Cursor Adapter - denial message formatting

use mr_nope::adapter::cursor::CursorAdapter;
use mr_nope::adapter::{Adapter, HookInput, Permission};
use mr_nope::engine::PolicyEngine;

fn default_adapter() -> CursorAdapter {
    CursorAdapter::new(PolicyEngine::default_policy())
}

// ============================================================
// Denial message formatting tests (Task 6.3)
// ============================================================

/// Validates: Requirements 5.2, 12.4
/// For "git push" with default rule `git [commit, push]`:
/// User message shows the specific matched subcommand, plus the full rule.
#[test]
fn test_deny_message_user_format_git_push() {
    let adapter = default_adapter();
    let response = adapter.handle_shell_execution("git push");
    assert_eq!(response.permission, Permission::Deny);

    let user_msg = response.user_message.unwrap();
    assert_eq!(
        user_msg,
        "🚫 Mr. Nope blocked: git push (matched deny rule: git [commit, push]). \
         Note: this protection applies only to AI agent execution via hooks, \
         not to direct terminal usage."
    );
}

/// Validates: Requirements 5.2, 12.4
/// For "git commit" with default rule `git [commit, push]`:
/// User message shows "git commit" as the blocked command.
#[test]
fn test_deny_message_user_format_git_commit() {
    let adapter = default_adapter();
    let response = adapter.handle_shell_execution("git commit -m test");
    assert_eq!(response.permission, Permission::Deny);

    let user_msg = response.user_message.unwrap();
    assert_eq!(
        user_msg,
        "🚫 Mr. Nope blocked: git commit (matched deny rule: git [commit, push]). \
         Note: this protection applies only to AI agent execution via hooks, \
         not to direct terminal usage."
    );
}

/// Validates: Requirements 5.2, 12.4
/// Agent message for "git push" shows the specific matched cmd+subcmd.
#[test]
fn test_deny_message_agent_format_git_push() {
    let adapter = default_adapter();
    let response = adapter.handle_shell_execution("git push");
    assert_eq!(response.permission, Permission::Deny);

    let agent_msg = response.agent_message.unwrap();
    assert_eq!(
        agent_msg,
        "Command 'git push' is blocked by Mr. Nope policy. \
         This deny rule prevents git push operations. \
         Do not attempt to bypass this restriction."
    );
}

/// Validates: Requirements 5.2, 12.4
/// Agent message for "git commit" shows the specific matched cmd+subcmd.
#[test]
fn test_deny_message_agent_format_git_commit() {
    let adapter = default_adapter();
    let response = adapter.handle_shell_execution("git commit -m test");
    assert_eq!(response.permission, Permission::Deny);

    let agent_msg = response.agent_message.unwrap();
    assert_eq!(
        agent_msg,
        "Command 'git commit' is blocked by Mr. Nope policy. \
         This deny rule prevents git commit operations. \
         Do not attempt to bypass this restriction."
    );
}

/// Validates: Requirements 12.4
/// The transparency notice must always be appended to the user message.
#[test]
fn test_deny_message_always_contains_transparency_notice() {
    let adapter = default_adapter();
    let response = adapter.handle_shell_execution("git push origin main");
    assert_eq!(response.permission, Permission::Deny);

    let user_msg = response.user_message.unwrap();
    assert!(
        user_msg.contains("Note: this protection applies only to AI agent execution via hooks, not to direct terminal usage."),
        "User message must contain the transparency notice"
    );
}

/// Validates: Requirements 5.2, 12.4
/// For MCP execution that contains a forbidden command, the denial message
/// follows the same format.
#[test]
fn test_deny_message_mcp_execution_format() {
    let adapter = default_adapter();
    let response = adapter.handle_mcp_execution(r#"{"command": "git push origin main"}"#);
    assert_eq!(response.permission, Permission::Deny);

    let user_msg = response.user_message.unwrap();
    assert!(user_msg.starts_with("🚫 Mr. Nope blocked: git push"));
    assert!(user_msg.contains("(matched deny rule: git [commit, push])"));
    assert!(user_msg.contains("Note: this protection applies only to AI agent execution via hooks, not to direct terminal usage."));

    let agent_msg = response.agent_message.unwrap();
    assert!(agent_msg.starts_with("Command 'git push' is blocked by Mr. Nope policy."));
    assert!(agent_msg.contains("Do not attempt to bypass this restriction."));
}

/// Validates: Requirements 5.2
/// With a custom policy having multiple subcommands, the user message
/// correctly shows the specific matched subcommand vs. the full rule.
#[test]
fn test_deny_message_custom_policy_shows_specific_subcommand() {
    let yaml = r#"
rules:
  - deny:
      command: "npm"
      subcommands:
        - "publish"
        - "unpublish"
        - "deprecate"
"#;
    let engine = PolicyEngine::load_from_str(yaml, false).unwrap();
    let adapter = CursorAdapter::new(engine);

    let response = adapter.handle_shell_execution("npm unpublish");
    assert_eq!(response.permission, Permission::Deny);

    let user_msg = response.user_message.unwrap();
    // Should show "npm unpublish" as the blocked command (specific match)
    assert!(user_msg.contains("🚫 Mr. Nope blocked: npm unpublish"));
    // Should show the full rule with all subcommands
    assert!(user_msg.contains("(matched deny rule: npm [publish, unpublish, deprecate])"));

    let agent_msg = response.agent_message.unwrap();
    assert_eq!(
        agent_msg,
        "Command 'npm unpublish' is blocked by Mr. Nope policy. \
         This deny rule prevents npm unpublish operations. \
         Do not attempt to bypass this restriction."
    );
}

/// Validates: Requirements 12.4
/// Unknown hook event denial also includes transparency notice.
#[test]
fn test_deny_message_unknown_event_includes_transparency_notice() {
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

    let user_msg = response.user_message.unwrap();
    assert!(
        user_msg.contains("Note: this protection applies only to AI agent execution via hooks, not to direct terminal usage."),
        "Unknown event denial must also include transparency notice"
    );
}
