// Unit tests for the Policy Engine - YAML loading and validation

use mr_nope::engine::{PolicyEngine, PolicyError};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_load_valid_policy() {
    let yaml = r#"
rules:
  - deny:
      command: "git"
      subcommands:
        - "commit"
        - "push"
"#;
    let engine = PolicyEngine::load_from_str(yaml, false).unwrap();
    assert_eq!(engine.rules.len(), 1);
    assert_eq!(engine.rules[0].command, "git");
    assert_eq!(engine.rules[0].subcommands, vec!["commit", "push"]);
    assert!(!engine.is_default);
}

#[test]
fn test_load_multiple_rules() {
    let yaml = r#"
rules:
  - deny:
      command: "git"
      subcommands:
        - "commit"
        - "push"
  - deny:
      command: "rm"
      subcommands:
        - "-rf"
"#;
    let engine = PolicyEngine::load_from_str(yaml, false).unwrap();
    assert_eq!(engine.rules.len(), 2);
    assert_eq!(engine.rules[0].command, "git");
    assert_eq!(engine.rules[1].command, "rm");
    assert_eq!(engine.rules[1].subcommands, vec!["-rf"]);
}

#[test]
fn test_load_empty_rules_array() {
    let yaml = r#"
rules: []
"#;
    let engine = PolicyEngine::load_from_str(yaml, false).unwrap();
    assert_eq!(engine.rules.len(), 0);
}

#[test]
fn test_load_missing_rules_array() {
    let yaml = r#"
other_key: "value"
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::MissingRulesArray);
}

#[test]
fn test_load_invalid_yaml() {
    let yaml = "not: valid: yaml: [[[";
    let result = PolicyEngine::load_from_str(yaml, false);
    assert!(matches!(result.unwrap_err(), PolicyError::InvalidYaml(_)));
}

#[test]
fn test_load_missing_deny_object() {
    let yaml = r#"
rules:
  - other: "something"
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::MissingCommand);
}

#[test]
fn test_load_missing_command_field() {
    let yaml = r#"
rules:
  - deny:
      subcommands:
        - "push"
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::MissingCommand);
}

#[test]
fn test_load_empty_command() {
    let yaml = r#"
rules:
  - deny:
      command: ""
      subcommands:
        - "push"
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::EmptyCommand);
}

#[test]
fn test_load_whitespace_only_command() {
    let yaml = r#"
rules:
  - deny:
      command: "   "
      subcommands:
        - "push"
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::EmptyCommand);
}

#[test]
fn test_load_command_too_long() {
    let long_command = "a".repeat(129);
    let yaml = format!(
        r#"
rules:
  - deny:
      command: "{}"
      subcommands:
        - "push"
"#,
        long_command
    );
    let result = PolicyEngine::load_from_str(&yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::CommandTooLong);
}

#[test]
fn test_load_command_exactly_128_chars() {
    let command = "a".repeat(128);
    let yaml = format!(
        r#"
rules:
  - deny:
      command: "{}"
      subcommands:
        - "push"
"#,
        command
    );
    let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();
    assert_eq!(engine.rules[0].command.len(), 128);
}

#[test]
fn test_load_missing_subcommands() {
    let yaml = r#"
rules:
  - deny:
      command: "git"
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::MissingSubcommands);
}

#[test]
fn test_load_empty_subcommands_array() {
    let yaml = r#"
rules:
  - deny:
      command: "git"
      subcommands: []
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::EmptySubcommands);
}

#[test]
fn test_load_whitespace_only_subcommand() {
    let yaml = r#"
rules:
  - deny:
      command: "git"
      subcommands:
        - "   "
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::WhitespaceOnlySubcommand);
}

#[test]
fn test_load_subcommand_too_long() {
    let long_subcmd = "b".repeat(129);
    let yaml = format!(
        r#"
rules:
  - deny:
      command: "git"
      subcommands:
        - "{}"
"#,
        long_subcmd
    );
    let result = PolicyEngine::load_from_str(&yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::SubcommandTooLong);
}

#[test]
fn test_load_subcommand_exactly_128_chars() {
    let subcmd = "b".repeat(128);
    let yaml = format!(
        r#"
rules:
  - deny:
      command: "git"
      subcommands:
        - "{}"
"#,
        subcmd
    );
    let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();
    assert_eq!(engine.rules[0].subcommands[0].len(), 128);
}

#[test]
fn test_load_is_default_flag() {
    let yaml = r#"
rules:
  - deny:
      command: "git"
      subcommands:
        - "commit"
"#;
    let engine = PolicyEngine::load_from_str(yaml, true).unwrap();
    assert!(engine.is_default);
}

#[test]
fn test_load_none_path_returns_default_policy() {
    let engine = PolicyEngine::load(None).unwrap();
    assert_eq!(engine.rules.len(), 1);
    assert_eq!(engine.rules[0].command, "git");
    assert_eq!(engine.rules[0].subcommands, vec!["commit", "push"]);
    assert!(engine.is_default);
}

#[test]
fn test_load_nonexistent_file_returns_default_policy() {
    use std::path::Path;
    let engine = PolicyEngine::load(Some(Path::new("/nonexistent/path/.mr-nope.yml"))).unwrap();
    assert_eq!(engine.rules.len(), 1);
    assert_eq!(engine.rules[0].command, "git");
    assert_eq!(engine.rules[0].subcommands, vec!["commit", "push"]);
    assert!(engine.is_default);
}

#[test]
fn test_load_from_file() {
    let yaml = r#"
rules:
  - deny:
      command: "git"
      subcommands:
        - "commit"
        - "push"
"#;
    let mut temp = NamedTempFile::new().unwrap();
    write!(temp, "{}", yaml).unwrap();

    let engine = PolicyEngine::load(Some(temp.path())).unwrap();
    assert_eq!(engine.rules.len(), 1);
    assert_eq!(engine.rules[0].command, "git");
    assert_eq!(engine.rules[0].subcommands, vec!["commit", "push"]);
    assert!(!engine.is_default);
}

// ============================================================
// PolicyEvaluator evaluate tests (Task 5.6)
// ============================================================

use mr_nope::engine::{Decision, PolicyEvaluator};

/// Validates: Requirements 1.1, 1.2, 9.1
#[test]
fn test_evaluate_git_status_allows() {
    let engine = PolicyEngine::load(None).unwrap();
    let result = engine.evaluate("git status");
    assert_eq!(result.decision, Decision::Allow);
}

/// Validates: Requirements 1.1, 1.2, 14.1
#[test]
fn test_evaluate_git_push_denies() {
    let engine = PolicyEngine::load(None).unwrap();
    let result = engine.evaluate("git push");
    assert!(matches!(result.decision, Decision::Deny { .. }));
    if let Decision::Deny { rule, .. } = &result.decision {
        assert_eq!(rule.command, "git");
        assert!(rule.subcommands.contains(&"push".to_string()));
    }
}

/// Validates: Requirements 1.1, 1.2, 14.1
#[test]
fn test_evaluate_git_commit_denies() {
    let engine = PolicyEngine::load(None).unwrap();
    let result = engine.evaluate("git commit");
    assert!(matches!(result.decision, Decision::Deny { .. }));
    if let Decision::Deny { rule, .. } = &result.decision {
        assert_eq!(rule.command, "git");
        assert!(rule.subcommands.contains(&"commit".to_string()));
    }
}

/// Validates: Requirements 1.1, 1.2, 14.1
#[test]
fn test_evaluate_git_push_with_args_denies() {
    let engine = PolicyEngine::load(None).unwrap();
    let result = engine.evaluate("git push origin main");
    assert!(matches!(result.decision, Decision::Deny { .. }));
}

/// Validates: Requirements 1.1, 1.2, 14.1
#[test]
fn test_evaluate_git_commit_with_message_denies() {
    let engine = PolicyEngine::load(None).unwrap();
    let result = engine.evaluate("git commit -m \"msg\"");
    assert!(matches!(result.decision, Decision::Deny { .. }));
}

/// Validates: Requirements 9.1
#[test]
fn test_evaluate_git_diff_allows() {
    let engine = PolicyEngine::load(None).unwrap();
    let result = engine.evaluate("git diff");
    assert_eq!(result.decision, Decision::Allow);
}

/// Validates: Requirements 9.1
#[test]
fn test_evaluate_git_log_allows() {
    let engine = PolicyEngine::load(None).unwrap();
    let result = engine.evaluate("git log");
    assert_eq!(result.decision, Decision::Allow);
}

/// Validates: Requirements 9.1
#[test]
fn test_evaluate_git_branch_allows() {
    let engine = PolicyEngine::load(None).unwrap();
    let result = engine.evaluate("git branch");
    assert_eq!(result.decision, Decision::Allow);
}

/// Validates: Requirements 9.1
#[test]
fn test_evaluate_git_fetch_allows() {
    let engine = PolicyEngine::load(None).unwrap();
    let result = engine.evaluate("git fetch");
    assert_eq!(result.decision, Decision::Allow);
}

// ============================================================
// Custom policy replaces default (Task 5.6)
// ============================================================

/// Validates: Requirements 14.2
#[test]
fn test_custom_policy_replaces_default_allows_git_push() {
    // Custom policy only denies "npm publish" — git push should be allowed
    let yaml = r#"
rules:
  - deny:
      command: "npm"
      subcommands:
        - "publish"
"#;
    let engine = PolicyEngine::load_from_str(yaml, false).unwrap();
    let result = engine.evaluate("git push");
    assert_eq!(result.decision, Decision::Allow);
}

/// Validates: Requirements 14.2, 4.2
#[test]
fn test_custom_policy_denies_npm_publish() {
    let yaml = r#"
rules:
  - deny:
      command: "npm"
      subcommands:
        - "publish"
"#;
    let engine = PolicyEngine::load_from_str(yaml, false).unwrap();
    let result = engine.evaluate("npm publish");
    assert!(matches!(result.decision, Decision::Deny { .. }));
    if let Decision::Deny { rule, .. } = &result.decision {
        assert_eq!(rule.command, "npm");
        assert!(rule.subcommands.contains(&"publish".to_string()));
    }
}

// ============================================================
// Malformed YAML handling (Task 5.6)
// ============================================================

/// Validates: Requirements 4.4, 4.6
#[test]
fn test_malformed_yaml_missing_rules_key() {
    let yaml = r#"
something_else:
  - item: "value"
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::MissingRulesArray);
}

/// Validates: Requirements 4.4, 4.6
#[test]
fn test_malformed_yaml_empty_command_field() {
    let yaml = r#"
rules:
  - deny:
      command: ""
      subcommands:
        - "push"
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::EmptyCommand);
}

/// Validates: Requirements 4.4, 4.6
#[test]
fn test_malformed_yaml_empty_subcommands_array() {
    let yaml = r#"
rules:
  - deny:
      command: "git"
      subcommands: []
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::EmptySubcommands);
}

/// Validates: Requirements 4.4, 4.6
#[test]
fn test_malformed_yaml_whitespace_only_subcommand() {
    let yaml = r#"
rules:
  - deny:
      command: "git"
      subcommands:
        - "  "
"#;
    let result = PolicyEngine::load_from_str(yaml, false);
    assert_eq!(result.unwrap_err(), PolicyError::WhitespaceOnlySubcommand);
}

/// Validates: Requirements 4.4
#[test]
fn test_malformed_yaml_invalid_syntax() {
    let yaml = "rules: [[[invalid yaml:::";
    let result = PolicyEngine::load_from_str(yaml, false);
    assert!(matches!(result.unwrap_err(), PolicyError::InvalidYaml(_)));
}

// ============================================================
// Large policy test (100 rules) (Task 5.6)
// ============================================================

/// Validates: Requirements 4.3, 4.5, 11.5
#[test]
fn test_large_policy_100_rules_evaluates_correctly() {
    // Generate a policy with 100 deny rules: cmd0 deny sub0, cmd1 deny sub1, ... cmd99 deny sub99
    let mut yaml = String::from("rules:\n");
    for i in 0..100 {
        yaml.push_str(&format!(
            "  - deny:\n      command: \"cmd{}\"\n      subcommands:\n        - \"sub{}\"\n",
            i, i
        ));
    }

    let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();
    assert_eq!(engine.rules.len(), 100);

    // Rule #50 should deny cmd50 sub50
    let result = engine.evaluate("cmd50 sub50");
    assert!(matches!(result.decision, Decision::Deny { .. }));
    if let Decision::Deny { rule, .. } = &result.decision {
        assert_eq!(rule.command, "cmd50");
        assert!(rule.subcommands.contains(&"sub50".to_string()));
    }

    // Rule #99 should deny cmd99 sub99
    let result = engine.evaluate("cmd99 sub99");
    assert!(matches!(result.decision, Decision::Deny { .. }));
    if let Decision::Deny { rule, .. } = &result.decision {
        assert_eq!(rule.command, "cmd99");
        assert!(rule.subcommands.contains(&"sub99".to_string()));
    }

    // An unmatched command should still ALLOW
    let result = engine.evaluate("unmatched command");
    assert_eq!(result.decision, Decision::Allow);
}
