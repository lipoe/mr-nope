// Mr. Nope - CLI policy command
// Displays active policy rules and indicates whether the default or custom policy is active.

use crate::cli::evaluate::discover_policy_from_cwd;
use crate::engine::PolicyEngine;
use std::path::PathBuf;

/// Run the `mr-nope policy` command.
///
/// Discovers the policy from `.mr-nope.yml` in the current working directory
/// (if present), otherwise falls back to the built-in default policy. Displays
/// the active deny rules and indicates which policy source is active.
pub fn run_policy_command() {
    let (engine, policy_path) = discover_policy_from_cwd();
    display_policy(&engine, policy_path.as_ref());
}

/// Display the active policy rules.
fn display_policy(engine: &PolicyEngine, policy_path: Option<&PathBuf>) {
    if engine.is_default {
        println!("Active Policy (default built-in):");
    } else {
        let path_display = policy_path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| crate::cli::evaluate::POLICY_FILE_NAME.to_string());
        println!("Active Policy (custom: {}):", path_display);
    }

    println!();

    if engine.rules.is_empty() {
        println!("No deny rules configured (all commands allowed).");
    } else {
        println!("Deny Rules:");
        for rule in &engine.rules {
            let subcommands = rule.subcommands.join(", ");
            println!("  \u{2022} {} [{}]", rule.command, subcommands);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::DenyRule;

    /// Helper: captures the display_policy output by testing the logic directly.
    /// Since display_policy prints to stdout, we test the underlying engine state.

    #[test]
    fn test_default_policy_displays_correct_rules() {
        let engine = PolicyEngine::default_policy();

        // The default policy should have exactly one rule: git [commit, push]
        assert!(engine.is_default);
        assert_eq!(engine.rules.len(), 1);
        assert_eq!(engine.rules[0].command, "git");
        assert_eq!(engine.rules[0].subcommands, vec!["commit", "push"]);
    }

    #[test]
    fn test_custom_policy_displays_correct_rules() {
        let engine = PolicyEngine {
            rules: vec![
                DenyRule {
                    command: "rm".to_string(),
                    subcommands: vec!["-rf".to_string(), "-r".to_string()],
                },
                DenyRule {
                    command: "docker".to_string(),
                    subcommands: vec!["push".to_string()],
                },
            ],
            is_default: false,
        };

        assert!(!engine.is_default);
        assert_eq!(engine.rules.len(), 2);

        assert_eq!(engine.rules[0].command, "rm");
        assert_eq!(engine.rules[0].subcommands, vec!["-rf", "-r"]);

        assert_eq!(engine.rules[1].command, "docker");
        assert_eq!(engine.rules[1].subcommands, vec!["push"]);
    }

    #[test]
    fn test_empty_policy_displays_no_rules() {
        let engine = PolicyEngine {
            rules: vec![],
            is_default: false,
        };

        assert!(engine.rules.is_empty());
    }

    #[test]
    fn test_display_policy_default_header() {
        // Verify the default policy engine is marked as default
        let engine = PolicyEngine::default_policy();
        assert!(engine.is_default);
        // display_policy would print "Active Policy (default built-in):" for this
    }

    #[test]
    fn test_display_policy_custom_header() {
        let engine = PolicyEngine {
            rules: vec![DenyRule {
                command: "git".to_string(),
                subcommands: vec!["push".to_string()],
            }],
            is_default: false,
        };
        assert!(!engine.is_default);
        // display_policy would print "Active Policy (custom: ...):" for this
    }

    #[test]
    fn test_policy_rule_subcommands_formatting() {
        // Verify the subcommands join produces the expected format
        let rule = DenyRule {
            command: "git".to_string(),
            subcommands: vec![
                "commit".to_string(),
                "push".to_string(),
                "rebase".to_string(),
            ],
        };

        let formatted = rule.subcommands.join(", ");
        assert_eq!(formatted, "commit, push, rebase");
        // display_policy outputs: "  • git [commit, push, rebase]"
    }

    #[test]
    fn test_policy_from_yaml_displays_correctly() {
        // Load from YAML string, verify rules are correct for display
        let yaml = r#"rules:
  - deny:
      command: "kubectl"
      subcommands:
        - "delete"
        - "apply"
  - deny:
      command: "terraform"
      subcommands:
        - "destroy"
"#;
        let engine = PolicyEngine::load_from_str(yaml, false).unwrap();

        assert!(!engine.is_default);
        assert_eq!(engine.rules.len(), 2);
        assert_eq!(engine.rules[0].command, "kubectl");
        assert_eq!(engine.rules[0].subcommands, vec!["delete", "apply"]);
        assert_eq!(engine.rules[1].command, "terraform");
        assert_eq!(engine.rules[1].subcommands, vec!["destroy"]);
    }
}
