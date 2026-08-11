// Mr. Nope - CLI test command
// Runs policy self-test by evaluating each deny rule's command+subcommand pairs
// and verifying they produce a DENY decision.

use crate::cli::evaluate::discover_policy_from_cwd;
use crate::engine::{Decision, PolicyEngine, PolicyEvaluator};

/// Run the policy self-test.
///
/// Loads the active policy (custom `.mr-nope.yml` in CWD, or default),
/// then for each deny rule, synthesizes `"{command} {subcommand}"` strings
/// and evaluates them through the engine.
///
/// Returns exit code 0 if all tests pass, 1 if any fail.
pub fn run_test() -> i32 {
    // Discover policy from current working directory
    let (engine, _policy_path) = discover_policy_from_cwd();

    run_test_with_engine(&engine)
}

/// Run the policy self-test with a given engine. Returns exit code 0 if all pass, 1 otherwise.
///
/// This is separated from `run_test` to enable unit testing without filesystem dependency.
pub fn run_test_with_engine(engine: &PolicyEngine) -> i32 {
    let policy_source = if engine.is_default {
        "default"
    } else {
        "custom (.mr-nope.yml)"
    };

    println!("Running policy self-test ({})", policy_source);
    println!();

    let mut passed = 0u32;
    let mut total = 0u32;

    for rule in &engine.rules {
        for subcommand in &rule.subcommands {
            total += 1;
            let synthesized = format!("{} {}", rule.command, subcommand);
            let result = engine.evaluate(&synthesized);

            match result.decision {
                Decision::Deny { .. } => {
                    println!("  \u{2713} {} {} \u{2192} DENY (pass)", rule.command, subcommand);
                    passed += 1;
                }
                Decision::Allow => {
                    println!(
                        "  \u{2717} {} {} \u{2192} ALLOW (FAIL)",
                        rule.command, subcommand
                    );
                }
            }
        }
    }

    println!();
    println!("{}/{} tests passed", passed, total);

    if passed == total {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::DenyRule;

    #[test]
    fn test_default_policy_test_passes() {
        // The default policy denies "git commit" and "git push".
        // The test command should confirm both are denied.
        let engine = PolicyEngine::default_policy();
        let exit_code = run_test_with_engine(&engine);
        assert_eq!(
            exit_code, 0,
            "Default policy self-test should pass (all denied commands correctly denied)"
        );
    }

    #[test]
    fn test_default_policy_denies_git_commit() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("git commit");
        assert!(
            matches!(result.decision, Decision::Deny { .. }),
            "git commit should be denied by default policy"
        );
    }

    #[test]
    fn test_default_policy_denies_git_push() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("git push");
        assert!(
            matches!(result.decision, Decision::Deny { .. }),
            "git push should be denied by default policy"
        );
    }

    #[test]
    fn test_custom_engine_denies_synthesized_commands() {
        // Create a custom engine with a rule denying "npm publish"
        let engine = PolicyEngine {
            rules: vec![DenyRule {
                command: "npm".to_string(),
                subcommands: vec!["publish".to_string()],
            }],
            is_default: false,
            mode: crate::engine::PolicyMode::Replace,
        };

        let exit_code = run_test_with_engine(&engine);
        assert_eq!(exit_code, 0, "Custom policy self-test should pass");

        // Verify the synthesized command "npm publish" is correctly denied
        let result = engine.evaluate("npm publish");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_custom_engine_multiple_rules_all_pass() {
        let engine = PolicyEngine {
            rules: vec![
                DenyRule {
                    command: "git".to_string(),
                    subcommands: vec!["push".to_string(), "commit".to_string()],
                },
                DenyRule {
                    command: "docker".to_string(),
                    subcommands: vec!["push".to_string()],
                },
            ],
            is_default: false,
            mode: crate::engine::PolicyMode::Replace,
        };

        let exit_code = run_test_with_engine(&engine);
        assert_eq!(exit_code, 0, "All deny rules should correctly produce DENY");
    }

    #[test]
    fn test_empty_rules_produces_zero_exit_code() {
        // Empty rules = no tests to run, all pass vacuously
        let engine = PolicyEngine {
            rules: vec![],
            is_default: false,
            mode: crate::engine::PolicyMode::Replace,
        };

        let exit_code = run_test_with_engine(&engine);
        assert_eq!(
            exit_code, 0,
            "Empty policy should produce exit code 0 (0/0 passed)"
        );
    }

    #[test]
    fn test_synthesized_command_format() {
        // Verify the format used for synthesized test commands is "{command} {subcommand}"
        let engine = PolicyEngine {
            rules: vec![DenyRule {
                command: "docker".to_string(),
                subcommands: vec!["push".to_string(), "login".to_string()],
            }],
            is_default: false,
            mode: crate::engine::PolicyMode::Replace,
        };

        // Verify "docker push" and "docker login" are both denied
        let result1 = engine.evaluate("docker push");
        let result2 = engine.evaluate("docker login");
        assert!(matches!(result1.decision, Decision::Deny { .. }));
        assert!(matches!(result2.decision, Decision::Deny { .. }));
    }
}
