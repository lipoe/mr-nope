// Property tests for the Policy Engine
// Properties 1, 2, 12, 13, 14, 21

use mr_nope::engine::{Decision, DenyRule, PolicyEngine, PolicyEvaluator, PolicyMode};
use mr_nope::parser::ParsedCommand;
use proptest::prelude::*;

// --- Strategies ---

/// Generate a simple command token (binary name or subcommand-like).
fn command_token() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z][a-z0-9_-]{0,10}")
        .unwrap()
        .prop_filter("non-empty token", |s| !s.is_empty())
}

/// Generate a valid command string for evaluation (simple shell-like commands).
fn valid_command_string() -> impl Strategy<Value = String> {
    prop_oneof![
        // Simple command with subcommand
        (command_token(), command_token()).prop_map(|(cmd, sub)| format!("{} {}", cmd, sub)),
        // Command only
        command_token(),
        // Command with flags and subcommand
        (command_token(), command_token(), command_token())
            .prop_map(|(cmd, flag, sub)| format!("{} --{} {}", cmd, flag, sub)),
    ]
}

/// Generate a valid YAML policy string with arbitrary rules.
fn valid_policy_yaml() -> impl Strategy<Value = String> {
    prop::collection::vec(
        (command_token(), prop::collection::vec(command_token(), 1..=4)),
        1..=5,
    )
    .prop_map(|rules| {
        let mut yaml = String::from("rules:\n");
        for (cmd, subcmds) in rules {
            yaml.push_str(&format!("  - deny:\n      command: \"{}\"\n      subcommands:\n", cmd));
            for sub in subcmds {
                yaml.push_str(&format!("        - \"{}\"\n", sub));
            }
        }
        yaml
    })
}

/// Generate whitespace-only strings (spaces, tabs, and empty).
fn whitespace_only_string() -> impl Strategy<Value = String> {
    prop::collection::vec(prop_oneof![Just(' '), Just('\t')], 0..=20)
        .prop_map(|chars| chars.into_iter().collect())
}

// --- Property 1: Evaluation Determinism ---
// Feature: mr-nope, Property 1: For any command string and policy, evaluating the same
// command N≥2 times produces the same result.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 1.2**
    #[test]
    fn prop1_evaluation_determinism(
        cmd in valid_command_string(),
        n in 2u32..=10,
    ) {
        let engine = PolicyEngine::default_policy();

        let first_result = engine.evaluate(&cmd);

        for _ in 1..n {
            let result = engine.evaluate(&cmd);
            prop_assert_eq!(
                &result.decision,
                &first_result.decision,
                "Evaluation of '{}' produced different decisions across {} runs",
                cmd,
                n
            );
            prop_assert_eq!(
                &result.normalized,
                &first_result.normalized,
                "Evaluation of '{}' produced different normalized output across {} runs",
                cmd,
                n
            );
        }
    }

    /// **Validates: Requirements 1.2**
    #[test]
    fn prop1_evaluation_determinism_with_custom_policy(
        cmd in valid_command_string(),
        policy_yaml in valid_policy_yaml(),
    ) {
        let engine = PolicyEngine::load_from_str(&policy_yaml, false).unwrap();

        let first_result = engine.evaluate(&cmd);
        let second_result = engine.evaluate(&cmd);

        prop_assert_eq!(
            &first_result.decision,
            &second_result.decision,
            "Evaluation of '{}' with custom policy produced different decisions",
            cmd
        );
        prop_assert_eq!(
            &first_result.normalized,
            &second_result.normalized,
            "Evaluation of '{}' with custom policy produced different normalized output",
            cmd
        );
    }
}

// --- Property 2: Empty and Whitespace-Only Inputs Are Allowed ---
// Feature: mr-nope, Property 2: For any whitespace-only string (spaces, tabs, empty),
// the engine returns Allow.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 1.5, 5.4**
    #[test]
    fn prop2_empty_and_whitespace_only_inputs_allowed(
        input in whitespace_only_string(),
    ) {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate(&input);

        prop_assert!(
            result.decision == Decision::Allow,
            "Whitespace-only input '{}' (len={}) should return Allow",
            input.escape_debug(),
            input.len(),
        );
    }

    /// **Validates: Requirements 1.5, 5.4**
    #[test]
    fn prop2_empty_and_whitespace_with_custom_policy(
        input in whitespace_only_string(),
        policy_yaml in valid_policy_yaml(),
    ) {
        let engine = PolicyEngine::load_from_str(&policy_yaml, false).unwrap();
        let result = engine.evaluate(&input);

        prop_assert_eq!(
            result.decision,
            Decision::Allow,
            "Whitespace-only input '{}' should be allowed with any valid policy",
            input.escape_debug()
        );
    }
}

// --- Property 12: Policy Matching Correctness ---
// Feature: mr-nope, Property 12: For any ParsedCommand, the engine returns DENY iff
// command matches a rule's command AND subcommand matches any entry in subcommands.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 4.2, 4.3, 9.1**
    #[test]
    fn prop12_policy_matching_denies_exact_match(
        cmd_name in command_token(),
        subcmds in prop::collection::vec(command_token(), 1..=4),
        match_idx in 0usize..4,
    ) {
        // Pick a subcommand from the list that should trigger a deny
        let match_idx = match_idx % subcmds.len();
        let matching_sub = subcmds[match_idx].clone();

        let engine = PolicyEngine {
            rules: vec![DenyRule {
                command: cmd_name.clone(),
                subcommands: subcmds.clone(),
            }],
            is_default: false,
            mode: PolicyMode::Replace,
        };

        let parsed = ParsedCommand {
            command: cmd_name.clone(),
            subcommand: Some(matching_sub.clone()),
            full_segment: format!("{} {}", cmd_name, matching_sub),
        };

        let decision = engine.match_command(&parsed);

        prop_assert!(
            matches!(decision, Decision::Deny { .. }),
            "Command '{}' with subcommand '{}' should be DENIED (rule: {} {:?}), got {:?}",
            cmd_name,
            matching_sub,
            cmd_name,
            subcmds,
            decision
        );
    }

    /// **Validates: Requirements 4.2, 4.3, 9.1**
    #[test]
    fn prop12_policy_matching_allows_non_matching_subcommand(
        cmd_name in command_token(),
        subcmds in prop::collection::vec(command_token(), 1..=4),
        other_sub in command_token(),
    ) {
        // Ensure the other_sub is NOT in the subcommands list
        prop_assume!(!subcmds.contains(&other_sub));

        let engine = PolicyEngine {
            rules: vec![DenyRule {
                command: cmd_name.clone(),
                subcommands: subcmds.clone(),
            }],
            is_default: false,
            mode: PolicyMode::Replace,
        };

        let parsed = ParsedCommand {
            command: cmd_name.clone(),
            subcommand: Some(other_sub.clone()),
            full_segment: format!("{} {}", cmd_name, other_sub),
        };

        let decision = engine.match_command(&parsed);

        prop_assert_eq!(
            decision,
            Decision::Allow,
            "Command '{}' with non-matching subcommand '{}' should be ALLOWED (rule subcmds: {:?})",
            cmd_name,
            other_sub,
            subcmds
        );
    }

    /// **Validates: Requirements 4.2, 4.3, 9.1**
    #[test]
    fn prop12_policy_matching_allows_non_matching_command(
        rule_cmd in command_token(),
        other_cmd in command_token(),
        subcmds in prop::collection::vec(command_token(), 1..=4),
        sub_idx in 0usize..4,
    ) {
        // Ensure the commands are different
        prop_assume!(rule_cmd != other_cmd);

        let sub_idx = sub_idx % subcmds.len();
        let sub = subcmds[sub_idx].clone();

        let engine = PolicyEngine {
            rules: vec![DenyRule {
                command: rule_cmd.clone(),
                subcommands: subcmds.clone(),
            }],
            is_default: false,
            mode: PolicyMode::Replace,
        };

        let parsed = ParsedCommand {
            command: other_cmd.clone(),
            subcommand: Some(sub.clone()),
            full_segment: format!("{} {}", other_cmd, sub),
        };

        let decision = engine.match_command(&parsed);

        prop_assert_eq!(
            decision,
            Decision::Allow,
            "Command '{}' (rule expects '{}') should be ALLOWED even with matching subcommand '{}'",
            other_cmd,
            rule_cmd,
            sub
        );
    }

    /// **Validates: Requirements 4.2, 4.3, 9.1**
    #[test]
    fn prop12_policy_matching_allows_no_subcommand(
        cmd_name in command_token(),
        subcmds in prop::collection::vec(command_token(), 1..=4),
    ) {
        let engine = PolicyEngine {
            rules: vec![DenyRule {
                command: cmd_name.clone(),
                subcommands: subcmds.clone(),
            }],
            is_default: false,
            mode: PolicyMode::Replace,
        };

        let parsed = ParsedCommand {
            command: cmd_name.clone(),
            subcommand: None,
            full_segment: cmd_name.clone(),
        };

        let decision = engine.match_command(&parsed);

        prop_assert_eq!(
            decision,
            Decision::Allow,
            "Command '{}' with no subcommand should be ALLOWED (deny rules require subcommand match)",
            cmd_name
        );
    }
}

// --- Property 13: Malformed Policy Denies All ---
// Feature: mr-nope, Property 13: For any invalid policy content, PolicyEngine::load_from_str
// returns an error.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 4.4, 4.6**
    #[test]
    fn prop13_missing_rules_array_returns_error(
        random_key in command_token(),
        random_val in command_token(),
    ) {
        // YAML without a 'rules' array
        let yaml = format!("{}: {}\n", random_key, random_val);
        let result = PolicyEngine::load_from_str(&yaml, false);

        prop_assert!(
            result.is_err(),
            "Policy YAML without 'rules' array should return error, got {:?}",
            result
        );
    }

    /// **Validates: Requirements 4.4, 4.6**
    #[test]
    fn prop13_empty_command_field_returns_error(
        whitespace in prop::collection::vec(Just(' '), 0..=5),
        subcmd in command_token(),
    ) {
        // A deny rule with empty or whitespace-only command
        let ws: String = whitespace.into_iter().collect();
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands:\n        - \"{}\"\n",
            ws, subcmd
        );
        let result = PolicyEngine::load_from_str(&yaml, false);

        prop_assert!(
            result.is_err(),
            "Policy with empty/whitespace command '{}' should return error, got {:?}",
            ws.escape_debug(),
            result
        );
    }

    /// **Validates: Requirements 4.4, 4.6**
    #[test]
    fn prop13_empty_subcommands_array_returns_error(
        cmd in command_token(),
    ) {
        // A deny rule with empty subcommands array
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands: []\n",
            cmd
        );
        let result = PolicyEngine::load_from_str(&yaml, false);

        prop_assert!(
            result.is_err(),
            "Policy with empty subcommands for command '{}' should return error, got {:?}",
            cmd,
            result
        );
    }

    /// **Validates: Requirements 4.4, 4.6**
    #[test]
    fn prop13_whitespace_only_subcommand_entry_returns_error(
        cmd in command_token(),
        whitespace in prop::collection::vec(Just(' '), 0..=5),
    ) {
        // A deny rule with a whitespace-only entry in subcommands
        let ws: String = whitespace.into_iter().collect();
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands:\n        - \"{}\"\n",
            cmd, ws
        );
        let result = PolicyEngine::load_from_str(&yaml, false);

        prop_assert!(
            result.is_err(),
            "Policy with whitespace-only subcommand '{}' for command '{}' should return error, got {:?}",
            ws.escape_debug(),
            cmd,
            result
        );
    }
}

// --- Property 14: Valid Policy Schema Acceptance ---
// Feature: mr-nope, Property 14: For any YAML conforming to the schema,
// PolicyEngine::load_from_str succeeds.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 4.5**
    #[test]
    fn prop14_valid_policy_schema_acceptance(
        policy_yaml in valid_policy_yaml(),
    ) {
        let result = PolicyEngine::load_from_str(&policy_yaml, false);

        prop_assert!(
            result.is_ok(),
            "Valid policy YAML should load successfully, got error: {:?}\nYAML:\n{}",
            result.err(),
            policy_yaml
        );

        let engine = result.unwrap();
        prop_assert!(
            !engine.rules.is_empty(),
            "Loaded engine should have at least one rule for valid policy"
        );
    }

    /// **Validates: Requirements 4.5**
    #[test]
    fn prop14_valid_policy_rules_preserved(
        commands in prop::collection::vec(
            (command_token(), prop::collection::vec(command_token(), 1..=3)),
            1..=4,
        ),
    ) {
        // Build valid YAML and verify loaded rules match
        let mut yaml = String::from("rules:\n");
        for (cmd, subcmds) in &commands {
            yaml.push_str(&format!("  - deny:\n      command: \"{}\"\n      subcommands:\n", cmd));
            for sub in subcmds {
                yaml.push_str(&format!("        - \"{}\"\n", sub));
            }
        }

        let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();

        prop_assert_eq!(
            engine.rules.len(),
            commands.len(),
            "Number of loaded rules should match the number of rules in the YAML"
        );

        for (i, (cmd, subcmds)) in commands.iter().enumerate() {
            prop_assert_eq!(
                &engine.rules[i].command,
                cmd,
                "Rule {} command mismatch",
                i
            );
            prop_assert_eq!(
                &engine.rules[i].subcommands,
                subcmds,
                "Rule {} subcommands mismatch",
                i
            );
        }
    }
}

// --- Property 21: Custom Policy Fully Replaces Default ---
// Feature: mr-nope, Property 21: When a custom policy is loaded that doesn't include
// "git push", evaluating "git push" returns Allow.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 14.2**
    #[test]
    fn prop21_custom_policy_fully_replaces_default(
        custom_cmd in command_token().prop_filter("not git", |s| s != "git"),
        custom_subcmds in prop::collection::vec(command_token(), 1..=3),
    ) {
        // Build a custom policy that does NOT include "git push"
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands:\n{}",
            custom_cmd,
            custom_subcmds
                .iter()
                .map(|s| format!("        - \"{}\"\n", s))
                .collect::<String>()
        );

        // Load as custom (is_default = false)
        let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();

        // Verify the engine does NOT have git rules
        prop_assert!(
            !engine.is_default,
            "Custom policy should have is_default = false"
        );

        // Evaluate "git push" — should be ALLOWED since custom policy replaces default
        let result = engine.evaluate("git push");

        prop_assert!(
            result.decision == Decision::Allow,
            "Custom policy without 'git push' rule should ALLOW 'git push'. \
            Custom policy denies: {} {:?}",
            custom_cmd,
            custom_subcmds
        );
    }

    /// **Validates: Requirements 14.2**
    #[test]
    fn prop21_custom_policy_enforces_own_rules(
        custom_cmd in command_token(),
        custom_subcmds in prop::collection::vec(command_token(), 1..=3),
        match_idx in 0usize..3,
    ) {
        let match_idx = match_idx % custom_subcmds.len();
        let matching_sub = custom_subcmds[match_idx].clone();

        // Build a custom policy
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands:\n{}",
            custom_cmd,
            custom_subcmds
                .iter()
                .map(|s| format!("        - \"{}\"\n", s))
                .collect::<String>()
        );

        let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();

        // Evaluate a command that matches the custom policy — should be DENIED
        let cmd_str = format!("{} {}", custom_cmd, matching_sub);
        let result = engine.evaluate(&cmd_str);

        prop_assert!(
            matches!(result.decision, Decision::Deny { .. }),
            "Custom policy should DENY '{}' (rule: {} {:?}), got {:?}",
            cmd_str,
            custom_cmd,
            custom_subcmds,
            result.decision
        );
    }
}
