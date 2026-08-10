// Property tests for the Cursor Adapter
// Properties 15, 16, 17

use mr_nope::adapter::cursor::CursorAdapter;
use mr_nope::adapter::{Adapter, HookInput, Permission};
use mr_nope::engine::{Decision, PolicyEngine, PolicyEvaluator};
use proptest::prelude::*;

// --- Strategies ---

/// Generate a simple command token (binary name or subcommand-like).
fn command_token() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z][a-z0-9_-]{0,10}")
        .unwrap()
        .prop_filter("non-empty token", |s| !s.is_empty())
}

/// Generate a simple safe command string that won't trigger parse errors.
fn safe_command_string() -> impl Strategy<Value = String> {
    prop_oneof![
        // Simple command with subcommand
        (command_token(), command_token()).prop_map(|(cmd, sub)| format!("{} {}", cmd, sub)),
        // Command only
        command_token(),
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
            yaml.push_str(&format!(
                "  - deny:\n      command: \"{}\"\n      subcommands:\n",
                cmd
            ));
            for sub in subcmds {
                yaml.push_str(&format!("        - \"{}\"\n", sub));
            }
        }
        yaml
    })
}

// --- Property 15: Adapter Response Correctness ---
// Feature: mr-nope, Property 15: For any command string, the adapter returns
// permission: "deny" with rule info when the engine denies, and permission: "allow"
// when the engine allows.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 5.2, 5.3, 5.6**
    #[test]
    fn prop15_adapter_deny_matches_engine_deny(
        cmd_name in command_token(),
        subcmds in prop::collection::vec(command_token(), 1..=3),
        match_idx in 0usize..3,
    ) {
        let match_idx = match_idx % subcmds.len();
        let matching_sub = subcmds[match_idx].clone();

        // Build a policy that will deny cmd_name + matching_sub
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands:\n{}",
            cmd_name,
            subcmds
                .iter()
                .map(|s| format!("        - \"{}\"\n", s))
                .collect::<String>()
        );

        let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();
        let adapter = CursorAdapter::new(engine);

        // The command that should be denied
        let command_str = format!("{} {}", cmd_name, matching_sub);

        let input = HookInput {
            hook_event_name: "beforeShellExecution".to_string(),
            command: Some(command_str.clone()),
            tool_name: None,
            tool_input: None,
            workspace_roots: vec![],
        };

        let response = adapter.handle_hook(&input);

        prop_assert_eq!(
            response.permission,
            Permission::Deny,
            "Adapter should return Deny for command '{}' that matches policy rule '{}' {:?}",
            command_str,
            cmd_name,
            subcmds
        );
        prop_assert!(
            response.user_message.is_some(),
            "Deny response should include user_message with rule info"
        );
        prop_assert!(
            response.agent_message.is_some(),
            "Deny response should include agent_message with rule info"
        );
        // Verify rule info is present in the message
        let user_msg = response.user_message.unwrap();
        prop_assert!(
            user_msg.contains(&cmd_name),
            "User message should contain the matched command name '{}', got: {}",
            cmd_name,
            user_msg
        );
    }

    /// **Validates: Requirements 5.2, 5.3, 5.6**
    #[test]
    fn prop15_adapter_allow_matches_engine_allow(
        cmd_name in command_token(),
        other_cmd in command_token(),
        subcmds in prop::collection::vec(command_token(), 1..=3),
        other_sub in command_token(),
    ) {
        // Ensure the command we evaluate doesn't match the rule
        prop_assume!(cmd_name != other_cmd);

        // Build a policy that denies cmd_name but NOT other_cmd
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands:\n{}",
            cmd_name,
            subcmds
                .iter()
                .map(|s| format!("        - \"{}\"\n", s))
                .collect::<String>()
        );

        let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();
        let adapter = CursorAdapter::new(engine);

        // Evaluate a command that should be allowed
        let command_str = format!("{} {}", other_cmd, other_sub);

        let input = HookInput {
            hook_event_name: "beforeShellExecution".to_string(),
            command: Some(command_str.clone()),
            tool_name: None,
            tool_input: None,
            workspace_roots: vec![],
        };

        let response = adapter.handle_hook(&input);

        prop_assert_eq!(
            response.permission,
            Permission::Allow,
            "Adapter should return Allow for command '{}' that doesn't match policy rule '{}' {:?}",
            command_str,
            cmd_name,
            subcmds
        );
        prop_assert!(
            response.user_message.is_none(),
            "Allow response should not include user_message"
        );
        prop_assert!(
            response.agent_message.is_none(),
            "Allow response should not include agent_message"
        );
    }

    /// **Validates: Requirements 5.2, 5.3, 5.6**
    #[test]
    fn prop15_adapter_response_agrees_with_engine(
        cmd in safe_command_string(),
        policy_yaml in valid_policy_yaml(),
    ) {
        let engine = PolicyEngine::load_from_str(&policy_yaml, false).unwrap();
        let engine_result = engine.evaluate(&cmd);

        let engine2 = PolicyEngine::load_from_str(&policy_yaml, false).unwrap();
        let adapter = CursorAdapter::new(engine2);

        let input = HookInput {
            hook_event_name: "beforeShellExecution".to_string(),
            command: Some(cmd.clone()),
            tool_name: None,
            tool_input: None,
            workspace_roots: vec![],
        };

        let response = adapter.handle_hook(&input);

        match engine_result.decision {
            Decision::Allow => {
                prop_assert_eq!(
                    response.permission,
                    Permission::Allow,
                    "Engine allows '{}' but adapter returned Deny",
                    cmd
                );
            }
            Decision::Deny { .. } => {
                prop_assert_eq!(
                    response.permission,
                    Permission::Deny,
                    "Engine denies '{}' but adapter returned Allow",
                    cmd
                );
            }
        }
    }
}

// --- Property 16: Parse Error Results in Denial ---
// Feature: mr-nope, Property 16: For any input that causes a parse error
// (e.g., unclosed quotes), the adapter denies with an error message.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 5.5**
    #[test]
    fn prop16_unclosed_single_quote_denies(
        prefix in safe_command_string(),
    ) {
        // A command with an unclosed single quote should trigger a parse error
        let bad_command = format!("{} 'unclosed", prefix);

        let engine = PolicyEngine::default_policy();
        let adapter = CursorAdapter::new(engine);

        let input = HookInput {
            hook_event_name: "beforeShellExecution".to_string(),
            command: Some(bad_command.clone()),
            tool_name: None,
            tool_input: None,
            workspace_roots: vec![],
        };

        let response = adapter.handle_hook(&input);

        prop_assert_eq!(
            response.permission,
            Permission::Deny,
            "Unclosed single quote in '{}' should result in deny",
            bad_command
        );
        prop_assert!(
            response.user_message.is_some(),
            "Parse error denial should include a user message"
        );
    }

    /// **Validates: Requirements 5.5**
    #[test]
    fn prop16_unclosed_double_quote_denies(
        prefix in safe_command_string(),
    ) {
        // A command with an unclosed double quote should trigger a parse error
        let bad_command = format!("{} \"unclosed", prefix);

        let engine = PolicyEngine::default_policy();
        let adapter = CursorAdapter::new(engine);

        let input = HookInput {
            hook_event_name: "beforeShellExecution".to_string(),
            command: Some(bad_command.clone()),
            tool_name: None,
            tool_input: None,
            workspace_roots: vec![],
        };

        let response = adapter.handle_hook(&input);

        prop_assert_eq!(
            response.permission,
            Permission::Deny,
            "Unclosed double quote in '{}' should result in deny",
            bad_command
        );
        prop_assert!(
            response.user_message.is_some(),
            "Parse error denial should include a user message"
        );
    }

    /// **Validates: Requirements 5.5**
    #[test]
    fn prop16_malformed_substitution_denies(
        prefix in safe_command_string(),
    ) {
        // A command with an unclosed $( substitution should trigger a parse error
        let bad_command = format!("{} $(unclosed", prefix);

        let engine = PolicyEngine::default_policy();
        let adapter = CursorAdapter::new(engine);

        let input = HookInput {
            hook_event_name: "beforeShellExecution".to_string(),
            command: Some(bad_command.clone()),
            tool_name: None,
            tool_input: None,
            workspace_roots: vec![],
        };

        let response = adapter.handle_hook(&input);

        prop_assert_eq!(
            response.permission,
            Permission::Deny,
            "Unclosed substitution in '{}' should result in deny",
            bad_command
        );
        prop_assert!(
            response.user_message.is_some(),
            "Parse error denial should include a user message"
        );
    }
}

// --- Property 17: MCP Tool Call Scanning ---
// Feature: mr-nope, Property 17: For any MCP tool call with N string parameters,
// the adapter denies iff at least one string matches a deny rule.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 6.1, 6.2, 6.3**
    #[test]
    fn prop17_mcp_denies_when_any_string_matches_deny_rule(
        safe_strings in prop::collection::vec(
            command_token().prop_map(|s| format!("echo {}", s)),
            0..=3,
        ),
        denied_cmd in command_token(),
        denied_sub in command_token(),
    ) {
        // Build a policy that denies denied_cmd + denied_sub
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands:\n        - \"{}\"\n",
            denied_cmd, denied_sub
        );

        let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();
        let adapter = CursorAdapter::new(engine);

        // Build JSON with safe strings plus one forbidden command
        let forbidden_str = format!("{} {}", denied_cmd, denied_sub);
        let mut all_strings = safe_strings.clone();
        all_strings.push(forbidden_str.clone());

        // Build the JSON object with numbered keys
        let json_entries: Vec<String> = all_strings
            .iter()
            .enumerate()
            .map(|(i, s)| format!("\"param{}\": \"{}\"", i, s))
            .collect();
        let tool_input_json = format!("{{{}}}", json_entries.join(", "));

        let input = HookInput {
            hook_event_name: "beforeMCPExecution".to_string(),
            command: None,
            tool_name: Some("some_tool".to_string()),
            tool_input: Some(tool_input_json.clone()),
            workspace_roots: vec![],
        };

        let response = adapter.handle_hook(&input);

        prop_assert_eq!(
            response.permission,
            Permission::Deny,
            "MCP call with forbidden string '{}' in tool_input should be denied. JSON: {}",
            forbidden_str,
            tool_input_json
        );
    }

    /// **Validates: Requirements 6.1, 6.2, 6.3**
    #[test]
    fn prop17_mcp_allows_when_no_string_matches_deny_rule(
        safe_strings in prop::collection::vec(
            command_token().prop_map(|s| format!("echo {}", s)),
            1..=5,
        ),
        denied_cmd in command_token(),
        denied_sub in command_token(),
    ) {
        // Build a policy that denies denied_cmd + denied_sub
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands:\n        - \"{}\"\n",
            denied_cmd, denied_sub
        );

        let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();

        // Ensure none of the safe strings match the deny rule
        // (they all start with "echo " so they won't match a random command)
        // However, we need to make sure `denied_cmd` != "echo"
        prop_assume!(denied_cmd != "echo");

        let adapter = CursorAdapter::new(engine);

        // Build JSON object with safe strings only
        let json_entries: Vec<String> = safe_strings
            .iter()
            .enumerate()
            .map(|(i, s)| format!("\"param{}\": \"{}\"", i, s))
            .collect();
        let tool_input_json = format!("{{{}}}", json_entries.join(", "));

        let input = HookInput {
            hook_event_name: "beforeMCPExecution".to_string(),
            command: None,
            tool_name: Some("some_tool".to_string()),
            tool_input: Some(tool_input_json.clone()),
            workspace_roots: vec![],
        };

        let response = adapter.handle_hook(&input);

        prop_assert_eq!(
            response.permission,
            Permission::Allow,
            "MCP call with only safe strings should be allowed. JSON: {}",
            tool_input_json
        );
    }

    /// **Validates: Requirements 6.1, 6.2, 6.3**
    #[test]
    fn prop17_mcp_scans_all_string_values_in_nested_json(
        denied_cmd in command_token(),
        denied_sub in command_token(),
        nesting_depth in 1usize..=3,
    ) {
        // Build a policy that denies denied_cmd + denied_sub
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands:\n        - \"{}\"\n",
            denied_cmd, denied_sub
        );

        let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();
        let adapter = CursorAdapter::new(engine);

        // Build nested JSON where the forbidden command is buried deep
        let forbidden_str = format!("{} {}", denied_cmd, denied_sub);
        let mut json = format!("\"{}\"", forbidden_str);
        for i in 0..nesting_depth {
            json = format!("{{\"level{}\": {}}}", i, json);
        }

        let input = HookInput {
            hook_event_name: "beforeMCPExecution".to_string(),
            command: None,
            tool_name: Some("nested_tool".to_string()),
            tool_input: Some(json.clone()),
            workspace_roots: vec![],
        };

        let response = adapter.handle_hook(&input);

        prop_assert_eq!(
            response.permission,
            Permission::Deny,
            "MCP call with forbidden string nested {} levels deep should be denied. JSON: {}",
            nesting_depth,
            json
        );
    }

    /// **Validates: Requirements 6.1, 6.2, 6.3**
    #[test]
    fn prop17_mcp_scans_strings_in_arrays(
        denied_cmd in command_token(),
        denied_sub in command_token(),
        safe_count in 0usize..=3,
    ) {
        // Build a policy that denies denied_cmd + denied_sub
        let yaml = format!(
            "rules:\n  - deny:\n      command: \"{}\"\n      subcommands:\n        - \"{}\"\n",
            denied_cmd, denied_sub
        );

        let engine = PolicyEngine::load_from_str(&yaml, false).unwrap();
        let adapter = CursorAdapter::new(engine);

        // Build JSON array with safe strings followed by the forbidden one
        let forbidden_str = format!("{} {}", denied_cmd, denied_sub);
        let mut array_elements: Vec<String> = (0..safe_count)
            .map(|i| format!("\"safe_value_{}\"", i))
            .collect();
        array_elements.push(format!("\"{}\"", forbidden_str));

        let json = format!("{{\"commands\": [{}]}}", array_elements.join(", "));

        let input = HookInput {
            hook_event_name: "beforeMCPExecution".to_string(),
            command: None,
            tool_name: Some("array_tool".to_string()),
            tool_input: Some(json.clone()),
            workspace_roots: vec![],
        };

        let response = adapter.handle_hook(&input);

        prop_assert_eq!(
            response.permission,
            Permission::Deny,
            "MCP call with forbidden string in array should be denied. JSON: {}",
            json
        );
    }
}
