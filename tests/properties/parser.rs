// Property tests for the Parser
// Properties 7, 8, 9, 10, 11, 18, 19, 20

use mr_nope::engine::{Decision, PolicyEngine};
use mr_nope::parser::Parser;
use proptest::prelude::*;

// --- Strategies ---

/// Generate a simple command token (binary name or subcommand-like).
fn command_token() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z][a-z0-9_-]{0,10}")
        .unwrap()
        .prop_filter("non-empty token", |s| !s.is_empty())
}

/// Generate a list of flags (arguments starting with `-`).
fn flags() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop::string::string_regex("-{1,2}[a-z][a-z0-9-]{0,8}")
            .unwrap()
            .prop_filter("non-empty flag", |s| !s.is_empty()),
        0..3,
    )
}

/// Generate a compound operator for joining commands.
fn compound_operator() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(" | ".to_string()),
        Just(" && ".to_string()),
        Just(" || ".to_string()),
        Just("; ".to_string()),
    ]
}

/// Generate a simple command segment (binary + optional args).
fn simple_command_segment() -> impl Strategy<Value = String> {
    (command_token(), prop::collection::vec(command_token(), 0..3)).prop_map(|(cmd, args)| {
        if args.is_empty() {
            cmd
        } else {
            format!("{} {}", cmd, args.join(" "))
        }
    })
}

/// Generate a shell binary name.
fn shell_binary() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("sh".to_string()),
        Just("bash".to_string()),
        Just("zsh".to_string()),
    ]
}

/// Generate a builtin prefix.
fn builtin_prefix() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("command".to_string()),
        Just("exec".to_string()),
        Just("env".to_string()),
    ]
}

// --- Property 7: Compound Command Splitting ---
// Feature: mr-nope, Property 7: For any N commands joined by |, &&, ||, or ;,
// split_compound extracts all N segments.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 3.1, 3.4**
    #[test]
    fn prop7_compound_command_splitting(
        segments in prop::collection::vec(simple_command_segment(), 1..=6),
        operators in prop::collection::vec(compound_operator(), 5),
    ) {
        // Join N segments with operators (use first N-1 operators)
        let n = segments.len();
        let mut compound = segments[0].clone();
        for i in 1..n {
            let op = &operators[i - 1];
            compound.push_str(op);
            compound.push_str(&segments[i]);
        }

        let result = Parser::split_compound(&compound).unwrap();

        // The number of segments extracted should equal N
        prop_assert_eq!(
            result.len(),
            n,
            "Expected {} segments from compound '{}', got {:?}",
            n,
            compound,
            result
        );

        // Each extracted segment should match the original (trimmed)
        for (i, seg) in result.iter().enumerate() {
            prop_assert_eq!(
                seg.trim(),
                segments[i].trim(),
                "Segment {} mismatch in compound '{}'",
                i,
                compound
            );
        }
    }
}

// --- Property 8: Nested Shell Extraction ---
// Feature: mr-nope, Property 8: For any command wrapped in 1-3 levels of sh/bash/zsh -c,
// extract_nested_shell extracts the innermost command.

/// Wrap a command in N levels of shell -c nesting.
/// Uses alternating quote styles for outer levels and unquoted form for the
/// innermost wrapping, which mirrors how the parser extracts nested shells.
///
/// For N=1: `sh -c "inner"`
/// For N=2: `sh -c "bash -c 'inner'"`  
/// For N=3: `sh -c "bash -c 'zsh -c inner'"` (innermost is unquoted)
fn wrap_nested_shells(inner: &str, shells: &[String]) -> String {
    let n = shells.len();
    let mut wrapped = inner.to_string();

    for (i, shell) in shells.iter().rev().enumerate() {
        // i=0 is innermost wrapper, i=n-1 is outermost
        if i == 0 && n > 2 {
            // Innermost wrapper: use unquoted form (parser takes rest of string)
            wrapped = format!("{} -c {}", shell, wrapped);
        } else if i % 2 == 0 {
            // Use single quotes
            wrapped = format!("{} -c '{}'", shell, wrapped);
        } else {
            // Use double quotes
            wrapped = format!("{} -c \"{}\"", shell, wrapped);
        }
    }
    wrapped
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 3.2**
    #[test]
    fn prop8_nested_shell_extraction(
        inner_cmd in simple_command_segment(),
        shells in prop::collection::vec(shell_binary(), 1..=3),
    ) {
        // Wrap the inner command in N levels of shell -c with alternating quotes
        let wrapped = wrap_nested_shells(&inner_cmd, &shells);

        let result = Parser::extract_nested_shell(&wrapped, 0).unwrap();

        // The result should contain the innermost command
        prop_assert!(
            !result.is_empty(),
            "Expected non-empty result from nested shell extraction of '{}'",
            wrapped
        );

        // The extracted innermost command should be the original inner command
        prop_assert_eq!(
            result[0].trim(),
            inner_cmd.trim(),
            "Innermost command mismatch for wrapped '{}', got {:?}",
            wrapped,
            result
        );
    }
}

// --- Property 9: Builtin Prefix Stripping ---
// Feature: mr-nope, Property 9: For any command prefixed with command/exec/env,
// strip_builtin_prefix returns the actual command.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 3.3**
    #[test]
    fn prop9_builtin_prefix_stripping(
        prefix in builtin_prefix(),
        actual_cmd in simple_command_segment(),
    ) {
        let prefixed = format!("{} {}", prefix, actual_cmd);
        let result = Parser::strip_builtin_prefix(&prefixed);

        prop_assert_eq!(
            result.trim(),
            actual_cmd.trim(),
            "strip_builtin_prefix('{}') should return '{}', got '{}'",
            prefixed,
            actual_cmd,
            result
        );
    }
}

// --- Property 10: Command and Subcommand Identification ---
// Feature: mr-nope, Property 10: For any segment with a binary name followed by flags
// and positional args, identify_command identifies the binary as command and first
// non-flag as subcommand.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 3.5**
    #[test]
    fn prop10_command_and_subcommand_identification(
        binary in command_token(),
        pre_flags in flags(),
        subcommand in command_token(),
        post_flags in flags(),
    ) {
        // Build: binary [flags...] subcommand [flags...]
        let mut parts: Vec<String> = vec![binary.clone()];
        parts.extend(pre_flags.clone());
        parts.push(subcommand.clone());
        parts.extend(post_flags);

        let segment = parts.join(" ");
        let result = Parser::identify_command(&segment);

        // Binary is the command
        prop_assert_eq!(
            &result.command,
            &binary,
            "Command mismatch for segment '{}': expected '{}', got '{}'",
            segment,
            binary,
            result.command
        );

        // First non-flag is the subcommand
        prop_assert_eq!(
            result.subcommand.as_deref(),
            Some(subcommand.as_str()),
            "Subcommand mismatch for segment '{}': expected Some('{}'), got {:?}",
            segment,
            subcommand,
            result.subcommand
        );
    }
}

// --- Property 11: Command Substitution Extraction ---
// Feature: mr-nope, Property 11: For any command embedded in $(...) or backticks,
// extract_substitutions includes it.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 3.6, 9.4**
    #[test]
    fn prop11_dollar_paren_substitution_extraction(
        outer_cmd in command_token(),
        inner_cmd in simple_command_segment(),
    ) {
        // Embed inner_cmd in $(...) within a larger command
        let full = format!("{} $({}) arg", outer_cmd, inner_cmd);
        let result = Parser::extract_substitutions(&full).unwrap();

        prop_assert!(
            result.contains(&inner_cmd),
            "extract_substitutions('{}') should contain '{}', got {:?}",
            full,
            inner_cmd,
            result
        );
    }

    /// **Validates: Requirements 3.6, 9.4**
    #[test]
    fn prop11_backtick_substitution_extraction(
        outer_cmd in command_token(),
        inner_cmd in simple_command_segment(),
    ) {
        // Embed inner_cmd in backticks within a larger command
        let full = format!("{} `{}` arg", outer_cmd, inner_cmd);
        let result = Parser::extract_substitutions(&full).unwrap();

        prop_assert!(
            result.contains(&inner_cmd),
            "extract_substitutions('{}') should contain '{}', got {:?}",
            full,
            inner_cmd,
            result
        );
    }
}

// --- Property 18: Quoted Strings Not Treated as Commands ---
// Feature: mr-nope, Property 18: For any forbidden command name inside quotes
// (not substitution), identify_command on the outer command does not identify
// the quoted content as the command.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 9.2**
    #[test]
    fn prop18_single_quoted_forbidden_not_treated_as_command(
        outer_cmd in command_token(),
    ) {
        // Use "git push" as the forbidden command inside quotes
        let segment = format!("{} 'git push'", outer_cmd);
        let result = Parser::identify_command(&segment);

        // The outer command should be identified, not "git"
        prop_assert_eq!(
            &result.command,
            &outer_cmd,
            "identify_command('{}') should identify '{}' as command, got '{}'",
            segment,
            outer_cmd,
            result.command
        );

        // The subcommand should be "git push" as a single token (quoted),
        // NOT "git" treated as command
        prop_assert_ne!(
            result.command.as_str(),
            "git",
            "Quoted 'git push' inside segment '{}' should not be treated as the command",
            segment
        );
    }

    /// **Validates: Requirements 9.2**
    #[test]
    fn prop18_double_quoted_forbidden_not_treated_as_command(
        outer_cmd in command_token(),
    ) {
        // Use "git push" as the forbidden command inside double quotes
        let segment = format!("{} \"git push\"", outer_cmd);
        let result = Parser::identify_command(&segment);

        // The outer command should be identified, not "git"
        prop_assert_eq!(
            &result.command,
            &outer_cmd,
            "identify_command('{}') should identify '{}' as command, got '{}'",
            segment,
            outer_cmd,
            result.command
        );

        prop_assert_ne!(
            result.command.as_str(),
            "git",
            "Quoted \"git push\" inside segment '{}' should not be treated as the command",
            segment
        );
    }

    /// **Validates: Requirements 9.2**
    #[test]
    fn prop18_quoted_forbidden_with_policy_engine(
        outer_cmd in command_token().prop_filter("not git", |s| s != "git"),
        forbidden_sub in prop_oneof![Just("commit".to_string()), Just("push".to_string())],
    ) {
        // Build a command where the forbidden command appears only in quotes
        let segment = format!("{} 'git {}'", outer_cmd, forbidden_sub);
        let parsed = Parser::identify_command(&segment);

        // Apply the default policy engine
        let engine = PolicyEngine::default_policy();
        let decision = engine.match_command(&parsed);

        prop_assert_eq!(
            decision,
            Decision::Allow,
            "Quoted forbidden command in '{}' should be ALLOWED, parsed as cmd='{}' sub={:?}",
            segment,
            parsed.command,
            parsed.subcommand
        );
    }
}

// --- Property 19: Substring Matching Avoidance ---
// Feature: mr-nope, Property 19: For any forbidden command name as a substring
// in a larger token, identify_command does not match it.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 9.3**
    #[test]
    fn prop19_substring_not_matched_as_command(
        prefix in prop::string::string_regex("[a-z]{1,5}").unwrap(),
        suffix in prop::string::string_regex("[a-z]{1,5}").unwrap(),
        forbidden_sub in prop_oneof![Just("commit".to_string()), Just("push".to_string())],
    ) {
        // Create a token where "git" is a substring (e.g., "xgit", "gity", "xgity")
        let token_with_substring = format!("{}git{}", prefix, suffix);

        // Build a command segment with this token as the command
        let segment = format!("{} {}", token_with_substring, forbidden_sub);
        let parsed = Parser::identify_command(&segment);

        // The policy engine should NOT match it as "git"
        let engine = PolicyEngine::default_policy();
        let decision = engine.match_command(&parsed);

        prop_assert_eq!(
            decision,
            Decision::Allow,
            "Substring 'git' in '{}' should not be matched as command, parsed cmd='{}' sub={:?}",
            segment,
            parsed.command,
            parsed.subcommand
        );
    }

    /// **Validates: Requirements 9.3**
    #[test]
    fn prop19_substring_in_subcommand_not_matched(
        suffix in prop::string::string_regex("[a-z]{1,5}").unwrap(),
    ) {
        // "git" is the command but the subcommand contains "push" as a substring
        let subcmd_with_substring = format!("{}push{}", suffix, suffix);

        let segment = format!("git {}", subcmd_with_substring);
        let parsed = Parser::identify_command(&segment);

        // The policy engine should NOT deny because the subcommand doesn't exactly match
        let engine = PolicyEngine::default_policy();
        let decision = engine.match_command(&parsed);

        prop_assert_eq!(
            decision,
            Decision::Allow,
            "Substring 'push' in subcommand '{}' should not trigger deny, segment='{}'",
            subcmd_with_substring,
            segment
        );
    }
}

// --- Property 20: Comments Not Treated as Commands ---
// Feature: mr-nope, Property 20: For any command followed by # and a forbidden command,
// strip_comments removes the comment portion.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Validates: Requirements 9.5**
    #[test]
    fn prop20_comments_stripped_before_evaluation(
        safe_cmd in command_token().prop_filter("not git", |s| s != "git"),
        safe_sub in command_token(),
        forbidden_sub in prop_oneof![Just("commit".to_string()), Just("push".to_string())],
    ) {
        // Build: safe_cmd safe_sub # git push (forbidden only in comment)
        let full_line = format!("{} {} # git {}", safe_cmd, safe_sub, forbidden_sub);

        // strip_comments should remove the comment portion
        let stripped = Parser::strip_comments(&full_line);

        // The stripped result should NOT contain "git"
        prop_assert!(
            !stripped.contains("git"),
            "strip_comments('{}') should remove comment containing 'git', got '{}'",
            full_line,
            stripped
        );

        // The stripped result should contain the safe command
        prop_assert!(
            stripped.contains(&safe_cmd),
            "strip_comments('{}') should preserve '{}', got '{}'",
            full_line,
            safe_cmd,
            stripped
        );

        // After stripping comments, identify the command and check policy
        let parsed = Parser::identify_command(&stripped);
        let engine = PolicyEngine::default_policy();
        let decision = engine.match_command(&parsed);

        prop_assert_eq!(
            decision,
            Decision::Allow,
            "Command '{}' after stripping comments from '{}' should be ALLOWED",
            stripped,
            full_line
        );
    }

    /// **Validates: Requirements 9.5**
    #[test]
    fn prop20_strip_comments_preserves_pre_comment_content(
        cmd in simple_command_segment(),
        comment_text in prop::string::string_regex("[a-z ]{1,20}").unwrap(),
    ) {
        let full_line = format!("{} # {}", cmd, comment_text);
        let stripped = Parser::strip_comments(&full_line);

        // The result should be the command portion only (trimmed)
        prop_assert_eq!(
            stripped.trim(),
            cmd.trim(),
            "strip_comments('{}') should return '{}', got '{}'",
            full_line,
            cmd,
            stripped
        );
    }
}
