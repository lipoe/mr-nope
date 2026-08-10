// Unit tests for the Parser

#[allow(unused_imports)]
use mr_nope::parser::{ParseError, ParsedCommand, Parser};

#[cfg(test)]
mod split_compound_tests {
    use super::*;

    #[test]
    fn single_command_no_operators() {
        let result = Parser::split_compound("git status").unwrap();
        assert_eq!(result, vec!["git status"]);
    }

    #[test]
    fn split_on_and_operator() {
        let result = Parser::split_compound("git add . && git commit -m 'test'").unwrap();
        assert_eq!(result, vec!["git add .", "git commit -m 'test'"]);
    }

    #[test]
    fn split_on_or_operator() {
        let result = Parser::split_compound("git push || echo failed").unwrap();
        assert_eq!(result, vec!["git push", "echo failed"]);
    }

    #[test]
    fn split_on_semicolon() {
        let result = Parser::split_compound("echo hello; echo world").unwrap();
        assert_eq!(result, vec!["echo hello", "echo world"]);
    }

    #[test]
    fn split_on_pipe() {
        let result = Parser::split_compound("cat file.txt | grep pattern").unwrap();
        assert_eq!(result, vec!["cat file.txt", "grep pattern"]);
    }

    #[test]
    fn split_mixed_operators() {
        let result =
            Parser::split_compound("echo a | grep b && echo c || echo d; echo e").unwrap();
        assert_eq!(result, vec!["echo a", "grep b", "echo c", "echo d", "echo e"]);
    }

    #[test]
    fn preserves_single_quoted_operators() {
        let result = Parser::split_compound("echo '&&' | cat").unwrap();
        assert_eq!(result, vec!["echo '&&'", "cat"]);
    }

    #[test]
    fn preserves_double_quoted_operators() {
        let result = Parser::split_compound("echo \"||\" && cat").unwrap();
        assert_eq!(result, vec!["echo \"||\"", "cat"]);
    }

    #[test]
    fn preserves_single_quoted_pipe() {
        let result = Parser::split_compound("echo 'a | b'").unwrap();
        assert_eq!(result, vec!["echo 'a | b'"]);
    }

    #[test]
    fn preserves_double_quoted_semicolon() {
        let result = Parser::split_compound("echo \"a; b\"").unwrap();
        assert_eq!(result, vec!["echo \"a; b\""]);
    }

    #[test]
    fn unclosed_single_quote_returns_error() {
        let result = Parser::split_compound("echo 'hello");
        assert_eq!(result, Err(ParseError::UnclosedQuote));
    }

    #[test]
    fn unclosed_double_quote_returns_error() {
        let result = Parser::split_compound("echo \"hello");
        assert_eq!(result, Err(ParseError::UnclosedQuote));
    }

    #[test]
    fn empty_input_returns_empty_vec() {
        let result = Parser::split_compound("").unwrap();
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn whitespace_only_returns_empty_vec() {
        let result = Parser::split_compound("   ").unwrap();
        assert_eq!(result, Vec::<String>::new());
    }

    #[test]
    fn trailing_operator_produces_no_empty_segment() {
        let result = Parser::split_compound("echo hello;").unwrap();
        assert_eq!(result, vec!["echo hello"]);
    }

    #[test]
    fn leading_operator_produces_no_empty_segment() {
        let result = Parser::split_compound("; echo hello").unwrap();
        assert_eq!(result, vec!["echo hello"]);
    }

    #[test]
    fn multiple_pipes() {
        let result = Parser::split_compound("cat file | grep foo | sort | uniq").unwrap();
        assert_eq!(result, vec!["cat file", "grep foo", "sort", "uniq"]);
    }

    #[test]
    fn single_quote_inside_double_quotes_not_special() {
        // A single quote inside double quotes doesn't start a quoted region
        let result = Parser::split_compound("echo \"it's fine\" && echo done").unwrap();
        assert_eq!(result, vec!["echo \"it's fine\"", "echo done"]);
    }

    #[test]
    fn double_quote_inside_single_quotes_not_special() {
        // A double quote inside single quotes doesn't start a quoted region
        let result = Parser::split_compound("echo '\"hello\"' | cat").unwrap();
        assert_eq!(result, vec!["echo '\"hello\"'", "cat"]);
    }

    #[test]
    fn complex_compound_command() {
        let input = "git add . && git commit -m \"fix: resolve issue\" && git push origin main";
        let result = Parser::split_compound(input).unwrap();
        assert_eq!(
            result,
            vec![
                "git add .",
                "git commit -m \"fix: resolve issue\"",
                "git push origin main",
            ]
        );
    }
}


// ============================================================
// Nested Shell Tests (Requirement 3.2)
// ============================================================
#[cfg(test)]
mod nested_shell_tests {
    use super::*;

    #[test]
    fn sh_c_extracts_inner_command() {
        // Requirement 3.2: sh -c "git push" → extracts "git push"
        let result = Parser::extract_nested_shell("sh -c \"git push\"", 0).unwrap();
        assert_eq!(result, vec!["git push"]);
    }

    #[test]
    fn bash_c_extracts_inner_command() {
        // Requirement 3.2: bash -c "git commit -m test" → extracts inner command
        let result = Parser::extract_nested_shell("bash -c \"git commit -m test\"", 0).unwrap();
        assert_eq!(result, vec!["git commit -m test"]);
    }

    #[test]
    fn three_levels_of_nesting_succeeds() {
        // Three levels: sh → bash → zsh → actual command (within limit of 3)
        let result =
            Parser::extract_nested_shell("sh -c \"bash -c 'zsh -c git_status'\"", 0).unwrap();
        assert_eq!(result, vec!["git_status"]);
    }

    #[test]
    fn four_levels_of_nesting_returns_nesting_too_deep() {
        // Directly test the depth limit: if we start at depth 3 and encounter another shell -c,
        // it goes to depth 4 which exceeds MAX_NESTING_DEPTH (3).
        let result = Parser::extract_nested_shell("sh -c \"git push\"", 3);
        assert_eq!(result, Err(ParseError::NestingTooDeep));
    }

    #[test]
    fn depth_4_immediately_rejected() {
        // Starting at depth > MAX_NESTING_DEPTH immediately errors
        let result = Parser::extract_nested_shell("git push", 4);
        assert_eq!(result, Err(ParseError::NestingTooDeep));
    }

    #[test]
    fn unclosed_quotes_in_nested_shell() {
        let result = Parser::extract_nested_shell("sh -c \"git push", 0);
        assert_eq!(result, Err(ParseError::UnclosedQuote));
    }
}

// ============================================================
// Prefix Stripping Tests (Requirement 3.3)
// ============================================================
#[cfg(test)]
mod prefix_stripping_tests {
    use super::*;

    #[test]
    fn command_prefix_stripped() {
        // Requirement 3.3: command git push → "git push"
        assert_eq!(Parser::strip_builtin_prefix("command git push"), "git push");
    }

    #[test]
    fn env_with_var_assignment_stripped() {
        // Requirement 3.3: env FOO=bar git push → "git push"
        assert_eq!(
            Parser::strip_builtin_prefix("env FOO=bar git push"),
            "git push"
        );
    }

    #[test]
    fn env_command_exec_chained_all_stripped() {
        // Requirement 3.3: env command exec git push → "git push"
        assert_eq!(
            Parser::strip_builtin_prefix("env command exec git push"),
            "git push"
        );
    }

    #[test]
    fn exec_prefix_stripped() {
        assert_eq!(Parser::strip_builtin_prefix("exec git push"), "git push");
    }

    #[test]
    fn env_with_multiple_vars_stripped() {
        assert_eq!(
            Parser::strip_builtin_prefix("env FOO=bar BAZ=qux git commit"),
            "git commit"
        );
    }

    #[test]
    fn no_prefix_unchanged() {
        assert_eq!(Parser::strip_builtin_prefix("git push"), "git push");
    }
}

// ============================================================
// Command Identification Tests (Requirement 3.5)
// ============================================================
#[cfg(test)]
mod command_identification_tests {
    use super::*;

    #[test]
    fn git_push_identified() {
        // Requirement 3.5: git push → command="git", subcommand="push"
        let result = Parser::identify_command("git push");
        assert_eq!(result.command, "git");
        assert_eq!(result.subcommand, Some("push".to_string()));
    }

    #[test]
    fn flag_before_subcommand_skipped() {
        // Requirement 3.5: git -f push → command="git", subcommand="push" (flag before subcommand)
        let result = Parser::identify_command("git -f push");
        assert_eq!(result.command, "git");
        assert_eq!(result.subcommand, Some("push".to_string()));
    }

    #[test]
    fn all_flags_no_subcommand() {
        // Requirement 3.5: ls -la → command="ls", subcommand=None (all flags)
        let result = Parser::identify_command("ls -la");
        assert_eq!(result.command, "ls");
        assert_eq!(result.subcommand, None);
    }

    #[test]
    fn git_commit_with_flag_message() {
        let result = Parser::identify_command("git commit -m \"fix bug\"");
        assert_eq!(result.command, "git");
        assert_eq!(result.subcommand, Some("commit".to_string()));
    }

    #[test]
    fn command_with_multiple_flags_then_subcommand() {
        let result = Parser::identify_command("git --no-pager -v push");
        assert_eq!(result.command, "git");
        assert_eq!(result.subcommand, Some("push".to_string()));
    }

    #[test]
    fn single_command_no_args() {
        let result = Parser::identify_command("ls");
        assert_eq!(result.command, "ls");
        assert_eq!(result.subcommand, None);
    }
}

// ============================================================
// Substitution Extraction Tests (Requirement 3.6, 9.4)
// ============================================================
#[cfg(test)]
mod substitution_extraction_tests {
    use super::*;

    #[test]
    fn dollar_paren_extracts_git_push() {
        // Requirement 3.6, 9.4: echo $(git push) → extracts "git push"
        let result = Parser::extract_substitutions("echo $(git push)").unwrap();
        assert_eq!(result, vec!["git push"]);
    }

    #[test]
    fn backtick_extracts_git_push() {
        // Requirement 3.6: echo `git push` → extracts "git push"
        let result = Parser::extract_substitutions("echo `git push`").unwrap();
        assert_eq!(result, vec!["git push"]);
    }

    #[test]
    fn substitution_inside_single_quotes_not_extracted() {
        // Requirement 9.2: substitution inside single quotes is NOT extracted
        let result = Parser::extract_substitutions("echo '$(git push)'").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn unclosed_dollar_paren_returns_malformed_substitution() {
        // Unclosed $( returns MalformedSubstitution
        let result = Parser::extract_substitutions("echo $(git push");
        assert_eq!(result, Err(ParseError::MalformedSubstitution));
    }

    #[test]
    fn unclosed_backtick_returns_malformed_substitution() {
        let result = Parser::extract_substitutions("echo `git push");
        assert_eq!(result, Err(ParseError::MalformedSubstitution));
    }

    #[test]
    fn substitution_inside_double_quotes_is_extracted() {
        // $() inside double quotes is still expanded in shell
        let result = Parser::extract_substitutions("echo \"$(git push)\"").unwrap();
        assert_eq!(result, vec!["git push"]);
    }
}

// ============================================================
// Quote Awareness Tests (Requirement 9.2)
// ============================================================
#[cfg(test)]
mod quote_awareness_tests {
    use super::*;

    #[test]
    fn echo_git_push_in_double_quotes_not_treated_as_command() {
        // Requirement 9.2: echo "git push" → command="echo", subcommand="git push" (not "git")
        let result = Parser::identify_command("echo \"git push\"");
        assert_eq!(result.command, "echo");
        assert_eq!(result.subcommand, Some("git push".to_string()));
    }

    #[test]
    fn echo_git_push_in_single_quotes_not_treated_as_command() {
        let result = Parser::identify_command("echo 'git push'");
        assert_eq!(result.command, "echo");
        assert_eq!(result.subcommand, Some("git push".to_string()));
    }

    #[test]
    fn forbidden_command_inside_quotes_not_treated_as_command() {
        // Forbidden command inside quotes should NOT be matched as executable
        // The outer command is "echo", not "git"
        let result = Parser::identify_command("echo \"git commit -m test\"");
        assert_eq!(result.command, "echo");
        // The entire quoted string is the subcommand
        assert_eq!(result.subcommand, Some("git commit -m test".to_string()));
    }

    #[test]
    fn split_compound_preserves_quoted_operators() {
        // Operators inside quotes should not trigger splitting
        let result = Parser::split_compound("echo \"git push && git commit\"").unwrap();
        assert_eq!(result, vec!["echo \"git push && git commit\""]);
    }
}

// ============================================================
// Comment Handling Tests (Requirement 9.5)
// ============================================================
#[cfg(test)]
mod comment_handling_tests {
    use super::*;

    #[test]
    fn strips_comment_forbidden_command_not_seen() {
        // Requirement 9.5: echo hello # git push → strips comment, command="echo"
        let stripped = Parser::strip_comments("echo hello # git push");
        assert_eq!(stripped, "echo hello");
        let parsed = Parser::identify_command(&stripped);
        assert_eq!(parsed.command, "echo");
        assert_eq!(parsed.subcommand, Some("hello".to_string()));
    }

    #[test]
    fn hash_inside_quotes_preserved() {
        // Requirement 9.5: echo "# not a comment" → # inside quotes preserved
        let stripped = Parser::strip_comments("echo \"# not a comment\"");
        assert_eq!(stripped, "echo \"# not a comment\"");
        let parsed = Parser::identify_command(&stripped);
        assert_eq!(parsed.command, "echo");
        assert_eq!(parsed.subcommand, Some("# not a comment".to_string()));
    }

    #[test]
    fn hash_in_single_quotes_preserved() {
        let stripped = Parser::strip_comments("echo '# not a comment'");
        assert_eq!(stripped, "echo '# not a comment'");
    }

    #[test]
    fn no_comment_returns_unchanged() {
        let stripped = Parser::strip_comments("git status --short");
        assert_eq!(stripped, "git status --short");
    }
}

// ============================================================
// Substring Avoidance Tests (Requirement 9.3)
// ============================================================
#[cfg(test)]
mod substring_avoidance_tests {
    use super::*;

    #[test]
    fn filename_containing_forbidden_name_not_matched() {
        // Requirement 9.3: cat git-push-docs.md → command="cat", subcommand="git-push-docs.md"
        let result = Parser::identify_command("cat git-push-docs.md");
        assert_eq!(result.command, "cat");
        assert_eq!(result.subcommand, Some("git-push-docs.md".to_string()));
    }

    #[test]
    fn variable_containing_forbidden_name_not_matched() {
        let result = Parser::identify_command("echo $git_push_count");
        assert_eq!(result.command, "echo");
        assert_eq!(result.subcommand, Some("$git_push_count".to_string()));
    }

    #[test]
    fn hyphenated_binary_treated_as_single_command() {
        // "git-push" is a whole token, not split into "git" + "push"
        let result = Parser::identify_command("git-push some-arg");
        assert_eq!(result.command, "git-push");
        assert_eq!(result.subcommand, Some("some-arg".to_string()));
    }

    #[test]
    fn concatenated_name_not_split() {
        // "gitpush" is not "git" + "push"
        let result = Parser::identify_command("gitpush arg1");
        assert_eq!(result.command, "gitpush");
        assert_eq!(result.subcommand, Some("arg1".to_string()));
    }

    #[test]
    fn filename_with_dot_extension_not_split() {
        let result = Parser::identify_command("cat git-commit-helper.sh");
        assert_eq!(result.command, "cat");
        assert_eq!(result.subcommand, Some("git-commit-helper.sh".to_string()));
    }
}

// ============================================================
// Compound Command Tests with Mixed Operators (Requirement 3.1, 3.4)
// ============================================================
#[cfg(test)]
mod compound_mixed_operator_tests {
    use super::*;

    #[test]
    fn pipe_and_logical_and_semicolon_combined() {
        let result =
            Parser::split_compound("echo a | grep b && echo c; echo d || echo e").unwrap();
        assert_eq!(
            result,
            vec!["echo a", "grep b", "echo c", "echo d", "echo e"]
        );
    }

    #[test]
    fn deeply_nested_quotes_with_operators() {
        // Operators inside nested quotes should not trigger splitting
        let result =
            Parser::split_compound("echo \"hello && world\" | grep 'foo || bar'").unwrap();
        assert_eq!(result, vec!["echo \"hello && world\"", "grep 'foo || bar'"]);
    }

    #[test]
    fn empty_segments_filtered_out() {
        // Multiple separators should not produce empty segments
        let result = Parser::split_compound("echo a ;; echo b").unwrap();
        assert_eq!(result, vec!["echo a", "echo b"]);
    }

    #[test]
    fn unclosed_quote_in_compound() {
        let result = Parser::split_compound("echo \"hello && git push");
        assert_eq!(result, Err(ParseError::UnclosedQuote));
    }
}
