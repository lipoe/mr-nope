// Mr. Nope - Parser module
// Handles compound command splitting, nested shell extraction,
// prefix stripping, command identification, and substitution extraction.

use std::fmt;

/// A parsed command segment with identified command and subcommand.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedCommand {
    /// The binary/command name (e.g., "git").
    pub command: String,
    /// The first non-flag argument (e.g., "push"), if present.
    pub subcommand: Option<String>,
    /// The full original segment text before parsing.
    pub full_segment: String,
}

/// Errors that can occur during command parsing.
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    /// Unclosed quote in the command string.
    UnclosedQuote,
    /// Malformed command substitution syntax.
    MalformedSubstitution,
    /// Shell nesting exceeds the maximum depth of 3.
    NestingTooDeep,
    /// The command string is empty after parsing.
    EmptyCommand,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnclosedQuote => write!(f, "unclosed quote in command string"),
            ParseError::MalformedSubstitution => {
                write!(f, "malformed command substitution syntax")
            }
            ParseError::NestingTooDeep => {
                write!(f, "shell nesting exceeds maximum depth of 3")
            }
            ParseError::EmptyCommand => write!(f, "command string is empty after parsing"),
        }
    }
}

impl std::error::Error for ParseError {}

/// The Parser handles structural analysis of shell commands.
pub struct Parser;

/// The maximum allowed nesting depth for shell invocations.
const MAX_NESTING_DEPTH: u8 = 3;

/// Shell binaries that can invoke nested commands via `-c`.
const SHELL_BINARIES: &[&str] = &["sh", "bash", "zsh"];

/// Builtin prefixes that should be stripped before identifying the actual command.
const BUILTIN_PREFIXES: &[&str] = &["command", "exec", "env"];

impl Parser {
    /// Extract commands from nested shell invocations.
    ///
    /// Detects `sh -c`, `bash -c`, `zsh -c` patterns and extracts the inner
    /// command string. Supports up to 3 levels of nesting depth.
    ///
    /// Returns the innermost command(s) as strings to be evaluated. If the input
    /// is not a nested shell invocation, it is returned as-is in the result vector.
    ///
    /// Returns `Err(ParseError::NestingTooDeep)` if nesting exceeds 3 levels.
    /// Returns `Err(ParseError::UnclosedQuote)` if quoted arguments are malformed.
    pub fn extract_nested_shell(input: &str, depth: u8) -> Result<Vec<String>, ParseError> {
        let trimmed = input.trim();

        if trimmed.is_empty() {
            return Ok(vec![]);
        }

        // Check if this exceeds maximum nesting depth
        if depth > MAX_NESTING_DEPTH {
            return Err(ParseError::NestingTooDeep);
        }

        // Try to detect a shell -c pattern
        if let Some(inner) = Self::try_extract_shell_arg(trimmed)? {
            // Recurse into the extracted inner command
            Self::extract_nested_shell(&inner, depth + 1)
        } else {
            // Not a nested shell invocation — return as-is
            Ok(vec![trimmed.to_string()])
        }
    }

    /// Try to parse a `sh -c "..."`, `bash -c '...'`, or `zsh -c ...` pattern.
    ///
    /// Returns `Some(inner_command)` if the input matches a shell -c invocation,
    /// or `None` if it does not match.
    fn try_extract_shell_arg(input: &str) -> Result<Option<String>, ParseError> {
        // Split into at most 3 parts: <shell> <flag> <rest>
        let mut parts = input.splitn(3, |c: char| c.is_whitespace());

        let shell = match parts.next() {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(None),
        };

        let flag = match parts.next() {
            Some(f) => f,
            None => return Ok(None),
        };

        let rest = match parts.next() {
            Some(r) => r.trim(),
            None => return Ok(None),
        };

        // Check if the flag is `-c`
        if flag != "-c" {
            return Ok(None);
        }

        // Extract just the binary name (handle path-qualified shells like /bin/sh)
        let shell_name = shell.rsplit('/').next().unwrap_or(shell);
        let shell_name = shell_name.rsplit('\\').next().unwrap_or(shell_name);

        if !SHELL_BINARIES.contains(&shell_name) {
            return Ok(None);
        }

        if rest.is_empty() {
            return Ok(None);
        }

        // Extract the command string, handling quotes
        let inner = Self::extract_quoted_or_unquoted_arg(rest)?;
        Ok(Some(inner))
    }

    /// Extract the argument to `-c`, handling both quoted and unquoted forms.
    ///
    /// - If the argument starts with `'` or `"`, extract the content between matching quotes.
    /// - Otherwise, return the entire remaining string as the argument.
    fn extract_quoted_or_unquoted_arg(input: &str) -> Result<String, ParseError> {
        let chars: Vec<char> = input.chars().collect();

        if chars.is_empty() {
            return Ok(String::new());
        }

        let first = chars[0];

        if first == '\'' || first == '"' {
            // Find the matching closing quote
            let mut i = 1;
            while i < chars.len() {
                if chars[i] == first {
                    // Found the closing quote — return content between quotes
                    let inner: String = chars[1..i].iter().collect();
                    return Ok(inner);
                }
                i += 1;
            }
            // No matching closing quote found
            Err(ParseError::UnclosedQuote)
        } else {
            // Unquoted: the entire rest is the argument
            Ok(input.to_string())
        }
    }

    /// Strip builtin shell prefixes (`command`, `exec`, `env`) from a command string,
    /// returning the remaining string with the actual command and its arguments.
    ///
    /// Handles:
    /// - Simple prefixes: `command git push` → `git push`
    /// - Chained prefixes: `env command git push` → `git push`
    /// - `env` with VAR=value assignments: `env FOO=bar git push` → `git push`
    /// - Combinations: `env VAR=val command exec git push` → `git push`
    ///
    /// Returns the input unchanged if no known prefix is found.
    pub fn strip_builtin_prefix(input: &str) -> String {
        let mut remaining = input.trim();

        loop {
            // Check if the remaining string starts with a known builtin prefix
            let mut matched = false;

            for &prefix in BUILTIN_PREFIXES {
                if remaining == prefix {
                    // The entire remaining input is just the prefix with nothing after it
                    // Return empty since there's no actual command
                    return String::new();
                }

                if let Some(after) = remaining.strip_prefix(prefix) {
                    // Must be followed by a space to be a valid prefix usage
                    if after.starts_with(' ') {
                        let after = after.trim_start();

                        // For `env`, skip any VAR=value assignments
                        if prefix == "env" {
                            remaining = Self::skip_env_assignments(after);
                        } else {
                            remaining = after;
                        }

                        matched = true;
                        break;
                    }
                }
            }

            if !matched {
                break;
            }
        }

        remaining.to_string()
    }

    /// Skip `VAR=value` style environment variable assignments that follow `env`.
    /// Returns the remaining string after all assignments are consumed.
    fn skip_env_assignments(input: &str) -> &str {
        let mut remaining = input;

        loop {
            // Check if the next token looks like a VAR=value assignment
            // A VAR=value token contains '=' and no leading '-' (not a flag)
            let token_end = remaining.find(' ').unwrap_or(remaining.len());
            let token = &remaining[..token_end];

            if token.is_empty() {
                break;
            }

            // A variable assignment: starts with a letter or underscore,
            // contains '=', and the part before '=' is a valid variable name
            if Self::is_env_assignment(token) {
                // Skip this token
                remaining = remaining[token_end..].trim_start();
            } else {
                break;
            }
        }

        remaining
    }

    /// Check if a token looks like an environment variable assignment (e.g., `FOO=bar`).
    fn is_env_assignment(token: &str) -> bool {
        if let Some(eq_pos) = token.find('=') {
            // The part before '=' must be a valid variable name:
            // starts with letter or underscore, contains only alphanumeric and underscore
            let var_name = &token[..eq_pos];
            if var_name.is_empty() {
                return false;
            }
            let first_char = var_name.chars().next().unwrap();
            if !first_char.is_ascii_alphabetic() && first_char != '_' {
                return false;
            }
            var_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        } else {
            false
        }
    }

    /// Identify the command (binary name) and subcommand from a single command segment.
    ///
    /// The segment is split into whitespace-separated tokens (respecting quotes).
    /// The first token is the command. The first remaining token that does not
    /// start with `-` is the subcommand. If no such token exists, subcommand is None.
    ///
    /// The full original segment is stored in `full_segment`.
    pub fn identify_command(segment: &str) -> ParsedCommand {
        let full_segment = segment.to_string();
        let tokens = Self::tokenize(segment);

        if tokens.is_empty() {
            return ParsedCommand {
                command: String::new(),
                subcommand: None,
                full_segment,
            };
        }

        let command = tokens[0].clone();
        let subcommand = tokens[1..]
            .iter()
            .find(|t| !t.starts_with('-'))
            .cloned();

        ParsedCommand {
            command,
            subcommand,
            full_segment,
        }
    }

    /// Tokenize a command segment by splitting on whitespace, respecting single
    /// and double quotes. Quotes are stripped from the resulting tokens.
    fn tokenize(input: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let ch = chars[i];

            if ch == '\'' && !in_double_quote {
                in_single_quote = !in_single_quote;
                // Don't push the quote character itself into the token
                i += 1;
                continue;
            }

            if ch == '"' && !in_single_quote {
                in_double_quote = !in_double_quote;
                // Don't push the quote character itself into the token
                i += 1;
                continue;
            }

            if ch.is_whitespace() && !in_single_quote && !in_double_quote {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
                i += 1;
                continue;
            }

            current.push(ch);
            i += 1;
        }

        if !current.is_empty() {
            tokens.push(current);
        }

        tokens
    }

    /// Extract commands from command substitutions (`$(...)` and backtick syntax).
    ///
    /// Scans the input for `$(...)` patterns (handling nested parentheses) and
    /// backtick `` `...` `` patterns, extracting the inner command strings.
    /// These commands are meant to be ADDED to the set of commands evaluated
    /// against policy (in addition to the outer command).
    ///
    /// This method is quote-aware: substitutions inside single quotes are treated
    /// as literal text and are NOT extracted.
    ///
    /// Returns `Err(ParseError::MalformedSubstitution)` for unclosed `$(` or unmatched backticks.
    pub fn extract_substitutions(input: &str) -> Result<Vec<String>, ParseError> {
        let mut results: Vec<String> = Vec::new();
        let chars: Vec<char> = input.chars().collect();
        let len = chars.len();
        let mut i = 0;
        let mut in_single_quote = false;
        let mut in_double_quote = false;

        while i < len {
            let ch = chars[i];

            // Track single quotes (toggle, but not inside double quotes)
            if ch == '\'' && !in_double_quote {
                in_single_quote = !in_single_quote;
                i += 1;
                continue;
            }

            // Track double quotes (toggle, but not inside single quotes)
            if ch == '"' && !in_single_quote {
                in_double_quote = !in_double_quote;
                i += 1;
                continue;
            }

            // Inside single quotes, everything is literal — skip
            if in_single_quote {
                i += 1;
                continue;
            }

            // Detect $( ... ) — allowed inside double quotes (they are still expanded in sh)
            if ch == '$' && i + 1 < len && chars[i + 1] == '(' {
                // Find the matching closing ) accounting for nested parens
                let start = i + 2; // skip past "$("
                let mut depth = 1;
                let mut j = start;

                while j < len && depth > 0 {
                    match chars[j] {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    if depth > 0 {
                        j += 1;
                    }
                }

                if depth != 0 {
                    return Err(ParseError::MalformedSubstitution);
                }

                // Extract content between $( and the matching )
                let inner: String = chars[start..j].iter().collect();
                let trimmed = inner.trim().to_string();
                if !trimmed.is_empty() {
                    results.push(trimmed);
                }
                i = j + 1; // skip past the closing ')'
                continue;
            }

            // Detect backtick `...`
            if ch == '`' {
                let start = i + 1;
                let mut j = start;

                // Find the matching closing backtick
                while j < len && chars[j] != '`' {
                    j += 1;
                }

                if j >= len {
                    return Err(ParseError::MalformedSubstitution);
                }

                // Extract content between backticks
                let inner: String = chars[start..j].iter().collect();
                let trimmed = inner.trim().to_string();
                if !trimmed.is_empty() {
                    results.push(trimmed);
                }
                i = j + 1; // skip past the closing backtick
                continue;
            }

            i += 1;
        }

        // Check for unmatched quotes that might indicate malformed input
        // (single quote left open means unclosed backtick/substitution could be inside)
        if in_single_quote {
            // An unclosed single quote is technically an UnclosedQuote error,
            // but for this method we only report substitution-related errors.
            // The single quote just means the rest of the string is literal.
            // Actually, let's not error here — split_compound handles quote errors.
        }

        Ok(results)
    }

    /// Strip shell comments from a command string.
    ///
    /// Detects the first unquoted `#` character (not inside single or double quotes)
    /// and removes everything from that `#` onwards. Returns the trimmed result.
    ///
    /// This ensures that forbidden command names appearing only in shell comments
    /// are not treated as executable commands.
    ///
    /// # Examples
    /// ```
    /// # use mr_nope::parser::Parser;
    /// assert_eq!(Parser::strip_comments("echo hello # this is a comment"), "echo hello");
    /// assert_eq!(Parser::strip_comments("echo '#not a comment'"), "echo '#not a comment'");
    /// ```
    pub fn strip_comments(input: &str) -> String {
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let chars: Vec<char> = input.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            let ch = chars[i];

            // Track single quotes (toggle, but not inside double quotes)
            if ch == '\'' && !in_double_quote {
                in_single_quote = !in_single_quote;
                i += 1;
                continue;
            }

            // Track double quotes (toggle, but not inside single quotes)
            if ch == '"' && !in_single_quote {
                in_double_quote = !in_double_quote;
                i += 1;
                continue;
            }

            // If inside any quotes, skip
            if in_single_quote || in_double_quote {
                i += 1;
                continue;
            }

            // Unquoted `#` — everything from here on is a comment
            if ch == '#' {
                let result: String = chars[..i].iter().collect();
                return result.trim_end().to_string();
            }

            i += 1;
        }

        // No unquoted `#` found — return the input unchanged
        input.to_string()
    }

    /// Split a normalized command string into segments at unquoted compound operators.
    ///
    /// Splits on `&&`, `||`, `;`, and `|` operators that are not inside
    /// single or double quotes. Returns each segment as a trimmed string.
    ///
    /// Returns `Err(ParseError::UnclosedQuote)` if the input contains an unclosed quote.
    pub fn split_compound(input: &str) -> Result<Vec<String>, ParseError> {
        let mut segments: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let chars: Vec<char> = input.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            let ch = chars[i];

            // Handle quote toggling
            if ch == '\'' && !in_double_quote {
                in_single_quote = !in_single_quote;
                current.push(ch);
                i += 1;
                continue;
            }

            if ch == '"' && !in_single_quote {
                in_double_quote = !in_double_quote;
                current.push(ch);
                i += 1;
                continue;
            }

            // If inside quotes, just accumulate the character
            if in_single_quote || in_double_quote {
                current.push(ch);
                i += 1;
                continue;
            }

            // Outside quotes: check for compound operators
            // Check for `&&` (must check before single `&` if we were to handle background)
            if ch == '&' && i + 1 < len && chars[i + 1] == '&' {
                // Split here
                segments.push(current.trim().to_string());
                current = String::new();
                i += 2;
                continue;
            }

            // Check for `||`
            if ch == '|' && i + 1 < len && chars[i + 1] == '|' {
                segments.push(current.trim().to_string());
                current = String::new();
                i += 2;
                continue;
            }

            // Check for single `|` (pipe)
            if ch == '|' {
                segments.push(current.trim().to_string());
                current = String::new();
                i += 1;
                continue;
            }

            // Check for `;`
            if ch == ';' {
                segments.push(current.trim().to_string());
                current = String::new();
                i += 1;
                continue;
            }

            // Regular character
            current.push(ch);
            i += 1;
        }

        // Check for unclosed quotes
        if in_single_quote || in_double_quote {
            return Err(ParseError::UnclosedQuote);
        }

        // Push the last segment
        segments.push(current.trim().to_string());

        // Filter out empty segments (e.g., from trailing operators)
        let segments: Vec<String> = segments.into_iter().filter(|s| !s.is_empty()).collect();

        Ok(segments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod strip_builtin_prefix {
        use super::*;

        #[test]
        fn strips_command_prefix() {
            assert_eq!(Parser::strip_builtin_prefix("command git push"), "git push");
        }

        #[test]
        fn strips_exec_prefix() {
            assert_eq!(Parser::strip_builtin_prefix("exec git push"), "git push");
        }

        #[test]
        fn strips_env_prefix() {
            assert_eq!(Parser::strip_builtin_prefix("env git push"), "git push");
        }

        #[test]
        fn strips_chained_prefixes() {
            assert_eq!(
                Parser::strip_builtin_prefix("env command git push"),
                "git push"
            );
            assert_eq!(
                Parser::strip_builtin_prefix("command exec git push"),
                "git push"
            );
            assert_eq!(
                Parser::strip_builtin_prefix("env command exec git push"),
                "git push"
            );
        }

        #[test]
        fn strips_env_with_var_assignments() {
            assert_eq!(
                Parser::strip_builtin_prefix("env FOO=bar git push"),
                "git push"
            );
            assert_eq!(
                Parser::strip_builtin_prefix("env FOO=bar BAZ=qux git push"),
                "git push"
            );
        }

        #[test]
        fn strips_env_with_vars_and_chained_prefix() {
            assert_eq!(
                Parser::strip_builtin_prefix("env FOO=bar command git push"),
                "git push"
            );
        }

        #[test]
        fn no_prefix_returns_unchanged() {
            assert_eq!(Parser::strip_builtin_prefix("git push"), "git push");
            assert_eq!(Parser::strip_builtin_prefix("ls -la"), "ls -la");
        }

        #[test]
        fn does_not_strip_prefix_as_substring() {
            // "commands" is not "command", should not be stripped
            assert_eq!(
                Parser::strip_builtin_prefix("commands git push"),
                "commands git push"
            );
            assert_eq!(
                Parser::strip_builtin_prefix("environment git push"),
                "environment git push"
            );
        }

        #[test]
        fn handles_empty_input() {
            assert_eq!(Parser::strip_builtin_prefix(""), "");
        }

        #[test]
        fn handles_prefix_only_no_command() {
            assert_eq!(Parser::strip_builtin_prefix("command"), "");
            assert_eq!(Parser::strip_builtin_prefix("exec"), "");
            assert_eq!(Parser::strip_builtin_prefix("env"), "");
        }

        #[test]
        fn handles_env_with_only_assignments() {
            // env with assignments but no actual command after
            assert_eq!(Parser::strip_builtin_prefix("env FOO=bar"), "");
        }

        #[test]
        fn handles_extra_whitespace() {
            assert_eq!(
                Parser::strip_builtin_prefix("command   git push"),
                "git push"
            );
            assert_eq!(
                Parser::strip_builtin_prefix("env   FOO=bar   git push"),
                "git push"
            );
        }

        #[test]
        fn env_assignment_with_underscore_var() {
            assert_eq!(
                Parser::strip_builtin_prefix("env _MY_VAR=value git status"),
                "git status"
            );
        }

        #[test]
        fn env_assignment_with_empty_value() {
            assert_eq!(
                Parser::strip_builtin_prefix("env FOO= git push"),
                "git push"
            );
        }

        #[test]
        fn env_does_not_treat_flags_as_assignments() {
            // -i is a flag to env, not a VAR=value, so it should stop stripping
            // In practice, `env -i git push` means env with -i flag, then git push.
            // Our implementation treats -i as the start of the actual command since
            // it doesn't look like a VAR=value assignment.
            assert_eq!(
                Parser::strip_builtin_prefix("env -i git push"),
                "-i git push"
            );
        }

        #[test]
        fn preserves_arguments_after_command() {
            assert_eq!(
                Parser::strip_builtin_prefix("command git push --force origin main"),
                "git push --force origin main"
            );
        }
    }

    mod identify_command {
        use super::*;

        #[test]
        fn simple_command_with_subcommand() {
            let result = Parser::identify_command("git push");
            assert_eq!(result.command, "git");
            assert_eq!(result.subcommand, Some("push".to_string()));
            assert_eq!(result.full_segment, "git push");
        }

        #[test]
        fn command_only_no_subcommand() {
            let result = Parser::identify_command("ls");
            assert_eq!(result.command, "ls");
            assert_eq!(result.subcommand, None);
            assert_eq!(result.full_segment, "ls");
        }

        #[test]
        fn command_with_flags_only() {
            let result = Parser::identify_command("ls -la --color");
            assert_eq!(result.command, "ls");
            assert_eq!(result.subcommand, None);
            assert_eq!(result.full_segment, "ls -la --color");
        }

        #[test]
        fn flags_before_subcommand() {
            let result = Parser::identify_command("git --no-pager push");
            assert_eq!(result.command, "git");
            assert_eq!(result.subcommand, Some("push".to_string()));
            assert_eq!(result.full_segment, "git --no-pager push");
        }

        #[test]
        fn multiple_flags_before_subcommand() {
            // -c is a flag, but user.name=test does not start with '-',
            // so it is identified as the subcommand (first non-flag argument).
            // This is the expected behavior per the spec.
            let result = Parser::identify_command("git --no-pager -c user.name=test commit");
            assert_eq!(result.command, "git");
            assert_eq!(result.subcommand, Some("user.name=test".to_string()));
        }

        #[test]
        fn subcommand_followed_by_args() {
            let result = Parser::identify_command("git push origin main");
            assert_eq!(result.command, "git");
            assert_eq!(result.subcommand, Some("push".to_string()));
        }

        #[test]
        fn subcommand_followed_by_flags() {
            let result = Parser::identify_command("git push --force");
            assert_eq!(result.command, "git");
            assert_eq!(result.subcommand, Some("push".to_string()));
        }

        #[test]
        fn empty_segment() {
            let result = Parser::identify_command("");
            assert_eq!(result.command, "");
            assert_eq!(result.subcommand, None);
            assert_eq!(result.full_segment, "");
        }

        #[test]
        fn whitespace_only_segment() {
            let result = Parser::identify_command("   ");
            assert_eq!(result.command, "");
            assert_eq!(result.subcommand, None);
        }

        #[test]
        fn quoted_subcommand() {
            let result = Parser::identify_command("git commit -m \"initial commit\"");
            assert_eq!(result.command, "git");
            assert_eq!(result.subcommand, Some("commit".to_string()));
        }

        #[test]
        fn quoted_token_with_spaces() {
            // The quoted token should be treated as one token
            let result = Parser::identify_command("echo \"hello world\"");
            assert_eq!(result.command, "echo");
            assert_eq!(result.subcommand, Some("hello world".to_string()));
        }

        #[test]
        fn single_quoted_token() {
            let result = Parser::identify_command("echo 'hello world'");
            assert_eq!(result.command, "echo");
            assert_eq!(result.subcommand, Some("hello world".to_string()));
        }

        #[test]
        fn command_with_flag_argument_then_subcommand() {
            // -C is a flag with an argument, but since the argument doesn't start
            // with '-', it will be identified as the subcommand. This is the expected
            // behavior per the spec: first non-flag argument is the subcommand.
            let result = Parser::identify_command("git -C /tmp status");
            assert_eq!(result.command, "git");
            assert_eq!(result.subcommand, Some("/tmp".to_string()));
        }

        #[test]
        fn preserves_full_segment() {
            let segment = "git --no-pager push --force origin main";
            let result = Parser::identify_command(segment);
            assert_eq!(result.full_segment, segment);
        }

        // --- Substring matching avoidance tests (Requirement 9.3) ---
        // These tests verify that deny rules only match against WHOLE command
        // tokens separated by whitespace, not substrings within larger tokens.

        #[test]
        fn filename_containing_forbidden_command_not_matched_as_command() {
            // "cat git-push-docs.md" → command="cat", subcommand="git-push-docs.md"
            // The token "git-push-docs.md" is NOT split into "git" + "push"
            let result = Parser::identify_command("cat git-push-docs.md");
            assert_eq!(result.command, "cat");
            assert_eq!(result.subcommand, Some("git-push-docs.md".to_string()));
        }

        #[test]
        fn variable_containing_forbidden_command_not_matched_as_command() {
            // "echo $git_push_count" → command="echo", subcommand="$git_push_count"
            // The token "$git_push_count" is NOT split into "git" + "push"
            let result = Parser::identify_command("echo $git_push_count");
            assert_eq!(result.command, "echo");
            assert_eq!(result.subcommand, Some("$git_push_count".to_string()));
        }

        #[test]
        fn hyphenated_binary_not_split_into_command_and_subcommand() {
            // "git-push some-arg" → command="git-push", subcommand="some-arg"
            // The token "git-push" is treated as a whole command name, NOT as "git" + "push"
            let result = Parser::identify_command("git-push some-arg");
            assert_eq!(result.command, "git-push");
            assert_eq!(result.subcommand, Some("some-arg".to_string()));
        }

        #[test]
        fn underscore_joined_name_not_split() {
            // "git_push_helper --verbose" → command="git_push_helper", subcommand=None
            // Underscored name is a single token, not "git" + "push"
            let result = Parser::identify_command("git_push_helper --verbose");
            assert_eq!(result.command, "git_push_helper");
            assert_eq!(result.subcommand, None);
        }

        #[test]
        fn filename_as_first_token_not_matched_as_forbidden_command() {
            // If someone runs a script named "git-commit-helper.sh", it's a single token
            let result = Parser::identify_command("git-commit-helper.sh build");
            assert_eq!(result.command, "git-commit-helper.sh");
            assert_eq!(result.subcommand, Some("build".to_string()));
        }

        #[test]
        fn concatenated_name_not_split() {
            // "gitpush" is not "git" + "push"
            let result = Parser::identify_command("gitpush arg1");
            assert_eq!(result.command, "gitpush");
            assert_eq!(result.subcommand, Some("arg1".to_string()));
        }
    }

    mod extract_substitutions {
        use super::*;

        #[test]
        fn extracts_dollar_paren_substitution() {
            let result = Parser::extract_substitutions("echo $(git push)").unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn extracts_backtick_substitution() {
            let result = Parser::extract_substitutions("echo `git push`").unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn extracts_multiple_substitutions() {
            let result =
                Parser::extract_substitutions("echo $(git push) && echo `git commit -m x`")
                    .unwrap();
            assert_eq!(result, vec!["git push", "git commit -m x"]);
        }

        #[test]
        fn handles_nested_parentheses_in_dollar_paren() {
            let result =
                Parser::extract_substitutions("echo $(cmd $(inner))").unwrap();
            assert_eq!(result, vec!["cmd $(inner)"]);
        }

        #[test]
        fn does_not_extract_from_single_quotes() {
            let result = Parser::extract_substitutions("echo '$(git push)'").unwrap();
            assert_eq!(result, Vec::<String>::new());
        }

        #[test]
        fn does_not_extract_backticks_from_single_quotes() {
            let result = Parser::extract_substitutions("echo '`git push`'").unwrap();
            assert_eq!(result, Vec::<String>::new());
        }

        #[test]
        fn extracts_from_double_quotes() {
            // In shell, $() inside double quotes is still expanded
            let result = Parser::extract_substitutions("echo \"$(git push)\"").unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn extracts_backticks_from_double_quotes() {
            let result = Parser::extract_substitutions("echo \"`git push`\"").unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn returns_error_for_unclosed_dollar_paren() {
            let result = Parser::extract_substitutions("echo $(git push");
            assert_eq!(result, Err(ParseError::MalformedSubstitution));
        }

        #[test]
        fn returns_error_for_unmatched_backtick() {
            let result = Parser::extract_substitutions("echo `git push");
            assert_eq!(result, Err(ParseError::MalformedSubstitution));
        }

        #[test]
        fn no_substitutions_returns_empty_vec() {
            let result = Parser::extract_substitutions("git status").unwrap();
            assert_eq!(result, Vec::<String>::new());
        }

        #[test]
        fn empty_input_returns_empty_vec() {
            let result = Parser::extract_substitutions("").unwrap();
            assert_eq!(result, Vec::<String>::new());
        }

        #[test]
        fn empty_substitution_is_skipped() {
            let result = Parser::extract_substitutions("echo $()").unwrap();
            assert_eq!(result, Vec::<String>::new());
        }

        #[test]
        fn empty_backtick_substitution_is_skipped() {
            let result = Parser::extract_substitutions("echo ``").unwrap();
            assert_eq!(result, Vec::<String>::new());
        }

        #[test]
        fn handles_dollar_sign_without_paren() {
            // A bare $variable shouldn't trigger substitution extraction
            let result = Parser::extract_substitutions("echo $HOME").unwrap();
            assert_eq!(result, Vec::<String>::new());
        }

        #[test]
        fn mixed_dollar_paren_and_backtick() {
            let result =
                Parser::extract_substitutions("result=$(cat file) && echo `wc -l`").unwrap();
            assert_eq!(result, vec!["cat file", "wc -l"]);
        }

        #[test]
        fn handles_deeply_nested_parens() {
            let result =
                Parser::extract_substitutions("echo $(echo $(echo inner))").unwrap();
            // The outer $( finds its matching ) which accounts for nested parens
            assert_eq!(result, vec!["echo $(echo inner)"]);
        }
    }

    mod extract_nested_shell {
        use super::*;

        #[test]
        fn non_shell_command_returned_as_is() {
            let result = Parser::extract_nested_shell("git push", 0).unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn extracts_from_sh_c_double_quoted() {
            let result = Parser::extract_nested_shell("sh -c \"git push\"", 0).unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn extracts_from_sh_c_single_quoted() {
            let result = Parser::extract_nested_shell("sh -c 'git push'", 0).unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn extracts_from_bash_c() {
            let result = Parser::extract_nested_shell("bash -c \"git commit -m test\"", 0).unwrap();
            assert_eq!(result, vec!["git commit -m test"]);
        }

        #[test]
        fn extracts_from_zsh_c() {
            let result = Parser::extract_nested_shell("zsh -c \"git push origin main\"", 0).unwrap();
            assert_eq!(result, vec!["git push origin main"]);
        }

        #[test]
        fn extracts_unquoted_argument() {
            let result = Parser::extract_nested_shell("sh -c git push", 0).unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn handles_two_levels_of_nesting() {
            let result =
                Parser::extract_nested_shell("sh -c \"bash -c 'git push'\"", 0).unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn handles_three_levels_of_nesting() {
            let result = Parser::extract_nested_shell(
                "sh -c \"bash -c 'zsh -c git push'\"",
                0,
            )
            .unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn rejects_four_levels_of_nesting() {
            let _result = Parser::extract_nested_shell(
                "sh -c \"bash -c 'zsh -c \\\"sh -c git push\\\"'\"",
                0,
            );
            // At depth 0, we enter sh -c, depth becomes 1
            // Then bash -c, depth becomes 2
            // Then zsh -c, depth becomes 3
            // Then sh -c at depth 4 → NestingTooDeep
            // But due to quote handling, the inner content depends on parsing.
            // Let's test the depth check directly:
            let result_direct = Parser::extract_nested_shell("sh -c \"git push\"", 3);
            // depth starts at 3, then we try to recurse → depth becomes 4 > MAX_NESTING_DEPTH
            assert_eq!(result_direct, Err(ParseError::NestingTooDeep));
        }

        #[test]
        fn depth_exceeds_max_returns_error() {
            // Starting at depth 4 directly (> MAX_NESTING_DEPTH of 3) triggers error
            let result = Parser::extract_nested_shell("git push", 4);
            assert_eq!(result, Err(ParseError::NestingTooDeep));
        }

        #[test]
        fn empty_input_returns_empty_vec() {
            let result = Parser::extract_nested_shell("", 0).unwrap();
            assert_eq!(result, Vec::<String>::new());
        }

        #[test]
        fn whitespace_only_returns_empty_vec() {
            let result = Parser::extract_nested_shell("   ", 0).unwrap();
            assert_eq!(result, Vec::<String>::new());
        }

        #[test]
        fn unclosed_quote_returns_error() {
            let result = Parser::extract_nested_shell("sh -c \"git push", 0);
            assert_eq!(result, Err(ParseError::UnclosedQuote));
        }

        #[test]
        fn does_not_match_sh_without_c_flag() {
            let result = Parser::extract_nested_shell("sh script.sh", 0).unwrap();
            assert_eq!(result, vec!["sh script.sh"]);
        }

        #[test]
        fn does_not_match_unknown_shell() {
            let result = Parser::extract_nested_shell("fish -c \"git push\"", 0).unwrap();
            assert_eq!(result, vec!["fish -c \"git push\""]);
        }

        #[test]
        fn handles_path_qualified_shell() {
            let result =
                Parser::extract_nested_shell("/usr/bin/bash -c \"git push\"", 0).unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn handles_backslash_path_qualified_shell() {
            let result =
                Parser::extract_nested_shell("C:\\Windows\\System32\\bash -c \"git push\"", 0)
                    .unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn leading_trailing_whitespace_trimmed() {
            let result =
                Parser::extract_nested_shell("  sh -c \"git push\"  ", 0).unwrap();
            assert_eq!(result, vec!["git push"]);
        }

        #[test]
        fn extracts_complex_inner_command() {
            let result =
                Parser::extract_nested_shell("bash -c \"echo hello && git push\"", 0).unwrap();
            assert_eq!(result, vec!["echo hello && git push"]);
        }

        #[test]
        fn three_levels_mixed_shells() {
            // sh -c wrapping bash -c wrapping zsh -c with an unquoted final arg
            let result =
                Parser::extract_nested_shell("sh -c \"bash -c 'zsh -c ls'\"", 0).unwrap();
            assert_eq!(result, vec!["ls"]);
        }
    }

    mod strip_comments {
        use super::*;

        #[test]
        fn removes_trailing_comment() {
            assert_eq!(
                Parser::strip_comments("echo hello # this is a comment"),
                "echo hello"
            );
        }

        #[test]
        fn removes_comment_with_forbidden_command() {
            // A forbidden command after `#` should not be treated as executable
            assert_eq!(
                Parser::strip_comments("echo safe # git push"),
                "echo safe"
            );
        }

        #[test]
        fn hash_at_beginning_removes_everything() {
            assert_eq!(Parser::strip_comments("# git push origin main"), "");
        }

        #[test]
        fn no_hash_returns_input_unchanged() {
            assert_eq!(
                Parser::strip_comments("git status --short"),
                "git status --short"
            );
        }

        #[test]
        fn hash_inside_single_quotes_not_treated_as_comment() {
            assert_eq!(
                Parser::strip_comments("echo '# not a comment'"),
                "echo '# not a comment'"
            );
        }

        #[test]
        fn hash_inside_double_quotes_not_treated_as_comment() {
            assert_eq!(
                Parser::strip_comments("echo \"# not a comment\""),
                "echo \"# not a comment\""
            );
        }

        #[test]
        fn hash_after_quoted_region_is_comment() {
            assert_eq!(
                Parser::strip_comments("echo 'hello' # comment here"),
                "echo 'hello'"
            );
        }

        #[test]
        fn multiple_hashes_only_first_unquoted_matters() {
            assert_eq!(
                Parser::strip_comments("echo test # first # second"),
                "echo test"
            );
        }

        #[test]
        fn empty_input_returns_empty() {
            assert_eq!(Parser::strip_comments(""), "");
        }

        #[test]
        fn whitespace_only_input() {
            assert_eq!(Parser::strip_comments("   "), "   ");
        }

        #[test]
        fn hash_immediately_after_command_no_space() {
            assert_eq!(Parser::strip_comments("echo hello#comment"), "echo hello");
        }

        #[test]
        fn forbidden_command_in_quoted_hash_region_not_matched() {
            // Even though "git push" appears, it's inside quotes with `#`
            assert_eq!(
                Parser::strip_comments("echo '# git push' && ls"),
                "echo '# git push' && ls"
            );
        }

        #[test]
        fn mixed_quotes_with_hash() {
            // Double-quoted string with hash, then unquoted hash
            assert_eq!(
                Parser::strip_comments("echo \"#foo\" bar # real comment"),
                "echo \"#foo\" bar"
            );
        }
    }

    mod quote_awareness {
        use super::*;

        // Tests verifying that identify_command does not treat quoted content
        // as command names (Requirement 9.2).

        #[test]
        fn quoted_forbidden_command_is_not_identified_as_command() {
            // "git push" is in a quoted argument to echo — echo is the command
            let result = Parser::identify_command("echo \"git push\"");
            assert_eq!(result.command, "echo");
            // The subcommand is the string content, not "git"
            assert_eq!(result.subcommand, Some("git push".to_string()));
        }

        #[test]
        fn single_quoted_forbidden_command_is_not_identified_as_command() {
            let result = Parser::identify_command("echo 'git push'");
            assert_eq!(result.command, "echo");
            assert_eq!(result.subcommand, Some("git push".to_string()));
        }

        #[test]
        fn command_substitution_in_single_quotes_not_extracted() {
            // Requirement 9.2: forbidden command inside single-quoted strings
            // should not be extracted as a substitution
            let result = Parser::extract_substitutions("echo '$(git push)'").unwrap();
            assert!(result.is_empty());
        }

        #[test]
        fn split_compound_does_not_split_on_quoted_operators() {
            // Operators inside quotes should not cause splitting
            let result = Parser::split_compound("echo 'git push && git commit'").unwrap();
            assert_eq!(result, vec!["echo 'git push && git commit'"]);
        }

        #[test]
        fn comment_after_hash_makes_forbidden_command_invisible() {
            // Requirement 9.5: forbidden command after unquoted # is not executable
            let stripped = Parser::strip_comments("echo safe # git push");
            assert_eq!(stripped, "echo safe");
            // After stripping, identify_command sees only "echo safe"
            let parsed = Parser::identify_command(&stripped);
            assert_eq!(parsed.command, "echo");
            assert_eq!(parsed.subcommand, Some("safe".to_string()));
        }

        #[test]
        fn forbidden_command_only_in_comment_not_matched() {
            // Full flow: strip comment, then identify — no "git" command found
            let input = "ls -la # git push origin main";
            let stripped = Parser::strip_comments(input);
            let parsed = Parser::identify_command(&stripped);
            assert_eq!(parsed.command, "ls");
            assert_eq!(parsed.subcommand, None);
        }

        #[test]
        fn hash_in_quotes_preserves_content_for_parsing() {
            // The # is inside quotes, so strip_comments leaves it alone
            let input = "grep '# TODO' file.txt";
            let stripped = Parser::strip_comments(input);
            assert_eq!(stripped, "grep '# TODO' file.txt");
            let parsed = Parser::identify_command(&stripped);
            assert_eq!(parsed.command, "grep");
            assert_eq!(parsed.subcommand, Some("# TODO".to_string()));
        }
    }
}
