// Mr. Nope - Policy Engine module
// Loads YAML policy files and matches commands against deny rules.

use crate::normalizer::Normalizer;
use crate::self_protection;
use crate::parser::{ParsedCommand, Parser};
use serde::Deserialize;
use std::fmt;
use std::path::Path;

/// Represents the decision made by the policy engine.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow,
    Deny {
        rule: DenyRule,
        matched_subcommand: String,
    },
}

/// A single deny rule from the policy file.
#[derive(Debug, Clone, PartialEq)]
pub struct DenyRule {
    pub command: String,
    pub subcommands: Vec<String>,
}

/// The result of evaluating a command against the policy.
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluationResult {
    pub decision: Decision,
    pub raw_input: String,
    pub normalized: String,
    pub parsed_commands: Vec<ParsedCommand>,
}

/// Trait for evaluating commands against a policy.
pub trait PolicyEvaluator {
    fn evaluate(&self, raw_command: &str) -> EvaluationResult;
}

/// Errors that can occur during policy loading or evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyError {
    /// The policy file could not be parsed as valid YAML.
    InvalidYaml(String),
    /// The policy file is missing the required `rules` array.
    MissingRulesArray,
    /// A deny rule is missing the required `command` field.
    MissingCommand,
    /// A deny rule has an empty or whitespace-only `command` field.
    EmptyCommand,
    /// A deny rule's `command` field exceeds the maximum length of 128 characters.
    CommandTooLong,
    /// A deny rule is missing the required `subcommands` field.
    MissingSubcommands,
    /// A deny rule has an empty `subcommands` array.
    EmptySubcommands,
    /// A deny rule has a whitespace-only entry in the `subcommands` array.
    WhitespaceOnlySubcommand,
    /// A deny rule has a `subcommands` entry exceeding 128 characters.
    SubcommandTooLong,
    /// The policy file could not be read.
    IoError(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::InvalidYaml(msg) => write!(f, "invalid YAML: {}", msg),
            PolicyError::MissingRulesArray => write!(f, "missing 'rules' array"),
            PolicyError::MissingCommand => write!(f, "deny rule missing 'command' field"),
            PolicyError::EmptyCommand => {
                write!(f, "deny rule has empty or whitespace-only 'command'")
            }
            PolicyError::CommandTooLong => write!(f, "deny rule 'command' exceeds 128 characters"),
            PolicyError::MissingSubcommands => {
                write!(f, "deny rule missing 'subcommands' field")
            }
            PolicyError::EmptySubcommands => write!(f, "deny rule has empty 'subcommands' array"),
            PolicyError::WhitespaceOnlySubcommand => {
                write!(f, "deny rule has whitespace-only entry in 'subcommands'")
            }
            PolicyError::SubcommandTooLong => {
                write!(f, "deny rule 'subcommands' entry exceeds 128 characters")
            }
            PolicyError::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for PolicyError {}

// --- Policy Mode ---

/// Defines how a project-level policy interacts with the global/default policy.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyMode {
    /// Project policy completely replaces global/default (default behavior).
    Replace,
    /// Project policy extends the global policy.
    /// If the same command appears in both, the project's subcommands replace the global's for that command.
    /// Commands only in global remain. Commands only in project are added.
    Extend,
}

impl Default for PolicyMode {
    fn default() -> Self {
        PolicyMode::Replace
    }
}

// --- Serde deserialization structs for YAML policy file ---

/// Top-level YAML schema for the policy file.
#[derive(Debug, Deserialize)]
struct PolicyFileSchema {
    mode: Option<String>,
    rules: Option<Vec<RuleEntrySchema>>,
}

/// A single rule entry in the `rules` array.
#[derive(Debug, Deserialize)]
struct RuleEntrySchema {
    deny: Option<DenyRuleSchema>,
}

/// The `deny` object within a rule entry.
#[derive(Debug, Deserialize)]
struct DenyRuleSchema {
    command: Option<String>,
    subcommands: Option<Vec<String>>,
}

// --- PolicyEngine ---

/// The built-in default policy YAML that denies critical git operations.
pub const DEFAULT_POLICY_YAML: &str = r#"rules:
  - deny:
      command: "git"
      subcommands:
        - "commit"
        - "push"
        - "merge"
        - "rebase"
        - "reset"
        - "cherry-pick"
        - "revert"
        - "tag"
"#;

/// The policy engine that holds loaded deny rules and evaluates commands.
#[derive(Debug)]
pub struct PolicyEngine {
    pub rules: Vec<DenyRule>,
    pub is_default: bool,
    pub mode: PolicyMode,
}

impl PolicyEngine {
    /// Returns a `PolicyEngine` loaded with the built-in default policy.
    ///
    /// The default policy denies `git commit` and `git push`.
    pub fn default_policy() -> Self {
        // The default policy YAML is known-valid, so unwrap is safe here.
        Self::load_from_str(DEFAULT_POLICY_YAML, true)
            .expect("built-in default policy YAML must be valid")
    }

    /// Load a policy from a YAML file path.
    ///
    /// - If `path` is `None`, loads the built-in default policy with `is_default = true`.
    /// - If `path` is `Some` but the file does not exist, loads the built-in default policy with `is_default = true`.
    /// - If `path` is `Some` and the file exists, loads from file with `is_default = false`.
    pub fn load(path: Option<&Path>) -> Result<Self, PolicyError> {
        let path = match path {
            Some(p) => p,
            None => return Ok(Self::default_policy()),
        };

        if !path.exists() {
            return Ok(Self::default_policy());
        }

        let content =
            std::fs::read_to_string(path).map_err(|e| PolicyError::IoError(e.to_string()))?;

        Self::load_from_str(&content, false)
    }

    /// Match a parsed command against deny rules.
    ///
    /// Returns `Decision::Deny` if the command name matches a rule's `command` field
    /// AND the parsed subcommand matches ANY entry in the rule's `subcommands` array
    /// (case-sensitive exact match). Otherwise returns `Decision::Allow`.
    ///
    /// If `cmd.subcommand` is `None`, the command cannot match any deny rule since
    /// deny rules require a subcommand match.
    pub fn match_command(&self, cmd: &ParsedCommand) -> Decision {
        // If there's no subcommand, we can't match any deny rule
        let subcommand = match &cmd.subcommand {
            Some(sub) => sub,
            None => return Decision::Allow,
        };

        for rule in &self.rules {
            // Case-sensitive exact match on command name
            if cmd.command == rule.command {
                // Check if the subcommand matches any entry in the rule's subcommands
                if rule.subcommands.iter().any(|s| s == subcommand) {
                    return Decision::Deny {
                        rule: rule.clone(),
                        matched_subcommand: subcommand.clone(),
                    };
                }
            }
        }

        Decision::Allow
    }

    /// Load a policy from a YAML string. Used internally by `load` and for testing.
    pub fn load_from_str(yaml_content: &str, is_default: bool) -> Result<Self, PolicyError> {
        let schema: PolicyFileSchema = serde_yaml::from_str(yaml_content)
            .map_err(|e| PolicyError::InvalidYaml(e.to_string()))?;

        // Parse the mode field (defaults to Replace if absent or unrecognized)
        let mode = match schema.mode.as_deref() {
            Some("extend") => PolicyMode::Extend,
            _ => PolicyMode::Replace,
        };

        let rules_entries = schema.rules.ok_or(PolicyError::MissingRulesArray)?;

        let mut rules = Vec::new();

        for entry in rules_entries {
            let deny = entry.deny.ok_or(PolicyError::MissingCommand)?;

            let command = deny.command.ok_or(PolicyError::MissingCommand)?;

            // Validate command is non-whitespace-only
            if command.trim().is_empty() {
                return Err(PolicyError::EmptyCommand);
            }

            // Validate command length (1–128 chars)
            if command.len() > 128 {
                return Err(PolicyError::CommandTooLong);
            }

            let subcommands = deny.subcommands.ok_or(PolicyError::MissingSubcommands)?;

            // Validate subcommands is non-empty
            if subcommands.is_empty() {
                return Err(PolicyError::EmptySubcommands);
            }

            // Validate each subcommand entry
            for subcmd in &subcommands {
                if subcmd.trim().is_empty() {
                    return Err(PolicyError::WhitespaceOnlySubcommand);
                }
                if subcmd.len() > 128 {
                    return Err(PolicyError::SubcommandTooLong);
                }
            }

            rules.push(DenyRule {
                command,
                subcommands,
            });
        }

        Ok(PolicyEngine {
            rules,
            is_default,
            mode,
        })
    }

    /// Merge a base policy with an extension policy.
    ///
    /// For each rule in extension:
    /// - If base has a rule with the same command, replace its subcommands with extension's.
    /// - If the command is new, add it to the result.
    /// Base rules not mentioned in extension stay as-is.
    ///
    /// The resulting engine has `is_default = false` and `mode = Replace` (merged result is final).
    pub fn merge(base: &PolicyEngine, extension: &PolicyEngine) -> PolicyEngine {
        let mut merged_rules: Vec<DenyRule> = Vec::new();

        // Start with base rules, replacing subcommands if extension has same command
        for base_rule in &base.rules {
            if let Some(ext_rule) = extension.rules.iter().find(|r| r.command == base_rule.command)
            {
                // Extension overrides the subcommands for this command
                merged_rules.push(DenyRule {
                    command: base_rule.command.clone(),
                    subcommands: ext_rule.subcommands.clone(),
                });
            } else {
                // Keep the base rule as-is
                merged_rules.push(base_rule.clone());
            }
        }

        // Add commands that only exist in extension (not in base)
        for ext_rule in &extension.rules {
            if !base.rules.iter().any(|r| r.command == ext_rule.command) {
                merged_rules.push(ext_rule.clone());
            }
        }

        PolicyEngine {
            rules: merged_rules,
            is_default: false,
            mode: PolicyMode::Replace,
        }
    }
}

impl PolicyEvaluator for PolicyEngine {
    /// Evaluate a raw command string against the policy.
    ///
    /// Pipeline: Normalize → strip comments → split compound → for each segment:
    ///   extract nested shell → strip builtin prefix → extract substitutions →
    ///   identify command → match against policy.
    ///
    /// Returns Allow immediately for empty/whitespace-only input.
    /// Returns Deny (fail-closed) if any parse error occurs.
    /// Returns Deny if ANY extracted command matches a deny rule.
    fn evaluate(&self, raw_command: &str) -> EvaluationResult {
        // 1. Empty or whitespace-only → Allow immediately
        if raw_command.trim().is_empty() {
            return EvaluationResult {
                decision: Decision::Allow,
                raw_input: raw_command.to_string(),
                normalized: String::new(),
                parsed_commands: vec![],
            };
        }

        // 2. Normalize the input
        let normalizer = Normalizer;
        let normalized_output = normalizer.normalize(raw_command);
        let normalized_text = normalized_output.text.clone();

        // If normalized result is empty after normalization, allow
        if normalized_text.trim().is_empty() {
            return EvaluationResult {
                decision: Decision::Allow,
                raw_input: raw_command.to_string(),
                normalized: normalized_text,
                parsed_commands: vec![],
            };
        }

        // 2.5 Self-protection: block any command that modifies Mr. Nope's own files
        if let Some(protected_pattern) = self_protection::check_self_protection(&normalized_text) {
            return EvaluationResult {
                decision: Decision::Deny {
                    rule: DenyRule {
                        command: "__self_protection__".to_string(),
                        subcommands: vec![self_protection::SELF_PROTECTION_REASON.to_string()],
                    },
                    matched_subcommand: format!(
                        "write to protected path '{}'",
                        protected_pattern
                    ),
                },
                raw_input: raw_command.to_string(),
                normalized: normalized_text,
                parsed_commands: vec![],
            };
        }

        // Also check the raw input (in case normalization stripped relevant info)
        if let Some(protected_pattern) = self_protection::check_self_protection(raw_command) {
            return EvaluationResult {
                decision: Decision::Deny {
                    rule: DenyRule {
                        command: "__self_protection__".to_string(),
                        subcommands: vec![self_protection::SELF_PROTECTION_REASON.to_string()],
                    },
                    matched_subcommand: format!(
                        "write to protected path '{}'",
                        protected_pattern
                    ),
                },
                raw_input: raw_command.to_string(),
                normalized: normalized_text,
                parsed_commands: vec![],
            };
        }

        // 3. Strip comments
        let comment_stripped = Parser::strip_comments(&normalized_text);

        // If nothing left after stripping comments, allow
        if comment_stripped.trim().is_empty() {
            return EvaluationResult {
                decision: Decision::Allow,
                raw_input: raw_command.to_string(),
                normalized: normalized_text,
                parsed_commands: vec![],
            };
        }

        // 4. Split compound commands
        let segments = match Parser::split_compound(&comment_stripped) {
            Ok(segs) => segs,
            Err(_) => {
                // Parse error → fail-closed: deny with synthetic rule
                return EvaluationResult {
                    decision: Decision::Deny {
                        rule: DenyRule {
                            command: "__parse_error__".to_string(),
                            subcommands: vec!["command could not be parsed for policy evaluation"
                                .to_string()],
                        },
                        matched_subcommand: "command could not be parsed for policy evaluation"
                            .to_string(),
                    },
                    raw_input: raw_command.to_string(),
                    normalized: normalized_text,
                    parsed_commands: vec![],
                };
            }
        };

        let mut all_parsed_commands: Vec<ParsedCommand> = Vec::new();

        // 5. For each segment
        for segment in &segments {
            if segment.trim().is_empty() {
                continue;
            }

            // 5a. Extract nested shell (depth 0)
            let extracted_commands = match Parser::extract_nested_shell(segment, 0) {
                Ok(cmds) => cmds,
                Err(_) => {
                    // Parse error → fail-closed
                    return EvaluationResult {
                        decision: Decision::Deny {
                            rule: DenyRule {
                                command: "__parse_error__".to_string(),
                                subcommands: vec![
                                    "command could not be parsed for policy evaluation"
                                        .to_string(),
                                ],
                            },
                            matched_subcommand:
                                "command could not be parsed for policy evaluation".to_string(),
                        },
                        raw_input: raw_command.to_string(),
                        normalized: normalized_text,
                        parsed_commands: all_parsed_commands,
                    };
                }
            };

            // Collect all commands to evaluate for this segment
            let mut commands_to_evaluate: Vec<String> = Vec::new();

            for extracted in &extracted_commands {
                // 5b. Strip builtin prefix
                let stripped = Parser::strip_builtin_prefix(extracted);
                if !stripped.is_empty() {
                    commands_to_evaluate.push(stripped);
                }

                // 5c. Extract substitutions from the extracted command
                match Parser::extract_substitutions(extracted) {
                    Ok(subs) => {
                        for sub in subs {
                            let sub_stripped = Parser::strip_builtin_prefix(&sub);
                            if !sub_stripped.is_empty() {
                                commands_to_evaluate.push(sub_stripped);
                            }
                        }
                    }
                    Err(_) => {
                        // Parse error → fail-closed
                        return EvaluationResult {
                            decision: Decision::Deny {
                                rule: DenyRule {
                                    command: "__parse_error__".to_string(),
                                    subcommands: vec![
                                        "command could not be parsed for policy evaluation"
                                            .to_string(),
                                    ],
                                },
                                matched_subcommand:
                                    "command could not be parsed for policy evaluation".to_string(),
                            },
                            raw_input: raw_command.to_string(),
                            normalized: normalized_text,
                            parsed_commands: all_parsed_commands,
                        };
                    }
                }
            }

            // 5d. For each command: identify_command, then match against policy
            for cmd_str in &commands_to_evaluate {
                let parsed = Parser::identify_command(cmd_str);
                let decision = self.match_command(&parsed);

                all_parsed_commands.push(parsed);

                // 6. If ANY command matches DENY → return Deny
                if let Decision::Deny {
                    rule,
                    matched_subcommand,
                } = decision
                {
                    return EvaluationResult {
                        decision: Decision::Deny {
                            rule,
                            matched_subcommand,
                        },
                        raw_input: raw_command.to_string(),
                        normalized: normalized_text,
                        parsed_commands: all_parsed_commands,
                    };
                }
            }
        }

        // 8. All commands allowed
        EvaluationResult {
            decision: Decision::Allow,
            raw_input: raw_command.to_string(),
            normalized: normalized_text,
            parsed_commands: all_parsed_commands,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ParsedCommand;

    #[test]
    fn test_default_policy_yaml_is_valid() {
        let engine = PolicyEngine::default_policy();
        assert_eq!(engine.rules.len(), 1);
        assert_eq!(engine.rules[0].command, "git");
        assert_eq!(engine.rules[0].subcommands, vec!["commit", "push", "merge", "rebase", "reset", "cherry-pick", "revert", "tag"]);
        assert!(engine.is_default);
    }

    #[test]
    fn test_load_none_returns_default_policy() {
        let engine = PolicyEngine::load(None).unwrap();
        assert_eq!(engine.rules.len(), 1);
        assert_eq!(engine.rules[0].command, "git");
        assert_eq!(engine.rules[0].subcommands, vec!["commit", "push", "merge", "rebase", "reset", "cherry-pick", "revert", "tag"]);
        assert!(engine.is_default);
    }

    #[test]
    fn test_load_nonexistent_path_returns_default_policy() {
        let engine =
            PolicyEngine::load(Some(Path::new("/does/not/exist/.mr-nope.yml"))).unwrap();
        assert_eq!(engine.rules.len(), 1);
        assert_eq!(engine.rules[0].command, "git");
        assert!(engine.is_default);
    }

    #[test]
    fn test_load_existing_file_sets_is_default_false() {
        use std::io::Write;
        let yaml = r#"rules:
  - deny:
      command: "rm"
      subcommands:
        - "-rf"
"#;
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        write!(temp, "{}", yaml).unwrap();

        let engine = PolicyEngine::load(Some(temp.path())).unwrap();
        assert_eq!(engine.rules[0].command, "rm");
        assert!(!engine.is_default);
    }

    // --- match_command tests ---

    #[test]
    fn test_match_command_denies_matching_command_and_subcommand() {
        let engine = PolicyEngine::default_policy();
        let cmd = ParsedCommand {
            command: "git".to_string(),
            subcommand: Some("push".to_string()),
            full_segment: "git push".to_string(),
        };
        let decision = engine.match_command(&cmd);
        assert_eq!(
            decision,
            Decision::Deny {
                rule: DenyRule {
                    command: "git".to_string(),
                    subcommands: vec!["commit".to_string(), "push".to_string(), "merge".to_string(), "rebase".to_string(), "reset".to_string(), "cherry-pick".to_string(), "revert".to_string(), "tag".to_string()],
                },
                matched_subcommand: "push".to_string(),
            }
        );
    }

    #[test]
    fn test_match_command_denies_git_commit() {
        let engine = PolicyEngine::default_policy();
        let cmd = ParsedCommand {
            command: "git".to_string(),
            subcommand: Some("commit".to_string()),
            full_segment: "git commit".to_string(),
        };
        let decision = engine.match_command(&cmd);
        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_match_command_allows_non_matching_subcommand() {
        let engine = PolicyEngine::default_policy();
        let cmd = ParsedCommand {
            command: "git".to_string(),
            subcommand: Some("status".to_string()),
            full_segment: "git status".to_string(),
        };
        let decision = engine.match_command(&cmd);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_match_command_allows_non_matching_command() {
        let engine = PolicyEngine::default_policy();
        let cmd = ParsedCommand {
            command: "ls".to_string(),
            subcommand: Some("push".to_string()),
            full_segment: "ls push".to_string(),
        };
        let decision = engine.match_command(&cmd);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_match_command_allows_when_no_subcommand() {
        let engine = PolicyEngine::default_policy();
        let cmd = ParsedCommand {
            command: "git".to_string(),
            subcommand: None,
            full_segment: "git".to_string(),
        };
        let decision = engine.match_command(&cmd);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_match_command_case_sensitive_command() {
        let engine = PolicyEngine::default_policy();
        // "Git" (uppercase G) should NOT match "git"
        let cmd = ParsedCommand {
            command: "Git".to_string(),
            subcommand: Some("push".to_string()),
            full_segment: "Git push".to_string(),
        };
        let decision = engine.match_command(&cmd);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_match_command_case_sensitive_subcommand() {
        let engine = PolicyEngine::default_policy();
        // "Push" (uppercase P) should NOT match "push"
        let cmd = ParsedCommand {
            command: "git".to_string(),
            subcommand: Some("Push".to_string()),
            full_segment: "git Push".to_string(),
        };
        let decision = engine.match_command(&cmd);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_match_command_multiple_rules() {
        let engine = PolicyEngine {
            rules: vec![
                DenyRule {
                    command: "git".to_string(),
                    subcommands: vec!["commit".to_string(), "push".to_string()],
                },
                DenyRule {
                    command: "rm".to_string(),
                    subcommands: vec!["-rf".to_string()],
                },
            ],
            is_default: false,
            mode: PolicyMode::Replace,
        };

        // rm -rf should be denied by second rule
        let cmd = ParsedCommand {
            command: "rm".to_string(),
            subcommand: Some("-rf".to_string()),
            full_segment: "rm -rf".to_string(),
        };
        let decision = engine.match_command(&cmd);
        assert_eq!(
            decision,
            Decision::Deny {
                rule: DenyRule {
                    command: "rm".to_string(),
                    subcommands: vec!["-rf".to_string()],
                },
                matched_subcommand: "-rf".to_string(),
            }
        );
    }

    #[test]
    fn test_match_command_empty_rules_allows_all() {
        let engine = PolicyEngine {
            rules: vec![],
            is_default: false,
            mode: PolicyMode::Replace,
        };
        let cmd = ParsedCommand {
            command: "git".to_string(),
            subcommand: Some("push".to_string()),
            full_segment: "git push".to_string(),
        };
        let decision = engine.match_command(&cmd);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_match_command_first_matching_rule_wins() {
        let engine = PolicyEngine {
            rules: vec![
                DenyRule {
                    command: "git".to_string(),
                    subcommands: vec!["push".to_string()],
                },
                DenyRule {
                    command: "git".to_string(),
                    subcommands: vec!["push".to_string(), "commit".to_string()],
                },
            ],
            is_default: false,
            mode: PolicyMode::Replace,
        };

        let cmd = ParsedCommand {
            command: "git".to_string(),
            subcommand: Some("push".to_string()),
            full_segment: "git push".to_string(),
        };
        let decision = engine.match_command(&cmd);
        // Should match first rule (only "push" in subcommands)
        assert_eq!(
            decision,
            Decision::Deny {
                rule: DenyRule {
                    command: "git".to_string(),
                    subcommands: vec!["push".to_string()],
                },
                matched_subcommand: "push".to_string(),
            }
        );
    }

    // --- evaluate (PolicyEvaluator) tests ---

    #[test]
    fn test_evaluate_empty_string_allows() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("");
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.raw_input, "");
        assert!(result.parsed_commands.is_empty());
    }

    #[test]
    fn test_evaluate_whitespace_only_allows() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("   \t\t   ");
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.raw_input, "   \t\t   ");
        assert!(result.parsed_commands.is_empty());
    }

    #[test]
    fn test_evaluate_simple_allowed_command() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("git status");
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.raw_input, "git status");
        assert_eq!(result.normalized, "git status");
        assert!(!result.parsed_commands.is_empty());
        assert_eq!(result.parsed_commands[0].command, "git");
        assert_eq!(result.parsed_commands[0].subcommand, Some("status".to_string()));
    }

    #[test]
    fn test_evaluate_simple_denied_command() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("git push");
        assert!(matches!(result.decision, Decision::Deny { .. }));
        assert_eq!(result.raw_input, "git push");
        assert_eq!(result.normalized, "git push");
    }

    #[test]
    fn test_evaluate_denied_git_commit() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("git commit -m \"hello\"");
        assert!(matches!(result.decision, Decision::Deny { .. }));
        if let Decision::Deny { rule, .. } = &result.decision {
            assert_eq!(rule.command, "git");
            assert!(rule.subcommands.contains(&"commit".to_string()));
        }
    }

    #[test]
    fn test_evaluate_normalizes_url_encoded() {
        let engine = PolicyEngine::default_policy();
        // "git%20push" → after URL decode → "git push" → denied
        let result = engine.evaluate("git%20push");
        assert!(matches!(result.decision, Decision::Deny { .. }));
        assert_eq!(result.normalized, "git push");
    }

    #[test]
    fn test_evaluate_normalizes_path() {
        let engine = PolicyEngine::default_policy();
        // "/usr/bin/git push" → path extract → "git push" → denied
        let result = engine.evaluate("/usr/bin/git push");
        assert!(matches!(result.decision, Decision::Deny { .. }));
        assert_eq!(result.normalized, "git push");
    }

    #[test]
    fn test_evaluate_compound_command_any_deny() {
        let engine = PolicyEngine::default_policy();
        // "echo hello && git push" → split → "echo hello" (allow), "git push" (deny)
        let result = engine.evaluate("echo hello && git push");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_compound_all_allowed() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("echo hello && git status");
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_pipe_any_deny() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("echo test | git push");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_nested_shell_denied() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("sh -c \"git push\"");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_builtin_prefix_stripped() {
        let engine = PolicyEngine::default_policy();
        // "command git push" → strip prefix → "git push" → denied
        let result = engine.evaluate("command git push");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_env_prefix_stripped() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("env FOO=bar git push");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_substitution_denied() {
        let engine = PolicyEngine::default_policy();
        // "echo $(git push)" → extract substitution "git push" → denied
        let result = engine.evaluate("echo $(git push)");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_backtick_substitution_denied() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("echo `git push`");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_comment_stripped_allows() {
        let engine = PolicyEngine::default_policy();
        // "echo hello # git push" → strip comment → "echo hello" → allowed
        let result = engine.evaluate("echo hello # git push");
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_parse_error_unclosed_quote_denies() {
        let engine = PolicyEngine::default_policy();
        // Unclosed quote triggers parse error → fail-closed deny
        let result = engine.evaluate("echo \"unclosed");
        assert!(matches!(result.decision, Decision::Deny { .. }));
        if let Decision::Deny { rule, .. } = &result.decision {
            assert_eq!(rule.command, "__parse_error__");
        }
    }

    #[test]
    fn test_evaluate_returns_raw_input_unchanged() {
        let engine = PolicyEngine::default_policy();
        let raw = "  git   status  ";
        let result = engine.evaluate(raw);
        assert_eq!(result.raw_input, raw);
    }

    #[test]
    fn test_evaluate_returns_normalized_form() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("  git   status  ");
        assert_eq!(result.normalized, "git status");
    }

    #[test]
    fn test_evaluate_deterministic() {
        let engine = PolicyEngine::default_policy();
        let result1 = engine.evaluate("git push");
        let result2 = engine.evaluate("git push");
        assert_eq!(result1.decision, result2.decision);
        assert_eq!(result1.normalized, result2.normalized);
    }

    #[test]
    fn test_evaluate_double_encoded_url() {
        let engine = PolicyEngine::default_policy();
        // "git%2520push" → pass1: "git%20push" → pass2: "git push" → denied
        let result = engine.evaluate("git%2520push");
        assert!(matches!(result.decision, Decision::Deny { .. }));
        assert_eq!(result.normalized, "git push");
    }

    #[test]
    fn test_evaluate_quoted_forbidden_not_denied() {
        let engine = PolicyEngine::default_policy();
        // 'echo "git push"' — "git push" is in quotes, not a substitution context
        let result = engine.evaluate("echo \"git push\"");
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_semicolons_deny() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("ls; git push");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_or_operator_deny() {
        let engine = PolicyEngine::default_policy();
        let result = engine.evaluate("false || git commit -m test");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }

    #[test]
    fn test_evaluate_allowed_git_operations() {
        let engine = PolicyEngine::default_policy();
        for cmd in &["git status", "git diff", "git log", "git branch", "git fetch"] {
            let result = engine.evaluate(cmd);
            assert_eq!(result.decision, Decision::Allow, "Expected ALLOW for: {}", cmd);
        }
    }

    // --- PolicyMode and Merge tests ---

    #[test]
    fn test_load_from_str_default_mode_is_replace() {
        let yaml = r#"rules:
  - deny:
      command: "git"
      subcommands:
        - "push"
"#;
        let engine = PolicyEngine::load_from_str(yaml, false).unwrap();
        assert_eq!(engine.mode, PolicyMode::Replace);
    }

    #[test]
    fn test_load_from_str_explicit_replace_mode() {
        let yaml = r#"mode: replace
rules:
  - deny:
      command: "git"
      subcommands:
        - "push"
"#;
        let engine = PolicyEngine::load_from_str(yaml, false).unwrap();
        assert_eq!(engine.mode, PolicyMode::Replace);
    }

    #[test]
    fn test_load_from_str_extend_mode() {
        let yaml = r#"mode: extend
rules:
  - deny:
      command: "git"
      subcommands:
        - "push"
"#;
        let engine = PolicyEngine::load_from_str(yaml, false).unwrap();
        assert_eq!(engine.mode, PolicyMode::Extend);
    }

    #[test]
    fn test_load_from_str_unknown_mode_defaults_to_replace() {
        let yaml = r#"mode: unknown_value
rules:
  - deny:
      command: "git"
      subcommands:
        - "push"
"#;
        let engine = PolicyEngine::load_from_str(yaml, false).unwrap();
        assert_eq!(engine.mode, PolicyMode::Replace);
    }

    #[test]
    fn test_merge_adds_new_commands_from_extension() {
        let base = PolicyEngine {
            rules: vec![DenyRule {
                command: "git".to_string(),
                subcommands: vec!["push".to_string(), "commit".to_string()],
            }],
            is_default: true,
            mode: PolicyMode::Replace,
        };

        let extension = PolicyEngine {
            rules: vec![DenyRule {
                command: "docker".to_string(),
                subcommands: vec!["push".to_string()],
            }],
            is_default: false,
            mode: PolicyMode::Extend,
        };

        let merged = PolicyEngine::merge(&base, &extension);
        assert_eq!(merged.rules.len(), 2);
        assert_eq!(merged.rules[0].command, "git");
        assert_eq!(merged.rules[0].subcommands, vec!["push", "commit"]);
        assert_eq!(merged.rules[1].command, "docker");
        assert_eq!(merged.rules[1].subcommands, vec!["push"]);
        assert!(!merged.is_default);
    }

    #[test]
    fn test_merge_replaces_subcommands_for_same_command() {
        let base = PolicyEngine {
            rules: vec![DenyRule {
                command: "git".to_string(),
                subcommands: vec!["push".to_string(), "commit".to_string(), "merge".to_string()],
            }],
            is_default: true,
            mode: PolicyMode::Replace,
        };

        let extension = PolicyEngine {
            rules: vec![DenyRule {
                command: "git".to_string(),
                subcommands: vec!["push".to_string(), "rebase".to_string()],
            }],
            is_default: false,
            mode: PolicyMode::Extend,
        };

        let merged = PolicyEngine::merge(&base, &extension);
        assert_eq!(merged.rules.len(), 1);
        assert_eq!(merged.rules[0].command, "git");
        // Extension's subcommands replace base's for the same command
        assert_eq!(merged.rules[0].subcommands, vec!["push", "rebase"]);
    }

    #[test]
    fn test_merge_preserves_base_rules_not_in_extension() {
        let base = PolicyEngine {
            rules: vec![
                DenyRule {
                    command: "git".to_string(),
                    subcommands: vec!["push".to_string()],
                },
                DenyRule {
                    command: "rm".to_string(),
                    subcommands: vec!["-rf".to_string()],
                },
            ],
            is_default: true,
            mode: PolicyMode::Replace,
        };

        let extension = PolicyEngine {
            rules: vec![DenyRule {
                command: "docker".to_string(),
                subcommands: vec!["push".to_string()],
            }],
            is_default: false,
            mode: PolicyMode::Extend,
        };

        let merged = PolicyEngine::merge(&base, &extension);
        assert_eq!(merged.rules.len(), 3);
        assert_eq!(merged.rules[0].command, "git");
        assert_eq!(merged.rules[0].subcommands, vec!["push"]);
        assert_eq!(merged.rules[1].command, "rm");
        assert_eq!(merged.rules[1].subcommands, vec!["-rf"]);
        assert_eq!(merged.rules[2].command, "docker");
        assert_eq!(merged.rules[2].subcommands, vec!["push"]);
    }

    #[test]
    fn test_merge_combined_replace_and_add() {
        let base = PolicyEngine {
            rules: vec![
                DenyRule {
                    command: "git".to_string(),
                    subcommands: vec!["push".to_string(), "commit".to_string()],
                },
                DenyRule {
                    command: "rm".to_string(),
                    subcommands: vec!["-rf".to_string()],
                },
            ],
            is_default: true,
            mode: PolicyMode::Replace,
        };

        let extension = PolicyEngine {
            rules: vec![
                DenyRule {
                    command: "git".to_string(),
                    subcommands: vec!["push".to_string(), "merge".to_string()],
                },
                DenyRule {
                    command: "docker".to_string(),
                    subcommands: vec!["push".to_string()],
                },
            ],
            is_default: false,
            mode: PolicyMode::Extend,
        };

        let merged = PolicyEngine::merge(&base, &extension);
        assert_eq!(merged.rules.len(), 3);
        // git subcommands replaced by extension
        assert_eq!(merged.rules[0].command, "git");
        assert_eq!(merged.rules[0].subcommands, vec!["push", "merge"]);
        // rm stays from base
        assert_eq!(merged.rules[1].command, "rm");
        assert_eq!(merged.rules[1].subcommands, vec!["-rf"]);
        // docker added from extension
        assert_eq!(merged.rules[2].command, "docker");
        assert_eq!(merged.rules[2].subcommands, vec!["push"]);
    }

    #[test]
    fn test_merge_empty_extension_preserves_base() {
        let base = PolicyEngine::default_policy();
        let extension = PolicyEngine {
            rules: vec![],
            is_default: false,
            mode: PolicyMode::Extend,
        };

        let merged = PolicyEngine::merge(&base, &extension);
        assert_eq!(merged.rules.len(), base.rules.len());
        assert_eq!(merged.rules[0].command, "git");
    }

    #[test]
    fn test_merge_empty_base_uses_extension_only() {
        let base = PolicyEngine {
            rules: vec![],
            is_default: true,
            mode: PolicyMode::Replace,
        };

        let extension = PolicyEngine {
            rules: vec![DenyRule {
                command: "npm".to_string(),
                subcommands: vec!["publish".to_string()],
            }],
            is_default: false,
            mode: PolicyMode::Extend,
        };

        let merged = PolicyEngine::merge(&base, &extension);
        assert_eq!(merged.rules.len(), 1);
        assert_eq!(merged.rules[0].command, "npm");
    }

    #[test]
    fn test_merged_engine_evaluates_correctly() {
        let base = PolicyEngine {
            rules: vec![DenyRule {
                command: "git".to_string(),
                subcommands: vec!["push".to_string(), "commit".to_string()],
            }],
            is_default: true,
            mode: PolicyMode::Replace,
        };

        let extension = PolicyEngine {
            rules: vec![
                DenyRule {
                    command: "git".to_string(),
                    subcommands: vec!["push".to_string(), "merge".to_string()],
                },
                DenyRule {
                    command: "docker".to_string(),
                    subcommands: vec!["push".to_string()],
                },
            ],
            is_default: false,
            mode: PolicyMode::Extend,
        };

        let merged = PolicyEngine::merge(&base, &extension);

        // git push - still denied (in extension's git subcommands)
        let result = merged.evaluate("git push");
        assert!(matches!(result.decision, Decision::Deny { .. }));

        // git merge - now denied (added by extension)
        let result = merged.evaluate("git merge");
        assert!(matches!(result.decision, Decision::Deny { .. }));

        // git commit - no longer denied (extension replaced base git subcommands, commit not included)
        let result = merged.evaluate("git commit");
        assert_eq!(result.decision, Decision::Allow);

        // docker push - denied (new rule from extension)
        let result = merged.evaluate("docker push");
        assert!(matches!(result.decision, Decision::Deny { .. }));
    }
}
