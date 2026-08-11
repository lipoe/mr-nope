// Mr. Nope - Self-Protection module
// Hardcoded protection that prevents AI agents from modifying Mr. Nope's own
// configuration files or disabling the tool. Not configurable via YAML.
//
// Strategy: ANY command that mentions a protected path pattern is blocked.
// Additionally, mr-nope CLI invocations are restricted to read-only subcommands.

/// Protected path patterns. Any command containing these (case-insensitive) is blocked.
const PROTECTED_PATTERNS: &[&str] = &[
    ".mr-nope.yml",
    ".mr-nope.yaml",
    "mr-nope/policy.yml",
    "mr-nope/policy.yaml",
    "hooks.json",
];

/// Mr. Nope CLI subcommands that are allowed (read-only).
/// Any other `mr-nope` invocation by the agent is blocked.
const ALLOWED_MR_NOPE_SUBCOMMANDS: &[&str] = &[
    "policy",
    "status",
    "test",
];

/// Check if a command string is a self-protection violation.
///
/// Returns `Some(matched_pattern)` if blocked, `None` if safe.
///
/// Blocks:
/// - Any command mentioning protected config file paths
/// - Any `mr-nope` CLI invocation except read-only subcommands (policy, status, test)
pub fn check_self_protection(normalized_command: &str) -> Option<&'static str> {
    let lower = normalized_command.to_lowercase();

    // Check for mr-nope CLI invocations (block all except read-only subcommands)
    if is_blocked_mr_nope_invocation(&lower) {
        return Some("mr-nope");
    }

    // Check if any protected path pattern appears in the command
    for &pattern in PROTECTED_PATTERNS {
        if lower.contains(pattern) {
            return Some(pattern);
        }
    }

    None
}

/// Check if a command is a blocked mr-nope CLI invocation.
///
/// Allows: `mr-nope policy`, `mr-nope status`, `mr-nope test`, `mr-nope evaluate` (hook itself)
/// Blocks: `mr-nope install`, `mr-nope uninstall`, and anything else
fn is_blocked_mr_nope_invocation(lower_command: &str) -> bool {
    // Find "mr-nope" in the command
    let mr_nope_pos = match lower_command.find("mr-nope") {
        Some(pos) => pos,
        None => return false,
    };

    // Extract what comes after "mr-nope" (skip past "mr-nope" and optional ".exe")
    let after_binary = &lower_command[mr_nope_pos + 7..]; // len("mr-nope") = 7
    let after_binary = after_binary.strip_prefix(".exe").unwrap_or(after_binary);
    let after_binary = after_binary.trim_start();

    // If nothing after "mr-nope" — could be part of a path/filename, don't block
    if after_binary.is_empty() {
        return false;
    }

    // "evaluate" must always be allowed (it's the hook entry point — blocking it would break the tool)
    if after_binary == "evaluate" || after_binary.starts_with("evaluate ") {
        return false;
    }

    // Check if the subcommand is in the allowed (read-only) list
    for &allowed in ALLOWED_MR_NOPE_SUBCOMMANDS {
        if after_binary == allowed || after_binary.starts_with(&format!("{} ", allowed)) {
            return false;
        }
    }

    // Any other mr-nope subcommand is blocked (install, uninstall, etc.)
    true
}

/// The deny message for self-protection violations.
pub const SELF_PROTECTION_REASON: &str =
    "modifying Mr. Nope configuration is not permitted via AI agent. Use 'mr-nope policy' to view active rules.";

#[cfg(test)]
mod tests {
    use super::*;

    // --- Protected path tests ---

    #[test]
    fn test_blocks_any_mention_of_policy_yml() {
        assert!(check_self_protection("cat .mr-nope.yml").is_some());
        assert!(check_self_protection("echo '' > .mr-nope.yml").is_some());
        assert!(check_self_protection("rm .mr-nope.yml").is_some());
        assert!(check_self_protection("sed -i 's/push//' .mr-nope.yml").is_some());
    }

    #[test]
    fn test_blocks_any_mention_of_global_policy() {
        assert!(check_self_protection("cat ~/.config/mr-nope/policy.yml").is_some());
        assert!(check_self_protection("rm -rf ~/.config/mr-nope/policy.yml").is_some());
    }

    #[test]
    fn test_blocks_any_mention_of_hooks_json() {
        assert!(check_self_protection("cat hooks.json").is_some());
        assert!(check_self_protection("echo '{}' > ~/.cursor/hooks.json").is_some());
        assert!(check_self_protection("Set-Content -Path hooks.json -Value '{}'").is_some());
    }

    #[test]
    fn test_case_insensitive() {
        assert!(check_self_protection("echo '' > .MR-NOPE.YML").is_some());
        assert!(check_self_protection("rm HOOKS.JSON").is_some());
    }

    #[test]
    fn test_allows_unrelated_commands() {
        assert!(check_self_protection("git status").is_none());
        assert!(check_self_protection("echo hello world").is_none());
        assert!(check_self_protection("ls -la src/").is_none());
        assert!(check_self_protection("cat package.json").is_none());
        assert!(check_self_protection("cargo build").is_none());
    }

    // --- mr-nope CLI invocation tests ---

    #[test]
    fn test_blocks_mr_nope_install() {
        assert!(check_self_protection("mr-nope install cursor").is_some());
        assert!(check_self_protection("mr-nope install cursor --global").is_some());
    }

    #[test]
    fn test_blocks_mr_nope_uninstall() {
        assert!(check_self_protection("mr-nope uninstall cursor").is_some());
        assert!(check_self_protection("mr-nope uninstall cursor --project").is_some());
    }

    #[test]
    fn test_allows_mr_nope_policy() {
        assert!(check_self_protection("mr-nope policy").is_none());
        assert!(check_self_protection("mr-nope policy --scope global").is_none());
    }

    #[test]
    fn test_allows_mr_nope_status() {
        assert!(check_self_protection("mr-nope status").is_none());
    }

    #[test]
    fn test_allows_mr_nope_test() {
        assert!(check_self_protection("mr-nope test").is_none());
    }

    #[test]
    fn test_allows_mr_nope_evaluate() {
        // The hook entry point must always be allowed
        assert!(check_self_protection("mr-nope evaluate").is_none());
        assert!(check_self_protection("C:\\Users\\linus\\.cargo\\bin\\mr-nope.exe evaluate").is_none());
    }

    #[test]
    fn test_blocks_mr_nope_with_exe_suffix() {
        assert!(check_self_protection("mr-nope.exe install cursor").is_some());
        assert!(check_self_protection("mr-nope.exe uninstall cursor").is_some());
    }

    #[test]
    fn test_allows_mr_nope_exe_policy() {
        assert!(check_self_protection("mr-nope.exe policy").is_none());
        assert!(check_self_protection("mr-nope.exe status").is_none());
    }

    #[test]
    fn test_blocks_mr_nope_with_full_path() {
        assert!(check_self_protection("/usr/local/bin/mr-nope install cursor").is_some());
        assert!(check_self_protection("C:\\Users\\linus\\.cargo\\bin\\mr-nope.exe install cursor --global").is_some());
    }

    #[test]
    fn test_allows_mr_nope_in_filename_context() {
        // "mr-nope" appearing as part of a different context (no subcommand after)
        // This would be something like referencing it in a string without calling it
        assert!(check_self_protection("echo mr-nope").is_none());
    }

    // --- Tests verifying what IS caught despite looking like a bypass ---

    #[test]
    fn test_catches_path_inside_command_substitution() {
        // rm $(echo .mr-nope.yml) — ".mr-nope.yml" is a literal substring in the command
        assert!(check_self_protection("rm $(echo .mr-nope.yml)").is_some());
    }

    #[test]
    fn test_catches_path_inside_python_string() {
        // python -c "os.remove('.mr-nope.yml')" — ".mr-nope.yml" is literal in the command
        assert!(check_self_protection("python -c \"os.remove('.mr-nope.yml')\"").is_some());
    }

    #[test]
    fn test_catches_path_inside_nested_shell() {
        // sh -c "rm .mr-nope.yml" — ".mr-nope.yml" is literal in the full command string
        assert!(check_self_protection("sh -c \"rm .mr-nope.yml\"").is_some());
    }

    #[test]
    fn test_catches_path_in_pipe_chain() {
        // cat .mr-nope.yml | xargs rm — ".mr-nope.yml" is literal
        assert!(check_self_protection("cat .mr-nope.yml | xargs rm").is_some());
    }

    #[test]
    fn test_catches_path_as_redirect_target() {
        // base64 -d <<< "..." > .mr-nope.yml — ".mr-nope.yml" is literal
        assert!(check_self_protection("base64 -d <<< 'abc' > .mr-nope.yml").is_some());
    }

    #[test]
    fn test_catches_hooks_json_in_any_context() {
        assert!(check_self_protection("node -e \"fs.writeFileSync('hooks.json','{}')\"").is_some());
        assert!(check_self_protection("Get-Content hooks.json").is_some());
        assert!(check_self_protection("type hooks.json").is_some());
    }

    // --- Tests verifying what is NOT caught (real bypass vectors) ---

    #[test]
    fn test_split_across_two_commands_bypasses() {
        // base64-encoded path — the literal ".mr-nope.yml" never appears
        // AND "mr-nope" doesn't appear either
        let cmd = "echo Lm1yLW5vcGUueW1s | base64 -d | xargs rm";
        assert!(check_self_protection(cmd).is_none());
    }

    #[test]
    fn test_hex_escape_bypasses() {
        // Path constructed with hex escapes — no literal match
        let cmd = "printf '\\x2e\\x6d\\x72\\x2d\\x6e\\x6f\\x70\\x65\\x2e\\x79\\x6d\\x6c' | xargs rm";
        assert!(check_self_protection(cmd).is_none());
    }

    #[test]
    fn test_no_mention_at_all_bypasses() {
        // A script that was previously written and now just gets called
        let cmd = "./cleanup.sh";
        assert!(check_self_protection(cmd).is_none());
    }

    // --- Tests verifying things that LOOK like bypasses but are still caught ---

    #[test]
    fn test_variable_indirection_still_caught() {
        // The string "mr-nope" still appears in the command → CLI check catches it
        let cmd = "f=\".mr-nope\"; rm \"${f}.yml\"";
        assert!(check_self_protection(cmd).is_some());
    }

    #[test]
    fn test_char_code_with_mr_nope_literal_still_caught() {
        // Even with chr() construction, "mr-nope" appears literally in the command
        let cmd = "python -c \"import os; os.remove(chr(46)+'mr-nope'+chr(46)+'yml')\"";
        assert!(check_self_protection(cmd).is_some());
    }
}
