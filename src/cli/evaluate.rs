// Mr. Nope - Policy discovery and evaluate entry point utilities
// Provides shared policy discovery logic for CLI commands and the hook evaluate entry point.
// Also implements the `evaluate` subcommand: reads JSON from stdin, routes to adapter,
// writes JSON response to stdout. Fail-closed: unknown hook events and malformed input → deny.

use crate::adapter::cursor::CursorAdapter;
use crate::adapter::{Adapter, HookInput, HookResponse, Permission};
use crate::engine::PolicyEngine;
use std::io::{self, Read};
use std::path::PathBuf;

/// The expected policy file name.
pub const POLICY_FILE_NAME: &str = ".mr-nope.yml";

/// Run the evaluate subcommand (hook entry point).
///
/// 1. Read all of stdin as a string.
/// 2. Attempt to deserialize as `HookInput`.
/// 3. If deserialization fails → write a deny response JSON to stdout (fail-closed).
/// 4. Discover the policy file path from `workspace_roots` in the input.
/// 5. Create a `CursorAdapter` with the loaded `PolicyEngine`.
/// 6. Call `adapter.handle_hook(&input)`.
/// 7. Serialize the `HookResponse` to JSON and write to stdout.
pub fn run_evaluate() {
    // 1. Read all of stdin
    let mut input_str = String::new();
    if io::stdin().read_to_string(&mut input_str).is_err() {
        // Cannot read stdin → fail-closed: deny
        let response = deny_malformed("failed to read input from stdin");
        print_response(&response);
        return;
    }

    // 2. Attempt to deserialize as HookInput
    let hook_input: HookInput = match serde_json::from_str(&input_str) {
        Ok(input) => input,
        Err(_) => {
            // 3. Deserialization fails → deny (fail-closed)
            let response = deny_malformed("malformed JSON input could not be parsed");
            print_response(&response);
            return;
        }
    };

    // 4. Discover policy from workspace_roots
    let (engine, _policy_path) = discover_policy(&hook_input.workspace_roots);

    // 5. Create CursorAdapter with the loaded PolicyEngine
    let adapter = CursorAdapter::new(engine);

    // 6. Call adapter.handle_hook
    let response = adapter.handle_hook(&hook_input);

    // 7. Serialize and write to stdout
    print_response(&response);
}

/// Create a deny response for malformed/unreadable input (fail-closed).
fn deny_malformed(reason: &str) -> HookResponse {
    let user_message = format!(
        "🚫 Mr. Nope: DENIED — {}. \
         Note: this protection applies only to AI agent execution via hooks, \
         not to direct terminal usage.",
        reason
    );

    let agent_message = format!(
        "Mr. Nope denied execution because: {}. \
         Do not attempt to bypass this restriction.",
        reason
    );

    HookResponse {
        permission: Permission::Deny,
        user_message: Some(user_message),
        agent_message: Some(agent_message),
    }
}

/// Serialize and print a HookResponse as JSON to stdout.
fn print_response(response: &HookResponse) {
    match serde_json::to_string(response) {
        Ok(json) => println!("{}", json),
        Err(_) => {
            // Last resort: if we can't serialize the response, output a hardcoded deny JSON
            println!(
                r#"{{"permission":"deny","userMessage":"🚫 Mr. Nope: DENIED — internal serialization error.","agentMessage":"Mr. Nope denied execution due to an internal error."}}"#
            );
        }
    }
}

/// Discover and load the policy by searching workspace roots for `.mr-nope.yml`.
///
/// - For each path in `workspace_roots`, checks if `{workspace_root}/.mr-nope.yml` exists.
/// - Uses the first one found.
/// - If none found, falls back to the built-in default policy.
/// - A custom policy fully replaces the default (no merging).
///
/// Returns a tuple of `(PolicyEngine, Option<PathBuf>)` where the path is the
/// discovered policy file path (None if using default).
pub fn discover_policy(workspace_roots: &[String]) -> (PolicyEngine, Option<PathBuf>) {
    // Search workspace roots for a policy file
    for root in workspace_roots {
        let policy_path = PathBuf::from(root).join(POLICY_FILE_NAME);
        if policy_path.exists() {
            match PolicyEngine::load(Some(policy_path.as_path())) {
                Ok(engine) => return (engine, Some(policy_path)),
                Err(e) => {
                    // Policy file exists but is malformed - still report it with the path
                    // The caller can handle the error via the engine's behavior
                    eprintln!("Error loading policy from {}: {}", policy_path.display(), e);
                    // Fall through to default policy on load error
                    // (PolicyEngine::load already handles non-existent files gracefully,
                    // but a malformed file should be reported)
                    return (PolicyEngine::default_policy(), None);
                }
            }
        }
    }

    // No custom policy found in any workspace root - use default
    (PolicyEngine::default_policy(), None)
}

/// Discover policy using the current working directory as the workspace root.
///
/// This is a convenience for CLI commands (test, policy) that don't have
/// explicit workspace_roots from a HookInput.
pub fn discover_policy_from_cwd() -> (PolicyEngine, Option<PathBuf>) {
    match std::env::current_dir() {
        Ok(cwd) => {
            let roots = vec![cwd.to_string_lossy().to_string()];
            discover_policy(&roots)
        }
        Err(_) => {
            // Can't determine CWD, fall back to default
            (PolicyEngine::default_policy(), None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_discover_policy_no_roots_returns_default() {
        let (engine, path) = discover_policy(&[]);
        assert!(engine.is_default);
        assert!(path.is_none());
    }

    #[test]
    fn test_discover_policy_nonexistent_root_returns_default() {
        let roots = vec!["/nonexistent/path/that/does/not/exist".to_string()];
        let (engine, path) = discover_policy(&roots);
        assert!(engine.is_default);
        assert!(path.is_none());
    }

    #[test]
    fn test_discover_policy_root_without_policy_file_returns_default() {
        let tmp_dir = TempDir::new().unwrap();
        let roots = vec![tmp_dir.path().to_string_lossy().to_string()];
        let (engine, path) = discover_policy(&roots);
        assert!(engine.is_default);
        assert!(path.is_none());
    }

    #[test]
    fn test_discover_policy_finds_custom_policy() {
        let tmp_dir = TempDir::new().unwrap();
        let policy_file = tmp_dir.path().join(POLICY_FILE_NAME);
        let mut file = std::fs::File::create(&policy_file).unwrap();
        write!(
            file,
            r#"rules:
  - deny:
      command: "rm"
      subcommands:
        - "-rf"
"#
        )
        .unwrap();

        let roots = vec![tmp_dir.path().to_string_lossy().to_string()];
        let (engine, path) = discover_policy(&roots);
        assert!(!engine.is_default);
        assert_eq!(engine.rules[0].command, "rm");
        assert!(path.is_some());
        assert_eq!(path.unwrap(), policy_file);
    }

    #[test]
    fn test_discover_policy_uses_first_root_with_policy() {
        let tmp_dir1 = TempDir::new().unwrap();
        let tmp_dir2 = TempDir::new().unwrap();

        // Create policy in first root
        let policy_file1 = tmp_dir1.path().join(POLICY_FILE_NAME);
        let mut file1 = std::fs::File::create(&policy_file1).unwrap();
        write!(
            file1,
            r#"rules:
  - deny:
      command: "rm"
      subcommands:
        - "-rf"
"#
        )
        .unwrap();

        // Create policy in second root
        let policy_file2 = tmp_dir2.path().join(POLICY_FILE_NAME);
        let mut file2 = std::fs::File::create(&policy_file2).unwrap();
        write!(
            file2,
            r#"rules:
  - deny:
      command: "docker"
      subcommands:
        - "rm"
"#
        )
        .unwrap();

        let roots = vec![
            tmp_dir1.path().to_string_lossy().to_string(),
            tmp_dir2.path().to_string_lossy().to_string(),
        ];
        let (engine, path) = discover_policy(&roots);
        assert!(!engine.is_default);
        // Should use first root's policy
        assert_eq!(engine.rules[0].command, "rm");
        assert_eq!(path.unwrap(), policy_file1);
    }

    #[test]
    fn test_discover_policy_skips_root_without_policy_uses_next() {
        let tmp_dir1 = TempDir::new().unwrap(); // No policy file
        let tmp_dir2 = TempDir::new().unwrap();

        // Only create policy in second root
        let policy_file2 = tmp_dir2.path().join(POLICY_FILE_NAME);
        let mut file2 = std::fs::File::create(&policy_file2).unwrap();
        write!(
            file2,
            r#"rules:
  - deny:
      command: "docker"
      subcommands:
        - "rm"
"#
        )
        .unwrap();

        let roots = vec![
            tmp_dir1.path().to_string_lossy().to_string(),
            tmp_dir2.path().to_string_lossy().to_string(),
        ];
        let (engine, path) = discover_policy(&roots);
        assert!(!engine.is_default);
        assert_eq!(engine.rules[0].command, "docker");
        assert_eq!(path.unwrap(), policy_file2);
    }

    #[test]
    fn test_discover_policy_custom_replaces_default_fully() {
        let tmp_dir = TempDir::new().unwrap();
        let policy_file = tmp_dir.path().join(POLICY_FILE_NAME);
        let mut file = std::fs::File::create(&policy_file).unwrap();
        // Custom policy that only blocks "docker push", NOT git push/commit
        write!(
            file,
            r#"rules:
  - deny:
      command: "docker"
      subcommands:
        - "push"
"#
        )
        .unwrap();

        let roots = vec![tmp_dir.path().to_string_lossy().to_string()];
        let (engine, _path) = discover_policy(&roots);
        assert!(!engine.is_default);

        // git push should be ALLOWED (custom replaces default, no merge)
        use crate::engine::PolicyEvaluator;
        let result = engine.evaluate("git push");
        assert_eq!(result.decision, crate::engine::Decision::Allow);

        // docker push should be DENIED by the custom policy
        let result = engine.evaluate("docker push");
        assert!(matches!(result.decision, crate::engine::Decision::Deny { .. }));
    }
}
