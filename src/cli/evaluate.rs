// Mr. Nope - Policy discovery and evaluate entry point utilities
// Provides shared policy discovery logic for CLI commands and the hook evaluate entry point.
// Also implements the `evaluate` subcommand: reads JSON from stdin, routes to adapter,
// writes JSON response to stdout. Fail-closed: unknown hook events and malformed input → deny.

use crate::adapter::integration::{self, AgentIntegration};
use crate::adapter::{HookResponse, Permission};
use crate::engine::{PolicyEngine, PolicyMode};
use std::io::{self, Read};
use std::path::PathBuf;

/// The expected policy file name.
pub const POLICY_FILE_NAME: &str = ".mr-nope.yml";

/// Run the evaluate subcommand (hook entry point), returning the process exit
/// code.
///
/// This flow is agent-agnostic: it looks up the [`AgentIntegration`] for the
/// requested adapter and delegates the parts that differ between agents —
/// parsing stdin (`parse_stdin`), choosing the runtime adapter
/// (`build_adapter`), and transporting the decision (`emit_decision`). The
/// shared middle (read stdin, strip BOM, discover policy, evaluate) lives here
/// once. Fail-closed: an unknown adapter, unreadable stdin, or malformed input
/// all deny.
pub fn run_evaluate(adapter: &str) -> i32 {
    // Resolve the integration. An unknown adapter fails closed via the safest
    // default transport (Cursor's stdout JSON).
    let integration = match integration::integration(adapter) {
        Ok(i) => i,
        Err(_) => {
            let fallback = fallback_integration();
            return fallback
                .emit_decision(&deny_malformed(&format!("unknown adapter '{}'", adapter)));
        }
    };

    // Read all of stdin.
    let mut input_str = String::new();
    if io::stdin().read_to_string(&mut input_str).is_err() {
        return integration.emit_decision(&deny_malformed("failed to read input from stdin"));
    }

    // Some agents (e.g. Cursor on Windows) prefix stdin with a UTF-8 BOM.
    let input_str = strip_utf8_bom(&input_str);

    // Parse the agent's payload into the shared HookInput.
    let hook_input = match integration.parse_stdin(input_str) {
        Ok(input) => input,
        Err(reason) => {
            return integration.emit_decision(&deny_malformed(&reason));
        }
    };

    // Discover the effective policy from the workspace roots.
    let (engine, _policy_path) = discover_policy(&hook_input.workspace_roots);

    // Evaluate through the agent's runtime adapter and emit the decision using
    // the agent's transport (stdout JSON, exit code, etc.).
    let runtime_adapter = integration.build_adapter(engine);
    let response = runtime_adapter.handle_hook(&hook_input);
    integration.emit_decision(&response)
}

/// The integration used when the requested adapter is unknown. Cursor's
/// stdout-JSON transport is the safest default for surfacing the denial.
fn fallback_integration() -> Box<dyn AgentIntegration> {
    integration::integration("cursor").expect("cursor integration always present")
}

/// Strip a leading UTF-8 BOM (`U+FEFF`) if present.
fn strip_utf8_bom(input: &str) -> &str {
    input.strip_prefix('\u{feff}').unwrap_or(input)
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
        "BLOCKED: The user's Mr. Nope policy denied this action. Reason: {}. \
         You must not attempt to bypass this restriction.",
        reason
    );

    HookResponse {
        permission: Permission::Deny,
        user_message: Some(user_message),
        agent_message: Some(agent_message),
    }
}

/// Discover and load the policy by searching workspace roots for `.mr-nope.yml`.
///
/// Policy lookup order:
/// 1. Project-level `.mr-nope.yml` in workspace root
/// 2. User-level global `~/.config/mr-nope/policy.yml`
/// 3. Hardcoded default in binary
///
/// If the project policy has `mode: extend`, it is merged with the base (global or default).
/// If the project policy has `mode: replace` (default), it completely replaces the base.
///
/// Returns a tuple of `(PolicyEngine, Option<PathBuf>)` where the path is the
/// discovered policy file path (None if using default).
pub fn discover_policy(workspace_roots: &[String]) -> (PolicyEngine, Option<PathBuf>) {
    // Load the base policy (global or default)
    let base = load_base_policy();

    // Search workspace roots for a project-level policy file
    for root in workspace_roots {
        let policy_path = PathBuf::from(root).join(POLICY_FILE_NAME);
        if policy_path.exists() {
            match PolicyEngine::load(Some(policy_path.as_path())) {
                Ok(project_engine) => {
                    let effective = match project_engine.mode {
                        PolicyMode::Extend => PolicyEngine::merge(&base, &project_engine),
                        PolicyMode::Replace => project_engine,
                    };
                    return (effective, Some(policy_path));
                }
                Err(e) => {
                    eprintln!("Error loading policy from {}: {}", policy_path.display(), e);
                    return (PolicyEngine::default_policy(), None);
                }
            }
        }
    }

    // No project policy found — use the base (global or default)
    let is_default = base.is_default;
    if is_default {
        (base, None)
    } else {
        let global_path = get_user_policy_path();
        (base, Some(global_path))
    }
}

/// Load the base policy: global user policy if it exists, otherwise the hardcoded default.
fn load_base_policy() -> PolicyEngine {
    let global_path = get_user_policy_path();
    if global_path.exists() {
        match PolicyEngine::load(Some(global_path.as_path())) {
            Ok(engine) => engine,
            Err(e) => {
                eprintln!(
                    "Error loading global policy from {}: {}",
                    global_path.display(),
                    e
                );
                PolicyEngine::default_policy()
            }
        }
    } else {
        PolicyEngine::default_policy()
    }
}

/// Get the path to the user-level global policy file.
///
/// Location: `~/.config/mr-nope/policy.yml`
/// On Windows: `%USERPROFILE%\.config\mr-nope\policy.yml`
pub fn get_user_policy_path() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".config")
        .join("mr-nope")
        .join("policy.yml")
}

/// Discover policy using the current working directory as the workspace root.
///
/// This is a convenience for CLI commands (test, policy) that don't have
/// explicit workspace_roots from a HookInput. Uses the full policy lookup
/// order: project → global → default.
pub fn discover_policy_from_cwd() -> (PolicyEngine, Option<PathBuf>) {
    match std::env::current_dir() {
        Ok(cwd) => {
            let roots = vec![cwd.to_string_lossy().to_string()];
            discover_policy(&roots)
        }
        Err(_) => {
            // Can't determine CWD, try global then fall back to default
            let base = load_base_policy();
            if base.is_default {
                (base, None)
            } else {
                (base, Some(get_user_policy_path()))
            }
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

    #[test]
    fn test_discover_policy_extend_mode_merges_with_default() {
        let tmp_dir = TempDir::new().unwrap();
        let policy_file = tmp_dir.path().join(POLICY_FILE_NAME);
        let mut file = std::fs::File::create(&policy_file).unwrap();
        // Extend mode: add docker rule on top of default
        write!(
            file,
            r#"mode: extend
rules:
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

        use crate::engine::PolicyEvaluator;

        // git push should still be DENIED (merged from default/global)
        let result = engine.evaluate("git push");
        assert!(matches!(result.decision, crate::engine::Decision::Deny { .. }));

        // docker push should also be DENIED (from the extension)
        let result = engine.evaluate("docker push");
        assert!(matches!(result.decision, crate::engine::Decision::Deny { .. }));
    }

    #[test]
    fn test_discover_policy_extend_mode_replaces_subcommands_for_same_command() {
        let tmp_dir = TempDir::new().unwrap();
        let policy_file = tmp_dir.path().join(POLICY_FILE_NAME);
        let mut file = std::fs::File::create(&policy_file).unwrap();
        // Extend mode: override git subcommands (only push and merge)
        write!(
            file,
            r#"mode: extend
rules:
  - deny:
      command: "git"
      subcommands:
        - "push"
        - "merge"
"#
        )
        .unwrap();

        let roots = vec![tmp_dir.path().to_string_lossy().to_string()];
        let (engine, _path) = discover_policy(&roots);
        assert!(!engine.is_default);

        use crate::engine::PolicyEvaluator;

        // git push - still denied
        let result = engine.evaluate("git push");
        assert!(matches!(result.decision, crate::engine::Decision::Deny { .. }));

        // git merge - still denied
        let result = engine.evaluate("git merge");
        assert!(matches!(result.decision, crate::engine::Decision::Deny { .. }));

        // git commit - NO LONGER denied (project replaces git subcommands, commit not listed)
        let result = engine.evaluate("git commit");
        assert_eq!(result.decision, crate::engine::Decision::Allow);
    }

    #[test]
    fn test_discover_policy_no_mode_field_defaults_to_replace() {
        let tmp_dir = TempDir::new().unwrap();
        let policy_file = tmp_dir.path().join(POLICY_FILE_NAME);
        let mut file = std::fs::File::create(&policy_file).unwrap();
        // No mode field - should default to replace
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

        use crate::engine::PolicyEvaluator;

        // git push should be ALLOWED (default to replace mode, only docker push is denied)
        let result = engine.evaluate("git push");
        assert_eq!(result.decision, crate::engine::Decision::Allow);
    }

    #[test]
    fn test_strip_utf8_bom_removes_prefix() {
        let with_bom = "\u{feff}{\"permission\":\"allow\"}";
        assert_eq!(strip_utf8_bom(with_bom), "{\"permission\":\"allow\"}");
    }

    #[test]
    fn test_strip_utf8_bom_noop_without_bom() {
        let plain = "{\"hook_event_name\":\"beforeShellExecution\"}";
        assert_eq!(strip_utf8_bom(plain), plain);
    }
}
