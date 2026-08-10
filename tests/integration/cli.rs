// Integration tests for CLI install/uninstall commands
// Tests the mr-nope binary via std::process::Command with temp directories.

use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

/// Get the path to the compiled mr-nope binary.
fn mr_nope_bin() -> std::path::PathBuf {
    // cargo test builds the binary in the same target directory
    let mut path = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    path.push(format!("mr-nope{}", std::env::consts::EXE_SUFFIX));
    path
}

#[test]
fn test_install_with_project_creates_hooks_json() {
    let tmp = TempDir::new().unwrap();

    let output = Command::new(mr_nope_bin())
        .args(["install", "cursor", "--project"])
        .current_dir(tmp.path())
        .output()
        .expect("failed to execute mr-nope install");

    assert!(
        output.status.success(),
        "install should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify .cursor/hooks.json was created
    let hooks_path = tmp.path().join(".cursor").join("hooks.json");
    assert!(hooks_path.exists(), ".cursor/hooks.json should be created");

    // Verify content
    let content = fs::read_to_string(&hooks_path).unwrap();
    let parsed: Value = serde_json::from_str(&content).unwrap();

    // Should have version
    assert_eq!(parsed["version"], 1);

    // Should have beforeShellExecution with mr-nope evaluate
    let shell_hooks = parsed["hooks"]["beforeShellExecution"].as_array().unwrap();
    assert!(
        shell_hooks
            .iter()
            .any(|h| h["command"] == "mr-nope evaluate"),
        "beforeShellExecution should contain 'mr-nope evaluate'"
    );

    // Should have beforeMCPExecution with mr-nope evaluate
    let mcp_hooks = parsed["hooks"]["beforeMCPExecution"].as_array().unwrap();
    assert!(
        mcp_hooks
            .iter()
            .any(|h| h["command"] == "mr-nope evaluate"),
        "beforeMCPExecution should contain 'mr-nope evaluate'"
    );
}

#[test]
fn test_install_preserves_existing_hooks() {
    let tmp = TempDir::new().unwrap();

    // Create an existing hooks.json with another tool's hook
    let cursor_dir = tmp.path().join(".cursor");
    fs::create_dir_all(&cursor_dir).unwrap();
    let hooks_path = cursor_dir.join("hooks.json");

    let existing = serde_json::json!({
        "version": 1,
        "hooks": {
            "beforeShellExecution": [
                { "command": "other-tool check" }
            ],
            "beforeMCPExecution": [
                { "command": "security-scanner verify" }
            ]
        }
    });
    fs::write(&hooks_path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

    // Run install
    let output = Command::new(mr_nope_bin())
        .args(["install", "cursor", "--project"])
        .current_dir(tmp.path())
        .output()
        .expect("failed to execute mr-nope install");

    assert!(
        output.status.success(),
        "install should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify other tool's hooks are preserved and mr-nope was added
    let content = fs::read_to_string(&hooks_path).unwrap();
    let parsed: Value = serde_json::from_str(&content).unwrap();

    let shell_hooks = parsed["hooks"]["beforeShellExecution"].as_array().unwrap();
    assert_eq!(shell_hooks.len(), 2, "should have both hooks");
    assert_eq!(shell_hooks[0]["command"], "other-tool check");
    assert_eq!(shell_hooks[1]["command"], "mr-nope evaluate");

    let mcp_hooks = parsed["hooks"]["beforeMCPExecution"].as_array().unwrap();
    assert_eq!(mcp_hooks.len(), 2, "should have both hooks");
    assert_eq!(mcp_hooks[0]["command"], "security-scanner verify");
    assert_eq!(mcp_hooks[1]["command"], "mr-nope evaluate");
}

#[test]
fn test_uninstall_removes_only_mr_nope_entries() {
    let tmp = TempDir::new().unwrap();

    // Create hooks.json with both mr-nope and another tool's hooks
    let cursor_dir = tmp.path().join(".cursor");
    fs::create_dir_all(&cursor_dir).unwrap();
    let hooks_path = cursor_dir.join("hooks.json");

    let existing = serde_json::json!({
        "version": 1,
        "hooks": {
            "beforeShellExecution": [
                { "command": "other-tool check" },
                { "command": "mr-nope evaluate" },
                { "command": "lint-staged run" }
            ],
            "beforeMCPExecution": [
                { "command": "mr-nope evaluate" },
                { "command": "security-scanner verify" }
            ]
        }
    });
    fs::write(&hooks_path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

    // Run uninstall
    let output = Command::new(mr_nope_bin())
        .args(["uninstall", "cursor", "--project"])
        .current_dir(tmp.path())
        .output()
        .expect("failed to execute mr-nope uninstall");

    assert!(
        output.status.success(),
        "uninstall should succeed. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify mr-nope entries removed, others preserved
    let content = fs::read_to_string(&hooks_path).unwrap();
    let parsed: Value = serde_json::from_str(&content).unwrap();

    let shell_hooks = parsed["hooks"]["beforeShellExecution"].as_array().unwrap();
    assert_eq!(shell_hooks.len(), 2, "mr-nope entry should be removed");
    assert_eq!(shell_hooks[0]["command"], "other-tool check");
    assert_eq!(shell_hooks[1]["command"], "lint-staged run");

    let mcp_hooks = parsed["hooks"]["beforeMCPExecution"].as_array().unwrap();
    assert_eq!(mcp_hooks.len(), 1, "mr-nope entry should be removed");
    assert_eq!(mcp_hooks[0]["command"], "security-scanner verify");
}

#[test]
fn test_install_with_unsupported_adapter_fails() {
    let tmp = TempDir::new().unwrap();

    let output = Command::new(mr_nope_bin())
        .args(["install", "vscode", "--project"])
        .current_dir(tmp.path())
        .output()
        .expect("failed to execute mr-nope install");

    assert!(
        !output.status.success(),
        "install with unsupported adapter should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported adapter"),
        "stderr should mention 'unsupported adapter', got: {}",
        stderr
    );
    assert!(
        stderr.contains("cursor"),
        "stderr should list supported adapters (cursor), got: {}",
        stderr
    );
}

#[test]
fn test_uninstall_with_no_hooks_json_is_graceful() {
    let tmp = TempDir::new().unwrap();

    // No .cursor/hooks.json exists
    assert!(!tmp.path().join(".cursor").join("hooks.json").exists());

    let output = Command::new(mr_nope_bin())
        .args(["uninstall", "cursor", "--project"])
        .current_dir(tmp.path())
        .output()
        .expect("failed to execute mr-nope uninstall");

    assert!(
        output.status.success(),
        "uninstall with no hooks.json should exit 0 (graceful no-op). stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
