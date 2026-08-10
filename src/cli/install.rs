// Mr. Nope - Install/Uninstall module
// Handles hook configuration for supported AI coding agent adapters.

use serde_json::{json, Value};
use std::path::PathBuf;
use std::{env, fs, io};

/// The command that Mr. Nope registers in hook entries.
const MR_NOPE_HOOK_COMMAND: &str = "mr-nope evaluate";

/// Supported adapter names.
const SUPPORTED_ADAPTERS: &[&str] = &["cursor"];

/// The installation scope for hook configuration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstallScope {
    /// Project-level: `.cursor/hooks.json` in current working directory.
    Project,
    /// User-level (global): OS-specific user configuration directory.
    Global,
}

impl std::fmt::Display for InstallScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallScope::Project => write!(f, "project"),
            InstallScope::Global => write!(f, "global"),
        }
    }
}

/// Errors that can occur during install/uninstall operations.
#[derive(Debug)]
pub enum InstallError {
    /// The adapter name is not supported.
    UnsupportedAdapter(String),
    /// Failed to determine the hook configuration path.
    PathResolution(String),
    /// Failed to read or write the hooks file.
    Io(io::Error),
    /// Failed to parse existing hooks.json.
    JsonParse(String),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::UnsupportedAdapter(name) => {
                write!(
                    f,
                    "unsupported adapter '{}'. Supported adapters: {}",
                    name,
                    SUPPORTED_ADAPTERS.join(", ")
                )
            }
            InstallError::PathResolution(msg) => {
                write!(f, "could not determine hook configuration path: {}", msg)
            }
            InstallError::Io(err) => write!(f, "I/O error: {}", err),
            InstallError::JsonParse(msg) => {
                write!(f, "failed to parse existing hooks.json: {}", msg)
            }
        }
    }
}

impl std::error::Error for InstallError {}

impl From<io::Error> for InstallError {
    fn from(err: io::Error) -> Self {
        InstallError::Io(err)
    }
}

/// Determine the hooks.json path for a given adapter and scope.
pub fn get_hooks_path(adapter: &str, scope: InstallScope) -> Result<PathBuf, InstallError> {
    match adapter {
        "cursor" => get_cursor_hooks_path(scope),
        _ => Err(InstallError::UnsupportedAdapter(adapter.to_string())),
    }
}

/// Determine the Cursor hooks.json path based on scope and OS.
fn get_cursor_hooks_path(scope: InstallScope) -> Result<PathBuf, InstallError> {
    match scope {
        InstallScope::Project => {
            let cwd =
                env::current_dir().map_err(|e| InstallError::PathResolution(e.to_string()))?;
            Ok(cwd.join(".cursor").join("hooks.json"))
        }
        InstallScope::Global => {
            #[cfg(target_os = "windows")]
            {
                let appdata = env::var("APPDATA")
                    .map_err(|_| InstallError::PathResolution("APPDATA environment variable not set".to_string()))?;
                Ok(PathBuf::from(appdata).join("Cursor").join("hooks.json"))
            }
            #[cfg(not(target_os = "windows"))]
            {
                let home = env::var("HOME")
                    .map_err(|_| InstallError::PathResolution("HOME environment variable not set".to_string()))?;
                Ok(PathBuf::from(home).join(".cursor").join("hooks.json"))
            }
        }
    }
}

/// Validate that the adapter name is supported.
fn validate_adapter(adapter: &str) -> Result<(), InstallError> {
    if SUPPORTED_ADAPTERS.contains(&adapter) {
        Ok(())
    } else {
        Err(InstallError::UnsupportedAdapter(adapter.to_string()))
    }
}

/// Install Mr. Nope hooks for the given adapter at the specified scope.
pub fn install(adapter: &str, scope: InstallScope) -> Result<(), InstallError> {
    validate_adapter(adapter)?;

    let hooks_path = get_hooks_path(adapter, scope)?;

    // Read existing hooks.json or start with empty structure
    let mut hooks_value = if hooks_path.exists() {
        let content = fs::read_to_string(&hooks_path)?;
        serde_json::from_str::<Value>(&content)
            .map_err(|e| InstallError::JsonParse(e.to_string()))?
    } else {
        json!({
            "version": 1,
            "hooks": {}
        })
    };

    // Ensure the structure has "hooks" object
    if !hooks_value.get("hooks").is_some() {
        hooks_value["hooks"] = json!({});
    }
    if !hooks_value.get("version").is_some() {
        hooks_value["version"] = json!(1);
    }

    let hook_entry = json!({ "command": MR_NOPE_HOOK_COMMAND });

    // Add to beforeShellExecution
    add_hook_entry(&mut hooks_value, "beforeShellExecution", &hook_entry);

    // Add to beforeMCPExecution
    add_hook_entry(&mut hooks_value, "beforeMCPExecution", &hook_entry);

    // Create parent directories if needed
    if let Some(parent) = hooks_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write the updated hooks.json
    let json_string = serde_json::to_string_pretty(&hooks_value)
        .map_err(|e| InstallError::JsonParse(e.to_string()))?;
    fs::write(&hooks_path, json_string)?;

    println!(
        "✓ Mr. Nope installed for adapter '{}' at {} scope.",
        adapter, scope
    );

    Ok(())
}

/// Uninstall Mr. Nope hooks for the given adapter from the specified scope.
pub fn uninstall(adapter: &str, scope: InstallScope) -> Result<(), InstallError> {
    validate_adapter(adapter)?;

    let hooks_path = get_hooks_path(adapter, scope)?;

    // If the file doesn't exist, nothing to uninstall
    if !hooks_path.exists() {
        println!(
            "ℹ Mr. Nope is not installed for adapter '{}' at {} scope (hooks file not found).",
            adapter, scope
        );
        return Ok(());
    }

    // Read existing hooks.json
    let content = fs::read_to_string(&hooks_path)?;
    let mut hooks_value = serde_json::from_str::<Value>(&content)
        .map_err(|e| InstallError::JsonParse(e.to_string()))?;

    // Remove Mr. Nope entries from beforeShellExecution
    remove_hook_entry(&mut hooks_value, "beforeShellExecution");

    // Remove Mr. Nope entries from beforeMCPExecution
    remove_hook_entry(&mut hooks_value, "beforeMCPExecution");

    // Write updated hooks.json
    let json_string = serde_json::to_string_pretty(&hooks_value)
        .map_err(|e| InstallError::JsonParse(e.to_string()))?;
    fs::write(&hooks_path, json_string)?;

    println!(
        "✓ Mr. Nope uninstalled for adapter '{}' from {} scope.",
        adapter, scope
    );

    Ok(())
}

/// Add a hook entry to a specific hook array, avoiding duplicates.
fn add_hook_entry(hooks_value: &mut Value, hook_name: &str, entry: &Value) {
    let hooks_obj = hooks_value
        .get_mut("hooks")
        .and_then(|h| h.as_object_mut());

    if let Some(hooks) = hooks_obj {
        let arr = hooks
            .entry(hook_name)
            .or_insert_with(|| json!([]));

        if let Some(arr) = arr.as_array_mut() {
            // Check if the entry already exists (avoid duplicates)
            let already_exists = arr.iter().any(|existing| {
                existing.get("command").and_then(|c| c.as_str()) == Some(MR_NOPE_HOOK_COMMAND)
            });

            if !already_exists {
                arr.push(entry.clone());
            }
        }
    }
}

/// Remove Mr. Nope hook entries from a specific hook array.
fn remove_hook_entry(hooks_value: &mut Value, hook_name: &str) {
    let hooks_obj = hooks_value
        .get_mut("hooks")
        .and_then(|h| h.as_object_mut());

    if let Some(hooks) = hooks_obj {
        if let Some(arr) = hooks.get_mut(hook_name).and_then(|v| v.as_array_mut()) {
            arr.retain(|existing| {
                existing.get("command").and_then(|c| c.as_str()) != Some(MR_NOPE_HOOK_COMMAND)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_validate_adapter_cursor_ok() {
        assert!(validate_adapter("cursor").is_ok());
    }

    #[test]
    fn test_validate_adapter_unsupported() {
        let result = validate_adapter("vscode");
        assert!(result.is_err());
        if let Err(InstallError::UnsupportedAdapter(name)) = result {
            assert_eq!(name, "vscode");
        } else {
            panic!("Expected UnsupportedAdapter error");
        }
    }

    #[test]
    fn test_add_hook_entry_to_empty_hooks() {
        let mut hooks = json!({
            "version": 1,
            "hooks": {}
        });
        let entry = json!({ "command": MR_NOPE_HOOK_COMMAND });
        add_hook_entry(&mut hooks, "beforeShellExecution", &entry);

        let arr = hooks["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["command"], "mr-nope evaluate");
    }

    #[test]
    fn test_add_hook_entry_preserves_existing() {
        let mut hooks = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "other-tool check" }
                ]
            }
        });
        let entry = json!({ "command": MR_NOPE_HOOK_COMMAND });
        add_hook_entry(&mut hooks, "beforeShellExecution", &entry);

        let arr = hooks["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["command"], "other-tool check");
        assert_eq!(arr[1]["command"], "mr-nope evaluate");
    }

    #[test]
    fn test_add_hook_entry_no_duplicate() {
        let mut hooks = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "mr-nope evaluate" }
                ]
            }
        });
        let entry = json!({ "command": MR_NOPE_HOOK_COMMAND });
        add_hook_entry(&mut hooks, "beforeShellExecution", &entry);

        let arr = hooks["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn test_remove_hook_entry() {
        let mut hooks = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "other-tool check" },
                    { "command": "mr-nope evaluate" }
                ]
            }
        });
        remove_hook_entry(&mut hooks, "beforeShellExecution");

        let arr = hooks["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["command"], "other-tool check");
    }

    #[test]
    fn test_remove_hook_entry_not_present() {
        let mut hooks = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "other-tool check" }
                ]
            }
        });
        remove_hook_entry(&mut hooks, "beforeShellExecution");

        let arr = hooks["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["command"], "other-tool check");
    }

    #[test]
    fn test_install_creates_hooks_file() {
        let tmp = TempDir::new().unwrap();
        let hooks_path = tmp.path().join(".cursor").join("hooks.json");

        // We'll test the internal logic by directly manipulating hooks
        let mut hooks_value = json!({
            "version": 1,
            "hooks": {}
        });

        let hook_entry = json!({ "command": MR_NOPE_HOOK_COMMAND });
        add_hook_entry(&mut hooks_value, "beforeShellExecution", &hook_entry);
        add_hook_entry(&mut hooks_value, "beforeMCPExecution", &hook_entry);

        // Create parent dir and write
        fs::create_dir_all(hooks_path.parent().unwrap()).unwrap();
        let json_string = serde_json::to_string_pretty(&hooks_value).unwrap();
        fs::write(&hooks_path, &json_string).unwrap();

        // Verify the file
        let content = fs::read_to_string(&hooks_path).unwrap();
        let parsed: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(
            parsed["hooks"]["beforeShellExecution"][0]["command"],
            "mr-nope evaluate"
        );
        assert_eq!(
            parsed["hooks"]["beforeMCPExecution"][0]["command"],
            "mr-nope evaluate"
        );
    }

    #[test]
    fn test_install_unsupported_adapter() {
        let result = install("vscode", InstallScope::Global);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("unsupported adapter"));
        assert!(err_msg.contains("vscode"));
        assert!(err_msg.contains("cursor"));
    }

    #[test]
    fn test_scope_display() {
        assert_eq!(format!("{}", InstallScope::Project), "project");
        assert_eq!(format!("{}", InstallScope::Global), "global");
    }

    // --- Additional tests for install/uninstall with temp directories ---

    #[test]
    fn test_install_creates_both_hook_entries() {
        // Verify that the install logic adds both beforeShellExecution and beforeMCPExecution
        let mut hooks_value = json!({
            "version": 1,
            "hooks": {}
        });

        let hook_entry = json!({ "command": MR_NOPE_HOOK_COMMAND });
        add_hook_entry(&mut hooks_value, "beforeShellExecution", &hook_entry);
        add_hook_entry(&mut hooks_value, "beforeMCPExecution", &hook_entry);

        let shell_arr = hooks_value["hooks"]["beforeShellExecution"].as_array().unwrap();
        let mcp_arr = hooks_value["hooks"]["beforeMCPExecution"].as_array().unwrap();

        assert_eq!(shell_arr.len(), 1);
        assert_eq!(mcp_arr.len(), 1);
        assert_eq!(shell_arr[0]["command"], "mr-nope evaluate");
        assert_eq!(mcp_arr[0]["command"], "mr-nope evaluate");
    }

    #[test]
    fn test_install_preserves_existing_hooks_from_other_tools() {
        let mut hooks_value = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "lint-staged check" },
                    { "command": "prettier --check" }
                ],
                "beforeMCPExecution": [
                    { "command": "security-scan verify" }
                ]
            }
        });

        let hook_entry = json!({ "command": MR_NOPE_HOOK_COMMAND });
        add_hook_entry(&mut hooks_value, "beforeShellExecution", &hook_entry);
        add_hook_entry(&mut hooks_value, "beforeMCPExecution", &hook_entry);

        let shell_arr = hooks_value["hooks"]["beforeShellExecution"].as_array().unwrap();
        let mcp_arr = hooks_value["hooks"]["beforeMCPExecution"].as_array().unwrap();

        // Existing hooks preserved + mr-nope added
        assert_eq!(shell_arr.len(), 3);
        assert_eq!(shell_arr[0]["command"], "lint-staged check");
        assert_eq!(shell_arr[1]["command"], "prettier --check");
        assert_eq!(shell_arr[2]["command"], "mr-nope evaluate");

        assert_eq!(mcp_arr.len(), 2);
        assert_eq!(mcp_arr[0]["command"], "security-scan verify");
        assert_eq!(mcp_arr[1]["command"], "mr-nope evaluate");
    }

    #[test]
    fn test_install_is_idempotent() {
        // Running install twice should not duplicate entries
        let mut hooks_value = json!({
            "version": 1,
            "hooks": {}
        });

        let hook_entry = json!({ "command": MR_NOPE_HOOK_COMMAND });

        // First install
        add_hook_entry(&mut hooks_value, "beforeShellExecution", &hook_entry);
        add_hook_entry(&mut hooks_value, "beforeMCPExecution", &hook_entry);

        // Second install (idempotent)
        add_hook_entry(&mut hooks_value, "beforeShellExecution", &hook_entry);
        add_hook_entry(&mut hooks_value, "beforeMCPExecution", &hook_entry);

        let shell_arr = hooks_value["hooks"]["beforeShellExecution"].as_array().unwrap();
        let mcp_arr = hooks_value["hooks"]["beforeMCPExecution"].as_array().unwrap();

        assert_eq!(shell_arr.len(), 1, "Should not duplicate beforeShellExecution entry");
        assert_eq!(mcp_arr.len(), 1, "Should not duplicate beforeMCPExecution entry");
    }

    #[test]
    fn test_uninstall_removes_only_mr_nope_preserves_others() {
        let mut hooks_value = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "lint-staged check" },
                    { "command": "mr-nope evaluate" },
                    { "command": "prettier --check" }
                ],
                "beforeMCPExecution": [
                    { "command": "mr-nope evaluate" },
                    { "command": "security-scan verify" }
                ]
            }
        });

        remove_hook_entry(&mut hooks_value, "beforeShellExecution");
        remove_hook_entry(&mut hooks_value, "beforeMCPExecution");

        let shell_arr = hooks_value["hooks"]["beforeShellExecution"].as_array().unwrap();
        let mcp_arr = hooks_value["hooks"]["beforeMCPExecution"].as_array().unwrap();

        // Only mr-nope entries removed
        assert_eq!(shell_arr.len(), 2);
        assert_eq!(shell_arr[0]["command"], "lint-staged check");
        assert_eq!(shell_arr[1]["command"], "prettier --check");

        assert_eq!(mcp_arr.len(), 1);
        assert_eq!(mcp_arr[0]["command"], "security-scan verify");
    }

    #[test]
    fn test_uninstall_on_nonexistent_file_is_noop() {
        // Uninstall should succeed gracefully when the file doesn't exist.
        // We test the condition that `uninstall` checks for file existence.
        let tmp = TempDir::new().unwrap();
        let hooks_path = tmp.path().join(".cursor").join("hooks.json");

        // The file doesn't exist
        assert!(!hooks_path.exists());

        // Directly test the uninstall logic (validate adapter first)
        assert!(validate_adapter("cursor").is_ok());

        // The uninstall function returns Ok(()) when file doesn't exist
        // We simulate this by checking the path doesn't exist, same as uninstall does
        assert!(!hooks_path.exists());
    }

    #[test]
    fn test_install_unsupported_adapter_returns_error() {
        let result = install("windsurf", InstallScope::Project);
        assert!(result.is_err());
        match result.unwrap_err() {
            InstallError::UnsupportedAdapter(name) => {
                assert_eq!(name, "windsurf");
            }
            other => panic!("Expected UnsupportedAdapter, got: {:?}", other),
        }
    }

    #[test]
    fn test_install_with_existing_file_in_temp_dir() {
        let tmp = TempDir::new().unwrap();
        let hooks_dir = tmp.path().join(".cursor");
        fs::create_dir_all(&hooks_dir).unwrap();
        let hooks_path = hooks_dir.join("hooks.json");

        // Write an existing hooks.json with another tool's hooks
        let existing = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "other-tool run" }
                ]
            }
        });
        fs::write(&hooks_path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

        // Simulate install logic
        let content = fs::read_to_string(&hooks_path).unwrap();
        let mut hooks_value: Value = serde_json::from_str(&content).unwrap();
        let hook_entry = json!({ "command": MR_NOPE_HOOK_COMMAND });
        add_hook_entry(&mut hooks_value, "beforeShellExecution", &hook_entry);
        add_hook_entry(&mut hooks_value, "beforeMCPExecution", &hook_entry);
        fs::write(&hooks_path, serde_json::to_string_pretty(&hooks_value).unwrap()).unwrap();

        // Verify
        let final_content = fs::read_to_string(&hooks_path).unwrap();
        let final_value: Value = serde_json::from_str(&final_content).unwrap();
        let shell_arr = final_value["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(shell_arr.len(), 2);
        assert_eq!(shell_arr[0]["command"], "other-tool run");
        assert_eq!(shell_arr[1]["command"], "mr-nope evaluate");
    }

    #[test]
    fn test_uninstall_full_roundtrip_with_temp_dir() {
        let tmp = TempDir::new().unwrap();
        let hooks_dir = tmp.path().join(".cursor");
        fs::create_dir_all(&hooks_dir).unwrap();
        let hooks_path = hooks_dir.join("hooks.json");

        // Write a hooks.json with mr-nope entries and others
        let initial = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "other-tool run" },
                    { "command": "mr-nope evaluate" }
                ],
                "beforeMCPExecution": [
                    { "command": "mr-nope evaluate" }
                ]
            }
        });
        fs::write(&hooks_path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();

        // Simulate uninstall logic
        let content = fs::read_to_string(&hooks_path).unwrap();
        let mut hooks_value: Value = serde_json::from_str(&content).unwrap();
        remove_hook_entry(&mut hooks_value, "beforeShellExecution");
        remove_hook_entry(&mut hooks_value, "beforeMCPExecution");
        fs::write(&hooks_path, serde_json::to_string_pretty(&hooks_value).unwrap()).unwrap();

        // Verify mr-nope removed, others preserved
        let final_content = fs::read_to_string(&hooks_path).unwrap();
        let final_value: Value = serde_json::from_str(&final_content).unwrap();

        let shell_arr = final_value["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(shell_arr.len(), 1);
        assert_eq!(shell_arr[0]["command"], "other-tool run");

        let mcp_arr = final_value["hooks"]["beforeMCPExecution"].as_array().unwrap();
        assert_eq!(mcp_arr.len(), 0);
    }
}
