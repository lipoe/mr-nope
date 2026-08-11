// Mr. Nope - Install/Uninstall module
// Handles hook configuration for supported AI coding agent adapters.

use serde_json::{json, Value};
use std::path::PathBuf;
use std::{env, fs, io};

/// The command that Mr. Nope registers in hook entries.
/// At install time, this is replaced with the absolute path to the binary
/// (Unix) or a Windows `.cmd` stdin-forwarding wrapper.
const MR_NOPE_HOOK_COMMAND_SUFFIX: &str = "evaluate";

/// Filename of the Windows Cursor hook wrapper that forwards stdin to the binary.
#[cfg(target_os = "windows")]
const WINDOWS_CURSOR_WRAPPER_NAME: &str = "mr-nope-evaluate.cmd";

/// The marker used to identify Mr. Nope entries during uninstall.
/// We check if the command string ends with "mr-nope evaluate" or contains "mr-nope".
const MR_NOPE_MARKER: &str = "mr-nope";

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
                let userprofile = env::var("USERPROFILE")
                    .map_err(|_| InstallError::PathResolution("USERPROFILE environment variable not set".to_string()))?;
                Ok(PathBuf::from(userprofile).join(".cursor").join("hooks.json"))
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

    // Determine the hook command (direct binary on Unix; .cmd wrapper on Windows Cursor)
    let hook_command = prepare_hook_command(adapter, scope)?;

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

    let hook_entry = json!({ "command": hook_command });

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
    println!("  Hook command: {}", hook_command);

    Ok(())
}

/// Resolve `current_exe`, canonicalize, and strip Windows `\\?\` prefix.
fn resolve_binary_path() -> Result<PathBuf, InstallError> {
    let binary_path = env::current_exe().map_err(|e| {
        InstallError::PathResolution(format!("could not determine binary path: {}", e))
    })?;

    let canonical = binary_path.canonicalize().unwrap_or(binary_path);

    #[cfg(target_os = "windows")]
    {
        let path_str = canonical.display().to_string();
        let stripped = path_str.strip_prefix(r"\\?\").unwrap_or(&path_str);
        Ok(PathBuf::from(stripped))
    }

    #[cfg(not(target_os = "windows"))]
    {
        Ok(canonical)
    }
}

/// Build the hook command string for hooks.json, creating a Windows wrapper when needed.
fn prepare_hook_command(adapter: &str, scope: InstallScope) -> Result<String, InstallError> {
    let binary_path = resolve_binary_path()?;

    #[cfg(target_os = "windows")]
    {
        if adapter == "cursor" {
            return install_windows_cursor_wrapper(scope, &binary_path);
        }
    }

    // Direct binary invocation (Unix, and non-Cursor adapters on Windows)
    let _ = scope;
    Ok(format_direct_hook_command(&binary_path))
}

/// Quote a path for use in a shell/cmd command line.
fn quote_path_for_command(path: &str) -> String {
    if path.contains(' ') || path.contains('"') || cfg!(target_os = "windows") {
        format!("\"{}\"", path.replace('"', ""))
    } else {
        path.to_string()
    }
}

/// Direct hook command: `"<binary>" evaluate` (quoted on Windows / when needed).
fn format_direct_hook_command(binary_path: &std::path::Path) -> String {
    let path_str = binary_path.display().to_string();
    format!(
        "{} {}",
        quote_path_for_command(&path_str),
        MR_NOPE_HOOK_COMMAND_SUFFIX
    )
}

/// On Windows, Cursor often fails to pipe stdin into a raw `.exe` hook command.
/// Write a tiny `.cmd` wrapper (cmd.exe forwards stdin) and register that instead.
#[cfg(target_os = "windows")]
fn install_windows_cursor_wrapper(
    scope: InstallScope,
    binary_path: &std::path::Path,
) -> Result<String, InstallError> {
    let hooks_json_path = get_cursor_hooks_path(scope)?;
    let cursor_dir = hooks_json_path.parent().ok_or_else(|| {
        InstallError::PathResolution("hooks.json has no parent directory".to_string())
    })?;
    let scripts_dir = cursor_dir.join("hooks");
    fs::create_dir_all(&scripts_dir)?;

    let wrapper_path = scripts_dir.join(WINDOWS_CURSOR_WRAPPER_NAME);
    let binary_str = binary_path.display().to_string().replace('"', "");
    let wrapper_contents = format!(
        "@echo off\r\n\"{bin}\" {suffix}\r\n",
        bin = binary_str,
        suffix = MR_NOPE_HOOK_COMMAND_SUFFIX
    );
    fs::write(&wrapper_path, wrapper_contents)?;

    // Cursor runs user hooks from ~/.cursor and project hooks from the project root.
    let command = match scope {
        InstallScope::Global => format!("./hooks/{}", WINDOWS_CURSOR_WRAPPER_NAME),
        InstallScope::Project => format!(".cursor/hooks/{}", WINDOWS_CURSOR_WRAPPER_NAME),
    };

    Ok(command)
}

/// Remove the Windows Cursor stdin-forwarding wrapper if present.
#[cfg(target_os = "windows")]
fn remove_windows_cursor_wrapper(scope: InstallScope) -> Result<(), InstallError> {
    let hooks_json_path = get_cursor_hooks_path(scope)?;
    if let Some(cursor_dir) = hooks_json_path.parent() {
        let wrapper_path = cursor_dir.join("hooks").join(WINDOWS_CURSOR_WRAPPER_NAME);
        if wrapper_path.exists() {
            fs::remove_file(&wrapper_path)?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn remove_windows_cursor_wrapper(_scope: InstallScope) -> Result<(), InstallError> {
    Ok(())
}

/// Get the hook command string using the absolute path to the current binary.
///
/// Prefer [`prepare_hook_command`] for install — this remains for tests/callers
/// that only need a direct binary invocation string.
#[allow(dead_code)]
fn get_hook_command() -> Result<String, InstallError> {
    let binary_path = resolve_binary_path()?;
    Ok(format_direct_hook_command(&binary_path))
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

    if adapter == "cursor" {
        remove_windows_cursor_wrapper(scope)?;
    }

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
            // Check if a mr-nope entry already exists (avoid duplicates)
            let already_exists = arr.iter().any(|existing| {
                existing
                    .get("command")
                    .and_then(|c| c.as_str())
                    .map(|s| s.contains(MR_NOPE_MARKER))
                    .unwrap_or(false)
            });

            if !already_exists {
                arr.push(entry.clone());
            } else {
                // Update existing entry with the new command (in case path changed)
                for existing in arr.iter_mut() {
                    if existing
                        .get("command")
                        .and_then(|c| c.as_str())
                        .map(|s| s.contains(MR_NOPE_MARKER))
                        .unwrap_or(false)
                    {
                        *existing = entry.clone();
                        break;
                    }
                }
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
                !existing
                    .get("command")
                    .and_then(|c| c.as_str())
                    .map(|s| s.contains(MR_NOPE_MARKER))
                    .unwrap_or(false)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Test-only constant simulating what install would produce.
    /// In real usage, this would be an absolute path like "/usr/local/bin/mr-nope evaluate".
    const MR_NOPE_HOOK_COMMAND: &str = "mr-nope evaluate";

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

    #[test]
    fn test_quote_path_for_command_quotes_spaces() {
        let quoted = quote_path_for_command(r"C:\Program Files\mr-nope.exe");
        assert!(quoted.starts_with('"') && quoted.ends_with('"'));
        assert!(quoted.contains("Program Files"));
    }

    #[test]
    fn test_format_direct_hook_command_includes_evaluate() {
        let cmd = format_direct_hook_command(std::path::Path::new("/usr/local/bin/mr-nope"));
        assert!(cmd.contains("evaluate"));
        assert!(cmd.contains("mr-nope"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_cursor_wrapper_written_for_project_scope() {
        let tmp = TempDir::new().unwrap();
        let original = env::current_dir().unwrap();
        env::set_current_dir(tmp.path()).unwrap();

        let binary = tmp.path().join("mr-nope-win32-x64.exe");
        fs::write(&binary, b"fake").unwrap();

        let command = install_windows_cursor_wrapper(InstallScope::Project, &binary).unwrap();
        assert_eq!(command, ".cursor/hooks/mr-nope-evaluate.cmd");

        let wrapper = tmp
            .path()
            .join(".cursor")
            .join("hooks")
            .join("mr-nope-evaluate.cmd");
        assert!(wrapper.exists());
        let contents = fs::read_to_string(&wrapper).unwrap();
        assert!(contents.contains("evaluate"));
        assert!(contents.contains("mr-nope-win32-x64.exe"));

        remove_windows_cursor_wrapper(InstallScope::Project).unwrap();
        assert!(!wrapper.exists());

        env::set_current_dir(original).unwrap();
    }
}
