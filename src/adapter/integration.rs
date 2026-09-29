// Mr. Nope - Agent integration capability
//
// A single, domain-independent abstraction for "integrate Mr. Nope with an AI
// coding agent's hook system". It captures the axes that genuinely differ
// between agents so that the install / uninstall / status / evaluate flows stay
// fully agent-agnostic — no `match adapter` or `if adapter == "..."` in shared
// code. Adding a new agent means adding one `AgentIntegration` implementation,
// never editing the shared flows.
//
// The axes that actually vary between agents:
//   1. Where the hook configuration lives on disk (`hook_config_path`).
//   2. How installation mutates that configuration (`install` / `uninstall`) —
//      e.g. merge into a shared `hooks.json` vs. own a dedicated hook file.
//   3. How a decision is transported back to the agent (`emit_decision`) —
//      e.g. a JSON response on stdout vs. a process exit code with stderr.
//   4. How the agent's stdin payload maps to the shared `HookInput`
//      (`parse_stdin`).
//
// Everything the agents share (policy discovery, the Normalizer -> Parser ->
// PolicyEngine pipeline, string extraction, deny messaging) stays in the
// stable core and is reused unchanged.

use crate::adapter::cursor::CursorAdapter;
use crate::adapter::kiro::{KiroAdapter, KiroHookPayload};
use crate::adapter::{Adapter, HookInput, HookResponse, Permission};
use crate::engine::PolicyEngine;
use serde_json::{Value, json};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::{env, fs};

/// Process exit code meaning "allow the tool call".
pub const EXIT_ALLOW: i32 = 0;
/// Process exit code used by agents that block via exit status.
pub const EXIT_BLOCK: i32 = 2;

/// The installation scope for hook configuration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstallScope {
    /// Project-level: config inside the current working directory.
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
    /// Failed to parse existing hook configuration.
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
                    supported_adapter_names().join(", ")
                )
            }
            InstallError::PathResolution(msg) => {
                write!(f, "could not determine hook configuration path: {}", msg)
            }
            InstallError::Io(err) => write!(f, "I/O error: {}", err),
            InstallError::JsonParse(msg) => {
                write!(f, "failed to parse existing hook configuration: {}", msg)
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

/// The generic capability: integrate Mr. Nope with one AI coding agent.
///
/// Implementations describe *how* a specific agent is wired up; the shared CLI
/// flows only ever talk to this trait.
pub trait AgentIntegration {
    /// The adapter name used on the CLI (e.g. `cursor`, `kiro`).
    fn name(&self) -> &'static str;

    /// The path to this agent's hook configuration for the given scope.
    ///
    /// Used both by install/uninstall and by `status` (to detect a Mr. Nope
    /// entry via [`is_installed_at`]).
    fn hook_config_path(&self, scope: InstallScope) -> Result<PathBuf, InstallError>;

    /// Install the Mr. Nope hook into this agent's configuration.
    fn install(&self, scope: InstallScope) -> Result<(), InstallError>;

    /// Remove the Mr. Nope hook from this agent's configuration.
    fn uninstall(&self, scope: InstallScope) -> Result<(), InstallError>;

    /// Map the agent's raw stdin payload into the shared [`HookInput`].
    ///
    /// Returns `Err(reason)` if the payload cannot be parsed; the caller
    /// fail-closes (denies) with that reason.
    fn parse_stdin(&self, stdin: &str) -> Result<HookInput, String>;

    /// Build the runtime [`Adapter`] used to evaluate a parsed hook input.
    fn build_adapter(&self, engine: PolicyEngine) -> Box<dyn Adapter>;

    /// Communicate a decision back to the agent, returning the process exit
    /// code the `evaluate` entry point should exit with.
    ///
    /// Different agents use different transports (stdout JSON vs. exit code +
    /// stderr); this method owns that difference entirely.
    fn emit_decision(&self, response: &HookResponse) -> i32;
}

/// Look up an agent integration by CLI name.
pub fn integration(name: &str) -> Result<Box<dyn AgentIntegration>, InstallError> {
    match name {
        "cursor" => Ok(Box::new(CursorIntegration)),
        "kiro" => Ok(Box::new(KiroIntegration)),
        other => Err(InstallError::UnsupportedAdapter(other.to_string())),
    }
}

/// Every supported integration, in display order. This is the single source of
/// truth for `status` (which reports each) and for supported-name listings.
pub fn all_integrations() -> Vec<Box<dyn AgentIntegration>> {
    vec![Box::new(CursorIntegration), Box::new(KiroIntegration)]
}

/// The names of all supported adapters.
pub fn supported_adapter_names() -> Vec<&'static str> {
    all_integrations().iter().map(|i| i.name()).collect()
}

/// The marker used to detect a Mr. Nope entry in any agent's hook config.
const MR_NOPE_MARKER: &str = "mr-nope";

/// Whether a Mr. Nope hook entry is present in the config file at `path`.
///
/// Agent-agnostic: a file "contains" Mr. Nope if the literal marker appears.
/// Works for both Cursor's `hooks.json` and Kiro's dedicated hook file.
pub fn is_installed_at(path: &Path) -> bool {
    match fs::read_to_string(path) {
        Ok(content) => content.contains(MR_NOPE_MARKER),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Shared helpers used by concrete integrations
// ---------------------------------------------------------------------------

/// Resolve the user's home directory (`%USERPROFILE%` on Windows, `HOME` else).
fn home_dir() -> Result<PathBuf, InstallError> {
    #[cfg(target_os = "windows")]
    let key = "USERPROFILE";
    #[cfg(not(target_os = "windows"))]
    let key = "HOME";

    env::var(key)
        .map(PathBuf::from)
        .map_err(|_| InstallError::PathResolution(format!("{} environment variable not set", key)))
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

/// Quote a path for use in a shell/cmd command line.
fn quote_path_for_command(path: &str) -> String {
    if path.contains(' ') || path.contains('"') || cfg!(target_os = "windows") {
        format!("\"{}\"", path.replace('"', ""))
    } else {
        path.to_string()
    }
}

/// Read a JSON file if it exists, else return `None`.
fn read_json_if_exists(path: &Path) -> Result<Option<Value>, InstallError> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    let value = serde_json::from_str::<Value>(&content)
        .map_err(|e| InstallError::JsonParse(e.to_string()))?;
    Ok(Some(value))
}

/// Pretty-print a JSON value and write it to `path`, creating parent dirs.
fn write_json(path: &Path, value: &Value) -> Result<(), InstallError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json_string =
        serde_json::to_string_pretty(value).map_err(|e| InstallError::JsonParse(e.to_string()))?;
    fs::write(path, json_string)?;
    Ok(())
}

// ===========================================================================
// Cursor integration
// ===========================================================================

/// Filename of the Windows Cursor hook wrapper that forwards stdin to the binary.
#[cfg(target_os = "windows")]
const WINDOWS_CURSOR_WRAPPER_NAME: &str = "mr-nope-evaluate.cmd";

/// Integrates Mr. Nope with Cursor.
///
/// Cursor keeps all hooks in a single shared `hooks.json`, so install merges a
/// Mr. Nope entry into the `beforeShellExecution` and `beforeMCPExecution`
/// arrays (and uninstall removes only those). Decisions are transported as a
/// JSON `HookResponse` on stdout; the process always exits 0.
pub struct CursorIntegration;

impl CursorIntegration {
    /// Direct hook command: `"<binary>" evaluate` (quoted on Windows/when needed).
    #[cfg(not(target_os = "windows"))]
    fn direct_hook_command(binary_path: &Path) -> String {
        format!(
            "{} evaluate --adapter cursor",
            quote_path_for_command(&binary_path.display().to_string())
        )
    }

    /// Build the hook command string, creating a Windows wrapper when needed.
    fn prepare_hook_command(&self, scope: InstallScope) -> Result<String, InstallError> {
        let binary_path = resolve_binary_path()?;
        #[cfg(target_os = "windows")]
        {
            return self.install_windows_wrapper(scope, &binary_path);
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = scope;
            Ok(Self::direct_hook_command(&binary_path))
        }
    }

    /// On Windows, Cursor often fails to pipe stdin into a raw `.exe` hook
    /// command. Write a tiny `.cmd` wrapper (cmd.exe forwards stdin) and
    /// register that instead.
    #[cfg(target_os = "windows")]
    fn install_windows_wrapper(
        &self,
        scope: InstallScope,
        binary_path: &Path,
    ) -> Result<String, InstallError> {
        let hooks_json_path = self.hook_config_path(scope)?;
        let cursor_dir = hooks_json_path.parent().ok_or_else(|| {
            InstallError::PathResolution("hooks.json has no parent directory".to_string())
        })?;
        let scripts_dir = cursor_dir.join("hooks");
        fs::create_dir_all(&scripts_dir)?;

        let wrapper_path = scripts_dir.join(WINDOWS_CURSOR_WRAPPER_NAME);
        let binary_str = binary_path.display().to_string().replace('"', "");
        let wrapper_contents = format!(
            "@echo off\r\n\"{bin}\" evaluate --adapter cursor\r\n",
            bin = binary_str
        );
        fs::write(&wrapper_path, wrapper_contents)?;

        let command = match scope {
            InstallScope::Global => format!("./hooks/{}", WINDOWS_CURSOR_WRAPPER_NAME),
            InstallScope::Project => format!(".cursor/hooks/{}", WINDOWS_CURSOR_WRAPPER_NAME),
        };
        Ok(command)
    }

    #[cfg(target_os = "windows")]
    fn remove_windows_wrapper(&self, scope: InstallScope) -> Result<(), InstallError> {
        let hooks_json_path = self.hook_config_path(scope)?;
        if let Some(cursor_dir) = hooks_json_path.parent() {
            let wrapper_path = cursor_dir.join("hooks").join(WINDOWS_CURSOR_WRAPPER_NAME);
            if wrapper_path.exists() {
                fs::remove_file(&wrapper_path)?;
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn remove_windows_wrapper(&self, _scope: InstallScope) -> Result<(), InstallError> {
        Ok(())
    }
}

/// Add a Mr. Nope hook entry to a named hook array, avoiding duplicates.
///
/// If an entry already exists, it is refreshed (in case the binary path
/// changed) rather than duplicated.
fn cursor_add_hook_entry(hooks_value: &mut Value, hook_name: &str, entry: &Value) {
    let Some(hooks) = hooks_value.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return;
    };
    let arr = hooks.entry(hook_name).or_insert_with(|| json!([]));
    let Some(arr) = arr.as_array_mut() else {
        return;
    };

    let is_mr_nope = |v: &Value| {
        v.get("command")
            .and_then(|c| c.as_str())
            .map(|s| s.contains(MR_NOPE_MARKER))
            .unwrap_or(false)
    };

    if let Some(existing) = arr.iter_mut().find(|v| is_mr_nope(v)) {
        *existing = entry.clone();
    } else {
        arr.push(entry.clone());
    }
}

/// Remove Mr. Nope hook entries from a named hook array.
fn cursor_remove_hook_entry(hooks_value: &mut Value, hook_name: &str) {
    if let Some(hooks) = hooks_value.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        if let Some(arr) = hooks.get_mut(hook_name).and_then(|v| v.as_array_mut()) {
            arr.retain(|v| {
                !v.get("command")
                    .and_then(|c| c.as_str())
                    .map(|s| s.contains(MR_NOPE_MARKER))
                    .unwrap_or(false)
            });
        }
    }
}

impl AgentIntegration for CursorIntegration {
    fn name(&self) -> &'static str {
        "cursor"
    }

    fn hook_config_path(&self, scope: InstallScope) -> Result<PathBuf, InstallError> {
        match scope {
            InstallScope::Project => {
                let cwd =
                    env::current_dir().map_err(|e| InstallError::PathResolution(e.to_string()))?;
                Ok(cwd.join(".cursor").join("hooks.json"))
            }
            InstallScope::Global => Ok(home_dir()?.join(".cursor").join("hooks.json")),
        }
    }

    fn install(&self, scope: InstallScope) -> Result<(), InstallError> {
        let hooks_path = self.hook_config_path(scope)?;
        let hook_command = self.prepare_hook_command(scope)?;

        let mut hooks_value = read_json_if_exists(&hooks_path)?
            .unwrap_or_else(|| json!({ "version": 1, "hooks": {} }));

        if hooks_value.get("hooks").is_none() {
            hooks_value["hooks"] = json!({});
        }
        if hooks_value.get("version").is_none() {
            hooks_value["version"] = json!(1);
        }

        let hook_entry = json!({ "command": hook_command });
        cursor_add_hook_entry(&mut hooks_value, "beforeShellExecution", &hook_entry);
        cursor_add_hook_entry(&mut hooks_value, "beforeMCPExecution", &hook_entry);

        write_json(&hooks_path, &hooks_value)?;

        println!(
            "✓ Mr. Nope installed for adapter 'cursor' at {} scope.",
            scope
        );
        println!("  Hook command: {}", hook_command);
        Ok(())
    }

    fn uninstall(&self, scope: InstallScope) -> Result<(), InstallError> {
        let hooks_path = self.hook_config_path(scope)?;

        let Some(mut hooks_value) = read_json_if_exists(&hooks_path)? else {
            println!(
                "ℹ Mr. Nope is not installed for adapter 'cursor' at {} scope (hooks file not found).",
                scope
            );
            return Ok(());
        };

        cursor_remove_hook_entry(&mut hooks_value, "beforeShellExecution");
        cursor_remove_hook_entry(&mut hooks_value, "beforeMCPExecution");
        write_json(&hooks_path, &hooks_value)?;

        self.remove_windows_wrapper(scope)?;

        println!(
            "✓ Mr. Nope uninstalled for adapter 'cursor' from {} scope.",
            scope
        );
        Ok(())
    }

    fn parse_stdin(&self, stdin: &str) -> Result<HookInput, String> {
        // Cursor sends a HookInput directly (tool_input is a JSON *string*).
        serde_json::from_str(stdin).map_err(|err| {
            let preview: String = stdin.chars().take(80).collect();
            format!(
                "malformed JSON input could not be parsed (stdin_len={}, error={}, preview={:?})",
                stdin.len(),
                err,
                preview
            )
        })
    }

    fn build_adapter(&self, engine: PolicyEngine) -> Box<dyn Adapter> {
        Box::new(CursorAdapter::new(engine))
    }

    fn emit_decision(&self, response: &HookResponse) -> i32 {
        write_notices(response);
        // Cursor reads a JSON HookResponse from stdout and always exits 0.
        match serde_json::to_string(response) {
            Ok(json) => println!("{}", json),
            Err(_) => println!(
                r#"{{"permission":"deny","userMessage":"🚫 Mr. Nope: DENIED — internal serialization error.","agentMessage":"Mr. Nope denied execution due to an internal error."}}"#
            ),
        }
        EXIT_ALLOW
    }
}

// ===========================================================================
// Kiro integration
// ===========================================================================

/// Filename of the dedicated Kiro hook file that Mr. Nope owns.
const KIRO_HOOK_FILE_NAME: &str = "mr-nope.json";

/// Regex matcher for the Kiro tool names Mr. Nope guards: shell execution and
/// file writes across CLI/IDE surfaces.
const KIRO_TOOL_MATCHER: &str = "execute_bash|shell|fs_write|write";

/// Integrates Mr. Nope with Kiro.
///
/// Kiro reads standalone hook files with a versioned schema, so Mr. Nope owns a
/// dedicated file (`mr-nope.json`): install (over)writes it and uninstall
/// deletes it — no merge, no risk of clobbering the user's other hooks.
/// Decisions are transported via the process exit code (0 = allow, 2 = block)
/// with the block reason on stderr.
pub struct KiroIntegration;

impl KiroIntegration {
    /// The command Kiro runs: `"<binary>" evaluate --adapter kiro`.
    fn hook_command(binary_path: &Path) -> String {
        format!(
            "{} evaluate --adapter kiro",
            quote_path_for_command(&binary_path.display().to_string())
        )
    }

    /// Build the JSON body of Mr. Nope's Kiro hook file: a single `PreToolUse`
    /// hook matching shell/write tools and running the evaluate command.
    fn hook_file(hook_command: &str) -> Value {
        json!({
            "version": "v1",
            "hooks": [
                {
                    "name": "Mr. Nope",
                    "trigger": "PreToolUse",
                    "matcher": KIRO_TOOL_MATCHER,
                    "action": { "type": "command", "command": hook_command }
                }
            ]
        })
    }
}

impl AgentIntegration for KiroIntegration {
    fn name(&self) -> &'static str {
        "kiro"
    }

    fn hook_config_path(&self, scope: InstallScope) -> Result<PathBuf, InstallError> {
        let base = match scope {
            InstallScope::Project => {
                env::current_dir().map_err(|e| InstallError::PathResolution(e.to_string()))?
            }
            InstallScope::Global => home_dir()?,
        };
        Ok(base.join(".kiro").join("hooks").join(KIRO_HOOK_FILE_NAME))
    }

    fn install(&self, scope: InstallScope) -> Result<(), InstallError> {
        let hook_path = self.hook_config_path(scope)?;
        let hook_command = Self::hook_command(&resolve_binary_path()?);

        write_json(&hook_path, &Self::hook_file(&hook_command))?;

        println!(
            "✓ Mr. Nope installed for adapter 'kiro' at {} scope.",
            scope
        );
        println!("  Hook file: {}", hook_path.display());
        println!("  Hook command: {}", hook_command);
        Ok(())
    }

    fn uninstall(&self, scope: InstallScope) -> Result<(), InstallError> {
        let hook_path = self.hook_config_path(scope)?;
        if !hook_path.exists() {
            println!(
                "ℹ Mr. Nope is not installed for adapter 'kiro' at {} scope (hook file not found).",
                scope
            );
            return Ok(());
        }
        fs::remove_file(&hook_path)?;
        println!(
            "✓ Mr. Nope uninstalled for adapter 'kiro' from {} scope.",
            scope
        );
        Ok(())
    }

    fn parse_stdin(&self, stdin: &str) -> Result<HookInput, String> {
        // Kiro sends a PreToolUse payload (tool_input is a JSON *object*).
        let payload: KiroHookPayload = serde_json::from_str(stdin).map_err(|err| {
            let preview: String = stdin.chars().take(80).collect();
            format!(
                "malformed JSON input could not be parsed (stdin_len={}, error={}, preview={:?})",
                stdin.len(),
                err,
                preview
            )
        })?;
        Ok(payload.into_hook_input())
    }

    fn build_adapter(&self, engine: PolicyEngine) -> Box<dyn Adapter> {
        Box::new(KiroAdapter::new(engine))
    }

    fn emit_decision(&self, response: &HookResponse) -> i32 {
        write_notices(response);
        match response.permission {
            Permission::Allow => EXIT_ALLOW,
            Permission::Deny => {
                // Prefer the agent-facing message; Kiro forwards stderr to the model.
                let message = response
                    .agent_message
                    .as_deref()
                    .or(response.user_message.as_deref())
                    .unwrap_or("Mr. Nope denied this action.");
                let _ = writeln!(io::stderr(), "{}", message);
                EXIT_BLOCK
            }
        }
    }
}

/// Write parse-error notes. They are not the block message.
fn write_notices(response: &HookResponse) {
    for notice in &response.notices {
        let _ = writeln!(io::stderr(), "{notice}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_integration_lookup_known() {
        assert_eq!(integration("cursor").ok().map(|i| i.name()), Some("cursor"));
        assert_eq!(integration("kiro").ok().map(|i| i.name()), Some("kiro"));
    }

    #[test]
    fn test_integration_lookup_unknown() {
        match integration("windsurf") {
            Err(InstallError::UnsupportedAdapter(n)) => assert_eq!(n, "windsurf"),
            _ => panic!("expected UnsupportedAdapter error"),
        }
    }

    #[test]
    fn test_supported_names() {
        let names = supported_adapter_names();
        assert!(names.contains(&"cursor"));
        assert!(names.contains(&"kiro"));
    }

    #[test]
    fn test_scope_display() {
        assert_eq!(format!("{}", InstallScope::Project), "project");
        assert_eq!(format!("{}", InstallScope::Global), "global");
    }

    #[test]
    fn test_is_installed_at_detects_marker() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        fs::write(&path, r#"{"hooks":{"x":[{"command":"mr-nope evaluate"}]}}"#).unwrap();
        assert!(is_installed_at(&path));
    }

    #[test]
    fn test_is_installed_at_absent_or_no_marker() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("nope.json");
        assert!(!is_installed_at(&missing));

        let path = dir.path().join("hooks.json");
        fs::write(&path, r#"{"hooks":{"x":[{"command":"other-tool"}]}}"#).unwrap();
        assert!(!is_installed_at(&path));
    }

    // --- Cursor merge logic ---

    #[test]
    fn test_cursor_add_hook_entry_to_empty() {
        let mut hooks = json!({ "version": 1, "hooks": {} });
        let entry = json!({ "command": "mr-nope evaluate --adapter cursor" });
        cursor_add_hook_entry(&mut hooks, "beforeShellExecution", &entry);
        let arr = hooks["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn test_cursor_add_hook_entry_preserves_existing_and_no_duplicate() {
        let mut hooks = json!({
            "version": 1,
            "hooks": { "beforeShellExecution": [{ "command": "other-tool check" }] }
        });
        let entry = json!({ "command": "mr-nope evaluate --adapter cursor" });
        cursor_add_hook_entry(&mut hooks, "beforeShellExecution", &entry);
        cursor_add_hook_entry(&mut hooks, "beforeShellExecution", &entry);
        let arr = hooks["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 2); // other-tool + single mr-nope
        assert_eq!(arr[0]["command"], "other-tool check");
    }

    #[test]
    fn test_cursor_remove_hook_entry_preserves_others() {
        let mut hooks = json!({
            "version": 1,
            "hooks": { "beforeShellExecution": [
                { "command": "other-tool check" },
                { "command": "mr-nope evaluate" }
            ] }
        });
        cursor_remove_hook_entry(&mut hooks, "beforeShellExecution");
        let arr = hooks["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["command"], "other-tool check");
    }

    // --- Kiro hook file ---

    #[test]
    fn test_kiro_hook_file_structure() {
        let hook = KiroIntegration::hook_file("mr-nope evaluate --adapter kiro");
        assert_eq!(hook["version"], "v1");
        let entry = &hook["hooks"][0];
        assert_eq!(entry["name"], "Mr. Nope");
        assert_eq!(entry["trigger"], "PreToolUse");
        assert_eq!(entry["matcher"], KIRO_TOOL_MATCHER);
        assert_eq!(entry["action"]["type"], "command");
        assert!(
            entry["action"]["command"]
                .as_str()
                .unwrap()
                .contains("--adapter kiro")
        );
    }

    #[test]
    fn test_kiro_command_includes_adapter_flag() {
        let cmd = KiroIntegration::hook_command(Path::new("/usr/local/bin/mr-nope"));
        assert!(cmd.contains("evaluate"));
        assert!(cmd.contains("--adapter kiro"));
    }

    // --- parse_stdin per agent ---

    #[test]
    fn test_cursor_parse_stdin_reads_hookinput() {
        let input = CursorIntegration
            .parse_stdin(r#"{"hook_event_name":"beforeShellExecution","command":"git push"}"#)
            .unwrap();
        assert_eq!(input.command.as_deref(), Some("git push"));
    }

    #[test]
    fn test_kiro_parse_stdin_reads_payload() {
        let input = KiroIntegration
            .parse_stdin(r#"{"tool_name":"execute_bash","tool_input":{"command":"git push"}}"#)
            .unwrap();
        assert_eq!(input.command.as_deref(), Some("git push"));
    }

    #[test]
    fn test_parse_stdin_malformed_is_err() {
        assert!(CursorIntegration.parse_stdin("not json {{{").is_err());
        assert!(KiroIntegration.parse_stdin("not json {{{").is_err());
    }

    // --- emit_decision transports ---

    #[test]
    fn test_cursor_emit_always_allows_exit_code() {
        let allow = HookResponse {
            permission: Permission::Allow,
            user_message: None,
            agent_message: None,
            notices: Vec::new(),
        };
        let deny = HookResponse {
            permission: Permission::Deny,
            user_message: Some("blocked".to_string()),
            agent_message: Some("blocked".to_string()),
            notices: Vec::new(),
        };
        // Cursor exits 0 regardless; the decision rides in the stdout JSON.
        assert_eq!(CursorIntegration.emit_decision(&allow), EXIT_ALLOW);
        assert_eq!(CursorIntegration.emit_decision(&deny), EXIT_ALLOW);
    }

    #[test]
    fn test_kiro_emit_uses_exit_codes() {
        let allow = HookResponse {
            permission: Permission::Allow,
            user_message: None,
            agent_message: None,
            notices: Vec::new(),
        };
        let deny = HookResponse {
            permission: Permission::Deny,
            user_message: Some("blocked".to_string()),
            agent_message: Some("blocked".to_string()),
            notices: Vec::new(),
        };
        assert_eq!(KiroIntegration.emit_decision(&allow), EXIT_ALLOW);
        assert_eq!(KiroIntegration.emit_decision(&deny), EXIT_BLOCK);
    }

    #[test]
    fn test_hook_response_json_omits_notices() {
        let response = HookResponse {
            permission: Permission::Allow,
            user_message: None,
            agent_message: None,
            notices: vec!["mr-nope: parse_error context=tool_input kind=UnclosedQuote action=allow preview=\"x\"".to_string()],
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("notices"));
        assert!(!json.contains("parse_error"));
        assert!(json.contains("\"permission\":\"allow\""));
    }
}
