// Mr. Nope - Status command
// Detects installed adapters by checking hook configuration file locations.

use std::fs;
use std::path::PathBuf;

/// Represents the installation state of an adapter at a particular scope.
#[derive(Debug, Clone, PartialEq)]
pub enum InstallState {
    Installed,
    NotInstalled,
}

impl std::fmt::Display for InstallState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallState::Installed => write!(f, "installed"),
            InstallState::NotInstalled => write!(f, "not installed"),
        }
    }
}

/// Status of a single adapter at both scopes.
#[derive(Debug, Clone, PartialEq)]
pub struct AdapterStatus {
    pub name: String,
    pub global: InstallState,
    pub project: InstallState,
}

/// The marker string that indicates Mr. Nope is installed in a hooks.json file.
const MR_NOPE_MARKER: &str = "mr-nope evaluate";

/// Returns the global hooks.json path for the Cursor adapter.
///
/// - macOS/Linux: `~/.cursor/hooks.json`
/// - Windows: `%APPDATA%\Cursor\hooks.json`
pub fn cursor_global_hooks_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok().map(|appdata| {
            PathBuf::from(appdata).join("Cursor").join("hooks.json")
        })
    }

    #[cfg(not(target_os = "windows"))]
    {
        dirs_path_home().map(|home| home.join(".cursor").join("hooks.json"))
    }
}

/// Returns the project-level hooks.json path for the Cursor adapter.
///
/// This is `.cursor/hooks.json` relative to the current working directory.
pub fn cursor_project_hooks_path() -> Option<PathBuf> {
    std::env::current_dir()
        .ok()
        .map(|cwd| cwd.join(".cursor").join("hooks.json"))
}

/// Check if a hooks.json file at the given path contains a Mr. Nope entry.
///
/// A hook is "installed" if the file exists and contains `"mr-nope evaluate"`.
pub fn is_installed_at(path: &PathBuf) -> InstallState {
    match fs::read_to_string(path) {
        Ok(content) => {
            if content.contains(MR_NOPE_MARKER) {
                InstallState::Installed
            } else {
                InstallState::NotInstalled
            }
        }
        Err(_) => InstallState::NotInstalled,
    }
}

/// Get the status of the Cursor adapter at both global and project scopes.
pub fn get_cursor_status() -> AdapterStatus {
    let global = cursor_global_hooks_path()
        .map(|p| is_installed_at(&p))
        .unwrap_or(InstallState::NotInstalled);

    let project = cursor_project_hooks_path()
        .map(|p| is_installed_at(&p))
        .unwrap_or(InstallState::NotInstalled);

    AdapterStatus {
        name: "cursor".to_string(),
        global,
        project,
    }
}

/// Execute the status command: display installation state and security scope.
pub fn run_status() {
    let cursor_status = get_cursor_status();

    println!("Mr. Nope Status:");
    println!();
    println!("Adapter: {}", cursor_status.name);
    println!("  Global: {}", cursor_status.global);
    println!("  Project: {}", cursor_status.project);
    println!();
    println!("SECURITY SCOPE:");
    println!("• Mr. Nope only prevents execution via supported hook paths of the integrated AI coding agent.");
    println!("• Mr. Nope does not prevent a human user from running forbidden commands directly in a terminal.");
    println!("• Mr. Nope is not a system-wide sandbox or a replacement for OS-level access controls.");
}

/// Helper to get the user's home directory without adding a dependency.
/// Uses the HOME environment variable on Unix and USERPROFILE on Windows.
#[cfg(not(target_os = "windows"))]
fn dirs_path_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_is_installed_at_nonexistent_file() {
        let path = PathBuf::from("/nonexistent/path/hooks.json");
        assert_eq!(is_installed_at(&path), InstallState::NotInstalled);
    }

    #[test]
    fn test_is_installed_at_file_without_marker() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, r#"{{"version": 1, "hooks": {{}}}}"#).unwrap();
        assert_eq!(is_installed_at(&path), InstallState::NotInstalled);
    }

    #[test]
    fn test_is_installed_at_file_with_marker() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        let mut file = fs::File::create(&path).unwrap();
        writeln!(
            file,
            r#"{{"version": 1, "hooks": {{"beforeShellExecution": [{{"command": "mr-nope evaluate"}}]}}}}"#
        )
        .unwrap();
        assert_eq!(is_installed_at(&path), InstallState::Installed);
    }

    #[test]
    fn test_install_state_display() {
        assert_eq!(format!("{}", InstallState::Installed), "installed");
        assert_eq!(format!("{}", InstallState::NotInstalled), "not installed");
    }

    #[test]
    fn test_status_detects_installed_hooks_in_temp_hooks_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        let mut file = fs::File::create(&path).unwrap();
        writeln!(
            file,
            r#"{{
                "version": 1,
                "hooks": {{
                    "beforeShellExecution": [{{"command": "mr-nope evaluate"}}],
                    "beforeMCPExecution": [{{"command": "mr-nope evaluate"}}]
                }}
            }}"#
        )
        .unwrap();
        assert_eq!(is_installed_at(&path), InstallState::Installed);
    }

    #[test]
    fn test_status_reports_not_installed_when_file_does_not_exist() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent").join("hooks.json");
        // File does not exist
        assert_eq!(is_installed_at(&path), InstallState::NotInstalled);
    }

    #[test]
    fn test_status_reports_not_installed_when_file_exists_but_no_mr_nope() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        let mut file = fs::File::create(&path).unwrap();
        // File exists with other hooks but not mr-nope
        writeln!(
            file,
            r#"{{
                "version": 1,
                "hooks": {{
                    "beforeShellExecution": [{{"command": "other-tool run"}}],
                    "beforeMCPExecution": [{{"command": "security-check verify"}}]
                }}
            }}"#
        )
        .unwrap();
        assert_eq!(is_installed_at(&path), InstallState::NotInstalled);
    }

    #[test]
    fn test_status_detects_marker_in_mcp_hook_only() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        let mut file = fs::File::create(&path).unwrap();
        // mr-nope marker only in beforeMCPExecution
        writeln!(
            file,
            r#"{{
                "version": 1,
                "hooks": {{
                    "beforeShellExecution": [{{"command": "other-tool run"}}],
                    "beforeMCPExecution": [{{"command": "mr-nope evaluate"}}]
                }}
            }}"#
        )
        .unwrap();
        assert_eq!(is_installed_at(&path), InstallState::Installed);
    }

    #[test]
    fn test_adapter_status_struct() {
        let status = AdapterStatus {
            name: "cursor".to_string(),
            global: InstallState::Installed,
            project: InstallState::NotInstalled,
        };
        assert_eq!(status.name, "cursor");
        assert_eq!(status.global, InstallState::Installed);
        assert_eq!(status.project, InstallState::NotInstalled);
    }
}
