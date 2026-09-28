// Mr. Nope - Install/Uninstall facade
//
// This module is a thin, agent-agnostic facade over the `AgentIntegration`
// capability (see `adapter::integration`). It contains no per-adapter logic:
// installing or uninstalling any supported agent is "look up the integration,
// then delegate". Adding a new agent never touches this file.

use crate::adapter::integration;

// Re-export the shared install types so existing call sites
// (`cli::install::InstallScope`, `cli::install::InstallError`) keep working.
pub use crate::adapter::integration::{InstallError, InstallScope};

/// Determine the hook configuration path for a given adapter and scope.
pub fn get_hooks_path(
    adapter: &str,
    scope: InstallScope,
) -> Result<std::path::PathBuf, InstallError> {
    integration::integration(adapter)?.hook_config_path(scope)
}

/// Install Mr. Nope hooks for the given adapter at the specified scope.
pub fn install(adapter: &str, scope: InstallScope) -> Result<(), InstallError> {
    integration::integration(adapter)?.install(scope)
}

/// Uninstall Mr. Nope hooks for the given adapter from the specified scope.
pub fn uninstall(adapter: &str, scope: InstallScope) -> Result<(), InstallError> {
    integration::integration(adapter)?.uninstall(scope)
}

/// The names of all supported adapters (single source of truth: the registry).
pub fn supported_adapters() -> Vec<&'static str> {
    integration::supported_adapter_names()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_adapters_lists_cursor_and_kiro() {
        let names = supported_adapters();
        assert!(names.contains(&"cursor"));
        assert!(names.contains(&"kiro"));
    }

    #[test]
    fn test_install_unsupported_adapter_errors() {
        let result = install("vscode", InstallScope::Global);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unsupported adapter"));
        assert!(msg.contains("vscode"));
    }

    #[test]
    fn test_uninstall_unsupported_adapter_errors() {
        assert!(uninstall("windsurf", InstallScope::Project).is_err());
    }

    #[test]
    fn test_get_hooks_path_delegates_to_integration() {
        // The facade delegates path resolution to the integration; a supported
        // adapter resolves, an unsupported one errors.
        assert!(get_hooks_path("cursor", InstallScope::Project).is_ok());
        assert!(get_hooks_path("kiro", InstallScope::Project).is_ok());
        assert!(get_hooks_path("windsurf", InstallScope::Project).is_err());
    }

    // Note: full install/uninstall roundtrips (which touch the real home or CWD)
    // are covered in adapter::integration's tests against isolated temp paths,
    // avoiding process-wide env/CWD mutation that would race under the parallel
    // test runner.
}
