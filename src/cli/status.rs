// Mr. Nope - Status command
//
// Reports install state for every registered agent integration. This module
// contains no per-adapter logic: it iterates over the integration registry and
// asks each one where its hook configuration lives, then checks for a Mr. Nope
// marker there. Adding a new agent never touches this file.

use crate::adapter::integration::{self, is_installed_at, AgentIntegration, InstallScope};

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

/// Resolve the install state of one integration at one scope.
///
/// Any path-resolution failure is treated as "not installed" rather than an
/// error — status is best-effort reporting.
fn state_at(integration: &dyn AgentIntegration, scope: InstallScope) -> InstallState {
    match integration.hook_config_path(scope) {
        Ok(path) if is_installed_at(&path) => InstallState::Installed,
        _ => InstallState::NotInstalled,
    }
}

/// Compute the status of a single integration at both scopes.
fn status_of(integration: &dyn AgentIntegration) -> AdapterStatus {
    AdapterStatus {
        name: integration.name().to_string(),
        global: state_at(integration, InstallScope::Global),
        project: state_at(integration, InstallScope::Project),
    }
}

/// Compute the status of every registered adapter.
pub fn get_all_statuses() -> Vec<AdapterStatus> {
    integration::all_integrations()
        .iter()
        .map(|i| status_of(i.as_ref()))
        .collect()
}

/// Execute the status command: display installation state and security scope.
pub fn run_status() {
    println!("Mr. Nope Status:");
    println!();
    for status in get_all_statuses() {
        println!("Adapter: {}", status.name);
        println!("  Global: {}", status.global);
        println!("  Project: {}", status.project);
        println!();
    }
    println!("SECURITY SCOPE:");
    println!("• Mr. Nope only prevents execution via supported hook paths of the integrated AI coding agent.");
    println!("• Mr. Nope does not prevent a human user from running forbidden commands directly in a terminal.");
    println!("• Mr. Nope is not a system-wide sandbox or a replacement for OS-level access controls.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_state_display() {
        assert_eq!(format!("{}", InstallState::Installed), "installed");
        assert_eq!(format!("{}", InstallState::NotInstalled), "not installed");
    }

    #[test]
    fn test_get_all_statuses_covers_registered_adapters() {
        let statuses = get_all_statuses();
        let names: Vec<&str> = statuses.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"cursor"));
        assert!(names.contains(&"kiro"));
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
