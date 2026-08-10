// Mr. Nope - CLI module
// Defines CLI commands using clap: install, uninstall, status, test, policy, evaluate.

pub mod evaluate;
pub mod install;
pub mod policy;
pub mod status;
pub mod test_cmd;

use clap::{Parser, Subcommand};

const SECURITY_SCOPE: &str = "\
SECURITY SCOPE:\n  \
• Mr. Nope only prevents execution via supported hook paths of the integrated AI coding agent.\n  \
• Mr. Nope does not prevent a human user from running forbidden commands directly in a terminal.\n  \
• Mr. Nope is not a system-wide sandbox or a replacement for OS-level access controls.";

#[derive(Parser)]
#[command(
    name = "mr-nope",
    about = "Deterministic guardrail tool for AI coding agents. Evaluates commands against a YAML-based deny-list policy before execution.",
    after_help = SECURITY_SCOPE
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Install Mr. Nope hooks for an AI coding agent adapter
    Install {
        /// Adapter name (e.g., cursor)
        adapter: String,

        /// Install at the project level (current directory only)
        #[arg(long)]
        project: bool,

        /// Install at the user level (global)
        #[arg(long)]
        global: bool,
    },

    /// Uninstall Mr. Nope hooks for an AI coding agent adapter
    Uninstall {
        /// Adapter name (e.g., cursor)
        adapter: String,

        /// Uninstall from the project level (current directory only)
        #[arg(long)]
        project: bool,

        /// Uninstall from the user level (global)
        #[arg(long)]
        global: bool,
    },

    /// Display installation status and active adapters
    Status,

    /// Run policy self-test against all deny rules
    Test,

    /// Display the active policy rules
    Policy,

    /// Hook entry point: reads JSON from stdin, writes decision to stdout
    Evaluate,
}
