// Mr. Nope - Deterministic guardrail tool for AI coding agents
// Evaluates commands against a YAML-based deny-list policy before execution.

use clap::Parser;
use mr_nope::cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Install {
            adapter,
            project,
            global,
        } => {
            let scope = if project {
                mr_nope::cli::install::InstallScope::Project
            } else if global {
                mr_nope::cli::install::InstallScope::Global
            } else {
                mr_nope::cli::install::InstallScope::Global
            };
            if let Err(e) = mr_nope::cli::install::install(&adapter, scope) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Uninstall {
            adapter,
            project,
            global,
        } => {
            let scope = if project {
                mr_nope::cli::install::InstallScope::Project
            } else if global {
                mr_nope::cli::install::InstallScope::Global
            } else {
                mr_nope::cli::install::InstallScope::Global
            };
            if let Err(e) = mr_nope::cli::install::uninstall(&adapter, scope) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Status => {
            mr_nope::cli::status::run_status();
        }
        Commands::Test => {
            let exit_code = mr_nope::cli::test_cmd::run_test();
            std::process::exit(exit_code);
        }
        Commands::Policy { scope } => {
            mr_nope::cli::policy::run_policy_command(scope.as_deref());
        }
        Commands::Evaluate => {
            mr_nope::cli::evaluate::run_evaluate();
        }
    }
}
