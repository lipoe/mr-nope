// Mr. Nope - Adapter module
// Defines the Adapter trait and re-exports adapter implementations.

pub mod cursor;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Input received from the AI agent's hook mechanism.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HookInput {
    /// The name of the hook event (e.g., "beforeShellExecution", "beforeMCPExecution").
    #[serde(rename = "hook_event_name")]
    pub hook_event_name: String,
    /// The shell command to evaluate (present for shell execution hooks).
    #[serde(default)]
    pub command: Option<String>,
    /// The MCP tool name (present for MCP execution hooks).
    #[serde(default)]
    pub tool_name: Option<String>,
    /// The MCP tool input as a JSON string (present for MCP execution hooks).
    #[serde(default)]
    pub tool_input: Option<String>,
    /// The workspace root paths for the current project.
    #[serde(default)]
    pub workspace_roots: Vec<String>,
}

/// Response to return to the AI agent's hook mechanism.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookResponse {
    /// The permission decision.
    pub permission: Permission,
    /// Message displayed to the user (present on deny).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
    /// Message sent to the AI agent (present on deny).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_message: Option<String>,
}

/// The permission decision returned by an adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Allow,
    Deny,
}

/// Trait for AI agent adapters.
///
/// Each adapter handles hook events from a specific AI coding agent,
/// invoking the policy engine and returning the appropriate response.
pub trait Adapter {
    /// Process a hook event and return a response.
    fn handle_hook(&self, input: &HookInput) -> HookResponse;
}

/// Errors that can occur in adapter processing.
#[derive(Debug, Clone, PartialEq)]
pub enum AdapterError {
    /// The hook input JSON could not be parsed.
    MalformedInput(String),
    /// A required field is missing from the hook input.
    MissingField(String),
    /// An unknown hook event was received.
    UnknownEvent(String),
    /// The policy engine returned an error.
    PolicyError(String),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterError::MalformedInput(msg) => write!(f, "malformed input: {}", msg),
            AdapterError::MissingField(field) => write!(f, "missing required field: {}", field),
            AdapterError::UnknownEvent(event) => write!(f, "unknown hook event: {}", event),
            AdapterError::PolicyError(msg) => write!(f, "policy error: {}", msg),
        }
    }
}

impl std::error::Error for AdapterError {}
