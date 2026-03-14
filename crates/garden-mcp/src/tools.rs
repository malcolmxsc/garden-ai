//! MCP Tool parameter definitions.
//!
//! Each struct defines the input schema for a tool that AI clients can invoke
//! inside the Garden sandbox. JSON schemas are auto-generated via `schemars`.

use schemars::JsonSchema;
use serde::Deserialize;

fn default_cwd() -> String {
    ".".to_string()
}

/// Parameters for the `run_command` tool.
///
/// Executes a shell command inside the sandbox VM and returns stdout/stderr.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunCommandParams {
    /// The command to execute (e.g. "ls", "python3", "cargo")
    pub command: String,
    /// Command arguments
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory relative to /workspace (default: ".")
    #[serde(default = "default_cwd")]
    pub cwd: String,
}

/// Parameters for the `read_file` tool.
///
/// Reads the contents of a file from the sandbox's shared filesystem.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadFileParams {
    /// File path relative to /workspace
    pub path: String,
}

/// Parameters for the `write_file` tool.
///
/// Writes content to a file in the sandbox's shared filesystem.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteFileParams {
    /// File path relative to /workspace
    pub path: String,
    /// The content to write to the file
    pub content: String,
}

/// Parameters for the `list_directory` tool.
///
/// Lists the contents of a directory in the sandbox.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListDirectoryParams {
    /// Directory path relative to /workspace (default: ".")
    #[serde(default = "default_cwd")]
    pub path: String,
}
