//! MCP Tool definitions.
//!
//! Each tool corresponds to an action an AI client can invoke inside
//! the Garden sandbox (e.g., run a command, read a file, write a file).

/// Tool: `run_command`
///
/// Executes a shell command inside the sandbox VM and returns stdout/stderr.
pub struct RunCommandTool;

/// Tool: `read_file`
///
/// Reads the contents of a file from the sandbox's shared filesystem.
pub struct ReadFileTool;

/// Tool: `write_file`
///
/// Writes content to a file in the sandbox's shared filesystem.
pub struct WriteFileTool;

/// Tool: `list_directory`
///
/// Lists the contents of a directory in the sandbox.
pub struct ListDirectoryTool;
