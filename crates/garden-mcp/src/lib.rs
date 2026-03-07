//! Garden AI — MCP (Model Context Protocol) Server.
//!
//! This crate implements a JSON-RPC server following the MCP specification,
//! allowing AI clients like Claude Desktop, Cursor, and LangChain agents
//! to connect and execute commands inside Garden sandboxes.

pub mod resources;
pub mod server;
pub mod tools;
