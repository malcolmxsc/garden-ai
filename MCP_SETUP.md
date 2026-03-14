# Garden AI — MCP Server Setup Guide

This guide walks you through connecting AI clients (Claude Desktop, Cursor, Claude Code) to your Garden AI sandbox via MCP (Model Context Protocol).

## Prerequisites

1. **Build the project**
   ```bash
   cargo build -p garden-cli -p garden-mcp
   ```

2. **Initialize the workspace** (first time only)
   ```bash
   cargo run -p garden-cli -- init
   ```

3. **Boot the sandbox VM**
   ```bash
   cargo run -p garden-cli -- boot
   ```
   The VM must be running before the MCP server can connect. The daemon listens on `127.0.0.1:10000` and proxies gRPC to the guest agent via vSock.

## Connecting Claude Desktop

Add the following to your Claude Desktop config file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "garden-ai": {
      "command": "cargo",
      "args": ["run", "-p", "garden-cli", "--", "serve"],
      "cwd": "/path/to/garden-ai"
    }
  }
}
```

Or if you've built the release binary:

```json
{
  "mcpServers": {
    "garden-ai": {
      "command": "/path/to/garden-ai/target/release/garden",
      "args": ["serve"]
    }
  }
}
```

Restart Claude Desktop after editing the config. You should see "garden-ai" appear in the MCP tools menu.

## Connecting Claude Code

Add to your project's `.mcp.json` or global MCP config:

```json
{
  "mcpServers": {
    "garden-ai": {
      "command": "cargo",
      "args": ["run", "-p", "garden-cli", "--", "serve"],
      "cwd": "/path/to/garden-ai"
    }
  }
}
```

## Connecting Cursor

In Cursor settings, add an MCP server with:
- **Command:** `cargo run -p garden-cli -- serve`
- **Working Directory:** `/path/to/garden-ai`

## Available Tools

Once connected, the AI client has access to 4 tools:

### `run_command`
Execute any command inside the hardware-isolated sandbox VM.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | string | yes | The command to execute (e.g. `ls`, `python3`, `cargo`) |
| `args` | string[] | no | Command arguments |
| `cwd` | string | no | Working directory relative to `/workspace` (default: `.`) |

**Example:** Run `ls -la` in the sandbox
```json
{ "command": "ls", "args": ["-la"], "cwd": "." }
```

### `read_file`
Read the contents of a file from the sandbox workspace.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | File path relative to `/workspace` |

**Example:** Read a file
```json
{ "path": "src/main.rs" }
```

### `write_file`
Write content to a file in the sandbox. Creates the file if it doesn't exist, overwrites if it does.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | File path relative to `/workspace` |
| `content` | string | yes | The content to write |

**Example:** Create a Python script
```json
{ "path": "hello.py", "content": "print('Hello from the sandbox!')" }
```

### `list_directory`
List the contents of a directory in the sandbox.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | no | Directory path relative to `/workspace` (default: `.`) |

**Example:** List the workspace root
```json
{ "path": "." }
```

## How It Works

```
AI Client (Claude/Cursor)
    |
    | MCP JSON-RPC over stdio
    v
garden-cli serve
    |
    | gRPC over TCP (127.0.0.1:10000)
    v
garden-daemon (TCP-to-vSock proxy)
    |
    | AF_VSOCK (hypervisor transport)
    v
garden-agent (PID 1 inside Linux micro-VM)
    |
    | tokio::process::Command
    v
Command executes in isolated sandbox
```

All commands run inside a hardware-isolated Linux micro-VM via Apple's Virtualization.framework. The host filesystem is only exposed through VirtioFS at `~/GardenBox` (mounted as `/workspace` in the guest). Path traversal (`..`) is rejected.

## Troubleshooting

**"gRPC error: transport error"**
The daemon isn't running or the VM hasn't booted. Run `cargo run -p garden-cli -- boot` first.

**MCP server doesn't appear in Claude Desktop**
- Check that the `cwd` path in your config points to the garden-ai project root
- Check Claude Desktop logs: `~/Library/Logs/Claude/`
- Make sure `cargo` is in your PATH (Claude Desktop may not inherit your shell PATH)

**Commands fail with "Permission denied"**
Make sure you're working inside `~/GardenBox`. The CLI enforces that all operations happen within the VirtioFS security boundary.
