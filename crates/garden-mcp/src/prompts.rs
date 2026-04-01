//! MCP Prompt implementations for Garden AI sandbox.
//!
//! Three prompts help AI clients request security analysis directly:
//!
//! | Name                | Args  | Description                                      |
//! |---------------------|-------|--------------------------------------------------|
//! | `analyze-security`  | none  | Analyse recent events and violations             |
//! | `sandbox-report`    | none  | Full sandbox status + security summary           |
//! | `investigate-process` | pid | All events for a specific guest PID              |

use rmcp::model::{
    ErrorData, GetPromptRequestParams, GetPromptResult, ListPromptsResult, Prompt, PromptArgument,
    PromptMessage, PromptMessageRole,
};

use crate::resources::{find_latest_session_log, read_recent_events, read_violations};

// ---------------------------------------------------------------------------
// List prompts
// ---------------------------------------------------------------------------

pub fn build_list_prompts_result() -> ListPromptsResult {
    let prompts = vec![
        Prompt::new(
            "analyze-security",
            Some(
                "Analyse the most recent security events and policy violations from the Garden \
                 sandbox. Returns a structured overview of what the AI workload has been doing \
                 and flags anything suspicious.",
            ),
            None,
        ),
        Prompt::new(
            "sandbox-report",
            Some(
                "Full sandbox health report: VM running state, uptime, kernel version, and a \
                 summary of recent security telemetry.",
            ),
            None,
        ),
        Prompt::new(
            "investigate-process",
            Some(
                "Retrieve all security events associated with a specific guest PID. \
                 Useful for tracing the activity of a suspicious process.",
            ),
            Some(vec![PromptArgument {
                name: "pid".to_string(),
                title: Some("Process ID".to_string()),
                description: Some("The guest PID to investigate (e.g. 42)".to_string()),
                required: Some(true),
            }]),
        ),
    ];

    ListPromptsResult {
        meta: None,
        next_cursor: None,
        prompts,
    }
}

// ---------------------------------------------------------------------------
// Get prompt
// ---------------------------------------------------------------------------

pub async fn dispatch_get_prompt(
    req: GetPromptRequestParams,
) -> Result<GetPromptResult, ErrorData> {
    match req.name.as_str() {
        "analyze-security" => Ok(prompt_analyze_security()),
        "sandbox-report" => Ok(prompt_sandbox_report().await),
        "investigate-process" => {
            let pid = req
                .arguments
                .as_ref()
                .and_then(|a| a.get("pid"))
                .and_then(|v| v.as_str())
                .or_else(|| {
                    req.arguments
                        .as_ref()
                        .and_then(|a| a.get("pid"))
                        .and_then(|v| v.as_u64().map(|_| ""))
                })
                .map(|s| s.to_string());

            // Try numeric extraction via serde_json
            let pid_str = req
                .arguments
                .as_ref()
                .and_then(|a| a.get("pid"))
                .and_then(|v| {
                    if let Some(s) = v.as_str() {
                        Some(s.to_string())
                    } else if let Some(n) = v.as_u64() {
                        Some(n.to_string())
                    } else {
                        None
                    }
                })
                .or(pid);

            match pid_str {
                Some(pid) => Ok(prompt_investigate_process(&pid)),
                None => Err(ErrorData::invalid_params(
                    "Missing required argument: pid",
                    None,
                )),
            }
        }
        other => Err(ErrorData::invalid_params(
            format!("Unknown prompt: {other}"),
            None,
        )),
    }
}

// ---------------------------------------------------------------------------
// Prompt builders
// ---------------------------------------------------------------------------

fn prompt_analyze_security() -> GetPromptResult {
    let events = read_recent_events();
    let violations = read_violations();

    let text = format!(
        "You are a security analyst reviewing activity from a Garden AI sandbox — a \
         hardware-isolated Linux micro-VM running AI agent workloads.\n\n\
         ## Recent Security Events\n\n\
         {events}\n\n\
         ## Policy Violations\n\n\
         {violations}\n\n\
         Please analyse the above telemetry and:\n\
         1. Summarise what the AI workload has been doing.\n\
         2. Identify any suspicious patterns (unusual file access, unexpected network \
            connections, privilege changes, large data transfers).\n\
         3. Rate the overall risk level: LOW / MEDIUM / HIGH.\n\
         4. Recommend any policy changes if warranted."
    );

    GetPromptResult {
        description: Some("Security event analysis".to_string()),
        messages: vec![PromptMessage::new_text(PromptMessageRole::User, text)],
    }
}

async fn prompt_sandbox_report() -> GetPromptResult {
    let status = crate::resources::read_sandbox_status().await;
    let events = read_recent_events();
    let violations = read_violations();

    let text = format!(
        "You are a DevOps engineer reviewing the Garden AI sandbox state.\n\n\
         ## Sandbox Status\n\n\
         {status}\n\n\
         ## Recent Security Events (last 50)\n\n\
         {events}\n\n\
         ## Policy Violations\n\n\
         {violations}\n\n\
         Please produce a concise sandbox health report covering:\n\
         - VM operational status and any concerns\n\
         - Summary of workload activity\n\
         - Any violations and their severity\n\
         - Overall health: HEALTHY / DEGRADED / CRITICAL"
    );

    GetPromptResult {
        description: Some("Sandbox status and security report".to_string()),
        messages: vec![PromptMessage::new_text(PromptMessageRole::User, text)],
    }
}

fn prompt_investigate_process(pid: &str) -> GetPromptResult {
    let pid_u64: Option<u64> = pid.parse().ok();

    let events_text = match (find_latest_session_log(), pid_u64) {
        (Some(path), Some(target_pid)) => {
            use std::io::{BufRead, BufReader};
            let file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => return error_result(&format!("Could not open log: {e}")),
            };
            let matching: Vec<String> = BufReader::new(file)
                .lines()
                .filter_map(|l| l.ok())
                .filter(|line| {
                    // Parse JSON to compare pid exactly — avoids "12" matching "123".
                    serde_json::from_str::<serde_json::Value>(line)
                        .ok()
                        .and_then(|v| v["pid"].as_u64())
                        .map(|p| p == target_pid)
                        .unwrap_or(false)
                })
                .collect();

            if matching.is_empty() {
                format!("No events found for PID {pid} in the current session.")
            } else {
                format!(
                    "Events for PID {pid} ({} total):\n\n{}",
                    matching.len(),
                    matching.join("\n")
                )
            }
        }
        (None, _) => {
            "No session log found. The Garden daemon may not have been started yet.".to_string()
        }
        (_, None) => format!("Invalid PID value: '{pid}'. Must be a non-negative integer."),
    };

    let text = format!(
        "You are a security analyst investigating a specific process in the Garden AI sandbox.\n\n\
         ## Events for PID {pid}\n\n\
         {events_text}\n\n\
         Please analyse the events for this process and:\n\
         1. Describe what the process was doing.\n\
         2. Identify any suspicious activity.\n\
         3. Determine whether this process poses a security risk."
    );

    GetPromptResult {
        description: Some(format!("Process investigation for PID {pid}")),
        messages: vec![PromptMessage::new_text(PromptMessageRole::User, text)],
    }
}

fn error_result(msg: &str) -> GetPromptResult {
    GetPromptResult {
        description: Some("Error".to_string()),
        messages: vec![PromptMessage::new_text(
            PromptMessageRole::User,
            format!("Error: {msg}"),
        )],
    }
}
