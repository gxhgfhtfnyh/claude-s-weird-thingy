{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/session_start.py\"" }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/prompt_context_hook.py\"", "timeout": 10 },
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/recall_hook.py\"", "timeout": 10 }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/send_gate.py\"" }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch|WebSearch",
        "hooks": [
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/injection_prescan_hook.py\"", "timeout": 10 }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/stop_gate.py\"" },
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/keep_going.py\"", "timeout": 10 },
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/claim_gate.py\"", "timeout": 10 },
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/handoff_write.py\"", "timeout": 10 }
        ]
      }
    ]
  }
}
