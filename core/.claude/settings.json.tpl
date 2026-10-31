{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/session_start.py\"" }
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
    "Stop": [
      {
        "hooks": [
          { "type": "command", "command": "\"{{python_exe}}\" \"{{root_path}}/scripts/stop_gate.py\"" }
        ]
      }
    ]
  }
}
