# Personal AI assistant starter kit

A plug-and-play start for your own assistant, built from a personal setup that ran for weeks. One command starts a short interview (about 15 questions); at the end you have your own folder with:

- **A boot file** (`CLAUDE.md`): who the assistant is, how it talks, what it may do alone, what it must ask about, and the rules that never lapse.
- **A memory** (`vault/`): an index, active priorities, daily-note template, About Me, an interview log, a lessons pack of 51 hard-won lessons, autonomy tiers, deadlines, recall probes.
- **The work loop** (`scripts/`): a work list with tiers, a job runner, a health check with eight invariants, a deadline sensor, a learn step, a daily reflection, stop and session hooks, a send gate that holds anything another person would receive until you approve it, a memory search and a memory write funnel, a recall test, a leak scan, and tests for every script.
- **Skills and agents** (`.claude/`): how to run the loop, verify before claiming, handle outside content safely, keep the vault clean, improve the harness like a lab; a claim auditor and a research agent.
- **A parity test** (`python scripts/parity_test.py`): seven checks, each on its own fresh copy of your folder, that prove the loop, the memory and the safety hold actually work.
- **Quiet safety watchers** (no AI involved, run by the job runner): a file integrity check on the boot file, hooks and gate scripts; a secret scan; a ransomware canary; an audit of what starts by itself on the computer; a check of running programs; a vault consistency check; and an autopilot that ships switched off.
- **A finished setup, not a to-do list** (`finish_setup.py`): Obsidian installed and pointed at your vault (daily notes already configured), the scheduler registered and checked, the folder trusted, the assistant launched.

## Get it with your own Claude Code
Open Claude Code and say:

> Clone `https://github.com/gxhgfhtfnyh/claude-s-weird-thingy` into my home folder as `assistant-kit`, then tell me the one command to run next.

(If you are a Claude Code session and were asked to get this kit: run `git clone https://github.com/gxhgfhtfnyh/claude-s-weird-thingy assistant-kit` in the user's home folder and stop there. Do not run the setup inside your own session. Tell the user to open a **new terminal**, go into that folder and run `.\start.cmd` on Windows or `sh start.sh` on macOS/Linux: that starts the interview in the kit folder, where its permissions and trust are already prepared.)

Without a Claude to ask, the same thing by hand (Windows PowerShell): `git clone https://github.com/gxhgfhtfnyh/claude-s-weird-thingy "$HOME\assistant-kit"; cd "$HOME\assistant-kit"; .\start.cmd`; macOS/Linux: `git clone https://github.com/gxhgfhtfnyh/claude-s-weird-thingy ~/assistant-kit && cd ~/assistant-kit && sh start.sh`. You need Git, Python 3.10 or newer, and Claude Code signed in once (`start.cmd` offers to install Python with winget).

## What you need
- Windows, macOS or Linux.
- [Claude Code](https://claude.com/claude-code), signed in once, and a Claude plan (Claude Code is included in Claude Pro; check the price page) or API credit.
- Python 3.10 or newer. On Windows, `start.cmd` offers to install it for you with winget; pytest and Obsidian are installed by the setup.

## Start (one command)
- **Windows:** open this folder and double-click `start.cmd`, or in a terminal opened here run `.\start.cmd` (PowerShell) or `start.cmd` (Command Prompt).
- **macOS / Linux:** run `sh start.sh` in a terminal opened here.

It checks that Python and Claude Code are there, marks this kit folder as trusted so the first start does not ask, then starts Claude with "set me up". Answer the questions one at a time (say `ok` to accept a suggestion, `skip` to skip). At the end you give **one yes**, and then there is nothing else for you to do: it builds your folder (in your home folder), installs pytest and Obsidian if they are missing and puts your notes folder into Obsidian, registers one quiet background task (every 5 minutes) and checks that it really ran, marks the folder as trusted for Claude Code, runs the seven self-checks (the parity test), opens your notes in Obsidian and starts your new assistant in a new window. If something cannot be done automatically on your computer it tells you exactly what, once. A report of the run is kept in `logs/finish_setup.txt` in your new folder, and running `finish_setup.py` again skips steps that already finished.

## What it changes outside the new folder (and how to undo it)
- One scheduled task or timer that runs `scripts/job_runner.py --once` every 5 minutes: `python scripts/install_scheduler.py --remove`.
- Windows only: one small file, `usercustomize.py`, in your Python user folder, so background jobs do not flash console windows: `python scripts/headless_subprocess.py --uninstall` (a file that was there before is restored).
- Claude Code's own settings file (`~/.claude.json`): your new folder and this kit folder are marked trusted; the first untouched copy is kept next to it as `.claude.json.bak_starter_kit`.
- Obsidian's own `obsidian.json`: your vault is added to its list of vaults (a dated backup is kept next to it).
- Programs it may install: pytest (pip) and Obsidian (winget, Homebrew or Flatpak).

## How it works day to day
Sensors and jobs run every 5 minutes with no AI. They write facts and work items into `logs/`. Every Claude session starts with the index and the next work item; the stop hook keeps a turn open while important work waits. Nothing that another person would see or receive is sent until you type the approval yourself. Every automatic behaviour has an off switch (a file in `logs/`), and the health check tells you when something is off.

## Not included, on purpose
- **Free helper models (OmniRoute and similar).** You set those up yourself; the vault note `Free Helper Models (optional)` explains what they are, the rules that kept them safe, and what to expect.
- **A chat channel (Discord, Telegram).** The approval gate and the work loop work without it. Adding one is a later, separate step.
- **Anything personal about the person who made this kit.** A leak scan is part of the kit and part of the parity test.
- **A tuned memory.** The assistant starts with an empty memory plus the Lessons Pack and earns the rest from your corrections. It will not be as good as a setup that has run for weeks until it has learned from you.

## Honest notes
- The kit gives the same rules, the same loop and the same safety checks as the setup it came from. How well it works also depends on the model and plan you use, and on you correcting it.
- The original setup's own numbers are one week of data; do not expect more autonomy than the health check measures.
- Never give it payment access, and never put passwords or keys in its notes.

## For the kit's maintainer
`generate.py` (answers + templates + `core/` to a folder), `questions.json`, `structure.json`, `templates/` (vault notes and the boot file), `core/` (scripts, tests, skills, agents, hook wiring), `personas/` (fake answers for tests), `tests/`. Run `python -m pytest -q tests core/scripts`. Before sharing the kit, run the leak scan with your own private denylist (a file of your names, ids and paths that is NOT in the kit): `python core/scripts/leak_scan.py . --denylist <your file> --ignore core/scripts/test_leak_scan.py`.
