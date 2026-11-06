# -*- coding: utf-8 -*-
"""Delete gate: a Claude Code PreToolUse hook that holds a destructive, hard-to-reverse filesystem
action until the owner has approved that exact content -- the same pattern send_gate.py already uses
for outbound sends, applied to deletes instead.

Built 2026-11-06 after a real end-to-end test of this kit proved the gap: a fresh assistant, told to
delete all the files in its vault folder, just did it immediately and only asked a question
afterward. There was no code anywhere enforcing "ask before a destructive action" -- only CLAUDE.md
prose a model under pressure can skip, the same place rule-as-prose used to leave send_gate's own
job before it became code.

Wired in .claude/settings.json (matcher "*", same as send_gate.py). DENY = print one JSON object
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
"permissionDecisionReason": ...}} and exit 0. ALLOW = exit 0 and print nothing.

What counts as destructive (v1, NOT exhaustive -- see each pattern's own comment for what it does
and does not catch): a recursive/forced delete (rm -rf, Remove-Item -Recurse -Force, del /s /q,
rd /s /q, find -delete, a PowerShell pipeline that feeds Get-ChildItem into Remove-Item or
Clear-Content), shutil.rmtree and a python loop that deletes files, git clean -f/-fd/-fdx, a SQL
statement that drops or truncates a table/database, and wiping a drive (format, a diskpart script
with a clean step). A single file delete, a normal Edit/Write overwrite, and tearing down something
the SAME command just created (its own temp clone, its own mkdir) are never flagged -- those are
routine and reversible, and flagging them would just teach the owner to stop reading these holds.

How the owner approves: the denial shows the exact text and a short code. The owner types, with the
! prefix, `python scripts/approve_delete.py <code>`; that records an approval of the exact text for
30 minutes. Approvals live in their OWN file (logs/delete_approvals.jsonl), separate from
send_gate.py's approvals.jsonl, so the two gates can never consume each other's yes. The assistant
cannot approve its own deletes: any command that writes to this gate's own files (its mode, kill
switch, log or approvals, or a wildcard/variable reaching into the logs directory) is itself denied
as tamper.

Honest limitation, not solved by this v1: tamper protection here is a command-TEXT pattern match,
not a sandbox. It cannot stop a determined local attacker who can run arbitrary code -- real
protection would need the approvals/kill-switch/mode files to live somewhere this account cannot
write at all (ACL'd, or owned by a separate process), which is a structural follow-up, not something
this file claims to have done.

Files in logs/: delete_gate_mode.txt (shadow, the default = allow but record what enforce WOULD have
done to delete_gate_shadow.jsonl; or enforce), delete_gate_off.txt (kill switch: allow everything, one
alert line a day in alerts.txt), delete_approvals.jsonl, delete_pending_approvals.jsonl.
    python delete_gate.py --canary     # samples + an approve-then-allow round trip in a temp folder; writes logs/delete_gate_canary.json; exit 0 when ok, else 1
Pure core (unit tested): classify, is_tamper, fingerprint, decide."""
import datetime
import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
import time

EPOCH = time.time

SHELL_TOOLS = {"bash", "shell", "powershell", "pwsh"}
FILE_TOOLS = {"write", "edit", "multiedit", "notebookedit"}
WRITER_CMDS = frozenset(("tee", "rm", "del", "mv", "move", "cp", "copy", "truncate", "remove-item", "set-content",
                         "add-content", "out-file", "new-item", "clear-content", "ri", "erase", "rd", "rmdir", "ren", "rename"))
WRAPPERS = frozenset(("sudo", "env", "command", "nohup", "time", "timeout", "nice", "stdbuf", "ionice", "call", "start"))

PROTECTED_BASENAMES = {"delete_approvals.jsonl", "delete_approvals_used.jsonl", "delete_pending_approvals.jsonl",
                       "delete_gate_off.txt", "delete_gate_mode.txt", "delete_gate.py", "delete_gate_shadow.jsonl", "approve_delete.py"}
RX_TAMPER = re.compile(r"delete_approvals(?:_used)?\.jsonl|delete_pending_approvals\.jsonl|delete_gate_off(?:\.txt)?|delete_gate_mode(?:\.txt)?|delete_gate\.py|delete_gate_shadow\.jsonl|approve_delete\.py", re.I)
RX_REDIRECT_INTO = re.compile(r">>?\s*[\"']?\S*(?:delete_approvals(?:_used)?\.jsonl|delete_pending_approvals\.jsonl|delete_gate_off\.txt|delete_gate_mode\.txt)", re.I)
RX_PY_WRITE = re.compile(r"open\([^)]*['\"][wax]|\.write\(|write_text|write_bytes|\.append\(|os\.(?:remove|replace|rename)|shutil\.", re.I)
RX_LOGS_PATH = re.compile(r"\blog\w*[\\/]", re.I)
RX_WILDCARD_OR_VAR = re.compile(r"[*?]|\$\{?\w+\}?|%\w+%")
RX_REDIRECT_INTO_LOGS = re.compile(r">>?\s*[\"']?\S*log", re.I)
RX_SCRATCH = re.compile(r"AppData[\\/]+Local[\\/]+Temp[\\/]+claude|[\\/]tmp[\\/]+claude", re.I)
CREATE_VERBS = re.compile(r"\bmkdir\b|\bNew-Item\b|\bgit\s+clone\b|\bcp\s+-[A-Za-z]*r[A-Za-z]*\b|\bCopy-Item\b|\brobocopy\b", re.I)

RX_GCI_REMOVE = re.compile(r"Get-ChildItem\b[^\n]{0,200}\|\s*(?:ForEach-Object|%)?[^\n]{0,100}\bRemove-Item\b", re.I)
RX_GCI_CLEAR = re.compile(r"Get-ChildItem\b[^\n]{0,200}\|\s*(?:ForEach-Object|%)?[^\n]{0,100}\bClear-Content\b", re.I)
RX_RMTREE = re.compile(r"shutil\.rmtree\s*\(")
RX_RMTREE_ARG = re.compile(r"shutil\.rmtree\s*\(\s*(?:f?['\"])([^'\"]+)['\"]")
RX_OS_REMOVE_LOOP = re.compile(r"for\s+\w+\s+in\b.{0,200}?:\s*\n[^\n]{0,200}?(?:os\.(?:remove|unlink)\(|\.unlink\(\))", re.S)
RX_DROP_TRUNCATE = re.compile(r"\bDROP\s+(?:TABLE|DATABASE)\b|\bTRUNCATE\s+TABLE\b", re.I)
RX_FORMAT = re.compile(r"\bformat\s+[A-Za-z]:", re.I)
RX_MKFS = re.compile(r"\bmkfs(?:\.\w+)?\s+/dev/", re.I)
# A quoted argument to a pure-text command (echo/printf/Write-Host, or a git commit message) is DATA,
# not something that runs; blanked only when its own output is never piped/redirected into something
# that would actually run it (a direct pipe into sqlite3, say) -- then it must stay visible.
RX_SAFE_TEXT_ARG = re.compile(r"(?:\b(?:echo|printf|Write-Host|Write-Output|Write-Information)\b[^\n;|&]*?|\bgit\s+commit\b[^\n;|&]*?-m\s*)(['\"])((?:(?!\1).)*)\1(?P<tail>[^\n;&]*)", re.I)
INERT_BASE_CMDS = frozenset(("echo", "printf", "write-host", "write-output", "write-information"))
CANARY_OK = re.compile(r"^(?:python[w3]?(?:\.exe)?|py)\s+\S*delete_gate\.py\s+--canary$", re.I)


def _is_provably_inert(full):
    """Pure. True ONLY when nothing in the command could consume, substitute or re-interpret quoted
    text as code: a single statement (no ; && || | & newline chaining), no parens/braces/brackets/
    angle-brackets/backticks ANYWHERE in the raw text (bare PowerShell grouping, a subexpression, the
    call operator, a scriptblock, a redirect), and a base command that is a pure-text printer or
    `git commit`. A whitelist-of-inert, not a blacklist of execution-context markers (eval, -c, iex,
    cmd /c, -Command, -EncodedCommand, ... keeps growing) -- any base command besides the few pure
    printers below is treated as NOT inert, so the real scan always runs on it."""
    if re.search(r"[(){}<>`\[\]]", full):
        return False
    if len(_split_unquoted(full)) != 1:
        return False
    tokens = _tokens(full)
    base, i = _command_word(tokens)
    if base in INERT_BASE_CMDS:
        return True
    return base == "git" and tokens[i + 1:i + 2] == ["commit"]


# ---------- paths (read at call time so tests and callers can redirect them with the environment) ----------
def root():
    return os.environ.get("HARNESS_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def logs():
    return os.environ.get("HARNESS_LOGS") or os.path.join(root(), "logs")


def _path(name):
    return os.path.join(logs(), name)


# ---------- text helpers ----------
def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize(command):
    return re.sub(r"\s+", " ", str(command).strip())


SHOW_LIMIT = 1500   # a pending-by-code approval must never bind more text than the owner was actually shown


def command_of(tool_input):
    if isinstance(tool_input, dict):
        return str(tool_input.get("command") or tool_input.get("cmd") or "")
    return str(tool_input or "")


def fingerprint(tool_name, tool_input):
    if str(tool_name).lower() in SHELL_TOOLS:
        return normalize(command_of(tool_input))
    try:
        body = json.dumps(tool_input, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        body = str(tool_input)
    return "%s\n%s" % (tool_name, body)


def _split_unquoted(text):
    """Pure. Split at ; && || | & and newlines, but not inside quotes."""
    segs, buf, quote, i, n = [], [], None, 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == quote and not (quote == '"' and i and text[i - 1] == "\\"):
                quote = None
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch in ";|&\r\n":
            segs.append("".join(buf).strip())
            buf = []
            if text[i:i + 2] in ("&&", "||"):
                i += 1
        else:
            buf.append(ch)
        i += 1
    segs.append("".join(buf).strip())
    return [s for s in segs if s]


def _tokens(stmt):
    try:
        return shlex.split(stmt, posix=True)
    except ValueError:
        return stmt.split()


def _command_word(tokens):
    """Pure. -> (basename, index) of the command word, past env assignments and wrapper words."""
    i, n = 0, len(tokens)
    while i < n:
        t = tokens[i]
        if re.match(r"^[A-Za-z_]\w*=", t):
            i += 1
            continue
        base = os.path.basename(t.replace("\\", "/")).lower()
        if base.endswith(".exe"):
            base = base[:-4]
        if base in WRAPPERS:
            i += 1
            continue
        return base, i
    return None, i


def _python_blocks(full):
    """Pure. The python source inside a command: heredoc bodies fed to python and the string
    argument of `-c` -- real code, as opposed to a plain-text argument to echo or a commit message."""
    blocks = [m.group(2) for m in re.finditer(r"(?:python[0-9.]*(?:\.exe)?|pythonw|py)\b[^\n|;&<]*<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n(.*?)\n[ \t]*\1[ \t]*(?=\n|$)", full, re.S | re.I)]
    blocks += [m.group(1) for m in re.finditer(r"-\w*c\s+(\"(?:\\.|[^\"\\])*\"|'[^']*')", full)]
    return blocks


def _is_scratch_path(p):
    return bool(RX_SCRATCH.search(p or ""))


def _self_created(full, path):
    """Pure. True when `path` (or its basename) appears a second time in the full command text next
    to a creation verb -- a heuristic for "this is the same thing the command just built and is now
    tearing down", not a real parse of intent."""
    if not path:
        return False
    occurrences = len(re.findall(re.escape(path), full))
    if occurrences < 2:
        base = os.path.basename(path.rstrip("\\/"))
        if len(base) < 3:
            return False
        occurrences = len(re.findall(re.escape(base), full))
        if occurrences < 2:
            return False
    return bool(CREATE_VERBS.search(full))


def _rm_is_recursive_force(rest):
    has_r = any(t == "--recursive" or (t.startswith("-") and not t.startswith("--") and re.search(r"[rR]", t)) for t in rest)
    has_f = any(t == "--force" or (t.startswith("-") and not t.startswith("--") and "f" in t.lower()) for t in rest)
    return has_r and has_f


def _ps_remove_is_recursive_force(rest):
    """PowerShell lets a parameter be abbreviated to any unambiguous prefix (-r, -rec, -recurse ...)."""
    has_r = any(re.match(r"^-r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?$", t, re.I) for t in rest)
    has_f = any(re.match(r"^-f(?:o(?:r(?:c(?:e)?)?)?)?$", t, re.I) for t in rest)
    return has_r and has_f


def _del_is_recursive_quiet(rest):
    return any(t.lower() == "/s" for t in rest) and any(t.lower() == "/q" for t in rest)


def _git_clean_is_force(rest):
    return any(t == "--force" or (t.startswith("-") and not t.startswith("--") and "f" in t.lower()) for t in rest)


def _is_diskpart_wipe(full):
    low = full.lower()
    return "diskpart" in low and (re.search(r"\bclean\b", full, re.I) or re.search(r"/s\b", full, re.I))


def _judge(kind, targets, full, why):
    """Pure. Applies the two standing exemptions (scratchpad-only, self-created-and-torn-down);
    None means not flagged (either not destructive, or exempt)."""
    if targets:
        if all(_is_scratch_path(t) for t in targets):
            return None
        if all(_self_created(full, t) for t in targets):
            return None
    return dict(destructive=True, kind=kind, target=(targets[0] if targets else ""), why=why)


def _classify_stmt(stmt, full):
    tokens = _tokens(stmt)
    base, i = _command_word(tokens)
    if base is None:
        return None
    rest = tokens[i + 1:]
    if base == "rm" and _rm_is_recursive_force(rest):
        return _judge("rm_rf", [t for t in rest if not t.startswith("-")], full, "a recursive, forced delete (rm -rf-style)")
    if base in ("remove-item", "ri") and _ps_remove_is_recursive_force(rest):
        return _judge("powershell_remove", [t for t in rest if not t.startswith("-")], full, "a recursive, forced PowerShell delete (Remove-Item -Recurse -Force)")
    if base in ("del", "erase") and _del_is_recursive_quiet(rest):
        return _judge("del_sq", [t for t in rest if not t.startswith("/")], full, "a recursive, silent delete (del /s /q)")
    if base in ("rd", "rmdir") and _del_is_recursive_quiet(rest):
        return _judge("rd_sq", [t for t in rest if not t.startswith("/")], full, "a recursive, silent directory removal (rd /s /q)")
    if base == "find" and any(t == "-delete" for t in rest):
        return _judge("find_delete", [], full, "a bulk find ... -delete")
    if base == "git" and rest[:1] == ["clean"] and _git_clean_is_force(rest[1:]):
        return _judge("git_clean", [], full, "an untracked-file wipe (git clean -f)")
    return None


def _blank_safe_text(full):
    """Pure. Same length/structure, quoted text-only arguments replaced with filler so a mention
    inside an echoed warning or a commit message cannot trigger the whole-text destructive patterns
    -- but ONLY when that text is never piped or redirected into something that would run it."""
    def repl(m):
        tail = m.group("tail") or ""
        if re.search(r"[|>]", tail):
            return m.group(0)
        start, end = m.start(2) - m.start(0), m.end(2) - m.start(0)
        s = m.group(0)
        return s[:start] + "x" * (end - start) + s[end:]
    return RX_SAFE_TEXT_ARG.sub(repl, full)


# ---------- tamper protection ----------
READ_ONLY_VIEWERS = frozenset(("grep", "egrep", "fgrep", "rg", "echo", "printf", "cat", "head", "tail", "less", "more", "type", "findstr",
                               "select-string", "ls", "dir", "wc", "sort", "file", "stat", "pwd", "which", "where", "get-content", "get-childitem", "gc", "gci"))


def _viewer_only(command):
    """True for read-only viewers only: every part of the command (pipes and chains allowed) is a
    viewer, with no substitution and no redirect -- same rule send_gate.py already uses."""
    if re.search(r"\$\(|`|[<>]", command):
        return False
    segs = _split_unquoted(command)
    if not segs:
        return False
    for s in segs:
        base, _i = _command_word(_tokens(s))
        if base not in READ_ONLY_VIEWERS:
            return False
    return True


def is_tamper(tool_name, tool_input):
    """A mention of ANY of the gate's own protected names anywhere in the command is tamper UNLESS
    the whole command is a plain read-only viewer (same model as send_gate.py's own is_tamper --
    this is NOT just "a write": the assistant must not even be able to RUN approve_delete.py itself,
    since unlike delete_gate_hook.py's real-harness sibling, approve_delete.py has no independent
    evidence check of its own -- running it IS the approval, so it being denied here is the only
    thing stopping self-approval). Honest limitation (see the module docstring): this is a command-
    TEXT pattern match, not a sandbox, and cannot stop a determined local attacker -- real protection
    needs the approval/kill-switch/mode files ACL'd somewhere this account cannot write."""
    name = str(tool_name).lower()
    if name in FILE_TOOLS:
        target = ""
        if isinstance(tool_input, dict):
            target = str(tool_input.get("file_path") or tool_input.get("notebook_path") or tool_input.get("path") or "")
        return os.path.basename(target.replace("\\", "/")).lower() in PROTECTED_BASENAMES
    if name not in SHELL_TOOLS:
        return False
    cmd = command_of(tool_input)
    if CANARY_OK.match(normalize(cmd)):
        return False
    full = cmd
    if RX_TAMPER.search(full) and not _viewer_only(full):
        return True
    # round-2 addition: a wildcard or a variable reaching into the logs directory, not one of the
    # literal protected names above (`rm logs/delete_*`, `echo x >> $LOGS_DIR/...`)
    for stmt in _split_unquoted(full):
        if not (RX_LOGS_PATH.search(stmt) and RX_WILDCARD_OR_VAR.search(stmt)):
            continue
        tokens = _tokens(stmt)
        base, _i = _command_word(tokens)
        if base in WRITER_CMDS or RX_REDIRECT_INTO_LOGS.search(stmt):
            return True
    return False


# ---------- classification ----------
def classify(tool_name, tool_input):
    """Pure. -> {destructive, kind, target, why}."""
    name = str(tool_name)
    tin = tool_input if isinstance(tool_input, dict) else {}
    if name.lower() in FILE_TOOLS:
        return dict(destructive=False, kind="none", target="", why="")        # single-file Edit/Write is routine and reversible; never gated here
    if name.lower() not in SHELL_TOOLS:
        return dict(destructive=False, kind="none", target="", why="")
    full = command_of(tin)
    if RX_RMTREE.search(full):
        targets = []
        for blk in _python_blocks(full):
            targets += [m.group(1) for m in RX_RMTREE_ARG.finditer(blk)]
        if not targets:
            targets = [m.group(1) for m in RX_RMTREE_ARG.finditer(full)]
        c = _judge("shutil_rmtree", targets, full, "shutil.rmtree deletes a whole directory tree with no recycle bin")
        if c:
            return c
        if not targets:
            return dict(destructive=True, kind="shutil_rmtree", target="", why="shutil.rmtree with a target that can't be read from the command text")
    if RX_OS_REMOVE_LOOP.search(full):
        return dict(destructive=True, kind="py_remove_loop", target="", why="python code that deletes files in a loop")
    masked = _blank_safe_text(full)

    def _whole_text_hit(text):
        if RX_DROP_TRUNCATE.search(text):
            return dict(destructive=True, kind="sql_drop", target="", why="a SQL statement that drops or truncates a table/database")
        if RX_FORMAT.search(text) or RX_MKFS.search(text):
            return dict(destructive=True, kind="drive_format", target="", why="formats or wipes a drive")
        if _is_diskpart_wipe(text):
            return dict(destructive=True, kind="diskpart", target="", why="a diskpart script that may clean (wipe) a disk")
        if RX_GCI_REMOVE.search(text) or RX_GCI_CLEAR.search(text):
            return dict(destructive=True, kind="powershell_pipeline_delete", target="", why="a PowerShell pipeline that bulk-deletes or clears everything it's given")
        return None

    c = _whole_text_hit(masked)
    if c:
        return c
    if not _is_provably_inert(full):
        c = _whole_text_hit(full)
        if c:
            return c
    for stmt in _split_unquoted(full):
        c = _classify_stmt(stmt, full)
        if c:
            return c
    return dict(destructive=False, kind="none", target="", why="")


# ---------- approvals ----------
def _read_jsonl(name):
    rows = []
    try:
        with open(_path(name), encoding="utf-8") as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return rows


def _append_jsonl(name, row):
    try:
        os.makedirs(logs(), exist_ok=True)
        with open(_path(name), "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=True) + "\n")
    except OSError:
        pass


def _parse_time(text):
    return datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))


def approved(sha, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    for row in _read_jsonl("delete_approvals.jsonl"):
        if row.get("sha") == sha:
            try:
                if _parse_time(row.get("expires")) > now:
                    return True
            except (ValueError, TypeError):
                continue
    return False


def record_approval(sha, preview, minutes=30, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    row = {"ts": now.isoformat(), "expires": (now + datetime.timedelta(minutes=minutes)).isoformat(), "sha": sha, "preview": preview[:200]}
    _append_jsonl("delete_approvals.jsonl", row)
    return row


def current_mode():
    try:
        with open(_path("delete_gate_mode.txt"), encoding="utf-8") as f:
            return f.read().strip().lower() or "shadow"
    except OSError:
        return "shadow"              # unlike send_gate.py, a brand-new gate with untested regexes defaults to shadow, not enforce


def kill_switch_on():
    return os.path.exists(_path("delete_gate_off.txt"))


def _alert_once_a_day(text):
    today = datetime.date.today().isoformat()
    try:
        with open(_path("alerts.txt"), encoding="utf-8") as f:
            if any(ln.startswith(today) and "delete_gate" in ln for ln in f):
                return
    except OSError:
        pass
    try:
        os.makedirs(logs(), exist_ok=True)
        with open(_path("alerts.txt"), "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (today, text))
    except OSError:
        pass


# ---------- the decision ----------
def deny_output(reason):
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}})


def decide(tool_name, tool_input):
    """-> ("allow" | "deny", reason). Records pending approvals and shadow rows as a side effect."""
    if is_tamper(tool_name, tool_input):
        return "deny", ("Blocked: this touches the delete gate itself (its script, switches, approvals or log). The assistant may not approve its own deletes or change the gate; "
                        "only the owner can, by typing the ! command from a denial message.")
    if kill_switch_on():
        _alert_once_a_day("delete_gate kill switch is ON (logs/delete_gate_off.txt exists): nothing is being held")
        return "allow", "kill switch"
    cls = classify(tool_name, tool_input)
    if not cls["destructive"]:
        return "allow", cls["why"]
    text = fingerprint(tool_name, tool_input)
    sha = sha256(text)
    if approved(sha):
        return "allow", "approved"
    if current_mode() == "shadow":
        _append_jsonl("delete_gate_shadow.jsonl", {"ts": EPOCH(), "tool": str(tool_name), "kind": cls["kind"], "why": cls["why"], "text": text[:1000]})
        return "allow", "shadow"
    if len(text) > SHOW_LIMIT:
        # Too long to show the owner in full, so a short code must never bind an approval to more text than they saw.
        # No pending row is written for this sha; the only path is --text with the exact command (hashed fresh from
        # whatever the owner actually supplies, so what is approved can never be longer than what was typed).
        return "deny", ("Held for the owner's approval (%s: %s).\nThis command is %d characters, too long to hold for a short-code approval. "
                         "Show the owner the exact full command and have them approve it with the exact text, with the ! prefix:\n"
                         "python scripts/approve_delete.py --text \"<paste the exact command, in full>\"\n"
                         "Do not try to work around this." % (cls["kind"], cls["why"], len(text)))
    _append_jsonl("delete_pending_approvals.jsonl", {"ts": EPOCH(), "sha": sha, "tool": str(tool_name), "kind": cls["kind"], "text": text})
    return "deny", ("Held for the owner's approval (%s: %s).\nExact content:\n%s\n\nShow the owner this exact text and wait. They approve it by typing, with the ! prefix: python scripts/approve_delete.py %s\n"
                    "Do not try to work around this." % (cls["kind"], cls["why"], text, sha[:10]))


def decide_failsafe(tool_name, tool_input):
    """Used when decide() itself failed: hold what looks destructive, let the rest through. Never raises."""
    try:
        cls = classify(tool_name, tool_input)
        if cls["destructive"] or is_tamper(tool_name, tool_input):
            return "deny", "The delete gate hit an internal error and holds this command to be safe. Ask the owner to look at logs/alerts.txt."
    except Exception:
        pass
    return "allow", "failsafe"


# ---------- canary ----------
CANARY_SAMPLES = [
    ("Bash", {"command": "rm -rf /home/user/project"}, True), ("Bash", {"command": "Remove-Item -Recurse -Force C:\\x"}, True),
    ("Bash", {"command": "del /s /q C:\\temp\\old"}, True), ("Bash", {"command": "find . -name '*.tmp' -delete"}, True),
    ("Bash", {"command": "git clean -fdx"}, True), ("Bash", {"command": "sqlite3 app.db \"DROP TABLE users;\""}, True),
    ("Bash", {"command": "format D: /q"}, True), ("Bash", {"command": "python -c \"import shutil; shutil.rmtree('x')\""}, True),
    ("Bash", {"command": "rm notes.md"}, False), ("Bash", {"command": "rm -r ./build"}, False), ("Bash", {"command": "git status"}, False),
    ("Bash", {"command": "git commit -m 'docs: warn against rm -rf in scripts'"}, False), ("Bash", {"command": "ls -la"}, False),
    ("Edit", {"file_path": "notes.md"}, False), ("Bash", {"command": "rm -rf /tmp/claude/run123/out"}, False),
    ("Write", {"file_path": "logs/delete_approvals.jsonl", "content": "x"}, "tamper"),
    ("Bash", {"command": "rm -rf logs/delete_*"}, "tamper"),
]


def run_canary():
    """-> {ts, ok, detail}. The approve-then-allow round trip runs in a temporary folder so no real approval is written."""
    bad = []
    for tool, tin, expected in CANARY_SAMPLES:
        got = "tamper" if is_tamper(tool, tin) else classify(tool, tin)["destructive"]
        if got != expected:
            bad.append("%s %r should be %r" % (tool, str(tin)[:40], expected))
    old = os.environ.get("HARNESS_LOGS")
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["HARNESS_LOGS"] = tmp
        try:
            with open(os.path.join(tmp, "delete_gate_mode.txt"), "w", encoding="utf-8") as f:
                f.write("enforce")
            verdict1, _ = decide("Bash", {"command": "rm -rf /home/user/canary"})
            row = _read_jsonl("delete_pending_approvals.jsonl")
            if verdict1 != "deny" or not row:
                bad.append("a planted rm -rf was not held")
            else:
                record_approval(row[-1]["sha"], row[-1]["text"])
                if decide("Bash", {"command": "rm  -rf  /home/user/canary"})[0] != "allow":
                    bad.append("an approved command was still held")
        finally:
            if old is None:
                os.environ.pop("HARNESS_LOGS", None)
            else:
                os.environ["HARNESS_LOGS"] = old
    ok = not bad
    return {"ts": EPOCH(), "ok": ok, "detail": ("%d of %d samples and the approve-then-allow round trip behaved as expected" % (len(CANARY_SAMPLES), len(CANARY_SAMPLES))) if ok else "; ".join(bad[:3])}


def main(argv=None, stdin=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--canary"]:
        result = run_canary()
        try:
            os.makedirs(logs(), exist_ok=True)
            with open(_path("delete_gate_canary.json"), "w", encoding="utf-8") as f:
                json.dump(result, f)
        except OSError:
            pass
        print("canary %s: %s" % ("ok" if result["ok"] else "FAILED", result["detail"]))
        return 0 if result["ok"] else 1
    try:
        raw = (stdin if stdin is not None else sys.stdin).read()
        data = json.loads(raw) if raw.strip() else {}
        if not isinstance(data, dict):
            data = {}
    except (ValueError, OSError):
        _alert_once_a_day("delete_gate got unreadable hook input and let the call through")
        return 0
    tool_name, tool_input = data.get("tool_name", ""), data.get("tool_input", {})
    try:
        verdict, reason = decide(tool_name, tool_input)
    except Exception:
        verdict, reason = decide_failsafe(tool_name, tool_input)
    if verdict == "deny":
        print(deny_output(reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
