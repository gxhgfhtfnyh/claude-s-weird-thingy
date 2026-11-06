# -*- coding: utf-8 -*-
"""Tests for approve_delete.py (the owner's side of the delete gate). A temp folder stands in for
logs/. Unlike send_gate.py, delete_gate.py defaults to SHADOW mode, so these tests set enforce
explicitly -- that's the realistic state once the owner has watched shadow mode and turned it on."""
import json
import os
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import approve_delete as apd  # noqa: E402
import delete_gate as dg  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(autouse=True)
def logs(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_LOGS", str(tmp_path / "logs"))
    monkeypatch.setenv("HARNESS_ROOT", str(tmp_path))
    d = tmp_path / "logs"
    d.mkdir(parents=True, exist_ok=True)
    (d / "delete_gate_mode.txt").write_text("enforce", encoding="utf-8")
    return d


def held(command):
    verdict, reason = dg.decide("Bash", {"command": command})
    assert verdict == "deny", reason
    return reason.split("python scripts/approve_delete.py ")[1].split()[0]


def test_approving_by_code_lets_exactly_that_command_through_and_prints_what_it_approved(capsys):
    code = held("rm -rf /home/user/project")
    assert apd.main([code]) == 0
    out = capsys.readouterr().out
    assert "approved for 30 minutes" in out and "rm -rf /home/user/project" in out
    assert dg.decide("Bash", {"command": "rm  -rf   /home/user/project"}) == ("allow", "approved")
    assert dg.decide("Bash", {"command": "rm -rf /home/user/other"})[0] == "deny"


def test_the_approval_records_the_full_hash_and_an_expiry_in_the_future(logs):
    code = held("rm -rf /x")
    apd.main([code, "--minutes", "5"])
    row = json.loads((logs / "delete_approvals.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert row["sha"] == dg.sha256("rm -rf /x") and row["preview"] == "rm -rf /x"
    assert 200 < (dg._parse_time(row["expires"]) - dg._parse_time(row["ts"])).total_seconds() <= 300


def test_an_unknown_code_is_refused_and_nothing_is_approved(logs, capsys):
    held("rm -rf /x")
    assert apd.main(["deadbeef00"]) == 1 and "no held delete matches" in capsys.readouterr().out
    assert not (logs / "delete_approvals.jsonl").exists()


def test_a_one_character_code_cannot_approve_anything(logs, capsys):
    (logs / "delete_pending_approvals.jsonl").write_text(json.dumps({"ts": time.time(), "sha": "a" + "0" * 63, "tool": "Bash", "text": "rm -rf /x"}) + "\n", encoding="utf-8")
    assert apd.main(["a"]) == 1 and "not a code" in capsys.readouterr().out
    assert not (logs / "delete_approvals.jsonl").exists()


def test_approving_ahead_of_time_with_the_exact_text(capsys):
    assert apd.main(["--text", "  rm  -rf  /home/user/stuff "]) == 0
    assert dg.decide("Bash", {"command": "rm -rf /home/user/stuff"}) == ("allow", "approved")
    assert "rm -rf /home/user/stuff" in capsys.readouterr().out


def test_empty_text_is_refused(capsys):
    assert apd.main(["--text", "   "]) == 1 and "empty" in capsys.readouterr().out


@pytest.mark.parametrize("minutes", ["0", "-5", "1441", "abc"])
def test_bad_minutes_are_refused_and_nothing_is_recorded(minutes, logs, capsys):
    code = held("rm -rf /x")
    assert apd.main([code, "--minutes", minutes]) == 1
    assert not (logs / "delete_approvals.jsonl").exists()


def test_no_arguments_prints_usage(capsys):
    assert apd.main([]) == 1 and "usage" in capsys.readouterr().out


def test_an_approval_here_does_not_leak_into_send_gates_approvals_file(logs):
    """the two gates must never share or consume each other's yes."""
    code = held("rm -rf /x")
    apd.main([code])
    assert not (logs / "approvals.jsonl").exists()
    assert (logs / "delete_approvals.jsonl").exists()


def test_the_whole_flow_as_real_processes(tmp_path):
    env = dict(os.environ, HARNESS_ROOT=str(tmp_path), HARNESS_LOGS=str(tmp_path / "logs"), PYTHONIOENCODING="ascii")
    os.makedirs(os.path.join(str(tmp_path), "logs"), exist_ok=True)
    with open(os.path.join(str(tmp_path), "logs", "delete_gate_mode.txt"), "w", encoding="utf-8") as f:
        f.write("enforce")
    hook = lambda cmd: subprocess.run([sys.executable, os.path.join(HERE, "delete_gate.py")], input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}), capture_output=True, text=True, env=env)
    first = hook("rm -rf /home/user/project")
    reason = json.loads(first.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    code = reason.split("python scripts/approve_delete.py ")[1].split()[0]
    owner = subprocess.run([sys.executable, os.path.join(HERE, "approve_delete.py"), code], capture_output=True, text=True, env=env)
    assert owner.returncode == 0 and "rm -rf /home/user/project" in owner.stdout
    assert hook("rm -rf /home/user/project").stdout == ""                       # now allowed
    assert json.loads(hook("rm -rf /home/user/other").stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    # and the assistant cannot run the approval itself
    assert json.loads(hook("python scripts/approve_delete.py " + code).stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
