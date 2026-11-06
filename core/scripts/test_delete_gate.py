# -*- coding: utf-8 -*-
"""Tests for delete_gate.py. Each test redirects HARNESS_LOGS/HARNESS_ROOT to a temp folder; nothing
real is read or written. v1 scope only (see the module docstring for what is NOT covered yet)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import delete_gate as dg  # noqa: E402


@pytest.fixture(autouse=True)
def logs(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_LOGS", str(tmp_path / "logs"))
    monkeypatch.setenv("HARNESS_ROOT", str(tmp_path))
    return tmp_path / "logs"


def bash(command):
    return dg.classify("Bash", {"command": command})


class TestRecursiveForceDeletesAreFlagged:
    def test_rm_rf_combined_flag(self):
        c = bash("rm -rf /home/user/project")
        assert c["destructive"] and c["kind"] == "rm_rf"

    def test_rm_with_separate_flags_either_order(self):
        assert bash("rm -r -f ./build")["destructive"]
        assert bash("rm -f -r ./build")["destructive"]

    def test_rm_long_form_flags(self):
        assert bash("rm --recursive --force ./build")["destructive"]

    def test_rm_without_force_is_not_flagged(self):
        assert not bash("rm -r ./build")["destructive"]

    def test_rm_single_file_is_not_flagged(self):
        assert not bash("rm notes.md")["destructive"]

    def test_powershell_remove_item_recurse_force(self):
        c = bash('Remove-Item -Recurse -Force "C:\\Users\\x\\vault"')
        assert c["destructive"] and c["kind"] == "powershell_remove"

    def test_powershell_remove_item_abbreviated_flags(self):
        assert bash("Remove-Item -r -fo C:\\temp\\x")["destructive"]

    def test_powershell_remove_item_recurse_only_not_flagged(self):
        assert not bash("Remove-Item -Recurse C:\\temp\\x")["destructive"]

    def test_del_s_q(self):
        c = bash("del /s /q C:\\temp\\old")
        assert c["destructive"] and c["kind"] == "del_sq"

    def test_del_without_q_not_flagged(self):
        assert not bash("del /s C:\\temp\\old")["destructive"]

    def test_rd_s_q(self):
        c = bash("rd /s /q C:\\temp\\old")
        assert c["destructive"] and c["kind"] == "rd_sq"


class TestOtherBulkPatterns:
    def test_find_delete(self):
        c = bash("find . -name '*.tmp' -delete")
        assert c["destructive"] and c["kind"] == "find_delete"

    def test_find_without_delete_not_flagged(self):
        assert not bash("find . -name '*.tmp'")["destructive"]

    def test_git_clean_force(self):
        c = bash("git clean -fdx")
        assert c["destructive"] and c["kind"] == "git_clean"

    def test_git_clean_dry_run_not_flagged(self):
        assert not bash("git clean -ndx")["destructive"]

    def test_git_status_not_flagged(self):
        assert not bash("git status")["destructive"]

    def test_powershell_pipeline_gci_into_remove_item(self):
        c = bash("Get-ChildItem C:\\vault | Remove-Item")
        assert c["destructive"] and c["kind"] == "powershell_pipeline_delete"

    def test_plain_gci_listing_not_flagged(self):
        assert not bash("Get-ChildItem C:\\vault")["destructive"]

    def test_shutil_rmtree(self):
        c = bash("python -c \"import shutil; shutil.rmtree('C:/Users/x/vault')\"")
        assert c["destructive"] and c["kind"] == "shutil_rmtree"

    def test_shutil_rmtree_unreadable_target_still_flagged(self):
        c = bash("python -c \"import shutil; shutil.rmtree(target_var)\"")
        assert c["destructive"] and c["kind"] == "shutil_rmtree"

    def test_os_remove_loop(self):
        code = "python <<'EOF'\nfor f in glob.glob('notes/*.md'):\n    os.remove(f)\nEOF"
        assert bash(code)["destructive"]

    def test_single_os_remove_not_flagged(self):
        assert not bash("python -c \"import os; os.remove('a.txt')\"")["destructive"]

    def test_sql_drop_table(self):
        c = bash("sqlite3 app.db \"DROP TABLE users;\"")
        assert c["destructive"] and c["kind"] == "sql_drop"

    def test_sql_select_not_flagged(self):
        assert not bash("sqlite3 app.db \"SELECT * FROM users;\"")["destructive"]

    def test_windows_format_drive(self):
        c = bash("format D: /q")
        assert c["destructive"] and c["kind"] == "drive_format"

    def test_diskpart_with_clean(self):
        c = bash("diskpart /s wipe_script.txt\n# select disk 1\n# clean")
        assert c["destructive"] and c["kind"] == "diskpart"


class TestStandingExemptions:
    def test_scratchpad_delete_is_exempt(self):
        cmd = r'Remove-Item -Recurse -Force "C:\Users\x\AppData\Local\Temp\claude\abc\scratch"'
        assert not bash(cmd)["destructive"]

    def test_scratchpad_delete_unix_style_is_exempt(self):
        assert not bash("rm -rf /tmp/claude/run123/out")["destructive"]

    def test_tearing_down_a_temp_clone_the_same_command_made_is_exempt(self):
        cmd = 'git clone https://example.com/repo.git /tmp/e2e_check && echo done; Remove-Item -Recurse -Force /tmp/e2e_check'
        assert not bash(cmd)["destructive"]

    def test_a_delete_of_something_not_created_in_the_same_command_is_not_exempt(self):
        assert bash('Remove-Item -Recurse -Force /home/user/notes')["destructive"]

    def test_edit_tool_on_an_ordinary_file_is_never_flagged(self):
        assert not dg.classify("Edit", {"file_path": "notes.md"})["destructive"]


class TestFalsePositivesInPlainTextArguments:
    def test_drop_table_mentioned_in_an_echoed_warning_is_not_flagged(self):
        assert not bash('echo "please dont DROP TABLE in prod"')["destructive"]

    def test_rm_rf_mentioned_in_a_commit_message_is_not_flagged(self):
        assert not bash('git commit -m "docs: warn against rm -rf in scripts"')["destructive"]

    def test_a_real_drop_table_through_sqlite_is_still_flagged(self):
        c = bash('sqlite3 app.db "DROP TABLE users;"')
        assert c["destructive"] and c["kind"] == "sql_drop"

    def test_echoed_text_actually_piped_into_something_that_runs_it_is_still_flagged(self):
        c = bash('echo "DROP TABLE users;" | sqlite3 app.db')
        assert c["destructive"] and c["kind"] == "sql_drop"

    def test_safe_text_wrapped_in_command_substitution_is_still_flagged(self):
        c = bash('x=$(echo "DROP TABLE users;")')
        assert c["destructive"] and c["kind"] == "sql_drop"

    def test_safe_text_passed_to_eval_is_still_flagged(self):
        c = bash('eval "echo \'format D: /q\'"')
        assert c["destructive"] and c["kind"] == "drive_format"

    def test_safe_text_passed_to_bash_dash_c_is_still_flagged(self):
        c = bash('bash -c "echo \'DROP TABLE users;\'"')
        assert c["destructive"] and c["kind"] == "sql_drop"

    def test_bare_powershell_grouping_parens_is_still_flagged(self):
        c = bash('(Write-Output "DROP TABLE users;")')
        assert c["destructive"] and c["kind"] == "sql_drop"

    def test_powershell_encodedcommand_is_still_flagged(self):
        c = bash("powershell -EncodedCommand \"echo 'format D: /q'\"")
        assert c["destructive"] and c["kind"] == "drive_format"


class TestTamperProtection:
    def test_deleting_the_approvals_file_is_tamper(self):
        assert dg.is_tamper("Bash", {"command": "rm logs/delete_approvals.jsonl"})

    def test_editing_the_approvals_file_via_the_edit_tool_is_tamper(self):
        assert dg.is_tamper("Edit", {"file_path": "logs/delete_approvals.jsonl"})

    def test_reading_the_approvals_file_is_not_tamper(self):
        assert not dg.is_tamper("Bash", {"command": "cat logs/delete_approvals.jsonl"})

    def test_echo_redirect_with_no_recognized_writer_verb_is_still_tamper(self):
        assert dg.is_tamper("Bash", {"command": "echo fake >> logs/delete_gate_mode.txt"})

    def test_python_write_to_an_approvals_file_is_tamper(self):
        assert dg.is_tamper("Bash", {"command": "python -c \"open('logs/delete_approvals.jsonl','a').write('{}')\""})

    def test_deleting_the_logs_directory_by_wildcard_is_tamper(self):
        assert dg.is_tamper("Bash", {"command": "rm -rf logs/delete_*"})

    def test_an_unrelated_wildcard_delete_with_no_logs_reference_is_not_tamper(self):
        assert not dg.is_tamper("Bash", {"command": "rm -rf build/output_*"})

    def test_canary_invocation_itself_is_never_tamper(self):
        assert not dg.is_tamper("Bash", {"command": "python scripts/delete_gate.py --canary"})


class TestApprovalsAndDecide:
    def test_shadow_mode_never_denies_even_a_destructive_call(self, tmp_path, logs):
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "delete_gate_mode.txt").write_text("shadow", encoding="utf-8")
        verdict, _ = dg.decide("Bash", {"command": "rm -rf /home/user/stuff"})
        assert verdict == "allow"
        assert (logs / "delete_gate_shadow.jsonl").exists()

    def test_enforce_mode_denies_an_unapproved_destructive_call(self, logs):
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "delete_gate_mode.txt").write_text("enforce", encoding="utf-8")
        verdict, reason = dg.decide("Bash", {"command": "rm -rf /home/user/stuff"})
        assert verdict == "deny" and "rm -rf" in reason

    def test_enforce_mode_allows_a_safe_call(self, logs):
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "delete_gate_mode.txt").write_text("enforce", encoding="utf-8")
        assert dg.decide("Bash", {"command": "ls -la"})[0] == "allow"

    def test_kill_switch_allows_everything(self, logs):
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "delete_gate_mode.txt").write_text("enforce", encoding="utf-8")
        (logs / "delete_gate_off.txt").write_text("", encoding="utf-8")
        assert dg.decide("Bash", {"command": "rm -rf /home/user/stuff"})[0] == "allow"

    def test_approving_then_rerunning_the_exact_text_allows_it(self, logs):
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "delete_gate_mode.txt").write_text("enforce", encoding="utf-8")
        text = dg.fingerprint("Bash", {"command": "rm -rf /home/user/stuff"})
        verdict1, _ = dg.decide("Bash", {"command": "rm -rf /home/user/stuff"})
        assert verdict1 == "deny"
        dg.record_approval(dg.sha256(text), text)
        verdict2, _ = dg.decide("Bash", {"command": "rm -rf /home/user/stuff"})
        assert verdict2 == "allow"

    def test_expired_approval_does_not_allow(self, logs):
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "delete_gate_mode.txt").write_text("enforce", encoding="utf-8")
        text = dg.fingerprint("Bash", {"command": "rm -rf /home/user/stuff"})
        past = dg.datetime.datetime.now(dg.datetime.timezone.utc) - dg.datetime.timedelta(minutes=5)
        dg.record_approval(dg.sha256(text), text, minutes=1, now=past)
        assert dg.decide("Bash", {"command": "rm -rf /home/user/stuff"})[0] == "deny"

    def test_tamper_is_denied_even_in_shadow_mode(self, logs):
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "delete_gate_mode.txt").write_text("shadow", encoding="utf-8")
        verdict, _ = dg.decide("Bash", {"command": "rm logs/delete_approvals.jsonl"})
        assert verdict == "deny"


class TestCanary:
    def test_run_canary_is_internally_consistent(self):
        result = dg.run_canary()
        assert result["ok"], result["detail"]

    def test_main_canary_flag_writes_the_canary_file(self, logs, capsys):
        code = dg.main(["--canary"])
        assert code == 0
        assert (logs / "delete_gate_canary.json").exists()
        assert "canary ok" in capsys.readouterr().out


class TestMainHookProtocol:
    def test_deny_prints_a_hook_specific_json_object(self, logs, capsys):
        import io
        (logs).mkdir(parents=True, exist_ok=True)
        (logs / "delete_gate_mode.txt").write_text("enforce", encoding="utf-8")
        payload = '{"tool_name": "Bash", "tool_input": {"command": "rm -rf /home/user/stuff"}}'
        code = dg.main([], stdin=io.StringIO(payload))
        assert code == 0
        out = capsys.readouterr().out
        assert "permissionDecision" in out and "deny" in out

    def test_allow_prints_nothing(self, logs, capsys):
        import io
        (logs).mkdir(parents=True, exist_ok=True)
        (logs / "delete_gate_mode.txt").write_text("enforce", encoding="utf-8")
        payload = '{"tool_name": "Bash", "tool_input": {"command": "ls -la"}}'
        code = dg.main([], stdin=io.StringIO(payload))
        assert code == 0
        assert capsys.readouterr().out == ""

    def test_unreadable_stdin_fails_open(self, logs, capsys):
        import io
        code = dg.main([], stdin=io.StringIO("not json"))
        assert code == 0
