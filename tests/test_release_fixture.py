"""Populated upgrade fixture contracts with synthetic HTTP and real Git history."""
import importlib.util
import json
from pathlib import Path
import subprocess

import httpx
import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_fixture", ROOT / "ops/installer/ci/fixture.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


def test_firm_card_uses_absence_guard_current_version_and_admin_upsert():
    calls = []
    def handle(req):
        calls.append((req.method, req.url.path, json.loads(req.content) if req.content else None))
        if req.url.path == "/api/aufgabenkarten":
            return httpx.Response(200, json={"kanzlei": {"version": "b" * 12}})
        if req.method == "PUT":
            assert req.url.path == "/api/admin/aufgabenkarten/upgrade-firm-1234abcd"
            body = json.loads(req.content)
            assert body["version"] == "b" * 12 and "1234abcd" in body["inhalt"]
            return httpx.Response(200, json={"saved": True, "version": "c" * 12})
        if len(calls) == 1: return httpx.Response(404, json={"error": {"code": "card not found"}})
        return httpx.Response(200, json={"inhalt": calls[2][2]["inhalt"]})
    with httpx.Client(base_url="https://synthetic", transport=httpx.MockTransport(handle)) as client:
        fixture.firm_card(client, client, "upgrade-firm-1234abcd", "1234abcd")
    assert [x[0] for x in calls] == ["GET", "GET", "PUT", "GET"]


def test_firm_name_collision_never_becomes_an_overwrite():
    methods = []
    def handle(req):
        methods.append(req.method)
        return httpx.Response(200, json={"inhalt": "existing unrelated synthetic card"})
    with httpx.Client(base_url="https://synthetic", transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(RuntimeError): fixture.firm_card(client, client, "owned-name", "1234abcd")
    assert methods == ["GET"]


def test_old_source_without_durable_document_interface_refuses_before_task_mutation(monkeypatch):
    monkeypatch.delattr(fixture.deployment_verification, "run_document_task")
    calls = []
    def handle(req):
        calls.append(req.method)
        assert req.method == "GET"
        if req.url.path.endswith("/notes/tatbestand.md"): return httpx.Response(404)
        return httpx.Response(200, json={"commit": {"id": "a" * 40}})
    with httpx.Client(base_url="https://synthetic", transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(RuntimeError, match="qualification source lacks the durable document"):
            fixture.generate_document(client, client, "owner", "case", "agent", 5)
    assert calls == ["GET", "GET"]


@pytest.mark.parametrize("fault", [None, "unlinked-author", "not-accepted", "failed", "short", "unchanged-head",
                                   "wrong-author", "wrong-email", "wrong-linked-user", "flat-commit",
                                   "malformed-linked-user", "missing-git-author", "wrong-pusher", "wrong-door"])
def test_generated_document_requires_new_saved_and_attributed_origin(fault, monkeypatch):
    heads = iter(["a" * 40, "a" * 40 if fault == "unchanged-head" else "b" * 40])
    seen_note, polls = 0, 0
    content = "# Synthetic generated document\n\n" + "A synthetic sentence preserving the fixture facts. " * 40
    def handle(req):
        nonlocal seen_note, polls
        path = req.url.path
        if path.endswith("/notes/tatbestand.md"):
            seen_note += 1
            if seen_note == 1: return httpx.Response(404)
            return httpx.Response(200, json={"content": "short" if fault == "short" else content})
        if path.endswith("/branches/main"):
            return httpx.Response(200, json={"commit": {"id": next(heads)}})
        if path.endswith("/skills/run"):
            assert json.loads(req.content) == {"skills": ["tatbestand"]}
            return httpx.Response(200, json={"angenommen": [] if fault == "not-accepted" else ["tatbestand"],
                "bereits": [], "lauf": {"active": True, "jobs": [{"skill": "tatbestand", "status": "queued",
                    "queued": "2026-09-13T12:00:00Z"}]}})
        if path.endswith("/skills"):
            polls += 1
            record = {"v": 1, "skill": "tatbestand", "attempt_id": "c" * 32,
                      "started": "2026-09-13T12:00:01Z", "ended": "2026-09-13T12:00:02Z",
                      "outcome": "failed" if fault == "failed" else "done", "reason": None}
            return httpx.Response(200, json={"lauf": {"active": False, "jobs": [],
                "verlauf": {} if polls == 1 else {"tatbestand": record}}})
        if "/git/commits/" in path:
            detail = {"author": {"name": "other" if fault == "wrong-author" else "agent",
                                 "email": "other@gsj.local" if fault == "wrong-email" else "agent@gsj.local"},
                      "message": "note\n\nDoor: " + ("web" if fault == "wrong-door" else "agent")}
            if fault == "flat-commit": return httpx.Response(200, json=detail)
            if fault == "missing-git-author": detail.pop("author")
            linked = {"login": "other" if fault == "wrong-linked-user" else "agent", "full_name": "GSJ Agent"}
            if fault == "unlinked-author": linked = None
            if fault == "malformed-linked-user": linked = "agent"
            return httpx.Response(200, json={"author": linked, "commit": detail})
        if path.endswith("/activities/feeds"):
            return httpx.Response(200, json=[{"op_type": "commit_repo", "act_user": {"login": "other" if fault == "wrong-pusher" else "agent"},
                "content": json.dumps({"Commits": [{"Sha1": "b" * 40}]})}])
        pytest.fail("unexpected fixture request")
    monkeypatch.setattr(fixture.time, "sleep", lambda _: None)
    with httpx.Client(base_url="https://synthetic", transport=httpx.MockTransport(handle)) as client:
        if fault not in (None, "unlinked-author"):
            with pytest.raises(RuntimeError): fixture.generate_document(client, client, "owner", "case", "agent", 5)
        else:
            result = fixture.generate_document(client, client, "owner", "case", "agent", 5)
            assert result["content_sha256"] == fixture.digest(content)
            assert result["origin"] == {"commit": "b" * 40, "author": "agent", "pusher": "agent", "door": "agent"}
            assert result["attempt"]["attempt_id"] == "c" * 32
            assert content not in json.dumps(result)


@pytest.fixture
def origin(tmp_path):
    root = tmp_path / "repos"
    bare = root / "owner" / "case.git"
    bare.parent.mkdir(parents=True)
    work = tmp_path / "work"
    def git(*args, input=None):
        return subprocess.run(["git", *map(str, args)], input=input, capture_output=True, check=True).stdout
    git("init", "--bare", bare)
    git("init", work)
    git("-C", work, "config", "user.name", "synthetic")
    git("-C", work, "config", "user.email", "synthetic@example.invalid")
    (work / "note").write_text("SENSITIVE-SYNTHETIC-FIXTURE-CONTENT")
    git("-C", work, "add", "note"); git("-C", work, "commit", "-m", "synthetic source")
    git("-C", work, "branch", "-M", "main")
    git("-C", work, "remote", "add", "origin", bare)
    git("-C", work, "push", "origin", "main")
    git("--git-dir=" + str(bare), "symbolic-ref", "HEAD", "refs/heads/main")
    state = {"permission": "write", "repo_id": 17, "collaborator_id": 22}
    pages = []
    def handle(req):
        if req.url.path == "/repos/owner/case":
            return httpx.Response(200, json={"id": state["repo_id"], "full_name": "owner/case", "private": True,
                "owner": {"login": "owner", "id": 11}, "default_branch": "main"})
        if req.url.path.endswith("/collaborators"):
            page = int(req.url.params["page"]); pages.append(page)
            # The API may clamp page size below the requested limit.
            rows = [{"login": "agent", "id": state["collaborator_id"]}] if page == 1 else [{"login": "reader", "id": 23}] if page == 2 else []
            return httpx.Response(200, json=rows)
        login = req.url.path.split("/")[-2]
        return httpx.Response(200, json={"user": {"login": login, "id": {"owner": 11, "agent": state["collaborator_id"], "reader": 23}[login]},
            "permission": "admin" if login == "owner" else state["permission"] if login == "agent" else "read", "role_name": ""})
    with httpx.Client(base_url="https://synthetic", transport=httpx.MockTransport(handle)) as client:
        yield root, bare, work, git, state, pages, client


def test_full_refs_history_objects_and_paginated_permissions_are_preserved(origin):
    root, _, work, git, state, pages, client = origin
    before = fixture.repository_snapshot(client, "owner", "case", repos_root=root)
    assert pages == [1, 2, 3] and before["permission_entries"] == 3
    assert before["commits"] == 1 and before["reachable_objects"] >= 3
    assert "SENSITIVE-SYNTHETIC-FIXTURE-CONTENT" not in json.dumps(before)
    assert fixture.repository_snapshot(client, "owner", "case", repos_root=root) == before
    git("-C", work, "commit", "--allow-empty", "-m", "synthetic history-only change")
    git("-C", work, "push", "origin", "main")
    after = fixture.repository_snapshot(client, "owner", "case", repos_root=root)
    assert after["history_sha256"] != before["history_sha256"] and after["commits"] == 2
    state["permission"] = "read"
    changed = fixture.repository_snapshot(client, "owner", "case", repos_root=root)
    assert changed["head"] == after["head"] and changed["permissions_sha256"] != after["permissions_sha256"]


def test_unreachable_gc_changes_diagnostics_without_losing_preserved_history(origin):
    root, bare, _, git, _, _, client = origin
    git("--git-dir=" + str(bare), "hash-object", "-w", "--stdin", input=b"synthetic unreachable archived object")
    before = fixture.repository_snapshot(client, "owner", "case", repos_root=root)
    git("--git-dir=" + str(bare), "gc", "--prune=now")
    after = fixture.repository_snapshot(client, "owner", "case", repos_root=root)
    assert before["head"] == after["head"] and before["history_sha256"] == after["history_sha256"]
    assert before["diagnostics"]["unreachable_objects"] == 1
    assert after["diagnostics"]["unreachable_objects"] == 0
    assert before["diagnostics"]["unreachable_objects_sha256"] != after["diagnostics"]["unreachable_objects_sha256"]
    assert {k: v for k, v in before.items() if k != "diagnostics"} == {
        k: v for k, v in after.items() if k != "diagnostics"}


@pytest.mark.parametrize("lost", ["ancestor-commit", "ancestor-blob"])
def test_reachable_ancestor_loss_fails_even_when_current_head_is_unchanged(origin, lost):
    root, bare, work, git, _, _, client = origin
    previous = git("-C", work, "rev-parse", "HEAD" if lost == "ancestor-commit" else "HEAD:note").decode().strip()
    (work / "note").write_text("Synthetic replacement content in the current version")
    git("-C", work, "add", "note"); git("-C", work, "commit", "-m", "synthetic next version")
    git("-C", work, "push", "origin", "main")
    before = fixture.repository_snapshot(client, "owner", "case", repos_root=root)
    assert before["commits"] == 2 and before["diagnostics"]["unreachable_objects"] == 0
    # Delete only this temporary fixture's prior object, still reachable through
    # the current commit's ancestry. Its current tree and HEAD ref remain intact.
    object_file = bare / "objects" / previous[:2] / previous[2:]
    assert object_file.is_file()
    object_file.unlink()
    assert git("--git-dir=" + str(bare), "rev-parse", "HEAD").decode().strip() == before["head"]
    with pytest.raises(RuntimeError, match="Git history or object integrity"):
        fixture.repository_snapshot(client, "owner", "case", repos_root=root)


def test_losing_a_side_ref_changes_preservation_even_with_all_objects_retained(origin):
    root, bare, work, git, _, _, client = origin
    git("-C", work, "checkout", "-b", "synthetic-side-history")
    (work / "side-note").write_text("Synthetic content reachable only from the side branch")
    git("-C", work, "add", "side-note"); git("-C", work, "commit", "-m", "synthetic side version")
    git("-C", work, "push", "origin", "synthetic-side-history")
    before = fixture.repository_snapshot(client, "owner", "case", repos_root=root)
    git("--git-dir=" + str(bare), "update-ref", "-d", "refs/heads/synthetic-side-history")
    after = fixture.repository_snapshot(client, "owner", "case", repos_root=root)
    assert before["head"] == after["head"]
    assert before["reachable_objects"] + before["diagnostics"]["unreachable_objects"] == (
        after["reachable_objects"] + after["diagnostics"]["unreachable_objects"])
    assert before["refs_sha256"] != after["refs_sha256"]
    assert before["history_sha256"] != after["history_sha256"]
    assert before["reachable_objects_sha256"] != after["reachable_objects_sha256"]


@pytest.mark.parametrize("action,outcome", [("start-interrupted", "running"), ("read-interrupted", "failed")])
def test_interrupted_skill_uses_actual_web_nested_history_and_persistent_ledger(tmp_path, monkeypatch, action, outcome):
    monkeypatch.setattr(fixture, "LEDGER_ROOT", tmp_path)
    run = "1234abcd"
    ledger = {"format": fixture.CONTRACT, "run_id": run, "phase": "seeded", "login": "owner",
              "password": "synthetic-password", "cases": [{"id": "a" * 12}]}
    (tmp_path / (run + ".json")).write_text(json.dumps(ledger))
    real_client = httpx.Client
    def handle(req):
        if req.url.path == "/api/me": return httpx.Response(200, json={"is_admin": False})
        if req.url.path.endswith("/skills"):
            return httpx.Response(200, json={"karten": [], "lauf": {"verlauf": {"sachbericht": {
                "outcome": outcome, "attempt_id": "b" * 32, "reason": "interrupted" if outcome == "failed" else None}}}})
        return httpx.Response(200, json={})
    monkeypatch.setattr(fixture.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw))
    result = fixture.exercise({"run_id": run, "web_url": "https://synthetic", "timeout_seconds": 5,
        "operator_login": "operator", "operator_password": "synthetic", "expected_attempt": "b" * 32}, action)
    assert result["outcome"] == outcome and result["attempt_id"] == "b" * 32
    assert fixture.CONTRACT == "gsj.upgrade-fixture/2"


def test_fixture_contract_requires_both_new_assets_and_origin_preservation():
    assert {"firm-card", "generated-document", "repository-history", "repository-permissions"} <= set(fixture.COVERAGE)
    assert str(fixture.LEDGER_ROOT).startswith("/data/verification/")
