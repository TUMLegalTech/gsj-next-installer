"""Runs through stdin in the web container on a disposable qualification target.

CONFIG and ACTION are prepended by `qualify.py`, which pipes this file into
the container. The private fixture
ledger stays on its data volume; stdout contains hashes, counts and synthetic
stable IDs only.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import time

import httpx
from gsj_deploy.corpus import atomic_json
from gsj_deploy.verify import ASSETS, connection_route, request, require, run_lock, terminal
from gsj_deploy import verify as deployment_verification

CONTRACT = "gsj.upgrade-fixture/2"
COVERAGE = sorted({"pdf-and-index", "notes", "annotations", "instructions", "settings",
                   "personal-card", "firm-card", "generated-document", "agent-history",
                   "conversations", "repository-history", "repository-permissions"})
LEDGER_ROOT = Path("/data/verification/qualification")


def digest(value):
    data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def origin_head(forge, owner, repo):
    value = request(forge, "GET", f"repos/{owner}/{repo}/branches/main").json()
    sha = (value.get("commit") or {}).get("id", "")
    require(re.fullmatch(r"[a-f0-9]{40}", sha or ""), "fixture origin HEAD missing")
    return sha


def origin_attribution(forge, owner, repo, sha, actor, *, timeout=20):
    """The ordinary verifier's Door/pusher proof, using this fixture's Basic login."""
    commit = request(forge, "GET", f"repos/{owner}/{repo}/git/commits/{sha}").json()
    require(isinstance(commit, dict) and isinstance(commit.get("commit"), dict),
            "fixture origin commit shape differs")
    detail = commit["commit"]
    require("Door: agent" in detail.get("message", "").splitlines(), "fixture origin Door differs")
    author, linked = detail.get("author"), commit.get("author")
    require(isinstance(author, dict) and author.get("name") == actor
            and author.get("email") == actor + "@gsj.local", "fixture origin author differs")
    require(linked is None or (isinstance(linked, dict) and linked.get("login") == actor),
            "fixture linked origin author differs")
    deadline = time.monotonic() + timeout
    while True:
        feed = request(forge, "GET", f"repos/{owner}/{repo}/activities/feeds", params={"limit": 40}).json()
        for event in feed:
            if event.get("op_type") != "commit_repo": continue
            commits = json.loads(event.get("content") or "{}").get("Commits", [])
            if sha in {item.get("Sha1") for item in commits}:
                require((event.get("act_user") or {}).get("login") == actor, "fixture origin pusher differs")
                return {"commit": sha, "author": actor, "pusher": actor, "door": "agent"}
        require(time.monotonic() < deadline, "fixture origin push activity missing")
        time.sleep(.5)


def firm_card(admin, user, name, run_id):
    # A shared firm library is writable only through its versioned admin API.
    # Never turn an unexpected name collision into an overwrite.
    request(user, "GET", f"/api/aufgabenkarten/kanzlei/{name}", ok=(404,))
    version = request(admin, "GET", "/api/aufgabenkarten").json()["kanzlei"]["version"]
    content = "GSJ FIRM UPGRADE PERSISTENCE " + run_id + ". Read only this synthetic case."
    out = request(admin, "PUT", f"/api/admin/aufgabenkarten/{name}", json={
        "version": version, "beschreibung": "Synthetic firm upgrade card", "inhalt": content}).json()
    require(out.get("saved") is True, "fixture firm card was not saved")
    saved = request(user, "GET", f"/api/aufgabenkarten/kanzlei/{name}").json()
    require(saved.get("inhalt") == content, "fixture firm card readback differs")


def generate_document(user, forge, owner, case, actor, timeout):
    from gsj.agent import is_document
    path = f"/api/case/{case}/notes/tatbestand.md"
    request(user, "GET", path, ok=(404,))
    before = origin_head(forge, owner, case)
    run_task = getattr(deployment_verification, "run_document_task", None)
    require(callable(run_task), "qualification source lacks the durable document verification interface")
    attempt = run_task(user, case, "tatbestand", timeout)
    content = request(user, "GET", path).json()["content"]
    require(is_document(content), "fixture generated document fails core predicate")
    after = origin_head(forge, owner, case)
    require(after != before, "fixture generated document did not advance origin")
    return {"case_id": case, "name": "tatbestand.md", "skill": "tatbestand",
            "content_sha256": digest(content), "attempt": attempt,
            "origin": origin_attribution(forge, owner, case, after, actor)}


def repository_snapshot(forge, owner, name, *, repos_root="/data/forgejo-repos"):
    """Preserve every ref and reachable object; record unreachable GC separately."""
    require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) for value in (owner, name)),
            "fixture repository path is invalid")
    repo = request(forge, "GET", f"repos/{owner}/{name}").json()
    require(type(repo.get("id")) is int and repo["id"] > 0 and repo.get("private") is True
            and repo.get("full_name") == f"{owner}/{name}" and repo.get("owner", {}).get("login") == owner
            and type(repo["owner"].get("id")) is int, "fixture repository identity differs")
    members, page = {}, 1
    while True:
        batch = request(forge, "GET", f"repos/{owner}/{name}/collaborators", params={"page": page, "limit": 50}).json()
        require(isinstance(batch, list), "fixture collaborator response differs")
        if not batch: break
        for member in batch:
            login = member.get("login")
            require(isinstance(login, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", login)
                    and type(member.get("id")) is int and login not in members, "fixture collaborator identity repeats")
            members[login] = member["id"]
        page += 1
    members[owner] = repo["owner"]["id"]
    permissions = []
    for login, uid in sorted(members.items()):
        value = request(forge, "GET", f"repos/{owner}/{name}/collaborators/{login}/permission").json()
        require(value.get("user", {}).get("id") == uid and value.get("user", {}).get("login") == login
                and isinstance(value.get("permission"), str) and value["permission"], "fixture permission binding differs")
        permissions.append({"id": uid, "login": login, "permission": value["permission"], "role_name": value.get("role_name")})
    root = Path(repos_root).resolve()
    path = root / owner.lower() / (name.lower() + ".git")
    require(path.is_dir() and not path.is_symlink() and path.resolve().is_relative_to(root), "fixture bare origin is unavailable")
    def git(*args):
        result = subprocess.run(["git", "-c", "safe.directory=" + str(path), "--git-dir=" + str(path), *args],
                                capture_output=True, timeout=120)
        require(result.returncode == 0, "fixture Git history or object integrity failed")
        return result.stdout
    git("fsck", "--full", "--strict", "--no-reflogs")
    refs = git("for-each-ref", "--format=%(refname)%00%(objectname)%00%(*objectname)")
    parents = sorted(git("rev-list", "--all", "--parents").splitlines())
    reachable = set(git("rev-list", "--objects", "--all", "--no-object-names").splitlines())
    objects = {row.split(b" ", 1)[0]: row for row in git(
        "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype) %(objectsize)").splitlines()}
    require(reachable <= objects.keys(), "fixture reachable object inventory is incomplete")
    unreachable = set(objects) - reachable
    head = git("rev-parse", "--verify", "HEAD").decode().strip()
    require(refs == git("for-each-ref", "--format=%(refname)%00%(objectname)%00%(*objectname)"),
            "fixture repository refs changed during the snapshot")
    return {"id": repo["id"], "owner_id": repo["owner"]["id"], "owner": owner, "name": name,
            "private": True, "default_branch": repo.get("default_branch"), "head": head,
            "refs_sha256": digest(refs), "history_sha256": digest(b"\n".join(parents)),
            "reachable_objects_sha256": digest(b"\n".join(objects[oid] for oid in sorted(reachable))),
            "commits": len(parents), "reachable_objects": len(reachable),
            "permissions_sha256": digest(permissions), "permission_entries": len(permissions),
            "diagnostics": {"unreachable_objects": len(unreachable),
                            "unreachable_objects_sha256": digest(b"\n".join(objects[oid] for oid in sorted(unreachable)))}}


def exercise(config, action):
    require(re.fullmatch(r"[a-f0-9]{8,16}", config["run_id"]), "invalid fixture run identity")
    require(action in {"seed", "read", "start-interrupted", "read-interrupted"}, "invalid fixture action")
    ledger_path = LEDGER_ROOT / (config["run_id"] + ".json")
    with run_lock(LEDGER_ROOT, filename=config["run_id"] + ".lock"), connection_route(config), \
         httpx.Client(base_url=config["web_url"], timeout=config["timeout_seconds"],
            verify=ssl.create_default_context(cafile=config.get("ca_file") or None)) as admin, \
         httpx.Client(base_url=config["web_url"], timeout=config["timeout_seconds"],
            verify=ssl.create_default_context(cafile=config.get("ca_file") or None)) as user:
        request(admin, "POST", "/api/login", json={"user": config["operator_login"], "password": config["operator_password"]})
        if action == "seed":
            require(not ledger_path.exists(), "populated fixture already exists")
            ledger = {"format": CONTRACT, "run_id": config["run_id"], "phase": "creating",
                      "login": "gsj-verify-" + config["run_id"] + "-a", "password": secrets.token_urlsafe(32), "cases": [],
                      "personal_card": "upgrade-personal-" + config["run_id"],
                      "firm_card": "upgrade-firm-" + config["run_id"]}
            # Persist before the first external mutation; never reset an unknown user.
            atomic_json(ledger_path, ledger)
            identity = request(admin, "POST", "/api/admin/users", json={"login": ledger["login"],
                "password": ledger["password"], "create_only": True}).json()
            require(identity.get("created") is True and identity.get("login") == ledger["login"]
                    and type(identity.get("id")) is int and identity["id"] > 0, "fixture user ownership failed")
            ledger["user_id"] = identity["id"]
            atomic_json(ledger_path, ledger)
        else:
            ledger = json.loads(ledger_path.read_bytes())
            require(ledger.get("format") == CONTRACT and ledger.get("run_id") == config["run_id"]
                    and ledger.get("phase") == "seeded", "fixture ownership or completion differs")
        request(user, "POST", "/api/login", json={"user": ledger["login"], "password": ledger["password"]})
        require(request(user, "GET", "/api/me").json().get("is_admin") is False, "fixture privilege changed")
        if action in {"start-interrupted", "read-interrupted"}:
            case = ledger["cases"][0]["id"]
            if action == "start-interrupted":
                request(user, "POST", f"/api/case/{case}/skills/run", json={"skills": ["sachbericht"]})
            deadline = time.monotonic() + min(config["timeout_seconds"], 120)
            while True:
                state = request(user, "GET", f"/api/case/{case}/skills").json()
                attempt = ((state.get("lauf") or {}).get("verlauf") or {}).get("sachbericht") or {}
                if action == "start-interrupted":
                    require(attempt.get("outcome") not in {"done", "failed"}, "draft ended before the hard fault")
                    if attempt.get("outcome") == "running" and attempt.get("attempt_id"):
                        break
                else:
                    require(attempt.get("outcome") == "failed" and attempt.get("reason") == "interrupted"
                            and attempt.get("attempt_id") == config.get("expected_attempt"), "interrupted attempt was not disclosed")
                    break
                require(time.monotonic() < deadline, "durable draft start did not appear")
                time.sleep(.2)
            request(user, "POST", "/api/logout"); request(admin, "POST", "/api/logout")
            return {"case_id": case, "attempt_id": attempt["attempt_id"], "outcome": attempt["outcome"],
                    "reason": attempt.get("reason")}
        if action == "seed":
            for asset, mode in (("digital", "never"), ("scanned", "always")):
                uploaded = request(admin, "POST", "/api/admin/cases", files={"pdf": (asset + ".pdf",
                    (ASSETS / (asset + ".pdf")).read_bytes(), "application/pdf")},
                    data={"name": "Upgrade fixture " + config["run_id"] + " " + asset, "owner": ledger["login"], "mode": mode})
                result = terminal(uploaded)
                require(result.get("pages") == 1 and result.get("chunks", 0) > 0, "populated fixture ingest failed")
                ledger["cases"].append({"id": result["case_id"], "asset": asset})
                atomic_json(ledger_path, ledger)
            case = ledger["cases"][0]["id"]
            request(user, "POST", f"/api/case/{case}/notes", json={"name": "preserved.md", "content": "GSJ UPGRADE PERSISTENCE " + config["run_id"]})
            request(user, "POST", f"/api/case/{case}/annotations", json={"id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "kind": "region", "page": 1, "rects": [[0.1, 0.1, 0.5, 0.3]], "comment": "Synthetic upgrade annotation"})
            instructions = request(user, "GET", f"/api/case/{case}/agent/instructions").json()
            request(user, "PUT", f"/api/case/{case}/agent/instructions", json={"version": instructions["version"],
                "content": instructions["content"] + "\nPreserve this synthetic upgrade instruction.\n"})
            settings = request(user, "GET", f"/api/case/{case}/agent/settings").json()
            request(user, "PUT", f"/api/case/{case}/agent/settings", json={"version": settings["version"],
                "url": config["llm_url"], "modell": config["llm_model"]})
            request(user, "POST", "/api/aufgabenkarten/eigene", json={"name": ledger["personal_card"],
                "beschreibung": "Synthetic personal card", "inhalt": "Read the synthetic case and preserve its exact sentinels."})
            ledger["firm_card_state"] = "create-pending"
            atomic_json(ledger_path, ledger)
            firm_card(admin, user, ledger["firm_card"], config["run_id"])
            ledger["firm_card_state"] = "owned"
            atomic_json(ledger_path, ledger)
            turn = terminal(request(user, "POST", f"/api/case/{case}/agent/turn", json={
                "message": "Write notes/upgrade-agent.md containing the exact sentence GSJ AGENT UPGRADE PERSISTENCE. Save the file now."}))
            require(turn.get("pushed") is True, "populated agent fixture failed")
            ledger["generated_document"] = {"case_id": case, "skill": "tatbestand", "state": "create-pending"}
            atomic_json(ledger_path, ledger)
            with httpx.Client(base_url=config["forge_url"].rstrip("/") + "/api/v1/", timeout=20,
                              auth=(ledger["login"], ledger["password"])) as forge:
                actor = config.get("agent_account", os.environ.get("GSJ_AGENT_ACCOUNT", "agent"))
                ledger["generated_document"] = {**generate_document(user, forge, ledger["login"], case,
                    actor, config["timeout_seconds"]), "state": "owned"}
            atomic_json(ledger_path, ledger)
        snapshots = []
        for item in ledger["cases"]:
            case = item["id"]
            sentinel = json.loads((ASSETS / "expected.json").read_bytes())[item["asset"]]
            hits = request(user, "GET", f"/api/case/{case}/search", params={"q": sentinel}).json()["hits"]
            require(any(sentinel.lower() in hit["text"].lower() for hit in hits), "preserved case index lost its sentinel")
            snapshots.append({"case_id": case, "asset": item["asset"],
                "pdf": digest(request(user, "GET", f"/api/case/{case}/blob/akte.pdf").content),
                "tree": digest(request(user, "GET", f"/api/case/{case}/tree").json()),
                "annotations": digest(request(user, "GET", f"/api/case/{case}/annotations").json()),
                "instructions": digest(request(user, "GET", f"/api/case/{case}/agent/instructions").json()["content"]),
                "settings": digest({key: value for key, value in request(user, "GET", f"/api/case/{case}/agent/settings").json().items()
                                    if key in {"url", "modell", "quelle"}}),
                "history": digest(request(user, "GET", f"/api/case/{case}/agent/history").json()),
                "conversations": digest(request(user, "GET", f"/api/case/{case}/agent/conversations").json())})
        first = ledger["cases"][0]["id"]
        for name in ("preserved.md", "upgrade-agent.md"):
            content = request(user, "GET", f"/api/case/{first}/notes/{name}").json()["content"]
            require(("GSJ AGENT UPGRADE PERSISTENCE" if name == "upgrade-agent.md" else "GSJ UPGRADE PERSISTENCE " + config["run_id"]) in content,
                    "owned fixture note lost its sentinel")
            snapshots[0][name] = digest(content)
        from gsj.agent import is_document
        generated = ledger["generated_document"]
        require(generated.get("state") == "owned" and generated.get("case_id") == first,
                "generated fixture ownership differs")
        content = request(user, "GET", f"/api/case/{first}/notes/{generated['name']}").json()["content"]
        require(is_document(content) and digest(content) == generated["content_sha256"], "generated fixture document changed")
        result = {"contract": CONTRACT, "coverage": COVERAGE, "user_id": ledger["user_id"], "cases": snapshots,
                  "generated_document": {"content_sha256": digest(content), "origin": generated["origin"]},
                  "personal_card": digest({key: value for key, value in request(user, "GET", f"/api/aufgabenkarten/eigene/{ledger['personal_card']}").json().items()
                                           if key in {"name", "beschreibung", "inhalt"}}),
                  "firm_card": digest({key: value for key, value in request(user, "GET", f"/api/aufgabenkarten/kanzlei/{ledger['firm_card']}").json().items()
                                       if key in {"name", "beschreibung", "inhalt"}})}
        with httpx.Client(base_url=config["forge_url"].rstrip("/") + "/api/v1/", timeout=20,
                          auth=(ledger["login"], ledger["password"])) as forge, \
             httpx.Client(base_url=config["forge_url"].rstrip("/") + "/api/v1/", timeout=20,
                          auth=(config["operator_login"], config["operator_password"])) as forge_admin:
            identity = request(forge, "GET", "user").json()
            require(identity.get("login") == ledger["login"] and identity.get("id") == ledger["user_id"]
                    and identity.get("is_admin") is False, "fixture user identity changed")
            from gsj_web.library import BASE_OWNER, LIBRARY_REPO
            repositories = {item["id"]: repository_snapshot(forge, ledger["login"], item["id"])
                            for item in ledger["cases"]}
            repositories["personal-library"] = repository_snapshot(forge, ledger["login"], LIBRARY_REPO)
            repositories["firm-library"] = repository_snapshot(forge_admin, BASE_OWNER, LIBRARY_REPO)
            bindings = {key: {field: value[field] for field in ("id", "owner_id", "owner", "name")}
                        for key, value in repositories.items()}
            require(all(value["owner_id"] == ledger["user_id"] for key, value in repositories.items()
                        if key != "firm-library"), "fixture repository owner changed")
            if action == "seed": ledger["repository_bindings"] = bindings
            else: require(bindings == ledger.get("repository_bindings"), "fixture repository stable identity changed")
            unreachable = {key: record["diagnostics"] for key, record in repositories.items()}
            if action == "seed": ledger["repository_unreachable_baseline"] = unreachable
            baseline = ledger.get("repository_unreachable_baseline", {})
            require(set(baseline) == set(repositories), "fixture unreachable baseline is incomplete")
            result["diagnostics"] = {"repository_unreachable_objects": {
                key: {**value, "changed_from_seed": value != baseline[key]} for key, value in unreachable.items()}}
            result["repositories"] = {key: {field: value for field, value in record.items()
                                            if field not in ("owner", "name", "diagnostics")}
                                      for key, record in repositories.items()}
        if action == "seed":
            ledger["phase"] = "seeded"
            atomic_json(ledger_path, ledger)
        request(user, "POST", "/api/logout")
        request(admin, "POST", "/api/logout")
        return result


if __name__ == "__main__":
    try:
        print(json.dumps(exercise(CONFIG, ACTION), sort_keys=True))
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        raise SystemExit(1)
