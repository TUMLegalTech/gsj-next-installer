"""First-start recovery requires real SQLite/Chroma payload proof, not markers."""
import fcntl
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import chromadb
import pytest

from gsj import ports, store
from gsj_deploy import corpus, initialize as init


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("startup_source_proof", ROOT / "ops/installer/startup-source-proof.py")
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)


@pytest.fixture
def ready_source(tmp_path, monkeypatch):
    source = tmp_path / "input"
    source.mkdir()
    for n in range(3):
        (source / f"{n}.xml").write_text(
            f"<dokument><doknr>SYNTH{n}</doknr><gertyp>TEST</gertyp>"
            f"<tenor><p>Only a synthetic startup fixture {n}.</p></tenor></dokument>")
    image, copied = tmp_path / "image", tmp_path / "copied"
    manifest = corpus.build(source, image, core_commit=corpus.installed_core_commit(),
                            release_owner="synthetic", source_provenance="synthetic", shard_size=2)
    corpus.copy_payload(image, copied, corpus.digest(image / "manifest.json"))
    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"),
                                       settings=chromadb.Settings(anonymized_telemetry=False))
    writes = []

    class ExplicitVectors:
        def replace_decision(self, did, ids, documents, metadatas):
            writes.append(did)
            collection = client.get_collection(manifest["collection"], embedding_function=None)
            collection.upsert(ids=ids, documents=documents, metadatas=metadatas,
                              embeddings=[[0.01] * 768 for _ in ids])

    model = tmp_path / "model"
    model.mkdir()
    cfg = {"db": str(tmp_path / "db" / "gsj.db"), "source": str(copied),
           "state": str(tmp_path / "state"), "chroma_url": "http://chroma:8000",
           "model_path": str(model), "manifest_sha256": corpus.digest(image / "manifest.json"),
           "deadline_seconds": 300, "attempts": 2, "repair_generation": 1, "allow_update": False,
           "released_vectors": False}
    init.initialize(cfg, client=client, index_factory=lambda *args: ExplicitVectors(), verify_model=False)
    # Existing case data belongs to the source, and must remain byte-identical.
    db = store.connect(cfg["db"])
    case = store.new_case(db, "synthetic", b"%PDF-synthetic-source", "synthetic")
    db.close()
    model_loads = []
    monkeypatch.setattr(ports, "embed_manifest_sha256", lambda path: ports.EMBED_MANIFEST_SHA256)
    monkeypatch.setattr(proof, "load_local_model", lambda path: model_loads.append(str(path)) or 768)
    settings = {"format": "gsj.startup-source-settings/1", "operation": "a" * 24,
        "release_identity": "synthetic-source", "namespace_uid": "synthetic-namespace-uid",
        "generation": "synthetic-source:1", "control_sha256": "b" * 64,
        "corpus_manifest_sha256": cfg["manifest_sha256"], "corpus_fingerprint": manifest["fingerprint"],
        "core_commit": manifest["core_commit"], "model": manifest["embedding"],
        "rows": manifest["rows"], "vectors": manifest["chunks"], "initializer": cfg,
        "paths": {k: cfg[k] for k in ("db", "source", "state", "model_path")}, "deadline_seconds": 60}
    current = json.loads((Path(cfg["state"]) / "current.json").read_bytes())
    checkpoint = Path(cfg["state"]) / (current["identity"] + ".json")
    def forbidden(*args, **kwargs):
        pytest.fail("a source-proof helper attempted a write or embedding path")
    monkeypatch.setattr(init, "initialize", forbidden)
    monkeypatch.setattr(init, "collection", forbidden)
    monkeypatch.setattr(store, "migrate", forbidden)
    monkeypatch.setattr(ports.ChromaIndex, "__init__", forbidden)
    return settings, client, manifest, checkpoint, model_loads, writes, case


def test_real_payload_verified_without_embedding_or_changing_source(ready_source):
    settings, client, manifest, checkpoint, loads, writes, case = ready_source
    tracked = [Path(settings["paths"]["db"]), checkpoint, checkpoint.parent / "current.json"]
    before = [p.read_bytes() for p in tracked]
    result = proof.prove(settings, client=client)
    assert result["status"] == "startup-complete"
    assert result["rows"] == result["vectors"] == 3
    assert result["inventory_verified"] and result["schema_ready"] and result["model_loaded"]
    assert result["document_embeddings_performed"] == 0
    assert result["application_readiness_verified"] is False
    assert len(loads) == 1 and len(writes) == 3
    assert [p.read_bytes() for p in tracked] == before
    with sqlite3.connect(settings["paths"]["db"]) as db:
        assert db.execute("SELECT source FROM cases WHERE id=?", (case["case_id"],)).fetchone()[0] == b"%PDF-synthetic-source"


@pytest.mark.parametrize("damage", ["row-text", "vector-text", "vector-metadata", "missing-vector",
                                     "orphan-vector", "orphan-row", "source-bytes", "distance", "model-stamp", "vector-dimension",
                                     "current-count", "checkpoint-incomplete", "checkpoint-missing", "schema"])
def test_real_store_damage_never_passes_completed_markers(ready_source, damage):
    settings, client, manifest, checkpoint, *_ = ready_source
    collection = client.get_collection(manifest["collection"], embedding_function=None)
    did = manifest["files"][0]["decision_id"]
    vector_id = did + ":0"
    if damage in ("row-text", "orphan-row", "schema"):
        with sqlite3.connect(settings["paths"]["db"]) as db:
            if damage == "row-text": db.execute("UPDATE decisions SET text='different synthetic payload' WHERE id=?", (did,))
            elif damage == "orphan-row": db.execute("INSERT INTO decisions(id,text) VALUES('ORPHAN','synthetic')")
            else: db.execute("DROP TABLE chunks")
    elif damage == "vector-text": collection.update(ids=[vector_id], documents=["different synthetic payload"], embeddings=[[.01] * 768])
    elif damage == "vector-metadata": collection.update(ids=[vector_id], metadatas=[{"decision_id": did, "court": "OTHER"}])
    elif damage == "missing-vector": collection.delete(ids=[vector_id])
    elif damage == "orphan-vector": collection.add(ids=["ORPHAN:0"], embeddings=[[.01] * 768], documents=["synthetic"], metadatas=[{"decision_id": "ORPHAN", "court": "TEST"}])
    elif damage == "source-bytes":
        item = manifest["files"][0]
        (Path(settings["paths"]["source"]) / item["shard"] / item["path"]).write_bytes(b"altered synthetic XML")
    elif damage in ("distance", "model-stamp", "vector-dimension"):
        if damage == "distance":
            # Chroma forbids modifying distance after creation: recreate only in
            # this isolated fixture, retaining the valid completion markers.
            client.delete_collection(manifest["collection"])
            client.create_collection(manifest["collection"], embedding_function=None,
                metadata={"hnsw:space": "l2", "gsj_model_manifest": ports.EMBED_MANIFEST_SHA256})
        else:
            records = collection.get(include=["documents", "metadatas", "embeddings"])
            client.delete_collection(manifest["collection"])
            changed = client.create_collection(manifest["collection"], embedding_function=None,
                metadata={"hnsw:space": "cosine", "gsj_model_manifest":
                          "c" * 64 if damage == "model-stamp" else ports.EMBED_MANIFEST_SHA256})
            changed.add(ids=records["ids"], documents=records["documents"], metadatas=records["metadatas"],
                        embeddings=records["embeddings"] if damage == "model-stamp" else [[.01] * 3 for _ in records["ids"]])
    elif damage == "current-count":
        path = checkpoint.parent / "current.json"
        value = json.loads(path.read_bytes()); value["rows"] += 1
        path.write_text(json.dumps(value))
    elif damage == "checkpoint-incomplete":
        value = json.loads(checkpoint.read_bytes()); value["shards"]["01"]["complete"] = False
        checkpoint.write_text(json.dumps(value))
    elif damage == "checkpoint-missing": checkpoint.unlink()
    with pytest.raises((ValueError, RuntimeError, FileNotFoundError)):
        proof.prove(settings, client=client)


@pytest.mark.parametrize("key,value", [("core_commit", "f" * 40), ("corpus_fingerprint", "f" * 64),
                                      ("corpus_manifest_sha256", "f" * 64), ("generation", "other:1")])
def test_wrong_source_binding_refused_before_model_load(ready_source, key, value):
    settings, client, _, _, loads, *_ = ready_source
    settings[key] = value
    with pytest.raises(ValueError): proof.prove(settings, client=client)
    assert loads == []


@pytest.mark.parametrize("kind", ["files", "dimension", "unloadable"])
def test_actual_model_qualification_is_required(ready_source, monkeypatch, kind):
    settings, client, *_ = ready_source
    if kind == "files": monkeypatch.setattr(ports, "embed_manifest_sha256", lambda path: "f" * 64)
    elif kind == "dimension": monkeypatch.setattr(proof, "load_local_model", lambda path: 383)
    else:
        def fail(path): raise RuntimeError("synthetic unavailable model")
        monkeypatch.setattr(proof, "load_local_model", fail)
    with pytest.raises((ValueError, RuntimeError)): proof.prove(settings, client=client)


def test_existing_initializer_writer_lock_is_never_bypassed(ready_source):
    settings, client, *_ = ready_source
    lock = Path(settings["paths"]["state"]) / "writer.lock"
    with lock.open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError): proof.prove(settings, client=client)
    result = proof.prove(settings, client=client)
    assert result["inventory_verified"] is True


def test_cli_busy_returns_78_without_private_data(ready_source, tmp_path):
    settings, _, *_ = ready_source
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(json.dumps(settings))
    with (Path(settings["paths"]["state"]) / "writer.lock").open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = subprocess.run([sys.executable, "-B", str(ROOT / "ops/installer/startup-source-proof.py"),
                                 "--settings", str(settings_path)], capture_output=True, text=True)
    assert result.returncode == 78
    assert json.loads(result.stdout) == {"format": "gsj.startup-source-data-proof/1", "status": "busy"}
    assert not result.stderr


def test_cli_errors_never_expose_input_values(tmp_path):
    path = tmp_path / "private.json"
    sentinel = "SENSITIVE-STARTUP-PROOF-SENTINEL"
    path.write_text(json.dumps({"private": sentinel}))
    result = subprocess.run([sys.executable, "-B", str(ROOT / "ops/installer/startup-source-proof.py"),
                             "--settings", str(path)], capture_output=True, text=True)
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "failed"
    assert sentinel not in result.stdout + result.stderr
    assert not result.stderr


def test_shard_progress_escapes_dependency_suppression_without_content(ready_source, monkeypatch):
    import contextlib
    import io
    settings, client, manifest, *_ = ready_source
    progress, hidden = io.StringIO(), io.StringIO()
    monkeypatch.setattr(proof.sys, '__stderr__', progress)
    with contextlib.redirect_stdout(hidden), contextlib.redirect_stderr(hidden):
        result = proof.prove(settings, client=client)
    records = [json.loads(line) for line in progress.getvalue().splitlines()]
    assert len(records) == 2*len(manifest['shards'])
    for i, shard in enumerate(manifest['shards']):
        assert records[2*i] == {'event':'source-shard-start','shard':shard['id'],'rows':shard['files'],'vectors':shard['chunks']}
        assert records[2*i+1] == {**records[2*i], 'event':'source-shard-verified'}
    assert 'synthetic startup fixture' not in progress.getvalue()
    assert result['application_readiness_verified'] is False


def test_a_source_older_than_the_sidecar_declaration_is_still_provable(ready_source):
    """The proof runs the CURRENT helper against the SOURCE deployment's live
    initializer.json, which a chart older than the declared vector sidecar renders
    without `released_vectors`. The contract is extended, never swapped — exactly the
    runtime allowlist's rule — so such an older source keeps its first-startup recovery."""
    settings, client, manifest, checkpoint, loads, writes, case = ready_source
    older = dict(settings["initializer"]); older.pop("released_vectors")
    settings = {**settings, "initializer": older}
    result = proof.prove(settings, client=client)
    assert result["status"] == "startup-complete" and result["rows"] == result["vectors"] == 3
    with pytest.raises(ValueError, match="invalid initializer contract"):
        proof.prove({**settings, "initializer": {**older, "unexpected": True}}, client=client)
