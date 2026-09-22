"""Read-only data proof for an explicitly owned, failed first application start.

The caller proves the signed source installer, Kubernetes ownership, stopped
application writers, storage and credentials. This helper binds that control
proof to independently checked source data; it never declares the web ready.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode), "expected a regular proof input")
    return path


def load_local_model(path):
    """Load only the hash-qualified local model; never embed source documents.

    v4.12.1-snowflake: the encoder is an ONNX INT8 graph run on CPU; its output
    width is read from the session's output signature, so nothing is encoded."""
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    import onnxruntime
    options = onnxruntime.SessionOptions()
    options.log_severity_level = 3
    session = onnxruntime.InferenceSession(str(Path(path) / "onnx" / "model_int8.onnx"),
                                           options, providers=["CPUExecutionProvider"])
    return int(session.get_outputs()[0].shape[-1])


def shard_progress(event, shard):
    # Bypass dependency log suppression with a fixed metadata-only schema.
    print(json.dumps({"event": event, "shard": shard["id"],
                      "rows": shard["files"], "vectors": shard["chunks"]},
                     sort_keys=True), file=sys.__stderr__, flush=True)


def prove(settings, *, client=None):
    from gsj import ports, store
    from gsj_deploy import corpus, initialize as init

    required = {"format", "operation", "release_identity", "namespace_uid",
                "generation", "control_sha256", "corpus_manifest_sha256",
                "corpus_fingerprint", "core_commit", "model", "rows", "vectors",
                "initializer", "paths", "deadline_seconds"}
    require(set(settings) == required and settings["format"] == "gsj.startup-source-settings/1",
            "invalid startup source settings")
    require(re.fullmatch(r"[a-f0-9]{24}", settings["operation"] or ""), "invalid operation")
    for key in ("control_sha256", "corpus_manifest_sha256", "corpus_fingerprint"):
        require(re.fullmatch(r"[a-f0-9]{64}", settings[key] or ""), "invalid proof digest")
    require(re.fullmatch(r"[a-f0-9]{40}", settings["core_commit"] or ""), "invalid core identity")
    require(isinstance(settings["namespace_uid"], str) and settings["namespace_uid"], "missing namespace identity")
    require(isinstance(settings["release_identity"], str) and settings["release_identity"], "missing release identity")
    require(re.fullmatch(re.escape(settings["release_identity"]) + r":[1-9][0-9]*",
                         settings["generation"] or ""), "invalid source generation")
    for key in ("rows", "vectors", "deadline_seconds"):
        require(type(settings[key]) is int and settings[key] > 0, "invalid positive proof bound")
    cfg = settings["initializer"]
    # The settings proven here are the SOURCE deployment's live initializer.json,
    # rendered by ITS chart; this helper is the current release's. A source older
    # than the release that added the declared vector sidecar (which the
    # initializer waits for and refuses by name, never silently replacing it by
    # embedding) renders no `released_vectors`, and it must stay provable
    # (added, never swapped — the runtime allowlist's rule). The key plays no
    # part in the identity recomputed below.
    require(set(cfg) - {"released_vectors"} == {"db", "source", "state", "chroma_url", "model_path",
                                                 "manifest_sha256", "deadline_seconds", "attempts",
                                                 "repair_generation", "allow_update"},
            "invalid initializer contract")
    require(type(cfg["allow_update"]) is bool and type(cfg.get("released_vectors", False)) is bool
            and type(cfg["repair_generation"]) is int
            and cfg["repair_generation"] >= 0, "invalid initializer identity")
    require(cfg["manifest_sha256"] == settings["corpus_manifest_sha256"], "initializer manifest mismatch")
    require(set(settings["paths"]) == {"db", "source", "state", "model_path"}, "invalid mounted paths")
    paths = {key: Path(value) for key, value in settings["paths"].items()}
    require(all(path.is_absolute() for path in paths.values()), "proof mounts must be absolute")
    for key in ("source", "state", "model_path"):
        require(stat.S_ISDIR(paths[key].lstat().st_mode), "expected a mounted proof directory")
    regular(paths["db"])
    lock_path = regular(paths["state"] / "writer.lock")
    deadline = time.monotonic() + settings["deadline_seconds"]
    with lock_path.open("rb") as lock, init.deadline_guard(deadline):
        # Never create a missing lock or replace an initializer's inode.
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = os.fstat(lock.fileno())
        current_path = regular(paths["state"] / "current.json")
        current_raw = current_path.read_bytes()
        current = json.loads(current_raw)
        manifest_path = regular(paths["source"] / "manifest.json")
        require(corpus.digest(manifest_path) == settings["corpus_manifest_sha256"], "corpus bytes mismatch")
        manifest = corpus.load_manifest(manifest_path)
        require(manifest["fingerprint"] == settings["corpus_fingerprint"]
                and manifest["core_commit"] == settings["core_commit"] == corpus.installed_core_commit(),
                "source core or corpus identity mismatch")
        require(all(manifest.get(key) == value for key, value in corpus.parser_identity().items()),
                "installed parser or chunker differs")
        expected_model = corpus.embedding_contract()
        require(manifest["embedding"] == settings["model"] == expected_model
                and manifest["collection"] == ports.ChromaIndex.DECISIONS,
                "embedding contract mismatch")
        require(manifest["rows"] == settings["rows"] and manifest["chunks"] == settings["vectors"],
                "release inventory mismatch")
        # Identity uses the original initializer paths, even when a maintenance
        # pod mounts those same volumes under different paths for read-only use.
        identity = corpus.sha(corpus.canonical({"corpus": manifest["fingerprint"],
            "db": str(Path(cfg["db"]).resolve()), "chroma": cfg["chroma_url"],
            "collection": manifest["collection"], "repair_generation": cfg["repair_generation"],
            "allow_update": cfg["allow_update"]}))
        require(current == {"format": "gsj.corpus-state/1", "fingerprint": manifest["fingerprint"],
                            "model_manifest": expected_model["manifest_sha256"], "identity": identity,
                            "rows": manifest["rows"], "vectors": manifest["chunks"]},
                "completed corpus receipt differs")
        checkpoint_path = regular(paths["state"] / (identity + ".json"))
        checkpoint_raw = checkpoint_path.read_bytes()
        checkpoint = json.loads(checkpoint_raw)
        require(checkpoint.get("format") == "gsj.corpus-progress/1"
                and checkpoint.get("identity") == identity and checkpoint.get("phase") == "complete"
                and not checkpoint.get("terminal")
                and set(checkpoint.get("shards", {})) == {s["id"] for s in manifest["shards"]}
                and all(s.get("complete") is True and not s.get("terminal")
                        for s in checkpoint["shards"].values()), "corpus checkpoint is not complete")
        require(ports.embed_manifest_sha256(str(paths["model_path"])) == expected_model["manifest_sha256"],
                "local model files differ")
        require(load_local_model(paths["model_path"]) == expected_model["dimensions"], "model dimensions differ")
        live = client or init.chroma_client(cfg["chroma_url"])
        live.heartbeat()
        # init.collection can stamp an empty collection; use a read-only getter.
        collection = live.get_collection(manifest["collection"], embedding_function=None)
        metadata = collection.metadata or {}
        require(metadata.get("hnsw:space") == expected_model["distance"]
                and metadata.get("gsj_model_manifest") == expected_model["manifest_sha256"]
                and metadata.get("gsj_embedding_encoding") == expected_model["encoding"],
                "existing collection provenance differs")
        with contextlib.closing(sqlite3.connect(paths["db"].resolve().as_uri() + "?mode=ro",
                                               uri=True, timeout=2)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            require(store.schema_ready(db), "schema is not ready")
            require([r[0] for r in db.execute("PRAGMA quick_check")] == ["ok"], "SQLite integrity check failed")
            for shard in manifest["shards"]:
                shard_progress("source-shard-start", shard)
                files = [f for f in manifest["files"] if f["shard"] == shard["id"]]
                require(corpus.verify_directory(paths["source"] / shard["id"], files), "source shard differs")
                require(init.verify_shard(db, collection, manifest, files), "stored shard payload differs")
                shard_progress("source-shard-verified", shard)
            counts = init.verify_inventory(db, collection, manifest, prune=False)
        require(current_path.read_bytes() == current_raw and checkpoint_path.read_bytes() == checkpoint_raw,
                "initializer receipts changed during proof")
        require(corpus.digest(manifest_path) == settings["corpus_manifest_sha256"], "source manifest changed")
        after = lock_path.stat()
        require((after.st_dev, after.st_ino) == (locked.st_dev, locked.st_ino), "initializer lock was replaced")
        return {"format": "gsj.startup-source-data-proof/1", "status": "startup-complete",
                "operation": settings["operation"], "release_identity": settings["release_identity"],
                "namespace_uid": settings["namespace_uid"], "generation": settings["generation"],
                "control_sha256": settings["control_sha256"], "corpus_manifest_sha256": settings["corpus_manifest_sha256"],
                "corpus_fingerprint": manifest["fingerprint"], "core_commit": manifest["core_commit"],
                "model": expected_model, "schema_ready": True, "sqlite_quick_check": True,
                "source_shards_verified": len(manifest["shards"]), "shards_verified": len(manifest["shards"]),
                "inventory_verified": True, "model_loaded": True, "document_embeddings_performed": 0,
                "current_sha256": hashlib.sha256(current_raw).hexdigest(),
                "checkpoint_sha256": hashlib.sha256(checkpoint_raw).hexdigest(), **counts,
                "application_readiness_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True)
    args = parser.parse_args()
    try:
        raw = regular(args.settings).read_bytes()
        with open(os.devnull, "w") as quiet, contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
            result = prove(json.loads(raw))
        result["settings_file_sha256"] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(result, sort_keys=True))
        return 0
    except BlockingIOError:
        print(json.dumps({"format": "gsj.startup-source-data-proof/1", "status": "busy"}))
        return 78
    except Exception as exc:
        print(json.dumps({"format": "gsj.startup-source-data-proof/1", "status": "failed",
                          "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
