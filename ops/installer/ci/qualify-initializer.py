#!/usr/bin/env python3
"""Qualify the RELEASED corpus initializer against the released images, without a cluster.

The initializer pair registered in startup-runtime-preflight.py (QUALIFIED_SOURCE_RUNTIMES)
records a claim; this run is what backs it. It runs the release's web image -- the
initializer's own code, library and embedding model -- against the release's Chroma image
through Docker, on a synthetic corpus and vector sidecar the image's own generator builds,
and passes only when all four hold:

  import   the released vectors are imported: `corpus-vector-source` says `released`,
           the initializer completes with the manifest's rows and vectors;
  readback SQLite and Chroma read back with matching identities: the rows and vectors the
           manifest declares, the sidecar's own values in Chroma for every chunk of every
           decision (one decision spans several chunks, so a vector stored under the wrong
           chunk is seen), the initializer's own inventory verification, and `current.json`
           carrying the computed identity;
  core     a deliberate deterministic shard failure -- a manifest row whose parse disagrees
           with the release (`core-mismatch`, the cause an independent review reproduced) --
           makes ONE import attempt on that shard, persists a terminal checkpoint, and the
           init container's restart names that cause again without a further attempt;
  block    the same shape for a released vector block whose ids disagree with the rows the
           site derives (`source-verification-failed`, the product's own shard-level cause).

Only the release's images run; nothing here is mounted into them. The report binds what it
proves: the images by digest (or, for an engineering image without one, its id, marked
local), the platform, the library commit, and the (initialize.py, corpus.py) sha256 pair
MEASURED inside the image -- which must be registered. The pass criteria live HERE, on the
host, in EXPECTED; the driver reports what it observed. Exit status 0 iff `status` is
`passed`. The release gate (ci/qualify.py gate) requires this report beside the two cluster
reports and holds its digests to the manifest's.

    python3 -B ops/installer/ci/qualify-initializer.py --release release.json --report out.json
    python3 -B ops/installer/ci/qualify-initializer.py --web IMAGE --chroma IMAGE --report out.json
"""
import argparse
import importlib.util
import json
import secrets
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "gsj.initializer-qualification/1"
CASES = ("import", "core", "block")
REGISTRY = Path(__file__).resolve().parents[1] / "startup-runtime-preflight.py"
# What a passing run observes; the driver measures, this module judges.
EXPECTED = {
    "import": {"exit": 0, "vector_source": "released", "complete": True, "rows_match": True, "vectors_match": True,
               "multi_chunk_decisions": 1},
    "readback": {"sqlite_rows_match": True, "chroma_count_matches": True, "inventory_verified": True,
                 "chroma_vectors_are_the_sidecar_s": True, "current_identity_matches": True,
                 "current_fingerprint_matches": True},
    "core": {"first_exit": 1, "first_reason": "core-mismatch", "first_shard_attempts": 1, "first_shard_terminal": True,
             "checkpoint_terminal": True, "checkpoint_last_error": "core-mismatch", "restart_exit": 1,
             "restart_reason": "core-mismatch", "restart_shard_attempts": 1, "restart_import_events_on_failing_shard": 0},
    "block": {"first_exit": 1, "first_reason": "source-verification-failed", "first_shard_attempts": 1,
              "first_shard_terminal": True, "checkpoint_terminal": True, "checkpoint_last_error": "source-verification-failed",
              "restart_exit": 1, "restart_reason": "source-verification-failed", "restart_shard_attempts": 1,
              "restart_import_events_on_failing_shard": 0},
}
# The driver runs INSIDE the web image, on its own python and library; it must import
# nothing that image does not carry (gsj, gsj_deploy, chromadb, numpy). It measures and
# reports; it judges nothing.
DRIVER = r'''
import hashlib, inspect, json, os, platform, shutil, sqlite3, subprocess, sys
from pathlib import Path
import numpy as np
from gsj_deploy import corpus, initialize as init

hosts = json.loads(sys.argv[1])
root = Path("/tmp/gsj-qualify-initializer"); root.mkdir()
model_path = os.environ["GSJ_EMBED_MODEL"]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
report = {"core_commit": corpus.installed_core_commit(),
          "pair": {"initialize_sha256": sha(inspect.getfile(init)), "corpus_sha256": sha(inspect.getfile(corpus))},
          "platform": {"machine": platform.machine(), "system": platform.system().lower(), "python": platform.python_version()}}


def emit(**event):
    print(json.dumps(event, sort_keys=True), flush=True)


def make_source(path, count):
    """count short decisions and ONE long one (several chunks), so the readback
    covers a decision whose chunks could be stored under the wrong rows."""
    path.mkdir()
    for n in range(count):
        body = (f"Initializer qualification synthetic text {n}: der Kläger obsiegt. " * (60 if n == count - 1 else 1)).strip()
        (path / f"{n}.xml").write_text(
            f"<dokument><doknr>QUAL{n}</doknr><aktenzeichen>QUAL-{n}</aktenzeichen>"
            f"<gertyp>QUAL</gertyp><entsch-datum>20200101</entsch-datum><tenor><p>{body}</p></tenor></dokument>")
    return path


def sidecar_into(copied, vectors_dir):
    for path in vectors_dir.iterdir():
        if path.name == "vectors.json" or path.name.endswith(".f16.gz"):
            shutil.copy2(path, copied / path.name)


def settings_for(case, copied, chroma_host):
    return {"db": str(root / case / "db" / "gsj.db"), "source": str(copied), "state": str(root / case / "state"),
            "chroma_url": f"http://{chroma_host}:8000", "model_path": model_path,
            "manifest_sha256": corpus.digest(copied / "manifest.json"), "deadline_seconds": 1800, "attempts": 2,
            "repair_generation": 0, "allow_update": False, "released_vectors": True}


def run_initializer(case, settings, label):
    path = root / case / f"settings-{label}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings))
    proc = subprocess.run([sys.executable, "-B", "-m", "gsj_deploy.initialize", "--settings", str(path)],
                          capture_output=True, text=True, timeout=1800)
    events = []
    for line in proc.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            pass
    emit(stage="initializer-run", case=case, run=label, exit=proc.returncode,
         stages=[e.get("stage") for e in events], stderr_tail=proc.stderr[-400:])
    return proc.returncode, events


def checkpoint_of(settings):
    state = Path(settings["state"])
    files = [p for p in state.glob("*.json") if p.name != "current.json"]
    return json.loads(files[0].read_bytes()) if files else None


def failure_case(case, copied, chroma_host, failing_shard):
    """A deterministic shard failure, then the init container's restart, observed."""
    settings = settings_for(case, copied, chroma_host)
    rc1, events1 = run_initializer(case, settings, "first")
    failed1 = [e for e in events1 if e.get("stage") == "initialization-failed"]
    checkpoint1 = checkpoint_of(settings)
    rc2, events2 = run_initializer(case, settings, "restart")
    failed2 = [e for e in events2 if e.get("stage") == "initialization-failed"]
    imports2 = [e for e in events2 if e.get("stage") == "corpus-import" and e.get("shard") == failing_shard]
    checkpoint2 = checkpoint_of(settings)
    record1 = (checkpoint1 or {}).get("shards", {}).get(failing_shard, {})
    record2 = (checkpoint2 or {}).get("shards", {}).get(failing_shard, {})
    return {"first_exit": rc1, "first_reason": failed1[-1].get("reason") if failed1 else None,
            "first_shard_attempts": record1.get("attempts"), "first_shard_terminal": record1.get("terminal"),
            "checkpoint_terminal": (checkpoint1 or {}).get("terminal"), "checkpoint_last_error": (checkpoint1 or {}).get("last_error"),
            "restart_exit": rc2, "restart_reason": failed2[-1].get("reason") if failed2 else None,
            "restart_shard_attempts": record2.get("attempts"), "restart_import_events_on_failing_shard": len(imports2)}


source = make_source(root / "xml", 5)
image = root / "image"
manifest = corpus.build(source, image, core_commit=report["core_commit"], release_owner="",
                        source_provenance="initializer qualification (synthetic, never published)",
                        qualification=True, shard_size=2)
vectors_dir = root / "vectors"
corpus.build_vectors(source, image, vectors_dir, model_path)
shards = [s["id"] for s in manifest["shards"]]
failing = shards[-1]                              # the first shards import; the last one fails
report["corpus"] = {"rows": manifest["rows"], "chunks": manifest["chunks"], "shards": shards, "failing_shard": failing,
                    "chunks_per_decision": [f["chunks"] for f in manifest["files"]]}

# --- import + readback -----------------------------------------------------------
copied = root / "import" / "copied"; copied.parent.mkdir(parents=True)
corpus.copy_payload(image, copied, corpus.digest(image / "manifest.json"))
sidecar_into(copied, vectors_dir)
settings = settings_for("import", copied, hosts["import"])
rc, events = run_initializer("import", settings, "first")
source_event = next((e for e in events if e.get("stage") == "corpus-vector-source"), {})
complete = next((e for e in events if e.get("stage") == "corpus-complete"), None)
report["import"] = {"exit": rc, "vector_source": source_event.get("source"), "complete": complete is not None,
                    "rows_match": (complete or {}).get("rows") == manifest["rows"],
                    "vectors_match": (complete or {}).get("vectors") == manifest["chunks"],
                    "multi_chunk_decisions": sum(1 for f in manifest["files"] if f["chunks"] > 1)}
readback = {}
try:
    db = sqlite3.connect(settings["db"])
    readback["sqlite_rows_match"] = db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == manifest["rows"]
    import chromadb
    client = chromadb.HttpClient(host=hosts["import"], port=8000)
    coll = init.collection(client, manifest)
    readback["chroma_count_matches"] = coll.count() == manifest["chunks"]
    from gsj import store
    live = store.connect(settings["db"])
    readback["inventory_verified"] = init.verify_inventory(live, coll, manifest) == {"rows": manifest["rows"], "vectors": manifest["chunks"]}
    # the vectors in Chroma are the sidecar's own values, row by row -- not an
    # embedding of the text, and not another chunk's vector
    sidecar = json.loads((copied / "vectors.json").read_bytes())
    identical = True
    for entry in sidecar["shards"]:
        ids, _ = corpus.vector_records(copied / entry["id"], manifest, entry["id"])
        block = corpus.read_shard_vectors(copied, entry, ids, manifest["embedding"]["dimensions"])
        got = coll.get(ids=ids, include=["embeddings"])
        stored = np.asarray([got["embeddings"][got["ids"].index(i)] for i in ids], dtype=np.float32)
        identical = identical and stored.shape == block.shape and np.allclose(stored, block, atol=1e-6)
    readback["chroma_vectors_are_the_sidecar_s"] = bool(identical)
    current = json.loads((Path(settings["state"]) / "current.json").read_bytes())
    identity = corpus.sha(corpus.canonical({"corpus": manifest["fingerprint"], "db": str(Path(settings["db"]).resolve()),
                                             "chroma": settings["chroma_url"], "collection": manifest["collection"],
                                             "repair_generation": 0, "allow_update": False}))
    readback["current_identity_matches"] = current.get("identity") == identity
    readback["current_fingerprint_matches"] = current.get("fingerprint") == manifest["fingerprint"]
except Exception as exc:                               # noqa: BLE001 -- reported, never hidden
    readback["error"] = f"{type(exc).__name__}: {exc}"
report["readback"] = readback

# --- core-mismatch: a manifest row whose parse disagrees with the release -------------
image2 = root / "image-core"; shutil.copytree(image, image2)
tampered = json.loads((image2 / "manifest.json").read_bytes())
victim = [f for f in tampered["files"] if f["shard"] == failing][-1]
victim["row_sha256"] = corpus.sha(b"another parse of this row")
tampered["fingerprint"] = corpus.sha(corpus.canonical({k: v for k, v in tampered.items() if k != "fingerprint"}))
corpus.atomic_json(image2 / "manifest.json", tampered)
copied2 = root / "core" / "copied"; copied2.parent.mkdir(parents=True)
corpus.copy_payload(image2, copied2, corpus.digest(image2 / "manifest.json"))
vectors2 = root / "vectors-core"; vectors2.mkdir()
manifest2 = corpus.load_manifest(image2 / "manifest.json")
for entry in json.loads((vectors_dir / "vectors.json").read_bytes())["shards"]:
    ids, _ = corpus.vector_records(copied / entry["id"], manifest, entry["id"])
    block = corpus.read_shard_vectors(copied, entry, ids, manifest["embedding"]["dimensions"])
    corpus.write_shard_vectors(vectors2, entry["id"], ids, block, corpus_fingerprint=manifest2["fingerprint"])
corpus.merge_vectors(image2, vectors2)
sidecar_into(copied2, vectors2)
report["core"] = failure_case("core", copied2, hosts["core"], failing)

# --- source-verification-failed: a released block whose ids disagree ------------------
copied3 = root / "block" / "copied"; copied3.parent.mkdir(parents=True)
corpus.copy_payload(image, copied3, corpus.digest(image / "manifest.json"))
sidecar_into(copied3, vectors_dir)
value = json.loads((copied3 / "vectors.json").read_bytes())
next(x for x in value["shards"] if x["id"] == failing)["ids_sha256"] = corpus.sha(b"another site's rows")
value.pop("fingerprint"); value["fingerprint"] = corpus.sha(corpus.canonical(value))
corpus.atomic_json(copied3 / "vectors.json", value)
report["block"] = failure_case("block", copied3, hosts["block"], failing)

emit(stage="initializer-qualification", report=report)
'''


def judge(observed):
    """The one judgement: every case's observed values against EXPECTED."""
    cases = {}
    for name, expected in EXPECTED.items():
        seen = observed.get(name) if isinstance(observed.get(name), dict) else {}
        disagreements = sorted(k for k, v in expected.items() if seen.get(k) != v)
        cases[name] = {"observed": seen, "expected": expected, "disagreements": disagreements,
                       "status": "passed" if not disagreements else "failed"}
    return cases


def registered_pairs():
    spec = importlib.util.spec_from_file_location("gsj_startup_runtime_preflight", REGISTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.QUALIFIED_SOURCE_RUNTIMES


def verdict(report):
    """passed iff the schema is this one, every case passed, and the pair the
    run measured inside the image is a registered one."""
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        return "failed"
    cases = report.get("cases") or {}
    if any(not isinstance(cases.get(name), dict) or cases[name].get("status") != "passed" for name in EXPECTED):
        return "failed"
    pair = report.get("pair") or {}
    if pair.get("registered") is not True or not pair.get("initialize_sha256") or not pair.get("corpus_sha256"):
        return "failed"
    return "passed"


def image_references(release):
    """web and chroma as repository@digest, read off a release manifest."""
    images = release.get("images") or {}
    refs = {}
    for name in ("web", "chroma"):
        item = images.get(name) or {}
        if not item.get("repository") or not str(item.get("digest", "")).startswith("sha256:"):
            raise SystemExit(f"release manifest names no {name} image by repository and digest")
        refs[name] = f"{item['repository']}@{item['digest']}"
    return refs


def docker(*argv, capture=True, check=True, stdin=None):
    return subprocess.run(["docker", *argv], check=check, text=True, input=stdin,
                          stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE).stdout


def resolve_image(reference):
    """What the run actually ran: the repository@digest when the image carries
    one, else the image id, marked local (an engineering build)."""
    digests = docker("image", "inspect", "--format", "{{json .RepoDigests}}", reference).strip()
    image_id = docker("image", "inspect", "--format", "{{.Id}}", reference).strip()
    digests = json.loads(digests) if digests else []
    named = [d for d in digests if "@" in reference and d == reference] or digests
    if named:
        return {"reference": reference, "digest": named[0], "id": image_id, "local": False}
    return {"reference": reference, "digest": None, "id": image_id, "local": True}


def qualify(web, chroma, report_path, keep):
    stamp = secrets.token_hex(4)
    network = f"gsj-qualify-initializer-{stamp}"
    containers = [f"{network}-web"]
    report = {"schema": SCHEMA, "status": "running", "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        report["images"] = {"web": resolve_image(web), "chroma": resolve_image(chroma)}
        docker("network", "create", network)
        hosts = {}
        for case in CASES:
            name = f"{network}-chroma-{case}"
            docker("run", "-d", "--name", name, "--network", network, chroma)
            containers.append(name); hosts[case] = name
        time.sleep(3)                                   # the initializer waits for Chroma itself
        proc = subprocess.run(["docker", "run", "--rm", "-i", "--network", network, "--name", f"{network}-web",
                               web, "python", "-B", "-", json.dumps(hosts)],
                              input=DRIVER, text=True, capture_output=True, timeout=3 * 3600)
        lines = []
        for line in proc.stdout.splitlines():
            try:
                lines.append(json.loads(line))
            except ValueError:
                continue
        final = next((line for line in reversed(lines) if line.get("stage") == "initializer-qualification"), None)
        report["runs"] = [line for line in lines if line.get("stage") == "initializer-run"]
        report["driver_exit"] = proc.returncode
        report["driver_stderr_tail"] = proc.stderr[-2000:]
        if final is None:
            report["cases"] = judge({})
            report["error"] = "the driver reported no verdict"
        else:
            inner = final["report"]
            report["corpus"] = inner.get("corpus"); report["core_commit"] = inner.get("core_commit")
            report["platform"] = inner.get("platform")
            pair = dict(inner.get("pair") or {})
            pair["registered"] = (pair.get("initialize_sha256"), pair.get("corpus_sha256")) in registered_pairs()
            report["pair"] = pair
            report["cases"] = judge(inner)
        report["status"] = verdict(report)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        report["status"] = "failed"
        report["error"] = f"{type(exc).__name__}: {getattr(exc, 'stderr', '') or exc}"[:2000]
    finally:
        report["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not keep:
            for name in containers:
                docker("rm", "-f", name, check=False)
            docker("network", "rm", network, check=False)
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--release", type=Path, help="the release manifest (images.web / images.chroma)")
    parser.add_argument("--web", help="the web image (repository@digest); overrides the manifest")
    parser.add_argument("--chroma", help="the chroma image (repository@digest); overrides the manifest")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--keep", action="store_true", help="leave the containers and network for inspection")
    args = parser.parse_args()
    refs = image_references(json.loads(args.release.read_bytes())) if args.release else {}
    web, chroma = args.web or refs.get("web"), args.chroma or refs.get("chroma")
    if not web or not chroma:
        raise SystemExit("name both images: --release release.json, or --web and --chroma")
    report = qualify(web, chroma, args.report, args.keep)
    print(json.dumps({"stage": "initializer-qualification", "status": report["status"],
                      "pair": report.get("pair"), "images": report.get("images"),
                      "cases": {name: case.get("status") for name, case in (report.get("cases") or {}).items()},
                      "report": str(args.report)}), flush=True)
    raise SystemExit(0 if report["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
