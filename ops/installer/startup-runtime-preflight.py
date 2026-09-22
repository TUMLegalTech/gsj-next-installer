"""Fail before stopping a source whose runtime or corpus import is incomplete.

This advisory preflight reads completion receipts under the existing initializer
lock. The later startup-source-proof still proves every SQLite/vector payload.
"""
import argparse
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import sys


def require(condition):
    if not condition:
        raise ValueError('source runtime or startup completion is unqualified')


# (initialize.py, corpus.py) sha256 pairs of qualified SOURCE runtimes. The
# preflight runs inside the failed source Pod, so every runtime still deployed
# somewhere must stay recoverable; a new pair is added, never swapped in.
QUALIFIED_SOURCE_RUNTIMES = {
    # Every engineering build up to the post-audit runtime below, including
    # the live beta.1 full-corpus import.
    ('39c230784af638b4824e7f8238e4871b5f01f33dc5308d99ef9037a6b52134dc',
     '926cd5409d8acefba85ac0b3ab508157aa2296bcc77aaefd734b4cc06e785bac'),
    # Post-audit: startup budget, reason codes, copier quarantine, Chroma wait.
    ('864aa9eb0d2a8fe16041ad93596474eabeb2b322b6067a8434857be54d324bb0',
     '2f565fa259d958aef672b3223475c91fce1e1c0a2993fc22a681afe8b3a6839b'),
    # The parser contract is a version, not a hash of library bytes:
    # parser_identity() reads DECISIONS_PARSER_VERSION instead of hashing
    # search.py's bytes, and both files now compare a manifest with .get so a
    # corpus predating a field reports `core-mismatch` rather than raising
    # KeyError. Added, never swapped: one deployment on the reference k3s
    # cluster still runs the pair above, while two others run this one.
    ('71b1fa3550cfb815c308f0246375184f76f230b08ae76da191f1b3c95e7f9894',
     '2914c4243ba82eeeb2e4521f7b8f6753181fd98b96d296b45e895714fbc7f2ac'),
    # The initializer imports RELEASED vectors when a verified sidecar sits
    # beside the shards (PrecomputedIndex over the existing index_factory
    # seam), and corpus.py gained build_vectors/vector_records/
    # load_vectors_manifest/read_shard_vectors. Added, never swapped: one
    # deployment on the reference cluster runs the first pair and two others
    # run the third.
    ('cf669f72577b10a528610fc234985c4c28a1eb5a7b2cd56c25e34d6c412930a9',
     'b353d7575dc6f779d7d18eff728107928b7c101e80a83968ae15cc0334642ec5'),
    # released_vectors WAITS while staging is in flight rather than silently
    # embedding. Measured race: the installer needs 47 s to unpack 0.75 GiB
    # into the volume while wait-deps + corpus-copy + startup take ~30 s, so
    # the initializer reached the directory before vectors.json existed and
    # spent hours re-deriving vectors that were seconds away. Added, never
    # swapped: the pair above is what another proof deployment runs.
    ('2f12aa6b98352ee7fd91ae74e8c1b750efa0a3cef14fc2d7c51588f1c8c828fd',
     'b353d7575dc6f779d7d18eff728107928b7c101e80a83968ae15cc0334642ec5'),
    # The embedding contract is six fields read from the installed library
    # (dimensions 768, `encoding`), compared field by field and NAMED on
    # refusal; the collection carries both library stamps and is never
    # re-stamped; the sidecar builder encodes through the library's ONNX
    # encoder (build-vectors/merge-vectors/assemble-vectors); the id-count
    # refusal names the count. Added, never swapped: the pair above is what a
    # proof deployment on the reference cluster and one on a second cluster
    # ran.
    ('ba2ae0cf859024ea04ad3639a9ef07aba780e26be43c716e318c974aac30fd47',
     '77fe649ab157c8bede32bcbb7fc9db8a430b3f9c99c4ca04446934de7b362204'),
    # The site DECLARES a released sidecar (initializer setting
    # `released_vectors`, from corpus.vectors_url/path); a declared sidecar is
    # waited for and refused by name, never inferred from blocks that landed
    # 17 s after the first look and never silently replaced by embedding.
    # Added, never swapped: the pair above is a runtime nothing was deployed
    # on.
    ('2698a0f30f01b60d1fab47fa464b4f15943a86116247350689b9052157d5341b',
     'edad077b5823103692ac8f049866a235f3ae6c73d864589acf4148ce3f59d66c'),
    ('2698a0f30f01b60d1fab47fa464b4f15943a86116247350689b9052157d5341b',
     'edad077b5823103692ac8f049866a235f3ae6c73d864589acf4148ce3f59d66c'),
    # corpus.py's tokenizer qualification switches the pinned tokenizer.json's
    # own truncation/padding off, and a shard part records the corpus it was
    # derived from (merge refuses a foreign part). initialize.py is unchanged
    # from the pair above. Added, never swapped: the reference deployment runs
    # the pair above.
    ('2698a0f30f01b60d1fab47fa464b4f15943a86116247350689b9052157d5341b',
     'c51fb2d3d12862edef0055fd1ecba8e6ab7083d06fcb9dca35bf00fd892a30c8'),
    # PrecomputedIndex holds the shard as the numpy block read_shard_vectors
    # already returned, plus an id -> row index, and slices per decision --
    # instead of materialising {id: [768 python floats]} for the WHOLE shard
    # before the first row was written. Measured on the real corpus's largest
    # shard (263,992 chunks x 768 dims) inside the release's own web image:
    # the retired form added 7,797 MiB (30,970 B/row) for a process peak of
    # 8,835 MiB, which no shippable limit could hold; the row index adds
    # 7.5 MiB and the process peaks at 1,732 MiB, in read_shard_vectors' own
    # decompress-and-upcast transient. corpus.py is BYTE-IDENTICAL to the pair
    # above. Added, never swapped: that pair is what the reference deployment
    # runs and what a proof deployment on a second cluster ran.
    ('2a587b583824472f8b13b82a3a42e0a51982ffef23af1715f3af0cd45e88bfc4',
     'c51fb2d3d12862edef0055fd1ecba8e6ab7083d06fcb9dca35bf00fd892a30c8'),
}


def runtime_checks(expected_core):
    from gsj import ports, store
    from gsj_deploy import corpus, initialize
    expected = {
        initialize.deadline_guard: '(deadline)', initialize.chroma_client: '(url)',
        initialize.verify_shard: '(db, coll, manifest, files)',
        initialize.verify_inventory: '(db, coll, manifest, *, prune=False)',
        corpus.digest: '(path)', corpus.load_manifest: '(path)',
        corpus.installed_core_commit: '()', corpus.parser_identity: '()',
        corpus.verify_directory: '(path, entries)', corpus.sha: '(data)', corpus.canonical: '(value)',
        store.schema_ready: '(conn)', ports.embed_manifest_sha256: '(model_dir)',
    }
    runtime = (hashlib.sha256(Path(inspect.getfile(initialize)).read_bytes()).hexdigest(),
               hashlib.sha256(Path(inspect.getfile(corpus)).read_bytes()).hexdigest())
    return {
        'core_identity': corpus.installed_core_commit() == expected_core,
        'public_api_signatures': all(str(inspect.signature(fn)) == signature for fn, signature in expected.items()),
        'initializer_source': runtime in QUALIFIED_SOURCE_RUNTIMES,
        'corpus_source': runtime in QUALIFIED_SOURCE_RUNTIMES,
        'collection_contract': ports.ChromaIndex.DECISIONS == 'gsj_snowflake_m_v2_int8_2048_decisions',
        'model_manifest': ports.EMBED_MANIFEST_SHA256 == '926bfa3a8788ddcc68cde3f706c92d7251781f768d0b01cf40066dd612d2bd42',
        'model_revision': ports.EMBED_MODEL_DEFAULT.endswith('@95c2741480856aa9666782eb4afe11959938017f'),
        'model_encoding': ports.EMBED_ENCODING == 'snowflake-m-v2-onnx-int8-cls-l2-f32-768-max2048-query-v1',
        'model_dimensions': ports.EMBED_DIMENSIONS == 768,
    }


def read_regular(path):
    path = Path(path)
    require(stat.S_ISREG(path.lstat().st_mode))
    return path.read_bytes()


def completed(settings):
    from gsj_deploy import corpus
    cfg = settings['initializer']; paths = settings['paths']
    manifest_raw = read_regular(Path(paths['source'])/'manifest.json')
    require(hashlib.sha256(manifest_raw).hexdigest() == settings['corpus_manifest_sha256'])
    manifest = json.loads(manifest_raw)
    require(manifest['fingerprint'] == settings['corpus_fingerprint']
            and manifest['core_commit'] == settings['core_commit']
            and manifest['embedding'] == settings['model']
            and manifest['rows'] == settings['rows'] and manifest['chunks'] == settings['vectors'])
    identity = corpus.sha(corpus.canonical({'corpus': manifest['fingerprint'],
        'db': str(Path(cfg['db']).resolve()), 'chroma': cfg['chroma_url'],
        'collection': manifest['collection'], 'repair_generation': cfg['repair_generation'],
        'allow_update': cfg['allow_update']}))
    state = Path(paths['state']); lock_path = state/'writer.lock'
    require(stat.S_ISREG(lock_path.lstat().st_mode))
    with lock_path.open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = lock_path.stat()
        opened = os.fstat(lock.fileno())
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino))
        current = json.loads(read_regular(state/'current.json'))
        require(current == {'format': 'gsj.corpus-state/1', 'fingerprint': manifest['fingerprint'],
            'model_manifest': settings['model']['manifest_sha256'], 'identity': identity,
            'rows': settings['rows'], 'vectors': settings['vectors']})
        checkpoint = json.loads(read_regular(state/(identity+'.json')))
        require(checkpoint.get('format') == 'gsj.corpus-progress/1' and checkpoint.get('identity') == identity
                and checkpoint.get('phase') == 'complete' and not checkpoint.get('terminal')
                and set(checkpoint.get('shards', {})) == {s['id'] for s in manifest['shards']}
                and all(s.get('complete') is True and not s.get('terminal') for s in checkpoint['shards'].values()))
        after = lock_path.stat()
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino))
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('core')
    parser.add_argument('--settings')
    args = parser.parse_args()
    try:
        checks = runtime_checks(args.core)
        require(all(checks.values()))
        done = False
        if args.settings:
            settings = json.loads(read_regular(args.settings))
            require(settings['core_commit'] == args.core)
            done = completed(settings)
        print(json.dumps({'format': 'gsj.startup-runtime-preflight/1', 'status': 'passed',
                          'checks': checks, 'startup_complete': done,
                          'application_readiness_verified': False}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'format': 'gsj.startup-runtime-preflight/1', 'status': 'failed',
                          'error_type': type(exc).__name__, 'application_readiness_verified': False}, sort_keys=True))
        return 1


if __name__ == '__main__':
    sys.exit(main())
