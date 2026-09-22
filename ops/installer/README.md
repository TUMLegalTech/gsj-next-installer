# Installer release artifacts

The release build/verification contract and the operator boundary for the
single distributed installer. The target operator runs the generated
script, never these Python build helpers. See `site.schema.json` and the
installer's help for site configuration and lifecycle commands.
Concrete install, upgrade and recovery commands are in
[the operator guide](OPERATOR.md).

`build.py --manifest FILE --output FILE` emits one executable. It packages
the chart of the PINNED product commit (`web-pin.json` at the repository
root, read from Git objects, never from a working tree, and refused unless
it hashes to the recorded digest), this directory's schema, defaults, jq
validators/compiler, the public release key, the declared addon payloads and
the runtime helpers. The shell
runtime is followed by `__GSJ_PAYLOAD_BELOW__` on a line by itself, then a
base64-encoded deterministic gzip/tar payload. `runtime.sh` exports
`GSJ_PAYLOAD`; its `@CLIENT_TABLE@` placeholder becomes the shell function
`gsj_client_info TOOL PLATFORM`, returning `URL<TAB>SHA256`. The function
works before jq is installed.

By default the runtime does NOT use that table: it reads the helm, kubectl and
jq already installed on the operator's machine and refuses, in the first
seconds, if one is missing or below its floor (helm 3.13, kubectl 1.24,
jq 1.6 — each measured against real binaries, see the comment block above
`GSJ_HELM_FLOOR` in `runtime.sh`). OpenSSL has a floor of its own, checked in
the same first seconds and never downloaded: OpenSSL 3.0 or newer, not LibreSSL
(`GSJ_OPENSSL_FLOOR`; the certificate-hostname refusals read the verdict
`openssl x509 -checkhost` prints, which LibreSSL does not implement). The
refusal happens before the payload is unpacked, so it costs nothing and touches
nothing. `--fetch-tools`, accepted by every command, restores the download:
`gsj_client_info` then supplies the pinned URL and SHA256 per tool, and
verified clients are cached in the runtime's private bin directory. Neither
source siblings nor Python/npm/pip/Docker are target prerequisites for an
existing-cluster installation.

`ops/installer/rehearsal.sh` turns an `inspect` profile
(`gsj.environment-profile/1`) into a local k3d cluster carrying the fields that
transfer — distribution and version, the default StorageClass shape and the
path local-path writes to, the IngressClass, the occupied namespaces — so an
install can be rehearsed before a consumer runs one. Its header lists what a
rehearsal cannot carry.

The immutable manifest format is documented in `release.schema.json` and
enforced by the builder. Required fields are:

| Field | Contract |
|---|---|
| `schema`, `identity`, `version` | `gsj.release/1`, explicit identity base, version matching chart version/appVersion; packaging appends the payload fingerprint to the public identity |
| `qualification` | `true` for development snapshots and unpublished corpus; this is retained in the signed descriptor |
| `core` | exact `{tag,commit}`; corpus parser commit must match |
| `platforms` | the native Linux architectures this artifact actually qualifies |
| `images` | exactly `web`, `runner`, `mcp`, `forgejo`, `chroma`, `decisionsData` |
| each image | `{repository,digest,platforms:{"linux/arm64":"sha256:…"}}`; every declared platform requires its own manifest digest |
| `clients` | `helm`, `kubectl`, `jq` → platform → `{url,sha256}`; HTTPS and fixed SHA256 required |
| `corpus` | `manifest_sha256`, `fingerprint`, `source_sha256`, positive `rows` and `chunks` |
| `model` | exact corpus embedding contract: `model`, Git `revision`, `manifest_sha256`, `dimensions`, `distance` |
| `schema_asset` | core Git path `gsj/assets/schema_registry/snapshot.json.gz` and its exact compressed-file `sha256` |
| `release_base_url` | immutable HTTPS artifact origin; an empty value is permitted only for qualification and records upgrade distribution as unavailable |
| `addons` | `traefik`, `certManager`, `localPath` → `{path,sha256,images}`; paths below `addons/`, every controller and helper image pinned |

`clients.json` supplies verified Linux amd64/arm64 downloads for Helm4.2.2,
kubectl1.35.8 and jq1.8.2. Download verification and native execution are
different evidence: do not claim an architecture was executed merely
because its official checksum and registry manifest exist.

Local build inputs live in `_build`, which is excluded from the embedded
public manifest. Paths are relative to the input manifest unless absolute:

```json
{
  "_build": {
    "corpus_manifest": "/release-inputs/corpus/manifest.json",
    "trust_key_file": "/release-keys/public.pem",
    "core_git_dir": "/release-inputs/gsj-next.git",
    "addons": {
      "traefik-41.5.0.tgz": {
        "path": "/release-inputs/addons/traefik-41.5.0.tgz",
        "sha256": "<64 hex characters>"
      }
    },
    "helpers": {
      "qualification.json": {
        "path": "/release-inputs/qualification.json",
        "sha256": "<64 hex characters>",
        "executable": false
      }
    }
  }
}
```

Optional `_build` keys `runtime`, `site.schema.json`, `defaults.json`,
`validate.jq`, and `compile.jq` override those inputs; defaults are this
directory's files. `chart` accepts a chart directory or an existing tgz, and
only a manifest with `qualification: true` may name one: a published release
packages the pinned chart and nothing else.
When the selected runtime sources `helpers/verification-cleanup.sh`, the builder
automatically embeds the adjacent helper and includes its hash in the release
identity. An explicit `_build.helpers["verification-cleanup.sh"]` path/hash can
select frozen helper bytes. A historical runtime that does not source it retains
its historical payload. Missing helpers, changed declared bytes and conflicting
file/directory paths fail packaging.
The standalone runtime marker `# GSJ_RUNTIME_HELPER: capacity.py` similarly
includes the capacity helper, which the installer feeds to Python inside the
signed application image. It adds no Python dependency on the operator host.
An explicit `_build.helpers["capacity.py"]` path/hash selects frozen bytes.
The corresponding `backup-recovery.py` marker embeds the public maintenance
recovery helper. It runs only in an exact owned maintenance Pod; it does not
add a Python dependency to the tools host or alter an application image.

Before an existing deployment is stopped, capacity qualification checks the
recorded namespace/PVC UIDs, live PV claim bindings and UIDs, source controller
identities, source node, and actual database/workspace mounts. A separate
owned Pod mounts all three source claims read-only and measures `statvfs`
bytes/inodes and aggregate file sizes. It never opens customer file payloads.
The script also measures its backup and private staging filesystems with GNU
`stat -f`. A missing mount, unavailable measurement, drift or insufficient
space stops the operation before application quiescence.

The estimate counts logical file bytes, including sparse holes and repeated
hard links, PAX/manifest overhead, gzip expansion, encryption padding and a
growth margin. It reserves two plaintext archive copies in maintenance
`/transfer`, encrypted output and private resource staging on the script host,
and configured source-filesystem headroom. Equal observed filesystem IDs are
grouped conservatively: requirements add and available bytes never add. The
quiesced maintenance Pod is measured again before checkpoint/archive writes;
the migration path repeats the source headroom gate. Reports contain only
aggregates and deployment/storage identities, with the measurement time and
live-estimate/quiesced distinction. These measurements are not space
reservations or proof that differently identified thin-provisioned filesystems
have independent physical backing. The read-only probe requires same-node
concurrent mounting; a claim that refuses it yields unknown, not a passing
capacity result.

Ordinary backup retry reuses an intact verified archive only while the exact
source writers stayed stopped, and never overwrites partial artifacts. An
immutable closure records the original snapshot hash, namespace/PVC/PV UIDs,
credential/configuration fingerprint, stopped Deployment generations and
terminal Job identities. Publication and reuse recheck this closure. A
scale-up/scale-down cycle, replacement PV, pending or newly completed Job,
or changed credentials requires a fresh recovery point. Historical archives
without a closure remain valid historical recovery material; they cannot
certify a fresh pre-migration backup.

Explicit `repair --operation ID --backup-round N` selects a new source round.
It verifies the preceding encrypted recovery point and key, matches the
actual workload/init images and corpus configuration against both owned
installed and ready-state records, and captures the source and original
replicas before stopping writers. A recorded ready target can therefore
supersede an older completed source after verification failed. Ambiguous or
unrecorded partially applied targets are refused. New source snapshots and
archives use `ID.rN` while round zero retains its original names. An exact
reserved round can continue after interruption; earlier rounds are never
replaced. Source selection and capacity checks are read-only apart from the
operation-owned read-only capacity Pod. They do not assert application
acceptance or that an unrecorded migration finished.

A first startup without an installed or ready-state record can be recovered
with `repair --operation ID --source-installer PATH`. The predecessor installer
must retain its adjacent signed descriptor and signature. The current embedded
trust root authenticates it; saved original operation/control identities,
credentials and a complete read-only SQLite/Chroma/model inventory proof admit
an immutable consistent backup. A `startup-complete` proof explicitly does not
claim application readiness.

A failed Helm apply in that first-startup repair has one bounded continuation.
A continuation program is a later signed installer that completes the already
attempted signed target, not a new application release:

```sh
bash ./continuation/gsj-install.sh repair --operation ID \
  --continue-helm-installer /saved/failed-target/gsj-install.sh \
  --config site.json --non-interactive
```

`--continue-helm-installer` is accepted only by `repair`, without
`--source-installer` or `--backup-round`. The target's adjacent descriptor and
signature must remain available. The program authenticates them with its own
embedded trust root, never a key supplied beside the target, and never executes
the target's shell header. A continuation program therefore embeds the same
release trust key as its target, and its manifest must declare the exact target
identity in `supported_sources`. Admission requires the saved partial
first-startup operation with its original source proof and backup evidence, no
installed or ready-state record, and the target's recorded failed Helm
revision: only a legacy `kubectl-patch` ownership conflict on web
`.spec.replicas`, with that web stopped and the partial target otherwise exactly
present. Configuration, repair generation, namespace, controller, PVC/PV and
credential identities stay bound to the saved operation; auxiliary resources
retain their original UIDs and Helm ownership. The historical backup remains
immutable and is not represented as a fresh snapshot of the restarted backing
services.

The program stages the exact successor template while replicas stay zero, then
starts it through a guarded scale-subresource write (UID/resourceVersion
preconditions, at most three attempts, retried only across status-only changes)
behind its new provisioning revision barrier. Ordinary Helm provisioning and
full application acceptance complete the selected target. A durable
continuation intent permits recovery of lost staging replies without creating
another successor revision. Pending or failed successor Helm writes are
refused; a completed successor is validated before acceptance resumes.
Deploying the program's own application release is a subsequent declared
upgrade or repair, with its own source and backup requirements.

A different signed program can take over a saved continuation only by adding
`--continue-from-program /saved/prior-program/gsj-install.sh` to that command,
while the exact successor is staged at zero and before its Helm revision
exists. Both predecessors need adjacent authenticated descriptors/signatures,
and the new program must declare both identities in `supported_sources`. The
original continuation intent remains unchanged; one create-only receipt binds
the original proof, backup, credentials, site, Lease, namespace and exact
stopped successor. The receipt and saved signed prior program permit retry by
the same program; an old or third program is refused. This never changes the
selected application target or creates a new backup round.

A restored instance whose files are already verified but whose first target
Helm operation has not begun can select a corrected installer program separately:

```sh
bash ./corrected/gsj-install.sh restore-repair --operation ID \
  --source-installer /saved/original-restore-release/gsj-install.sh \
  --config site.json --non-interactive
```

The corrected program must declare the exact original release in
`supported_sources`. It authenticates that release's adjacent descriptor and
signature, then retains its chart, images, schema, application identity and
acceptance checks. The complete restore checkpoint, original operation intent,
archive hashes, file proof, credentials and target storage UID bindings must
match before Lease renewal. No application controller, volume writer or new
Helm record is admitted; opaque Helm history restored from the backup is checked
against its exact creation intents and UID receipts. A create-only program
receipt and copies of the original checkpoint/operation preserve this distinction.
The same corrected program can retry before Helm starts; after application
startup begins, use the exact original release's ordinary named resume path.

Named `backup-repair --operation ID --generation N`
reserves a new immutable archive name and records the original quiescence,
credential/configuration fingerprint, previous artifact hashes and any old
maintenance Pod UID/specification. It refuses a source migration, credential
drift, foreign path, verified prior receipt, or historical snapshot without
the original credential baseline. Original controller replica counts remain
in that round's first quiescence snapshot. A generation retries incomplete
archives within one continuously quiesced round (`ID.rN.gM`); it cannot replace
a verified earlier round or relabel newer source data as the older source.

An abandoned `kubectl exec` archive writer can outlive its client. Generation
repair first proves a dedicated maintenance container, freezes its old exec
processes, and preserves every temporary `/transfer` file as separately
encrypted evidence. It verifies those bytes against the stopped source before
UID-conditional Pod deletion and waiting for disappearance. Every interrupted
preservation stream retains its own partial filename. Only a verified
preservation receipt and successful old-Pod retirement admit the next archive
generation; failure leaves the old recovery material and source PVCs intact.
The original operation is then continued through named resume.

`core_git_dir` defaults to `ops/.build/gsj-next.git`, a bare clone of the
core library (`git clone --bare <gsj-next> ops/.build/gsj-next.git`); the
builder reads the schema asset from the manifest's exact core commit and
packages the verified bytes at `core-schema/snapshot.json.gz`. The pinned
product commit is read from `ops/.build/gsj-next-web.git`, the `../gsj-next-web`
sibling, or the Git directory `GSJ_NEXT_WEB_GIT_DIR` names — whichever carries
the commit `web-pin.json` records.
Packaging a directory requires engineering Helm. The builder normalizes
the packaged tar ownership, modes and timestamps; the resulting chart
hash is the one in the installer inventory. It rejects symlinks, archive
traversal, duplicate entries, compiled Python/cache files and mismatched
chart versions. The product's own release publishes its chart to its OCI
registry for the direct Helm path; the installer embeds the pinned chart
with every image pinned by digest from the release manifest, and the
installer's release attaches these exact normalized bytes (hash
`source.chart_sha256`) as an audit copy. Installing that tgz directly is
unsupported: its values carry no digests.

Every payload file is listed in `SHA256SUMS`. `release.json` also records
payload byte counts/hashes, runtime hash and the public-key fingerprint.
Its `source` records runtime and normalized chart hashes. The public
`identity` includes a hash of the full public inputs, including the payload
inventory; changing the runtime, chart, configuration schema, helper,
image, or release origin changes that identity. The original identity
prefix remains in `identity_base`. Detached descriptors use this derived
public identity. Existing candidate files must remain unchanged: a repair
gets a new output directory and a new identity.
The builder checks that public addon entries match the actual packaged
bytes. It requires the full validated corpus manifest as a build input
and verifies its identity, aggregate counts and parser commit. A corpus
marked unpublished cannot be packaged as a public release. Public
packaging also requires a clean worktree of this repository; a build against
a dirty tree must declare `qualification: true`.
Builder validation checks the recorded inventories only. The hand-run
release preparation (`ci/release.py build`) builds no image: the four product
images (web, runner, mcp, decisions-data) are the product release's published
digests, pinned in `web-pin.json`, and Forgejo and Chroma are the approved
upstream digests in the input catalog. It inspects every one of them and every
managed add-on image in the registry, for every declared platform, reads the
corpus manifest out of the pinned decisions-data image, and writes the
release manifest before anything is signed; the full application's behavior
must be established by release qualification, not inferred from a
syntactically valid digest. Until promotion fills `release` and `images` in
`web-pin.json`, `build` refuses; a proof build is a hand-assembled manifest
with `qualification: true`. The pin is held a second time where every
published build passes: `build.py`'s shared preparation (`build` and `sign`
alike) refuses a published manifest while the pin names no release, and
refuses any product image (`web`, `runner`, `mcp`, `decisionsData`) whose
repository or digest is not the pinned one, naming the image and both values —
so a manifest whose product-image repository or digest was edited after
`ci/release.py build` wrote it can be neither built nor signed. Only those four
pairs are held to the pin: Forgejo and Chroma (approved upstream digests), the
per-platform child digests, the client downloads, the add-on image references
and the `_build` inputs are checked for shape and consistency, not against the
pin — they are what a maintainer reviews by hand in the written manifest, and
`_build.helpers` is where the isolated regression's report is added (the
release steps below). Qualification builds are exempt: they name loopback or
proof images on purpose.

The isolated regression (`ci/regression.py`, hand-run on a Linux host) runs
this repository's suites against the exact installed product and core pins.
Its engineering environment has pinned direct test dependencies, verified
Helm/jq binaries and the two pinned addon chart archives. Tests run as an
unprivileged user in a Linux network namespace with loopback only; no
cluster, Docker daemon or embedding model is used. A skip, failure or missing
test result blocks the build. The report records the installer, product and
core commits and the hashes of the runtime, its helpers and the tests. The
builder embeds it as `helpers/isolated-regression.json`, covered by the
installer signature. This precedes the separate full live ordinary and
populated upgrade/restore gates (`ci/qualify.py`, hand-run against a
disposable cluster that can pull the private images). No CI system runs any
of this: the repository's workflow runs the tests alone, holds no secret and
uses no self-hosted runner.

Prepare the pinned optional cluster addons with:

```sh
python3 -B ops/installer/prepare-addons.py --output /tmp/gsj-addon-inputs
```

The emitted `inventory.json` has `addons` for the public manifest and
`buildAddons` for `_build.addons`. It records upstream and transformed
hashes separately. Traefik41.5.0 and cert-manager1.21.2 remain exact
upstream chart bytes. All five cert-manager images are inventoried,
including the runtime-created ACME HTTP01 solver and startup check.

The local-path0.0.37 transform creates namespace `gsj-storage`, unique
cluster RBAC names, and provisioner `rancher.io/gsj-local-path`. It pins
both provisioner and helper images, sets the initial backing path to
`/var/local-path-provisioner/gsj-managed`, and removes the upstream
StorageClass. The runtime creates and owns the selected `Retain` class
and explicit node/path configuration. The namespace permits the hostPath
helper pods. The original kind provisioner can coexist. This transform
is guarded by the exact upstream SHA256 and expected replacement counts;
an upstream change requires a new reviewed payload. A partial fetch can
resume only while its existing named files match these exact bytes.

The sixth image, `gsj-decisions-data`, is built and published by the product
repository with the product's other images (its `ops/build-corpus-image.py`
and `ops/decisions-data.Dockerfile`): it contains pinned Python 3.12, the
product's stdlib-only copier and `/corpus/{manifest.json,shard-*.tar.gz}`,
generated from raw XML shards at the exact core pin, never from an existing
customer database. Its default nonroot invocation is `python -m
gsj_deploy.corpus copy --source /corpus`; the chart supplies `--destination`
and `--manifest-sha256`. Labels identify the core commit and the manifest
hash; `ci/release.py build` reads the manifest out of the pinned image and
requires the label to name the same bytes. The product's image-source
snapshot helper (`ops/snapshot.py` there) records the source identity of the
application images the same way; those identities travel in the product
release, and the installer pins the resulting digests.

## The release, step by step

Hand-run, in this order, on a maintainer's machine with the siblings and the
staged build material in place (the root README, *Building and testing*).
Nothing here runs in CI; the public workflow runs only the subset that needs
no private input.

1. **The full run** — every test, nothing skipped, nothing excluded:
   `.venv/bin/python -B ops/installer/ci/full-suite.py --report /release-output/full-suite.json`.
   It refuses to start when a prerequisite it knows is missing — the four
   packages (`gsj_deploy`, `gsj_web`, `agent_runner`, `gsj`), a
   `chromadb-client` still installed, the pinned Git objects, `bash`, `helm`,
   `jq` and `openssl`, the two add-on archives, an interpreter that is not
   X.509-strict, a missing system CA bundle — names every test file to pytest
   so the modules the public CI ignores cannot be left out, and fails on any
   skip whatever its reason, expected failure, deselection, collection error
   or file that contributed no test. A release whose full run is not green is
   not built: that is this list's rule, not a refusal in the builder.
2. **The isolated regression** on a Linux host (`ci/regression.py prepare`,
   then `run` inside a loopback-only network namespace; see above). Its
   report enters the installer only if the manifest names it: after step 3,
   add it to the written manifest's `_build.helpers` as
   `isolated-regression.json` (path and sha256) — the builder packages every
   `_build.helpers` entry under `helpers/`, and its hash enters the release
   identity.
3. **The release manifest**: `ci/release.py inputs`, then `ci/release.py build`
   against the promoted pin (`release` and `images` filled in `web-pin.json`);
   then the one hand edit above, and a review of every field the pin does not
   hold (the paragraph on the binding, above).
4. **Build, sign, verify** (below), with the private key outside every
   repository.
5. **Qualification** against a disposable cluster (`ci/qualify.py`, ordinary
   and populated upgrade/restore), then publication of the exact signed
   bytes (`ci/stage.py`).

Build, sign, then verify the same installer bytes:

```sh
python3 -B ops/installer/build.py --manifest /release-inputs/release.json \
  --output /release-output/gsj-install.sh
python3 -B ops/installer/build.py sign --manifest /release-inputs/release.json \
  --installer /release-output/gsj-install.sh \
  --private-key /release-keys/private.pem \
  --descriptor /release-output/installer-descriptor.json \
  --signature /release-output/installer-descriptor.sig
python3 -B ops/installer/build.py verify --installer /release-output/gsj-install.sh \
  --descriptor /release-output/installer-descriptor.json \
  --signature /release-output/installer-descriptor.sig \
  --public-key /release-keys/public.pem
```

Signing uses RSA3072 or stronger with SHA256. The private key must be
mode0600 or stricter, outside every repository and outside the cluster.
Only the public key enters the archive. Signing refuses an installer
whose bytes no longer match the manifest and current build inputs. It
creates a detached canonical descriptor containing release identity,
qualification status, manifest/key fingerprints and installer size/hash;
the signature covers that entire descriptor. Existing output files are
never silently overwritten.

Operators can verify before executing without Python or jq:

```sh
bash verify-release.sh gsj-install.sh installer-descriptor.json \
  installer-descriptor.sig trusted-release-public.pem
```

Publish `verify-release.sh`, the public key, descriptor, signature and
installer as release assets. The public key must be obtained through a
trusted channel; accepting a key supplied by an untrusted installer
would not establish authenticity. Verification does not execute the
installer.

The upgrade downloader expects each immutable version directory below
`release_base_url` to contain `gsj-install.sh`,
`installer-descriptor.json`, and `installer-descriptor.sig`. Verify the
signed descriptor before trusting or executing downloaded installer bytes.
Qualification artifacts served from a private CA origin require the
explicit site `delivery.ca_file`; the installer never
silently changes a host or browser trust store.

Populated upgrade qualification invokes the installed source script with
`upgrade --to VERSION`, then repeats that invocation and compares preserved
state. The candidate's exact signed files must be staged at that source
manifest's version URL before the test. A locally available target bundle does
not satisfy this prerequisite. Qualification records source/target versions
and installer hashes. A release is promoted publicly only after these checks,
complete corpus acceptance and restoration have passed for its exact signed
installer.
