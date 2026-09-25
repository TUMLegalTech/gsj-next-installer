# gsj-next-installer

The signed, one-script installer for **GSJ**, the German legal-case workbench
of TUM Legal Tech: one executable, `gsj-install.sh`, that installs, upgrades,
backs up and restores a GSJ deployment on an existing Kubernetes cluster and
verifies it end to end before it reports *Complete*.

This repository holds the installer program and its release tooling. The
product it installs — the lawyer's door, the KI-Kollege agent runner, the
Forgejo archive, the Chroma index, the MCP door and the Helm chart that
deploys them — is versioned in its own repository and **pinned** here (see
*The pin*). The installer never builds the product; it packages the pinned
chart, pins the product's images by digest and drives them.

**Licensing is not yet decided.** This repository deliberately carries no
LICENSE file. Until a licence is chosen and added, no licence is granted.

## What it installs

A GSJ site: the `gsj-web` application (the door lawyers use, the admin plane,
the MCP door the agent uses), the `agent-runner`, a Forgejo instance as the one
authority for cases and identities, a Chroma vector index, the decisions
corpus (about 34,000 German Federal Court of Justice decisions, imported at
first start), and the Kubernetes objects around them: volumes, NetworkPolicies,
an Ingress with TLS, and the provisioning Job that mints every credential.

One installer, verbs `inspect`, `install`, `upgrade`, `resume`, `repair`,
`backup`, `restore`, `abandon`, `sweep` and the named repairs, all under a
Kubernetes Lease so two operators cannot act on one deployment at once. The
operator guide is **[`ops/installer/OPERATOR.md`](ops/installer/OPERATOR.md)**:
it walks a first install in ten steps and is the reference for everything
after. Read its **step 0** before anything else; it lists what can stop an
install and when you would find out.

## What a customer must have

- **An existing Kubernetes cluster, version 1.27 or newer**, with a storage
  provisioner the installer admits — `rancher.io/local-path`, the installer's
  own `rancher.io/gsj-local-path`, or `kubernetes.io/no-provisioner` with
  volumes you make yourself — and a single node that can hold the three
  volumes (the deployment is single-node, ReadWriteOnce). An ingress
  controller and a TLS route, or the installer's managed Traefik and ACME
  profiles. A CNI that enforces NetworkPolicy, if the isolation is to be real.
- **A Linux machine to run the installer from**, with Bash, curl, tar/gzip,
  base64 and a SHA-256 tool, a kubeconfig for the cluster, **OpenSSL ≥ 3.0**
  (OpenSSL, not LibreSSL: macOS's `/usr/bin/openssl` is LibreSSL, which has
  no `x509 -checkhost`, and is refused by name) and the three clients at or
  above the measured floors: **helm ≥ 3.13**, **kubectl ≥ 1.24**,
  **jq ≥ 1.6**. The installer refuses in its first seconds, before touching
  anything, if one is missing or older: a missing or too-old client, and a
  LibreSSL or an OpenSSL below the floor, are named with the tool, the floor
  and what was found; an `openssl` absent from the PATH altogether is refused
  by name alone, as a required utility. `--fetch-tools` downloads its own
  pinned clients instead (it does not supply OpenSSL). `init` is the one
  command that does not stop at the first: it names them all at once, in its
  report (below).
- **A vision-capable OCR endpoint**, for scanned pages: an OpenAI-compatible
  chat-completions route whose model can read an image. Step 0 of the guide
  has a probe you can run with `curl` and `jq` before you start, and the
  installer probes it again in its first minute. It may be the same server as
  the LLM if that model reads images. Without one the install still completes,
  with the scanned-page acceptance check skipped and named as such, and no
  scanned page is read until you set the endpoint and run `install` again.
- **An LLM endpoint** (OpenAI-compatible), for the agent, with its API key in
  a file the installer reads, or in a Kubernetes Secret you name. Without one
  the install still completes, with the two agent checks skipped and named,
  and the agent cannot answer until an endpoint is set — per case in the web
  UI, or in the site file and `install` again. A verification with skipped
  checks is reported as **partial**, in the record and on screen.
- **A read-only GHCR token issued by TUM Legal Tech.** The product images are
  private packages on `ghcr.io`; the installer creates the pull Secret from a
  registry auth file you point it at. TUM Legal Tech hands the token over
  directly, with the release; it never travels through this repository.
- About 3.5 GB free on the machine you install from (the corpus vectors and
  their envelope), and the volume sizes in the guide on the cluster.

## `init`: one file, one command, one report

<!-- init: begin -->
The shortest path onto a customer's box is one download and one command.
Download `gsj-install.sh` alone from the release into an empty folder on the
Linux machine you will install from, export `KUBECONFIG`, and run:

```sh
bash gsj-install.sh init
```

`init` fetches the rest of its own release — `verify-release.sh`,
`release.pem`, `installer-descriptor.json` and `installer-descriptor.sig`,
from the release directory the installer names, for its own version. Files
already beside the installer (or, for the key alone, in
`$HOME/gsj-operator/trust/`, the guide's layout) are used and never
overwritten; a file from another release — another version, another build
of the same version, another key, a verifier that is not the one this
release was published with — is refused by name and never replaced. Every
file, present or downloaded, is copied into the run's private work directory
and judged there: the key against the one the installer carries, the
descriptor's version and build against the installer's own, the signature
under the embedded key, a verifier's bytes against the ones this release was
published with. Then the installer's own bytes are held to the signed
descriptor (SHA-256 and length, under the embedded key), the published
verifier is run over the same files from that private copy, and only when
both pass are the downloaded files put beside the installer (or, when that
folder cannot be written, in `$HOME/gsj-operator/releases/<version>/`); an
unverified run keeps none.

Then it checks the box, all at once, and writes every result as PASS, FAIL
or UNKNOWN with the reason and the fix: helm, kubectl (and its skew
against the cluster) and jq against their floors, saying what to install and
which of them `--fetch-tools` can supply for the other commands (never
OpenSSL), with OpenSSL, bash, curl, tar, gzip, base64 and the SHA-256 tool
recorded as found (a box that lacks one of those is refused before `init`
can run, one at a time); the
cluster its kubeconfig points at, named by its context, and its version
against the floor; `github.com`, where the corpus release lives, and
`ghcr.io`, where the images are, from this machine; the free disk the corpus
download needs (about 3.5 GB on one filesystem, or 1.9 GB under `TMPDIR`
and 1.7 GB under the cache when they are different filesystems), the OS,
the architecture — and the nodes' architecture against the release's
images, once `inspect` has run. It prepares `$HOME/gsj-operator/` with a
private `credentials/` folder (created 0700, create-only, never through a
symlink; a folder it did not make is refused unless it is a plain folder
you own that group and others cannot write, and that refusal comes before
anything is written beside the installer or under `$HOME` -- the only
thing written before it is the payload the installer unpacks into its own
private temporary folder, which it removes on exit), runs
`inspect`, and writes **one report** —
`$HOME/gsj-operator/gsj-init-report-<time>.json`: the verification result,
every check, and the inspect profile — the one file to send back to TUM
Legal Tech. It ends with a plain summary: what passed, what must be fixed
before an install, and that file. It exits 0 when the release is verified
and nothing failed, 3 when the report names something to fix (an unverified
release included), 1 when it stopped on a named refusal (a failed
verification, a companion file from another release, a working folder it
refused, `--fetch-tools`).

`init` is **read-only against your cluster**: its own read is one
`kubectl version`, and `inspect`'s are its gets, one more `version` and
`top nodes`; it creates, changes and deletes
nothing there — no namespace, no Lease, no Pod, no probe — so it is safe to
run against a production cluster. It downloads only its own release's four
files, only over HTTPS, and executes nothing it downloaded except the
published verifier; it refuses `--fetch-tools`, which would download and
run three clients. Without a network it still produces its report from what
is on the box, and says what the no-egress route needs instead. A missing or
LibreSSL `openssl`, a missing bash, curl, tar, gzip or base64, or a machine
without `sha256sum` or `shasum`, is refused by name before `init` runs, one
at a time, like before every other command: those are the tools `init`
cannot report around.

**The honest limit.** `init` proves that the installer arrived intact and
matches its published descriptor. It cannot prove that the installer is
genuine, because a modified installer could skip its own check. The
separate verifier, run by hand **before** executing anything, is the
stronger check and stays documented below; run it if that difference
matters to you.
<!-- init: end -->

## Releases: how they are named, what they contain, how to verify one

A release is named by the **product version it installs**:
`vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-beta.N`, the same number as the
chart's `version` and the product's own release tag. The installer's public
manifest (`release.json` inside the payload, `manifest.json` beside it) also
carries an `identity`: the version plus a hash of every public input, so two
builds with different bytes never share an identity.

Each release attaches:

| asset | what it is |
|---|---|
| `gsj-install.sh` | the installer: a Bash runtime followed by a base64 payload (chart, schemas, defaults, jq programs, add-on charts, helpers, the public trust key) |
| `installer-descriptor.json`, `installer-descriptor.sig` | the signed detached descriptor: release identity, qualification status, manifest hash, the installer's exact size and SHA-256 |
| `release.pem` | the public trust key the descriptor is verified under, published beside the installer |
| `verify-release.sh` | the verifier: Bash and OpenSSL, no Python, no jq |
| `manifest.json` | the public release manifest (`gsj.release/1`): the six images by digest, the client pins, the corpus identity, the core library commit |
| `gsj-<version>.tgz` | an audit copy of the chart the installer embeds; installing it directly is not supported |
| `image-inventory.json`, `corpus-manifest.json` | the registry inspection of every image and the corpus manifest the installer was built against |

Verify before you execute:

```sh
bash verify-release.sh gsj-install.sh installer-descriptor.json installer-descriptor.sig release.pem
```

It checks the descriptor's signature under the key you supply, the key's
fingerprint against the descriptor, and the installer's exact bytes against
the descriptor. It does not run the installer. Signing uses RSA (3072 bits or
more) with SHA-256; the private key stays on the maintainer's machine and
never enters this repository, any release asset, or any CI system — releases
are signed by hand there, and `build.py sign` refuses a key that sits inside a
Git repository or is readable by anyone but its owner.

**The handover is direct.** TUM Legal Tech hands the customer the release —
this repository's release page, or the files from it — and their GHCR token
themselves. The key travels with the release, and the verification proves
that the installer the customer holds is the one that was signed: a download
that was cut short, altered or swapped is refused. There is no separate key
channel, no fingerprint delivered out of band, and no key ceremony.

<!-- init: begin -->
`bash gsj-install.sh init` runs this same verifier for you — after fetching
the four companion files of its own release and checking each one — and
reports the result (see *`init`: one file, one command, one report*
above). That is the convenient check; the command above, run by hand before
executing anything, is the stronger one: `init` runs from inside the file it
verifies, and a modified installer could skip its own check.
<!-- init: end -->

**Releases are hand-run.** This repository's GitHub Actions run its tests on
GitHub-hosted runners and hold no secret — and cannot run the whole suite,
because the product is private (see *Building and testing*). The release
steps a maintainer runs, in order, are in
[`ops/installer/README.md`](ops/installer/README.md#the-release-step-by-step);
the first is the full run with nothing skipped and nothing excluded,
`ops/installer/ci/full-suite.py`, which refuses to start when a prerequisite
it knows is missing and fails on any skip.

## Where the corpus comes from

The decisions corpus has two parts. The **text** (the decisions' XML records,
sharded and fingerprinted) rides inside the private `gsj-decisions-data` image
the product publishes with its release; the installer pins that image by
digest like the other five. The **vectors** the Chroma index holds are
published separately, as a public release of
**[TUMLegalTech/gsj-decisions-corpus](https://github.com/TUMLegalTech/gsj-decisions-corpus)**:
a small manifest and seven blocks, each with its SHA-256. A site names that
manifest in `corpus.vectors_url` (or stages the eight files on local disk and
names `corpus.vectors_path` when the installer host has no egress), and the
initializer verifies every block against the corpus it parsed itself before it
trusts one. They cannot be regenerated locally: the encoder's INT8
quantization makes a vector depend on its batch, so a site that re-embeds gets
a *different* index. The corpus repository's README explains this and how to
verify the files.

## The pin

`web-pin.json` names the ONE product commit this installer builds against —
its chart's version, the Git tree of `chart/` and the SHA-256 of the chart as
`build.py` packages it, the Git tree of the product's `gsj_deploy` package (the
in-pod programs the installer runs), the core library tag that product ships,
and, once the product half has a release, the release tag and the digests of
the four product images it published. `requirements-local.txt` installs the
product and the library at those pins for the tests. Builds and tests read the
chart from Git objects at that commit, never from a working tree; an explicit
chart path is a qualification-only override. `tests/test_web_pin.py` holds
every pin site to the record, and `ops/installer/CONTRACT.md` states the
contract the installer and the chart share (the product carries the same
file as `chart/INSTALLER-CONTRACT.md`; the test fails when they differ).

Promotion fills the pin in one reviewed change: the commit becomes the
product release's, `release` names its tag, `images` carries the digests the
product release published.

## Building and testing

The generated installer needs no Python. The tests and the builder do:

```sh
# siblings: ../gsj-next (the library) and ../gsj-next-web (the product), both
# private repositories you have access to
python3 -m venv .venv
GSJ_NEXT_DIR="$(pwd)/../gsj-next" GSJ_NEXT_WEB_DIR="$(pwd)/../gsj-next-web" \
  .venv/bin/pip install -r requirements-local.txt
# the library depends on chromadb-client, which ships the same `chromadb`
# package as the embedded chromadb the tests need and overwrites it when pip
# installs it last: remove the client and put the embedded package back
.venv/bin/pip uninstall -y chromadb-client
.venv/bin/pip install --force-reinstall --no-deps chromadb==1.5.9
# the add-on chart archives three tests read (fetched by hash, ~420 KB), into
# a directory this run creates and owns (its parent must exist); to
# re-stage, remove it first
mkdir -p ops/.build && rm -rf ops/.build/installer-addons
python3 -B ops/installer/prepare-addons.py --output ops/.build/installer-addons
.venv/bin/python -m pytest -q
```

Without the chromadb commands the fixtures that open a local Chroma store
error at setup with "Chroma is running in http-only client mode"; without the
staged add-on archives the three add-on cases skip (the preparation refuses
a directory it did not create unless it is a plain directory of this user's
holding only its own add-on files; a previous run's `inventory.json` counts
as foreign, hence the removal first). After a re-pin, reinstall
the product explicitly — `pip install --force-reinstall --no-deps
"gsj-web[dev] @ git+file://…/gsj-next-web@<the new commit>"` — because pip
keeps an installed `gsj-web` whose version number did not change even when
the pinned commit did (`tests/test_web_pin.py` then fails, naming both).

The tests also need `helm`, `jq` and `openssl` on the PATH, and a Git
directory that carries the pinned product commit: the `../gsj-next-web`
sibling, a bare clone staged at `ops/.build/gsj-next-web.git`, or the one
named by `GSJ_NEXT_WEB_GIT_DIR`. Without that Git directory the tests that
read the pinned Git objects (the chart, the `gsj_deploy` sources, the
product's `requirements-local.txt`) skip (`needs_web`, `tests/pinned_web.py`);
without the product package, the five modules that import it are not
collected at all (`tests/conftest.py` names them) and the tests that import
it on their own skip; the CI workflow runs that subset, because the product is
private — and also skips the three add-on cases above, whose archives under
`ops/.build` (never committed) it does not stage. The whole
suite, with nothing skipped and nothing excluded, is
`.venv/bin/python -B ops/installer/ci/full-suite.py --report FILE`: it refuses
to start when a prerequisite it knows is missing — the four packages above
(`gsj_deploy`, `gsj_web`, `agent_runner`, `gsj`), a `chromadb-client` still
installed, the pinned Git objects, `bash`, `helm`, `jq` and `openssl`, the two
add-on archives, an interpreter that is not X.509-strict (Python 3.13 or newer
is), a missing system CA bundle — and fails on any skip whatever its reason,
and on any expected failure, deselection, collection error or test file that
contributed nothing.

Building an installer, signing it, and qualifying it against a disposable
cluster are the maintainer's hand-run steps in
[`ops/installer/README.md`](ops/installer/README.md). The core library is
staged as a bare clone at `ops/.build/gsj-next.git`.

## Layout

```
web-pin.json              the product pin (see above)
requirements-local.txt    the engineering environment's pins
ops/installer/            the installer: runtime.sh and its helpers, the site
                          and release schemas, compile/validate jq, defaults,
                          client pins, build.py (build/sign/verify),
                          verify-release.sh, rehearsal.sh, OPERATOR.md,
                          README.md (the builder contract), CONTRACT.md,
                          examples/ (site files), ci/ (the hand-run
                          qualification scripts)
tests/                    pytest: the runtime against synthetic clusters, the
                          builder, the pin, the contract with the pinned chart
```

`ops/installer/` keeps the path it had inside the product repository, so the
import that created this repository can be checked byte for byte against its
source commit and every documented path stays valid.
