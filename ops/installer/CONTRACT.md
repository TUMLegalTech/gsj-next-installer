# The installer ↔ chart contract

The signed installer (`gsj-install.sh`, built in **TUMLegalTech/gsj-next-installer**)
and the product chart (`chart/`, versioned in **TUMLegalTech/gsj-next-web** with
the application it deploys) share a wide contract: the values the installer
compiles, the object names it addresses, the in-pod programs it runs and the
exit codes it reads. This file states that contract. It is carried in **both**
repositories byte for byte — `ops/installer/CONTRACT.md` in the installer,
`chart/INSTALLER-CONTRACT.md` beside the chart — and the installer's
`tests/test_web_pin.py` fails when the two copies differ. A change on either
side edits both copies in the same change, and the tests named in §7.

## 1. The pin

The installer builds against ONE product commit, named in the installer's
`web-pin.json` (`gsj.web-pin/1`): the commit, the chart's version, the Git tree
id of `chart/` and the sha256 of the chart as `build.py` packages it (the
normalized `chart.tgz`), the Git tree id of `gsj_deploy/`, the library tag that
product commit ships (its `requirements-local.txt`), and — once the product
half has a release — the release tag and the digests of the four product images
(`web`, `runner`, `mcp`, `decisionsData`) that release published. The installer
reads the chart from Git objects at that commit, never from a working tree; an
explicit chart path is a qualification-only override.

The installer's release version is the pinned chart's version: `build.py`
refuses a manifest whose `version` differs from the chart's `version` and
`appVersion`, and `release.json` records `source.chart_sha256` and
`source.web_commit`.

## 2. The compiled values (`compile.jq` → the chart's `values.yaml`)

The installer turns a validated site file plus its release manifest into
exactly these values. Every leaf below is a value the chart declares in
`values.yaml`, and the chart's own test refuses a value no template reads.

| values key | from |
|---|---|
| `fullnameOverride` | `target.release` — every object name in §3 is `<release>-<suffix>` |
| `deployment.identity` | the release manifest's `identity` |
| `image.gsjNextTag` | the release manifest's `core.tag` |
| `image.{web,runner,mcp,forgejo,chroma,corpus}.{repository,digest,tag}` | the six release images, `tag` always `""`; `registry.base` replaces the repository by `<base>/<last path segment>` and never the digest |
| `image.pullSecrets` | `[registry.pull_secret]` when set |
| `corpus.enabled` | always `true` |
| `corpus.manifestSha256` | the release manifest's `corpus.manifest_sha256` |
| `corpus.deadlineSeconds`, `corpus.attempts` | `deadlines.initialization_seconds`, `deadlines.attempts` |
| `corpus.repairGeneration`, `corpus.allowUpdate` | `corpus.repair_generation`, `corpus.allow_update` |
| `corpus.releasedVectors` | `true` when `corpus.vectors_url` or `corpus.vectors_path` is set |
| `corpus.resources` | `resources.initializer` |
| `startup.dependencyDeadlineSeconds` | `deadlines.dependencies_seconds` |
| `startup.progressDeadlineSeconds` | `deadlines.dependencies_seconds + deadlines.initialization_seconds + 1800` |
| `startup.modelFailureThreshold` | `180` |
| `web.publicUrl`, `web.uploadMaxMB`, `web.worktreeBudgetMB` | `public_url`, `limits.upload_mb`, `limits.worktree_cache_mb` |
| `ingress.enabled` | `true` |
| `ingress.className`, `ingress.host` | `ingress.class`, the host of `public_url` |
| `ingress.controller` | `traefik.io/ingress-controller` under the managed Traefik profile, else `k8s.io/ingress-nginx` (a `--arg ingress_controller` is accepted by the program but not passed by the runtime today) |
| `ingress.tls` | `[{secretName: tls.secret, hosts: [<host>]}]` |
| `networkPolicy.enabled`, `networkPolicy.ingressControllerNamespace` | `true`, `ingress.namespace` |
| `operator.login`, `operator.existingSecret` | `operator.login`, `operator.secret` (the installer creates that Secret before Helm) |
| `operator.password`, `operator.autogenPassword` | `""`, `false` |
| `agent.turnTimeout` | `limits.turn_seconds` |
| `llm.model`, `llm.absent` | `openai@<llm.base_url>#<llm.model>`, and no `absent` key; with `llm.base_url` and `llm.model` both empty (an install with no LLM endpoint yet), `""` and `absent: true` |
| `llm.contextWindow`, `llm.outputTokens`, `llm.modelFlags`, `llm.keyedOrigins` | `llm.context_window`, `llm.output_tokens`, `llm.flags` joined by `,`, `llm.allowed_origins` joined by `,` |
| `ocr.url`, `ocr.model` | `ocr.url`, `ocr.model` |
| `ocr.existingSecret` | `<release>-ocr-key` when `ocr.credential.file` is set (the installer creates it), else `ocr.credential.secret` |
| `selfhostedKey.value`, `selfhostedKey.existingSecret` | `""`; `<release>-llm-key` when `llm.credential.file` is set, else `llm.credential.secret` |
| `placement.nodeSelector` | `{"kubernetes.io/hostname": storage.node}` when a node is named |
| `storage.{data,forgejo,chroma}.{size,className,existingClaim}` | each volume's `size` and `existing_claim`, `storage.class` |
| `resources.{web,mcp,runner,forgejo,chroma}` | `resources` without `initializer` |
| `trust.caConfigMap`, `trust.proxySecret` | `<release>-trust` / `<release>-proxy` when `trust.ca_file` / `trust.proxy_file` is set (the installer creates them) |
| `retention.keepClaims` | `true` |

Render-time refusals the chart makes that the installer relies on:
`llm.model` is required unless `llm.absent` is `true` (and refused beside it);
an operator password or `operator.existingSecret` is required; `corpus.manifestSha256` is required when `corpus.enabled`; and
`startup.progressDeadlineSeconds` must exceed
`startup.dependencyDeadlineSeconds + corpus.deadlineSeconds` plus the startup
window (`modelFailureThreshold × 5 s`), or the render fails with
`startup.progressDeadlineSeconds must exceed`.

## 3. Objects the installer addresses by name (release `R`, `gsj.fullname` = `R`)

Rendered by the chart:

| kind | name | notes |
|---|---|---|
| Deployment | `R-web` | containers `gsj-web`, `gsj-mcp`, `agent-runner`; init containers `wait-deps`, then `corpus-copy` + `corpus-initialize` when `corpus.enabled` (else `migrate`); `enableServiceLinks: false`; `spec.progressDeadlineSeconds` = `startup.progressDeadlineSeconds` |
| Deployment | `R-forgejo`, `R-chroma` | stock images |
| Service | `R-web` (8780), `R-forgejo` (3000), `R-chroma` (8000) | in-cluster addresses the installer and the verifier use (`http://R-forgejo:3000`) |
| Job | `R-provision` | hooks `post-install,post-upgrade,post-rollback`, `hook-delete-policy: before-hook-creation`; containers `plan`, `forge-bootstrap`, `provision`; carries `GSJ_DEPLOYMENT_GENERATION` and `GSJ_RELEASE_IDENTITY` |
| ConfigMap | `R-scripts` | `initializer.json` (§4), `wait-deps.py`, `provision.py`, `forge-bootstrap.sh` |
| ConfigMap | `R-provisioned` | the ready marker the Job writes last and `wait-deps` polls; generation-gated |
| Secret | `R-admin-token`, `R-agent-token`, `R-webhook` | minted by the Job, re-mint policy `reuse` |
| Secret | `R-operator` | rendered only without `operator.existingSecret`; the installer always names its own |
| PersistentVolumeClaim | `R-data`, `R-forgejo`, `R-chroma` | unless `existingClaim` names the operator's |
| ServiceAccount, Role, RoleBinding | `R-provisioner`, `R-pod`, `R-marker-reader` | the pod's only API access is the marker read |
| NetworkPolicy | `R-default-deny-ingress`, `R-gsj-web-ingress`, `R-forgejo-ingress`, `R-forgejo-egress`, `R-chroma-ingress` | `R-gsj-web-ingress` admits the whole `networkPolicy.ingressControllerNamespace` |
| Ingress | `R-web` | proxy limits rendered for ingress-nginx only (§2 `ingress.controller`) |

Created by the installer, before or beside the chart (the chart must never
render these names): Secrets `<operator.secret>`, `R-llm-key`, `R-ocr-key`,
`<tls.secret>`, `<registry.pull_secret>`, `R-proxy`; ConfigMaps `R-trust`,
`R-ready-state` (the `gsj.installed/1` record while verification is pending),
`R-installed` (the same record, `complete`); Lease `R-operation`; and the
operation-scoped `R-capacity-*`, `R-storage-*`, `R-restore-*`, `R-backup-*`,
`R-credential-*`, `R-acme-owner` objects.

## 4. In-pod programs (the product's `gsj_deploy` package, inside its images)

| where | command | contract |
|---|---|---|
| `corpus-copy` init container, on the decisions-data image | `python -m gsj_deploy.corpus copy --destination /source --manifest-sha256 <sha>` | copies `/corpus/{manifest.json,shard-*.tar.gz}` into the data volume under `bootstrap/corpora/<sha>`; on failure writes `gsj-copy:<reason>` to `/dev/termination-log` |
| `corpus-initialize` init container, on the web image | `python -m gsj_deploy.initialize --settings /scripts/initializer.json` | settings keys `db`, `source`, `state`, `chroma_url`, `model_path`, `manifest_sha256`, `deadline_seconds`, `attempts`, `repair_generation`, `allow_update`, `released_vectors`; on failure writes `gsj-corpus:<reason>` to `/dev/termination-log`. Both init containers keep the default termination message path and the `File` policy, which is what the installer reads |
| `gsj-web` container | `python -m gsj_deploy.verify --settings <file>` with `--resume`, `--cleanup`, or `--finish --bot-result <file>`; `agent-runner` container: `--bot-negative <file>` | exit `0` passed · `75` checks passed, cleanup pending · `76` bot check pending · `77` cleaned, re-verify required · `78` another verifier holds the lock · `79` the bot check failed on every bounded attempt (terminal) · `1` anything else. The settings carry `web_url`, `forge_url`, `mcp_url`, `operator_login`, `operator_password`, `generation`, `run_id`, `report_dir`, `lock_dir` (`/data/verification-locks`), `timeout_seconds`, `expected_upload_mb`, `expected_corpus_rows`, `expected_corpus_fingerprint`, `corpus_state_path`, `db_path`, `mcp_workspace`, `connect_host`, `connect_port`, `ca_file`. The report names each of `REQUIRED_CHECKS` (15 checks) with a status, and a failure carries one `failure_code` from `FAILURE_CODES` (29 codes), which the operator guide's codes table lists in full |
| the maintenance Pod (web image) | `python -m gsj_deploy.backup create --output … --volumes … --metadata …`, `verify --archive …`, `restore --archive … --volumes … --expected-release …` | quiesced archive of the three volumes with an inventory; the installer encrypts outside the Pod |
| Pods the installer opens for a helper | `python -` fed with `capacity.py`, `backup-recovery.py`, `restore-files.py`, `startup-source-proof.py` or `startup-runtime-preflight.py` from the installer's payload | the helpers import `gsj_deploy` and `gsj` from the image; `startup-runtime-preflight.py` admits a source Pod only if the sha256 pair of its `gsj_deploy/initialize.py` and `gsj_deploy/corpus.py` is in the installer's qualified list — a product change to either file adds a pair there |

Health: every probe of every container hits the process-local `/livez`; the
installer's NetworkPolicy check hits `R-web:8780/readyz` from a Pod in the
Forgejo namespace. `/readyz` reports `degraded` with per-check truth and never
removes the door from the Service.

## 5. Helm

The installer applies the chart with `helm upgrade --install R chart.tgz
--values <compiled values> --timeout <seconds>` plus its ownership flags, under
its own Lease; Helm's wait semantics are chosen by the installed Helm's major
(the runtime's dialect); its client floors are helm ≥ 3.13, kubectl ≥ 1.24,
jq ≥ 1.6. The chart's `kubeVersion: ">=1.27.0-0"` is asserted by the installer's
preflight against the live server, not left to Helm at apply time.

## 6. What the installer takes from the product commit at build time

`chart/` (packaged and normalized: the payload's `chart.tgz`), `gsj_deploy/verify.py`
(read for `REQUIRED_CHECKS` by the qualification harness), `requirements-local.txt`
(the library tag), `ops/Dockerfile`, `ops/Dockerfile.runner` (the images' base
images, recorded as evidence). Everything else the installer needs from the
product arrives inside the pinned images.

## 7. The tests that pin this contract

- installer: `tests/test_web_pin.py` (the pin and this file's identity across
  repositories), `tests/test_contract.py` (every example site validates,
  compiles and renders with the pinned chart; every compiled leaf is a chart
  value; the object names, init containers, termination policy, initializer
  settings keys, verifier checks and codes, exit codes), `tests/test_installer*.py`
  (the runtime's behaviour against synthetic clusters).
- product: `tests/test_chart.py` (every chart value has a consumer; the probes,
  hooks, init containers, ingress limits, the render refusals of §2).
