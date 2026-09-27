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
| `networkPolicy.egress.endpoints` | `[{cidr, port}]`, sorted and unique: one entry per address of `llm.base_url`, `ocr.url`, each `llm.allowed_origins[]` and each proxy URL in `trust.proxy_file` (`HTTP_PROXY`, `HTTPS_PROXY`; a restore to a machine that does not carry the file yet takes the proxy from the archive's `R-proxy` Secret once the archive is open and recompiles the values before its intent records them; an install or upgrade without the file refuses at its trust step); the URL's port in decimal (or the scheme's default: 443 https, 1080 socks, else 80; a proxy URL without a port gets the scheme's port and 1080, curl's proxy default), the host as itself when it is an address (an IPv4 dotted quad with octets 0–255 as `/32`; a bracketed IPv6 literal, read into its canonical form by the resolver, as `/128`; an IPv4-mapped literal in dotted form as its IPv4; a bracketed string the resolver cannot parse and a zone-scoped literal are refused) and otherwise resolved with `getent ahosts` on the machine the installer runs on, an answer in 127/8, 169.254/16, 0.0.0.0, ::1, :: or fe80::/10 dropped and said. Resolution happens when an operation STARTS (`install`, `upgrade`, `restore`); every later run of that operation (`resume`, `repair`, the restore program, the startup continuation) and every verb that applies nothing (`backup`, `sweep`, `abandon`, the named repairs) reuse the list the operation recorded — its own intent's `values.json` first, the retained `values.pending.json` otherwise — so the compiled configuration stays byte-identical across an operation and never depends on the resolver again; with nothing recorded, a continued operation resolves what it can once and keeps it in its state (`egress-endpoints-<operation>.json`), and a verb that continues nothing resolves at each compile. A host this machine cannot resolve, an in-cluster Service name (`*.svc…`), a missing `getent` and an unreadable proxy file are said in the log and get no entry, never a refusal (a site that installed before the list existed keeps installing; the endpoint preflight and acceptance say what the endpoint answers); what is refused is a URL no policy can be written for (a port outside 1–65535) and a proxy file that carries credentials or is not the three-string object. `public_url` and `verification.connect_host` are never address rules: the verifier reaches them through the cluster's translation to the controller, the namespace peers of §3. `compile.jq` emits the key only when the runtime passes the list (`--argjson egress_endpoints`); a compile without it yields the values of the release before the list existed. The chart renders the entries as `ipBlock` rules of the gsj pod's outbound policy, beside every endpoint the values name by an IPv4 literal (`llm.model`, `ocr.url`, `llm.keyedOrigins`), which the chart admits on its own — a policy cannot name a hostname, and a hostname among those with no list at all (the key unset, the Helm path's default) refuses the render; a list the installer passes is trusted, empty or not |
| `networkPolicy.ingressControllerPodSelector` | `{"app.kubernetes.io/name": "traefik"}` under the managed Traefik profile, else `{}` (emitted with the list above): the controller's own pods within `ingress.namespace`; empty admits every pod of that namespace on every port, which a reused controller that shares its namespace with other workloads inherits |
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
| Deployment | `R-web` | containers `gsj-web`, `gsj-mcp`, `agent-runner`; init containers `wait-deps`, then `corpus-copy` + `corpus-initialize` when `corpus.enabled` (else `migrate`); `enableServiceLinks: false`; `serviceAccountName: default`, `automountServiceAccountToken: false`, no projected token; `spec.progressDeadlineSeconds` = `startup.progressDeadlineSeconds`. `wait-deps` reads the ready marker from the `marker` ConfigMap volume (`configMap.name: R-provisioned`, `optional: true`, mounted read-only at `/marker`, env `WAIT_MARKER_DIR=/marker`) — the startup continuation accepts exactly this barrier or the earlier API-read one (the `WAIT_MARKER` env); `gsj-web`, `gsj-mcp`, `corpus-initialize` and `import-decisions` carry `ORT_DISABLE_TELEMETRY=1`; `agent-runner` carries `PI_OFFLINE=1` and `PI_SKIP_VERSION_CHECK=1` |
| Deployment | `R-forgejo`, `R-chroma` | stock images |
| Service | `R-web` (8780), `R-forgejo` (3000), `R-chroma` (8000) | in-cluster addresses the installer and the verifier use (`http://R-forgejo:3000`) |
| Job | `R-provision` | hooks `post-install,post-upgrade,post-rollback`, `hook-delete-policy: before-hook-creation`; containers `plan`, `forge-bootstrap`, `provision`; carries `GSJ_DEPLOYMENT_GENERATION` and `GSJ_RELEASE_IDENTITY` |
| ConfigMap | `R-scripts` | `initializer.json` (§4), `wait-deps.py`, `provision.py`, `forge-bootstrap.sh` |
| ConfigMap | `R-provisioned` | the ready marker the Job writes last and `wait-deps` polls; generation-gated |
| Secret | `R-admin-token`, `R-agent-token`, `R-webhook` | minted by the Job, re-mint policy `reuse` |
| Secret | `R-operator` | rendered only without `operator.existingSecret`; the installer always names its own |
| PersistentVolumeClaim | `R-data`, `R-forgejo`, `R-chroma` | unless `existingClaim` names the operator's |
| ServiceAccount, Role, RoleBinding | `R-provisioner` | the gsj pod has no API access: no service-account token is mounted in it (nor in the Forgejo and Chroma pods), and wait-deps reads the ready marker `R-provisioned` from a mounted ConfigMap volume |
| NetworkPolicy | `R-default-deny-ingress`, `R-gsj-web-ingress`, `R-forgejo-ingress`, `R-forgejo-egress`, `R-chroma-ingress`, `R-gsj-egress`, `R-chroma-egress` | `R-gsj-web-ingress` admits the whole `networkPolicy.ingressControllerNamespace`; `R-gsj-egress` closes the gsj pod's outbound traffic to cluster DNS (kube-system pods labelled `k8s-app: kube-dns`), Forgejo :3000, Chroma :8000, the ingress controller's namespace (narrowed by `networkPolicy.ingressControllerPodSelector` when set) and, on k3s, the `svccontroller.k3s.cattle.io/svcnamespace=<that namespace>` pods in kube-system (the site's own public URL, dialled by the verifier), and `networkPolicy.egress.endpoints`; `R-chroma-egress` admits DNS only. The Pods the installer opens beside the release are not selected: they carry no `app.kubernetes.io/component` label of the release — except the credential-repair Pod and the startup source-proof Pod, which carry the gsj pod's labels and are held to its list (the first needs only Forgejo; the second reads a volume) |
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
removes the door from the Service. The same check runs a probe program in the
`gsj-web` container (`python -c <program> egress-probe`, the targets on
stdin: httpx GETs that must answer — Forgejo, Chroma, and the LLM's
`/v1/models` and the OCR route when they answer the installer's machine at
that moment with an HTTP status of their own, dialled as the pod dials them:
the site's CA file, its proxy and its NO_PROXY names; a TLS failure or a
status the proxy itself answers with keeps the endpoint's skip — and socket
connects that must fail within 10 s), a bash `/dev/tcp` probe in the Chroma container (a positive control
against the cluster DNS the policy admits, then Forgejo, the door, a public
address, `github.com` and the Kubernetes API's ClusterIP, which must be
blocked — the API is what any unpoliced Pod reaches, so a missing policy
shows on a cluster without internet too — and a `getent` lookup that must
answer), and reads the door's isolation panel through the public route
as the operator (`POST /api/login`, `POST /api/admin/isolation`,
`POST /api/logout`; every verdict of both vantages must be `blockiert` — on a
site whose `trust.proxy_file` names an `HTTPS_PROXY` the verdicts are recorded and not held (the canaries are https),
because the panel's probes honour the proxy). The outbound part runs only
when the applied release's manifest (`helm get manifest`) carries
`R-gsj-egress`: a corrected program applying an earlier chart proves the
three pairs and records `egress: "not rendered by the applied chart"`; a
manifest that carries the policy and a cluster that does not hold it, or
`R-chroma-egress`, fails the check. Its record (`network-check.json`, the summary's
`networkpolicy`) keeps the three pairs and an `egress` object: the pod's
probe, `asserted` (which site endpoints and whether the panel were held),
Chroma's report and the panel's verdicts.

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
