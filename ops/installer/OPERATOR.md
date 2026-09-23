# Operate GSJ with the release installer

Operator commands and recovery boundaries for the distributed installer. It describes the installer as implemented; it announces no release
and certifies no deployment. Use it with the signed release's own help text
and release notes, which state what that release was qualified for.

The installer targets **existing Kubernetes**. Its one executable contains
the chart, configuration schema, default settings, addon payloads and an
immutable inventory of six application/data images. It uses **the Helm,
kubectl and jq already installed on your machine**. The target does not need
source repositories, Python, npm, pip, Docker or a local image build.

The installer execution environment needs Linux on a supported native
architecture, Bash, curl, OpenSSL 3.0 or newer (OpenSSL, not LibreSSL: it is
refused by name in the first seconds), tar/gzip, base64, a SHA256
implementation and ordinary filesystem/text utilities, including `sync`. It needs a kubeconfig
for the intended cluster. Kubernetes nodes must be able to pull the release's
images; a network path available only to the installer shell is insufficient.

**If you are installing for the first time, start at
[The install, step by step](#the-install-step-by-step) and follow it in order.**
It is ten steps — 0 through 9 — and it tells you which reference section to
read at each one.

## The install, step by step

This is the path. Ten steps, 0 through 9, in order, from a cluster to a
verified deployment. Each one says what to do and points at the section that explains
it. The sections after step 9 are **reference** — read one when a step sends
you there, not before. Four of them are themselves procedures: [Inspect, then
install](#inspect-then-install) covers the interactive wizard, which is a
different route through this same day, and [Upgrade and
recover](#upgrade-and-recover-a-named-operation), [Preserve and
restore](#preserve-and-restore-backups) and [Remove a
deployment](#remove-a-deployment) are for days after it.

Branches are marked **[if]**. Skip one only when its condition does not hold.

---

### Step 0 — is this installer qualified for your cluster?

**Answer these six before anything else.** Each of them can stop the install —
the last only in part: acceptance checks two of the three behaviours an ingress
controller must have, and a green install does not show that the third, its
timeout, is long enough. What differs is *when*:

| | enforced by | when you find out |
|---|---|---|
| Storage provisioner | a preflight refusal | step 8, first seconds |
| Model endpoint shape | schema validation | step 8, first seconds |
| A registry that mandates a path prefix | nothing relocates the managed add-ons' images; with `registry.base` set, a preflight notice names the ones your profiles select | step 8: the notice in its first seconds, then an add-on whose Pods cannot pull |
| An OCR endpoint that can read an image — **needed for scanned pages; the install completes without one** | the installer's own probe in its first minute (advisory), then acceptance, which **skips** `scanned-ingest-search` and says so when the endpoint is absent or does not read the test page from inside the cluster | step 8, first minute; step 9, hours in, for the verdict |
| An LLM endpoint — **needed for the agent; the install completes without one** | the same probe, then acceptance, which skips `agent-turn-note-history` and `generated-document` when the endpoint is absent or does not answer the runner | step 8, first minute; step 9 |
| NetworkPolicy | acceptance check `networkpolicy` | step 9, hours in |
| Ingress controller | acceptance, for two of the three behaviours it needs — a near-cap upload and an event-stream cadence check assert them across it; a green install does not show that its **timeout** is long enough (measured, below) | step 9, hours in, for a body cap or a buffering proxy; for the timeout, an upload or a turn that dies at your proxy's limit, after the install has passed |

The last row is the reason step 0 exists at all: the installer will happily
build you a deployment behind a controller that cuts long uploads — that is
what we ran, and all fifteen checks passed — and never mention it.

**[if]** you have no model that can read an image, or no LLM endpoint yet, the
install still completes: the checks that need the missing endpoint are skipped,
the closing line says **PARTIAL** and names them with the reason, and the product
runs without that capability — scanned pages are not read, or the agent cannot
answer — until you set the endpoint and run `install` again (the LLM can also be
set per case, in the lawyer's Einstellungen). Skipping is never quiet and never
a setting: an endpoint that is configured and answers is always exercised, and
must pass. **Your OCR endpoint must be able to read an image**, further down
this step, has the probe and the reasons. It need not be a second server: nothing in the site file ties `ocr.*` to `llm.*`, so if the
model you already serve can read images, `ocr.url` may be that same server's
complete chat-completions route and `ocr.model` that same model.

**Storage.** Run `kubectl get storageclass -o custom-columns=NAME:.metadata.name,PROV:.provisioner`.
Installer admission permits exactly three provisioners:
`rancher.io/local-path`, `rancher.io/gsj-local-path`, and
`kubernetes.io/no-provisioner`. Anything else — `ebs.csi.aws.com`,
`disk.csi.azure.com`, `pd.csi.storage.gke.io`, Ceph, Longhorn, NFS — is
refused with *"storage driver needs SQLite/fsync/locking qualification"*. The
application writes SQLite and a Chroma index through the filesystem, and only
those three have been qualified for its fsync and locking behaviour.

If no class on your cluster carries one of the three — the ordinary case on
managed Kubernetes, where a CSI class is the only one — that is not yet a No.
There are two routes. `storage.profile=managed-local-path` creates a class and
its provisioner for you (it pulls two add-on images; see the registry point
below). Or you create a `kubernetes.io/no-provisioner` StorageClass, three
`local` PersistentVolumes and the three claims that bind them yourself, and name
the claims in the site file — no add-on, no image:
[Installing onto claims that already exist](#installing-onto-claims-that-already-exist)
has the objects we ran.

**Every storage route this guide documents is one node's filesystem.** The two
local-path provisioners are node-local and the static route uses `local`
volumes — a directory on one node; `storage.node` is required, and all three
Pods are pinned to it for the life of the deployment. No verb moves a
deployment to another node — `upgrade` refuses a changed `storage` block — so if
that node is replaced, what you have is your last backup and a `restore` onto
another node's volumes ([Preserve and restore backups](#preserve-and-restore-backups)).
Decide now whether the disk behind that directory outlives the node.

A qualified provisioner is necessary, not sufficient: the class also has to
write somewhere with room. A cluster-wide `local-path` usually writes into a
directory on every node's **root** disk, which is rarely where your space is.
Step 5's `inspect` reports the path and its free bytes as
`storage.claim_backing`, and step 6 decides what to do about it; budget about
60 GiB there, because the claims are 50 Gi and the installer refuses below
`storage.minimum_free_bytes` (20 GiB) of headroom. The
fallback, `storage.profile=managed-local-path`, plants a local-path
provisioner and puts **all three claims in a directory on one node's
filesystem**, outside any cloud volume lifecycle: if that node is replaced —
a routine event in a managed node group, under Cluster Autoscaler or
Karpenter — the data is gone. Do not choose it on a cluster whose nodes are
disposable. Hand-made `local` volumes under `kubernetes.io/no-provisioner`
share that property exactly: a `local` volume is a directory on the node its
`nodeAffinity` names.

**A registry that mandates a path prefix** — a Nexus, ECR, Artifactory or
Harbor that keeps everything under something like `team/project/`. One site
value, `registry.base`, relocates the release's six application images there
(step 4). It does **not** relocate the add-ons: `ingress.profile=managed-traefik`
and `tls.profile=managed-acme` install third-party charts and
`storage.profile=managed-local-path` applies an upstream manifest — eight images
in all, which the release pins at `docker.io` and `quay.io` — and the installer
gives those Pods no pull Secret. Know which of these you are before you write a site file:

- your cluster already has a qualified StorageClass, an ingress controller and
  a certificate you can supply — most clusters behind a mandated registry do.
  Choose `reuse`, `reuse`, and `existing` or `files`: no add-on image is ever
  pulled and this limit does not touch you;
- your nodes can pull `docker.io` and `quay.io` images anyway, directly or
  through a proxy: the managed profiles work as they are;
- neither, on **k3s or RKE2**: their `registries.yaml` can rewrite the
  repository *path* as well as the host, so a mirror entry can serve those
  images from under your prefix —
  [A container-runtime mirror on every node](#a-container-runtime-mirror-on-every-node)
  has the entries. The add-on Pods get no pull Secret, so that mirror must allow
  anonymous pulls or the *runtime* must hold its credential. We measured the
  rewrite on k3s — not a managed-profile install through it, not an
  authenticated mirror for these images, and not RKE2;
- neither, on a runtime whose mirror cannot rewrite paths: the three managed
  profiles are closed to you in this release. `tls.profile=managed-local-ca`
  stays open — it installs no chart and pulls no image — and storage goes
  through [claims of your own](#installing-onto-claims-that-already-exist).
  Before you settle on this one, read what we did and did not test of *your*
  runtime's mirror in
  [A container-runtime mirror on every node](#a-container-runtime-mirror-on-every-node).

**Ingress.** One controller is qualified: `k8s.io/ingress-nginx`, for which
the chart writes the three behaviours the application needs (64 MiB body,
600 s read timeout, no response buffering). The managed alternative installs a
pinned Traefik. For anything else — HAProxy, Contour, an appliance, a cloud
load balancer — the chart still writes only the three
`nginx.ingress.kubernetes.io/*` annotations (under `reuse` it assumes
ingress-nginx; it does not look at what your class's controller is), which any
other controller ignores, and the site file has no field for supplying your
controller's equivalents. So you must configure those three behaviours on that
controller yourself. Acceptance would notice two of them: it uploads a PDF one
byte under `limits.upload_mb` through `public_url` and times two pings of an
event stream, so a lower body cap or a buffering proxy fails step 9. A green
install does not show that the timeout is long enough; what we measured is
below. An AWS ALB cannot be configured this way at all: its
behaviours are annotations on the Ingress object, which only the chart writes.

One way out works for every controller this rules out, a cloud load balancer
included: run ingress-nginx in the cluster yourself, send your load
balancer's traffic to it, and `reuse` it — `ingress.class` its IngressClass,
`ingress.namespace` the namespace its Pods run in. The installer's whole check
on a reused class is that an IngressClass of that name exists.

**A stock k3s box is the common case of this**, because k3s ships Traefik.
`managed-traefik` is *not* your way out: it installs a second Traefik from a
pinned chart, that chart carries the `traefik.io` CRDs, k3s's bundled Traefik
already owns those same cluster-scoped CRDs, and the installer refuses any
add-on object that *"already exists without its owner record"*. You have three
routes: install ingress-nginx beside it and `reuse` that; start k3s with
`--disable traefik` and let `managed-traefik` own the only one; or `reuse` the
bundled Traefik and give it the three behaviours yourself. For the second
route, know that the installer's check is on the *objects*, not on a running
controller: on a box where the bundled Traefik was ever deployed, confirm that
`kubectl get crd -o name | grep traefik.io` prints nothing before your **first**
`managed-traefik` install (afterwards it lists the installer's own). Any CRD it
lists before that is refused by name, and deleting a CRD deletes every object
of that kind on the cluster — look before you do. For that last route,
what we measured:

- **all fifteen acceptance checks pass behind a reused Traefik left at its stock
  settings** — every install on one of our two test clusters ran behind a
  Traefik v3.7.13 deployed from the upstream chart with no timeout values — so a
  green install tells you nothing about the next point;
- **Traefik stops reading a request after 60 seconds** — its default, measured
  on 2.11.18 and on 3.7.13, the two builds we ran. With the application itself
  behind the stock 3.7.13, a 9 MiB upload throttled to 100 KB/s died at 60.2 s
  with `502 Bad Gateway`; unthrottled it took 1.8 s. The acceptance upload is
  fast and never notices; a lawyer sending a 64 MiB Akte needs about 9 Mbit/s
  sustained to beat it. (A 150-second event stream was *not* cut — measured on
  the bundled 2.11.18 with a test backend only, never through the application.)
- the cure is what the installer's own managed Traefik sets on both
  entrypoints: `transport.respondingTimeouts.readTimeout=3600s` and
  `writeTimeout=0s`. On k3s's **bundled** Traefik give them as Traefik's own
  flags, which do not depend on the bundled chart's version. Measured on k3s
  v1.31.5 (Traefik 2.11.18, bundled chart 27.0.2): the chart-values spelling
  `ports.web.transport…` had changed nothing after six minutes; the flags below
  were among the Deployment's arguments within seconds, and a 102-second upload
  then completed on both entrypoints.

  **Look before you apply.** k3s customises its bundled Traefik through this one
  object, and `kubectl apply` replaces the object's whole `valuesContent` —
  every other setting you had put in it is dropped:

  ```sh
  kubectl -n kube-system get helmchartconfig traefik -o yaml --ignore-not-found
  ```

  If that prints an object, do **not** apply the file below over it. Run
  `kubectl -n kube-system edit helmchartconfig traefik` and add the four
  `- "--entryPoints…"` lines to the `additionalArguments:` list **inside**
  `spec.valuesContent` — creating that list there if it has none. Editing in
  place keeps whatever else `valuesContent` holds. (That route is ordinary
  `kubectl`; the cluster we measured on had no such object, so what we ran is
  the other branch.) If it prints nothing, save this as `traefik-timeouts.yaml`
  and run `kubectl apply -f traefik-timeouts.yaml`:

  ```yaml
  apiVersion: helm.cattle.io/v1
  kind: HelmChartConfig
  metadata: {name: traefik, namespace: kube-system}
  spec:
    valuesContent: |-
      additionalArguments:
        - "--entryPoints.web.transport.respondingTimeouts.readTimeout=3600s"
        - "--entryPoints.web.transport.respondingTimeouts.writeTimeout=0s"
        - "--entryPoints.websecure.transport.respondingTimeouts.readTimeout=3600s"
        - "--entryPoints.websecure.transport.respondingTimeouts.writeTimeout=0s"
  ```

  Confirm it took: both `readTimeout=3600s` flags must be among the arguments
  this prints. Ours were there in five seconds. If they are not after a few
  minutes the values did not take — the helm job reads `Complete` either way,
  so do not wait on it:

  ```sh
  kubectl -n kube-system get deploy traefik -o json \
    | jq -r '.spec.template.spec.containers[0].args[]' | grep -i timeout
  ```
- under `reuse`, `ingress.namespace` must be the namespace the controller's
  **Pods** run in — `kube-system` for k3s's bundled one; ours ran in
  `gsj-ingress`, which happens to be the default — because the application's
  NetworkPolicy admits that namespace, all of it, and no other to its port.
  That is a decision as well as a route: where the controller shares its
  namespace with other workloads — `kube-system` does — every Pod there is
  admitted to the application's web port, and no field narrows it to the
  controller's Pods; a controller in a namespace of its own is the narrower
  choice. `kubectl get pods -A | grep -i traefik` names it in its first column. (Read
  from the chart and the installer, not measured: get it wrong on a CNI that
  enforces policy and the install stops at its own public-route probe, after
  the corpus import and before any acceptance check has run.)

Traefik has no default request-body limit and does not buffer responses, so the
other two behaviours hold unless you have added a buffering middleware. What
we have **not** run is a whole GSJ install behind k3s's bundled Traefik: the
installs ran behind a Traefik we deployed from the upstream chart, and the
bundled one was measured with a test backend.

**Your model endpoints.** GSJ speaks one protocol: OpenAI-compatible chat
completions, authenticated with a bearer token or not at all.

The two URL fields have **different** schema patterns, and neither says
anything about `/v1`:

| field | pattern | what it forbids |
|---|---|---|
| `llm.base_url` | `^https?://[^/@?#:\s][^/@?#\s]*(/[^?#\s]*)?$` | a query string. A path is optional, a port is fine |
| `ocr.url` | `^https?://[^/@?#:\s][^/@?#\s]*/[^?#\s]+$` | a query string, **and** a bare host — it requires a non-empty path, because it is the complete chat-completions route |

So an endpoint whose route carries `?api-version=...` is refused by validation,
in step 8's first seconds, and so is an `ocr.url` that is only a host. Those two
are everything the schema catches about an endpoint's shape.

The rest is convention this guide relies on and **nothing checks**.
`llm.base_url` is expected to be the OpenAI root, ending `/v1` with no route
after it, because the application appends `/chat/completions` to it. Nothing
validates that, and the installer never probes the endpoint — a base that is
not the OpenAI root is accepted at install time and fails at the first agent
turn, which is acceptance check `agent-turn-note-history`. The credential is
sent as a bearer token; there is no field for an endpoint that authenticates
under its own header name.

Azure OpenAI's classic shape breaks all three: a query string (refused), no
`/v1` root (accepted, then broken), and an `api-key:` header (no field for it).
Put an OpenAI-compatible gateway in front of it, or use an endpoint that
already speaks this shape. Settle it now rather than at step 7.

**Your OCR endpoint must be able to read an image, if you name one.**
`ocr.url` may be left empty: the install then completes with
`scanned-ingest-search` skipped and recorded as `ocr-absent`, and no scanned
page is read until you set it and run `install` again. A named endpoint is
probed twice — from your machine in the install's first minute (advisory; the
same request as the block below, and the verdict is logged and recorded in the
state directory as `endpoint-preflight.json`) and from inside the cluster at
acceptance, where the verifier renders the scanned test page, sends it as the
application would, and requires the recognised sentence back. An endpoint that
gives no HTTP answer there skips the check as `ocr-unreachable`; one that
answers with a status other than 200 skips it as `ocr-refused` (the status is
recorded); one that answers HTTP 200 **without** the sentence skips it as
`ocr-not-vision-capable` — and that is the dangerous one, because the
application stores whatever a 200 says as the text of a scanned page: replace
it before anyone uploads scanned files. Only an endpoint that reads the page
runs the check, and then the check must pass. (The application itself runs
without OCR, and the bare chart treats it as optional; a partial verification
says in its record and on screen that the scanned-page path was not
exercised.)

Settle it now, from any machine that can reach the endpoint. It needs no
cluster, only `bash`, `jq` and `curl` — `curl` 7.55 or newer, because an older
one cannot read a header from a file and would send no key. **Type `bash` first
if this machine's shell is `sh`, `dash` or `ash`**: the block uses a bash array,
and in those shells it stops at a syntax error and prints no verdict. The block
posts a small image of the words `AKTE 58203` with the application's own OCR
prompt and token limit, looks for `58203` in what the application would store,
and allows the endpoint 300 seconds to answer — what the application allows each
call; a call that times out, is cut off, or answers 429, 500, 502, 503 or 504
it makes three times in all, and any other refusal it reports on the first.
(This block asks once.) It is **authenticated the way the application will
be**: if the endpoint needs a key, put `Authorization: Bearer YOUR_KEY` — the
same key you will give `ocr.credential` — as the single line of a `0600` file
and name it in `OCR_AUTH`.

```sh
if [ -z "${OCR_URL:-}" ] || [ -z "${OCR_MODEL:-}" ]; then
  echo 'set first, then paste this block again -- OCR_URL=<the complete chat-completions URL>; OCR_MODEL=<the model id it serves>; and OCR_AUTH=<the header file> if the endpoint needs a key' >&2
elif ! command -v jq >/dev/null || ! command -v curl >/dev/null || ! OCR_TMP=$(mktemp -d); then
  echo 'NO VERDICT -- this block needs jq, curl and a writable temporary directory on this machine' >&2
else
  PNG=iVBORw0KGgoAAAANSUhEUgAAATcAAABDAQAAAADRnX/8AAACLklEQVR42u2VMW7cMBBFHykhUpVVuu2sI+wBnJhHyRFSuooHCBDkGDkKj6Aj0F1KGXDBNbicFJS00tqFU6XZ6QR8/uH8+V80yntKLe+rK+6K+1fcsUVrHnfGmM/GGDgZw1OHWnh0HNsNX+g2BMMzL+r4PfDnBaiBmAD8tpE/EQkqDUEBVHWsNFfKF+AWUE2g8BDYJSoVHjRbgAwobhMIIBAhI/hyv7FgZQElyJX3Hgrzeo5kjIr6RqcA1j3cJxrFhFBwQYG4VvJGaTvkJ3Ev2G7m88BYv9LWAJDrc1+B0PIm0P2QGecB/ErmyHyaHu5nnOkB6V/RfZ+koJ/7etjI98nZOM6SMEx8AuhKPhgGUpgPqnMFZ7uzzEdjAZ7Nyck0KghYUAiXV8uI2Yx9VnfllxFwFlILkLXwUbcjF5yKP0HsFgpb3HJRN6ggkyrVvF8ADuMK14tU3hOKpvsRLCSIi3yNZtg7l+tDwLvLHMGveKZrBFpQKVrVy7wJQ9rcMNGSq/O+7bR1+9pWY6rfyvlq7Kdph8Vq3RmXwa4enGFq19EFTnHCjSvzrnfTjT3ghdQWvruSnbNhejzEeUMplpz7OyVXKncqmhpV1bAjNeONUMWGbMKu5NytqI7GCN0TpKEv32jfLfMKuLURjD05BGows+99WdoqHy12CYJlyZtMCV5wNbURBLDUuPn/UqqLK/FbnFHASEs/+Vk2PQGM/8bhIwBfD+w/AOb67l9x/xH3F0Tp4vsISHl9AAAAAElFTkSuQmCC
  jq -n --arg model "$OCR_MODEL" --arg png "$PNG" '{model:$model,max_tokens:2048,messages:[{role:"user",content:[{type:"image_url",image_url:{url:("data:image/png;base64,"+$png)}},{type:"text",text:"Text Recognition:"}]}]}' > "$OCR_TMP/request.json"
  OCR_CURL=(-sS --connect-timeout 10 --max-time 300 -o "$OCR_TMP/answer.json" -w '%{http_code}' -H 'Content-Type: application/json' -d "@$OCR_TMP/request.json")
  if [ -n "${OCR_AUTH:-}" ]; then OCR_CURL+=(--header "@$OCR_AUTH"); fi
  OCR_HTTP=$(curl "${OCR_CURL[@]}" "$OCR_URL"); OCR_RC=$?
  if [ "$OCR_RC" = 28 ]; then
    echo "NO VERDICT -- curl gave up waiting; its own message is on the line above. If that message is about CONNECTING, nothing answered at that address within 10 seconds: this machine, the URL or a firewall. If it says the OPERATION timed out, the endpoint took the request and did not answer within the 300 seconds this block allows: a busy, queued or still-loading server -- paste the block again before concluding anything"
  elif [ "$OCR_RC" != 0 ]; then
    echo "NO VERDICT -- curl did not complete the request; its own message is on the line above. That is about this machine, the URL or the header file, not about the model"
  elif [ "$OCR_HTTP" != 200 ]; then
    if [ -s "$OCR_TMP/answer.json" ]; then head -c 400 "$OCR_TMP/answer.json"; echo; fi
    echo "NOT ACCEPTED -- HTTP $OCR_HTTP; the endpoint's own reason, if it sent one, is on the line above"
  else
    OCR_SAID=$(jq -rs '(if length == 1 then .[0].choices[0].message? else null end // null) as $m | if ($m | type) == "object" and ($m | has("content")) then ($m.content | if type == "array" then map(strings // (.text? | strings) // "") | join("") elif . == null then "" else tostring end) as $text | "the application would store this as the page: [" + $text + "]", (if ($text | explode | map(select(. != 32 and . != 9 and . != 10 and . != 13)) | implode | contains("58203")) then "VERDICT: IT READ THE IMAGE" else "VERDICT: DANGEROUS -- HTTP 200, and 58203 is not in what the application would store as the text of this page" end) else "NOT ACCEPTED -- HTTP 200, but not a chat completion: the application treats that as a failed call" end' "$OCR_TMP/answer.json" 2>/dev/null) \
      || OCR_SAID='NOT ACCEPTED -- HTTP 200, but no readable choices[0].message: the application treats that as a failed call'
    case "$OCR_SAID" in "NOT ACCEPTED"*) if [ -s "$OCR_TMP/answer.json" ]; then head -c 400 "$OCR_TMP/answer.json"; echo; fi ;; esac
    printf '%s\n' "$OCR_SAID"
  fi
  rm -rf "$OCR_TMP"
fi
```

Only one outcome qualifies, and it is the last line the block prints.

- `VERDICT: IT READ THE IMAGE` — qualified. The line above it is what the
  application would store for this page; read it once — it should say
  `AKTE 58203`. It proves the endpoint can recognise text in an image. It does
  not prove your cluster can reach it —
  [The five values only you can supply](#the-five-values-only-you-can-supply)
  has that check, from a Pod, once step 7 has written the site file — and it
  does not prove a full page passes: the probe posts about 1 KB of request, the
  application a JPEG of the rendered page, some 170 KB of request for the
  acceptance check's own page, so a gateway that refuses one format or caps request bodies in
  between would not show here. Measured on three vision-capable models with
  this request — a dedicated OCR model and two general chat models, one of them
  the model the reference installs use as `llm.model` (they ran with a separate
  OCR model): each read the number eight times out of eight, and each also read
  the acceptance check's page.
- `NOT ACCEPTED -- HTTP …` — not qualified yet. When the endpoint sent a reason,
  the block printed it on the line above, and that decides what this means; an
  endpoint that sent none leaves the line on its own. A text-only model says so — measured:
  vLLM and Ollama answer HTTP 400 (*"… is not a multimodal model"*, *"… model
  does not support multimodal requests"*), llama.cpp HTTP 500 (*"image input is
  not supported"*) — and that is a No. A `404` or `405` is usually a URL that is
  not the **complete** chat-completions route, or a model id the endpoint does
  not serve (measured: `{"detail":"Not Found"}` and *"The model … does not
  exist"*); `401` and `403` are about the key; a `3xx` is a redirect, which the
  application does not follow either; `429` and `502` to `504` are usually a
  busy or starting server. `HTTP 200, but not a chat completion` and `HTTP 200,
  but no readable choices[0].message` are a URL that answered, but not as a
  chat-completions route: a sign-in page in front of the endpoint, a gateway's
  own error object, another service altogether. (Those two come from the block's
  logic and the application's code, tried against a stub; no server we measured
  answers like that.) Correct those and paste the block again.
- `VERDICT: DANGEROUS` — not qualified, and worse than a refusal: the endpoint
  answered, the number is not in its answer, and the application stores whatever
  it answers. Look at the printed answer before you act on it — a near miss of
  `AKTE 58203` is a model that did read the image and tripped on a glyph. An
  answer with nothing of the image in it is the dangerous one. Measured with a
  relay we built to drop the image and forward the prompt to a text-only model,
  as a lenient gateway might: the application stored that model's essay about
  text recognition as the text of the page, stamped as recognised. Empty
  brackets `[]` are the same verdict — typically a reasoning model that spent
  its token budget before answering — and would be stored as an empty page.
  [The five values only you can supply](#the-five-values-only-you-can-supply)
  has what each answer does to a scanned page.
- `NO VERDICT` — there is no answer to judge, for one of three reasons the line
  itself tells apart. *This block needs…*: it could not run; the line names all
  it needs — `jq`, `curl`, a writable temporary directory — not which one you
  lack. *curl did not complete the request*: `curl`'s own message is on the line
  above — a name that does not resolve, a refused connection, a header file it
  cannot read — and that is about this machine, the URL or the header file, and
  says nothing about the model. *curl gave up waiting*: read `curl`'s line. If
  it is about connecting, nothing answered at that address within 10 seconds,
  which is again this machine, the URL or a firewall. If the *operation* timed
  out, the endpoint took the request and did not answer in 300 seconds — a busy,
  queued or still-loading server, the same family as `429` and `502` to `504`
  above. Paste the block again before you conclude anything from that one.

**NetworkPolicy.** The installer runs its own deny/allow probe and step 9
requires it to have passed, alongside the fifteen application checks. `inspect`
will not probe it for you (it would have to create Pods). You
cannot settle it from a `kubectl get` either: enforcement is a property of your
CNI, not of any object you can read. **Step 4 carries a sixty-second probe that
answers it** -- it lives there and not here because it needs an image your
nodes can actually pull, which is exactly what step 4 establishes. Run it
before step 5.

Enforcing implementations include Calico, Cilium, Antrea, Weave, kube-router
(k3s and RKE2 bundle it unless started with `--disable-network-policy`), and
the AWS VPC CNI **only** with its network-policy agent explicitly enabled.
Plain flannel and Docker Desktop do not enforce. Stock EKS does not enforce by
default, and it is the most widely deployed managed Kubernetes there is -- do
not take a managed distribution on faith. Turning enforcement on is a
cluster-wide change to how every workload's traffic is treated, not a
sixty-second prerequisite: plan it with whoever owns the cluster.

Five of the six are settled here, with no installer, no payload helper and no
Pod: `kubectl get storageclass`, `kubectl get ingressclass`, the shape of the
endpoint URLs you already have, what your registry demands, and one request to
your OCR endpoint. That is the point of putting it first — you can be told No
for the price of two read-only commands and one `curl`, before you have
verified a signature or created anything. NetworkPolicy alone cannot be settled
by reading anything; step 4 proves it with a Pod, before step 5.

### Step 1 — check your machine and your cluster

**Paste this guide's blocks into an interactive `bash`.** They are written for
it and they carry `#` comments: a stock `zsh` does not treat `#` as a comment
at the prompt — it hands the rest of the line to the command, quotes and
backticks included. If your login shell is zsh, type `bash` first.

You need Linux on linux/amd64 or linux/arm64, `helm` ≥ 3.13, `kubectl` ≥ 1.24
(within one minor of your API server), `jq` ≥ 1.6, a kubeconfig, and about
3.5 GB free where `$HOME` and `TMPDIR` live. Your cluster needs Kubernetes
≥ 1.27 and one node with room for the claims and 8.25 GiB of schedulable
memory (plan on 9) — which is not the same as 9 GiB free (see step 8).

That 3.5 GB is two directories, and each follows a variable: the corpus block
cache under `${XDG_CACHE_HOME:-$HOME/.cache}/gsj-install`, and the installer's
working directory, which it makes with `mktemp` under `TMPDIR` (else `/tmp`).
With a small root disk, move them instead of freeing space you do not have:
export both, as absolute paths to directories that exist, in the shell you
will install from — `export XDG_CACHE_HOME=/data/gsj-cache TMPDIR=/data/gsj-tmp`.
Step 8's free-space check measures whichever filesystems those name. (Read
from the installer; our own runs left both where they were.)

```sh
helm version --short
kubectl version --client -o json | jq -r .clientVersion.gitVersion
kubectl version -o json | jq -r .serverVersion.gitVersion
jq --version
kubectl config current-context
```

All three clients are yours to install, the way your distribution installs
anything: the release ships none of them, and `--fetch-tools` equips the
*installer* for one run, not the blocks you paste into your own shell — steps 2
to 7 use your own `jq` and `kubectl`.

Helm 3.13 installs, upgrades and removes. **Helm 4 is required only by the
managed-add-on repair/rollback path and the restore-repair path** — steps you
reach when something has already gone wrong, and which say so by name at the
moment you reach them. You do not need it today; know that you will need it
then, and that on an air-gapped host `--fetch-tools` cannot fetch it.

**[if]** this machine reaches the internet only through a proxy. The installer
has no proxy setting of its own: it downloads with `curl`, and `curl` takes the
proxy from the environment. Two downloads need it — step 7's corpus manifest,
and in step 8 the corpus itself, about 1.5 GiB from `github.com` and
`release-assets.githubusercontent.com`. Export it in the shell you will install
from:

```sh
export https_proxy=http://proxy.example.org:3128 HTTPS_PROXY=http://proxy.example.org:3128
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' \
  | sed -E 's#^https?://##; s#[:/].*$##')
export no_proxy="$APISERVER" NO_PROXY="$APISERVER"
```

**The second half is not optional.** `kubectl` and `helm` read the same
variables, so a proxy exported for the download also captures every call to
your cluster unless the API server's host is exempted — and the failure blames
the wrong thing. Measured: `kubectl` says *"The connection to the server … was
refused - did you specify the right host or port?"* and `helm` says
*"proxyconnect tcp: … connection refused"*; the server was fine, the proxy
refused. (An API server on `127.0.0.1` or `localhost` is never proxied, so a
single-node box that installs from itself will not see this; every other shape
will.) Add your internal registry's host to both lists too if `registry.base`
names one. **Add the host of your `public_url` as well.** The installer's own
HTTPS check, at the end of step 8, is a `curl` from this machine in this
environment, and the installer passes `curl` no proxy option of its own: a
proxy that cannot reach that name turns the check into *"public HTTPS route is
unreachable … check public_url, DNS, the ingress and verification.ca_file"* —
after the corpus import, and naming everything but the proxy. And if proxy
variables were already set when you ran step 0's OCR block, that `curl` went
to the proxy too: exempt your model endpoints' hosts if the proxy is not meant
to carry them, and paste that block again. (Read from the installer, not run
behind a proxy by us.)

This covers **this machine only**. Your nodes' image pulls and your
application's own outbound calls are two separate proxies, met in steps 4 and 7.

→ [Before you start](#before-you-start) for the numbers and why each one.
→ [Client tools and versions](#client-tools-and-versions) for the floors.

### Step 2 — verify the release you were given

You were handed a release — its page, or the five files from it: the
executable, `installer-descriptor.json`, its `.sig`, the release key
`release.pem` and `verify-release.sh` — and your registry token, directly from
TUM Legal Tech.

```sh
umask 077
mkdir -p -m 700 "$HOME/gsj-operator/trust" "$HOME/gsj-operator/releases/r1"
# copy the key and verify-release.sh into trust/, the three release files into releases/r1/
cd "$HOME/gsj-operator/releases/r1"
INSTALLER=$(jq -r .installer.name installer-descriptor.json)
bash "$HOME/gsj-operator/trust/verify-release.sh" "$INSTALLER" \
     installer-descriptor.json installer-descriptor.sig \
     "$HOME/gsj-operator/trust/gsj-release.pem"
chmod 500 "$INSTALLER"
```

Success prints *"Verified signed descriptor and exact installer bytes. The
installer was not executed."* and exits 0. Any other exit is a failure: the
script prints which check failed — signature, or the installer's own sha256 —
and never executes the installer either way. Do not work around a failure;
ask for the release again. **`$INSTALLER` is the name this guide writes as
`gsj-install.sh`** — substitute it everywhere.

Keep all five files. Step 3 reads the executable and later recoveries read it
again.

→ [Obtain and verify a release](#obtain-and-verify-a-release).

### Step 3 — read what this release is

Everything about it is inside the executable. Nothing here needs a source
repository.

```sh
marker=$(awk '/^__GSJ_PAYLOAD_BELOW__$/ {print NR+1; exit}' "$INSTALLER")
payload() { tail -n "+$marker" "$INSTALLER" | base64 --decode | tar -xzO "$1"; }

payload release.json | jq '{version, identity, qualification, platforms}'
payload release.json | jq '.corpus'        # rows, chunks, fingerprint, memory requirement
payload release.json | jq '.images'        # the six repositories and digests
```

**`payload` and `marker` are shell state, not files.** They live only in this
terminal. Steps 4 and 7 use `payload`; if you open a new shell — or detach
into `tmux` in step 8 — re-run these two lines there. `INSTALLER` and
`KUBECONFIG` go with them.

`payload site.schema.json` is the complete field reference — for the
*effective* site, which is your file merged over `payload defaults.json`. That
merge is what the installer validates; it never validates the file you write on
its own. So the schema's `required` lists are not a checklist for your file:
every block you omit is supplied, and `payload defaults.json` is exactly what
you get for it. Note the `corpus.fingerprint`: its first eight characters
are the trailing segment of the corpus tag you will configure in step 7.

→ [Obtain and verify a release](#obtain-and-verify-a-release) for what else
the payload carries.

### Step 4 — prove your nodes can pull the images

This is the most common way an install fails, and it fails hours in. Prove it
now, on the node that will actually carry the deployment — a green result on
some other node proves nothing.

Pick that node now. It is the one whose filesystem will hold the claims, which
step 6 settles properly from `inspect`; for the probe, the node with the room:

```sh
kubectl get nodes -o wide                 # pick the one that will carry the claims
if [ -z "${NODE:-}" ]; then
  echo 'set first, then paste this block again -- NODE=<the node that will carry the claims, from the list above>' >&2
else
  BASE=${BASE:-}                          # empty: the repositories the release names. Set: your registry.base
  IMG=$(payload release.json | jq -r --arg base "$BASE" \
    '.images.web | (if $base == "" then .repository else $base + "/" + (.repository | split("/") | last) end) + "@" + .digest')
  kubectl run pull-probe -n default --restart=Never --image="$IMG" \
    --overrides="{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"$NODE\"}}}" \
    --command -- true
  kubectl -n default wait pod/pull-probe --for=jsonpath='{.status.phase}'=Succeeded --timeout=300s
  kubectl -n default get pod pull-probe           # Completed is the pass
  kubectl delete pod pull-probe -n default
fi
```

The block waits up to five minutes for the Pod to finish, prints its status and
removes it. `Completed` is the pass. `ImagePullBackOff` or `ErrImagePull` is
the failure this step exists to find; `ContainerCreating` means the pull was
still running when the wait gave up — raise `--timeout` and paste the block
again. It waits instead of watching on purpose. Measured on bash 5.2: Ctrl-C
ends the whole pasted block and discards whatever was pasted after it, so an
interrupted watch leaves the Pod behind — and, in the credentialed probe below,
the Secret. If you do interrupt one of these blocks, run its last line
yourself. (And it does not attach: with `--attach` a Pod that cannot pull
**blocks instead of reporting**.) Any namespace you can
write to will do; the probe proves the node, not the namespace, and the
install namespace need not exist yet.

Whether the repositories a release names answer an anonymous pull is a property
of the registry that published it; nothing in the release files you were given
says, and none of them carries a registry credential. This probe is what tells
you. If it is refused for want of one, ask whoever gave you the release — the
credential then goes in `registry.config_file`, and the next block probes with
it.

**[if]** the probe fails, or step 3's repositories name a host your nodes
cannot reach — a private registry, an air-gapped cluster, a Nexus, ECR,
Artifactory or Harbor that keeps everything under a path prefix:

→ [Make your nodes able to pull the images](#make-your-nodes-able-to-pull-the-images).
Copy the six digests into your own registry, under any prefix you like, and
name that place in one site value, **`registry.base`**. The installer then
pulls `<registry.base>/<name>@<the release's digest>` for everything it
creates: the location moves, the content cannot. Two things do **not** do this
job: **a pull Secret supplies credentials, it does not redirect a pull**, and a
plain container-runtime mirror preserves the repository path, so it does not
add your prefix. (k3s and RKE2 can be told to rewrite the path too — the mirror
section has the entry — but that is a change on every node, and `registry.base`
is none.)

**One consequence to decide on now, not at step 6.** `registry.base` moves the
six application images and nothing else. Three profiles bring
add-ons with their own pinned images — `managed-traefik` and `managed-acme`
install third-party charts, `managed-local-path` applies an upstream manifest —
and those images stay where the release names them. Step 0
listed the four routes. If yours is the last of them — a registry that insists
on a prefix, nodes that cannot reach `docker.io` and `quay.io`, and a runtime
whose mirror cannot rewrite paths — **those three are closed to you**: use
`reuse` for storage and `reuse` for ingress. TLS has no `reuse`; what remains there is `existing` (a Secret you
already hold), `files` (your own certificate and key), or `managed-local-ca`,
which installs no chart and pulls no image — the installer generates the CA and
the certificate on this machine — and is meant for practice environments. That
is a limit of this release, not of your cluster. It bites hardest
on storage, where `managed-local-path` was the easy way to choose a disk — the
route that remains is [claims of your own](#installing-onto-claims-that-already-exist).

If you will use `registry.base`, probe the **relocated** reference, not the
release's own: set `BASE` to your registry host and prefix — for example
`BASE=registry.example.org/team/project` — and paste the probe block above
again. It reads `BASE`, and the blocks below read the `IMG` it sets.

**[if]** your nodes reach registries only through a proxy. Image pulls are made
by each node's container runtime, which reads neither your shell's variables
nor anything in the site file: its proxy is node configuration — on k3s and
RKE2 the `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` lines of the service's
environment file (their documentation names
`/etc/systemd/system/k3s.service.env` — `k3s-agent.service.env` on an agent —
and `/etc/default/rke2-server` or `rke2-agent`), on plain containerd a systemd
drop-in — followed by a restart of that service on every node. That is your
distribution's procedure, not this installer's. What we measured is the
mechanism, on k3s v1.31, on a network with no other way out: a node whose k3s
process carried those three variables pulled its images through the proxy — the
proxy logged the `CONNECT` to each registry — and a second node started without
them could not pull even its sandbox image. (containerd's own environment there
showed `HTTP_PROXY` and a `NO_PROXY` that k3s had extended with the cluster
ranges; `HTTPS_PROXY` did not appear in it, and the HTTPS pulls were proxied
all the same. We tested no smaller set: set all three.) The files and the
restart are not something we ran. The alternative needs no node change at all: copy the six digests
into a registry your nodes already reach and set `registry.base` (next).

`Pending` is not a pull failure: an unsatisfiable `nodeSelector` also parks a
Pod in `Pending` forever. `kubectl -n default describe pod pull-probe` says
which one you have.

**[if]** your registry needs credentials, the probe needs them too, in the
same namespace. Set all three variables: `create secret` accepts empty strings
and **succeeds**, and the probe then fails as if your password were wrong. The
block asks for the password itself: once it is pasted the cursor waits, with no
prompt — type or paste the token and press Enter. Paste the block alone; a line
pasted after it would be taken as the token.

```sh
if [ -z "${REGISTRY_HOST:-}" ] || [ -z "${REGISTRY_USER:-}" ] || [ -z "${IMG:-}" ] || [ -z "${NODE:-}" ]; then
  echo 'set first, then paste this block again -- REGISTRY_HOST=<the host the Pod spec names: your registry.base host, or the original host behind a mirror>; REGISTRY_USER=<your registry username>; and IMG and NODE from the probe above' >&2
else
  read -rs REGISTRY_TOKEN; echo                    # typed, not echoed, not in history
  if [ -z "$REGISTRY_TOKEN" ]; then
    echo 'empty token: nothing was created' >&2
  else
    kubectl create secret docker-registry gsj-pull -n default \
      --docker-server="$REGISTRY_HOST" \
      --docker-username="$REGISTRY_USER" --docker-password="$REGISTRY_TOKEN"

    # the probe again, with the Secret -- this is the whole --overrides value, merged:
    kubectl run pull-probe2 -n default --restart=Never --image="$IMG" \
      --overrides="{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"$NODE\"},\"imagePullSecrets\":[{\"name\":\"gsj-pull\"}]}}" \
      --command -- true
    kubectl -n default wait pod/pull-probe2 --for=jsonpath='{.status.phase}'=Succeeded --timeout=300s
    kubectl -n default get pod pull-probe2          # Completed is the pass
    kubectl -n default delete pod pull-probe2; kubectl -n default delete secret gsj-pull
  fi
fi
```

`--docker-server` is always **the host the Pod spec names**, because that is
what the kubelet matches a credential against. With `registry.base` that is
your registry, the `registry.base` host. With a container-runtime mirror it is
still the **original** host the release names — the mirror is applied below the
Pod spec, where the credential has already been chosen.

**Now prove NetworkPolicy**, with the image you have just proved pullable. Step
0 said step 9 requires it and that nothing you can read settles it. This
settles it, in about a minute.

**[if]** a private registry, the Pods below need the pull Secret as well,
and the credentialed probe above deleted its copy. Before you paste the block,
create the namespace and the Secret in it — `kubectl create namespace npprobe`,
then the same `kubectl create secret docker-registry gsj-pull` as above with
`-n npprobe` — and set
`NP_OVERRIDES='{"spec":{"imagePullSecrets":[{"name":"gsj-pull"}]}}'`. The
block hands that value to both of its `kubectl run` lines, and deleting the
namespace at its end takes the Secret with it.

```sh
if [ -z "${IMG:-}" ]; then
  echo 'IMG is empty: run the pull probe above in this shell first -- it sets IMG to the image it probes' >&2
else
  NP_OVERRIDES=${NP_OVERRIDES:-'{}'}               # [if] a private registry: set as the paragraph above says
  kubectl get namespace npprobe >/dev/null 2>&1 || kubectl create namespace npprobe
  kubectl -n npprobe run target --image="$IMG" --overrides="$NP_OVERRIDES" --command -- python3 -m http.server 8080
  kubectl -n npprobe wait --for=condition=Ready pod/target --timeout=180s
  IP=$(kubectl -n npprobe get pod target -o jsonpath='{.status.podIP}')
  # STOP if the target never started, and mean it. An empty $IP makes both legs
  # connect to nothing, and in a Pod that raises ConnectionRefusedError -- which
  # is exactly what a PASSING `after` leg raises. Read on and the probe reports
  # enforcement it never tested.
  if [ -z "$IP" ]; then
    echo "target never got an IP; this probe proves nothing until it does" >&2
    kubectl -n npprobe describe pod target
  else
    probe() { kubectl -n npprobe run "$1" --rm -i --restart=Never --image="$IMG" --overrides="$NP_OVERRIDES" --command -- \
      python3 -c "
import socket,time
s=socket.socket(); s.settimeout(8); t=time.time()
try: s.connect(('$IP',8080)); print('reached in %.2fs' % (time.time()-t))
except Exception as e: print('%s in %.2fs' % (type(e).__name__, time.time()-t))"; }

    probe before                                   # must say: reached
    kubectl -n npprobe apply -f - <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all-ingress}
spec: {podSelector: {}, policyTypes: [Ingress]}
YAML
    sleep 5
    probe after                                    # must NOT say: reached
    kubectl delete namespace npprobe
  fi
fi
```

On the stop path the namespace is left in place on purpose: `describe` has just
told you why the target never started, and the Pod is the evidence. Remove it
with `kubectl delete namespace npprobe` once you have read it.

`before` must reach and `after` must not. If `after` also reaches, your CNI is
not enforcing NetworkPolicy and step 9 cannot pass. `kubectl` may wrap each
answer in noise — *"If you don't see a command prompt, try pressing enter"*,
*"couldn't attach to pod … falling back to streaming logs"* — which is about how
it fetched the output, not about the result. The line that matters is
`reached in …` or the exception's name.

This also answers a question the rest of this guide otherwise leaves open.
`after` fails one of two ways: `TimeoutError` after the full 8 s means your CNI
**drops**; an immediate `ConnectionRefusedError` means it **rejects**. Both are
enforcement and both pass. On k3s (kube-router) it rejects, in under 10 ms --
measured. Knowing which your cluster does is what lets you read a later hang
correctly.

The release's `web` image is used because it carries `python3` and your nodes
must be able to pull it anyway. Any image with `python3` that your nodes can
pull will do.

### Step 5 — look at your cluster

`inspect` writes nothing, takes no Lease, reads no site file, and is safe
against production.

```sh
export KUBECONFIG=/path/to/kubeconfig
./gsj-install.sh inspect > inspection.json
jq '{storage: .profile.storage.classes, backing: .profile.storage.claim_backing,
     filesystems: .profile.host.filesystems,
     ingress: .profile.networking.ingress.classes,
     hosts_in_use: .profile.networking.ingress.hosts_in_use,
     cert_manager: .profile.networking.tls.cert_manager_present,
     releases: .profile.occupancy.helm_releases,
     committed: .profile.compute.already_requested,
     egress: .profile.networking.egress.endpoints}' inspection.json
```

Seven of those fields answer a row of step 6 each. `committed` is what step 8's
memory preflight measures against; `egress` tells you whether step 7's corpus
block can be downloaded at all. Keep the file: it is also the one document you
can send back to us.

→ [Inspect, then install](#inspect-then-install).

### Step 6 — decide eight things

Seven of these come from step 5's output. One — whether `public_url` resolves
from inside the cluster — is a fact about your network that no `inspect` can
report; it is marked `you` in the table.

| decide | from | rule |
|---|---|---|
| namespace and release name | `occupancy.helm_releases` | no Helm release of that **name** may already exist in that namespace — the installer never adopts one. The **namespace** itself may exist and may hold things: the installer creates it only if it is missing, and several routes below *require* you to put a Secret, a Certificate or three claims into it first |
| `public_url` hostname | `ingress.hosts_in_use` | must be a host **no other release serves**, and must resolve from inside the cluster as well as outside |
| storage class and node | `storage.classes`, `storage.claim_backing` | under `profile=reuse`, a class from one of step 0's three qualified provisioners; under `profile=managed-local-path`, a **new** name, because the installer creates the class ([the profile table](#select-infrastructure-and-trust-profiles)). Either way, the node whose filesystem has the room |
| `storage.transfer_path` | `storage.claim_backing`, `host.filesystems` | a filesystem that is **not** the claims'; or leave empty to stage in an `emptyDir`, which is still the node's ephemeral filesystem — and a `backup` stages its archive through it twice, budgeted at about 2.5× your data ([why](#two-site-values-that-are-about-your-machine-not-gsjs)). Nothing but its shape is checked before a Pod mounts it — absolute, its first segment not beginning with a dot; [who creates it](#preserve-and-restore-backups) |
| which filesystem the claims land on | `storage.claim_backing` | `profile=reuse` takes whatever directory your existing class already writes to — it does **not** let you choose, and `storage.node` picks a node, not a disk. To place the data yourself: repoint the directory your own provisioner writes to — that is its configuration, not a site value; this installer never writes it, and reads it only to report `storage.claim_backing` and `storage.local_path_node_paths` (run `inspect` again afterwards) — or use `profile=managed-local-path` with `storage.backend_path` (default `/var/local-path-provisioner/gsj-managed`) after reading step 0's warning about disposable nodes — it does **not** collide with a local-path provisioner you already run, because it builds its own in namespace `gsj-storage` under provisioner `rancher.io/gsj-local-path`, `WaitForFirstConsumer`, `Retain`, with a node path map of exactly your `storage.node` and that one path — or bring claims of your own: [Installing onto claims that already exist](#installing-onto-claims-that-already-exist) |
| whether `public_url` resolves **inside** the cluster | you | The acceptance check dials it from the `gsj-web` container. Where a cloud load balancer's public name does not resolve or hairpin from inside the cluster — the normal case on managed Kubernetes — set `verification.connect_host` and `verification.connect_port` to a host and port the Pod can reach — one address that the machine you install from can reach as well, because the installer's own HTTPS check is redirected to it too. The complete example carries no `verification` block; add one. [The five values only you can supply](#the-five-values-only-you-can-supply) dials this route from a Pod before you install |
| ingress class and namespace | `ingress.classes` | `reuse` the ingress-nginx step 0 qualified; `namespace` is the namespace that controller runs in. If step 0 ruled your controller out, this row is where that verdict lands |
| TLS profile | `networking.tls.cert_manager_present` | four choices, below |

**The TLS rule.** `cert_manager_present` **true** and you already issue
certificates: pre-create the Certificate yourself and use `tls.profile=existing`
with the Secret it writes ([worked example](#a-certificate-you-already-issue-tlsprofileexisting)) — `managed-acme` installs its own pinned cert-manager
and is refused when unowned cert-manager CRDs are already present. If that certificate comes from a private or corporate CA rather than a public
one, also set `verification.ca_file` to that CA's PEM: the acceptance check
runs inside the Pod with strict verification and otherwise fails at the last
step with `origin-tls-failed`. **False** and you have a certificate: `files`,
with the same `verification.ca_file` rule when the issuer is private. **False**, no certificate, and this is not
public-facing: `managed-local-ca`, which generates a private CA — the reference
calls it practice-grade for a reason. Leave `tls.ca_file` and
`verification.ca_file` **out** of your site file for this profile: the
installer generates the CA, writes both paths back into your file before the
operation starts, and prints them. Setting them yourself is how you get a
resume refused for a changed configuration.

**The ingress fields the profiles make you choose between, and which this
guide otherwise never names:** `ingress.service_type` is `LoadBalancer`
(default) or `NodePort`; with `NodePort`, `ingress.http_node_port` and
`ingress.https_node_port` default to 30080 and 30443. `ingress.class` and
`ingress.namespace` both default to `gsj-ingress` — what `managed-traefik`
creates — so under `reuse` you must set both to your own controller's.
`public_url` accepts an explicit port, so a NodePort site can say
`https://host:30443`.

→ [Select infrastructure and trust profiles](#select-infrastructure-and-trust-profiles)
for what each profile creates and owns — and, if you are reusing a controller
that is **not** ingress-nginx, for the three behaviours you must configure on
it yourself.

### Step 7 — write the site file

Start from [the complete site file](#a-complete-site-file) — copy it whole —
and change the values step 6 decided, plus `target.context` (your kubeconfig
context name — `kubectl config current-context`, and the example's
`"production"` is almost certainly not yours), plus the five your own systems
supply: `llm.base_url` (the OpenAI root, ending `/v1`), `llm.model`,
`llm.context_window`, `ocr.url` (the complete chat-completions route),
`ocr.model`. Both URL fields are
OpenAI-compatible and **the schema refuses a query string in either**, so an
endpoint whose route carries `?api-version=…` cannot be configured as it
stands.

```sh
cd "$HOME/gsj-operator"
# write site.json here, from the complete example, with your editor or a heredoc
chmod 600 site.json
mkdir -p -m 700 credentials
# These write whatever you give them: a placeholder left in place installs
# cleanly and becomes the real password. Generate instead of editing a literal.
LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 > credentials/operator-password
LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 44 > credentials/backup-passphrase
chmod 600 credentials/*
cat credentials/operator-password; echo        # record it now
```

Keep both somewhere you will still have after this machine is gone. The backup
passphrase cannot be recovered and no restore can read the archives without it.

**Where you put it matters.** Paths inside the site file resolve relative to
the site file, not to your shell — so `credentials/` must be beside
`site.json`. Put both where the examples put them, `$HOME/gsj-operator`, and
pass `--config "$HOME/gsj-operator/site.json"`.

**Do not omit the `corpus` block.** The wizard does not ask for it and
`install --interactive` gives you no moment to add it, so a corpus-carrying
site is written by hand and installed with `--non-interactive`.

**Sourcing the corpus values for your release.** `corpus.vectors_url` is the
`vectors.json` asset of the corpus release whose tag ends in your release's
`corpus.fingerprint[0:8]`, and `corpus.vectors_sha256` is the sha256 **of that
file**. Derive and check both:

`payload` resolves `$INSTALLER` as a bare filename, so it only works in the
directory step 2 put the executable in. Step 7's own `cd` above moved you out
of it — run these from there, or re-point `INSTALLER` at an absolute path:

```sh
cd "$HOME/gsj-operator/releases/r1"       # where payload/marker resolve
FP=$(payload release.json | jq -r .corpus.fingerprint)
VECTORS_URL="https://github.com/TUMLegalTech/gsj-decisions-corpus/releases/download/corpus-1.snowflake-m-v2-int8-768.${FP:0:8}/vectors.json"
VECTORS_DIR=$(mktemp -d) && curl -fsSL "$VECTORS_URL" -o "$VECTORS_DIR/vectors.json"   # a private directory of your own, never a fixed /tmp path another user could pre-seed; no directory, no download
sha256sum "$VECTORS_DIR/vectors.json"                        # -> corpus.vectors_sha256
jq -r .corpus_fingerprint "$VECTORS_DIR/vectors.json"        # must equal $FP exactly
```

The tag's leading part names this corpus generation's model and dimensions; the
trailing eight hex characters are what pin it to your release. If that URL
404s, your release carries a different generation and the literal in the
complete example is not yours either — ask whoever gave you the release for
the corpus release matching `$FP`. You are not blocked meanwhile: with both
vector sources left empty the install embeds the corpus itself, which costs
hours and forfeits vectors identical to every other site's —
[Where the corpus artifact comes from](#where-the-corpus-artifact-comes-from)
has both.

Hashing the file you just downloaded proves it arrived intact, not that it is
the right file. The `corpus_fingerprint` comparison is what proves that, which
is why both lines are here.

Do **not** use `release.json`'s `corpus.manifest_sha256` here. That is the
corpus *image's* shard manifest — a different artifact that happens to share
the word. Using it fails after the download, not before it.

**[if]** the application must use a proxy to reach your model endpoints.
This is the third proxy and the only one the site file carries:
`trust.proxy_file` names a private JSON file with **exactly** these three keys,
all strings — a file with one or two of them is refused:

```sh
cat > "$HOME/gsj-operator/credentials/proxy.json" <<'JSON'
{"HTTP_PROXY": "http://proxy.example.org:3128",
 "HTTPS_PROXY": "http://proxy.example.org:3128",
 "NO_PROXY": "llm.internal.example.org,10.20.0.9"}
JSON
chmod 600 "$HOME/gsj-operator/credentials/proxy.json"
```

and in the site file `"trust": {"proxy_file": "credentials/proxy.json"}`. Three
rules, each enforced or each a trap:

- **No credentials in the proxy URLs.** Any `@` is refused: the agent runtime
  strips a proxy's `user:password@` before the model client sees it, so an
  authenticating proxy could never reach the model endpoint anyway. Use an
  unauthenticated or address-allowlisted proxy.
- **Put every endpoint the proxy should NOT carry into `NO_PROXY` yourself.**
  The installer adds only the cluster-internal names (`.svc`, `.cluster.local`,
  the release's own Forgejo and Chroma). A model server on your LAN is *not*
  exempted for you — leave it out and every model call is sent to the corporate
  proxy instead, and a working endpoint fails at the first agent turn.
- **A proxy that re-signs TLS needs its CA too**: set `trust.ca_file` to that
  CA's PEM, or the application refuses the certificates the proxy presents.

If neither of your endpoints is beyond a proxy, leave `trust` out entirely.

**Authentication.** `llm.credential` / `ocr.credential` take a `file` **or** a
`secret`, never both. For an endpoint that needs no authentication, omit the
`credential` object entirely — unknown properties are rejected, so do not
invent an empty or "none" value. A credential *file* — `credentials/llm-key`
and `credentials/ocr-key` in the complete example, beside the site file — holds
the key and nothing else: no `Authorization:` prefix and no trailing newline —
`printf '%s'` writes none; `echo`, a here-document and most editors add one —
in a file only its owner can access (`chmod 600`). The installer refuses a credential file that is empty, or that
group or others can access, and it looks only after the install has taken its
Lease. Its bytes go into the
Secret unchanged, the application adds `Bearer ` itself, and the agent runtime
refuses a key with a line break in it (*model API key must be a single-line
string*). Step 0's `OCR_AUTH` file is different on purpose: that one is a whole
header line, because `curl` reads it as one. (Read from the code; our own
endpoints needed no key.)

**Leave `resources` out.** `site.schema.json` lists it under the top-level
`required` array, but the installer merges `defaults.json` into your file
*before* validating it, so every omitted block is supplied. The shipped
defaults import the shipped corpus, and step 8's first seconds refuse if they
are ever not enough.

→ [The five values only you can supply](#the-five-values-only-you-can-supply)
— including the check, from a Pod on your node, that the cluster can reach both
endpoints.
→ [Two site values that are about YOUR machine, not GSJ's](#two-site-values-that-are-about-your-machine-not-gsjs).
→ **[if]** the machine you install from cannot reach GitHub — it is the
installer host that fetches the corpus, not the cluster:
[Where the corpus artifact comes from](#where-the-corpus-artifact-comes-from)
has the `corpus.vectors_path` alternative, which carries the same digests. It
sits under "Upgrade and recover a named operation" because that is where the
corpus reference lives — but you need it now, on a first install.

### Step 8 — install

It runs for hours. **Detach it**, or a dropped connection leaves a Lease you
must wait out and abandon. `tmux` is not one of the tools this guide requires
of your machine; if it is not installed, use the `setsid` form.

In tmux, start the session first and run the next block **inside** it. Pasting
both at once types the install into the outer shell, which is the one thing
this step exists to prevent:

```sh
tmux new -s gsj
```

```sh
cd "$HOME/gsj-operator/releases/r1"          # where step 2 put the executable
export KUBECONFIG=/path/to/kubeconfig        # set it here regardless: tmux may not have inherited yours
./gsj-install.sh install --config "$HOME/gsj-operator/site.json" --non-interactive
```

Without tmux, detach from the terminal entirely. This one keeps the
`KUBECONFIG` you already exported:

```sh
cd "$HOME/gsj-operator/releases/r1"
setsid nohup ./gsj-install.sh install \
  --config "$HOME/gsj-operator/site.json" --non-interactive \
  > "$HOME/gsj-operator/install.log" 2>&1 < /dev/null &
tail -f "$HOME/gsj-operator/install.log"
```

A tmux session is a new shell as far as step 3 is concerned: it has no
`payload`/`marker` — re-define them there if you need them — and it may not have
what you exported either. Measured on tmux 3.4: a session gets the environment
of whoever started the tmux *server*. If `tmux new` started it, your exports
came along; if a server was already running, the session has *that* shell's
environment — anything you exported since is absent, and anything it had is
present with its old value. So inside tmux, run the block's `export KUBECONFIG`
line first, then look — `env | grep -i -E 'kubeconfig|proxy|tmpdir|xdg_cache'` —
and paste step 1's exports again unless every value is the one you meant. In
that order: step 1's proxy block asks `kubectl` for the API server's host, and
without a kubeconfig it exports an empty `no_proxy`. A missing
`KUBECONFIG` fails in seconds. A missing proxy does not: the run passes its
preflight and applies Helm, and only then stops at the corpus download, which
is `curl` in *that* shell. The `setsid` form inherits the shell you stand in. And `gsj-install.sh` is still this guide's
stand-in for the name step 2 read out of the descriptor.

The first seconds check your clients, your server version, your storage and the
initializer's memory, and refuse there if anything is wrong. The memory check
is two questions, not one. First, whether `resources.initializer.limits.memory`
covers this corpus's largest shard. Second — and this one is about the whole
deployment, not the initializer — whether **any node the scheduler may use has
the deployment's entire memory request still unreserved**: about 8.25 GiB on
the shipped defaults, being the larger of the init container and the sum of the
application containers, plus chroma and forgejo. That second question is the
scheduler's arithmetic over what other Pods have *requested*, not over free
memory — a node that is 60 % idle can still be unable to place these Pods, and
the refusal says so. It is asked only for `install` and `upgrade`; the recovery
verbs run against Pods that are already placed. Then Helm applies, the
corpus is fetched and staged, and the import runs — about `corpus.chunks / 150`
seconds.

→ **If it stops**, the installer prints the command to run;
[Upgrade and recover a named operation](#upgrade-and-recover-a-named-operation)
explains each one. The short version: read the stop, change what caused it in
`site.json`, and run the `repair --operation ID --config "$HOME/gsj-operator/site.json"` it names —
repair re-reads the file you give it. (It also writes one value back into it,
`corpus.repair_generation`, and normally nothing else.
[Upgrade and recover](#upgrade-and-recover-a-named-operation) says why.)
→ **What a code means** — an exit status, a `command terminated with exit code N`
line, a `failure_code`, a refusal's opening words:
[Codes](#codes-what-the-installer-exits-with-and-what-it-records).

### Step 9 — what "done" means

Not a reachable login page. The installer finishes its own acceptance and
prints:

```
[2026-01-01T00:00:00.000000Z] Complete GSJ installation verified: 0.10.0-beta.5 at https://cases.example.org. Summary: /home/you/gsj-operator/.gsj/<sha256 of the context name>/<namespace>/<release>/summary.json
```

It is one line, on **stderr**, timestamped, and it ends with the summary path.
Take the path from it. Do not go looking under `$HOME/.gsj`: the state
directory is built from the **site file's** directory, not your home —
`<dir of site.json>/.gsj/<sha256 of the context name>/<namespace>/<release>`.
Step 7 put `site.json` in `$HOME/gsj-operator`, so with this guide's layout the
state is under `$HOME/gsj-operator/.gsj/`, beside the site file and **not**
beside the executable:

```sh
if [ -z "${SUMMARY:-}" ]; then
  echo 'set first, then paste this block again -- SUMMARY=<the summary path that line printed>' >&2
else
  jq '{status, public_url, operator_login, corpus, verification, verification_report}' "$SUMMARY"
fi
```

On a full verification `verification.coverage` is `full` and
`verification.checks_passed` equals `verification.checks` — fifteen of fifteen.
On a **partial** one — an endpoint left out of the site file, or one that did
not answer from inside the cluster — `coverage` is `partial`, `checks_passed`
plus `checks_skipped` make fifteen, `skipped` lists every skipped check with
its reason (`llm-absent`, `llm-unreachable`, `ocr-absent`, `ocr-unreachable`,
`ocr-refused`, `ocr-not-vision-capable`), `endpoints` records the state the
acceptance probe found each endpoint in, and the closing line begins **GSJ
installation complete, verification PARTIAL** instead of *Complete GSJ
installation verified*, names the skipped checks with their reasons, and says,
per recorded reason, what the product cannot do and what to correct — "set it"
only for an endpoint that is absent; an endpoint that is configured but did
not answer, refused the request (with the HTTP status it answered) or answered
without reading the test page is named for that, never told to be "set":

```
[2026-01-01T00:00:00.000000Z] GSJ installation complete, verification PARTIAL: 0.10.0-beta.5 at https://cases.example.org. 12 of 15 application checks ran and passed; 3 skipped: scanned-ingest-search (ocr-absent), agent-turn-note-history (llm-unreachable), generated-document (llm-unreachable). Until the LLM endpoint at llm.base_url answers the acceptance probe with a model list, the agent cannot answer: it is configured, but no model list came back (the endpoint was unreachable from the Pods, refused the request, or is not an OpenAI-compatible root), so check that it is up and reachable from the Pods, that its credential is right and that llm.base_url is the OpenAI root ending in /v1. Until an OCR endpoint is set, scanned pages are not read: set ocr.url and ocr.model in the site file. Then run install again with the site file: the acceptance then exercises what answers. Summary: …/summary.json
```

The install is complete either way — `backup` and `upgrade` work on it — but
a partial verification has not exercised the agent or the scanned-page path.
To close it: do what the closing line names for each reason — set an absent
endpoint (the LLM per case under Einstellungen, or both in the site file),
make a configured one answer, accept the request or read images — and run
`install` again from the same site file; the run converges on what exists and
re-runs the acceptance, this time exercising them. Either way the two fields beside the counts, `public_https` and
`networkpolicy`, must both read `passed`. Those two are not among the fifteen; they are the
installer's own route and policy probes, reported in the same object. The
fifteen application checks, in the order they run: `operator-login`,
`temporary-users`, `digital-ingest-search`, `scanned-ingest-search`,
`pipeline-index-freshness`, `upload-limit-and-pdf-delivery`, `authorization`,
`notes-library`, `live-sse-signed-webhook`, `lawyer-origin-and-hook`,
`mcp-tools-corpus-schema`, `agent-turn-note-history`, `generated-document`,
`logout`, `bot-contract-hook`. The summary is a
digest; the per-check detail is in the file it names as
`verification_report`, whose `checks[]` gives every check its `name` and
`status`:

```sh
jq -r '.checks[] | "\(.status)\t\(.name)"' "$(jq -r .verification_report "$SUMMARY")"
```

A check that fails names a fixed `failure_code`.
[Codes](#codes-what-the-installer-exits-with-and-what-it-records) lists all
twenty-nine with their usual cause — and how to read one from a run that
stopped, which writes no `summary.json` at all. Quote the code verbatim when you
report it.

Preserve the state directory, the site file and the credential files: recovery
needs all three.

**Then take your first backup**, before anyone uploads a case, from the site
file exactly as installed — `backup` refuses one that differs outside its
`backup`, `delivery` and `verification` blocks:

```sh
cd "$HOME/gsj-operator/releases/r1"
export KUBECONFIG=/path/to/kubeconfig        # a new shell has none
./gsj-install.sh backup --config "$HOME/gsj-operator/site.json" --non-interactive
```

The archive lands **on this machine** already encrypted, in
`backup.directory`, beside a separately encrypted resource archive and their
receipts. While the backup runs the archive is also staged on the
node, behind `storage.transfer_path`, twice: once as it is written, and once
decrypted back for verification. **Budget for what the capacity check demands,
not for what you end up with** — it assumes your data will not compress.
Measured on this guide's test deployment, from the installer's own report
(`capacity-<operation>-before.json` in the state directory): 10.4 GiB of data
as the installer counts it (7.5 GiB of it the vector store; `du` showed 8.1 GiB
on disk) demanded **13.5 GiB free under `backup.directory`** and **26.1 GiB
free for staging on the node** — 46.1 GiB in all on that node, because staging
shared a filesystem with the claims and their 20 GiB
`storage.minimum_free_bytes` floor is charged to the same disk. The archive
came out at 6.5 GiB. Short of either, the backup refuses before it stops
anything: *"actual source or backup capacity is insufficient or unknown; no
application writer was stopped"*.

And it is not free for your users: backup **stops the application, the runner,
Forgejo and Chroma** while it checks SQLite integrity and writes a consistent
archive — 38 minutes for that deployment — and starts them again afterwards.
*"Consistent encrypted backup verified: …"* means the archive is safe **and the
application is still stopped**; the run then scales the controllers back up,
printing `{"stage":"backup-restarting",…}` lines, and ends with *"Backup
operation … complete; original controllers and replica counts are ready."*
Wait for that line. If the run is cut short in between, the way back is
`resume --operation ID`; `abandon` is refused while the controllers are still
scaled to zero, and says so. No restore can read the archive without the backup
passphrase from step 7.

→ [Preserve and restore backups](#preserve-and-restore-backups).
→ [Remove a deployment](#remove-a-deployment) when the time comes. There is no
`uninstall` verb and the order matters.

---

# Reference

Everything below is reference. The steps above send you here.

## Before you start

Everything below assumes six things are true. Establish them first; each one
costs minutes now and hours later.

**1. You were handed a release and a token, directly.** A release is five
files on its release page: the executable, its `installer-descriptor.json`,
that descriptor's `.sig`, the release public key `release.pem` and the
`verify-release.sh` utility; TUM Legal Tech hands you the page, or the files,
and your registry token themselves. The verification below proves that the
installer you hold is the one that was signed — a download that was cut short,
altered or swapped is refused. Put the files somewhere private and verify
before you run anything:

```sh
umask 077
mkdir -p -m 700 "$HOME/gsj-operator/trust" "$HOME/gsj-operator/releases/THIS-RELEASE"
# put the key and verify-release.sh in trust/, the three release files in releases/THIS-RELEASE/
cd "$HOME/gsj-operator/releases/THIS-RELEASE"
bash "$HOME/gsj-operator/trust/verify-release.sh" \
  "$(jq -r .installer.name installer-descriptor.json)" \
  installer-descriptor.json installer-descriptor.sig \
  "$HOME/gsj-operator/trust/gsj-release.pem"
# success prints, and exits 0:
#   Verified signed descriptor and exact installer bytes. The installer was not executed.
chmod 500 "$(jq -r .installer.name installer-descriptor.json)"
```

**2. The executable's name is whatever the descriptor says.** Every example in
this guide writes `gsj-install.sh`; substitute
`jq -r .installer.name installer-descriptor.json`. Nothing else changes. Where
examples write `./gsj-install.sh` and elsewhere `bash gsj-install.sh`, both work
— the difference carries no meaning.

**3. Everything about THIS release is inside the executable.** You do not need a
source repository, and you should not guess anything this can answer:

```sh
INSTALLER=$(jq -r .installer.name installer-descriptor.json)   # NOT "gsj-install.sh"
marker=$(awk '/^__GSJ_PAYLOAD_BELOW__$/ {print NR+1; exit}' "$INSTALLER")
payload() { tail -n "+$marker" "$INSTALLER" | base64 --decode | tar -xzO "$1"; }

payload release.json | jq '{version, identity, qualification, platforms,
                            core, model, corpus, images}'   # what it is
payload release.json | jq '.clients'                        # what --fetch-tools would download
payload site.schema.json | jq '.properties | keys'          # EVERY site field, the full reference
payload defaults.json    | jq .                             # what you get if you omit one
```

`site.schema.json` is the "configuration schema" the interactive wizard's
prompts refer to. This guide describes the settings an operator usually
touches; the schema is the complete list.

**4. Your installer host.** Linux on **linux/amd64 or linux/arm64** — the
runtime and its pinned clients run on both. The cluster's nodes are another
matter: the node that will carry the volumes (`storage.node`, or every node
when it is unset) must have an architecture the release has images for —
`payload release.json | jq .platforms`, linux/amd64 for the releases built
today — and the installer refuses otherwise. Bash, curl, OpenSSL **3.0 or newer** (not
LibreSSL — the installer refuses it by name, in the first seconds, like a
too-old client; `--fetch-tools` does not supply OpenSSL), tar/gzip, base64, a
SHA256 implementation, `sync`, and the three clients in the next section. About
**3.5 GB free** for the corpus cache and its staging envelope, on whatever
filesystem carries `$HOME` and `TMPDIR`.

**5. Your cluster.** Kubernetes **1.27 or newer**. An **enforcing NetworkPolicy
implementation** — the deployment's isolation is expressed in NetworkPolicies
and a cluster that ignores them will install happily and isolate nothing. k3s
and RKE2 ship one unless started with `--disable-network-policy`; most managed
distributions have one; if you are unsure, ask whoever runs the cluster, because
`inspect` deliberately will not probe it (it would have to create Pods).

**6. Your storage node.** One node carries all three claims, and the defaults
ask for **20Gi data + 10Gi Forgejo + 20Gi Chroma**. The installer also refuses
below `storage.minimum_free_bytes`, **20 GiB by default**, free on the
filesystem backing them. Budget **at least 60 GiB free** on that node's claim
filesystem for a comfortable install of the shipped corpus, and **8.25 GiB of
schedulable memory and 2.2 CPUs** — the exact figures the table below totals.
Step 8's preflight checks the **memory** figure only; the CPU one is yours to
plan, and a node with no CPU left will simply leave the Pod Pending. That is the Kubernetes scheduling sum,
which is not the arithmetic sum of the containers: a Pod's request is
`max(largest init container, sum of its containers)` per resource, so the
initializer's 4Gi/2-CPU request does not ADD to the web Pod's containers, it
replaces them when it is larger. The three Pods are:

| Pod | memory request | CPU request |
|---|---|---|
| web (init `corpus-initialize` 4Gi/2 CPU; containers web 2Gi + MCP 1Gi + runner 512Mi = 3.5Gi/500m) | **4Gi** | **2** |
| chroma | 4Gi | 100m |
| forgejo | 256Mi | 100m |
| **total the scheduler must place on the node** | **8.25Gi** | **2.2** |

Round up when you plan — 9 GiB and 3 CPUs leaves margin. 8.25Gi and 2.2 CPUs
is what the **scheduler** demands; the preflight checks only the 8.25Gi, so a
node short of CPU is not refused — its Pod simply stays Pending. `inspect`'s
`compute.already_requested` reports what is already committed there and
`storage.claim_backing` the claim filesystem's free bytes; §"What initialization
costs in memory" below covers the LIMITS, which is a different question.

## Client tools and versions

The installer reads the clients you already have and refuses in the first
seconds if one is missing or too old — before it unpacks its payload, before
it reads your site file, before it takes the operation Lease and before it
creates the first cluster object. A refusal names the tool, the floor and what
it found:

```
GSJ: requires helm >= 3.13, found 3.12.3 (/usr/local/bin/helm). Upgrade helm,
or re-run with --fetch-tools to download this release's pinned clients for
this run only.
```

| client | floor | why that number |
|---|---|---|
| `helm` | **3.13** | Two things meet here, and the higher one is the floor. The add-on step passes `--labels gsj.io/addon-owner=…` — the ownership label the add-on repair and rollback paths fence on — and `--labels` does not exist before Helm 3.13 (3.12 answers `unknown flag: --labels`). Separately, the chart declares `kubeVersion: ">=1.27.0-0"`, and the installer renders it with `helm template`, which checks that against Helm's own built-in default Kubernetes version rather than your server's: Helm 3.11 defaults to 1.26 and refuses the chart, 3.12 defaults to 1.27 and renders it. Helm 3.12 through 3.22 and Helm 4 render this chart identically. |
| `kubectl` | **1.24**, and within **one minor of your API server** | 1.24 is where `kubectl patch --subresource=scale` arrives, which the startup-recovery path uses (1.23 answers `unknown flag: --subresource`); nothing the installer runs needs a newer client. But 1.24 is a *flag-availability* floor, not the whole answer: kubectl is supported within ±1 minor of the API server, so a 1.24 client against a 1.33 server is far outside that window even though every flag exists. In practice this takes care of itself — the installer uses the kubectl you already have, and on both environments measured so far that was the cluster's own matching version. If yours is not, `inspect`'s profile reports `host.installed_clients.kubectl.version` beside `kubernetes.server_version` so the gap is visible before an install. |
| `jq` | **1.6** | All 734 distinct jq programs the installer runs were compiled under jq 1.6, 1.7, 1.7.1, 1.8.0 and 1.8.2 — and because compiling is not running, `inspect` was then executed end to end under 1.6, 1.7 and 1.8.2 against the same cluster and produced the same document. 1.6 is what Debian 12 and RHEL 9 ship. |

Your **cluster** must be Kubernetes **1.27 or newer**: the chart's NetworkPolicy
selects the provisioning Job's Pod by `batch.kubernetes.io/job-name`, a label
the Job controller stamps only from 1.27, and neither that selector nor the
cleanup path carries a pre-1.27 fallback. On an older server the release used to
install happily and the provisioning Job was then denied its dependencies by a
policy matching nothing — silently. The installer now checks the server version
in its preflight and refuses there, before it writes anything to your cluster;
the chart's `kubeVersion` is the second gate behind it.

**Helm 4 is required by the managed-add-on repair/rollback path and the
restore-repair path, and only those.** They
serialize a release with no cluster at all (`KUBECONFIG=/dev/null helm install
--dry-run=client`), which no Helm 3 can do — Helm 3 has no `--kube-version` on
`install` to suppress the discovery, and it fails with `Kubernetes cluster
unreachable`. An ordinary install and upgrade need only the floor above. If you
reach one of those steps on Helm 3 the installer says so exactly, at that step,
naming Helm 4 and `--fetch-tools`.

**`--fetch-tools`** — accepted by every command — restores the old behaviour:
the installer downloads this release's own checksum-pinned Helm, kubectl and jq
into a private directory for that run and uses those instead. Use it on a box
whose clients are too old to upgrade, on an air-gapped host that already has
the cache populated, or to get Helm 4 for the two paths above. The pinned
versions and their SHA256s are in the release you already hold —
`payload release.json | jq .clients` — re-define the two-line `payload()` helper
from "Before you start" in whatever shell you are in; it does not survive a new
one. **Read them before you let `--fetch-tools` run:** its kubectl is
pinned for the release, not for your cluster, and it can sit well outside the
+/-1 window the kubectl row above makes a rule. If it does, upgrade your own
kubectl rather than fetching that one, and reserve `--fetch-tools` for the two
cluster-free-render paths that genuinely require Helm 4. The download happens
before the site file is read, so a proxy or custom CA needed for it must
already be available to `curl`.

## Obtain and verify a release

The release public key is published beside the installer, on the release
page, and the release and your registry token are handed to you directly by
TUM Legal Tech. Retain the exact installer, descriptor, signature and key for
recovery. Use a release's immutable directory — for this line,
`https://github.com/TUMLegalTech/gsj-next-installer/releases/download/<version>`.

**Read this section even if you already verified your release.** Two parts of it
are prerequisites for every install: the image inventory and, if your nodes do
not pull from the registry the release names, **[Make your nodes able to pull
the images](#make-your-nodes-able-to-pull-the-images)** below. That one is the
most common way an install fails, and it fails hours in.

What you may skip is the next block only. It fetches a release from its HTTPS
release directory into a directory of its own and verifies it. If you already
downloaded and verified the five files by hand, "Before you start" covered
you; go to the image inventory below.

For the public, credential-free HTTPS release directory:

```sh
umask 077
mkdir -p "$HOME/gsj-operator/releases"
# bash, not sh. The whole download sits INSIDE the check: a refused name must
# reach nothing below it, and `|| exit` would close the terminal you pasted into.
if [ -z "${GSJ_RELEASE_NAME:-}" ] || [ -z "${GSJ_RELEASE_URL:-}" ]; then
  echo 'set first, then paste this block again -- GSJ_RELEASE_NAME=<a new local name for this exact release>; GSJ_RELEASE_URL=<the exact release directory URL>' >&2
elif [[ $GSJ_RELEASE_NAME =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  mkdir -m 700 "$HOME/gsj-operator/releases/$GSJ_RELEASE_NAME" &&
  cd "$HOME/gsj-operator/releases/$GSJ_RELEASE_NAME" &&
  for asset in gsj-install.sh installer-descriptor.json installer-descriptor.sig release.pem verify-release.sh; do
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
      "$GSJ_RELEASE_URL/$asset" --output "$asset" || break
  done &&
  bash verify-release.sh gsj-install.sh installer-descriptor.json \
    installer-descriptor.sig release.pem &&
  chmod 500 gsj-install.sh &&
  ./gsj-install.sh --help
else
  echo 'refused: use letters, digits, dot, dash or underscore' >&2
fi
```

The exclusive directory creation refuses to overwrite a previously saved
release. Retain each predecessor directory for named recovery.

The verification command checks the signature and exact executable hash without
executing the installer.

**What you are given, and what it is called.** A release is five things, all
on its release page: the executable, its `installer-descriptor.json`, that
descriptor's `.sig`, the release public key `release.pem` and the
`verify-release.sh` utility that checks them. The executable's own filename
is whatever the release publisher chose and the signed descriptor records; read
it before you run anything, because the examples in this guide all write
`./gsj-install.sh` and yours may not be called that:

```sh
jq -r '.installer.name, .version, .releaseId' installer-descriptor.json
```

Substitute that name wherever this guide writes `gsj-install.sh`. Nothing else
about the command lines changes. (A qualification build is commonly named for
its engineering line rather than the product; the descriptor is the authority,
and `verify-release.sh` compares the bytes, not the name.)

A published release names its own release directory (`release_base_url` in the
payload's `release.json`: this repository's release page), and that is where
`upgrade --to` fetches a successor from. A qualification build — one a
maintainer hands you outside a release — may carry none, and then **every
`--to` option is unavailable** — `upgrade --to`, `repair --to`, and the
corrected-release recoveries the reason-code table names. The installer says
so, in those words, in about six seconds. To move to another version you run
THAT version's own signed installer directly. The plain `repair --operation ID
--config <your site.json>` reapplies the release you already have and needs no
endpoint at all. Whatever the build, the release's six images are pinned by
digest at whatever registry the build recorded. **Your Kubernetes nodes must be
able to pull those exact digests.** Read the inventory out of the executable
before you plan for it:

```sh
INSTALLER=$(jq -r .installer.name installer-descriptor.json)   # NOT "gsj-install.sh"
marker=$(awk '/^__GSJ_PAYLOAD_BELOW__$/ {print NR+1; exit}' "$INSTALLER")
tail -n "+$marker" "$INSTALLER" | base64 --decode | tar -xzO release.json \
  | jq -r '.images | to_entries[] | "\(.key)\t\(.value.repository)@\(.value.digest)"'
```

**Those six are the application images. A managed profile adds more**, and they
are pinned in the same payload under `addons`. If you choose
`tls.profile=managed-acme` (cert-manager), `ingress.profile=managed-traefik` or
`storage.profile=managed-local-path`, mirror these too:

```sh
tail -n "+$marker" "$INSTALLER" | base64 --decode | tar -xzO release.json \
  | jq -r '.addons | to_entries[] | .key as $a | .value.images | to_entries[]
           | "\($a)\t\(.key)\t\(.value)"'
```

A `reuse` profile needs none of them, which is one reason to prefer `reuse`
wherever you already run a controller.

### Make your nodes able to pull the images

**A pull Secret does not redirect a pull.** `registry.config_file` and
`registry.pull_secret` supply *credentials*; they never change where an image
is pulled from. What changes that is **`registry.base`**.

#### Your own registry, under any prefix: `registry.base`

The release names where each image was *published*. If your nodes pull from
somewhere else — and in most enterprises they do, from a project or repository
under a path prefix — copy the six digests there and say where:

```json
"registry": {"base": "registry.example.org/team/project"}
```

Every image reference the installer composes then becomes
`<registry.base>/<last path segment of the release's repository>@<digest>`: the
chart's five workload images, the corpus image, and every maintenance Pod the
installer itself creates. **The digest is always the signed release's.** It is
never site input — the schema refuses a tag or an `@` in `registry.base` — and
a by-digest pull cannot resolve to other bytes, so a registry holding different
content under that name fails the pull rather than supplying something else.

The value is a registry host with an optional port and an optional lowercase
path: no scheme, no trailing slash, no tag. This prints the six copies you
need, source then destination:

```sh
if [ -z "${BASE:-}" ]; then
  echo 'set first, then paste this block again -- BASE=<your registry host and prefix, for example registry.example.org/team/project>' >&2
else
  payload release.json | jq -r --arg base "$BASE" \
    '.images[] | "\(.repository)@\(.digest)  ->  \($base)/\(.repository | split("/") | last)"'
fi
```

Copy them with any tool that moves a manifest **without rewriting it**.
`docker buildx imagetools create` does, and needs nothing but Docker; run it
where both registries are reachable and you are logged in to both:

```sh
payload release.json | jq -r --arg base "$BASE" \
  '.images[] | "\(.repository)@\(.digest) \($base)/\(.repository | split("/") | last)"' |
while read -r src dst; do
  docker buildx imagetools create --tag "$dst:gsj" "$src" &&
  docker buildx imagetools inspect "$dst@${src##*@}" >/dev/null && echo "ok  $dst@${src##*@}"
done
```

The tag (`:gsj`) is only a handle the registry needs; **its** digest will
differ, because `imagetools` wraps the manifest in a new index. That does not
matter. What must exist at the destination is the release's own digest, which
is what the second command asks for by digest and what the installer will pull.
Six `ok` lines, or do not go on. `docker pull` / `docker tag` / `docker push`
is **not** a substitute: it re-packs layers and can change the digest.

If that registry needs credentials, give `registry.config_file` a Docker
config whose `auths` key is the **`registry.base` host** — that is the host the
Pod specs now name — and `registry.pull_secret` the Secret name to create.

**What the installer does with it.** Before Helm applies anything it starts one
Pod on your storage node with one container per image, by relocated digest,
using your pull Secret, and waits for the node's own container runtime to pull
all six. A wrong prefix, a digest that was not copied and a credential that does
not apply all stop there, in about two minutes, in the runtime's own words:

```
GSJ: the node cannot pull this release from registry.base (registry.example.org/team/wrong): 6 of 6 images: ... The container runtime said, of the first: ... not found. ... Helm has applied nothing in this run
```

On a first install nothing exists yet at that point. On an upgrade the probe
runs **before** the backup quiesces your application, so what was running is
still running. Correct `registry.base`, the registry's contents or the
credential, wait the 180 s the operation's Lease needs to go stale, and run the
`repair --operation ID --config ...` the installer names — `resume` would
refuse, because the cure is a changed site file.

**It is asked again whenever the location changes**, in either direction. An
upgrade whose site file has *lost* `registry.base` — a stale copy, a deleted
line — would otherwise point every Pod back at the release's original
repositories, the ones you said your nodes cannot reach. That is probed exactly
like a new base, and refused the same way.

**Three limits.** The interactive wizard never asks for `registry.base`; it
keeps one you wrote into the site file beforehand, so write it first. `backup`
refuses a site file that differs from the installed one in any application
setting, this one included — take the backup **before** you edit
`registry.base`, not after. And `restore` carries the source's registry
credential in the archive and requires the recovery site's to match it: a
recovery site may name a different `registry.base` only if it needs no
different credential. Restore onto the source's registry arrangement first, and
move registries afterwards with an upgrade.

**What it does not move.** The managed add-ons — `managed-traefik` and
`managed-acme` (third-party charts) and `managed-local-path` (an upstream
manifest) — carry their own pinned images, and `registry.base` leaves those where the release names them
(the installer lists them for you at preflight when your profiles select one).
For those, and for a site you would rather not change, the older remedy still
applies.

#### A container-runtime mirror on every node

1. copy the digests into a registry your nodes can reach, **at the repository
   path the runtime will ask for** — the path the release names, except that an
   official Docker Hub image written `docker.io/traefik` is asked for as
   `library/traefik`. A plain mirror preserves that path. k3s and RKE2 can also
   *rewrite* it, which is how a registry that insists on a prefix can serve a
   mirror after all — the entries are below;
2. tell each node's container runtime to resolve the original host to yours. On
   k3s that is `/etc/rancher/k3s/registries.yaml` on **every** node followed by a
   `systemctl restart k3s` / `k3s-agent`; on RKE2 it is
   `/etc/rancher/rke2/registries.yaml` (RKE2 generates containerd's `certs.d`
   from it and overwrites hand edits); on plain containerd it is a `hosts.toml`
   under `certs.d/`. Consult your distribution — this is the one prerequisite
   that lives outside both the installer and the cluster API;
3. use `registry.pull_secret` only if that mirror needs authentication, keyed on
   the host the Pod spec names — with a mirror that is still the **original**
   host, because the mirror is applied below it. (Measured on k3s, against a
   mirror that demands a login: a Secret keyed on the original host pulled; the
   same credential keyed on the mirror's own host was refused, and so was no
   Secret at all.)

The k3s entry, which RKE2's file shares the format of. The first key is the host
**the release names** — step 3 printed it — never your own:

```yaml
# /etc/rancher/k3s/registries.yaml        (RKE2: /etc/rancher/rke2/registries.yaml)
mirrors:
  "registry.the-release-names.example":
    endpoint:
      - "https://registry.example.org"
    rewrite:                               # ONLY if your registry insists on a prefix
      "^tumlegaltech/(.*)": "team/project/$1"
```

Measured on k3s v1.31.5, on nodes with no route to the registries the Pods
named. With the `rewrite` line, a Pod on a freshly started node naming
`<original host>/tumlegaltech/<image>@<digest>` was pulled from a registry that
held that digest **only** under `team/project/<image>`. With the mirror entry
but no `rewrite` line — probed with a second prefix, `gsj/`, which the lab's
file rewrote with a second rule of the same shape — the pull of
`<original host>/gsj/<image>@<digest>` failed, and the error the runtime
reported was the original host's: with nothing at the unrewritten path,
containerd goes on to the host the Pod named. (That leg recorded the Pod's
error, not the registry's own log.) With no mirror entry at all the pull went straight to the
original host, which did not resolve. k3s writes the rule into the `hosts.toml`
it generates.

**For the managed add-ons** — route 3 of step 0 — the hosts the release pins
them at become **further keys in that one `mirrors:` map**, beside the entry
above, and the rules must match the paths the runtime asks for. The whole file:

```yaml
# the same registries.yaml, complete: ONE `mirrors:` map, one key per host
mirrors:
  "registry.the-release-names.example":         # the entry above, unchanged
    endpoint:
      - "https://registry.example.org"
    rewrite:
      "^tumlegaltech/(.*)": "team/project/$1"
  docker.io:
    endpoint:
      - "https://registry.example.org"
    rewrite:
      "^library/(.*)": "team/project/$1"        # docker.io/traefik and docker.io/library/busybox
      "^rancher/local-path-provisioner(.*)": "team/project/local-path-provisioner$1"
  quay.io:
    endpoint:
      - "https://registry.example.org"
    rewrite:
      "^jetstack/(.*)": "team/project/$1"       # the five cert-manager images
configs:                                        # a sibling of `mirrors:`, not inside it; ONLY if that registry needs a login
  "registry.example.org":                       # the MIRROR's host: the opposite key from the pull Secret
    auth: {username: "…", password: "…"}
```

Measured, the first rule only: a Pod naming `docker.io/traefik@<digest>` was
pulled from a registry that held the digest only under `team/project/traefik`,
the runtime reporting the image as `docker.io/library/traefik`; without the
rule the same pull failed.

**These rules are wider than the eight images.** A mirror entry is consulted for
**every** pull from that host on that node, the distribution's own images
included: in that run the node also asked the mirror for k3s's own
`rancher/mirrored-pause`, `rancher/mirrored-coredns-coredns` and
`rancher/local-path-provisioner:v0.0.30`. The lab's registry had been stocked
with the first, at its own path, and served it; it held neither of the others
and answered 404 — after which the runtime goes to `docker.io`, the one host
such a node cannot reach. Two things follow. Your registry must also carry your
distribution's own `docker.io` images, at the paths your rules leave them at,
unless the node already holds them: a node that cannot fetch its sandbox image
starts no Pod at all (measured separately, on a node with no route out:
*failed to get sandbox image*). And the `rancher/local-path-provisioner` rule
above also catches k3s's **bundled** provisioner — the same repository at
another version, and a rewrite sees only the repository — so the rewritten
repository has to hold that version as well; `^library/(.*)` likewise sends
every official Docker Hub image pulled on that node to your prefix. Narrow them
to what you use: a rule may name one repository exactly, with a literal target
(`"^library/traefik$": "team/project/traefik"` — a form we did not run).

If you use `configs:`, that registry's password sits in clear in this file on
**every** node, and nothing sets its permissions for you: you create the file,
so create it under `umask 077`, or `chmod 0600` it, and leave it owned by root.

**Not run:** the `rancher/` and `quay.io` rules above, the `configs:` block,
RKE2 itself, a whole install through a rewriting mirror, and plain containerd.
Plain containerd's own `hosts.toml`
documents no `rewrite` key; it does document `override_path`, which makes the
path in the host URL the registry API root, so every repository is fetched
beneath it. That is a different mechanism, we have not tried it, and if it works
for you, step 0's last route is not yours.

There is no way to verify this from the installer shell, and `inspect` cannot do
it for you: its egress probe is explicitly `probed_from: "the installer host,
not from inside the cluster"`. The cheap proof is to run one throwaway Pod on
the target node against one of the six digests before you start:

```sh
kubectl get nodes -o wide
if [ -z "${NODE:-}" ]; then
  echo 'set first, then paste this block again -- NODE=<the node that will carry the claims, from the list above>' >&2
else
  BASE=${BASE:-}                      # your registry.base, or empty for the repositories the release names
  IMG=$(payload release.json | jq -r --arg base "$BASE" \
    '.images.web | (if $base == "" then .repository else $base + "/" + (.repository | split("/") | last) end) + "@" + .digest')
  kubectl run pull-probe -n default --restart=Never --image="$IMG" \
    --overrides="{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"$NODE\"}}}" \
    --command -- true
  kubectl -n default wait pod/pull-probe --for=jsonpath='{.status.phase}'=Succeeded --timeout=300s
  kubectl -n default get pod pull-probe           # Completed is the pass
  kubectl delete pod pull-probe -n default
fi
```

The `nodeSelector` is the point: a green result on some other node proves
nothing about the node that will carry the claims and run the initializer.
The block waits and prints the status rather than passing `--attach`: with
`--attach` a Pod that cannot pull blocks instead of reporting, and `ImagePullBackOff` is visible only
in its status, from a second terminal. `Completed` is the pass.

If your mirror needs authentication, the probe needs the same Secret the
install will use — create it first and name it in the override, because
`kubectl run` has no flag for it:

```sh
if [ -z "${REGISTRY_HOST:-}" ] || [ -z "${REGISTRY_USER:-}" ] || [ -z "${IMG:-}" ] || [ -z "${NODE:-}" ]; then
  echo 'set first, then paste this block again -- REGISTRY_HOST=<the host the Pod spec names: your registry.base host, or the original host behind a mirror>; REGISTRY_USER=<your registry username>; and IMG and NODE from the probe above' >&2
else
  read -rs REGISTRY_TOKEN; echo                    # typed, not echoed, not in history
  if [ -z "$REGISTRY_TOKEN" ]; then
    echo 'empty token: nothing was created' >&2
  else
    kubectl create secret docker-registry gsj-pull -n default \
      --docker-server="$REGISTRY_HOST" \
      --docker-username="$REGISTRY_USER" --docker-password="$REGISTRY_TOKEN"

    # the probe again, with the Secret -- this is the whole --overrides value, merged:
    kubectl run pull-probe2 -n default --restart=Never --image="$IMG" \
      --overrides="{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"$NODE\"},\"imagePullSecrets\":[{\"name\":\"gsj-pull\"}]}}" \
      --command -- true
    kubectl -n default wait pod/pull-probe2 --for=jsonpath='{.status.phase}'=Succeeded --timeout=300s
    kubectl -n default get pod pull-probe2          # Completed is the pass
    kubectl -n default delete pod pull-probe2; kubectl -n default delete secret gsj-pull
  fi
fi
```

`--docker-server` must name the host the **Pod spec** names — the
`registry.base` host if you set one, otherwise the release's original host even
behind a mirror: the kubelet matches the credential against the requested
registry and applies a mirror below that. Any namespace you can write to will do — the install
namespace need not exist yet, and the probe proves the node, not the namespace.

The block waits for the Pod, prints its status and removes it — it neither
watches nor attaches: with `--attach` a Pod that cannot pull blocks instead of
reporting, and a watch has to be interrupted, which ends the whole pasted block
before its cleanup line ([step 4](#step-4--prove-your-nodes-can-pull-the-images)
has the measurement).

If that Pod reaches `Completed`, your nodes can pull. `Pending` is not a pull failure — an unsatisfiable `nodeSelector` parks a Pod there too; `describe` says which. If it sits in
`ImagePullBackOff`, fix it now — during an install the same failure appears
much later, as a provisioning hook that exceeds its deadline.
For an authenticated origin, use a protected single-line `Authorization:`
header file, `curl --header @FILE`, and `--max-redirs 0`. Do not put tokens in
URLs or command arguments. The distribution rules at the end of this guide
explain why authenticated GitHub release redirects need a different origin.

## Inspect, then install

`inspect` reads cluster APIs and reports the installer host separately from
Kubernetes nodes. It includes cores, RAM, host filesystem availability, Helm
and Kubernetes versions, Node capacity/allocatable, pod requests, PVC/PV and
StorageClass details, ingress classes, and live Node usage when the metrics
API is available. Missing telemetry or permissions remain visible as unknowns.
It does not create application resources, and it never writes to the cluster
at all: every probe is a read, a version query, a `df` or an outbound HTTPS
reachability check. It takes no Lease, needs no namespace and reads no site
file, so it is safe to run against a stranger's production cluster.

`inspect` also emits a **`profile`** object (schema `gsj.environment-profile/1`)
— one structured document you can send back to us. From it we can stand up a
rehearsal cluster shaped like yours and test the install before you run
anything. It records the Kubernetes distribution and version, the node and
control-plane topology, capacity against what is already committed, every
StorageClass with its provisioner/reclaim policy/binding mode and the path
`local-path` actually writes to, the CNI, the ingress controllers and the
hostnames and NodePorts already in use, whether a LoadBalancer Service can get
an address, cert-manager, outbound reachability of the image and artifact
hosts, and which namespaces and Helm releases already exist.

Its `excluded` field states what it deliberately leaves out, and the omissions
are the point: **no Secret data of any kind** (the Helm release inventory is
read through `custom-columns`, which cannot emit a release payload), no
annotation/label/StorageClass parameter *values* — only their names, no
PersistentVolume backend paths or handles, no kubeconfig, token or credential,
and no proxy userinfo (origin only). Node and namespace *names* are kept,
because a rehearsal needs the shape and the collisions.

Two fields are honest about their limits. `networking.cni.denied_policy_behaviour`
is `unknown`: whether a denied NetworkPolicy drops (the connection hangs) or
rejects (it fails at once) is an implementation choice of the CNI, deciding it
needs a probe pod pair and a deny policy, and `inspect` never creates anything.
The `rehearsal` field lists what a rehearsal built from the profile proves and
what it cannot — your hardware, your network, a proxy, multi-node scheduling
and real ReadWriteOnce contention do not transfer. A green rehearsal proves the
install logic, not your environment.

`inspect` first — it writes nothing:

```sh
export KUBECONFIG=/path/to/kubeconfig
./gsj-install.sh inspect --context "$(kubectl config current-context)" > inspection.json
```

Then, and only once you have read it and written a site file, the wizard. This
one **does** install:

```sh
./gsj-install.sh install --interactive --config "$HOME/gsj-operator/site.json"
```

The wizard asks you to review the context, namespace/release, HTTPS URL, operator
login, LLM/OCR endpoints and model, storage node/class, ingress and TLS profiles.
On a new configuration it discovers Nodes, StorageClasses and IngressClasses;
it offers a managed profile when the relevant addon is absent. Those choices
still need review. It accepts LLM/OCR authentication as direct protected terminal
input, a private file, an existing Secret with a `key` entry, or explicitly no
authentication. It disables terminal echo before showing a secret prompt.

**The wizard does not ask about the decisions corpus, and `install --interactive`
does not stop between saving your site file and applying it.** There is no
moment in that command in which to add the corpus block, so **a site that wants
the released vectors must be installed non-interactively**: run the wizard once
if you like it for discovery, let it fail or complete, then edit the site file
it saved and use `install --config "$HOME/gsj-operator/site.json" --non-interactive` from then on. Or write
the file yourself from the complete example below, which carries the corpus
already. Unless the site is meant to embed its own, different store, set

```json
"corpus": {
  "vectors_url": "https://github.com/TUMLegalTech/gsj-decisions-corpus/releases/download/corpus-1.snowflake-m-v2-int8-768.f93c956f/vectors.json",
  "vectors_sha256": "15bf3fb0530af8e2cb3941f0b35bf2454cc3d21bad55a467465f5939a502399c"
}
```

This is the default a customer's site should carry.
[Where the corpus artifact comes from](#where-the-corpus-artifact-comes-from)
has the full recipe, the no-egress `vectors_path` alternative and the disk
budget — it is filed under "Upgrade and recover a named operation" because that
is where the corpus reference lives, but a first install needs it. Leaving both sources empty is a real choice, not an oversight —
but it is the choice to search a store nobody else has.

The wizard saves reusable configuration plus private credential files beside
it. It generates a backup passphrase when none is supplied. Preserve an
independent recovery copy of that passphrase. The wizard discovers your
**cluster** — nodes, StorageClasses, IngressClasses — and never your model
endpoint: it contacts neither `llm.base_url` nor `ocr.url`, and takes the model
name and context window as you type them. A context-window value of zero leaves
the limit to the application's own run-time discovery and SDK defaults, which is
not proof that an arbitrary endpoint advertises a usable one.

For automation, prepare a site JSON and its protected inputs in advance, or
reuse the wizard's saved file:

```sh
./gsj-install.sh install --config "$HOME/gsj-operator/site.json" --non-interactive
```

### A complete site file

This illustrative site uses existing storage/ingress and certificate files.
Replace the example names, URLs, model and paths with real site values. Omitted
properties receive the embedded defaults; unknown properties are rejected.
The OCR URL is the complete OpenAI-compatible chat-completions URL.

```json
{
  "schema_version": "gsj.site/1",
  "target": {"context": "production", "namespace": "gsj", "release": "gsj"},
  "public_url": "https://cases.example.org",
  "operator": {"login": "operator", "password_file": "credentials/operator-password"},
  "llm": {
    "base_url": "https://models.example.org/v1",
    "model": "your-deployed-model",
    "context_window": 131072,
    "output_tokens": 8192,
    "credential": {"file": "credentials/llm-key"},
    "allowed_origins": []
  },
  "ocr": {
    "url": "https://ocr.example.org/v1/chat/completions",
    "model": "glm-ocr",
    "credential": {"file": "credentials/ocr-key"}
  },
  "storage": {"profile": "reuse", "class": "local-path", "node": "worker-1",
              "transfer_path": "/srv/gsj/transfer"},
  "ingress": {"profile": "reuse", "class": "nginx", "namespace": "ingress-nginx"},
  "tls": {
    "profile": "files",
    "secret": "gsj-tls",
    "certificate_file": "certificates/fullchain.pem",
    "private_key_file": "credentials/tls-key.pem"
  },
  "backup": {"directory": "/backups/application", "passphrase_file": "credentials/backup-passphrase"},
  "deadlines": {"initialization_seconds": 86400},
  "registry": {"config_file": "credentials/registry-auth.json", "pull_secret": "gsj-pull"},
  "corpus": {
    "vectors_url": "https://github.com/TUMLegalTech/gsj-decisions-corpus/releases/download/corpus-1.snowflake-m-v2-int8-768.f93c956f/vectors.json",
    "vectors_sha256": "15bf3fb0530af8e2cb3941f0b35bf2454cc3d21bad55a467465f5939a502399c"
  }
}
```

One field in it is explained nowhere else: `llm.output_tokens` caps the tokens
a single model reply may generate. Leave it out and pi's own default applies;
set it when your endpoint's default is too small for a drafted document.

That example is complete on purpose: it carries the **`corpus`** block — without
which the site builds its own store that matches no other site — and the
**`registry`** block, which a cluster pulling from an authenticated private
registry needs. Drop `registry` if your nodes pull anonymously. Check the
corpus URL against your own release's fingerprint as described above before
using it.

### Installing onto claims that already exist

`storage.data.existing_claim`, `storage.forgejo.existing_claim` and
`storage.chroma.existing_claim` name PersistentVolumeClaims you already have.
It is the route for putting the data on a disk of your choosing without a
managed add-on, and the route for re-installing onto the data of a release you
removed.

```json
"storage": {"profile": "reuse", "class": "local-path", "node": "worker-1",
            "data":    {"existing_claim": "gsj-data"},
            "forgejo": {"existing_claim": "gsj-forgejo"},
            "chroma":  {"existing_claim": "gsj-chroma"}}
```

What the installer then does, and requires:

- for each role with a name, the chart creates **no** claim and mounts yours.
  A role you leave empty gets the chart's own `<release>-<role>` claim — new
  only if nothing already holds that name. The chart marks its claims
  `helm.sh/resource-policy: keep`, so a claim a previous install *of the same
  release name* created is still there after `helm uninstall` and is mounted
  again, data and all;
- the claims must be in the **target namespace** (create the namespace first;
  the installer adopts an existing one), `ReadWriteOnce`, and bindable on
  `storage.node`, because all three Pods are pinned there;
- before Helm applies the application chart, the storage probe mounts the
  **data** claim and checks its free space against `storage.minimum_free_bytes`
  and its SQLite, locking and `fsync` behaviour. A claim that fails is refused
  there. (One thing runs earlier: a managed add-on, if you chose one, is
  installed before this probe and is not removed by a refused claim;)
- `storage.class` must still name a qualified StorageClass that exists:
  preflight reads it under `reuse` whether or not you bring claims.

**One thing rides along with a data claim: the corpus initializer's
checkpoint.** It lives on the data claim, keyed to — among other things — the
release's own Chroma service name and `corpus.repair_generation`. Re-install
under the **same** release name onto a claim whose last initialization ended
terminal, and the new install stops at once with
`gsj-corpus:terminal-budget-exhausted` — or `gsj-corpus:deadline-exceeded`,
when that is how it ended — whatever the original reason was:
[Sweep the residue of a dead run](#sweep-the-residue-of-a-dead-run) gives the
two ways through. Under a **new** release name the key differs and
initialization starts with a fresh budget — it still finds the corpus already
imported and verifies it rather than importing again, which is what the runs
below did.

**What we have run:** re-installing onto the claims of an uninstalled release
— Helm keeps them — twice, on a live cluster. The initializer found the corpus
already imported, verified every shard instead of re-importing, and the install
completed in 17 minutes instead of four and a half hours.

**Volumes you provisioned by hand under `kubernetes.io/no-provisioner`** — run
too: once as the target of a restore onto a second cluster, whose own run
reached fifteen of fifteen, and twice as the target of an install with all three
claims named. Those two installs went onto volumes we had seeded with a copy of
the restored deployment's data, so they adopted a corpus instead of importing
one. On both, the storage check passed on the named claims and every Pod came
up; both were then stopped on purpose at the OCR check — step 0's prerequisite,
left unmet — and both ended fifteen of fifteen after the OCR values were
corrected: the second by one `repair`, the first by a longer road through a
defect this release fixes. Three `local` PersistentVolumes each time, on a
filesystem of our choosing. What made ours bind:
each volume `volumeMode: Filesystem`, `ReadWriteOnce`, with a `nodeAffinity` for
exactly `storage.node`; each at least as large as the claim that binds it; and a
`claimRef` naming the claim's namespace and name, which keeps any other claim
from taking it. (Our class was `WaitForFirstConsumer`, the usual choice for
`local` volumes; the installer reads a class you bring only to admit its
provisioner and never looks at its binding mode.) The installer checks none of
this before the Pods need it. On a restore the claims are recreated from the
archived ones — the requested sizes and access modes are the source's, only the
class is yours — so size the volumes for the source's claims. Forgejo's Pod
deliberately carries no `securityContext`: its stock image starts as root and
takes ownership of its own data directory, so that directory's owner is not
yours to get right. We did not record the owner or mode of the other two
directories before the Pods first wrote to them.
`storage.<role>.size` is still required by the schema and is ignored for a role
whose claim you name. `inspect` cannot tell you the free space behind such a
class: `storage.claim_backing` describes the directories of a local-path
provisioner if the cluster runs one — k3s bundles one unless it was started with
`--disable local-storage` — and those are not your volumes'. With no readable
local-path configuration it lists no paths at all, and
`storage.local_path_node_paths` says `known: false` with the reason. Either way,
check that filesystem yourself.

The objects, in the shape we ran them — one role of three; repeat the volume
and the claim for `forgejo` and `chroma`, each with its own names and
directory. Everything in capitals is yours. We made the directories on the node
beforehand. The capacity of a `local` volume is a label, not a quota: what the
storage check measures is the free space of the filesystem behind the data
claim.

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {name: gsj-static}                          # -> storage.class
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Retain
---
apiVersion: v1
kind: PersistentVolume
metadata: {name: gsj-data}
spec:
  capacity: {storage: 20Gi}
  volumeMode: Filesystem
  accessModes: ["ReadWriteOnce"]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: gsj-static
  local: {path: /DIRECTORY/ON/THAT/NODE/data}
  claimRef: {namespace: NAMESPACE, name: gsj-data}
  nodeAffinity: {required: {nodeSelectorTerms: [{matchExpressions: [{key: kubernetes.io/hostname, operator: In, values: ["STORAGE-NODE"]}]}]}}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: gsj-data, namespace: NAMESPACE}     # -> storage.data.existing_claim
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: gsj-static
  volumeName: gsj-data
  resources: {requests: {storage: 20Gi}}
```

**On such a class, name all three claims — above all the data claim.** With
`storage.data.existing_claim` empty the storage check makes a temporary 1 Gi
claim of its own, and on a class where nothing deletes a released volume that
ends badly. Measured: the temporary claim bound a spare volume of *ours*, the
check marked that volume `Delete` and removed its claim, nothing deleted the
volume, and two minutes later the install stopped with *"temporary storage
backend cleanup incomplete"*, leaving the volume `Failed` with reclaim policy
`Delete` — its directory still empty, but the object useless until deleted and
created again. (This release's message names the volume and says so; earlier
ones printed those four words alone.) The way back we ran: once the Lease had
gone 180 seconds unrenewed, `abandon --operation ID --reason "…"`, then the
claims named in the site file, then `install` again — its storage check passed
on the named claim. The spoiled volume matters only if you still mean to use
it. (A cluster running a static-volume deleter, such as the sig-storage local
static provisioner, is the case where an empty name can work; we have not run
one.)

### A certificate you already issue: `tls.profile=existing`

```json
"tls": {"profile": "existing", "secret": "gsj-tls"},
"verification": {"ca_file": "certificates/corp-ca.pem"}
```

`tls.secret` names a Secret of type `kubernetes.io/tls`, holding `tls.crt` and
`tls.key`, **in the target namespace, before you install** — the installer
reads it and refuses *"TLS Secret is unavailable or incomplete"* otherwise. How
it gets there is yours: a cert-manager `Certificate` whose `secretName` is that
name, or `kubectl create secret tls`. Unlike `files`, this profile does not
check that the certificate matches `public_url`'s hostname; the installer's own
`public_https` probe does — a `curl` from the machine you run the installer on,
so `verification.ca_file` must be readable there and that machine must reach the
route: `public_url` itself, or `verification.connect_host`/`connect_port` when
you set them, because that redirect applies to this `curl` too. The installer
then checks the certificate once more from inside the `gsj-web` container before
it starts the verifier. `verification.ca_file` is
needed exactly when the issuer is not publicly trusted: the PEM of the CA that
signed it, path relative to the site file. Leave the whole `verification` block
out for a publicly trusted certificate.

### The five values only you can supply

Nothing discovers these and no default is right for them. They describe systems
GSJ talks to but does not run. An install can start — and complete — without
the model endpoints: leave `llm.base_url` and `llm.model` both empty, or
`ocr.url` empty, and the acceptance checks that need them are skipped and named
(step 9), and the product lacks that capability until they are set.

| field | what it is | where you get it |
|---|---|---|
| `llm.base_url` | the OpenAI-compatible **base** URL of the chat model the agent uses — the part ending `/v1`, with no route after it — or empty, together with `llm.model`: the install completes with the two agent checks skipped (`llm-absent`) and the agent cannot answer until an endpoint is set, per case under Einstellungen or here and `install` again | your own model deployment (vLLM, an inference gateway, a hosted endpoint). GSJ ships no model and no endpoint |
| `llm.model` | the model id that endpoint serves | `curl "$LLM_BASE_URL/models"` — note `llm.base_url` ALREADY ends in `/v1`, so the models route is `$LLM_BASE_URL/models`, never `$LLM_BASE_URL/v1/models` |
| `llm.context_window` | that model's usable context in tokens; drives the lawyer-facing KONTEXT meter and compaction | the same answer's `max_model_len`, or the model card. `0` is a defined setting, not a gap: the agent runtime then asks the endpoint's `/models` route itself, with your key, and falls back to its SDK defaults where that gives nothing — which is not proof the endpoint advertises a usable limit. A number you write is taken as given and never checked against the endpoint. The installer itself never contacts `llm.base_url`: nothing is probed at install time |
| `ocr.url` | the **complete** chat-completions URL of a vision model for scanned pages — note this one is the full route, not a base — or empty: the install completes with the scanned-page check skipped (`ocr-absent`) and scanned pages are not read until it is set and `install` runs again | your OCR deployment; step 0's probe and the reasons are there |
| `ocr.model` | the model id that endpoint serves | as above |

`http://` is accepted as well as `https://` for both, which is what a
same-network model host usually is. Both endpoints must be reachable **from
inside the cluster**, not merely from the installer shell: the agent runner and
the web container dial them, and that is where acceptance decides whether an
endpoint works (the installer's own first-minute probe runs from your machine
and only forecasts). A quick check before you install, from any pod on the
target cluster — skip the line of an endpoint you left empty:

```sh
# Use an image your NODES can already pull -- on a private-registry cluster
# `curlimages/curl` is exactly the thing that will not start. The `web` image
# from the inventory above carries python3 and is one your nodes must be able
# to pull anyway. Every kubectl flag must come BEFORE the `--`; everything
# after it is the container's argv.
LLM_BASE_URL=$(jq -r .llm.base_url "$HOME/gsj-operator/site.json")
OCR_URL=$(jq -r .ocr.url "$HOME/gsj-operator/site.json")
NODE=$(jq -r .storage.node "$HOME/gsj-operator/site.json")
BASE=$(jq -r '.registry.base // ""' "$HOME/gsj-operator/site.json")
ROUTE=$(jq -r '(.public_url | capture("^https://(?<h>[^:/]+)(:(?<p>[0-9]+))?")) as $u | (.verification // {}) as $v
  | (if ($v.connect_host // "") != "" then $v.connect_host else $u.h end) + ":"
    + ((if ($v.connect_port // 0) > 0 then $v.connect_port else ($u.p // "443") end) | tostring)' "$HOME/gsj-operator/site.json")
WEB_IMAGE=$(payload release.json | jq -r --arg base "$BASE" \
  '.images.web | (if $base == "" then .repository else $base + "/" + (.repository | split("/") | last) end) + "@" + .digest')
kubectl run llm-probe --rm -i --restart=Never --image="$WEB_IMAGE" \
  --env="U=$LLM_BASE_URL" --env="O=$OCR_URL" --env="R=$ROUTE" \
  --overrides="{\"spec\":{\"nodeSelector\":{\"kubernetes.io/hostname\":\"$NODE\"}}}" \
  --command -- python3 -c '
import os, socket, urllib.request, urllib.error
for name, url in (("llm.base_url + /models", os.environ["U"] + "/models"), ("ocr.url", os.environ["O"])):
    try:
        print(name, url, "->", urllib.request.urlopen(url, timeout=10).status)
    except urllib.error.HTTPError as e:
        print(name, url, "->", e.code)
    except Exception as e:
        print(name, url, "-> FAILED", type(e).__name__ + ":", e)
host, port = os.environ["R"].rsplit(":", 1)
try:
    socket.create_connection((host, int(port)), timeout=10).close(); print("public_url route", os.environ["R"], "-> TCP reached")
except Exception as e:
    print("public_url route", os.environ["R"], "-> FAILED", type(e).__name__ + ":", e)
'
```

Each endpoint gets one line. A number is an HTTP status: something answered
HTTP at that address — `200` for the models route; for `ocr.url` usually `405`
or `404`, because this is a plain `GET` at a route that wants a `POST`; `401`
where a key is wanted, since this Pod carries none. A status can also come from
a proxy or gateway in front of the endpoint: a `502`, `503`, `504` or `407`
says the front answered, not the model server. `FAILED` names what went wrong:
`URLError` for a refused connection, an unresolvable name, a blocked route or a
certificate this Pod does not trust; `TimeoutError` for an endpoint that accepts
the connection and does not answer within ten seconds.

The last line is the route step 9 dials — `verification.connect_host` and
`connect_port` if you set them, else `public_url`'s own host and port — as one
TCP connection: the first thing the installer tries on this route from the
application's container — after the corpus import, just before it starts the
verifier. `TCP reached` means
the name resolves inside the cluster and the port answers; it says nothing
about the certificate. Under `ingress.profile=managed-traefik` nothing listens
there until the install has made the controller, so a refused connection means
nothing yet; a name that does not resolve, or a timeout, does.

**What this check cannot tell you.** The Pod is not the application's
environment: it carries neither the CA bundle of `trust.ca_file` nor the proxy
settings of `trust.proxy_file`, which the chart gives the web and runner
containers. With either of those in your site file, a `FAILED` here may be a
certificate or a route the application would handle, and a number may be a
direct connection the application — sent through your proxy — would not make.
Without them it proves reachability from the node, and nothing more. Whether
the OCR endpoint can read an image is step 0's probe. A `404` on the first line
is either an endpoint that does not serve `/models` — some enterprise gateways
do not, while still serving chat completions; read `llm.context_window` from
the model's own documentation then — or a `llm.base_url` that is not the OpenAI
root, which the first agent turn will meet.

If they are authenticated, supply the key through `llm.credential.file` /
`ocr.credential.file` (a protected file) or `.secret` (an existing Secret in the
application namespace with a `key` entry) — one or the other, never both. For
an endpoint that needs no authentication, omit the `credential` object
entirely: unknown properties are rejected, so there is no empty or "none"
value to write.

**Why a model that can read an image matters, and what the install does
without one.** OCR is used for one thing — pages of an uploaded PDF that carry
no extractable text, which is most scanned Akten. Step 9's
`scanned-ingest-search` check uploads such a page with recognition *forced* and
requires the recognised sentence to come back searchable. Before it runs, the
verifier probes the endpoint you named with that same page, from inside the
cluster: an endpoint that reads it runs the check, and the check must pass; one
that is absent, gives no answer, refuses, or answers without reading the page
**skips** the check, recorded as `ocr-absent`, `ocr-unreachable`,
`ocr-refused` (with the HTTP status) or `ocr-not-vision-capable`, and the
install completes with *verification PARTIAL* — a completed-install record,
which `upgrade` and the ordinary `backup` require, and a closing line that
says the scanned-page path was not exercised. Until you set a working
endpoint and run `install` again, scanned pages are stored with no text
(`ocr_fallback`) and the agent is told so.

Measured on an earlier build of this release line, with `ocr.url` naming a
text-only model on vLLM, before acceptance learned to skip: checks one to
three passed, `scanned-ingest-search` failed with `failure_code`
`stream-terminal` and `terminal` `error`, the installer ended with *"required
verification was interrupted or failed…"*, and the way out was `repair` after
the Lease had lapsed — 46 minutes with a backup in it. That road still exists
for a check that genuinely fails; an endpoint that merely does not answer no
longer sends you down it. The endpoint's own words, when you need them, are
in the application's log:

```sh
kubectl -n "$(jq -r .target.namespace "$HOME/gsj-operator/site.json")" logs \
  "deploy/$(jq -r .target.release "$HOME/gsj-operator/site.json")-web" -c gsj-web | grep 'OCR'
```

**Do not point `ocr.url` at a text-only endpoint to "have one".** The probe
tells the two apart most of the time — a refusal skips the check as
`ocr-refused` — but what happens to a scanned page in production depends on how
that endpoint answers a request that carries an image, and a lenient gateway can
turn a refusal into a 200 the application stores. We measured it with the application's own OCR
client and ingest code — the first answer against three real text-only servers,
the third against a relay we built:

- a text-only model on **vLLM** or **Ollama** answers HTTP 400, and on
  **llama.cpp** HTTP 500, which the application tries three times before it
  gives up. In the default automatic mode the page then falls back to whatever
  text the PDF itself carried — for a true scan, none — and is stamped
  `ocr_fallback`: honestly marked as not recognised, and not searchable. Where
  recognition is forced instead — the acceptance check, or a re-processing run
  an administrator sets to always use OCR — there is no fallback and that run
  fails on the same error;
- an HTTP 200 that is not a chat completion — an error object, no `choices`, an
  empty or non-JSON body — is treated as a failed call and degrades the same
  honest way. (Read from the application's code; no server we measured answers
  like this);
- an HTTP 200 **with a chat completion** is the dangerous one. Whatever is in
  `choices[0].message.content` is stored as that page's text and stamped `ocr`,
  exactly as a genuine recognition would be — and an empty or `null` content is
  stored as an *empty* page, still stamped `ocr`. Measured with a relay we built
  to drop the image part and forward the prompt to a text-only model, as a
  lenient gateway might (we have not observed a deployed gateway do it): the
  OCR client returned 1,545 characters of essay about text recognition, and the
  two ingest runs stored 1,732 and 1,828 — a new essay each time — as the page,
  stamped `ocr`, in automatic mode and in forced mode alike. Nothing downstream
  can tell the difference.

Step 0's probe prints `DANGEROUS` for exactly that third answer. The acceptance
check refuses it too — the sentence it requires is not in an invented
transcription — so an install never certifies such an endpoint. Nothing
re-checks it while the deployment runs: an endpoint that changes behind the
same URL is noticed only when an operation runs the acceptance checks again.
Two differences remain between step 0's probe and the application: the probe
posts about 1 KB of request, the application a JPEG of the rendered page — about
170 KB of request for the acceptance check's page — so an endpoint or gateway
that refuses one format, or caps request bodies in between, would not show it
there. Digital PDFs are unaffected
either way. `inspect` cannot tell you whether the endpoint you gave can read an
image; after step 0, nothing asks again until a scanned page is processed.

**`llm.allowed_origins`** is the one remaining field in the example site JSON.
It lists origins the browser is permitted to contact directly for model traffic;
leaving it `[]` is correct and is what almost every site wants, because the
application proxies model calls itself. Set it only if you have been told to.

### Two site values that are about YOUR machine, not GSJ's

**`public_url` must be a hostname no other release on the cluster serves.**
Nothing enforces it and the failure is not obvious: two deployments behind one
hostname serve each other's certificate, and each one's acceptance verifier is
pinned to its own CA, so the second install fails its public-HTTPS check with a
trust error while its data is perfectly fine. `inspect`'s
`networking.ingress.hosts_in_use` lists what is already taken — check it before
you choose.

**`storage.transfer_path` should not sit on the same filesystem as the claims.**
It is the hostPath every maintenance Pod stages through, and a backup stages
its archive through it twice, budgeted at about 2.5× your data. The capacity check sums every role
that shares a filesystem and refuses the total, so pointing `transfer_path` at
the disk the PVCs already live on can turn a working install into a refusal —
and, on a host where the claims live on a big data disk and the root filesystem
is small, pointing it at the root is worse. Put it on the roomiest filesystem
that is not the claims', or leave it empty to stage in an `emptyDir` — which is
still the node's own ephemeral filesystem, not nowhere.

**If the node has one big disk and a small root**, the rule above cannot be
satisfied, and the right way to break it is towards the big disk: give
`transfer_path` a directory of its own **on the claims' filesystem**. Nothing
refuses that arrangement as such — the capacity check simply counts the claims
and the staging area against the same free space, so what you need is room for
both. Size it for a backup, which is the demanding case: the check charges that
filesystem the larger of the claims' floor (`storage.minimum_free_bytes`, 20 GiB
by default) and about a fifth of your data, **plus** twice an archive budget
that assumes no compression. It is how this
guide's own test deployment runs (claims and `transfer_path` both on a 17 TB
data disk; install, vector staging and a full backup all passed), and its
backup demanded 46.1 GiB free there for 10.4 GiB of data. The arrangement to avoid is the other one: staging a
data-sized archive through a small root filesystem that other applications
share. `inspect`'s `storage.claim_backing` and
`host.filesystems` are the two fields that answer this.

Private inputs must be regular files with mode `0600` or `0400`; directories
containing credentials/state should be `0700`. Paths in the site file resolve
relative to that file, inside the environment executing the installer. Existing
Kubernetes Secret references name Secrets in the application namespace. For
private images there are two arrangements, and `registry.config_file` picks
between them. Set it — a protected Docker authentication JSON — together with
`registry.pull_secret`, and the installer **creates** that Secret from the file,
before Helm applies anything and before its own pull proof under
`registry.base`; pre-create nothing. (If a Secret of that
name already exists, its content must equal your file, or the run is refused
rather than the Secret overwritten.) Leave `config_file` empty, and
`registry.pull_secret` instead **selects** a Docker registry Secret you made
yourself: the installer checks that it exists, before its first write, and
never creates it. `restore` and `restore-repair` skip that check: the source's
pull Secret travels in the archive, and restore recreates it. A host Docker
credential helper is not a node pull Secret.

Initialization imports the complete raw corpus delivered by the sixth image
and uses the packaged model. It does not seed from a prior live database.
The default initialization deadline is **86,400 seconds (24 hours)**; the
schema admits up to 172,800.

**How long it takes, by regime.** These are engineering measurements, not
qualification results, and the two regimes differ — so read the row that matches
your site:

| regime | corpus | host | measured |
|---|---|---|---|
| **imports released vectors** (`corpus.vectors_url`/`vectors_path` set — what "Where the corpus artifact comes from" below tells every site to do) | 33,979 decisions / 1,141,170 vectors | 192 cores, otherwise idle | **2.0 h** |
| the same | the same | 32 cores, shared with a live neighbour | **2.8 h** |
| **embeds its own** (both sources left empty) | the same | 192 cores | **3.1 h** |

None of those rows will be your cluster. Use the rate rather than the total:
the imported regime moved **roughly 140-160 vectors per second** on both boxes
regardless of core count, because the work is dominated by Chroma's inserts and
the initializer's own 2-CPU request, not by the node's size. So estimate
`corpus.chunks / 150` seconds — about **2.1 hours for the 1,141,170 vectors this
release ships** — and set `deadlines.initialization_seconds` to at least twice
that. The 24-hour default is ample for this corpus on any cluster that meets
the storage-node requirements in "Before you start"; raise it only for a much
larger corpus or storage you know to be slow; a much larger corpus, far fewer or contended cores, a
lower `resources.initializer.requests.cpu` or slower storage all eat into that.
Raising the deadline does not extend an initialization already in progress; that
takes the named repair described below. Other defaults are 900 seconds for
dependencies and 1,800 seconds for verification.

**What initialization costs in memory, and why the installer checks it first.**
The initializer holds **one shard at a time**, so its memory need is a property
of the release's corpus, not of your site. Each release declares its own
requirement, computed at build time from the largest shard in its corpus
manifest, and the installer compares that against
`resources.initializer.limits.memory` **in its preflight** — before the Lease,
before the first cluster write. A site that gives the container less is refused
in seconds, naming the number to set:

```
GSJ: the corpus initializer needs 4619Mi for this release's corpus (263992 chunks
in its largest shard at 768 dimensions), but resources.initializer.limits.memory
is 2Gi. Raise it in your site file.
```

You can read what a release asks for before you install it:

```sh
INSTALLER=$(jq -r .installer.name installer-descriptor.json)   # NOT "gsj-install.sh"
marker=$(awk '/^__GSJ_PAYLOAD_BELOW__$/ {print NR+1; exit}' "$INSTALLER")
tail -n "+$marker" "$INSTALLER" | base64 --decode | tar -xzO release.json \
  | jq '.corpus'
```

That prints `fingerprint` and `manifest_sha256` alongside the memory figures.
**Check the `fingerprint` against the trailing segment of the corpus tag you are
about to configure** — the `f93c956f` in
`corpus-1.snowflake-m-v2-int8-768.f93c956f` is the first eight characters of
that fingerprint, and a mismatch is fatal, discovered only after the download
and the import. The same payload also carries `site.schema.json`, which is the
complete field reference for the site file and the "configuration schema" the
wizard's prompts refer to:

```sh
tail -n "+$marker" "$INSTALLER" | base64 --decode | tar -xzO site.schema.json | jq .
```

The shipped default is `limits.memory: 6Gi` with `requests: {cpu: 2, memory:
4Gi}`, which carries about **1.3x** the requirement of the corpus this release
ships. The requirement itself was set from a full install: importing all
1,141,170 vectors under these defaults, the container peaked at 2,166 MiB
working set and 3,864 MiB including page cache, and the declared figure sits
about 20% above the higher of the two. You should not need to change it.

The check exists because the failure it replaces was expensive and misleading: an initializer that runs out of memory is
OOMKilled partway through a shard, and after the retry budget is spent the
operator is shown `terminal-budget-exhausted` — a message about a RETRY BUDGET,
with the word `OOMKilled` reachable only through
`kubectl get pod -o json | jq '.status.initContainerStatuses[].lastState'`.

The other containers' defaults, for planning: `web` 4Gi limit / 2Gi request,
`chroma` 6Gi / 4Gi, `mcp` 2Gi / 1Gi, `runner` 2Gi / 512Mi, `forgejo` 1Gi /
256Mi. All are `resources.<role>` in the site file. Note the difference between
the two questions: **limits** are per-container ceilings and the initializer's
does not overlap in time with the application's, because it runs while they
wait; **requests** are scheduling reservations, and those are summed as
described in "Before you start" — `max(largest init container, sum of
containers)` per Pod. Plan the node from the requests, size the limits from
this section.

The installer prints its persistent state directory and operation ID. Preserve
that directory, the site file and credential files. Progress, inspection,
verification and recovery records live there. An initialized Pod or reachable
login page is not the final acceptance result; success requires the installer
to finish its application checks and owned test-data cleanup. On success it
prints a summary and saves it as `summary.json` in that directory: the public
URL, operator login, effective settings with protected input paths redacted,
the release version and identity, the chart, core, model and corpus
fingerprints, corpus rows and vectors, the verification results, and the paths
of the full installed record and verification report. Acceptance stages the
operator password only on the application container's temporary filesystem,
never on a persistent volume. A failed check in the verification report names a
fixed `failure_code`. A turn that ended with a terminal other than `ok` also
names that `terminal` (`busy`: the turn waited past its bound for the shared
agent and never started).

## Select infrastructure and trust profiles

| Setting | Choice and required input |
|---|---|
| `storage.profile=reuse` | A qualified existing local-path or static-local StorageClass, selected Node, and optional existing claim names. Current installer admission permits `rancher.io/local-path`, `rancher.io/gsj-local-path`, and `kubernetes.io/no-provisioner`; other drivers need qualification. |
| `storage.profile=managed-local-path` | Create the pinned provisioner and a `Retain`, `WaitForFirstConsumer` class at the explicit Node/backend path. Here **`storage.class` is not a class you pick from `inspect`'s list — it is the name of the class the installer creates**, so give it a name no existing StorageClass uses; `storage.node` and `storage.backend_path` say where that new class writes. An existing class of that name that this site does not already own is refused (*managed dependency differs or has another owner*) — including one an earlier GSJ install created for a different namespace or release name, because ownership is a hash of the namespace's UID and the release name; re-running this same site converges on the class it created. To keep using a class some other install made, name it under `storage.profile=reuse` instead: its provisioner, `rancher.io/gsj-local-path`, is admitted there, and that class's own node path map — not `storage.backend_path`, which `reuse` does not read — goes on deciding where it writes. Use `reuse` for an existing shared controller. |
| `ingress.profile=reuse` | Supply the existing class and controller namespace. Its networking and TLS must support the configured public URL and the installer checks — see "What a reused controller must do" below. |
| `ingress.profile=managed-traefik` | Create the pinned dedicated controller/class. Choose `LoadBalancer` with a working load-balancer implementation, or `NodePort` with explicit reachability. Kubernetes alone does not provide a public address. New installs' entrypoints allow 3,600 seconds to read one request, so an upload at the default 64 MiB cap needs about 19 KB/s, and never time out a streaming response. |
| `tls.profile=existing` | An existing `kubernetes.io/tls` Secret with certificate and key. |
| `tls.profile=files` | Certificate chain and private-key files for the public hostname; the installer creates the selected TLS Secret. |
| `tls.profile=managed-acme` | Pinned cert-manager plus an ACME Issuer/Certificate. Set issuer name/email, real DNS and externally reachable HTTP01 validation through the ingress class. |
| `tls.profile=managed-local-ca` | Generate a persistent private CA and hostname certificate for practice environments. The installer saves the CA path in the site file before an operation starts, and prints it. Browser trust requires an explicit operator action. |

**What a reused controller must do.** GSJ needs three things from whatever
proxies it, and stock defaults get two of them wrong:

- **accept an upload of `limits.upload_mb`** (64 MiB by default). ingress-nginx
  defaults to `proxy-body-size: 1m`, which rejects almost every real Akte;
- **not time out an agent turn**, which runs to `limits.turn_seconds` (600 s by
  default). ingress-nginx defaults to `proxy-read-timeout: 60`;
- **not buffer the response**, because agent turns are streamed (SSE). Buffering
  holds the whole turn until it ends.

**The chart writes all three nginx annotations onto its own Ingress for every
profile but `managed-traefik`** —
`nginx.ingress.kubernetes.io/proxy-body-size`, `…/proxy-read-timeout` and
`…/proxy-buffering: off`, derived from your `limits.upload_mb` and
`limits.turn_seconds`. It does **not** read your IngressClass's
`spec.controller` to decide; it assumes `k8s.io/ingress-nginx`.

On an ingress-nginx cluster that is exactly right and you need do nothing. You
do not need to touch your shared controller, and you should not: these are
per-Ingress annotations, not controller configuration.

For any other controller — HAProxy, Contour, an appliance, a cloud load balancer
in front of it — those same three annotations are still written, and your
controller ignores them: they are nginx's vocabulary. The site file has no
field for supplying the equivalents in yours. You must configure the three behaviours on that
controller yourself. Acceptance notices a body cap below `limits.upload_mb` and
a proxy that buffers responses, because two of its checks assert exactly those
across your controller. A green install does not show that the timeout is long
enough — step 0 has the measurement — and its symptom is an upload or a turn
that dies at your proxy's limit, after acceptance has passed.

Managed Traefik and cert-manager reserve dedicated namespaces and immutable
owner records tied to the application namespace UID, release, exact chart,
images, values and resource names. Existing unowned Helm releases, controllers,
IngressClasses and CRDs are refused before installation — the application
release included: `install` — and the `resume` of an install that has not
applied yet — refuses a target namespace that already holds a Helm release of
the target name without an installer record, in either of Helm's storage
drivers, naming the release, namespace, revision count, chart and status. The
installer never adopts a release it did not create;
choose another release name or namespace, or manage that release with the
tooling that installed it. Use `reuse` and an existing TLS Secret for shared
infrastructure. Repeating the same owned profile can converge; changing its
identity requires a separately supported migration.
An interrupted Helm `pending-*` revision reports a concrete named recovery command:

The refusal names both the addon and the revision. Take them from it:

```sh
if [ -z "${GSJ_OPERATION_ID:-}" ] || [ -z "${ADDON_REVISION:-}" ]; then
  echo 'set first, then paste this block again -- GSJ_OPERATION_ID=<the operation id the refusal named>; ADDON_REVISION=<the revision the refusal named>' >&2
else
  ./gsj-install.sh addon-repair --operation "$GSJ_OPERATION_ID" \
    --addon certManager --revision "$ADDON_REVISION" --config "$HOME/gsj-operator/site.json" --non-interactive
fi
```

Use the reported addon (`traefik` or `certManager`) and revision after stopping
the previous tools process. Recovery requires the exact saved operation and
unchanged owned chart, values, manifests and hooks. It uses Helm's explicit
rollback to create a new revision, including revision 1 recovery, then verifies
controller/API readiness and preservation of credentials, CRD identities and
history. It does not apply to the application's Helm release or change addon
profiles. The installer does not rewrite Helm's encoded history records.

Managed ACME also reserves an immutable application owner record for its Issuer,
Certificate and account key. The account Secret is created once; a lost key must
be restored rather than registering a replacement account. Backups include that
exact key, TLS Secret and ownership metadata only in the encrypted resource
archive. Empty-target restore validates the source configuration and rebinds
ownership to the new namespace while retaining both private-key values and
certificate bytes. Foreign objects with the same names are refused. Certificate
renewal uses the retained server key (`rotationPolicy: Never`).

Local storage keeps the SQLite and shared volumes on the selected Node. PVC
requests are not enforced local filesystem quotas and do not measure remaining
backend space. The installer performs an actual mounted-volume free-space,
SQLite WAL, cross-process lock and fsync probe. Retention does not provide a
second physical copy; keep backups outside the data disk's failure domain.
The existing cluster also needs an enforcing NetworkPolicy implementation.
Managed Traefik enforces no request-body limit: its buffering middleware
would also hold entire streamed responses (SSE, agent turns) until they end.
The application enforces `limits.upload_mb` itself and answers HTTP 413. New
managed Traefik installs allow 3600 s request reads and unbounded response
writes on both entrypoints. A managed controller installed by a pre-release
engineering build keeps its recorded immutable profile, including Traefik's
60 s read limit: the installer has no Traefik profile migration, so on such a
site keep uploads small enough to finish within 60 seconds, for example with a
lower `limits.upload_mb`.

NetworkPolicy restricts egress for Forgejo only. GSJ (web, agent runner and
MCP), the provisioning Job and Chroma have unrestricted egress. The
installer's deny/allow check proves that one policy pair, not isolation of the
whole stack.

If you must write that namespace's egress rules yourself, this is what the
release is *configured* to reach — read from the chart and your site file, not
from a capture of its traffic. Inside the namespace: the `<release>-forgejo`
Service on 3000, the `<release>-chroma` Service on 8000, and — from Forgejo —
the `<release>-web` Service on 8780, the webhook delivery the chart's own
Forgejo egress policy already permits. Cluster DNS. The
Kubernetes API, from the gsj Pod's start-up check and from the provisioning
Job. The two endpoints your site file names, `llm.base_url` and `ocr.url` — or
the proxy in `trust.proxy_file`, if you set one. And, during acceptance, the
route of `public_url` (`verification.connect_host` and `connect_port` if you
set them), because the verifier runs inside the application's container and
dials the public route from there. Forgejo and Chroma are stock third-party
images: what they attempt on their own account beyond this, we have not
enumerated.

Trust inputs serve different consumers:

| Input | Consumer |
|---|---|
| Independently trusted release public key | Verifies the installer's signature. It is not a TLS CA. |
| `delivery.ca_file` / `delivery.auth_header_file` | HTTPS release downloads after site loading; authorization is limited to the embedded release origin and cannot follow redirects. |
| `trust.ca_file` / `trust.proxy_file` | Application Python, Node and git clients. Proxy JSON contains exactly `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` string entries; the proxy URLs carry no credentials (`user:password@` is refused, with or without a scheme — the agent runtime strips it from the model client's environment, so an authenticating proxy cannot reach the model endpoint). Internal service bypass entries are added. A `<release>-proxy` Secret that already carries credentials (a site installed by an earlier 0.10.0-beta build) must be deleted by hand before an upgrade or restore with a credential-free file: the installer never rotates that Secret itself. |
| `verification.ca_file` | HTTPS checks for the configured public application URL. |
| `backup.ca_file` / `backup.auth_header_file` | Independent off-box backup endpoint, supporting PUT and immediate GET/read-back. |
| Node/container-runtime registry trust | Image pulls. Configure this on the existing infrastructure; an imagePullSecret supplies authentication and does not install a CA. |

Initial client bootstrap happens before the site file is loaded. A corporate
proxy or custom CA needed for that first download must already be available to
curl in the tools environment; `delivery.ca_file` cannot repair an earlier
bootstrap failure.

Keep the user-facing hostname separate from the connection
address. `verification.connect_host` and `verification.connect_port` choose only
the TCP destination: `public_url` still supplies the URL, Host and TLS SNI, and
TLS still verifies against `verification.ca_file` (the system trust store when
it is empty). The route is dialled from two places and must work from both:
the installer's public HTTPS check in the tools environment, and the acceptance
verifier in the application Pod. Set `verification.connect_host` to a node
hostname both reach and `verification.connect_port`
to the ingress NodePort.
`host.docker.internal` and host-published ports such as `8443` usually resolve
only inside Docker Desktop containers, not from Pods.

A site that sets `verification.connect_host` must also set
`verification.connect_port` (1-65535); the installer refuses the site
otherwise. An operation retained with a `connect_host` and no `connect_port`, a
route the acceptance verifier could never use, cannot be continued by this
release's installer, which refuses that saved site. Keep the operation retained
and take its fresh path: restore its verified archive (a restore's archive, or
the backup an upgrade or repair took) with that archive's exact source installer
into another Kubernetes context whose namespace of the same name is empty, or,
for a first install, `install` afresh into an empty namespace.

Before the installer starts or reconnects a verifier for an unfinished run, it
opens one TCP connection from the `gsj-web` container over this route, or to
the `public_url` host and port through Pod DNS when no route is set, and
completes one TLS handshake verified for the `public_url` hostname with that
container's Python and trust settings. This release's application image runs
Python 3.13, whose certificate verification applies strict X.509 rules that the
installer's tools-side HTTPS check does not. No request
or credential is sent. When the proxy that `trust.proxy_file` gives the
application carries `public_url` (`HTTPS_PROXY` is set and `NO_PROXY` does not
exempt its host), the verifier reaches the origin through that proxy, where the
route settings do not apply, and this check (and the verifier's own) is
skipped. On failure no verifier starts and no test data is
created; the installer stops with one of these codes, or reports that the check
could not run in the Pod:

| Code | Meaning | Recovery |
|---|---|---|
| `origin-unreachable` | The Pod cannot resolve or connect to the route. | Correct `verification.connect_host`/`verification.connect_port` in the site file, then `resume --operation ID`. |
| `origin-tls-failed` | The Pod connected, but the TLS handshake failed or the certificate did not pass strict verification for the `public_url` hostname. The message names the reason the Pod reported. | `tls-repair --operation ID`, then `resume --operation ID`, when the installer names them (below). Otherwise correct the served certificate or the trust file at its source, or a route that reaches a different endpoint, then `resume --operation ID`. |

The installer names `tls-repair` only with `tls.profile=managed-local-ca`, only
for the reasons it repairs (`CA cert does not include key usage extension`,
`Basic Constraints of CA cert not marked critical`, `Missing Subject Key
Identifier`), and only while the saved CA is not the one an earlier
`tls-repair` produced: a CA that `tls-repair` produced and the Pod still
refuses gets the general recovery instead. `tls-repair` and the `resume` after
it each need the operation Lease unrenewed for 180 seconds, so wait 3 minutes
before each. For any other reason (for example `Missing Authority Key
Identifier` on the server certificate, or `unable to get local issuer
certificate` for the wrong trust file), no installer command replaces the
certificate: correct it in the TLS Secret, or the contents of the file that
`verification.ca_file` names, at their source, keeping the configured paths.
With `tls.profile=files`, also update the configured files: the installer
refuses a TLS Secret that differs from them.

A refused run was never launched, so `resume` continues it without spending
another of the operation's three verification attempts. When a `repair`, a
`repair --to` or a startup continuation re-applies Helm before verification
continues, the installer retires that run without cleanup and starts a fresh
one, which counts as one attempt.

Correcting the route through `resume` applies to an operation whose target is
this release and that no other program continues. A continued operation (a
restore continued by a corrected installer's restore-program transition, or a
first-startup repair continued with `--continue-helm-installer`) keeps its exact
saved configuration, so no command corrects its route and the installer names
none. If the failure was transient, run `resume --operation ID` once the route
is reachable: with the corrected installer for a continued restore, and with
the operation's exact target installer for a continued first-startup repair.
`tls-repair` changes no saved configuration, and neither does a certificate or
trust file corrected at its configured path, so both still apply to a continued
operation's `origin-tls-failed`: run `tls-repair --operation ID` when the
installer names it, or correct the certificate as described above, then that
`resume`, waiting for the Lease as above.
Otherwise keep the operation retained and take the fresh path: for a restore,
restore the same verified archive with the exact source installer into another
Kubernetes context whose namespace of the same name is empty; for a continued
first install, `install` afresh into an empty namespace. A run left under an
earlier `public_url` keeps its own route, which the current site cannot
correct; the installer reports that instead of a correction.

If the route already fails when a run's operator login or its recovery begins,
this release's verifier names the same code: in the report, as the
operator-login check's `failure_code` or as `cleanup_failure_code`; when the
installer resumes a run or cleans up an earlier one, in the verifier's
`verification-failed` progress line. A test through the node port is different
from a test through the host's published port; record which path passed. No
browser or host trust store is modified automatically.

## Upgrade and recover a named operation

Retain the same configuration location, target identities and protected inputs.
Use the **exact version string in the target signed descriptor**, including a
leading `v` only when it is present there. An upgrade requires a completed
installed-release record, a target that declares the exact source identity,
compatible model/configuration and unchanged storage identities. It takes and
verifies a consistent encrypted backup before applying the target.

```sh
if [ -z "${GSJ_TARGET_VERSION:-}" ]; then
  echo 'set first, then paste this block again -- GSJ_TARGET_VERSION=<the exact version string in the target signed descriptor>' >&2
else
  ./gsj-install.sh upgrade --to "$GSJ_TARGET_VERSION" \
    --config "$HOME/gsj-operator/site.json" --non-interactive
fi
```

**[if]** you are moving `registry.base` — a new registry, a new prefix, or the
line deleted — edit the site file and let the next operation that applies it
adopt it: the edited base becomes the *installed* one only when that operation
completes. With a release directory that operation is this upgrade. On a build
that has none, where every `--to` is unavailable, it is `install` run again with
the same installer, which is a reinstall: it proves the nodes can pull from the
new base, takes a source backup, and applies the file as it stands. Run that
way, on an installed deployment whose six images we had copied under a second
prefix: fifteen of fifteen, every Pod on the new prefix. Until such an operation
completes, a standalone `backup` refuses the edited file — we ran that too — so
take that backup before the edit, or after the operation that adopts it.

That uses the site file as it stands. With `--interactive` in place of
`--non-interactive`, the target release runs its own configuration wizard once
its signature has been verified.

The current installer downloads the target descriptor/signature and executable,
verifies them with its existing trust root, and runs that target installer.
Non-interactive `upgrade` requires `--to`; to repeat the installed release,
pass its own version. Interactive mode also permits `upgrade --interactive`
and prompts for the version. Review the saved settings; a wizard does not authorize a credential
reset or storage relocation. A changed corpus requires explicit
`corpus.allow_update=true` and the pre-migration backup. Model replacement is
currently refused until both case and decision indexes have a qualified
migration path.

Sign-in sessions live only in the web process memory. An upgrade, repair,
restore, backup or any Pod restart ends them, and users sign in again. Saved
cases, notes, annotations and conversations persist.

If an operation stops, use the ID printed by that operation. First establish
that the earlier installer/tools process has stopped. The current lease must
have been unrenewed for at least 180 seconds, and the volume lock still fences
initialization. Elapsed time does not authorize a different operation ID.

```sh
if [ -z "${GSJ_OPERATION_ID:-}" ]; then
  echo 'set first, then paste this block again -- GSJ_OPERATION_ID=<the ID the stopped operation printed>' >&2
else
  ./gsj-install.sh resume --operation "$GSJ_OPERATION_ID" \
    --config "$HOME/gsj-operator/site.json" --non-interactive
fi
```

Every recovery command in the rest of this guide reads that same
`$GSJ_OPERATION_ID` — except the two backup-recovery blocks under
[Preserve and restore backups](#preserve-and-restore-backups), which read
`$GSJ_BACKUP_OPERATION_ID`: the ID the stopped backup printed. For a
standalone `backup` that is the backup's own operation, and `resume` with it
only finishes the backup. When the backup that an install or an upgrade takes
first is what stopped, the ID is that operation's, and `resume` with it carries
on through the whole operation — the backup, then the apply and the
verification. A **repair** whose own backup stopped is not resumable: run the
same `repair --operation ID` again. In every one of these cases a stopped
backup that left a partial archive is refused — *"incomplete backup artifacts
exist…"* — until `backup-repair` has opened the next generation: `--generation
1` for the first retry in the current backup round, one more each time after,
and `1` again once a `repair --backup-round` has opened a new round; the refusal
does not print the number. Left unset, a command passes an empty ID, and every verb refuses that
before it changes anything in the cluster.

`resume` requires the original exact target installer and unchanged saved
configuration. It continues supported recorded phases; other phases require
inspection and an explicit repair. Do not delete the lease, progress directory
or PVCs to bypass this check.

One exception: for a `verifying` operation whose target is this release and
that no other program continues, `resume` admits a corrected
`verification.connect_host` and
`verification.connect_port`, and no other change. These two fields select only
the TCP destination, never what is deployed; `public_url`, Host, SNI and
`verification.ca_file` stay pinned. The installer logs the old and new route
and records the new one in the operation's saved site. On any command (install,
upgrade, repair, restore or resume), an earlier acceptance run for the same
`public_url` that still needs cleanup uses the current site's route.

```sh
./gsj-install.sh repair --operation "$GSJ_OPERATION_ID" \
  --config "$HOME/gsj-operator/site.json" --non-interactive

# Only for a reviewed replacement release declaring that failed source:
./gsj-install.sh repair --operation "$GSJ_OPERATION_ID" --to "$GSJ_TARGET_VERSION" \
  --config "$HOME/gsj-operator/site.json" --non-interactive
```

For an install or upgrade operation, repair preserves the operation identity,
stops the previous initializer, increments the corpus repair generation and
reapplies/reverifies the release.

**Repair re-reads the site file you give it, and that is how you fix a bad
setting.** It compiles chart values from `--config` as it stands NOW, so
correcting a value there and re-running repair changes what is deployed — this
is the supported way out of a stop whose cause is a setting rather than a
transient. The worked example is a resource limit: raise
`resources.initializer.limits.memory` and run `repair --operation ID --config
site.json --non-interactive`, and the next attempt runs under the new limit.
Re-running repair with the SAME configuration that already failed simply spends
another attempt budget on the same wall, so read the stop first and change
something. What repair will not do is change the operation's identity, its
target release, its credentials or its storage bindings; those need the fresh
paths described below. A replacement installer is admitted only from
a recorded `verification-pending` source with the declared transition; it cannot
replace an unknown interrupted migration. An installed source is backed up
first. A restore operation has only the repair in
[Restore stopped by a failed application Helm revision](#restore-stopped-by-a-failed-application-helm-revision),
which never takes a backup or changes the corpus repair generation.

**Repair normally writes ONE value into the site file you give it.** When a
repair opens a new corpus generation it sets `corpus.repair_generation` in your
`--config` file — adding a `corpus` block if you had none — and leaves every
other key as you wrote it, in your order. The file is re-serialised, so its
layout becomes the installer's; its content does not change. It does this only
when your file — once the installer has put the new number into it — plus this
release's defaults reproduces, byte for byte, the configuration the repair
recorded as its result; if it ever does not, it writes the
**complete merged** site instead — every default spelled out — and logs that it
did. (Releases before this one always wrote the complete site, and the
interactive wizard still writes a complete file, because it builds the file for
you.) The number is written *before* Helm applies the generation, so a repair
that stops ahead of the apply leaves your file naming a
`corpus.repair_generation` the cluster is not yet running. Continue it with
`resume --operation ID` and that file, which is exactly the saved configuration
`resume` requires.

If you have had to *correct* that file, `resume` refuses it — the one exception
is the verification-route correction described above — and the way on is
`repair` again, which opens a further generation: the number now in your file
is superseded, not deployed. In two states **both** verbs refuse an edited
file: while the transition is still being published (status `repair-prepared`),
and while the repair's own source backup has not yet verified (status
`repair-backing-up`). From the first, `resume` with the file as it was finishes
the generation — the whole apply, initialization and verification under the
configuration the repair recorded, not just its bookkeeping — and your
correction goes in with a further `repair` afterwards. From the second, run the
same `repair --operation ID` again with the file as it was; `resume` does not
continue that state. **Keep a copy of the file you start a repair with until
that operation completes.** Without one, the first state has a fallback:
`site_before` inside the `repair-transition-….json` that `operation.json` names
is accepted in its place — but it is the merged site, so writing it over your
file pins this release's defaults there. The second state keeps only a hash of
the file.

**Never lower `corpus.repair_generation`, and never delete it.** That number is
the installer's counter, not a default: a repair generation is a budget kept
*with the data*, on the data claim, and removing the key returns it to 0. If
generation 0 is the one that ended terminal — the usual reason there was a
repair at all — the initializer refuses the moment it starts, with
`gsj-corpus:terminal-budget-exhausted` or `gsj-corpus:deadline-exceeded`.
Raising the number is the only direction that works. The block's other keys
(`vectors_url`/`vectors_path`/`vectors_sha256`, `allow_update`) are yours.
Everything else in the file is still what you wrote, so a later release's
changed default reaches your site at the next upgrade, exactly as it does for a
site that never ran a repair. One kind of change is refused rather than
adopted: an upgrade compares the whole `target`, `operator` and `storage`
blocks, defaults included, with the installed ones (*"upgrade cannot change
target, operator or storage identity…"*). If a later release changes a default
inside one of them, write the installed value into your file explicitly.

The installer stops waiting as soon as corpus initialization reports a
terminal code, and prints the command to run. For an install or upgrade
operation, `terminal-budget-exhausted`, `deadline-exceeded`,
`checkpoint-identity-mismatch` and `gsj-corpus:source-verification-failed`
need the named repair above, without `--to`.
`gsj-copy:source-verification-failed` means the release's corpus image
itself fails its signed hashes; repairing the same release cannot fix it. Use
`repair --to` with a verified signed release.
Repair increments `corpus.repair_generation`, which gives initialization a
fresh attempt budget and deadline. Shards that already verified are
re-verified without re-embedding; only incomplete shards are imported again.

### Where the corpus artifact comes from

**Released vectors are the only route to consistent retrieval across sites.**
The pinned encoder's INT8 activations are quantized with one dynamic scale per
batch, so the same text embeds to a different vector depending on its
batchmates (cosine 0.94–0.98); a site that embeds the corpus itself gets a
store of the same model and text but different numbers and different
neighbours at the margins, and no re-embed anywhere reproduces another site's
store. Configure `corpus.vectors_url` or `corpus.vectors_path` (with
`corpus.vectors_sha256`) for every site that must search like the release's
reference site; the initializer verifies the sidecar by field and imports its
rows byte for byte, and the provenance stamps prove identity of origin, not
reproducibility. Leaving both unset means "this site embeds its own, different
store", knowingly.

It is published as release assets on
`https://github.com/TUMLegalTech/gsj-decisions-corpus` — a 2.4 KB manifest,
`vectors.json`, and the seven blocks it names, each a separate asset. Point the
site at the MANIFEST; its blocks are fetched as siblings from the same release:

```json
"corpus": {
  "vectors_url": "https://github.com/TUMLegalTech/gsj-decisions-corpus/releases/download/corpus-1.snowflake-m-v2-int8-768.f93c956f/vectors.json",
  "vectors_sha256": "15bf3fb0530af8e2cb3941f0b35bf2454cc3d21bad55a467465f5939a502399c"
}
```

`corpus.vectors_sha256` is the sha256 of the manifest, and the release notes
publish it beside the tag. Every block's digest is inside the manifest, so that
one hash covers the whole 1.5 GiB set. The release tag names the model
generation and the corpus generation — `corpus-1` is the decisions and parser,
`snowflake-m-v2-int8-768` the encoder, and the trailing `f93c956f` the **first
eight characters** of the 64-character corpus fingerprint the initializer checks
against — so a corpus built for a different
model can never be pointed at this one by accident.

The fetch is unauthenticated on purpose: the public corpus is not your release
distribution, and `delivery.auth_header_file`, if you configure one, is never
sent to it. A firewall rule needs **two** names — `github.com`, which the URL
names, and `release-assets.githubusercontent.com`, which it redirects to.
`inspect` probes the first and reports it under `egress`. Budget about **3.5 GB of free space** on the installer host —
roughly 1.5 GiB of blocks under `${XDG_CACHE_HOME:-$HOME/.cache}/gsj-install/vectors`,
which is content-addressed so a named retry re-fetches only what is missing and
which you may delete at any time, plus a same-sized envelope under `TMPDIR`
that is removed as soon as the cluster has the blocks. Where `TMPDIR` and the
cache share a filesystem the installer asks for both at once and names the
shortfall before it starts fetching. That cache is never pruned: after a corpus
update the previous generation's blocks stay until you delete them.

Do not run two installs from the same host at the same time while either is
fetching the corpus. They share that cache, and a half-written block will make
both refuse with a hash mismatch. Re-running either one afterwards recovers;
the client-tool cache has always had the same property, but a 1.5 GiB object
leaves the window open far longer.

**No egress?** Download the eight assets on a machine that has it (about
1.6 GiB land in a fresh private directory that `mktemp -d` makes and the
block prints — what is guaranteed is a private directory of your own, not
where it sits: Linux places it under `TMPDIR`, else `/tmp`; macOS may place it
elsewhere whatever `TMPDIR` says — so read the printed path and make sure
that filesystem has the room), copy them into one
directory on the installer host, `chmod 600 vectors.json`, and name the
manifest with `corpus.vectors_path` instead — the blocks must sit beside it.
The manifest names them, so nothing has to be guessed:

Carry your release's `corpus.fingerprint` to that machine — a 64-character
sha256, of which the tag uses the **first eight**; read it with
`payload release.json | jq -r .corpus.fingerprint` on the installer host — and
build the URL there:

```sh
if [ -z "${FP:-}" ]; then
  echo 'set first, then paste this block again -- FP=<the corpus.fingerprint you carried from the installer host>' >&2
elif ! VECTORS_DIR=$(mktemp -d) || ! cd "$VECTORS_DIR"; then
  echo 'NO DOWNLOAD -- this block needs a writable temporary directory on this machine (mktemp -d failed; on Linux, export TMPDIR=<a writable directory with room> first)' >&2
else
  pwd                                         # a fresh private directory of your own: the eight files land here, to be carried over
  VECTORS_URL="https://github.com/TUMLegalTech/gsj-decisions-corpus/releases/download/corpus-1.snowflake-m-v2-int8-768.${FP:0:8}/vectors.json"
  curl -fsSL "$VECTORS_URL" -o vectors.json
  jq -r '.shards[].archive' vectors.json      # the block filenames it names
  base=${VECTORS_URL%/vectors.json}
  for a in $(jq -r '.shards[].archive' vectors.json); do curl -fsSL "$base/$a" -O; done
fi
```

Finish on that machine before you carry anything: `sha256sum vectors.json` is
your `corpus.vectors_sha256`, and `jq -r .corpus_fingerprint vectors.json` must
equal the whole `$FP`, not only the eight characters the tag used. The hash in
the example below is the sample release's, not yours — and a wrong one is
refused only after Helm has applied, when staging begins (*staged vectors
manifest does not match corpus.vectors_sha256*).

Those two blocks are the *fetch*, and they do run against GitHub — on the
machine that has egress. What `corpus.vectors_path` changes is the **install**:
nothing is downloaded from GitHub, because the manifest and its blocks are
already on disk. (The installer's reachability report still *tries*
`https://github.com/` from the installer host on every run and records that it
could not get there; that probe fetches nothing and its failure stops nothing.)
Same artifact, same digests, same verification.

```json
"corpus": {
  "vectors_path": "/srv/gsj-vectors/vectors.json",
  "vectors_sha256": "15bf3fb0530af8e2cb3941f0b35bf2454cc3d21bad55a467465f5939a502399c"
}
```

Configure exactly one of the two. A source without `corpus.vectors_sha256` is
refused before anything is fetched. A block whose bytes disagree with the
manifest is refused **by name** and nothing is published — an interrupted
transfer resumes, but a completed one that still hashes wrong is a corrupted
mirror or a substituted object and stops the run rather than being retried
quietly.

**A corpus update is a new release, not a rebuild.** Because no site can
re-derive these vectors, refreshing a corpus means a new tag here, a new
manifest, and every site re-importing from it.
`corpus-update-required` means the stored corpus differs from this release:
after a verified backup, set `corpus.allow_update=true` in the saved site and
run the same repair. `model-change-blocked` means the stored index uses another
embedding model: keep the previous release or restore its verified backup.
`manifest-mismatch`, `core-mismatch` and `invalid-settings` are release defects
that need `repair --to` with a corrected signed release. These refusals fail at
once with their own code rather than spending the attempt budget. Other codes
are transient: a Chroma outage is waited out until the persisted deadline, a
competing writer backs off without spending attempts, and `internal-error` is
retried within the attempt budget while the installer keeps waiting.

A bot contract-hook check that fails on every bounded attempt is likewise
terminal: `resume` would only repeat it. The verification ledger and its
owned test data are kept; for an install or upgrade, the named repair, with
`--to` for a corrected signed release, cleans them up before a fresh
verification.

A restore has no repair for a terminal corpus code or a terminal bot check:
`resume` would repeat the failure, and `repair` refuses a restore whose
application Helm revision has completed. Keep the operation retained for
inspection. The installer names a fresh restore into another Kubernetes context
whose namespace of the same name is empty (restore keeps the archive's
namespace and release names):

| Stop | Fresh restore |
|---|---|
| `terminal-budget-exhausted`, `deadline-exceeded`, `checkpoint-identity-mismatch`, `gsj-corpus:source-verification-failed`, `gsj-copy:source-verification-failed`, `manifest-mismatch`, `core-mismatch`, `invalid-settings`, a terminal bot check | The same verified archive with the exact source installer |
| `corpus-update-required` | The same verified archive with the exact source installer, from a recovery site that sets `corpus.allow_update=true`; the verified archive is its pre-update backup |
| `model-change-blocked` | An earlier verified archive of this deployment with that archive's exact source installer: this archive's decision index does not match its source release's embedding model |

Before publishing repair configuration, the installer saves the exact old and
new settings and target identity in an immutable transition record. If it stops
in `repair-prepared`, run `resume` with that transition's target installer and
the saved configuration. It finishes the same generation even if only some
configuration files were published; additional edits are refused until the
transition is resolved.

Two narrower commands exist for diagnosed input defects:

```sh
./gsj-install.sh credential-repair --operation "$GSJ_OPERATION_ID" \
  --config "$HOME/gsj-operator/site.json" --non-interactive
./gsj-install.sh tls-repair --operation "$GSJ_OPERATION_ID" \
  --config "$HOME/gsj-operator/site.json" --non-interactive
```

`credential-repair` validates the actual operator identity/admin role before
normalizing a trailing-newline input and updating its matching Secret. It does
not reset the account password. `tls-repair` is specific to the managed local
CA: it preserves the CA key/subject/serial and server certificate/key while
repairing CA signing extensions, and validates the unchanged leaf strictly.
Each narrow repair renews the operation Lease: wait until it has been
unrenewed for 180 seconds, then run `resume` with the installer that owns the
operation (for a continued restore, the corrected installer).
These commands are not general credential rotation or certificate replacement.

A failed installer retains the operation's Lease. If that Lease nevertheless
exists with an empty holder while the saved operation is still `initializing`
(for example after an interrupted pre-release engineering build released it
while its initializer continued), `resume` and `repair` refuse because the
Lease no longer names the operation. Restore the recorded holder with the exact
original installer, then continue with that same installer:

```sh
./gsj-install.sh lease-repair --operation "$GSJ_OPERATION_ID" \
  --config "$HOME/gsj-operator/site.json" --non-interactive
./gsj-install.sh resume --operation "$GSJ_OPERATION_ID" \
  --config "$HOME/gsj-operator/site.json" --non-interactive
```

`lease-repair` requires preserved operation metadata in the `initializing`
phase for this exact installer release and the selected site's target, an
existing empty Lease unrenewed for at least 180 seconds, matching deployment
ownership and immutable image/corpus identities, and inactive provisioning
Jobs. It restores only the recorded Lease holder using its existing resource
version and renewal time, and records `lease-repair.json` in the tools state;
application data, credentials and controllers are unchanged. Missing,
occupied, fresh or concurrently changed Leases are refused. Use `repair`
instead of `resume` only when the diagnosed initializer state requires that
supported operation.

### Sweep the residue of a dead run

`abandon` releases a LIVE operation's Lease after recording why, and deletes
nothing. A run that was killed and whose namespace or Lease is gone, an attempt
that was refused after it had already prepared its operation, or a release that
was uninstalled leave behind what no other verb reaches: a canonical operation
record every later operation refuses (`another active operation or later phase
owns canonical state`), the installer's own Jobs and their Pods, its record
ConfigMaps, the three token Secrets the provisioning Job mints, a free Lease and
a per-operation transfer directory.

```sh
./gsj-install.sh sweep --config "$HOME/gsj-operator/site.json" --reason "why" --non-interactive
```

sweeps exactly that, for the site's namespace and release, and never a live
deployment or a live operation: it refuses while the Lease has a holder (live:
stop that process; stale: `abandon` it first), while a Helm release of the name
exists in the namespace (uninstall it; its claims are kept), and while any
controller of the release is still present. PersistentVolumeClaims are never
listed or touched; a TLS Secret only when the installer created it
(`managed-local-ca`). Before the first deletion it writes
`swept-<time>-<operation>.json` on the immutable state path — the reason, the
actor, every object with its UID and every directory about to go, and what
stays — then deletes each object by that recorded UID. The canonical record is
retained and marked `swept`, which the admission guard accepts, so the next
`install` into the target proceeds (with `existing_claim` pointing at the kept
claims, the imported corpus is re-verified, not re-imported). Forgejo tokens of
spent verification runs are NOT revoked by a sweep: they live in Forgejo's
database on the retained claim — revoke them through Forgejo's admin API after
the next install, or delete the claim — and the record says so.

**One thing a sweep deliberately does not reset: the corpus attempt budget.**
That budget is persisted with the DATA, in the checkpoint on the data claim, not
with the operation — which is correct, because it is what stops an endless loop
of fresh operations re-attempting the same broken import. The consequence to
plan for: if you sweep and then install again **adopting the kept claims** with
`storage.<role>.existing_claim`, and the previous run had exhausted its budget,
the new operation is refused by the initializer at once with
`terminal-budget-exhausted` — before it attempts anything — because the budget
for that corpus repair generation is already spent. Two ways through, both
supported:

- raise `corpus.repair_generation` by one in the site file before that install;
  it is an ordinary site field, and a higher generation is a fresh budget and a
  fresh deadline; or
- install, let it refuse, and run once the `repair --operation ID` it names —
  repair increments the generation itself and then proceeds.

If instead you delete the claims along with the release, nothing is inherited
and no adjustment is needed. Whichever you choose, fix the cause of the original
exhaustion first: a fresh budget spent on an unchanged fault is three more
attempts at the same wall.

### Corpus initialization reason codes

A failed `corpus-copy` or `corpus-initialize` init container leaves one line,
`gsj-copy:<code>` or `gsj-corpus:<code>`, as its termination message and logs
`{"stage":"initialization-failed","reason":"<code>"}`. Codes never contain
corpus text, paths or credentials. The installer reads them while it waits:

| Code | Meaning | Action |
|---|---|---|
| `terminal-budget-exhausted`, `deadline-exceeded`, `checkpoint-identity-mismatch` | The persisted retry or time budget is spent, or the checkpoint belongs to another corpus identity | Named `repair`; it bumps the corpus repair generation and verified shards re-verify without re-embedding |
| `gsj-corpus:source-verification-failed` | A copied shard no longer matches the signed manifest | Named `repair`; the copier quarantines and recopies damaged copies on the next start |
| `gsj-copy:source-verification-failed` | The release's corpus image payload itself fails its signed hashes | Repair cannot help: re-pull from the trusted registry or select a verified signed release |
| `corpus-update-required` | The stored corpus differs from this release | After a verified backup, set `corpus.allow_update=true`, then run the named repair |
| `model-change-blocked` | The stored index uses another embedding model | Blocked until case and decision index migration exists; keep the previous release or restore its backup |
| `manifest-mismatch`, `core-mismatch`, `invalid-settings` | The release payload or settings contradict its signed manifest or core | Use a corrected signed release |
| `released-vectors-missing` | The site declared a released vector sidecar (`corpus.vectors_url` or `vectors_path`) and none arrived in the source volume within the initializer's wait; it refused rather than embed | Stage the sidecar (the installer's own staging step normally fails first and names why), or clear the declaration, then the named `repair` |
| `chroma-unavailable`, `writer-busy`, `internal-error` | Transient or unclassified | A Chroma outage is waited out until the persisted deadline; a competing writer backs off without spending attempts; other errors retry within the attempt budget |

A restore stopped by one of these terminal codes has no repair: for those codes,
[Upgrade and recover a named operation](#upgrade-and-recover-a-named-operation)
names the fresh restore. The transient codes are retried the same way for
every operation.

A damaged derived shard is renamed to `.quarantine-<shard>-<ns>` beside the
copied corpus under the data volume's `bootstrap/corpora/<manifest sha256>/`
before the copier recopies it from the verified image. These forensic copies
are safe to delete by hand after review.

A persisted initialization deadline cannot be extended in flight; only the
named repair starts a new one.

## Preserve and restore backups

Use the **exact signed installer for the completed installed release** to take
an application backup. Keep the saved site configuration; backup may change its
backup, delivery and verification settings, but cannot change application
settings or operate on an incomplete release. What it compares is the
*effective* configuration — your file merged with this release's defaults —
outside the `backup`, `delivery` and `verification` blocks: re-ordering keys, or
spelling out a default with the value it already had, changes nothing, and a
value that differs is refused, `registry.base` included (adding or deleting that
line counts). The refusal is *"backup cannot change application settings; use
the saved site configuration"*, and it stands until an operation that applies
the file has completed and recorded it as installed: take the backup before the
edit, or after the operation that adopts it. The same holds for the one value
the installer writes itself: after a repair that stopped before completing,
`corpus.repair_generation` in your file is ahead of the installed record, and a
standalone backup is refused until that repair completes.

```sh
./gsj-install.sh backup \
  --config "$HOME/gsj-operator/site.json" --interactive

# Or, with prepared private inputs:
./gsj-install.sh backup \
  --config "$HOME/gsj-operator/site.json" --non-interactive
```

Backup temporarily stops application, runner, Forgejo and Chroma writers,
captures and verifies their encrypted data and recovery resources, then restores
the original controller replica counts and waits for readiness. The source
release, controller identities and storage bindings must still match the saved
maintenance snapshot. Successful backup does not apply a new chart or run
verification workflows that create application data.

If backup or its final restart stops, preserve its printed operation ID, tools
state, configuration, passphrase and any partial archives. Once the earlier
installer has stopped and its Lease has been unrenewed for at least 180 seconds,
continue through the same signed installer:

```sh
if [ -z "${GSJ_BACKUP_OPERATION_ID:-}" ]; then
  echo 'set first, then paste this block again -- GSJ_BACKUP_OPERATION_ID=<the ID the interrupted backup printed>' >&2
else
  ./gsj-install.sh resume --operation "$GSJ_BACKUP_OPERATION_ID" \
    --config "$HOME/gsj-operator/site.json" --non-interactive
fi
```

Named resume of a standalone `backup` follows its recorded phase. It reuses a
verified immutable archive or completes the source restart; it cannot enter
deployment or ordinary verification. (With the ID of an install or upgrade whose
first backup stopped, the same command continues that whole operation.) An incomplete archive without a verified receipt is retained and
refused for automatic overwrite. A restart deadline failure leaves the verified
recovery point intact for named resume. Upgrade and supported repair/reinstall
operations also take a source backup before changing the installation.

For a diagnosed incomplete archive, explicitly select the next backup
generation. This preserves every earlier archive and partial transfer. It
requires the original source/controller/storage/credential baseline and the
same stopped operation; it cannot replace an already verified recovery point.

```sh
if [ -z "${GSJ_BACKUP_OPERATION_ID:-}" ] || [ -z "${NEXT_GENERATION:-}" ]; then
  echo 'set first, then paste this block again -- GSJ_BACKUP_OPERATION_ID=<the operation id the refusal named>; NEXT_GENERATION=<1 for the first retry in this backup round, then one more than the last; a new --backup-round starts again at 1>' >&2
else
  ./gsj-install.sh backup-repair --operation "$GSJ_BACKUP_OPERATION_ID" \
    --generation "$NEXT_GENERATION" --config "$HOME/gsj-operator/site.json" --non-interactive
fi
```

If an old maintenance Pod still contains a partial transfer, repair freezes
its owned processes, encrypts and verifies that transfer outside the Pod, then
deletes only its recorded UID before selecting the new generation. Failed
preservation leaves the Pod and earlier artifacts intact. The command prints
whether to continue with `resume` or the original `repair` transition. A prior
archive does not describe case/history writes made after that archive; a
changed source is refused as a fresh pre-mutation backup.

If the application ran after an earlier verified archive, select a fresh backup
round before the next repair. The installer verifies the current recorded
source against the actual containers and corpus configuration, stops its
writers, and captures a new immutable recovery point. It retains all earlier
rounds and partial transfers. Use the next number reported by the refusal:

```sh
if [ -z "${GSJ_OPERATION_ID:-}" ] || [ -z "${NEXT_ROUND:-}" ]; then
  echo 'set first, then paste this block again -- GSJ_OPERATION_ID=<the operation id the refusal named>; NEXT_ROUND=<the next round number the refusal named>' >&2
else
  ./gsj-install.sh repair --operation "$GSJ_OPERATION_ID" --backup-round "$NEXT_ROUND" \
    --config "$HOME/gsj-operator/site.json" --non-interactive
fi
```

A round captures a new source state. A generation retries an incomplete archive
within that same stopped source state. Neither operation treats an old archive
as proof that later case or conversation changes have been backed up.

The standalone command and its retry safeguards have focused automated tests.
A signed release's notes state whether a complete live backup and populated
restore were qualified for that release.

For each verified backup, preserve at least these three files together:

```text
OPERATION.tar.gz.enc
OPERATION.tar.gz.enc.resources.enc
OPERATION.tar.gz.enc.json
```

Also retain the generated `.sha256` files, any `.offbox.json` receipt, source
site/configuration, original signed installer bundle, and the decryption
passphrase in a separately protected location. The archive holds application
volume data; its separately encrypted resource archive includes the Kubernetes
and private configuration inputs needed for recovery. Keep the whole backup
directory private. Partial backups are preserved and cannot be silently
replaced by a retry.

The installer keeps every backup round, generation, partial transfer and
archive; it never prunes. Pruning old recovery points and copying them to
independent storage are operator tasks. Remove an archive only together with
its `.resources.enc`, `.json`, `.sha256` and any `.offbox.json` files, and only
after a newer verified backup exists.

`storage.transfer_path` is the staging directory every maintenance Pod —
backup, restore, vector staging and the capacity scans — mounts as a hostPath
under `<transfer_path>/<operation>`, so large archives never cross the Pod
boundary unencrypted. The installer checks nothing about the path but its
shape, and the Pods declare the mount `DirectoryOrCreate`, so the node's
kubelet makes the per-operation directory, as root, when it is missing. (We
always made `transfer_path` itself beforehand; a missing one is left to the
same mechanism and is not something we ran.) Those containers run as root, but the installer hands
each per-operation directory back to the user that ran it (`chown -R` inside
the Pod) before deleting the Pod, and again on the failure paths that keep the
Pod for `resume`. So after any completed or abandoned operation the staging
directories belong to you and `rm -rf <transfer_path>/<operation>` needs no
`sudo`; only the application's own volumes stay untouched. Leave
`storage.transfer_path` empty and each Pod stages in an `emptyDir` instead — the
node's own ephemeral filesystem, deleted with the Pod: the archive is on the
node while the operation runs and nothing of it survives afterwards, so there
is no directory to hand back and none to remove. If a handback is refused the installer says so and
names the directory that still needs root.

Set `backup.offbox_url` to a final HTTPS directory endpoint when the operation
should export automatically. It PUTs the three required files, GETs each back
and compares hashes before recording export success. Its optional single-line
Authorization header and CA are independent from release-delivery credentials.
Redirects are refused; a storage service that only accepts browser uploads,
redirects to another origin or lacks immediate read-back is unsuitable.

Copy an existing encrypted backup directory
to an independently retained host destination without entering the data volumes:

`backup.directory` is a path on the **installer host** — the machine running
these commands — not in the cluster and not in a container. Size it for what the
capacity check demands, not for the archive you end up with: the check assumes
no compression, so budget a quarter more than the installer's count of your
data (at least 256 MiB more), plus 512 MiB — and another 512 MiB where the
installer's temporary directory (`TMPDIR`, else `/tmp`) is on the same
filesystem. Step 9 gives the measured figures. The exact demand is in the
capacity report it names: `required_bytes` of the entry of `filesystems` whose
`roles` include `host_backup`. The report's top-level `archive_budget_bytes` is
the archive's share of that demand, before the reserve.
To copy a completed backup somewhere independent, it is an ordinary directory:

```sh
umask 077
mkdir -p "$HOME/gsj-recovery/application"
cp -a "$(jq -r .backup.directory "$HOME/gsj-operator/site.json")/." "$HOME/gsj-recovery/application/"
chmod -R go-rwx "$HOME/gsj-recovery"
```

The host directory is an export staging location. Move it to your independent
backup storage if it shares the same physical disk as Docker. Verify copied
archive/resource hashes against the receipt before relying on the copy — the
`.sha256` files hold a bare hash, not `sha256sum -c` input, so compare with the
receipt directly:

```sh
gsj_sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
if [ -z "${GSJ_BACKUP_COPY:-}" ]; then
  echo 'set first, then paste this block again -- GSJ_BACKUP_COPY=<path to the copied OPERATION.tar.gz.enc>' >&2
elif [ ! -f "$GSJ_BACKUP_COPY" ] || [ ! -f "$GSJ_BACKUP_COPY.resources.enc" ] || [ ! -f "$GSJ_BACKUP_COPY.json" ]; then
  echo 'CANNOT CHECK -- the archive, its .resources.enc or its .json receipt is missing at that path' >&2
elif [ "$(gsj_sha "$GSJ_BACKUP_COPY")" = "$(jq -r .sha256 "$GSJ_BACKUP_COPY.json")" ] &&
     [ "$(gsj_sha "$GSJ_BACKUP_COPY.resources.enc")" = "$(jq -r .resources_sha256 "$GSJ_BACKUP_COPY.json")" ]; then
  echo 'copy verified against its receipt'
else
  echo 'COPY DIFFERS FROM ITS RECEIPT -- do not rely on it' >&2
fi
```

Restore checks the same two hashes itself and refuses a copy that differs. It
also records the archive's absolute path for the life of the operation, so
restore from where the archive will stay, not from a copy you mean to move. Keep
the decryption passphrase separately; it is required before restore can read
the encrypted metadata.

Restore onto a fresh target using the **exact original signed source installer**
— the archive's receipt names it: `jq -r .release_identity` of
`OPERATION.tar.gz.enc.json` must equal `releaseId` in that installer's
`installer-descriptor.json`, or the restore refuses with *"restore must use the
exact source release installer"* before it touches anything. Install a
kubeconfig for the recovery cluster and prepare `recovery-site.json` from the
saved site.

**What may change in it:**

- the Kubernetes context;
- `storage.node`, the StorageClass and the rest of the `storage` block except
  the three claim *names* — but the three `size` values do not size anything:
  restore recreates each claim from the *archived* claim's own request and
  access modes and replaces only the StorageClass. Leave the sizes as the source
  had them, and on a static class make the volumes as large as the **source's**
  claims;
- the `ingress` block — except `ingress.class` when the TLS profile is
  `managed-acme`;
- the **port** of `public_url`, and `registry.base`;
- the `verification`, `deadlines`, `limits` and `resources` blocks;
- `backup` — with one condition: if `backup.offbox_url` differs from the
  source's at all, leave `backup.auth_header_file` empty or put that
  destination's own header at the declared path first; restore refuses to reuse
  the archived one, early, before it touches the cluster;
- `corpus` — but its vectors source is load-bearing on a restore. Staging runs
  *after* the Helm apply, and from then on the only site edit any verb accepts
  is the verification route (`verification.connect_host`/`connect_port`, on
  `resume`, once the operation is verifying): a vectors source cannot be
  corrected. Before
  you start, make sure `vectors_url` is reachable from this machine, or stage
  the manifest and its blocks on local disk and name them in `vectors_path`;
- every file *path* — the same protected input at a different place on this
  host, where restore writes the archived bytes back.

**What may not:** the namespace and release names; the public **hostname**; the
operator login and Secret; every `llm` and `ocr` setting except the two
credential file *paths* (they may move, but whether each is set at all may not:
that decides which Secret the deployment references); the TLS profile and
`tls.secret`; whether the `trust` files are set; and `registry.pull_secret`. A
difference there is refused with *"restore target changes an account,
inference/trust setting or resource reference"*.

The registry *credential* is pinned as well, though `registry.base` is not: the
source's credential travels inside the encrypted resource archive and is written
back at the path the recovery site declares, a file already there with
different bytes is refused, and so is a credential added where the source had
none. A recovery registry that needs a different credential is therefore out of
reach: restore onto the source's registry arrangement — the recovery site's
base is proved by a pull probe before anything is applied — and move registries
afterwards with an upgrade.

**The hostname is pinned, and a recovery cluster usually answers at another
address.** `verification.connect_host` and `verification.connect_port` are the
route: the verifier, on this machine and inside the application Pod, dials that
address while still asking for the pinned hostname, so a restore can verify
before anyone has moved DNS.

Required target application names, claims and Helm history must be empty;
restore creates the namespace, if it is missing, and the three claims itself.
Existing credentials with different bytes are refused. Recovery recreates
protected inputs from the encrypted resource archive at the declared paths; the
backup passphrase must already be available.

**Run once, across two clusters.** A deployment backed up on one cluster —
the 10.4 GiB step 9 measured, and its 6.5 GiB archive — was restored on
another: a different node,
a hand-made `kubernetes.io/no-provisioner` StorageClass, a different ingress
controller and port, and that cluster's own copy of the images under
`registry.base`. Thirty-five minutes to *Complete*, fifteen of fifteen: fifteen
for the archive's transfer, verification and file restore (11.1 GB written),
one to stage the released vectors, thirteen for the corpus initializer to
verify every shard — the corpus is restored as data, never imported again —
and four for acceptance. The restored deployment then took a deliberately
interrupted operation, `credential-repair` against a Secret we had broken,
`tls-repair`, `resume`, and a backup of its own, and finished fifteen of fifteen
again. The restored deployment's case table was empty when we read it after
the run — acceptance had already removed its own verification cases — so the
source had carried no lawyer's case, and this is one run, not a release
qualification, and what it proves about case content is file fidelity only:
the restore helper checks every restored path against the archive's manifest
and refuses any that differ, but no restored case was opened in the
application.
Budget for a restore: `storage.transfer_path` on the recovery node holds the
whole archive while it runs, and that operation's directory is still there
afterwards, yours to remove; the machine you restore from still fetches the
released vectors the recovery site declares — about 1.5 GiB, staged to the
cluster in our run — although no shard was imported from them; and acceptance
needs the pinned LLM and OCR endpoints reachable from the recovery cluster, the
OCR one able to read an image.

```sh
if [ -z "${GSJ_BACKUP_ARCHIVE:-}" ]; then
  echo 'set first, then paste this block again -- GSJ_BACKUP_ARCHIVE=<path to the retained encrypted source archive>' >&2
else
  export KUBECONFIG=/path/to/recovery-kubeconfig
  bash "$HOME/gsj-operator/trust/verify-release.sh" source-gsj-install.sh source-installer-descriptor.json \
    source-installer-descriptor.sig "$HOME/gsj-operator/trust/gsj-release.pem" &&
  bash source-gsj-install.sh restore --archive "$GSJ_BACKUP_ARCHIVE" \
    --config "$HOME/gsj-operator/recovery-site.json" --non-interactive
fi
```

Place the `.resources.enc` and `.json` sidecars beside that archive using the
same basename. The installer verifies the source manifest and transport
checksums, creates new storage bindings, restores data and private inputs,
then runs ordinary application verification. It records `restoration.json`.
An ordinary second `restore` refuses an existing checkpoint. After the earlier
client has stopped and its Lease has been unrenewed for 180 seconds, use the
exact source installer and the saved operation for a partial resource/file
restore:

```sh
bash source-gsj-install.sh restore-repair --operation "$GSJ_OPERATION_ID" \
  --config "$HOME/gsj-operator/recovery-site.json" --non-interactive
```

Named restore repair revalidates the original encrypted archive and recovery
metadata, namespace/PVC/PV UIDs, create intents, credential bytes, and absence
of other writers. An append-only journal and file lock authorize only the
recorded files and partial temporary bytes. Existing foreign or changed data
is refused. Complete file hashes, metadata and binding proofs are durable
before the maintenance Pod is removed by UID. Once application startup has
begun, use `resume --operation` rather than replaying the filesystem restore;
a failed application Helm revision is continued by `repair --operation`
(below).
Saved configuration, private inputs, journal and recovery archives must remain
available throughout recovery. A backup taken with `repair --backup-round`
from a source that never finished verification restores the same way.

A defect in the exact source installer can stop a restore after its files were
verified, before application startup. A newer signed release that lists the
source release in its supported sources can continue that operation:

```sh
bash corrected-gsj-install.sh restore-repair --operation "$GSJ_OPERATION_ID" \
  --source-installer "$HOME/gsj-operator/releases/SOURCE/$INSTALLER" \
  --config $HOME/gsj-operator/recovery-site.json --non-interactive
```

Keep the source release's `installer-descriptor.json` and
`installer-descriptor.sig` beside its `gsj-install.sh`. The corrected
installer verifies them with its own trust key, records a create-only
transition receipt with the restore evidence, and then starts the source
release's own chart, images and configuration. It refuses once an application
Helm attempt exists, while the restore Pod still exists, or when a restored
credential, claim, volume or Helm history identity changed. The
`<release>-trust` CA bundle is compared by identity only: every operation
rewrites it from the tools host's system bundle plus `trust.ca_file` before its
Helm apply. Later reconnects use the same corrected installer and may omit
`--source-installer`. Once the receipt exists, continue the operation only with
that corrected installer, and use its `restore-repair`, not `resume`, until
application startup has begun. Do not run the source installer's
`restore-repair`, `resume` or `repair` for the operation; source installers
from this release onward refuse them.

A populated restore is still a release qualification requirement; these commands
do not claim it has already passed for an unfinished candidate.

### Restore stopped by a failed application Helm revision

A restore can stop after its files are verified and its application Helm
revision has started, for example when the provisioning hook exceeds its
deadline because nodes cannot pull an image. The installer then names
`repair --operation`: `resume` does not continue a failed Helm revision, and
`restore-repair` never replays files once application startup has begun.

Before repair, fix the cause outside the namespace (registry reachability,
mirrors, the node image cache or node capacity), wait until the failed
revision's provisioning Job is no longer active, stop the earlier tools process,
and wait until its Lease has been unrenewed for 180 seconds. Repair never
changes restored credentials, so a pull failure caused by revoked or expired
registry credentials has no installer repair path. Do not interrupt repair
while Helm runs: an interrupted Helm client leaves a pending revision, which
only the fresh restore below recovers.

Use the installer that owns the operation: the corrected installer named by the
restore-program transition receipt, or the exact source installer when no
transition was recorded. Only an owning installer from this release onward has
this repair; do not run an earlier owning installer's `repair` for a restore.
Without such an installer, use the restore into another Kubernetes context
below.

```sh
bash gsj-install.sh repair --operation "$GSJ_OPERATION_ID" \
  --config $HOME/gsj-operator/recovery-site.json --non-interactive
```

Repair writes nothing until it has re-validated the original operation intent,
Lease and configuration; the namespace, archive, file and storage-binding
proofs; the recorded pre-startup capacity pass; the transition receipt against
its preserved evidence; the restored resources (those the transition receipt
lists, when one exists): credentials and the provisioning marker by identity
and bytes, claims and volumes by identity and binding; Helm history, which may
hold only the restored history and this operation's own attempts; the failed
revision against the signed chart and configuration; that only the release's
own controllers and provisioning Job mount the restored claims; and that the
GSJ application and its corpus initializers never started (only `wait-deps` may
have run). It then renews the Lease under the same operation identity and
validates again. It accepts three earlier changes: the failed revision's
Forgejo, Chroma and provisioning Job may have run on the restored claims (the
Job's bootstrap runs the Forgejo CLI against the Forgejo claim); Helm may have
pruned the oldest restored history revisions, but not the last deployed one;
and the `<release>-trust` bundle and the chart-owned `<release>-scripts`
ConfigMap are compared by identity only. The capacity pass it relies on was
measured before startup; acceptance is the check after startup.

Repair applies the same signed chart and configuration as the next Helm
revision. Only the deployment generation changes; it requires a fresh
provisioning Job before the GSJ application initializes, and Helm's hook policy
replaces the failed Job. Ordinary startup and acceptance follow. If the tools
process stops after the new revision deployed, use `resume --operation` with the
same installer; if the new revision fails, fix its cause and run repair again.

| Refusal | Next step |
|---|---|
| The prior installer is still live | Stop that tools process, wait until its Lease has been unrenewed for 180 seconds, then rerun repair |
| The provisioning Job is still active | Wait until it completes or fails, then rerun repair |
| An image pull is failing | Fix it, let the kubelet retry, then rerun repair |
| The restore evidence or the renewed Lease could not be read | Once the Kubernetes API answers and the Lease has been unrenewed for 180 seconds, rerun repair |
| The revision already completed, or the restore is complete | `resume --operation` with the installer that owns the operation |
| The restore has not started its application | `restore-repair --operation` |
| The configuration differs from the operation's saved configuration | Rerun with the exact site configuration the operation saved |
| An installer other than the owner (another target release, or not the recorded restore program) | Rerun with the installer that owns the operation |
| A corrected installer with no recorded transition | `repair --operation` with the exact source installer |
| A restored claim receipt, checkpoint entry or other local evidence is missing or unreadable | The restore into another Kubernetes context below; rerunning cannot restore it |
| `--backup-round` or `--continue-helm-installer` was given | Rerun without that option |
| The restore stopped in another phase | Inspect the saved state; repair does not continue it |

A refusal whose message names a restore of the verified archive in another
Kubernetes context means repair cannot re-prove this operation's recorded
state: a changed credential, claim, volume or provisioning marker; Helm history
outside the restored history and this operation's attempts; a failed revision
that is not the signed chart and configuration; a GSJ application or corpus
initializer container that already ran; missing or unreadable local evidence;
no recorded Helm target or pre-startup capacity pass; or a pending revision,
which an interrupted Helm client leaves and which has no continuation. Keep the operation retained and never delete it or its
namespace. Restore the same verified archive into another Kubernetes context
whose namespace of the same name is empty (restore keeps the archive's
namespace and release names):

```sh
bash source-gsj-install.sh restore --archive "$GSJ_BACKUP_ARCHIVE" \
  --config "$HOME/gsj-operator/recovery-site-other-context.json" --non-interactive
```

The repair command itself never uninstalls or rolls back Helm; recreates claims,
volumes, Secrets or the namespace; takes a backup; changes
`corpus.repair_generation` or other settings; or rotates or overwrites
credentials. Repairing a failed restore revision is a release qualification
requirement; this section does not claim it has passed for an unfinished
candidate.

## Codes: what the installer exits with, and what it records

Four families, and they turn up in four different places. None of them carries
corpus text, a path, a credential or a provider's error string — every code is
from a fixed list, so quote it verbatim when you report it.

### 1. How the installer itself ends

| exit | what happened | what to do |
|---|---|---|
| `0` | the verb finished | — |
| `1` | a **named refusal**: one line starting `GSJ: `, on stderr | read that line. If an operation was under way the very next line is `Operation ID incomplete; retained state at DIR. Use …` — and the verb it names is the one to run. It is not always `resume` |
| `129`, `130`, `143` | the installer was sent HUP, INT (Ctrl-C) or TERM | nothing is lost: the state directory and the operation's Lease are retained. Wait 180 s for the Lease to go stale, then run the `resume --operation ID` the closing line names |
| anything else | a child's status passed through unchanged | read the last lines of the log; section 2 lists the ones with a meaning |

`verify-release.sh` is separate and has two: `2` is a usage error (it takes
exactly four arguments), `1` is a release that **failed verification** — do not
run that installer.

### 2. `command terminated with exit code N` inside the log

These are not the installer's own status. They are `kubectl exec` reporting how
a helper **inside the application Pod** ended, and the installer reads each one
and acts on it. They matter because they are what is on screen when a run stops.

| code | who | meaning | what the installer does next |
|---|---|---|---|
| `73` | route preflight | the `gsj-web` container could not open a TCP connection to `public_url` over its own route | refuses, naming `verification.connect_host` / `connect_port` and `resume` |
| `74` | route preflight | TCP worked; the TLS handshake or strict certificate verification did not | refuses, naming `tls-repair` when the managed local CA can be reissued, otherwise the certificate or `verification.ca_file` at its source |
| `75` | verifier | checks ran; the verifier's own test accounts and cases still need cleaning | runs the account cleanup, then re-reads the result. Not a failure by itself |
| `76` | verifier | every web-side check passed; the `bot-contract-hook` check is handed to the runner | runs that step and re-enters. Not a failure |
| `77` | verifier | the run's test data is provably cleaned, but acceptance did **not** pass | refuses: *"required verification was interrupted or failed; owned resources are clean"*. Read the failed check (below), fix its cause, then the verb the closing line names |
| `78` | verifier / helpers | busy: another verifier, restore or source-proof holds the lock | refuses without using a stale handoff; wait, then `resume` |
| `79` | verifier | `bot-contract-hook` failed on every bounded attempt | terminal for this release: the closing line names `repair`, not `resume` |
| `80` | account cleanup | the three durable cleanup attempts of this verification round are spent | names `repair --operation ID`, which opens a fresh bounded round; `resume` would only repeat the spent one |

### 3. `failure_code`: why an acceptance check failed

A failed check records one code from a list of twenty-nine, plus up to three
companions that turn the code into a diagnosis. On a failed run there is no
`summary.json`; the report is `verification.json` in the state directory the
closing line printed:

```sh
if [ -z "${REPORT:-}" ]; then
  echo 'set first, then paste this block again -- REPORT=<the state directory the closing line printed, plus /verification.json>' >&2
else
  jq -r '.checks[] | select(.status != "passed")
         | [.name, .failure_code, (.terminal // "-"), (.http_status // "-" | tostring), (.error_type // "-")] | @tsv' "$REPORT"
fi
```

Measured, on an install whose model endpoint had stopped listening:
`agent-turn-note-history  stream-terminal  error  -  VerificationFailure`.

**Companions.** `terminal` accompanies `stream-terminal` only and is one of
`ok`, `hold`, `rejected`, `timeout`, `error`, `busy`, `unknown`. `http_status`
accompanies `http-status` (the status observed) and `pipeline-head-timeout`
(always 404). `error_type` is the exception's class name and is the whole signal
for `unexpected-error`. A run-level `cleanup_failure_code` means the *cleanup*
failed rather than a check: acceptance may be fine, but the verifier's test data
is not provably gone.

| code | the check saw | usual cause, and what to do |
|---|---|---|
| `assertion-failed` | an invariant inside the check was false | the code deliberately says no more. Read the check's `name`, then the `gsj-web` and `agent-runner` logs for that minute |
| `unexpected-error` | an exception the verifier did not classify | read `error_type`: `ConnectError`/`ConnectTimeout`/`ReadTimeout` are transport — fix reachability and `resume`; `RunBusy` is contention — just `resume` |
| `http-status` | a request answered outside what the check allows | read `http_status`: `401`/`403` on `operator-login` is the operator credential; `502`/`504` is the ingress or a proxy timing out; `413` on `upload-limit-and-pdf-delivery` is a body limit in front of the application |
| `stream-shape` | a streamed frame was not a JSON object | something between the Pod and the client is rewriting the event stream — a proxy that buffers or re-chunks SSE |
| `stream-final-count` | the stream carried no result frame, or more than one | almost always a stream cut short: a proxy read-timeout, a killed worker, a dropped connection |
| `stream-terminal` | a stream the check was following ended in something other than `ok`. Four checks follow one. On `agent-turn-note-history` it is the agent's turn. On `digital-ingest-search`, `scanned-ingest-search` and `upload-limit-and-pdf-delivery` it is the creation of a case — ingest, then the repository, its first push and the embedding — where the only other ending is `error`, and that frame carries no cause by design | for a case creation the cause is in the application's log and nowhere else: read `kubectl -n NAMESPACE logs deploy/RELEASE-web -c gsj-web` for that minute before you change anything. On `scanned-ingest-search` recognition is *forced*, so an `ocr.url` that cannot read an image is the usual cause, and the log then carries the OCR client's own words — [The five values only you can supply](#the-five-values-only-you-can-supply) has the measured case and the way out. For a turn, branch on `terminal`. `error`: the model endpoint failed — check `llm.base_url`, `llm.model`, the credential and whether the endpoint is still listening. `timeout`: the model is slower than `limits.turn_seconds`. `busy`: contention, `resume`. `hold`/`rejected`: the verification case's checkout or the pre-receive hook refused; read the runner log |
| `stream-error-frame` | the turn ended `ok` but carried an error frame | a partial failure inside a nominally successful turn; it repeats on `resume`, so find the failing sub-step in the runner log first |
| `agent-note-unpublished` | the turn ended `ok` but nothing was pushed | the agent bot's push path: its Forgejo account, its token, the hook |
| `agent-note-readback` | the push happened but the note does not hold the exact line asked for | the model paraphrased instead of following a literal instruction — a model too small or too truncated; check `llm.model`, `llm.flags`, `llm.context_window`, `llm.output_tokens` |
| `agent-history-missing` | the turn completed and left no conversation history | the data volume: read-only, full, or a writer that crashed after the turn |
| `agent-output-missing` | the history has no non-empty agent turn | the model returned nothing: an endpoint giving empty completions, refusing the key, or an output-token limit of zero |
| `agent-mcp-evidence-missing` | the turn published, but the MCP log does not show `search_case`, `search_decisions` and `schema_find` succeeding under the bot's identity | the model did not call its tools (a weak or mis-flagged model), or the MCP calls failed — check the `gsj-mcp` container |
| `origin-door`, `origin-agent-author`, `origin-pusher` | a commit's provenance stamp, author or pushing account is not the expected one | a defect in the deployed release, not in your configuration. Report it with the code; do not retry past it |
| `origin-push-missing` | the commit is at origin but Forgejo recorded no push event within 20 s | Forgejo under load; check its health, then `resume` |
| `document-busy`, `document-not-accepted` | the verifier's own case was already busy, or the queue treated the request as a duplicate | residue of an earlier verification round; `repair` opens a clean one |
| `document-attempt-changed` | the attempt being watched was replaced mid-observation | a `gsj-web` or `agent-runner` Pod restarted during the check — correlate with Pod restart events |
| `document-status-invalid` | the document-status payload had the wrong shape | a release defect; report it with the code |
| `document-failed`, `document-invalid` | the draft failed, or was saved but is not a document (shorter than the library's 800-character floor, or a confirmation instead of a draft) | the model again: the endpoint failed mid-draft, or the model is too weak for the task. The runner log for that attempt holds the cause |
| `document-timeout` | the draft never settled within `deadlines.verification_seconds` | decide slow or stuck from the runner log; raise that deadline with `repair` if the model is merely slow |
| `pipeline-head-timeout`, `pipeline-head-invalid` | the verification case's repository never got its first commit, or Forgejo described the branch unusably | Forgejo's write path: its health, the claim's free space |
| `pipeline-index-timeout` | origin HEAD, the index's recorded commit and "embedded ok" never lined up | Chroma or the embedder: the `chroma` Pod, and whether the embed model loaded |
| `bot-check-exhausted` | the bot's forbidden push was not refused by the hook in any bounded attempt | terminal; this is exit `79` above |
| `origin-unreachable`, `origin-tls-failed` | the Pod could not reach, or could not verify, `public_url` | the same two conditions as exits `73` and `74`, met during the run rather than before it; same remedies |

`pipeline-index-freshness` records no code of its own: it names evidence the
ingest checks already measured, so an index problem shows up on
`digital-ingest-search` or `scanned-ingest-search`.

A **skipped** check records no code either: its entry is `{"name", "status":
"skipped", "reason"}` with one of six reasons — `llm-absent`,
`llm-unreachable`, `ocr-absent`, `ocr-unreachable`, `ocr-refused`,
`ocr-not-vision-capable` — the state the acceptance probe found the endpoint
in (the run's `endpoints` field repeats it; `ocr_http_status` accompanies
`ocr-refused`). Only `scanned-ingest-search` (OCR), `agent-turn-note-history`
and `generated-document` (LLM) can be skipped, and only for those reasons; a
run with any skipped check is `coverage: partial` and its closing line says
so (step 9). Two edges of the probe, so a partial verification is read
right: `llm-unreachable` is the Verbindungstest's verdict — the runner asked
the endpoint's `/models` route and got no usable answer — so a gateway that
serves chat completions but not `/models` is skipped as unreachable rather
than exercised (name an endpoint that serves both, or test the agent by hand
after the install); and `ocr-not-vision-capable` means the recognised text
did not contain the test page's sentence, which a model that reads the page
but paraphrases it also earns — the check would have failed on the same
sentence. A probe that could not run at all (the relay route failing, the
renderer missing) fails the run under the name `endpoint-probe` with an
ordinary `failure_code`; it is never read as an endpoint state.

### 4. `gsj-corpus:<code>` and `gsj-copy:<code>`

The thirteen corpus initialization reason codes are listed, with their recovery,
under [Corpus initialization reason codes](#corpus-initialization-reason-codes).

### 5. Refusals that name their own next step

A refusal has no code; its first words are the handle. These are the ones a
first install, or its recovery, realistically meets:

| the refusal begins | it means | next |
|---|---|---|
| `an existing Helm release has no installer record` | that release name and namespace hold a deployment this installer did not create | choose another `target.namespace` or `target.release`. The installer never adopts a release |
| `another active operation or later phase owns canonical state` | an earlier operation on this target never finished and was never released | `abandon --operation ID --reason "…"`, then `sweep`; then start again |
| `… is still live` — worded *the prior installer*, *the previous installer* or *the prior installer lease*, depending on the verb | the operation's Lease was renewed less than 180 s ago | make sure no installer process is still running against this target, wait out the 180 s, and run the same command again. With nothing running it is a clock, not a fault |
| `resume configuration changed; use an explicit repair` | the site file differs from the one the operation was started with | `repair --operation ID --config …` — `repair` re-reads the file, `resume` never does. A `resume` refused for this reason has already renewed the Lease — it does so before it compares the file, and a failed run keeps its Lease. Measured: more than four minutes after the installer had exited, such a `resume` was refused, and a `repair` run straight after it was refused, nine seconds later, as *still live* with nothing running. Wait the 180 s again, from that refusal |
| `target release does not declare this source-to-target transition` | this executable is a different release from the one that installed, or started the operation on, this target | use the executable that did; or `abandon`, `helm uninstall` (claims are kept), `sweep`, and install afresh onto the kept claims with `storage.*.existing_claim` |
| `no node has room for this deployment` | the scheduler's arithmetic over what other Pods have *reserved* | free requests on a node or name another in `storage.node`; this is not about free memory |
| `the corpus initializer needs …Mi` | `resources.initializer.limits.memory` is below what this release's corpus needs | raise it in the site file to at least the figure named |
| `backup cannot change application settings` | the site file differs from the installed one outside its `backup`, `delivery` and `verification` blocks — an edited `registry.base` counts | put the installed values back, or run the operation that adopts the edit — an upgrade, or `install` again with the same installer — then back up |
| `temporary storage backend cleanup incomplete` | the storage check's temporary claim bound a volume and marked it `Delete`, and 120 s after that claim was deleted the volume was still there. The message names the volume and its phase, and the phase is the whole difference | *…and it is now Failed*: nothing on this cluster deletes a volume of that class. Name your own claim in `storage.data.existing_claim`; wait until the operation's Lease has gone 180 s unrenewed, `abandon --operation ID --reason "…"`, install again. The volume it names accepts no claim until that PersistentVolume object is deleted and created again — do that only if you still want it. *…was still present (phase …)*, any other phase, `unknown` if it could not be read: whatever removes volumes of that class is slow or stuck. Do **not** delete the volume; look at that provisioner or deleter, then continue with the command the closing line names |
| `the node cannot pull this release from` | `registry.base`, the registry's contents or the pull credential is wrong | correct it, wait 180 s, then the `repair` the closing line names |
| `the operation Lease is already free; nothing to abandon` | `abandon` on a target with no live operation — normal after a completed install | carry on; it exits `1` while doing no harm, so do not let a script stop on it |
| `a Helm release named … exists … sweep never removes a deployment` | `sweep` clears residue, never a deployment | `helm uninstall` first (its claims are kept), then `sweep` |

## Remove a deployment

There is no `uninstall` verb: removing a deployment is Helm's job plus two
cleanups, and the order matters. Doing it in the wrong order orphans the
installer's own canonical state, after which every later operation on that
target refuses with *another active operation or later phase owns canonical
state* and the only exit is a new namespace and release name.

The three values these commands need are the ones from your own site file, plus
the operation ID. If your terminal scrollback is gone, the ID is on disk — every
operation writes its own state directory:

Every command below resolves both the executable and the site file by absolute
path, because this guide keeps them in different directories: the executable in
`$HOME/gsj-operator/releases/r1`, the site file in `$HOME/gsj-operator`. Set
these once and no `cd` is needed:

```sh
GSJ=$HOME/gsj-operator/releases/r1/gsj-install.sh   # the name your descriptor gave
SITE=$HOME/gsj-operator/site.json
NAMESPACE=$(jq -r .target.namespace "$SITE")
RELEASE=$(jq -r .target.release "$SITE")
# The state directory is built from the SITE FILE's directory, never $HOME/.gsj:
#   <dir of site.json>/.gsj/<sha256 of the context name>/<namespace>/<release>
STATE="$(dirname "$SITE")/.gsj"
OP_FILE=$(find "$STATE" -name operation.json -path "*/$NAMESPACE/$RELEASE/*" 2>/dev/null | head -1)
GSJ_OPERATION_ID=$([ -n "$OP_FILE" ] && jq -r .operation "$OP_FILE")
echo "$NAMESPACE / $RELEASE / ${GSJ_OPERATION_ID:-<none>}"
```

**If that prints `<none>`, stop here.** Either your site file is not the one
this deployment was installed with — the state lives beside whichever site
file the installer was given — or this target never had an operation. Do not continue with an empty ID: the
next command would run `abandon --operation ""`, and step 1 of an irreversible
procedure is the wrong place to find out what that does.

That directory is also where the `abandoned-*.json` and `swept-*.json` records
live, which are the only durable account of what was done to this target.

Stop the tools process first if one is running, then:

```sh
# 1. release the operation. Its Lease must have been unrenewed for 180 s, so if
#    an installer just stopped, wait three minutes before this.
"$GSJ" abandon --operation "$GSJ_OPERATION_ID" \
    --reason "decommissioning" --config "$SITE" --non-interactive

#    After a SUCCESSFUL install there is no live operation to abandon and this
#    step reports that rather than doing anything -- run it anyway, because you
#    generally do not know whether the last operation completed.

# 2. remove the release. The chart keeps every claim (helm.sh/resource-policy:
#    keep), so this deletes no application data.
helm -n "$NAMESPACE" uninstall "$RELEASE" --wait --timeout 10m

# 3. clear the installer's residue: its Jobs and Pods, its record ConfigMaps,
#    the three token Secrets the provisioning Job minted, the free Lease and the
#    per-operation transfer directory. Claims are never listed or touched.
"$GSJ" sweep --config "$SITE" --reason "decommissioning" --non-interactive
```

After step 3 the namespace holds the three PersistentVolumeClaims and nothing
else of GSJ's. **They still hold every case, note, conversation and the whole
decisions index.** Deleting them is the irreversible step and is deliberately
not part of any verb:

```sh
# The claims are "$RELEASE-<role>" UNLESS the site installed onto claims that
# already existed (storage.<role>.existing_claim) -- then they keep those names.
for role in data forgejo chroma; do
  claim=$(jq -r --arg role "$role" --arg release "$RELEASE" \
    '(.storage[$role].existing_claim // "") | if . == "" then $release + "-" + $role else . end' "$SITE")
  kubectl -n "$NAMESPACE" delete pvc "$claim"
done
kubectl delete namespace "$NAMESPACE"
```

Take a backup first if the data matters — see
[Preserve and restore backups](#preserve-and-restore-backups). Whether deleting
a claim actually erases the bytes depends on its StorageClass's reclaim policy,
which `inspect` reports as `storage.classes[].deletes_data_on_release`; a
`Retain` class leaves the PersistentVolume and its data behind for you to
dispose of yourself.

Two things outlive all of this and are yours to remove: the operator state
directory under `$STATE/...` (keep it if you want the audit trail — the
abandoned/swept records are the only durable account of what happened), and the
content-addressed corpus cache under
`${XDG_CACHE_HOME:-$HOME/.cache}/gsj-install/vectors`, which is safe to delete
at any time and re-fetchable.

## Release service layout and redirects

The embedded `release_base_url` is a directory prefix. Every exact version must
resolve to these immutable files, with matching signed descriptor version:

```text
BASE/EXACT_VERSION/gsj-install.sh
BASE/EXACT_VERSION/installer-descriptor.json
BASE/EXACT_VERSION/installer-descriptor.sig
```

Serve final `200` responses and preferably `206` Range responses for resumable
downloads. An authenticated origin must serve these bytes directly without
redirects. Never replace bytes behind an already distributed signed version.
Also distribute the public manifest, release verification utility and trusted
key through the documented channels.

Credential-free public GitHub download URLs can work with the runtime's HTTPS
redirect handling when their tag segment equals the descriptor version. With
`delivery.auth_header_file`, redirects are refused. GitHub's release-asset API
may return either a direct response or a redirect, so it is not a guaranteed
direct authenticated origin. See [GitHub's release asset API contract](https://docs.github.com/en/rest/releases/assets#get-a-release-asset).

Release engineering's own downloader (the hand-run release preparation) is
stricter for protected input catalogs, addon payloads, trust and predecessor
bundles: it refuses redirects even when no token is supplied. Only public
client-tool downloads opt into HTTPS redirects. Supply those inputs from final
immutable HTTPS URLs. A release is published by hand as a **draft GitHub
prerelease** carrying the signed installer and its delivery assets; the
attached chart archive is an audit copy of the installer's embedded chart
(the product publishes the same chart to its own OCI registry for the direct
Helm path). Before qualification, release engineering stages only the
candidate's installer, descriptor and signature, create-only, under the
predecessor's signed release directory on an authenticated origin it
supplies; it does not publish the full delivery asset set there or make a
draft publicly available. A usable public/private delivery origin and the
qualification gates remain release engineering responsibilities; this guide
does not invent an available endpoint.
