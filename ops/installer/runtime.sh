#!/usr/bin/env bash
# Generated GSJ release installer. Its payload and trust root are immutable.
set -Eeuo pipefail
umask 077
# The installer's own identity, measured ONCE. Maintenance containers run as
# root, so every byte they write into the operator's storage.transfer_path
# hostPath lands root-owned and needed sudo to remove (measured on a real
# deployment: four root-owned per-operation directories, one of them 8.9 G).
TRANSFER_OWNER="$(id -u 2>/dev/null || printf 0):$(id -g 2>/dev/null || printf 0)"
# Only repair_operation opens a new bounded account-cleanup round; an
# ambient export of the signal is never authorization for one.
unset GSJ_CLEANUP_NEW_ROUND
@CLIENT_TABLE@
fail() { printf 'GSJ: %s\n' "$*" >&2; exit 1; }
log() { printf '[%s] %s\n' "$(date -u +%FT%T.000000Z)" "$*" >&2; }
sha_file() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f1; else shasum -a 256 "$1" | cut -d ' ' -f1; fi; }
atomic() { local dst=$1; cat > "$dst.pending.$$"; chmod 600 "$dst.pending.$$"; sync "$dst.pending.$$"; mv -f "$dst.pending.$$" "$dst"; sync "$(dirname "$dst")"; }
url_origin() { local rest=${1#*://}; printf '%s://%s' "${1%%://*}" "${rest%%/*}"; }
url_origin_only() {
 # scheme://host[:port] of a URL, the path, query, fragment AND any userinfo
 # dropped: a credential can sit in any of them, and a log line or a record
 # names the endpoint, never what it carries [review B2]. Not a URL: printed
 # as it is (no scheme). A URL whose authority is not a host and a numeric
 # port -- a password with an unencoded "/" cut the authority short, a
 # bracketless IPv6 -- is named by the fixed words below, never repeated.
 local rest authority
 [[ $1 == *://* ]] || { printf '%s' "$1"; return; }
 rest=${1#*://}; authority=${rest%%[/?#]*}; authority=${authority##*@}
 if [[ $authority =~ ^([A-Za-z0-9._~%-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$ ]]; then
   printf '%s://%s' "${1%%://*}" "$authority"
 else
   printf '(not a valid http(s) address)'
 fi
}
known_word() {
 # A word the API defines -- a Pod phase, a container waiting reason, a
 # condition type or reason, a PersistentVolume phase -- is repeated only
 # when it is one of the values this installer knows: the API does not
 # constrain a reason string, so anything else (a crafted status, a value a
 # newer API adds) becomes the fixed word "other" [review sweep B2,
 # review sweep B2]. Usage: known_word VALUE KNOWN...
 local value=$1 word; shift
 for word in "$@"; do [[ $value == "$word" ]] && { printf '%s' "$value"; return; }; done
 printf 'other'
}
validator_words() {
 # validate.jq's stderr, made printable [review B2]. The validator's OWN
 # line (`field: reason`, no quote, brace or bracket in it) passes through
 # with the line jq reported; a jq diagnostic -- a type error quotes the
 # input it choked on, a compile error the program -- is named by its line
 # and never repeated. The file is kept where the caller says.
 local line at own='^[a-z][a-z0-9_.]*: [^]"{}[]*$'
 line=$(sed -n 's/^jq: error (at [^)]*): //p' "$1" | head -n1)
 at=$(sed -n 's/^jq: error (at [^:)]*:\([0-9]*\)): .*/\1/p' "$1" | head -n1)
 if [[ -n $line && $line =~ $own ]]; then
   printf '%s (line %s)' "$line" "${at:-?}"
 else
   printf 'a jq diagnostic at line %s, not repeated here because it can quote the file'"'"'s contents (kept in %s)' "${at:-?}" "${2:-$1}"
 fi
}
pull_failure_condition() {
 # The CONDITION a container runtime's pull message establishes, in this
 # installer's words. The message itself is untrusted text -- a registry or
 # a proxy composes it, a bearer can ride in it -- and is never repeated
 # [review B2]; it is kept in the state directory for the operator.
 local m; m=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
 case $m in
   *unauthorized*|*"authentication required"*|*forbidden*|*denied*) printf 'the registry refused the pull (unauthorized or forbidden: the credential in registry.pull_secret, or its access to that repository)';;
   *"manifest unknown"*|*"not found"*|*notfound*|*"no such manifest"*|*"unknown blob"*) printf 'the registry does not hold that name and digest (not found: the digest was not copied there unchanged, or the prefix is not exact)';;
   *"no such host"*|*"server misbehaving"*|*"lookup "*|*"i/o timeout"*|*"connection refused"*|*"no route"*|*"dial tcp"*|*"network is unreachable"*|*"connection reset"*) printf 'the node could not connect to the registry (DNS, a route, a proxy, or a refused or timed-out connection)';;
   *x509*|*certificate*|*"tls handshake"*) printf 'the node does not trust the registry'"'"'s certificate (a CA the container runtime does not know)';;
   *toomanyrequests*|*"too many requests"*|*"rate limit"*) printf 'the registry rate-limited the pull (a limit or an outage on its side)';;
   *"no space"*|*"disk pressure"*) printf 'the node'"'"'s disk is full';;
   *) printf 'a condition this installer does not classify';;
 esac
}
kubectl_failure_condition() {
 # The same rule for kubectl's stderr on a refused create: classified, kept,
 # never repeated (an admission webhook's message is whatever its author
 # wrote) [review B2].
 local m; m=$(tr '[:upper:]' '[:lower:]' < "$1")
 case $m in
   *podsecurity*|*"admission webhook"*|*"denied the request"*|*admission*) printf 'an admission policy refused it';;
   *forbidden*) printf 'the API server refused it as forbidden (the kubeconfig'"'"'s permissions in this namespace)';;
   *"already exists"*) printf 'a Pod of that name already exists';;
   *"connection refused"*|*"unable to connect"*|*"no such host"*|*"i/o timeout"*|*"timed out"*) printf 'the API server could not be reached';;
   *) printf 'a condition this installer does not classify';;
 esac
}
system_ca_bundle() {
 local candidate
 if [[ -n ${CURL_CA_BUNDLE:-} && -r $CURL_CA_BUNDLE ]]; then printf '%s' "$CURL_CA_BUNDLE"; return; fi
 for candidate in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
   if [[ -r $candidate ]]; then printf '%s' "$candidate"; return; fi
 done
 fail 'system CA bundle is unavailable'
}
header_file() {
 private_file "$1"
 jq -Rse 'sub("\n$";"") | startswith("Authorization: ") and length>15 and (any(explode[]; .<32 or .==127)|not)' "$1" >/dev/null || fail 'authentication input must contain exactly one Authorization header'
}
download_curl() {
 local arg url=''
 for arg in "$@"; do case "$arg" in https://*|http://*) url=$arg;; esac; done
 if [[ -n ${DOWNLOAD_AUTH_FILE:-} ]]; then
   [[ -n $url && $url == https://* && $(url_origin "$url") == "${DOWNLOAD_AUTH_ORIGIN:-}" ]] || fail 'artifact credentials are restricted to the configured release origin'
   # Even a same-origin redirect must be supplied as an explicit immutable URL.
   curl --header "@$DOWNLOAD_AUTH_FILE" "$@" --location --max-redirs 0 --proto-redir '=https'
 else
   curl "$@" --proto-redir '=https'
 fi
}

fetch() {
 local url=$1 output=$2 expected=$3
 [[ $url == https://* || $url == http://localhost:* || $url == http://127.0.0.1:* ]] || fail 'artifact delivery requires HTTPS (loopback qualification is allowed)'
 if [[ -f $output ]] && [[ $(sha_file "$output") == "$expected" ]]; then return; fi
 mkdir -p "$(dirname "$output")"
 local rc=0
 download_curl --fail --silent --show-error --location --proto '=https,http' --connect-timeout 15 --max-time 1800 --retry 3 --continue-at - "$url" -o "$output.partial" || rc=$?
 if (( rc == 33 )); then
   # A server without Range support needs one fresh attempt. Other transport
   # failures retain partial bytes for a named retry through this same entrypoint.
   rm -f "$output.partial"
   download_curl --fail --silent --show-error --location --proto '=https,http' --connect-timeout 15 --max-time 1800 --retry 3 "$url" -o "$output.partial" || return $?
 elif (( rc != 0 )); then return "$rc"; fi
 [[ $(sha_file "$output.partial") == "$expected" ]] || { rm -f "$output.partial"; fail 'artifact hash mismatch'; }
 mv -f "$output.partial" "$output"
}
fetch_public() {
 # The vector sidecar is a PUBLIC artifact on a public origin,
 # not the operator's own release distribution. `download_curl`'s guard exists
 # so a delivery credential is never sent to another origin - and github.com is
 # another origin, which today fails the whole fetch by name. Honouring that
 # guard means fetching this WITHOUT the credential, never relaxing it: a
 # public object needs no Authorization header, and sending one there would be
 # the leak the guard was written to prevent. The bytes are proven by sha256
 # either way, so the credential has no role in trusting them. It also restores
 # redirect-following, which release assets require (`--max-redirs 0` belongs to
 # the authenticated path); `--proto-redir '=https'` still holds.
 local saved=${DOWNLOAD_AUTH_FILE:-} rc=0
 # An operator who MIRRORS the corpus on their own release origin is fetching
 # their own distribution, not a public object: there the credential belongs,
 # and the guard - origin match, no redirects - applies unchanged.
 if [[ -n $saved && $1 == https://* && $(url_origin "$1") == "${DOWNLOAD_AUTH_ORIGIN:-}" ]]; then fetch "$@"; return; fi
 DOWNLOAD_AUTH_FILE=''
 # `|| rc=$?` and an explicit `return`, never a bare `fetch "$@"`: the restore
 # below is a successful assignment, so it would reset $? and this function
 # would report success for a transport failure. Caught by a test, not in the
 # field - `fetch` exits through `fail` on a DIGEST mismatch, so only the
 # transport path ever returns at all.
 fetch "$@" || rc=$?
 DOWNLOAD_AUTH_FILE=$saved
 return $rc
}
# THE CLIENT FLOORS. Every one was MEASURED against
# real binaries running this installer's own programs — none was chosen:
#
#  helm 3.13    TWO measurements meet here, and the HIGHER one is the floor.
#               (a) managed_helm_addon passes `--labels gsj.io/addon-owner=...`,
#               the ownership label the add-on repair and rollback paths fence
#               on. helm 3.12.3 answers `unknown flag: --labels`; 3.13.3 accepts
#               it. A 3.12 admitted here would die INSIDE managed_dependencies,
#               after the Lease was taken and the add-on namespace and CRDs
#               existed.
#               (b) chart/Chart.yaml declares kubeVersion ">=1.27.0-0", and
#               helm_application_prepare renders the chart with `h template`,
#               which asserts that against helm's BUILT-IN default kube version
#               rather than the server's. Measured defaults: 3.11.3 -> 1.26.0
#               (refuses the chart), 3.12.3 -> 1.27.0, 3.13.3 -> 1.28.0,
#               3.14.0 -> 1.29.0, 3.19.2 -> 1.34.0, 3.22.0 -> 1.37.0,
#               4.2.2 -> 1.36.0. Measured further: 3.12.3, 3.14.0, 3.16.4,
#               3.18.6, 3.19.2 and 3.22.0 render this chart byte-identically,
#               and Helm 4.2.2 renders it identically but for blank lines.
#  kubectl 1.24 `k patch deployment --subresource=scale` (startup-recovery.sh).
#               kubectl 1.23.17 answers `unknown flag: --subresource`; 1.24
#               accepts it. Nothing the installer runs needs a newer client.
#  jq 1.6       all ~1,050 jq programs in runtime.sh, startup-recovery.sh and
#               verification-cleanup.sh were compiled under jq 1.6, 1.7, 1.7.1,
#               1.8.0 and 1.8.2; after the three rewrites this phase made, 1.6
#               compiles every one of them. Re-checked after this branch's
#               changes: 1,092 programs a harness could isolate (of 1,123
#               invocations; the rest are comments, tool loops and shell-
#               interpolated programs) compile identically under 1.6, 1.7,
#               1.7.1 and 1.8.2. Trap: jq 1.7 refuses an object VALUE written
#               as `{…} + (if … end)` unparenthesized where 1.8 accepts it.
#
# Set here so arithmetic on it is never an unbound-variable abort under
# `set -u` on a path that has not run bootstrap (the tests source this file
# directly). helm_dialect replaces it with the installed helm's real major.
HELM_MAJOR=0
GSJ_HELM_FLOOR=3.13
GSJ_KUBECTL_FLOOR=1.24
# The SERVER floor, ASSERTED in preflight() against the live cluster -- not left
# to Helm at apply time, by which point the Lease is held and Secrets, add-ons
# and a probe PVC have been written. The Job controller stamps
# `batch.kubernetes.io/job-name` -- which the chart's NetworkPolicy and
# verification-cleanup.sh both select on, with no legacy fallback -- only from
# Kubernetes 1.27.
GSJ_SERVER_FLOOR=1.27
GSJ_JQ_FLOOR=1.6
# OpenSSL, not LibreSSL, and 3.0 or newer. certificate_names_host reads the
# verdict `openssl x509 -checkhost` prints; LibreSSL's x509 has no -checkhost
# (macOS ships LibreSSL 3.3.6 as /usr/bin/openssl), so under it the helper
# would refuse every certificate as unreadable, late, with a message about the
# certificate. Measured: OpenSSL 3.0.13 (Ubuntu 24.04), 3.5.7 (Debian trixie)
# and 3.6.4 (Homebrew) all pass this floor and print the verdict; LibreSSL 3.3.6
# is refused by name. OpenSSL 1.x is unmeasured and below the floor.
# --fetch-tools does not supply OpenSSL.
GSJ_OPENSSL_FLOOR=3.0
version_at_least() {
 # Component-wise numeric compare; absent components are zero, so "1.24" and
 # "1.24.0" rank alike and "1.7" outranks "1.6.9". Leading zeroes are forced
 # base ten because kubectl really does ship minors like "08".
 local have=$1 want=$2 index count hv wv
 local -a mine theirs
 IFS=. read -r -a mine <<< "$have"; IFS=. read -r -a theirs <<< "$want"
 count=${#theirs[@]}; (( ${#mine[@]} > count )) && count=${#mine[@]}
 for (( index=0; index<count; index++ )); do
   # Keep only digits: a component like "7beta" would otherwise make
   # `(( 10#7beta ))` a bash arithmetic ERROR, not a comparison. client_version
   # already strips to digits and dots, so this is belt to that braces.
   hv=${mine[index]:-0}; hv=${hv//[!0-9]/}; hv=${hv:-0}
   wv=${theirs[index]:-0}; wv=${wv//[!0-9]/}; wv=${wv:-0}
   (( 10#$hv > 10#$wv )) && return 0
   (( 10#$hv < 10#$wv )) && return 1
 done
 return 0
}
client_version() {
 # Each tool spells its version differently and NONE of these spellings may
 # need jq, which is itself one of the tools under test. The first run of
 # digits-and-dots is the version in all three.
 # ANCHORED, not "the first digits anywhere in the output". A tool that answers
 # something other than a version -- a JSON blob, a usage message -- must yield
 # NOTHING, so the caller refuses for the right reason. Scraping the first digit
 # run out of arbitrary output turns `{"name":"gsj","version":1,...}` into the
 # confident and wrong answer "helm 1".
 # `|| true` on each probe, and the whole case guarded: this runs under
 # `set -Eeuo pipefail`, where a MISSING tool makes the pipeline nonzero and
 # `version=$(client_version helm)` then ABORTS the caller instead of yielding
 # an empty string. Reporting "no version" is this function's job; deciding
 # what that means belongs to client_preflight and require_offline_render.
 local tool=$1
 {
   case "$tool" in
     jq)      jq --version 2>/dev/null || true;;
     kubectl) kubectl version --client -o json 2>/dev/null || true;;
     helm)    helm version --short 2>/dev/null || true;;
   esac
 } | {
   case "$tool" in
     jq)      sed -n 's/^jq[- ]*\(version \)\{0,1\}v\{0,1\}\([0-9][0-9.]*\).*/\2/p';;
     kubectl) sed -n 's/.*"gitVersion"[^"]*"v\{0,1\}\([0-9][0-9.]*\).*/\1/p';;
     helm)    sed -n 's/^v\{0,1\}\([0-9][0-9.]*\).*/\1/p';;
   esac
 } | head -n1
}
openssl_preflight() {
 # Refused in the first seconds like the clients, by name, floor and finding.
 # Runs with and without --fetch-tools: OpenSSL is never downloaded.
 local found version
 found=$(openssl version 2>/dev/null | head -n1) || found=''
 [[ $found == OpenSSL\ * ]] \
   || fail "requires OpenSSL >= $GSJ_OPENSSL_FLOOR, found ${found:-no version} ($(command -v openssl)). macOS ships LibreSSL as /usr/bin/openssl; install OpenSSL 3 and put it first on PATH (--fetch-tools does not supply OpenSSL)."
 version=$(printf '%s\n' "$found" | sed -n 's/^OpenSSL \([0-9][0-9.]*\).*/\1/p')
 version_at_least "$version" "$GSJ_OPENSSL_FLOOR" \
   || fail "requires OpenSSL >= $GSJ_OPENSSL_FLOOR, found $found ($(command -v openssl)). Upgrade OpenSSL (--fetch-tools does not supply OpenSSL)."
}
client_preflight() {
 # A missing or too-old client is a TEN-SECOND refusal, here — before the
 # payload is even unpacked, before the site is read, before the Lease, before
 # the first cluster object exists. It names the tool, the floor, and what was
 # actually found, and it names the escape hatch.
 local tool floor found
 for tool in jq kubectl helm; do
   case "$tool" in jq) floor=$GSJ_JQ_FLOOR;; kubectl) floor=$GSJ_KUBECTL_FLOOR;; helm) floor=$GSJ_HELM_FLOOR;; esac
   command -v "$tool" >/dev/null \
     || fail "requires $tool >= $floor, found none on PATH. Install $tool, or re-run with --fetch-tools to download this release's pinned clients for this run only."
   found=$(client_version "$tool")
   [[ -n $found ]] \
     || fail "requires $tool >= $floor, but $(command -v "$tool") did not report a version. Check the binary, or re-run with --fetch-tools."
   version_at_least "$found" "$floor" \
     || fail "requires $tool >= $floor, found $found ($(command -v "$tool")). Upgrade $tool, or re-run with --fetch-tools to download this release's pinned clients for this run only."
 done
}
helm_dialect() {
 # Helm 3 and Helm 4 spell the same three intentions differently. Measured on a
 # live k3s v1.33.6 cluster with the chart's own hook/init-gate shape:
 #  - "run the hooks, never wait for the application": Helm 4's DEFAULT
 #    (`--wait` omitted == hookOnly) and Helm 3's default too. `--wait=hookOnly`
 #    was a no-op restatement on Helm 4 and a fatal ParseBool on Helm 3, so it
 #    is now spelled by OMISSION on both. Both majors still block on the
 #    provisioning hook Job (measured 23.8s against a 20s hook on 3.14, 3.19.2,
 #    3.22.0 and 4.2.2), which is what the wait-deps marker gate requires.
 #  - "wait for everything, jobs included": `--wait --wait-for-jobs` on BOTH.
 #    Measured on a live cluster: both majors parse it and both then wait for
 #    the application (both hit the deliberate init-gate deadlock at the
 #    timeout, which is what proves they waited). Helm 4 bare `--wait` is the
 #    kstatus watcher, whose readiness already includes Job completion; Helm 3
 #    bare `--wait` does NOT wait for Jobs, so the explicit flag is what makes
 #    the two majors mean the same thing. No dialect is needed for this one.
 #  - "take fields a previous manager owns": Helm 4 only. Helm 4 applies
 #    server-side and REFUSES a field `kubectl create` owns — measured, which is
 #    what a restore leaves behind — unless --force-conflicts. Helm 3 applies
 #    client-side, where that conflict does not arise and no flag exists.
 HELM_MAJOR=$(client_version helm); HELM_MAJOR=${HELM_MAJOR%%.*}; HELM_MAJOR=${HELM_MAJOR:-0}
 # Expanded at the call site as ${name[@]+"${name[@]}"}: bash 3.2 (still the
 # system bash on macOS) treats "${empty[@]}" as an unbound variable under
 # `set -u`, and HELM_APPLY_OWNERSHIP is empty on exactly the Helm 3 path
 # this phase opened.
 if (( HELM_MAJOR >= 4 )); then HELM_APPLY_OWNERSHIP=(--force-conflicts); else HELM_APPLY_OWNERSHIP=(); fi
}
require_offline_render() {
 # THE ONE REAL HELM 4 REQUIREMENT. Four call sites
 # serialize a release with NO CLUSTER AT ALL --
 #   KUBECONFIG=/dev/null helm install ... --dry-run=client
 # -- to obtain the pinned client cluster-free serialization of the signed
 # chart bytes and the exact reserved configuration, hooks included. Only
 # Helm 4 does that. Measured against the real chart with KUBECONFIG=/dev/null:
 #   helm 3.12.3  invalid argument "client" for --dry-run (bool until 3.13)
 #   helm 3.13.3  Kubernetes cluster unreachable
 #   helm 3.14.0  Kubernetes cluster unreachable
 #   helm 3.19.2  Kubernetes cluster unreachable
 #   helm 3.22.0  Kubernetes cluster unreachable
 #   helm 4.2.2   renders 24 objects
 # Helm 3 has no --kube-version on `install` to suppress the discovery, and
 # `helm template` renders manifests rather than a release object, so there is
 # no Helm 3 spelling of this. It is a documented precondition of these paths,
 # NOT of an ordinary install: the everyday install/upgrade needs only the
 # general floor, so a Helm 3 operator is refused HERE, precisely, instead of
 # being blocked up front or meeting "Kubernetes cluster unreachable" midway.
 # HELM_MAJOR is 0 until helm_dialect has run, so derive it first: a refusal
 # must name the helm that is actually installed, never a zero left over from
 # not having looked.
 (( HELM_MAJOR > 0 )) || helm_dialect
 # Refuse only on a POSITIVELY KNOWN Helm 3. A zero here means no helm reported
 # a version at all, and that cannot happen on a real run: client_preflight is
 # fail-CLOSED on exactly that case at startup, and --fetch-tools installs a
 # known Helm 4. The two checks are one design -- the strict one runs early,
 # where it can still be acted on, so refusing an unknown a second time here
 # would add no safety and would instead break every caller that legitimately
 # never had a helm binary to model.
 (( HELM_MAJOR == 0 || HELM_MAJOR >= 4 )) || fail "this step serializes a release without contacting the cluster, which only Helm 4 can do (found helm $(client_version helm)). Install Helm 4 alongside, or re-run this command with --fetch-tools."
}
helm_verb_preflight() {
 # THE HELM 4 VERBS, refused in the first seconds [review B3] -- after the
 # clients are known and the site is read, before the cluster is read and
 # before the Lease. Four paths reach the offline render above (the sites of
 # require_offline_render, all four): addon-repair always
 # (repair_managed_addon); repair of a RESTORE stopped at `applying` -- the
 # one restore phase whose application Helm revision is re-proven offline
 # (restore_application_evidence; every other restore phase is refused or
 # routed elsewhere by restore_application_repair without rendering); the
 # STARTUP-SOURCE repair -- repair with --source-installer, or of an
 # operation whose record carries `startup_source`, and its resumed
 # recovery, resume at the two phases that reach helm_apply (owned,
 # backup-verified): startup_source_control renders the signed predecessor;
 # and the STARTUP CONTINUATION, repair --continue-helm-installer:
 # startup_helm_failed_target renders the failed target. Every other verb
 # -- install, upgrade, upgrade --to, resume and repair outside those
 # recovery paths, backup, backup-repair, restore, restore-repair, sweep,
 # abandon, the credential/tls/lease repairs, inspect -- runs on the Helm
 # 3.13 floor. Before this, a Helm 3 operator was refused AT the step:
 # after the site was read, the cluster inspected (three reads for the
 # source proof, two for the continuation), the Lease renewed by a
 # same-target repair, and for the restore most of its evidence re-read.
 # require_offline_render still guards the four sites themselves.
 local verb='' record="${STATE_DIR:-}/operation.json" kind='' status='' recorded_source=false backup_round=0
 if [[ -f $record ]]; then
   kind=$(jq -r '.kind // ""' "$record" 2>/dev/null || true)
   status=$(jq -r '.status // ""' "$record" 2>/dev/null || true)
   backup_round=$(jq -r '.backup_round // 0' "$record" 2>/dev/null || true)
   jq -e '.startup_source != null' "$record" >/dev/null 2>&1 && recorded_source=true
 fi
 # A recorded startup source renders in read_repair_backup_source and in
 # helm_apply -- unless a backup round is selected or recorded, which reads
 # the backup source instead (read_backup_source) and never renders.
 local source_path=false
 if $recorded_source && [[ -z ${BACKUP_ROUND:-} && $backup_round == 0 ]]; then source_path=true; fi
 case $COMMAND in
   addon-repair) verb=addon-repair;;
   repair)
     if [[ $kind == restore ]]; then
       [[ $status != applying ]] || verb='repair of a restore stopped at its application (its Helm revision is re-proven offline)'
     elif [[ -n ${CONTINUE_HELM_INSTALLER:-} ]]; then
       verb='repair --continue-helm-installer (the startup continuation re-proves the failed Helm target offline)'
     elif [[ -n ${SOURCE_INSTALLER:-} ]] || $source_path; then
       verb='repair with a startup source (--source-installer, or a recorded one: the startup-source proof renders the signed predecessor offline)'
     fi;;
   resume)
     # the three resume phases that reach the render: owned and
     # backup-verified through helm_apply, repair-prepared through
     # repair_operation (the repair transition re-reads the source)
     if $source_path && [[ $kind != restore && ( $status == owned || $status == backup-verified || $status == repair-prepared ) ]]; then
       verb='resume of a startup-source recovery (the startup-source proof renders the signed predecessor offline)'
     fi;;
   backup-repair)
     if $source_path && [[ $kind != restore ]]; then
       verb='backup-repair of a startup-source recovery (the startup-source proof renders the signed predecessor offline)'
     fi;;
 esac
 [[ -n $verb ]] || return 0
 (( HELM_MAJOR > 0 )) || helm_dialect
 (( HELM_MAJOR == 0 || HELM_MAJOR >= 4 )) || fail "$verb serializes a release without contacting the cluster, which only Helm 4 can do (found helm $(client_version helm) at $(command -v helm)). Install Helm 4 alongside, or re-run this command with --fetch-tools (this release's pinned Helm 4 for this run only); every other command runs on Helm >= $GSJ_HELM_FLOOR"
}
bootstrap() {
 for utility in bash curl tar gzip base64 openssl awk cut uname mktemp date sync; do command -v "$utility" >/dev/null || fail "bootstrap utility required: $utility"; done
 openssl_preflight
 # ${FETCH_TOOLS:-false}: main sets it while parsing arguments, but bootstrap
 # must not abort with an unbound variable if it is ever reached without that.
 ${FETCH_TOOLS:-false} || client_preflight
 DOWNLOAD_AUTH_FILE=''
 local os arch tool info url checksum packed marker
 os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m)
 case "$arch" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) fail "unsupported installer architecture: $arch";; esac
 GSJ_PLATFORM="$os/$arch"; GSJ_WORK=$(mktemp -d "${TMPDIR:-/tmp}/gsj-install.XXXXXXXX")
 GSJ_PAYLOAD="$GSJ_WORK/payload"; GSJ_PRIVATE_BIN="$GSJ_WORK/bin"; mkdir -p "$GSJ_PAYLOAD" "$GSJ_PRIVATE_BIN"
 marker=$(awk '/^__GSJ_PAYLOAD_BELOW__$/ {print NR+1; exit}' "$0"); [[ -n $marker ]] || fail 'installer payload missing'
 tail -n "+$marker" "$0" | base64 --decode | tar -xz -C "$GSJ_PAYLOAD"
 (cd "$GSJ_PAYLOAD"; if command -v sha256sum >/dev/null; then sha256sum -c SHA256SUMS >/dev/null; else shasum -a 256 -c SHA256SUMS >/dev/null; fi) || fail 'embedded payload integrity failed'
 # The download path is KEPT, intact and checksum-pinned, for an
 # air-gapped or under-provisioned box — but it is now opt-in.
 if ${FETCH_TOOLS:-false}; then
   for tool in jq kubectl helm; do
     info=$(gsj_client_info "$tool" "$GSJ_PLATFORM") || fail "unqualified client platform: $GSJ_PLATFORM/$tool"
     IFS=$'\t' read -r url checksum <<< "$info"
     packed="${XDG_CACHE_HOME:-$HOME/.cache}/gsj-install/$tool/$GSJ_PLATFORM/$checksum"; mkdir -p "$(dirname "$packed")"; chmod 700 "$(dirname "$packed")"; fetch "$url" "$packed" "$checksum"
     if [[ $tool == helm ]]; then tar -xzf "$packed" -C "$GSJ_WORK" "$os-$arch/helm"; mv "$GSJ_WORK/$os-$arch/helm" "$GSJ_PRIVATE_BIN/helm"; else cp "$packed" "$GSJ_PRIVATE_BIN/$tool"; fi
     chmod 700 "$GSJ_PRIVATE_BIN/$tool"
   done
 fi
 export GSJ_PAYLOAD GSJ_PRIVATE_BIN PATH="$GSJ_PRIVATE_BIN:$PATH"
 helm_dialect
}
k() { kubectl --context "$CONTEXT" --namespace "$NAMESPACE" "$@"; }
h() { helm --kube-context "$CONTEXT" --namespace "$NAMESPACE" "$@"; }
j() { jq -r "$1" "$SITE"; }
# registry.base. The signed release names WHERE each
# image was published; a site whose nodes pull from somewhere else -- a Nexus,
# ECR, Artifactory or Harbor project under a path prefix -- names that place in
# registry.base, and every image reference this installer composes becomes
# <base>/<last path segment of the release's repository>@<the release's digest>.
# The location may move; the content may not: the digest is never site input,
# and a by-digest pull cannot resolve to other bytes. EVERY composition of an
# image reference goes through image_ref -- a consumer that skipped it would
# name a registry the site just said its nodes cannot reach.
# $base is always the registry.base of the site that PRODUCED the workload being
# described: $SITE for what this run creates, .site of installed.json for what a
# recorded installation is compared against (absent there before this field
# existed, hence the // "").
# shellcheck disable=SC2016
JQ_IMAGE='def relocated($base): if ($base // "") == "" then . else .repository = ($base + "/" + (.repository | split("/") | last)) end; def image_ref($base): relocated($base) | .repository + "@" + .digest;'
payload_image() { jq -r --arg role "$1" --arg base "$(j '.registry.base // ""')" "$JQ_IMAGE"' .images[$role] | image_ref($base)' "$GSJ_PAYLOAD/release.json"; }
installed_image() { jq -r --arg role "$1" "$JQ_IMAGE"' . as $i | $i.manifest.images[$role] | image_ref($i.site.registry.base)' "$2"; }
# Does the certificate name this host? `openssl x509 -checkhost` PRINTS its
# verdict and, on OpenSSL 3.0 (Ubuntu 22.04 and 24.04), exits 0 on a mismatch
# too -- only 3.5 and later exit 1 -- so the exit status is not the answer.
# Measured: Ubuntu 24.04's 3.0.13 exits 0 for "does NOT match certificate";
# Debian's 3.5.7 and Homebrew's 3.6.4 exit 1. The printed line is the same on
# every version, so that is what this reads. A certificate that cannot be read
# at all names no host.
certificate_names_host() {
 local verdict; verdict=$(openssl x509 -in "$1" -noout -checkhost "$2" 2>/dev/null) || return 1
 [[ $verdict == "Hostname $2 does match certificate" ]]
}
private_file() {
 [[ -f $1 && ! -L $1 ]] || fail "protected input is not a regular file: $1"
 local mode
 mode=$(stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1")
 (( (8#$mode & 077) == 0 )) || fail "protected input must have mode 0600 or 0400: $1"
}
resolve_file() { [[ $1 == /* ]] && printf '%s\n' "$1" || printf '%s/%s\n' "$SITE_DIR" "$1"; }
validate_site() {
 # The operator's file merged over the release's defaults, through the schema.
 # A refusal used to surface as jq's own line (`jq: error (at <stdin>:N):
 # site.operator.login: invalid format`, exit 5): not a named refusal, and
 # without the format that was expected. It is now a GSJ refusal naming the
 # field, the expected shape where the schema states one, and the file to
 # correct -- never jq's framing, never the file's contents.
 local words
 # The file is parsed on its own first, so a syntax error carries the file's
 # own line numbers (in the merged stream they count from the defaults); a
 # file that cannot be opened, or one that starts with a byte-order mark
 # (which the merge refuses at a line it cannot name), is named as that.
 [[ -r $CONFIG ]] || fail "the site file cannot be read: $CONFIG (check its permissions); nothing was validated"
 if [[ $(head -c 3 "$CONFIG" | od -An -tx1 | tr -d ' \n') == efbbbf ]]; then fail "the site file starts with a byte-order mark (a UTF-8 BOM): save $CONFIG without one"; fi
 if ! jq . "$CONFIG" > /dev/null 2> "$GSJ_WORK/validate.err"; then
   words=$(sed 's/^jq: //' "$GSJ_WORK/validate.err" | tr '\n' ' ' | cut -c1-300)
   fail "the site file is not valid JSON: ${words% }. Correct it in $CONFIG"
 fi
 # The top-level shape, named before the merge: a site whose whole value is
 # a string or a list would reach `.[0] * .[1]`, and jq's diagnostic for
 # that quotes the value -- a secret pasted in the wrong place [review B2].
 local shape; shape=$(jq -r type "$CONFIG")
 [[ $shape == object ]] || fail "the site file must be a JSON object at the top level, and $CONFIG holds a $shape. Its contents are not repeated here; the payload's site.schema.json is the field reference"
 if ! { jq -s '.[0] * .[1]' "$GSJ_PAYLOAD/defaults.json" "$CONFIG" | jq --slurpfile schema "$GSJ_PAYLOAD/site.schema.json" -f "$GSJ_PAYLOAD/validate.jq" > "$SITE"; } 2> "$GSJ_WORK/validate.err"; then
   # the validator's own line passes; a jq diagnostic is kept beside the
   # site's state, never printed (it can quote the file's contents)
   mkdir -p "$SITE_DIR/.gsj"; chmod 700 "$SITE_DIR/.gsj"; atomic "$SITE_DIR/.gsj/site-refusal.err" < "$GSJ_WORK/validate.err"
   fail "the site file was refused: $(validator_words "$GSJ_WORK/validate.err" "$SITE_DIR/.gsj/site-refusal.err"). Correct it in $CONFIG; the effective site is that file merged over the release's defaults, and the payload's site.schema.json is the field reference"
 fi
}
load_site() {
 [[ -f $CONFIG ]] || fail 'configuration file is missing; use --interactive'
 SITE_DIR=$(cd "$(dirname "$CONFIG")" && pwd); CONFIG="$SITE_DIR/$(basename "$CONFIG")"; SITE="$GSJ_WORK/site.json"
 validate_site
 CONTEXT=$(j .target.context); NAMESPACE=$(j .target.namespace); RELEASE=$(j .target.release)
 [[ -z $CONTEXT_ARG || $CONTEXT_ARG == "$CONTEXT" ]] || fail '--context differs from site target'
 kubectl config get-contexts "$CONTEXT" -o name | jq -Rse 'length>1' >/dev/null || fail 'target Kubernetes context is unavailable'
 RELEASE_ID=$(jq -r .identity "$GSJ_PAYLOAD/release.json"); VERSION=$(jq -r .version "$GSJ_PAYLOAD/release.json")
 STATE_DIR="$SITE_DIR/.gsj/$(printf %s "$CONTEXT" | openssl dgst -sha256 | awk '{print $NF}')/$NAMESPACE/$RELEASE"; mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
 if [[ $(j .tls.profile) == managed-local-ca ]] && ! jq -e --arg ca "$STATE_DIR/tls/ca.crt" '.tls.ca_file==$ca and .verification.ca_file==$ca' "$SITE" >/dev/null; then
   if [[ -e $STATE_DIR/site.pending.json || -L $STATE_DIR/site.pending.json ]]; then
     # An operation saved by an installer from before the saved site recorded
     # these derived paths retains its site without them, and that installer
     # resumes byte-exactly. Derive them for this run only; never touch the
     # operator's file for its operation.
     jq --arg ca "$STATE_DIR/tls/ca.crt" '.tls.ca_file=$ca | .verification.ca_file=$ca' "$SITE" > "$SITE.derived"
     mv -f "$SITE.derived" "$SITE"
   else
     # Save the derived local CA path before any operation binds this site. A
     # rewrite during the operation would break its named resume.
     [[ -f $CONFIG && ! -L $CONFIG ]] || fail 'the saved site must be a regular file to record the managed local CA path'
     jq --arg ca "$STATE_DIR/tls/ca.crt" '.tls.ca_file=$ca | .verification.ca_file=$ca' "$CONFIG" | atomic "$CONFIG"
     validate_site
   fi
 fi
 OP_PASSWORD=$(resolve_file "$(j .operator.password_file)"); if [[ $COMMAND != restore || -f $OP_PASSWORD ]]; then private_file "$OP_PASSWORD"; [[ -s $OP_PASSWORD ]] || fail 'operator password is empty'; fi
 BACKUP_DIR=$(resolve_file "$(j .backup.directory)"); BACKUP_PASSWORD=$(resolve_file "$(j .backup.passphrase_file)"); private_file "$BACKUP_PASSWORD"; [[ -s $BACKUP_PASSWORD ]] || fail 'backup encryption passphrase is empty'
 mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
 jq --slurpfile release "$GSJ_PAYLOAD/release.json" -f "$GSJ_PAYLOAD/compile.jq" "$SITE" > "$GSJ_WORK/values.pending.json"
 local delivery_ca delivery_auth
 delivery_ca=$(j .delivery.ca_file); delivery_auth=$(j .delivery.auth_header_file)
 if [[ -n $delivery_ca ]]; then
   delivery_ca=$(resolve_file "$delivery_ca"); openssl x509 -in "$delivery_ca" -noout >/dev/null || fail 'invalid artifact CA certificate'
   cat "$(system_ca_bundle)" "$delivery_ca" > "$GSJ_WORK/download-ca.pem"; export CURL_CA_BUNDLE="$GSJ_WORK/download-ca.pem"
 fi
 if [[ -n $delivery_auth ]]; then
   delivery_auth=$(resolve_file "$delivery_auth"); header_file "$delivery_auth"
   DOWNLOAD_AUTH_ORIGIN=$(url_origin "$(jq -r .release_base_url "$GSJ_PAYLOAD/release.json")")
   [[ $DOWNLOAD_AUTH_ORIGIN == https://* ]] || fail 'artifact authentication requires a release HTTPS origin'
   cp "$delivery_auth" "$GSJ_WORK/download-authorization"; chmod 600 "$GSJ_WORK/download-authorization"
   DOWNLOAD_AUTH_FILE="$GSJ_WORK/download-authorization"
 fi
 log "Target $CONTEXT / $NAMESPACE / $RELEASE; release $VERSION ($RELEASE_ID)"
}
ask() { local label=$1 current=$2 value; read -r -p "$label [$current]: " value </dev/tty; printf '%s' "${value:-$current}"; }
read_secret() (
 local saved value
 saved=$(stty -g </dev/tty)
 trap 'stty "$saved" </dev/tty' EXIT
 trap 'exit 130' HUP INT TERM
 # Disable echo BEFORE displaying the prompt. read -s alone can expose a
 # quickly pasted credential between its prompt and terminal-mode change.
 stty -echo </dev/tty
 printf '%s: ' "$1" >/dev/tty
 IFS= read -r value </dev/tty
 printf '\n' >/dev/tty
 printf '%s' "$value"
)
set_site() { local key=$1 value=$2; jq --arg path "$key" --arg v "$value" 'setpath($path|ltrimstr(".")|split(".");$v)' "$WIZARD" | atomic "$WIZARD"; }
wizard_credential() {
 local service=$1 directory=$2 method=none value path existing
 [[ $(jq -r ".$service.credential.file" "$WIZARD") == '' ]] || method=file
 [[ $(jq -r ".$service.credential.secret" "$WIZARD") == '' ]] || method=secret
 method=$(ask "$service authentication (none, enter, file, secret)" "$method")
 case "$method" in
 none) set_site ".$service.credential.file" ''; set_site ".$service.credential.secret" '';;
 file) set_site ".$service.credential.file" "$(ask 'Protected credential file inside the tools environment' "$(jq -r ".$service.credential.file" "$WIZARD")")"; set_site ".$service.credential.secret" '';;
 secret) set_site ".$service.credential.secret" "$(ask 'Existing Kubernetes Secret name (key: key)' "$(jq -r ".$service.credential.secret" "$WIZARD")")"; set_site ".$service.credential.file" '';;
 enter)
   value=$(read_secret "$service API key"); [[ -n $value ]] || fail 'credential cannot be empty'
   path="$directory/$service-api-key"
   printf '%s' "$value" > "$GSJ_WORK/wizard-credential"; unset value
   if [[ -e $path ]]; then private_file "$path"; cmp -s "$path" "$GSJ_WORK/wizard-credential" || fail 'a saved credential already exists; use a named rotation or a separate protected input';
   else cat "$GSJ_WORK/wizard-credential" | atomic "$path"; fi
   rm -f "$GSJ_WORK/wizard-credential"; set_site ".$service.credential.file" "$path"; set_site ".$service.credential.secret" '';;
 *) fail 'unsupported authentication selection';;
 esac
}
wizard_discover() {
 local context=$1 nodes classes ingress
 nodes=$(kubectl --context "$context" get nodes -o json)
 classes=$(kubectl --context "$context" get storageclasses -o json)
 ingress=$(kubectl --context "$context" get ingressclasses -o json)
 jq --argjson nodes "$nodes" --argjson classes "$classes" --argjson ingress "$ingress" '
   if ($nodes.items|length)==1 then .storage.node=$nodes.items[0].metadata.name else . end |
   if ($classes.items|length)==0 then .storage.profile="managed-local-path"|.storage.class="gsj-local"
   else .storage.class=($classes.items|sort_by(.metadata.annotations["storageclass.kubernetes.io/is-default-class"]!="true",.metadata.name)|.[0].metadata.name) end |
   if ($ingress.items|length)==0 then .ingress.profile="managed-traefik"
   elif ($ingress.items|length)==1 then .ingress.class=$ingress.items[0].metadata.name | .ingress.namespace=($ingress.items[0].metadata.annotations["meta.helm.sh/release-namespace"] // .ingress.namespace)
   else . end
 ' "$WIZARD" | atomic "$WIZARD"
}
wizard() {
 [[ -r /dev/tty ]] || fail 'interactive mode requires a terminal'
 mkdir -p "$(dirname "$CONFIG")"; WIZARD="$GSJ_WORK/wizard.json"
 if [[ -f $CONFIG ]]; then
   # the saved site's shape first: a string or a list would reach the merge,
   # whose diagnostic quotes the value [review sweep B2]
   local shape; shape=$(jq -r type "$CONFIG" 2>/dev/null || printf 'value that is not valid JSON')
   [[ $shape == object ]] || fail "the saved site file must be a JSON object at the top level, and $CONFIG holds a $shape. Its contents are not repeated here"
   jq -s '.[0] * .[1]' "$GSJ_PAYLOAD/defaults.json" "$CONFIG" > "$WIZARD"
 else cp "$GSJ_PAYLOAD/defaults.json" "$WIZARD"; fi
 local context value secret_dir pwd path
 context=${CONTEXT_ARG:-$(kubectl config current-context 2>/dev/null || true)}
 set_site .target.context "$(ask 'Kubernetes context' "$(jq -r --arg c "$context" '.target.context | if .=="" then $c else . end' "$WIZARD")")"
 if [[ ! -f $CONFIG ]]; then wizard_discover "$(jq -r .target.context "$WIZARD")"; fi
 for path in target.namespace target.release public_url operator.login llm.base_url llm.model ocr.url ocr.model storage.class storage.node ingress.class ingress.namespace; do
   set_site ".$path" "$(ask "$path" "$(jq -r ".$path" "$WIZARD")")"
 done
 for path in storage.profile ingress.profile tls.profile; do
   set_site ".$path" "$(ask "$path (see configuration schema for supported profiles)" "$(jq -r ".$path" "$WIZARD")")"
 done
 secret_dir="$(cd "$(dirname "$CONFIG")" && pwd)/credentials"; mkdir -p "$secret_dir"; chmod 700 "$secret_dir"
 path=$(jq -r .operator.password_file "$WIZARD")
 if [[ -z $path ]]; then
   pwd=$(read_secret 'Initial operator password'); [[ -n $pwd ]] || fail 'operator password required'
   printf '%s' "$pwd" | atomic "$secret_dir/operator-password"; unset pwd; set_site .operator.password_file "$secret_dir/operator-password"
 fi
 wizard_credential llm "$secret_dir"; wizard_credential ocr "$secret_dir"
 for path in llm.context_window llm.output_tokens limits.upload_mb limits.worktree_cache_mb; do
   value=$(ask "$path (0 model limits use endpoint discovery/SDK defaults)" "$(jq -r ".$path" "$WIZARD")")
   jq --arg path "$path" --argjson value "$value" 'setpath($path|split(".");$value)' "$WIZARD" | atomic "$WIZARD"
 done
 value=$(ask 'LLM key allowed origins, comma-separated (exact origins)' "$(jq -r '.llm.allowed_origins|join(",")' "$WIZARD")")
 if [[ -z $value && ( $(jq -r .llm.credential.file "$WIZARD") != '' || $(jq -r .llm.credential.secret "$WIZARD") != '' ) ]]; then value=$(url_origin "$(jq -r .llm.base_url "$WIZARD")"); fi
 jq --arg value "$value" '.llm.allowed_origins=($value|split(",")|map(select(.!="")))' "$WIZARD" | atomic "$WIZARD"
 for path in registry.config_file registry.pull_secret tls.secret tls.certificate_file tls.private_key_file tls.ca_file tls.issuer tls.email trust.ca_file trust.proxy_file verification.connect_host verification.ca_file delivery.ca_file delivery.auth_header_file backup.offbox_url backup.ca_file backup.auth_header_file storage.transfer_path; do
   set_site ".$path" "$(ask "$path (blank if unused)" "$(jq -r ".$path" "$WIZARD")")"
 done
 value=$(ask 'Verification connection port (0 uses public DNS)' "$(jq -r .verification.connect_port "$WIZARD")")
 jq --argjson p "$value" '.verification.connect_port=$p' "$WIZARD" | atomic "$WIZARD"
 set_site .backup.directory "$(ask 'Backup directory outside the data volumes' "$(jq -r '.backup.directory | if .=="" then "/backups/application" else . end' "$WIZARD")")"
 if [[ $(jq -r .backup.passphrase_file "$WIZARD") == '' ]]; then
   openssl rand -base64 48 | atomic "$secret_dir/backup-passphrase"; set_site .backup.passphrase_file "$secret_dir/backup-passphrase"
   log 'Generated protected backup passphrase; retain a separate recovery copy.'
 fi
 # Validate to a private file first: a refused answer must never replace the
 # saved site with an empty one, and the refusal is a named one.
 if ! jq --slurpfile schema "$GSJ_PAYLOAD/site.schema.json" -f "$GSJ_PAYLOAD/validate.jq" "$WIZARD" > "$GSJ_WORK/wizard-validated.json" 2> "$GSJ_WORK/validate.err"; then
   # the validator's own line passes; a jq diagnostic is kept, never printed [review B2]
   local kept; kept="$(dirname "$CONFIG")/.gsj"; mkdir -p "$kept"; chmod 700 "$kept"; atomic "$kept/site-refusal.err" < "$GSJ_WORK/validate.err"
   words=$(validator_words "$GSJ_WORK/validate.err" "$kept/site-refusal.err")
   # The effective site is the saved file merged with these answers; a refused
   # setting the wizard never asks for lives in the file.
   if [[ -f $CONFIG ]]; then fail "the effective site (the saved $CONFIG merged with these answers) was refused: $words. The saved site file was left as it was; if that setting is one the wizard did not ask for, correct it in $CONFIG, then run the wizard again"
   else fail "the effective site (the release defaults merged with these answers) was refused: $words. No site file was written; run the wizard again"; fi
 fi
 atomic "$CONFIG" < "$GSJ_WORK/wizard-validated.json"
 log "Reusable site configuration saved at $CONFIG"
}
inspect_cluster() {
 local out="$GSJ_WORK/inspect"; mkdir -p "$out"
 CONTEXT=${CONTEXT_ARG:-$(kubectl config current-context)}; NAMESPACE=default
 # Guarded like every other probe: an unreachable API server must still yield
 # a profile (host facts, client floors, egress), not one line of raw kubectl.
 kubectl --context "$CONTEXT" version -o json > "$out/version.json" 2>/dev/null \
   || printf '{"unavailable":true,"reason":"the Kubernetes API server could not be reached or did not answer version"}' > "$out/version.json"
 # READ-ONLY, ALWAYS. Every probe below is a get/version/df/curl: inspect runs
 # on a stranger's production cluster, so it never creates, never modifies and
 # never needs more than read. Each one degrades to a recorded UNKNOWN instead
 # of failing the run, because a profile that refuses to be produced on a
 # locked-down cluster is worth nothing.
 for resource in nodes pods persistentvolumeclaims persistentvolumes storageclasses ingressclasses \
                 namespaces services ingresses networkpolicies daemonsets deployments customresourcedefinitions; do
   if ! kubectl --context "$CONTEXT" get "$resource" --all-namespaces -o json > "$out/$resource.json" 2> "$out/$resource.error"; then printf '{"unavailable":true,"reason":"missing access or API"}' > "$out/$resource.json"; fi
 done
 kubectl --context "$CONTEXT" top nodes > "$out/live-usage.txt" 2>/dev/null || printf 'Unavailable: metrics API or access.\n' > "$out/live-usage.txt"
 # WHAT IS ALREADY THERE, by LABEL ONLY. A Helm release Secret's .data.release
 # is a gzipped blob of that release's values, which is exactly the kind of
 # thing this document must never carry -- so the release inventory is read
 # through custom-columns, which cannot emit a payload at all.
 kubectl --context "$CONTEXT" get secrets --all-namespaces -l owner=helm \
   -o 'custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.labels.name,VERSION:.metadata.labels.version,STATUS:.metadata.labels.status' \
   --no-headers > "$out/helm-releases.txt" 2>/dev/null || printf 'GSJ-DENIED\n' > "$out/helm-releases.txt"
 # local-path's node path map is the /-versus-/data difference that decided
 # PVC sizing on both measured boxes. Only this one well-known provisioner
 # ConfigMap is read, and only its paths are projected.
 # A label selector that matches nothing still exits 0, so the RESULT is what
 # decides whether to fall back -- not the exit code.
 kubectl --context "$CONTEXT" get configmap -A -l app=local-path-provisioner -o json > "$out/local-path.json" 2>/dev/null || printf '{"items":[]}' > "$out/local-path.json"
 if ! grep -q nodePathMap "$out/local-path.json" 2>/dev/null; then
   kubectl --context "$CONTEXT" -n kube-system get configmap local-path-config -o json > "$out/local-path.json" 2>/dev/null \
     || printf '{"unavailable":true,"reason":"no local-path provisioner configuration is readable"}' > "$out/local-path.json"
 fi
 local cores ram disk
 cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu); ram=$(awk '/MemTotal:/ {printf "%.0f",$2*1024}' /proc/meminfo 2>/dev/null || sysctl -n hw.memsize); disk=$(df -Pk "$GSJ_WORK" | tail -n1 | awk '{print $4*1024}')
 # THE INSTALLER HOST, which is not necessarily a cluster node -- said so in
 # the document rather than left to be assumed.
 local host_os host_kernel host_arch host_cgroup host_root host_sudo host_docker host_buildx
 host_os=$( (. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}") || sw_vers -productVersion 2>/dev/null || printf unknown); host_os=${host_os:-unknown}
 host_kernel=$(uname -sr 2>/dev/null || printf unknown); host_arch=$(uname -m 2>/dev/null || printf unknown)
 # cgroup v2 mounts a filesystem whose type reports as cgroup2fs; v1 does not.
 host_cgroup=$(stat -f -c %T /sys/fs/cgroup 2>/dev/null || printf unknown)
 case "$host_cgroup" in cgroup2fs) host_cgroup=v2;; tmpfs|cgroupfs) host_cgroup=v1;; esac
 host_root=$( [[ $(id -u 2>/dev/null || printf 1) == 0 ]] && printf true || printf false)
 # -n never prompts, so this cannot hang an unattended run on a password.
 host_sudo=$(sudo -n true >/dev/null 2>&1 && printf true || printf false)
 host_docker=$(docker version --format '{{.Server.Version}}' 2>/dev/null || printf unknown); host_docker=${host_docker:-unknown}
 host_buildx=$(docker buildx version >/dev/null 2>&1 && printf true || printf false)
 # THE FILESYSTEMS the operator can actually put things on. The node-root
 # capacity wall and storage.transfer_path both live here.
 { df -Pk / "$GSJ_WORK" "${HOME:-/}" /data /var/lib/docker /var/lib/rancher 2>/dev/null || true; } \
   | awk 'NR>1 && !seen[$6]++ {printf "%s\t%s\t%s\n",$6,$2*1024,$4*1024}' > "$out/filesystems.txt"
 [[ -s $out/filesystems.txt ]] || printf 'unknown\t0\t0\n' > "$out/filesystems.txt"
 # EGRESS, as the cluster's own image pulls and this installer's downloads need
 # it. Reachability only -- no credential is offered and no body is kept.
 : > "$out/egress.txt"
 local endpoint
 # github.com is on the list because the released vector sidecar
 # is fetched from a public GitHub release, which redirects to
 # release-assets.githubusercontent.com - both names matter to a firewall rule,
 # but only the entry point can be probed without downloading 1.5 GiB.
 for endpoint in https://ghcr.io/v2/ https://get.helm.sh/ https://dl.k8s.io/ https://huggingface.co/ https://github.com/; do
   # `|| true`, never `|| printf 000`: on a transport failure curl does BOTH --
  # it writes 000 because of --write-out AND exits nonzero -- so a printing
  # fallback appends a SECOND 000, and "000000" is not "000", which made every
  # unreachable endpoint read as REACHABLE. Inverted precisely on the
  # air-gapped box this field exists to characterise.
  printf '%s\t%s\n' "$endpoint" "$(curl --silent --show-error --output /dev/null --max-time 12 --write-out '%{http_code}' "$endpoint" 2>/dev/null || true)" >> "$out/egress.txt"
 done
 # A proxy is reported by PRESENCE and origin only: a proxy URL may carry
 # user:password@, which must never reach this document (proxy_file_check
 # refuses one at the site input for the same reason). Through
 # url_origin_only, the one function -- the hand-made cut before it dropped
 # the userinfo, the scheme and the path and KEPT the query and the fragment
 # (an init report carried `proxy.example?REVIEW_PROXY_QUERY_SECRET`)
 # [review B2]. A proxy variable may omit its scheme: one is lent for
 # the parse and taken back, so the field keeps its host[:port] shape; an
 # authority that is not a host is named by the function's fixed words.
 local proxy_set proxy_origin=''
 proxy_set=$( [[ -n ${HTTPS_PROXY:-${https_proxy:-${HTTP_PROXY:-${http_proxy:-}}}} ]] && printf true || printf false)
 if [[ $proxy_set == true ]]; then
   proxy_origin=${HTTPS_PROXY:-${https_proxy:-${HTTP_PROXY:-${http_proxy:-}}}}
   [[ $proxy_origin == *://* ]] || proxy_origin="http://$proxy_origin"
   proxy_origin=$(url_origin_only "$proxy_origin"); proxy_origin=${proxy_origin#*://}
 fi
 jq -n --arg context "$CONTEXT" --arg platform "$GSJ_PLATFORM" --arg helm "$(helm version --short 2>/dev/null || printf unknown)" --argjson cores "$cores" --arg ram "$ram" --arg disk "$disk" --slurpfile versions "$out/version.json" --slurpfile nodes "$out/nodes.json" --slurpfile pods "$out/pods.json" --slurpfile pvcs "$out/persistentvolumeclaims.json" --slurpfile pvs "$out/persistentvolumes.json" --slurpfile classes "$out/storageclasses.json" --slurpfile ingress "$out/ingressclasses.json" --rawfile usage "$out/live-usage.txt" \
   --arg kubectl_floor "$GSJ_KUBECTL_FLOOR" --arg helm_floor "$GSJ_HELM_FLOOR" --arg jq_floor "$GSJ_JQ_FLOOR" \
   --arg jq_version "$(jq --version 2>/dev/null || printf unknown)" \
   --arg host_os "$host_os" --arg host_kernel "$host_kernel" --arg host_arch "$host_arch" --arg host_cgroup "$host_cgroup" \
   --arg host_root "$host_root" --arg host_sudo "$host_sudo" --arg host_docker "$host_docker" --arg host_buildx "$host_buildx" \
   --arg proxy_set "$proxy_set" --arg proxy_origin "$proxy_origin" \
   --slurpfile namespaces "$out/namespaces.json" --slurpfile services "$out/services.json" \
   --slurpfile ingresses "$out/ingresses.json" --slurpfile policies "$out/networkpolicies.json" \
   --slurpfile daemonsets "$out/daemonsets.json" --slurpfile deployments "$out/deployments.json" \
   --slurpfile crds "$out/customresourcedefinitions.json" --slurpfile localpath "$out/local-path.json" \
   --rawfile releases "$out/helm-releases.txt" --rawfile filesystems "$out/filesystems.txt" --rawfile egress "$out/egress.txt" '
   def meta: {name:.metadata.name,namespace:.metadata.namespace,uid:.metadata.uid,
     creationTimestamp:.metadata.creationTimestamp,deletionTimestamp:.metadata.deletionTimestamp};
   def topology:
     {key,operator} +
     (if (.key|IN("kubernetes.io/hostname","kubernetes.io/os","kubernetes.io/arch",
                  "topology.kubernetes.io/zone","topology.kubernetes.io/region","metadata.name"))
      then {values:(.values // [])} else {value_count:((.values // [])|length)} end);
   def inventory(filter):
     if .unavailable==true then {unavailable:true,reason:.reason}
     else {items:[.items[]? | filter]} end;
   # Bound once, read twice below (readable/denied): which probes of this run
   # actually answered. A jq object cannot reference its own sibling key, so
   # this has to be a variable rather than a field.
   # (No apostrophes: this jq program is a single-quoted shell string.)
   [{name:"version",ok:(($versions[0].unavailable // false)|not)},
    {name:"nodes",ok:(($nodes[0].unavailable // false)|not)},
    {name:"pods",ok:(($pods[0].unavailable // false)|not)},
    {name:"persistentvolumeclaims",ok:(($pvcs[0].unavailable // false)|not)},
    {name:"persistentvolumes",ok:(($pvs[0].unavailable // false)|not)},
    {name:"storageclasses",ok:(($classes[0].unavailable // false)|not)},
    {name:"ingressclasses",ok:(($ingress[0].unavailable // false)|not)},
    {name:"namespaces",ok:(($namespaces[0].unavailable // false)|not)},
    {name:"services",ok:(($services[0].unavailable // false)|not)},
    {name:"ingresses",ok:(($ingresses[0].unavailable // false)|not)},
    {name:"networkpolicies",ok:(($policies[0].unavailable // false)|not)},
    {name:"daemonsets",ok:(($daemonsets[0].unavailable // false)|not)},
    {name:"deployments",ok:(($deployments[0].unavailable // false)|not)},
    {name:"customresourcedefinitions",ok:(($crds[0].unavailable // false)|not)},
    {name:"helm-release-labels",ok:($releases|test("GSJ-DENIED")|not)},
    {name:"local-path-configuration",ok:(($localpath[0].unavailable // false)|not)}] as $probes |
   {schema:"gsj.inspect/1",context:$context,
    installer_host:{platform:$platform,capacity_scope:"OS-visible capacity; container quotas are not measured here",cores:$cores,memory_bytes:$ram,filesystem_available_bytes:$disk},
    helm:$helm,kubernetes:$versions[0],
    nodes:($nodes[0].items // [] | map({name:.metadata.name,uid:.metadata.uid,os:.status.nodeInfo.osImage,
      architecture:.status.nodeInfo.architecture,kernel:.status.nodeInfo.kernelVersion,kubelet:.status.nodeInfo.kubeletVersion,
      capacity:.status.capacity,allocatable:.status.allocatable,conditions:.status.conditions})),
    requested_by_pods:($pods[0].items // [] | map({namespace:.metadata.namespace,name:.metadata.name,node:.spec.nodeName,
      phase:.status.phase,containers:[.spec.containers[]|{name,resources}],initialization:[.spec.initContainers[]?|{name,resources}]})),
    claims:($pvcs[0]|inventory({metadata:meta,
      spec:{storageClassName:.spec.storageClassName,volumeName:.spec.volumeName,volumeMode:.spec.volumeMode,
        accessModes:.spec.accessModes,resources:{requests:{storage:.spec.resources.requests.storage}}},
      status:{phase:.status.phase,capacity:{storage:.status.capacity.storage},allocatedResources:{storage:.status.allocatedResources.storage},
        conditions:[.status.conditions[]?|{type,status}]}})),
    volumes:($pvs[0]|inventory({metadata:meta,
      spec:{storageClassName:.spec.storageClassName,volumeMode:.spec.volumeMode,accessModes:.spec.accessModes,
        capacity:{storage:.spec.capacity.storage},persistentVolumeReclaimPolicy:.spec.persistentVolumeReclaimPolicy,
        claimRef:(if .spec.claimRef then .spec.claimRef|{namespace,name,uid,kind} else null end),
        backend_sources:(.spec|keys|map(select(IN("csi","local","hostPath","nfs","iscsi","rbd","cephfs","flexVolume",
          "awsElasticBlockStore","azureDisk","azureFile","gcePersistentDisk","vsphereVolume","fc")))),
        csi:(if .spec.csi then .spec.csi|{driver,fsType,readOnly,volume_attribute_names:((.volumeAttributes // {})|keys)} else null end),
        nodeAffinity:{required:{nodeSelectorTerms:[.spec.nodeAffinity.required.nodeSelectorTerms[]?|
          {matchExpressions:[.matchExpressions[]?|topology],matchFields:[.matchFields[]?|topology]}]}}},
      status:{phase:.status.phase}})),
    storage_classes:($classes[0]|inventory({metadata:meta,provisioner,reclaimPolicy,volumeBindingMode,allowVolumeExpansion,
      is_default:((.metadata.annotations["storageclass.kubernetes.io/is-default-class"]=="true") or
                  (.metadata.annotations["storageclass.beta.kubernetes.io/is-default-class"]=="true")),
      parameter_names:((.parameters // {})|keys),
      allowedTopologies:[.allowedTopologies[]?|{matchLabelExpressions:[.matchLabelExpressions[]?|topology]}]})),
    ingress_classes:($ingress[0]|inventory({metadata:meta,
      is_default:(.metadata.annotations["ingressclass.kubernetes.io/is-default-class"]=="true"),
      spec:{controller:.spec.controller,parameters:(if .spec.parameters then .spec.parameters|{apiGroup,kind,name,scope,namespace} else null end)}})),
    # The ingress controller belongs to the CLUSTER, not to this installer: the
    # reuse profile requires one to exist already. State that verdict outright
    # instead of making the operator infer it from an empty inventory list.
    # (No apostrophes here: this jq program is a single-quoted shell string.)
    ingress_available:($ingress[0]|
      if .unavailable==true then {ready:false,reason:.reason}
      elif ((.items|length)==0) then {ready:false,reason:"no IngressClass: this cluster provides no ingress controller"}
      else {ready:true,classes:[.items[].metadata.name]} end),
    node_live_usage:$usage,

    # ---- THE ENVIRONMENT PROFILE -------------------------------------------
    # One structured document the consumer can send back, from which a
    # rehearsal cluster shaped like theirs can be stood up. Every field below
    # was chosen because a DIFFERENCE in it changed something about a real
    # install on one of two real clusters; UNKNOWN is always spelled out
    # rather than guessed.
    profile:{
      schema:"gsj.environment-profile/1",
      # WHAT THIS RUN COULD ACTUALLY SEE. Without this, a scoped read-only token
      # and an empty cluster are indistinguishable: every section below would
      # say 0% committed, no StorageClasses, no NodePorts taken, no namespaces
      # -- and an operator would size PVCs and pick ports on that basis. So
      # absence is never allowed to read as emptiness.
      access:{scope:"what the token running inspect could read; a denied read is NOT an empty cluster",
        readable:[$probes[]|select(.ok)|.name],
        denied:[$probes[]|select(.ok|not)|.name],
        complete:($probes|all(.ok))},
      excluded:"Deliberately absent, because a profile is sent to us and must not carry the consumer secrets: no Secret data of any kind (the Helm release inventory is read through custom-columns, which cannot emit a release payload); no annotation, label or StorageClass parameter VALUES, only their names; no PersistentVolume backend paths, handles or server addresses; no kubeconfig, token, certificate or credential; no proxy userinfo (origin only); no pod environment values; no container image registry credentials. DELIBERATELY PRESENT, and named here so the exclusion above is not read as covering them: the directory the local-path provisioner writes claims into, the mountpoint and free/total bytes of the filesystem carrying it, and the host filesystem inventory -- the node-root capacity wall cannot be assessed without them. Node, namespace and Helm release NAMES are kept too, because the rehearsal needs the shape and the collisions.",

      host:{scope:"the machine running this installer, which is NOT necessarily a cluster node",
        os:$host_os,kernel:$host_kernel,architecture:$host_arch,cgroup_version:$host_cgroup,
        is_root:($host_root=="true"),passwordless_sudo:($host_sudo=="true"),
        container_runtime:{docker_server:$host_docker,buildx:($host_buildx=="true")},
        cores:$cores,memory_bytes:($ram|tonumber? // 0),
        filesystems:[$filesystems|rtrimstr("\n")|split("\n")[]|select(length>0)|split("\t")|
          {mountpoint:.[0],total_bytes:(.[1]|tonumber? // 0),available_bytes:(.[2]|tonumber? // 0)}],
        installed_clients:{helm:{version:$helm,floor:$helm_floor},
          kubectl:{version:($versions[0].clientVersion.gitVersion // "unknown"),floor:$kubectl_floor},
          jq:{version:$jq_version,floor:$jq_floor}}},

      kubernetes:{
        server_version:($versions[0].serverVersion.gitVersion // "unknown"),
        client_version:($versions[0].clientVersion.gitVersion // "unknown"),
        # The distribution decides more than the version does: k3s brings
        # kube-router (which REJECTS a denied NetworkPolicy rather than
        # dropping) and its own ServiceLB, and both measured boxes are k3s.
        distribution:(($nodes[0].items[0].status.nodeInfo.kubeletVersion // "") as $k |
          if ($k|test("k3s")) then "k3s" elif ($k|test("rke2")) then "rke2"
          elif ($k|test("eks")) then "eks" elif ($k|test("gke")) then "gke"
          elif ($k|test("aks")) then "aks"
          elif (($crds[0].items? // [])|any(.metadata.name|test("openshift"))) then "openshift"
          elif ($k=="") then "unknown" else "kubeadm-or-other" end),
        node_count:(($nodes[0].items // [])|length),
        control_plane_nodes:[($nodes[0].items // [])[]|select(((.metadata.labels // {})|keys|any(test("node-role.kubernetes.io/(control-plane|master)"))))|.metadata.name],
        single_node:((($nodes[0].items // [])|length)==1),
        container_runtimes:[($nodes[0].items // [])[]|.status.nodeInfo.containerRuntimeVersion]|unique,
        node_os_images:[($nodes[0].items // [])[]|.status.nodeInfo.osImage]|unique},

      # capacity is not headroom: a box with 192 cores mostly committed is not
      # a box with 192 cores, so requests already booked are summed here.
      compute:{
        # .metadata.name is bound FIRST: inside the pod comprehension below the
        # dot is the POD, so a node filter written as .spec.nodeName==.spec.nodeName
        # compares a pod with itself and every node carried the whole cluster.
        nodes:[($nodes[0].items // [])[]|.metadata.name as $node|{name:$node,
          capacity_cpu:.status.capacity.cpu,allocatable_cpu:.status.allocatable.cpu,
          capacity_memory:.status.capacity.memory,allocatable_memory:.status.allocatable.memory,
          capacity_ephemeral_storage:.status.capacity["ephemeral-storage"],
          allocatable_ephemeral_storage:.status.allocatable["ephemeral-storage"],
          evicted_pods:[($pods[0].items? // [])[]|select(.spec.nodeName==$node)|select((.status.reason // "")=="Evicted")|.metadata.name]}],
        # ALREADY COMMITTED. Capacity is not headroom: 192 cores mostly booked
        # is not 192 cores. Kubernetes quantity strings mix spellings, so both
        # are normalised here -- cpu to millicores, memory to bytes.
        already_requested:(
          def millicores: if .=="" or .==null then 0
            elif (.|test("m$")) then (.|rtrimstr("m")|tonumber? // 0)
            else ((.|tonumber? // 0)*1000) end;
          def bytes: if .=="" or .==null then 0
            elif (.|test("Ki$")) then ((.|rtrimstr("Ki")|tonumber? // 0)*1024)
            elif (.|test("Mi$")) then ((.|rtrimstr("Mi")|tonumber? // 0)*1048576)
            elif (.|test("Gi$")) then ((.|rtrimstr("Gi")|tonumber? // 0)*1073741824)
            elif (.|test("Ti$")) then ((.|rtrimstr("Ti")|tonumber? // 0)*1099511627776)
            elif (.|test("Pi$")) then ((.|rtrimstr("Pi")|tonumber? // 0)*1125899906842624)
            elif (.|test("Ei$")) then ((.|rtrimstr("Ei")|tonumber? // 0)*1152921504606846976)
            elif (.|test("k$"))  then ((.|rtrimstr("k")|tonumber? // 0)*1000)
            elif (.|test("M$"))  then ((.|rtrimstr("M")|tonumber? // 0)*1000000)
            elif (.|test("G$"))  then ((.|rtrimstr("G")|tonumber? // 0)*1000000000)
            elif (.|test("T$"))  then ((.|rtrimstr("T")|tonumber? // 0)*1000000000000)
            elif (.|test("P$"))  then ((.|rtrimstr("P")|tonumber? // 0)*1000000000000000)
            elif (.|test("E$"))  then ((.|rtrimstr("E")|tonumber? // 0)*1000000000000000000)
            else (.|tonumber? // 0) end;
          [($pods[0].items? // [])[]|select(((.status.phase // "")|IN("Running","Pending")))] as $live |
          [($nodes[0].items // [])[]|.status.allocatable] as $alloc |
          ([$live[]|(.spec.containers // [])[]|(.resources.requests.cpu // "")|millicores]|add // 0) as $cpu_req |
          ([$live[]|(.spec.containers // [])[]|(.resources.requests.memory // "")|bytes]|add // 0) as $mem_req |
          ([$alloc[]|(.cpu // "")|millicores]|add // 0) as $cpu_cap |
          ([$alloc[]|(.memory // "")|bytes]|add // 0) as $mem_cap |
          {pods_live:($live|length),
           cpu_requested_millicores:$cpu_req,cpu_allocatable_millicores:$cpu_cap,
           cpu_committed_percent:(if $cpu_cap>0 then (($cpu_req*100/$cpu_cap)|floor) else null end),
           memory_requested_bytes:$mem_req,memory_allocatable_bytes:$mem_cap,
           memory_committed_percent:(if $mem_cap>0 then (($mem_req*100/$mem_cap)|floor) else null end),
           note:"requests, not live usage: a container that requests nothing can still consume the node. node_live_usage carries kubectl top when the metrics API answers"}),
        pods_with_no_memory_limit:([($pods[0].items? // [])[]|select(any((.spec.containers // [])[]; (.resources.limits.memory // "")==""))|.metadata.name]|length)},

      storage:{
        classes:[($classes[0].items? // [])[]|{name:.metadata.name,provisioner:.provisioner,
          reclaim_policy:.reclaimPolicy,binding_mode:.volumeBindingMode,
          is_default:((.metadata.annotations["storageclass.kubernetes.io/is-default-class"]=="true") or
                      (.metadata.annotations["storageclass.beta.kubernetes.io/is-default-class"]=="true")),
          # local-path reclaims Delete, which is what made losing a PVC destructive.
          node_local:(.provisioner|test("local-path|no-provisioner|hostpath|openebs.io/local")),
          deletes_data_on_release:(.reclaimPolicy=="Delete")}],
        # THE /-VERSUS-/data DIFFERENCE. Where local-path actually writes
        # decided PVC sizing on one cluster (98G root) and transfer_path on
        # another.
        local_path_node_paths:($localpath[0]|
          if (.unavailable==true) then {known:false,reason:.reason}
          else [(.items? // [.])[]|(.data["config.json"] // .data.config // "")|
                 (fromjson? // {})|(.nodePathMap? // [])[]|
                 {node:(.node // "DEFAULT"),paths:(.paths|if type=="array" then . else [] end)}] as $map |
            if ($map|length)==0 then {known:false,reason:"no local-path nodePathMap was readable"}
            else {known:true,node_paths:$map,paths:[$map[]|.paths|if type=="array" then .[] else empty end]|unique} end end),
        # WHICH FILESYSTEM BACKS THE CLAIMS, AND WHAT IS LEFT ON IT. The single
        # most consequential storage fact measured so far: on one box local-path
        # wrote onto a 98 G node root and the PVC sizes had to be cut, on the
        # other onto a 19 T /data and they did not. Matched by longest mountpoint
        # prefix, and only meaningful when the installer host IS the node --
        # said so rather than assumed.
        claim_backing:(
          [$filesystems|rtrimstr("\n")|split("\n")[]|select(length>0)|split("\t")|
            {mountpoint:.[0],total_bytes:(.[1]|tonumber? // 0),available_bytes:(.[2]|tonumber? // 0)}] as $fs |
          [($localpath[0]|(.items? // [.])[]|(.data["config.json"] // .data.config // "")|
            (fromjson? // {})|(.nodePathMap? // [])[]|(.paths|if type=="array" then .[] else empty end))] as $paths |
          {scope:"resolved against the INSTALLER HOST filesystems; only the node itself can answer for a remote node",
           paths:[$paths[]|. as $path |
             # .mountpoint is bound FIRST: inside startswith(...) the dot is the
             # piped string, not the filesystem object, so .mountpoint there
             # indexes a string and jq refuses at run time.
             ([$fs[]|.mountpoint as $mount|
               select($mount=="/" or $path==$mount or ($path|startswith($mount+"/")))]
              |sort_by(.mountpoint|length)|last) as $best |
             if $best==null then {path:$path,filesystem:null,note:"no matching mountpoint on this host"}
             else {path:$path,filesystem:$best.mountpoint,
                   available_bytes:$best.available_bytes,total_bytes:$best.total_bytes} end]}),
        claims_bound:([($pvcs[0].items? // [])[]|select(.status.phase=="Bound")]|length),
        claims_retained_for_adoption:[($pvcs[0].items? // [])[]|
          select((.metadata.annotations["helm.sh/resource-policy"] // "")=="keep")|
          {namespace:.metadata.namespace,name:.metadata.name,storage:.spec.resources.requests.storage}]},

      networking:{
        # The CNI is NAMED from its own workload, never guessed from a label.
        cni:{workloads:[(($daemonsets[0].items? // [])+(($deployments[0].items? // [])))[]|
              select((.metadata.name|test("calico|cilium|flannel|kube-router|weave|kindnet|antrea|canal"))
                  or any((.spec.template.spec.containers // [])[]; (.image // "")|test("calico|cilium|flannel|kube-router|weave|kindnet|antrea")))|
              {namespace:.metadata.namespace,name:.metadata.name,
               images:[(.spec.template.spec.containers // [])[]|((.image // "")|split("@")[0]) // ""]}],
          policy_objects_present:(($policies[0].items? // [])|length),
          # k3s and rke2 run flannel and the kube-router NetworkPolicy
          # controller INSIDE the server process, so there is no CNI DaemonSet
          # to find. An empty workload list on those distributions is not
          # "no CNI" -- it is the built-in one, named from the distribution and
          # labelled as such, never passed off as an observation.
          in_process:((($nodes[0].items[0].status.nodeInfo.kubeletVersion // "")|test("k3s|rke2")) and
                      ([(($daemonsets[0].items? // [])+(($deployments[0].items? // [])))[]|
                        select((.metadata.name|test("calico|cilium|flannel|kube-router|weave|kindnet|antrea|canal")))]|length)==0),
          in_process_note:"on k3s/rke2 with no CNI workload listed, the CNI is the built-in flannel plus the kube-router NetworkPolicy controller, both inside the server process. Both measured boxes are this case.",
          # PROBED, NOT INFERRED -- and this run did not probe. Whether a denied
          # NetworkPolicy DROPS (the connection hangs) or REJECTS (it fails at
          # once) is the CNI implementation choice, not the policy, and reading
          # it off the CNI name is exactly the mistake that made a correctly
          # enforced k3s/kube-router policy fail a verifier which demanded a
          # hang. Determining it requires sending a packet from one pod to
          # another under a deny, which is a WRITE, and inspect never writes.
          denied_policy_behaviour:"unknown",
          denied_policy_behaviour_note:"not determined: deciding drop-vs-reject requires creating a probe pod pair and a deny policy, which inspect never does. The installer measures it during its own verification and records it as network-check.json deny_seconds; a rehearsal cluster on the same distribution reproduces it."},
        ingress:{
          classes:[($ingress[0].items? // [])[]|{name:.metadata.name,controller:.spec.controller,
            is_default:(.metadata.annotations["ingressclass.kubernetes.io/is-default-class"]=="true")}],
          controllers:[(($deployments[0].items? // [])+(($daemonsets[0].items? // [])))[]|
            select((.metadata.name|test("ingress|traefik|nginx|haproxy|contour|istio"))
                or any((.spec.template.spec.containers // [])[]; (.image // "")|test("ingress-nginx|traefik|haproxy|contour")))|
            {namespace:.metadata.namespace,name:.metadata.name,
             images:[(.spec.template.spec.containers // [])[]|((.image // "")|split("@")[0]) // ""]}],
          # Hosts and ports ALREADY OCCUPIED: on one cluster a shared nginx was
          # already serving another deployment, and on a second cluster
          # NodePort 30080 was taken.
          hosts_in_use:[($ingresses[0].items? // [])[]|(.spec.rules // [])[]|.host // empty]|unique,
          tls_hosts_in_use:[($ingresses[0].items? // [])[]|(.spec.tls // [])[]|(.hosts // [])[]]|unique,
          nodeports_allocated:[($services[0].items? // [])[]|(.spec.ports // [])[]|.nodePort // empty]|unique,
          load_balancer_services:[($services[0].items? // [])[]|select(.spec.type=="LoadBalancer")|
            {namespace:.metadata.namespace,name:.metadata.name,
             external_assigned:(((.status.loadBalancer.ingress // [])|length)>0)}],
          # A LoadBalancer that never gets an address is the ServiceLB gap
          # measured on a reference k3s cluster.
          load_balancer_satisfied:(([($services[0].items? // [])[]|select(.spec.type=="LoadBalancer")]|length) as $n |
            if $n==0 then "no LoadBalancer Service exists to judge by"
            elif ([($services[0].items? // [])[]|select(.spec.type=="LoadBalancer")|select(((.status.loadBalancer.ingress // [])|length)>0)]|length)==$n
            then "yes: every LoadBalancer Service has an address"
            else "no: a LoadBalancer Service is pending an address" end)},
        egress:{probed_from:"the installer host, not from inside the cluster",
          endpoints:[$egress|rtrimstr("\n")|split("\n")[]|select(length>0)|split("\t")|
            {url:.[0],http_status:.[1],reachable:(.[1]!="000")}],
          proxy_configured:($proxy_set=="true"),proxy_origin:$proxy_origin},
        tls:{cert_manager_present:(($crds[0].items? // [])|any(.metadata.name|test("cert-manager.io"))),
          cert_manager_workloads:[($deployments[0].items? // [])[]|select(.metadata.name|test("cert-manager"))|
            {namespace:.metadata.namespace,name:.metadata.name,
             images:[(.spec.template.spec.containers // [])[]|((.image // "")|split("@")[0]) // ""]}],
          issuer_kinds_available:[($crds[0].items? // [])[]|.metadata.name|select(test("issuers.cert-manager.io"))]}},

      # WHAT IS ALREADY THERE, and what would collide with a target release.
      occupancy:{
        namespaces:[($namespaces[0].items? // [])[]|.metadata.name],
        helm_releases_readable:($releases|test("GSJ-DENIED")|not),
        # ONE ROW PER RELEASE, not per revision. Helm keeps one labelled Secret
        # per revision, so a release with a long history would otherwise fill
        # this list and bury the collisions it exists to show (one measured box
        # returned 29 rows for 3 releases).
        helm_releases:([$releases|rtrimstr("\n")|split("\n")[]|select(length>0)|select(test("GSJ-DENIED")|not)|
          (split(" ")|map(select(length>0)))|select(length>=4)|
          {namespace:.[0],name:.[1],revision:.[2],status:.[3]}]
          |group_by(.namespace+"/"+.name)
          |map((max_by(.revision|tonumber? // 0)) as $latest |
               {namespace:$latest.namespace,name:$latest.name,
                revision:$latest.revision,status:$latest.status,
                revision_records:length})),
        gsj_like_releases:[$releases|rtrimstr("\n")|split("\n")[]|select(test("GSJ-DENIED")|not)|select(test("gsj"))|
          (split(" ")|map(select(length>0)))|select(length>=4)|{namespace:.[0],name:.[1]}]|unique,
        network_policies:[($policies[0].items? // [])[]|{namespace:.metadata.namespace,name:.metadata.name,
          policy_types:(.spec.policyTypes // [])}],
        custom_resource_groups:[($crds[0].items? // [])[]|.spec.group]|unique},

      rehearsal:{
        # What a rehearsal built from this profile does and does not prove.
        transfers:["the Kubernetes distribution and server version",
          "the StorageClass shape: provisioner, reclaim policy, binding mode, which is default, and whether it is node-local",
          "the presence or absence of an ingress controller and of cert-manager",
          "the CNI implementation, and with it the drop-versus-reject behaviour of a denied NetworkPolicy",
          "release and namespace name collisions",
          "the installers own logic end to end: every refusal, every ordering, every recovery path"],
        does_not_transfer:["their hardware: core count, memory, disk throughput and CPU microarchitecture",
          "their network latency, bandwidth and any corporate proxy or egress unlock",
          "multi-node scheduling and real ReadWriteOnce contention, which a single-node rehearsal cannot show",
          "the real free space on their filesystems and the node-root capacity wall that follows from it",
          "concurrent tenants competing for the same node, and a live deployment that must not be perturbed",
          "corpus import duration, which differed 1.54x between the two measured boxes for identical input and is still unexplained"],
        verdict:"a green rehearsal proves the install LOGIC, not the consumer environment"}},

    unknowns:["PVC requested/capacity bytes are not backend free space or enforced filesystem quotas",
      "Node allocated ephemeral storage does not measure a remote PVC backend",
      "Kubernetes nodes and the installer may share Docker VM resources; their capacities are not additive",
      "Admission, filesystem locking/fsync and NetworkPolicy require qualification",
      "Cluster telemetry/access gaps are preserved above",
      "Annotations, driver parameter values, backend paths/handles and nonstandard topology values are omitted"]}
 '
}
quantity_bytes() {
 # One Kubernetes memory quantity to bytes, or empty if it is not one.
 jq -rn --arg q "$1" '($q|capture("^(?<number>[0-9]+)(?<unit>Ki|Mi|Gi|Ti|)$")) as $c
   | ($c.number|tonumber) * ({"":1,"Ki":1024,"Mi":1048576,"Gi":1073741824,"Ti":1099511627776}[$c.unit])' 2>/dev/null || true
}
initializer_memory_check() {
 # The corpus initializer holds one shard at a time, so its
 # memory need is a property of the RELEASE's corpus, not of the site. The
 # release declares it (build.py, from its own corpus manifest's largest
 # shard); this refuses here -- before the Lease, before the first cluster
 # write -- when the site gives the container less than that, or when no node
 # the scheduler may use could place the Pods.
 #
 # Why this check exists at all: a full end-to-end run measured the shipped
 # default OOMKilled three shards in, and the operator was shown
 # `terminal-budget-exhausted` -- a message about a RETRY BUDGET, with
 # "OOMKilled" reachable only through the pod's lastState. An install that
 # cannot succeed must say so in its first seconds, in the units the
 # operator can act on.
 local nodes=$1 required declared node
 required=$(jq -r '.corpus.initializer_memory_bytes // empty' "$GSJ_PAYLOAD/release.json")
 # A release that does not declare a requirement is not second-guessed.
 [[ $required =~ ^[0-9]+$ ]] || return 0
 declared=$(quantity_bytes "$(j '.resources.initializer.limits.memory')")
 [[ $declared =~ ^[0-9]+$ ]] || fail "resources.initializer.limits.memory is not a Kubernetes memory quantity"
 (( declared >= required )) || fail "the corpus initializer needs $(( (required + 1048575) / 1048576 ))Mi for this release's corpus ($(jq -r '.corpus.max_shard_chunks' "$GSJ_PAYLOAD/release.json") chunks in its largest shard at $(jq -r '.model.dimensions' "$GSJ_PAYLOAD/release.json") dimensions), but resources.initializer.limits.memory is $(j '.resources.initializer.limits.memory'). Raise it in your site file. This is checked here because the import would otherwise be OOMKilled partway through and reported as a spent retry budget."
 # Everything below asks whether the SCHEDULER can place these Pods. Only an
 # operation that actually schedules them has a reason to ask: abandon, sweep,
 # every repair and every backup/restore verb run against Pods that are already
 # placed, and refusing those on capacity would block exactly the recovery an
 # operator reaches for when a node is full. preflight runs above the command
 # dispatch, so the gate has to be here.
 [[ $COMMAND == install || $COMMAND == upgrade ]] || return 0
 node=$(j .storage.node)
 local headroom pod_request init_request container_request best
 init_request=$(quantity_bytes "$(j '.resources.initializer.requests.memory')")
 container_request=$(( $(quantity_bytes "$(j '.resources.web.requests.memory')") \
                     + $(quantity_bytes "$(j '.resources.mcp.requests.memory')") \
                     + $(quantity_bytes "$(j '.resources.runner.requests.memory')") ))
 # Kubernetes sizes a Pod at max(largest init container, sum of containers) per
 # resource, because init containers run to completion before the others start.
 # The chart's web Pod has three init containers -- wait-deps (no request),
 # corpus-copy (256Mi, chart-fixed) and corpus-initialize (the site's
 # resources.initializer) -- and the initializer is the largest by construction,
 # which is why it alone stands in for the max here.
 pod_request=$(( init_request > container_request ? init_request : container_request ))
 pod_request=$(( pod_request + $(quantity_bytes "$(j '.resources.chroma.requests.memory')") \
                             + $(quantity_bytes "$(j '.resources.forgejo.requests.memory')") ))
 # One jq, one candidate set, one answer -- so the node whose allocatable is
 # read is always the node whose headroom is reported.
 #
 # A candidate node is schedulable: not cordoned, Ready, and carrying no
 # NoSchedule/NoExecute taint. Counting a drained node as room is a FALSE PASS,
 # and the operator would meet it again as an unschedulable Pod two minutes in.
 #
 # Pods in the TARGET namespace are excluded: this deployment is not its own
 # competition. On an upgrade its Pods are already placed and already hold the
 # request being tested -- measured, a repair on a proof deployment was refused
 # at 8377Mi free against 8448Mi needed, by its own 8448Mi. A fresh install's
 # namespace holds nothing, so this subtracts nothing in the case the check
 # exists for.
 #
 # Unparsed quantities count as zero, which can only make the check more
 # permissive, never less.
 best=$(k get pods -A -o json 2>/dev/null | jq -r --arg node "$node" --arg ns "$NAMESPACE" --slurpfile nodes <(printf '%s' "$nodes") '
   def qty: if . == null then 0 else
     (tostring | capture("^(?<n>[0-9]+)(?<u>Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E|)$")
      | (.n|tonumber) * ({"":1,"Ki":1024,"Mi":1048576,"Gi":1073741824,"Ti":1099511627776,
                          "Pi":1125899906842624,"Ei":1152921504606846976,
                          "k":1000,"M":1000000,"G":1000000000,"T":1000000000000,
                          "P":1000000000000000,"E":1000000000000000000}[.u]))
     // 0 end;
   ( [ .items[]
       | select(.status.phase=="Running" or .status.phase=="Pending")
       | select(.spec.nodeName != null)
       | select(.metadata.namespace != $ns)
       | { node: .spec.nodeName,
           want: ( ( [ .spec.containers[]?.resources.requests.memory | qty ] | add // 0 ) as $c
                 | ( [ .spec.initContainers[]?.resources.requests.memory | qty ] | max // 0 ) as $i
                 | if $i > $c then $i else $c end ) } ]
     | group_by(.node) | map({ key: .[0].node, value: ([.[].want] | add) }) | from_entries ) as $used
   | ( [ $nodes[0].items[] | select($node=="" or .metadata.name==$node) ] ) as $named
   | ( [ $named[]
       | select((.spec.unschedulable // false) | not)
       | select([.spec.taints[]? | select(.effect=="NoSchedule" or .effect=="NoExecute")] | length == 0)
       | select([.status.conditions[]? | select(.type=="Ready" and .status=="True")] | length > 0)
       # An allocatable figure this parser cannot read is not zero: reading it
       # as zero would refuse a node for having no memory at all. Drop it and
       # let the remaining candidates answer; if none remain, say so.
       | select(.status.allocatable.memory != null and (.status.allocatable.memory | qty) > 0)
       | { name: .metadata.name,
           alloc: (.status.allocatable.memory | qty),
           free: ((.status.allocatable.memory | qty) - ($used[.metadata.name] // 0)) } ] ) as $fit
   | if ($named | length) == 0 then "nosuchnode"
     elif ($fit | length) == 0 then "none"
     else ($fit | max_by(.free) | "\(.name) \(.alloc) \(.free)") end' 2>/dev/null || echo "")
 # Fails OPEN on purpose when the cluster-wide Pod list is unavailable -- a
 # namespace-scoped operator is a supported shape and must not be blocked by a
 # capacity check -- but never silently: an operator who is told nothing would
 # read the absence as a pass.
 if [[ -z $best ]]; then
   log "Schedulable-memory headroom was not checked: this credential could not list Pods cluster-wide. The install will still refuse later if the node cannot place these Pods, but it will refuse hours in rather than here"
   return 0
 fi
 [[ $best != nosuchnode ]] || fail "storage.node is set to \"$node\", which is not a node on this cluster. Run 'kubectl get nodes' and set it to one that exists"
 [[ $best != none ]] || fail "no schedulable node is available${node:+ matching storage.node $node}: every candidate is cordoned, not Ready, or carries a NoSchedule/NoExecute taint"
 local bname balloc
 bname=${best%% *}; best=${best#* }; balloc=${best%% *}; headroom=${best#* }
 [[ $balloc =~ ^-?[0-9]+$ && $headroom =~ ^-?[0-9]+$ ]] || return 0
 # A limit above the node's whole allocatable memory schedules (the scheduler
 # reads REQUESTS) and then cannot be honoured: the container is capped by the
 # machine, not by the limit it was given.
 (( balloc >= declared )) || fail "node $bname has $(( balloc / 1048576 ))Mi of allocatable memory in total, less than the $(j '.resources.initializer.limits.memory') resources.initializer.limits.memory gives the corpus initializer. The Pod would still be scheduled -- the scheduler reads requests, not limits -- and would then be capped by the machine rather than by that limit"
 (( headroom >= pod_request )) || fail "no node has room for this deployment: the most any candidate node ($bname) has left is $(( headroom / 1048576 ))Mi and this deployment's own resources block requests $(( pod_request / 1048576 ))Mi -- $(( (pod_request - $(quantity_bytes "$(j '.resources.chroma.requests.memory')") - $(quantity_bytes "$(j '.resources.forgejo.requests.memory')")) / 1048576 ))Mi for the application Pod, which is the larger of its init container and the sum of its containers, plus chroma and forgejo. Free requests on a node or give storage.node one that has room. This is the SCHEDULER's arithmetic over what other Pods have RESERVED, not free memory: a node can be mostly idle and still refuse to place these Pods"
}
# The two model endpoints, probed from THIS host in the install's first minute:
# advisory, never a refusal. What decides whether their acceptance checks run
# is the probe the verifier makes from inside the cluster at acceptance
# (gsj_deploy/verify.py probe_endpoints); this one tells the operator now what
# that one will most likely find, and records it (endpoint-preflight.json).
# An endpoint left out of the site file is reported as absent without a
# request; a configured one gets the request the application makes -- the
# models route for the LLM, and for OCR the application's own recognition
# request on a small image of the words AKTE 58203, whose answer must contain
# 58203 (the guide's step-0 block, verbatim in its logic). A credential file
# rides as a header read from a private file, never on a command line.
GSJ_OCR_PROBE_PNG=iVBORw0KGgoAAAANSUhEUgAAATcAAABDAQAAAADRnX/8AAACLklEQVR42u2VMW7cMBBFHykhUpVVuu2sI+wBnJhHyRFSuooHCBDkGDkKj6Aj0F1KGXDBNbicFJS00tqFU6XZ6QR8/uH8+V80yntKLe+rK+6K+1fcsUVrHnfGmM/GGDgZw1OHWnh0HNsNX+g2BMMzL+r4PfDnBaiBmAD8tpE/EQkqDUEBVHWsNFfKF+AWUE2g8BDYJSoVHjRbgAwobhMIIBAhI/hyv7FgZQElyJX3Hgrzeo5kjIr6RqcA1j3cJxrFhFBwQYG4VvJGaTvkJ3Ev2G7m88BYv9LWAJDrc1+B0PIm0P2QGecB/ErmyHyaHu5nnOkB6V/RfZ+koJ/7etjI98nZOM6SMEx8AuhKPhgGUpgPqnMFZ7uzzEdjAZ7Nyck0KghYUAiXV8uI2Yx9VnfllxFwFlILkLXwUbcjF5yKP0HsFgpb3HJRN6ggkyrVvF8ADuMK14tU3hOKpvsRLCSIi3yNZtg7l+tDwLvLHMGveKZrBFpQKVrVy7wJQ9rcMNGSq/O+7bR1+9pWY6rfyvlq7Kdph8Vq3RmXwa4enGFq19EFTnHCjSvzrnfTjT3ghdQWvruSnbNhejzEeUMplpz7OyVXKncqmhpV1bAjNeONUMWGbMKu5NytqI7GCN0TpKEv32jfLfMKuLURjD05BGows+99WdoqHy12CYJlyZtMCV5wNbURBLDUuPn/UqqLK/FbnFHASEs/+Vk2PQGM/8bhIwBfD+w/AOb67l9x/xH3F0Tp4vsISHl9AAAAAElFTkSuQmCC
endpoint_probe_header() {
 # Authorization: Bearer <the credential file's contents>, in a 0600 file
 # curl reads with --header @FILE; empty when the endpoint has no credential.
 local role=$1 file; file=$(j ".$role.credential.file"); [[ -n $file ]] || return 0
 file=$(resolve_file "$file"); private_file "$file"
 { printf 'Authorization: Bearer '; tr -d '\r\n' < "$file"; printf '\n'; } | atomic "$GSJ_WORK/endpoint-$role.header"
 printf '%s' "$GSJ_WORK/endpoint-$role.header"
}
endpoint_preflight() {
 local base url model header rc code state llm ocr said answer
 llm=absent; ocr=absent
 base=$(j .llm.base_url)
 if [[ -n $base ]]; then
   header=$(endpoint_probe_header llm); rc=0
   code=$(curl -sS --connect-timeout 10 --max-time 20 -o "$GSJ_WORK/endpoint-llm.json" -w '%{http_code}' ${header:+--header "@$header"} "${base%/}/models" 2>"$GSJ_WORK/endpoint-llm.err") || rc=$?
   if (( rc != 0 )); then llm=unreachable; elif [[ $code != 200 ]]; then llm="refused (HTTP $code)"; elif ! jq -e --arg m "$(j .llm.model)" '(.data|type)=="array" and any(.data[]; .id==$m)' "$GSJ_WORK/endpoint-llm.json" >/dev/null 2>&1; then llm="answers, but does not list llm.model"; else llm=working; fi
 fi
 url=$(j .ocr.url); model=$(j .ocr.model)
 if [[ -n $url ]]; then
   header=$(endpoint_probe_header ocr); rc=0
   jq -n --arg model "$model" --arg png "$GSJ_OCR_PROBE_PNG" '{model:$model,max_tokens:2048,messages:[{role:"user",content:[{type:"image_url",image_url:{url:("data:image/png;base64,"+$png)}},{type:"text",text:"Text Recognition:"}]}]}' > "$GSJ_WORK/endpoint-ocr-request.json"
   code=$(curl -sS --connect-timeout 10 --max-time 90 -o "$GSJ_WORK/endpoint-ocr.json" -w '%{http_code}' -H 'Content-Type: application/json' ${header:+--header "@$header"} -d "@$GSJ_WORK/endpoint-ocr-request.json" "$url" 2>"$GSJ_WORK/endpoint-ocr.err") || rc=$?
   if (( rc == 28 )); then ocr="no answer within 90 s"; elif (( rc != 0 )); then ocr=unreachable; elif [[ $code != 200 ]]; then ocr="refused (HTTP $code)";
   else
     answer=$(jq -r '(.choices[0].message.content // null) | if type=="array" then map(strings // (.text? | strings) // "") | join("") elif . == null then "" else tostring end' "$GSJ_WORK/endpoint-ocr.json" 2>/dev/null) || answer=''
     if ! jq -e '.choices[0].message | type=="object" and has("content")' "$GSJ_WORK/endpoint-ocr.json" >/dev/null 2>&1; then ocr="answers, but not as a chat-completions route"
     elif [[ $(printf '%s' "$answer" | tr -d ' \t\r\n') == *58203* ]]; then ocr=working
     else ocr="answered without the test image's text (did not read it)"; fi
   fi
 fi
 rm -f "$GSJ_WORK/endpoint-llm.header" "$GSJ_WORK/endpoint-ocr.header"
 jq -n --arg llm "$llm" --arg ocr "$ocr" --arg host "$(hostname 2>/dev/null || printf unknown)" '{format:"gsj.endpoint-preflight/1",probed_from:$host,llm:$llm,ocr:$ocr}' | atomic "$STATE_DIR/endpoint-preflight.json"
 case $llm in
   absent) log 'LLM endpoint: none in the site file. The install will complete; acceptance skips agent-turn-note-history and generated-document, and the agent cannot answer until an endpoint is set (per case under Einstellungen, or llm.base_url/llm.model here and install again)';;
   working) log "LLM endpoint $(url_origin_only "$base"): answers from this host and lists $(j .llm.model)";;
   *) log "LLM endpoint $(url_origin_only "$base"): $llm from this host$(if [[ -n $(j .llm.credential.secret) ]]; then printf ' (its credential is a Secret in the cluster, which this host did not send)'; fi). If it does not answer from inside the cluster either, acceptance skips agent-turn-note-history and generated-document and the agent cannot answer until it does; the install completes either way";;
 esac
 case $ocr in
   absent) log 'OCR endpoint: none in the site file. The install will complete; acceptance skips scanned-ingest-search, and scanned pages are not read until ocr.url names a vision-capable endpoint and install runs again';;
   working) log "OCR endpoint $(url_origin_only "$url"): read the test image from this host";;
   "answered without"*) log "OCR endpoint $(url_origin_only "$url"): answered HTTP 200 from this host but did not read the test image. Acceptance will skip scanned-ingest-search, and the application would store whatever this endpoint answers as the text of a scanned page: replace it before anyone uploads scanned files";;
   *) log "OCR endpoint $(url_origin_only "$url"): $ocr from this host$(if [[ -n $(j .ocr.credential.secret) ]]; then printf ' (its credential is a Secret in the cluster, which this host did not send)'; fi). If it does not read the verifier's page from inside the cluster either, acceptance skips scanned-ingest-search and scanned pages are not read until it does; the install completes either way";;
 esac
}
preflight() {
 k cluster-info >/dev/null
 local platform nodes pull server
 # The server floor, asserted HERE so a too-old cluster is refused before the
 # first write rather than by Helm after the Lease, the Secrets and the add-ons.
 # `|| true` inside the substitution: under `set -Eeuo pipefail` a kubectl that
 # cannot answer `version` would otherwise make this ASSIGNMENT abort preflight
 # outright rather than leave $server empty. An unreadable server version must
 # skip the floor check, not kill the run -- the same trap that cost 43 test
 # regressions in client_version.
 server=$( { k version -o json 2>/dev/null || true; } | jq -r '.serverVersion.gitVersion // ""' 2>/dev/null || true)
 [[ -z $server ]] || version_at_least "${server#v}" "$GSJ_SERVER_FLOOR" \
   || fail "requires Kubernetes >= $GSJ_SERVER_FLOOR, found $server. This release selects the provisioning Job by batch.kubernetes.io/job-name, a label the Job controller stamps only from 1.27; on an older server that Job is silently denied its dependencies by a NetworkPolicy that matches nothing."
 nodes=$(k get nodes -o json)
 platform=$(jq -r --arg node "$(j .storage.node)" '[.items[]|select($node=="" or .metadata.name==$node)|"linux/"+.status.nodeInfo.architecture]|unique|.[]' <<< "$nodes")
 initializer_memory_check "$nodes"
 [[ -n $platform ]] || fail 'selected storage node is unavailable'
 while IFS= read -r nodes; do jq -e --arg p "$nodes" '.platforms | index($p)' "$GSJ_PAYLOAD/release.json" >/dev/null || fail "release has no qualified native images for $nodes"; done <<< "$platform"
 for permission in 'get pods' 'create pods' 'create secrets' 'create configmaps' 'create leases.coordination.k8s.io' 'patch deployments.apps' 'create jobs.batch' 'get persistentvolumeclaims' 'create persistentvolumeclaims' 'create networkpolicies.networking.k8s.io'; do
   read -r verb resource <<< "$permission"; [[ $(k auth can-i "$verb" "$resource") == yes ]] || fail "missing deployment permission: $permission"
 done
 # A referenced pull Secret is never created here. Refuse before the first
 # write instead of after image pulls back off; restore recreates it.
 pull=$(j .registry.pull_secret)
 if [[ -n $pull && -z $(j .registry.config_file) && $COMMAND != restore && $COMMAND != restore-repair ]]; then
   k get secret "$pull" -o json 2>/dev/null | jq -e '(.type=="kubernetes.io/dockerconfigjson" and (.data[".dockerconfigjson"]|type=="string" and length>0)) or (.type=="kubernetes.io/dockercfg" and (.data[".dockercfg"]|type=="string" and length>0))' >/dev/null || fail "registry.pull_secret must name an existing image pull Secret in namespace $NAMESPACE; create it or set registry.config_file"
 fi
 registry_base_preflight
 [[ $(j .storage.profile) != reuse ]] || k get storageclass "$(j .storage.class)" -o json > "$STATE_DIR/storage-class.json"
 if [[ $(j .ingress.profile) == reuse ]]; then k get ingressclass "$(j .ingress.class)" -o json > "$STATE_DIR/ingress-class.json"; fi
 # Enforce the supported single-node, SQLite-compatible storage profile explicitly.
 if [[ $(j .storage.profile) == reuse ]]; then
   jq -e '.provisioner | IN("rancher.io/local-path","rancher.io/gsj-local-path","kubernetes.io/no-provisioner")' "$STATE_DIR/storage-class.json" >/dev/null || fail 'storage driver needs SQLite/fsync/locking qualification; only qualified local-path/static-local profiles are admitted'
   [[ $(j .storage.node) != '' ]] || fail 'SQLite local storage requires an explicit placement node'
 fi
}
lease_still_live() {
 # Every "still live" refusal states what it measured: the Lease was renewed
 # $2 s ago, and 180 s unrenewed is the rule. After a failure that is simply
 # the retained Lease of a dead process -- a clock, not a fault -- the
 # operator used to look for a process to stop.
 local who=$1 age=$2 rest=${3:-} renewed
 # A renewal time ahead of this clock is a skew between the renewing host and
 # this one, said as that; the admission check measures the age against this
 # clock, so the wait it needs is 180 s from that renewal time -- the skew
 # included, never counted from zero.
 if (( age < 0 )); then renewed="its renewal time is ahead of this clock by $(( -age )) s (a clock skew between the renewing host and this one)"
 else renewed="its Lease was renewed $age s ago"; fi
 fail "$who is still live: $renewed, and a Lease must go 180 s unrenewed. If no installer process is running against this target, wait $(( 180 - age )) s and run the same command again; if one is running, stop it first${rest:+ ($rest)}"
}
lease_read() { k get lease "$RELEASE-operation" -o json --ignore-not-found; }
proxy_file_check() {
 # The proxy Secret reaches the agent runner's
 # container, and the runtime strips a proxy URL's user:password@ from the pi
 # subprocess env so the agent's shell never sees it — an authenticating proxy
 # therefore cannot serve the model endpoint. Refuse it at the site input.
 # ANY `@` is refused: a proxy URL has no legitimate `@` outside its userinfo,
 # and the scheme-less `user:password@host:port` form — which curl and
 # Python's urllib both honour — carries no `://` for a scheme-anchored test
 # to find.
 jq -e 'all(.HTTP_PROXY,.HTTPS_PROXY; contains("@")|not)' "$1" >/dev/null || fail 'proxy_file URLs must not carry credentials (user:password@host, with or without a scheme): the agent runtime strips them from the model client, so an authenticating proxy cannot reach the model endpoint; use an unauthenticated or address-allowlisted proxy'
}
refuse_foreign_release() {
 # A namespace already holding a Helm release of the
 # target name that this installer did not create — Helm history present, no
 # installer record — is never taken over. The compiled fullnameOverride
 # would rename every resource and Helm would drop the old PVCs with their
 # data (measured: corpus, SQLite and repositories gone). Refused before the
 # Lease and before any write but the namespace itself, naming what was
 # found. Helm keeps release history in Secrets OR ConfigMaps depending on
 # the ambient HELM_DRIVER the guarded apply would inherit, so both are read
 # (as the add-on history reads do). Called from acquire for a fresh install
 # and from resume for an owned install that has not applied yet; the kind
 # argument names the operation being continued.
 local kind=${1:-$COMMAND} history count latest
 [[ $kind == install && ! -s $GSJ_WORK/installed.json ]] || return 0
 history=$(k get secrets,configmaps -l "owner=helm,name=$RELEASE" -o json | jq '[.items[]|select(.kind=="ConfigMap" or .type=="helm.sh/release.v1")]')
 count=$(jq 'length' <<< "$history"); (( count > 0 )) || return 0
 latest=$(h history "$RELEASE" --output json 2>/dev/null | jq -r 'if type=="array" and length>0 then (last|"revision \(.revision), chart \(.chart // "?"), status \(.status // "?")") else empty end') || latest=''
 [[ -n $latest ]] || latest=$(jq -r 'sort_by(.metadata.labels.version|tonumber)|last|"revision \(.metadata.labels.version), status \(.metadata.labels.status // "?")"' <<< "$history")
 fail "an existing Helm release has no installer record: $RELEASE in namespace $NAMESPACE ($count Helm revision(s); $latest). This installer never adopts a release it did not create: choose another release name or namespace, or manage that release with the tooling that installed it"
}
assert_owner() {
 [[ -f $STATE_DIR/lease-lost ]] && fail 'operation ownership lost; initialization keeps its own volume lock'
 [[ $(lease_read | jq -r '.spec.holderIdentity // ""') == "$OPERATION" ]] || fail 'operation ownership changed'
}
stage_operation_config() {
 assert_owner
 cat "$SITE" | atomic "$STATE_DIR/site.pending.json"
 cat "$GSJ_WORK/values.pending.json" | atomic "$STATE_DIR/values.pending.json"
}
create_operation_intent() {
 local current=$1 now=$2 directory="$STATE_DIR/operation-intents/$OPERATION" uid source archive='null'
 [[ $OPERATION =~ ^[a-f0-9]{24}$ ]] || fail 'invalid operation intent identity'
 [[ ! -L $STATE_DIR/operation-intents ]] || fail 'operation intent directory is a symlink'
 mkdir -p "$STATE_DIR/operation-intents"; chmod 700 "$STATE_DIR/operation-intents"; sync "$STATE_DIR"
 mkdir -m 700 "$directory" || fail 'operation intent already exists'
 sync "$STATE_DIR/operation-intents"
 for source in "$SITE" "$GSJ_WORK/values.pending.json" "$GSJ_PAYLOAD/release.json"; do
   [[ -f $source && ! -L $source ]] || fail 'operation intent input must be a regular file'
 done
 uid=$(k get namespace "$NAMESPACE" -o json | jq -er '.metadata.uid|select(type=="string" and length>0)') || fail 'operation namespace identity is unavailable'
 cat "$SITE" | immutable_file "$directory/site.json"
 cat "$GSJ_WORK/values.pending.json" | immutable_file "$directory/values.json"
 cat "$GSJ_PAYLOAD/release.json" | immutable_file "$directory/release.json"
 if [[ $COMMAND == restore ]]; then
   [[ -n ${ARCHIVE:-} ]] || fail 'restore operation intent requires its validated archive'
   for source in "$ARCHIVE" "$ARCHIVE.resources.enc" "$ARCHIVE.json"; do
     [[ -f $source && ! -L $source ]] || fail 'restore operation archive must be a regular file'
   done
   archive=$(jq -n --arg path "$ARCHIVE" --arg sha "$(sha_file "$ARCHIVE")" --arg resources "$(sha_file "$ARCHIVE.resources.enc")" --arg metadata "$(sha_file "$ARCHIVE.json")" '{path:$path,sha256:$sha,resources_sha256:$resources,metadata_sha256:$metadata}')
 fi
 jq -n --arg id "$OPERATION" --arg target "$RELEASE_ID" --arg kind "$COMMAND" --arg context "$CONTEXT" --arg namespace "$NAMESPACE" --arg release "$RELEASE" --arg uid "$uid" --arg now "$now" --arg lease_uid "$(jq -r '.metadata.uid//""' <<< "$current")" --arg site "$(sha_file "$directory/site.json")" --arg values "$(sha_file "$directory/values.json")" --arg manifest "$(sha_file "$directory/release.json")" --argjson archive "$archive" '{format:"gsj.operation-intent/1",record:{operation:$id,target:$target,kind:$kind,status:"owned"},context:$context,namespace:$namespace,release:$release,namespace_uid:$uid,acquire_time:$now,prior_lease_uid:$lease_uid,site_sha256:$site,values_sha256:$values,release_sha256:$manifest,archive:$archive}' | immutable_file "$directory/intent.json"
 log "Prepared operation $OPERATION; its immutable intent survives an interrupted Lease response"
}
recover_operation_intent() {
 # Validate only stages private work files. The caller must win the Lease CAS
 # before promotion; this keeps competing readers from overwriting local state.
 local id=$1 mode=${2:-validate} directory current canonical uid age file
 [[ $id =~ ^[a-f0-9]{24}$ && ( $mode == validate || $mode == promote ) ]] || fail 'invalid operation intent recovery request'
 directory="$STATE_DIR/operation-intents/$id"
 [[ -d $directory && ! -L $directory && ! -L $STATE_DIR/operation-intents ]] || fail 'saved operation intent is unavailable'
 for file in intent.json site.json values.json release.json; do
   [[ -f $directory/$file && ! -L $directory/$file ]] || fail 'saved operation intent is incomplete'
 done
 jq -e --arg id "$id" --arg target "$RELEASE_ID" --arg context "$CONTEXT" --arg namespace "$NAMESPACE" --arg release "$RELEASE" '.format=="gsj.operation-intent/1" and .record.operation==$id and .record.target==$target and .record.status=="owned" and (.record.kind|IN("install","upgrade","backup","restore")) and .context==$context and .namespace==$namespace and .release==$release and (.namespace_uid|type=="string" and length>0)' "$directory/intent.json" >/dev/null || fail 'saved operation intent target differs'
 [[ $(sha_file "$directory/site.json") == $(jq -r .site_sha256 "$directory/intent.json") && $(sha_file "$directory/values.json") == $(jq -r .values_sha256 "$directory/intent.json") && $(sha_file "$directory/release.json") == $(jq -r .release_sha256 "$directory/intent.json") ]] || fail 'saved operation intent bytes changed'
 cmp -s "$SITE" "$directory/site.json" || fail 'operation intent configuration differs from the selected site'
 cmp -s "$GSJ_WORK/values.pending.json" "$directory/values.json" || fail 'operation intent compiled configuration differs'
 cmp -s "$GSJ_PAYLOAD/release.json" "$directory/release.json" || fail 'operation intent requires the exact source installer manifest'
 jq -e --arg target "$RELEASE_ID" '.identity==$target' "$directory/release.json" >/dev/null || fail 'operation intent release identity differs'
 uid=$(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid) || fail 'operation namespace identity is unavailable'
 [[ $uid == $(jq -r .namespace_uid "$directory/intent.json") ]] || fail 'operation intent namespace was replaced'
 if [[ $(jq -r .record.kind "$directory/intent.json") == restore ]]; then
   file=$(jq -er '.archive.path|select(type=="string" and length>0)' "$directory/intent.json") || fail 'restore intent archive is unavailable'
   [[ -z ${ARCHIVE:-} || $ARCHIVE == "$file" ]] || fail 'restore intent archive selection differs'
   [[ -f $file && ! -L $file && -f $file.resources.enc && ! -L $file.resources.enc && -f $file.json && ! -L $file.json ]] || fail 'restore intent archive files are unavailable'
   [[ $(sha_file "$file") == $(jq -r .archive.sha256 "$directory/intent.json") && $(sha_file "$file.resources.enc") == $(jq -r .archive.resources_sha256 "$directory/intent.json") && $(sha_file "$file.json") == $(jq -r .archive.metadata_sha256 "$directory/intent.json") ]] || fail 'restore intent archive bytes changed'
 fi
 current=$(lease_read) || fail 'operation Lease identity is unavailable'
 jq -e --arg id "$id" --arg name "$RELEASE-operation" --arg sha "$(sha_file "$directory/intent.json")" --slurpfile intent "$directory/intent.json" '.metadata.name==$name and .spec.holderIdentity==$id and .metadata.annotations["gsj.io/operation-intent-sha256"]==$sha and .spec.acquireTime==$intent[0].acquire_time and ($intent[0].prior_lease_uid=="" or .metadata.uid==$intent[0].prior_lease_uid)' <<< "$current" >/dev/null || fail 'Lease does not belong to this immutable operation intent'
 canonical="$STATE_DIR/operation.json"
 if [[ -e $canonical || -L $canonical ]]; then
   [[ -f $canonical && ! -L $canonical ]] || fail 'canonical operation metadata is not a regular file'
   # "swept": the target's dead residue was cleared by the sweep verb, evidence
   # first; like "abandoned", a state the guard must let a later operation
   # recover from, or the sweep would brick the target.
   jq -e --arg id "$id" --arg target "$RELEASE_ID" --slurpfile intent "$directory/intent.json" '(.status|IN("complete","backup-complete","abandoned","swept")) or (.operation==$id and .target==$target and .kind==$intent[0].record.kind and .status=="owned")' "$canonical" >/dev/null || fail 'another active operation or later phase owns canonical state'
   if [[ $(jq -r .operation "$canonical") == "$id" ]]; then
     for file in site values; do
       [[ ! -e $STATE_DIR/$file.pending.json && ! -L $STATE_DIR/$file.pending.json ]] || { [[ ! -L $STATE_DIR/$file.pending.json ]] && cmp -s "$STATE_DIR/$file.pending.json" "$directory/$file.json"; } || fail 'canonical operation configuration differs from its intent'
     done
   fi
 fi
 cat "$directory/site.json" | atomic "$GSJ_WORK/recovered-site.json"
 cat "$directory/values.json" | atomic "$GSJ_WORK/recovered-values.json"
 jq .record "$directory/intent.json" | atomic "$GSJ_WORK/recovered-operation.json"
 [[ $mode == promote ]] || return 0
 [[ ${LEASE_ACQUIRED:-false} == true && ${OPERATION:-} == "$id" && -n ${LEASE_RESOURCE_VERSION:-} && $(jq -r .metadata.resourceVersion <<< "$current") == "$LEASE_RESOURCE_VERSION" ]] || fail 'operation promotion requires the exact successfully acquired Lease revision'
 age=$(jq -er 'now-(.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$current") || fail 'operation promotion Lease renewal is invalid'
 (( age >= -5 && age < 180 )) || fail 'operation promotion requires a fresh Lease'
 # Recheck after local staging. No heartbeat starts until promotion ends, so
 # any resourceVersion change means the caller no longer has its exact CAS.
 current=$(lease_read)
 [[ $(jq -r .metadata.resourceVersion <<< "$current") == "$LEASE_RESOURCE_VERSION" && $(jq -r .spec.holderIdentity <<< "$current") == "$id" ]] || fail 'operation promotion Lease changed during validation'
 cat "$GSJ_WORK/recovered-site.json" | atomic "$STATE_DIR/site.pending.json"
 cat "$GSJ_WORK/recovered-values.json" | atomic "$STATE_DIR/values.pending.json"
 cat "$GSJ_WORK/recovered-operation.json" | atomic "$canonical"
}
acquire() {
 k get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl --context "$CONTEXT" create namespace "$NAMESPACE" >/dev/null
 local current holder now intent_sha
 current=$(lease_read); [[ -n $current ]] || current='{}'; holder=$(jq -r '.spec.holderIdentity // ""' <<< "$current")
 if [[ -n $holder ]]; then
   fail "operation $holder owns this deployment. Use resume --operation $holder after the prior tools process has stopped; elapsed lease time alone never admits another initializer."
 fi
 # No Lease at all: nothing of this installer's has ever owned the release.
 if [[ $current == '{}' ]]; then refuse_foreign_release; fi
 # A backing-off initializer that already ran restarts on its own; it is as
 # active as a running one. A terminal code (initializer_stop) never clears by
 # restarting and a container that never ran cannot write: both admit the
 # operation that repairs them.
 if k get pods -l "app.kubernetes.io/instance=$RELEASE" -o json | jq -e 'any(.items[]; any(.status.initContainerStatuses[]?; .state.running != null or
     (.state.waiting != null and .lastState.terminated != null and
      ((.lastState.terminated.message//"")|test("^gsj-(corpus|copy):(terminal-budget-exhausted|deadline-exceeded|checkpoint-identity-mismatch|source-verification-failed|released-vectors-missing|corpus-update-required|model-change-blocked|manifest-mismatch|core-mismatch|invalid-settings)\\s*$")|not))))' >/dev/null; then
   fail 'an initializer is still running or restarting; use resume to observe its completion'
 fi
 OPERATION=$(openssl rand -hex 12); now=$(date -u +%FT%T.000000Z)
 create_operation_intent "$current" "$now"
 intent_sha=$(sha_file "$STATE_DIR/operation-intents/$OPERATION/intent.json")
 if [[ $current != '{}' ]]; then
   jq --arg id "$OPERATION" --arg now "$now" --arg intent "$intent_sha" '.metadata.annotations["gsj.io/operation-intent-sha256"]=$intent | .spec={holderIdentity:$id,leaseDurationSeconds:180,acquireTime:$now,renewTime:$now}' <<< "$current" | k replace -f - >/dev/null
 else
   jq -n --arg name "$RELEASE-operation" --arg ns "$NAMESPACE" --arg id "$OPERATION" --arg now "$now" --arg intent "$intent_sha" '{apiVersion:"coordination.k8s.io/v1",kind:"Lease",metadata:{name:$name,namespace:$ns,annotations:{"gsj.io/operation-intent-sha256":$intent}},spec:{holderIdentity:$id,leaseDurationSeconds:180,acquireTime:$now,renewTime:$now}}' | k create -f - >/dev/null
 fi
 LEASE_ACQUIRED=true
 LEASE_RESOURCE_VERSION=$(lease_read | jq -er '.metadata.resourceVersion|select(type=="string" and length>0)')
 recover_operation_intent "$OPERATION" promote
 rm -f "$STATE_DIR/lease-lost"; start_renewal
 log "Operation $OPERATION acquired"
}
stop_owned_process_group() {
 local pid=${1:-} deadline
 [[ -n $pid ]] || return 0
 [[ $pid =~ ^[1-9][0-9]*$ && $pid != $$ ]] || return 1
 # Only PIDs recorded at our monitor-mode launches enter here. Killing the
 # shell alone leaves its Helm/kubectl descendants able to mutate the cluster.
 kill -TERM -- "-$pid" 2>/dev/null || true
 deadline=$((SECONDS+3))
 while kill -0 -- "-$pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 0.1; done
 if kill -0 -- "-$pid" 2>/dev/null; then kill -KILL -- "-$pid" 2>/dev/null || true; fi
 wait "$pid" 2>/dev/null || true
}
start_renewal() {
 local monitored=false
 [[ $- == *m* ]] && monitored=true
 set -m
 (
   set +m; trap - EXIT HUP INT TERM
   while sleep 20; do
     current=$(lease_read) || { touch "$STATE_DIR/lease-lost"; exit 1; }
     [[ $(jq -r .spec.holderIdentity <<< "$current") == "$OPERATION" ]] || { touch "$STATE_DIR/lease-lost"; exit 1; }
     jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null || { touch "$STATE_DIR/lease-lost"; exit 1; }
   done
 ) & RENEWER=$!
 $monitored || set +m
}
release_operation() {
 stop_owned_process_group "${RENEWER:-}"; RENEWER=''
 if [[ -n ${OPERATION:-} ]]; then
   local current; current=$(lease_read 2>/dev/null || true); [[ -n $current ]] || current='{}'
   if [[ $(jq -r '.spec.holderIdentity // ""' <<< "$current") == "$OPERATION" ]]; then
     jq '.spec.holderIdentity=""' <<< "$current" | k replace -f - >/dev/null || true
   fi
 fi
}
cleanup_exit() {
 local rc=$? pending
 trap - EXIT
 # Once teardown starts, repeated terminal signals must not interrupt the
 # waits or overwrite the original status used by the Lease-retention rule.
 trap '' HUP INT TERM
 stop_owned_process_group "${GSJ_ADDON_COMMAND_PID:-}"; GSJ_ADDON_COMMAND_PID=''
 stop_owned_process_group "${HELM_PID:-}"; HELM_PID=''
 stop_owned_process_group "${RENEWER:-}"; RENEWER=''
 # A signal may arrive after fork and before the named PID assignment. Bash
 # already owns that job; drain its remaining groups rather than lose it.
 for pending in $(jobs -p); do stop_owned_process_group "$pending"; done
 # A stopped operation leaves its maintenance Pod for resume; its transfer
 # directory still goes back to the operator, so nothing here needs root later.
 if (( rc != 0 )) && [[ -n ${TRANSFER_HANDBACK_POD:-} ]]; then transfer_handback "$TRANSFER_HANDBACK_POD" || true; fi
 # The pull probe is not state anyone resumes: it goes on every exit.
 if [[ -n ${PROBE_POD:-} ]]; then k delete pod "$PROBE_POD" --ignore-not-found --wait=false >/dev/null 2>&1 || true; fi
 # Failure retains the lease and durable operation identity for named recovery.
 if (( rc == 0 )) && [[ -n ${OPERATION:-} ]]; then release_operation; fi
 # A terminal stage names its own recovery; resuming it would only repeat it.
 if (( rc != 0 )) && [[ ${LEASE_ACQUIRED:-false} == true ]]; then log "Operation $OPERATION incomplete; retained state at $STATE_DIR. Use ${RECOVERY_HINT:-resume --operation $OPERATION}."; fi
 [[ -n ${GSJ_WORK:-} ]] && rm -rf "$GSJ_WORK"
 exit "$rc"
}
install_exit_traps() {
 trap cleanup_exit EXIT
 # Bash may otherwise enter EXIT with status zero after a terminating signal.
 # A stopped client must never clear the durable owner of a running initializer.
 trap 'exit 129' HUP
 trap 'exit 130' INT
 trap 'exit 143' TERM
}
retained_site_matches() {
 # $1 selected site, $2 the site retained by an operation. Earlier installers
 # filled the two generated managed-local-ca trust paths into the saved site
 # after the operation was recorded; load_site now records them first.
 # Admit exactly that derivation of this operation's own CA, nothing else.
 cmp -s "$1" "$2" && return
 [[ -f $STATE_DIR/tls/ca.crt && ! -L $STATE_DIR/tls/ca.crt ]] || return 1
 jq -e --arg ca "$STATE_DIR/tls/ca.crt" --slurpfile o "$2" '
   $o[0] as $o | $o.tls.profile=="managed-local-ca" and .tls.profile=="managed-local-ca" and
   $o.tls.ca_file=="" and $o.verification.ca_file=="" and
   .tls.ca_file==$ca and .verification.ca_file==$ca and
   del(.tls.ca_file,.verification.ca_file)==($o|del(.tls.ca_file,.verification.ca_file))
 ' "$1" >/dev/null
}
lease_repair() {
 local current age source="$GSJ_PAYLOAD/release.json" target deployment
 [[ $RESUME_ID =~ ^[a-f0-9]{24}$ ]] || fail 'lease-repair requires the recorded interrupted operation ID'
 [[ ! -f $GSJ_PAYLOAD/helpers/lease-repair-source-release.json ]] || source="$GSJ_PAYLOAD/helpers/lease-repair-source-release.json"
 [[ -f $STATE_DIR/operation.json && -f $STATE_DIR/site.pending.json ]] || fail 'lease-repair requires preserved tools operation metadata'
 target=$(jq -r .identity "$source")
 jq -e --arg id "$RESUME_ID" --arg target "$target" '.operation==$id and .target==$target and .status=="initializing"' "$STATE_DIR/operation.json" >/dev/null || fail 'lease-repair is restricted to the exact recorded initializing release'
 jq -e --slurpfile site "$SITE" '.target==$site[0].target' "$STATE_DIR/site.pending.json" >/dev/null || fail 'saved operation target differs from selected site'
 current=$(lease_read)
 [[ -n $current ]] && jq -e '.spec.holderIdentity=="" and (.metadata.resourceVersion|type=="string")' <<< "$current" >/dev/null || fail 'lease-repair requires an existing empty Lease; an occupied or missing Lease is never replaced'
 age=$(jq -r 'now-(.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$current")
 (( age >= 180 )) || lease_still_live 'the previous installer lease' "$age"
 k get deployment "$RELEASE-web" -o json > "$GSJ_WORK/lease-repair-deployment.json"
 jq -e --arg release "$RELEASE" --arg ns "$NAMESPACE" --arg base "$(jq -r '.registry.base // ""' "$STATE_DIR/site.pending.json")" --slurpfile source "$source" "$JQ_IMAGE"'
   ([.spec.template.spec.containers[]|{key:.name,value:.image}]|from_entries) as $containers |
   ([.spec.template.spec.initContainers[]|{key:.name,value:.}]|from_entries) as $init |
   .metadata.annotations["meta.helm.sh/release-name"]==$release and
   .metadata.annotations["meta.helm.sh/release-namespace"]==$ns and
   .metadata.labels["app.kubernetes.io/instance"]==$release and
   all(["web","runner","mcp"][]; . as $role | $containers[(if $role=="runner" then "agent-runner" else "gsj-"+$role end)]==($source[0].images[$role]|image_ref($base))) and
   $init["corpus-initialize"].image==($source[0].images.web|image_ref($base)) and
   $init["corpus-copy"].image==($source[0].images.decisionsData|image_ref($base)) and
   $init["corpus-copy"].args==["--destination","/source","--manifest-sha256",$source[0].corpus.manifest_sha256]
 ' "$GSJ_WORK/lease-repair-deployment.json" >/dev/null || fail 'live deployment differs from the recorded immutable source; lease-repair refused'
 k get jobs -l "app.kubernetes.io/instance=$RELEASE" -o json | jq -e 'all(.items[];(.status.active//0)==0)' >/dev/null || fail 'provisioning is still active'
 jq -n --arg operation "$RESUME_ID" --arg source "$target" --arg lease_uid "$(jq -r .metadata.uid <<< "$current")" --arg deployment_uid "$(jq -r .metadata.uid "$GSJ_WORK/lease-repair-deployment.json")" '{format:"gsj.lease-repair/1",operation:$operation,source:$source,lease_uid:$lease_uid,deployment_uid:$deployment_uid,status:"prepared"}' | atomic "$STATE_DIR/lease-repair.json"
 # Preserve the prior renewal time: this command restores metadata only. The
 # exact original installer remains responsible for named resume/repair.
 jq --arg id "$RESUME_ID" '.spec.holderIdentity=$id' <<< "$current" | k replace -f - >/dev/null
 jq '.status="repaired"' "$STATE_DIR/lease-repair.json" | atomic "$STATE_DIR/lease-repair.json"
 log "Restored operation $RESUME_ID ownership; use its exact original installer for named resume or repair. Application data and controllers were unchanged."
}
# GSJ_RUNTIME_HELPER: stage-vectors.py
stage_vectors() {
 # Put the released vectors beside the copied shards, so the initializer
 # imports them instead of spending hours re-deriving vectors that would not
 # even be the SAME ones - measured, the INT8 encoder's per-tensor activation
 # scale makes a vector depend on its batchmates (cosine 0.95-0.98 against the
 # same text encoded alone), so a local re-embed is a different store, not a
 # slower route to this one.
 #
 # NOT in an image: the operator already ruled the embedding model out of the
 # mcp image and this artifact is larger. It arrives either from an HTTPS
 # MANIFEST (corpus.vectors_url, whose shards are published beside it) or from a
 # manifest the operator staged on LOCAL DISK with its shards beside it
 # (corpus.vectors_path) - because some clusters have no egress at all.
 #
 # One 1.6 GB object became a 2.4 KB manifest plus seven blocks,
 # published as separate release assets. The verification contract is UNCHANGED
 # and simply spans seven files: corpus.vectors_sha256 proves the manifest
 # before anything parses it, and the manifest proves every block by sha256 and
 # byte count - the same depth of trust the single tarball had, whose digest
 # only ever reached its members through that same manifest. What the split
 # buys is real: `fetch`'s --max-time is PER OBJECT (1.6 GB inside 1800 s
 # demanded >=7.2 Mbit/s sustained or the install failed; the largest block
 # demands ~1.7), and a block is resumable and cached under its own digest, so a
 # named retry re-fetches only what is missing.
 #
 # Placed at the ROOT of the corpus directory, never inside a shard: every
 # verify_directory comparison is an exact set over ONE shard's files, so a
 # sidecar there is invisible to the copier and can never be quarantined by it.
 # Absent or unconfigured means the ordinary embed path runs, untouched.
 local url path expected base staging name shard_sha shard_bytes holder rc destination pod image helper helper_hash
 local -a members=()
 url=$(j '.corpus.vectors_url // ""'); path=$(j '.corpus.vectors_path // ""')
 expected=$(j '.corpus.vectors_sha256 // ""')
 [[ -n $url || -n $path ]] || return 0
 [[ -n $expected ]] || fail 'corpus.vectors_sha256 is required with a vectors source; an unverified vector set is never imported'
 [[ -z $url || -z $path ]] || fail 'configure exactly one of corpus.vectors_url or corpus.vectors_path'
 staging="$GSJ_WORK/vectors"; mkdir -p "$staging"
 if [[ -n $url ]]; then
   # The blocks are siblings of the manifest, so the URL must HAVE a path -
   # a bare origin would resolve them against the scheme.
   [[ ${url#*://} == */?* ]] || fail 'corpus.vectors_url must name the vectors manifest; its shards are published beside it'
   base=${url%/*}
   log "Acquiring the released vectors manifest from the configured artifact endpoint"
   # A transport failure returns curl's own rc, which errexit would turn into a
   # bare non-zero exit naming nothing. Every leg here ends in a GSJ: line.
   rc=0; fetch_public "$url" "$staging/vectors.json" "$expected" || rc=$?
   (( rc == 0 )) || fail "the released vectors manifest could not be acquired from $(url_origin_only "$url") (transport exit $rc)"
 else
   path=$(resolve_file "$path"); private_file "$path"
   [[ $(sha_file "$path") == "$expected" ]] || fail 'staged vectors manifest does not match corpus.vectors_sha256'
   cp "$path" "$staging/vectors.json"
   base=$(cd "$(dirname "$path")" && pwd) || fail 'the directory holding the staged vectors manifest is unreadable'
   log "Using the operator-staged vectors from local disk (no egress)"
 fi
 jq -e '(.shards|type=="array") and (.shards|length)>0' "$staging/vectors.json" >/dev/null \
   || fail 'the configured vectors manifest names no shards; it is not a gsj.corpus-vectors/1 manifest'
 # The set needs room twice over - the blocks where they are proved, and the
 # envelope that carries them into the pod - so name the shortfall here rather
 # than meet ENOSPC an hour into a fetch. capacity.py's host gate predates the
 # sidecar and does not know about either.
 local needed cache_root work_device cache_device free want
 needed=$(( $(jq '[.shards[].bytes]|add' "$staging/vectors.json") / 1048576 ))
 cache_root=${XDG_CACHE_HOME:-${HOME:-}}
 [[ $cache_root == /* ]] || fail 'a client cache directory is required: set XDG_CACHE_HOME or HOME to an absolute path'
 mkdir -p "$cache_root"
 work_device=$(df -Pk "$GSJ_WORK" | awk 'NR==2{print $1}')
 cache_device=$(df -Pk "$cache_root" | awk 'NR==2{print $1}')
 # The blocks and the envelope that carries them are both on disk at once; on
 # a host where TMPDIR and the cache share a filesystem that is twice over.
 want=$(( needed + 256 ))
 [[ $work_device != "$cache_device" ]] || want=$(( needed * 2 + 256 ))
 free=$(( $(df -Pk "$GSJ_WORK" | awk 'NR==2{print $4}') / 1024 ))
 (( free >= want )) || fail "the released vectors need about $want MiB free on $work_device and it has $free MiB"
 if [[ $work_device != "$cache_device" ]]; then
   free=$(( $(df -Pk "$cache_root" | awk 'NR==2{print $4}') / 1024 ))
   (( free >= needed )) || fail "the released vector blocks need about $needed MiB free on $cache_device and it has $free MiB"
 fi
 # The manifest travels first and is what every block is proven against, here
 # and again inside the pod.
 members=(-C "$staging" vectors.json)
 while IFS=$'\t' read -r name shard_sha shard_bytes; do
   # Not a path, not hidden, and NOT AN OPTION: these names become bare `tar`
   # operands, so a leading dash would be read as a flag rather than a file.
   # Refused, never sanitised - the same rule the pod helper applies.
   [[ -n $name && $name != */* && $name != .* && $name != -* ]] || fail "the vectors manifest names a path, not a plain corpus file: $name"
   [[ $shard_sha =~ ^[0-9a-f]{64}$ ]] || fail "the vectors manifest carries no sha256 for the block $name"
   [[ $shard_bytes =~ ^[0-9]+$ ]] || fail "the vectors manifest carries no byte count for the block $name"
   if [[ -n $url ]]; then
     # Content-addressed, beside the client cache: a digest can never name the
     # wrong bytes, so a named retry keeps every block it already proved.
     holder="${XDG_CACHE_HOME:-${HOME:-}/.cache}/gsj-install/vectors/$shard_sha"
     [[ $holder == /* ]] || fail 'a client cache directory is required: set XDG_CACHE_HOME or HOME to an absolute path'
     mkdir -p "$holder"; chmod 700 "$holder"
     log "Acquiring released vector block $name ($((shard_bytes / 1048576)) MiB)"
     rc=0; fetch_public "$base/$name" "$holder/$name" "$shard_sha" || rc=$?
     (( rc == 0 )) || fail "the released vector block $name could not be acquired from $(url_origin_only "$base") (transport exit $rc)"
   else
     holder=$base
     [[ -f "$holder/$name" && ! -L "$holder/$name" ]] || fail "the vectors manifest names $name, which is not a plain file beside the staged manifest"
     [[ $(sha_file "$holder/$name") == "$shard_sha" ]] || fail "staged vectors block $name does not match its sha256 in the vectors manifest"
   fi
   members+=(-C "$holder" "$name")
 done < <(jq -r '.shards[]|[.archive,.sha256,.bytes]|@tsv' "$staging/vectors.json")
 # The blocks are already gzip, so the envelope carries no second codec and
 # nothing is re-copied: `tar` reads each block where it was proved. Built
 # BEFORE the maintenance pod exists, so a 1.6 GB write never runs with a pod
 # idling on the cluster.
 # COPYFILE_DISABLE: a macOS operator's `tar` otherwise writes an AppleDouble
 # `._name` member beside every file, and the helper's exact-set check - rightly
 # - refuses an archive holding anything its manifest does not name.
 COPYFILE_DISABLE=1 tar -cf "$GSJ_WORK/vectors.tar" "${members[@]}" || fail 'the verified vector blocks could not be assembled for staging'
 destination="/volumes/gsj/bootstrap/corpora/$(jq -r .corpus.manifest_sha256 "$GSJ_PAYLOAD/release.json")"
 pod="gsj-vectors-$(printf '%s' "$OPERATION" | cut -c1-12)"
 image=$(payload_image web)
 printf '["sleep","3600"]' > "$GSJ_WORK/vectors-sleep.json"
 maintenance_pod "$pod" "$image" "$GSJ_WORK/vectors-sleep.json"
 # Unpack INSIDE the pod under the destination's own filesystem: the manifest is
 # verified by sha256 before it is parsed, every member is checked against it
 # for size and digest, and nothing outside the corpus root is ever written.
 # Two streams, two execs: the helper is published under a hash-named path with
 # an inline verifying writer, then run with the archive on stdin. Collapsing
 # these into one exec would put two redirects on one stdin.
 helper_hash=$(sha_file "$GSJ_PAYLOAD/helpers/stage-vectors.py"); helper="/tmp/gsj-stage-vectors-$helper_hash.py"
 k exec -i "$pod" -- python -c 'import hashlib,os,pathlib,sys
p=pathlib.Path(sys.argv[1]); data=sys.stdin.buffer.read()
assert hashlib.sha256(data).hexdigest()==sys.argv[2]
p.write_bytes(data); os.chmod(p,0o500)' "$helper" "$helper_hash" < "$GSJ_PAYLOAD/helpers/stage-vectors.py" \
   || fail 'the vector staging helper could not be published into the application pod'
 # A file redirect, not a pipe: `k exec -i` is known to carry stdin at this
 # size from a regular file.
 k exec -i "$pod" -- python -B "$helper" "$destination" "$expected" < "$GSJ_WORK/vectors.tar" > "$GSJ_WORK/vectors-staged.json" \
   || fail 'released vectors could not be staged into the corpus volume'
 rm -f "$GSJ_WORK/vectors.tar"
 jq -e '.format=="gsj.vectors-staged/1" and .vectors>0' "$GSJ_WORK/vectors-staged.json" >/dev/null || fail 'vector staging did not report a complete verified set'
 transfer_handback "$pod"
 k delete pod "$pod" --wait=true >/dev/null
 log "Staged $(jq -r .vectors "$GSJ_WORK/vectors-staged.json") released vectors from $(jq -r .shards "$GSJ_WORK/vectors-staged.json") blocks; the initializer verifies them again before it trusts one"
}
abandon_operation() {
 # The sanctioned end for an operation that will never be resumed.
 #
 # Retaining the Lease on failure is DELIBERATE (cleanup_exit releases only on
 # rc==0) so named recovery can find its state, and "elapsed lease time alone
 # never admits another initializer" is the rule that keeps a live process from
 # being stolen from. But an operation whose cause is environmental and
 # unfixable - a capacity refusal on a node that will not grow - is never
 # resumed, and before this verb the only exits were to hand-patch the Lease
 # (fabricating state) or to leave the deployment permanently unoperable.
 #
 # So: release, but never silently. The reason and the actor are recorded FIRST,
 # on the immutable path, so the evidence outlives the Lease it releases. The
 # expiry is NOT honoured automatically - that would defeat the rule above; a
 # human names the operation and says why.
 local current holder age record="$STATE_DIR/abandoned-$RESUME_ID.json" actor
 [[ -n $RESUME_ID ]] || fail 'abandon requires --operation ID'
 [[ $RESUME_ID =~ ^[a-f0-9]{24}$ ]] || fail 'abandon requires the recorded operation ID'
 [[ -n ${ABANDON_REASON:-} ]] || fail 'abandon requires --reason naming why this operation will never be resumed'
 [[ ${#ABANDON_REASON} -le 512 && $(printf '%s' "$ABANDON_REASON" | tr -d '[:print:]' | wc -c) -eq 0 ]] || fail 'abandon reason must be one line of printable text'
 current=$(lease_read); [[ -n $current ]] || fail 'this deployment has no operation Lease to abandon'
 holder=$(jq -r '.spec.holderIdentity // ""' <<< "$current")
 [[ -n $holder ]] || fail 'the operation Lease is already free; nothing to abandon'
 [[ $holder == "$RESUME_ID" ]] || fail 'abandon identity differs from the persistent operation owner'
 age=$(jq -er 'now-(.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$current") || fail 'operation Lease renewal is invalid'
 (( age >= 180 )) || lease_still_live 'the prior installer lease' "$age" 'abandon takes the Lease only after that'
 # Measured: a backup/upgrade that stopped after quiescence
 # leaves every controller at replicas=0 and its maintenance Pod holding them
 # there. Releasing the Lease then REMOVES the `resume` that would have restarted
 # them - the application stays down and the only path back is gone. So refuse,
 # and name the repair, rather than strand a running deployment.
 local quiesced
 quiesced=$(k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json 2>/dev/null \
   | jq '[.items[]|select((.spec.replicas//1)==0)]|length')
 if [[ ${quiesced:-0} -gt 0 ]]; then
   fail "this operation left $quiesced controller(s) scaled to zero; abandoning would release the lease that resume needs and leave the application down. Restart it with: resume --operation $RESUME_ID --config $CONFIG --non-interactive"
 fi
 actor="$(id -un 2>/dev/null || printf unknown)@$(uname -n 2>/dev/null || printf unknown)"
 jq -n --arg operation "$RESUME_ID" --arg reason "$ABANDON_REASON" --arg actor "$actor" \
   --arg context "$CONTEXT" --arg namespace "$NAMESPACE" --arg release "$RELEASE" \
   --arg target "$RELEASE_ID" --arg at "$(date -u +%FT%T.000000Z)" --argjson age "$age" \
   --arg lease_uid "$(jq -r .metadata.uid <<< "$current")" \
   --arg version "$(jq -r .metadata.resourceVersion <<< "$current")" \
   --slurpfile operation_record "$STATE_DIR/operation.json" '
   {format:"gsj.operation-abandoned/1",operation:$operation,reason:$reason,abandoned_by:$actor,
    abandoned_at:$at,lease_age_seconds:$age,lease_uid:$lease_uid,lease_resource_version:$version,
    context:$context,namespace:$namespace,release:$release,installer_target:$target,
    retained:{kind:($operation_record[0].kind//null),status:($operation_record[0].status//null)},
    released:{application_data:"unchanged",helm_release:"unchanged",operation_state:"retained"}}' \
   | immutable_file "$record"
 # CAS on the exact resourceVersion read above: a concurrent acquirer or renewal
 # must lose this race rather than have its ownership silently discarded.
 jq '.spec.holderIdentity=""' <<< "$current" | k replace -f - >/dev/null \
   || fail 'the operation Lease changed while it was being abandoned; re-read it and repeat'
 # Freeing the Lease alone is NOT enough, measured: acquire() also requires the
 # canonical record to be complete/backup-complete/abandoned or to match the
 # incoming operation (runtime.sh admission guard). Left at status "owned", it
 # refuses EVERY later operation on the deployment - the release would make the
 # Lease free and the deployment permanently unoperable. Mark it abandoned,
 # keeping the kind, the operation id and the target for forensics.
 #
 # "abandoned" is admitted by the guard BECAUSE of this write.
 # The first version of this fix marked the record "abandoned" while the guard
 # still accepted only complete/backup-complete/owned, so the release freed the
 # Lease and the canonical record went on refusing every retry - the same brick,
 # under a different name. A recovery verb has to leave a state the guard lets
 # you recover from; the two are one change, not two.
 jq --arg at "$(date -u +%FT%T.000000Z)" --arg reason "$ABANDON_REASON" --arg actor "$actor" \
    '.status="abandoned" | .abandoned={at:$at, reason:$reason, by:$actor}' \
    "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 log "Abandoned operation $RESUME_ID ($ABANDON_REASON) by $actor; evidence at $record. Application data, Helm revision and the retained operation record are unchanged."
}
sweep_delete() {
 # One residue object, deleted by the UID that was inventoried and recorded
 # (preconditioned; a replacement under the same name is never deleted).
 local kind=$1 name=$2 uid=$3 path
 case "$kind" in
   Job) path="/apis/batch/v1/namespaces/$NAMESPACE/jobs/$name";;
   ConfigMap) path="/api/v1/namespaces/$NAMESPACE/configmaps/$name";;
   Secret) path="/api/v1/namespaces/$NAMESPACE/secrets/$name";;
   Pod) path="/api/v1/namespaces/$NAMESPACE/pods/$name";;
   *) fail "sweep never deletes a $kind";;
 esac
 jq -n --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid},propagationPolicy:"Foreground"}' > "$GSJ_WORK/sweep-delete.json"
 k delete --raw "$path" -f "$GSJ_WORK/sweep-delete.json" >/dev/null 2>&1 \
   || [[ -z $(k get "$kind" "$name" -o json --ignore-not-found 2>/dev/null) ]] \
   || fail "sweep could not delete $kind $name by its recorded UID; it may have been replaced - re-run sweep to inventory it again"
}
sweep_target() {
 # The residue of a DEAD run has no other verb. `abandon`
 # releases a LIVE operation's Lease and refuses without one; a killed
 # installer whose namespace went, a refused attempt that had already prepared
 # its operation, or an uninstalled release leave a canonical record in a
 # state every later operation refuses ("another active operation or later
 # phase owns canonical state"), installer-created Jobs, records and Secrets,
 # and a transfer directory - with nothing to clear them.
 #
 # Per target (the site's namespace + release), evidence first, and NEVER a live
 # deployment or a live operation:
 #  - refused while the operation Lease has a holder: live (renewed within the
 #    window) -> stop that process; stale -> abandon it, which records why and
 #    releases it properly;
 #  - refused while a Helm release of the name exists in the namespace or any
 #    controller of the release is still present (uninstall keeps the claims);
 #  - PersistentVolumeClaims are never listed, never touched; a TLS Secret only
 #    when the installer made it (managed-local-ca), never a supplied one.
 # Forgejo tokens of spent verification runs live in Forgejo's database on the
 # kept claim; nothing outside a running Forgejo can revoke them, so the record
 # says so instead of implying they died with their Secret.
 local reason=${ABANDON_REASON:-} actor at record canonical current holder age history controllers inventory transfer intents dirs item kind name uid opid status swept
 [[ -n $reason ]] || fail 'sweep requires --reason naming why this target is being swept'
 [[ ${#reason} -le 512 && $(printf '%s' "$reason" | tr -d '[:print:]' | wc -c) -eq 0 ]] || fail 'sweep reason must be one line of printable text'
 canonical="$STATE_DIR/operation.json"
 opid=''; status=''
 if [[ -f $canonical && ! -L $canonical ]]; then opid=$(jq -r '.operation // ""' "$canonical"); status=$(jq -r '.status // ""' "$canonical"); fi
 inventory='[]'; current=''
 # An absent namespace has nothing live to check; a namespace that could not
 # be READ (an expired kubeconfig, RBAC, an API outage) is not absent, and a
 # sweep that took it for absent skipped every check below and still marked
 # the record swept.
 local present
 present=$(k get namespace "$NAMESPACE" --ignore-not-found -o name 2>/dev/null) || fail "namespace $NAMESPACE could not be read (kubectl failed); nothing was swept"
 if [[ -n $present ]]; then
   current=$(lease_read) || fail 'operation Lease identity is unavailable'
   holder=''; [[ -z $current ]] || holder=$(jq -r '.spec.holderIdentity // ""' <<< "$current")
   if [[ -n $holder ]]; then
     age=$(jq -er 'now-(.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$current") || fail 'operation Lease renewal is invalid'
     # A held Lease is abandon's to release, live or not: a rerun of sweep would refuse
     # again, so the refusal names abandon -- and, while the Lease is live, the wait
     # abandon needs.
     local live='' renewed
     if (( age < 0 )); then renewed="its renewal time is ahead of this clock by $(( -age )) s, a clock skew between the renewing host and this one"; else renewed="renewed $age s ago"; fi
     if (( age < 180 )); then live=" -- and it is still live: abandon takes a Lease only after 180 s unrenewed, so if no installer process is running against this target, wait $(( 180 - age )) s first"; fi
     # the holder is printed only when it is an operation id this installer
     # writes; a foreign Lease's text is not repeated [review sweep B2]
     local shown=$holder; [[ $holder =~ ^[a-f0-9]{24}$ ]] || shown='<a holder identity this installer did not write>'
     fail "the operation Lease is held by $shown ($renewed); sweep clears only what abandon cannot: run abandon --operation $shown --reason ... first$live"
   fi
   history=$(k get secrets,configmaps -l "owner=helm,name=$RELEASE" -o json | jq '[.items[]|select(.kind=="ConfigMap" or .type=="helm.sh/release.v1")]|length')
   (( history == 0 )) || fail "a Helm release named $RELEASE exists in namespace $NAMESPACE ($history Helm revision(s)); sweep never removes a deployment - uninstall it (its claims are kept) and sweep the residue afterwards"
   controllers=$(k get deployments,statefulsets -l "app.kubernetes.io/instance=$RELEASE" -o json | jq '.items|length')
   (( controllers == 0 )) || fail "$controllers controller(s) of $RELEASE are still present in namespace $NAMESPACE; sweep never removes a deployment"
   # The residue, by the installer's own labels plus the three token Secrets
   # the provisioning Job mints (labelled by the Job, named by the release),
   # each with the UID the deletion below is preconditioned on.
   inventory=$(k get jobs,configmaps,secrets -o json | jq --arg r "$RELEASE" --arg tls "$(j .tls.secret)" --arg managed "$(j .tls.profile)" '
     [.items[]|select(.kind!="PersistentVolumeClaim")|select(
        (.metadata.labels["gsj.io/owner"]==$r) or (.metadata.labels["app.kubernetes.io/instance"]==$r)
        or (.kind=="Secret" and (.metadata.name==($r+"-admin-token") or .metadata.name==($r+"-agent-token") or .metadata.name==($r+"-webhook")))
        or (.kind=="ConfigMap" and (.metadata.name==($r+"-provisioned") or .metadata.name==($r+"-ready-state") or .metadata.name==($r+"-installed")))
        or (.kind=="Job" and .metadata.name==($r+"-provision"))
        or (.kind=="Secret" and $managed=="managed-local-ca" and .metadata.name==$tls))
      |select((.metadata.labels.owner//"")!="helm")
      |{kind:.kind,name:.metadata.name,uid:.metadata.uid}]')
   # ...plus a pull-probe Pod a killed installer left behind (cleanup_exit
   # removes it on every ordinary exit). Selected by ITS label alone: no other
   # Pod is ever swept.
   inventory=$(jq -c --argjson pods "$(k get pods -o json | jq --arg r "$RELEASE" '[.items[]|select(.metadata.labels["gsj.io/pull-probe"]==$r)|{kind:.kind,name:.metadata.name,uid:.metadata.uid}]')" '. + $pods' <<< "$inventory")
 fi
 # transfer residue: this target's operations only (the canonical one and every
 # recorded intent), under the site's own transfer_path
 transfer=$(j '.storage.transfer_path // ""'); dirs='[]'
 if [[ -n $transfer && -d $transfer ]]; then
   # `if`, never `[[ ]] &&` inside these substitutions: a false condition at the end
   # of an AND-list is a nonzero status, pipefail carries it out of the
   # substitution, and errexit then ends the verb with no message at all —
   # measured on the real orphan (no operation id, no transfer directory left).
   intents=$( { if [[ -n $opid ]]; then printf '%s\n' "$opid"; fi
                if [[ -d $STATE_DIR/operation-intents ]]; then ls -1 "$STATE_DIR/operation-intents" 2>/dev/null; fi; } | sort -u)
   dirs=$(for item in $intents; do
            if [[ $item =~ ^[a-f0-9]{24}$ && -d $transfer/$item ]]; then printf '%s\n' "$transfer/$item"; fi
          done | jq -R . | jq -s .)
 fi
 [[ $(jq length <<< "$inventory") -gt 0 || $(jq length <<< "$dirs") -gt 0 || ( -n $status && $status != complete && $status != backup-complete && $status != abandoned && $status != swept ) ]] \
   || { log "Nothing to sweep for $RELEASE in $NAMESPACE: no residue and the canonical record (${status:-none}) admits later operations"; return 0; }
 actor="$(id -un 2>/dev/null || printf unknown)@$(uname -n 2>/dev/null || printf unknown)"
 at=$(date -u +%FT%T.000000Z)
 record="$STATE_DIR/swept-$(date -u +%Y%m%dT%H%M%SZ)-${opid:-none}.json"
 # Evidence BEFORE the first deletion, on the immutable path, naming every
 # object and directory about to go and what deliberately stays.
 jq -n --arg reason "$reason" --arg actor "$actor" --arg at "$at" --arg context "$CONTEXT" --arg namespace "$NAMESPACE" \
   --arg release "$RELEASE" --arg target "$RELEASE_ID" --arg opid "$opid" --arg status "$status" \
   --argjson inventory "$inventory" --argjson dirs "$dirs" --arg lease "$( [[ -n $current ]] && printf '%s' "$RELEASE-operation" )" '
   {format:"gsj.target-swept/1",reason:$reason,swept_by:$actor,swept_at:$at,context:$context,namespace:$namespace,release:$release,
    installer_target:$target,canonical:{operation:(if $opid=="" then null else $opid end),status:(if $status=="" then null else $status end),disposition:"retained, marked swept"},
    deleted:{objects:$inventory,operation_lease:(if $lease=="" then null else $lease end),transfer_directories:$dirs},
    kept:{persistent_volume_claims:"untouched",helm_release:"none existed (refused otherwise)",
          forgejo_tokens:"NOT revoked: tokens of spent verification runs and the provisioning bot live in Forgejo database on the retained claim; revoke through Forgejo admin API after the next install, or delete the claim",
          state_directory:"retained (site, values, intents, tls material, this record)"}}' | immutable_file "$record"
 swept=0
 while IFS= read -r item; do
   [[ -n $item ]] || continue
   kind=$(jq -r .kind <<< "$item"); name=$(jq -r .name <<< "$item"); uid=$(jq -r .uid <<< "$item")
   sweep_delete "$kind" "$name" "$uid"; swept=$((swept+1))
 done < <(jq -c '.[]' <<< "$inventory")
 if [[ -n $current ]]; then k delete lease "$RELEASE-operation" --ignore-not-found >/dev/null; fi
 while IFS= read -r item; do
   [[ -n $item ]] || continue
   rm -rf "$item" 2>/dev/null || log "The transfer directory $item could not be removed; it needs root (a maintenance container running as root created it)"
 done < <(jq -r '.[]' <<< "$dirs")
 rm -f "$STATE_DIR/lease-lost"
 if [[ -n $status ]]; then
   jq --arg at "$at" --arg reason "$reason" --arg actor "$actor" --arg record "$record" \
      '.status="swept" | .swept={at:$at, reason:$reason, by:$actor, record:$record}' "$canonical" | atomic "$canonical"
 fi
 log "Swept $RELEASE in $NAMESPACE by $actor ($reason): $swept object(s), $(jq length <<< "$dirs") transfer director(y/ies), the operation Lease $( [[ -n $current ]] && printf removed || printf absent ); canonical record ${opid:-none} (${status:-none}) marked swept; claims untouched; evidence at $record"
}
secret_file() {
 local name=$1 key=$2 file=$3 existing expected
 if [[ $key == password ]]; then
   private_file "$file"
   jq -jn --rawfile password "$file" '$password|sub("\\n+$";"")|if length==0 or any(explode[]; .<32 or .==127) then error("invalid operator password file") else . end' > "$GSJ_WORK/operator-normalized"
   file="$GSJ_WORK/operator-normalized"
 fi
 [[ $key == tls.crt ]] || private_file "$file"; [[ -s $file ]] || fail "empty protected input for Secret $name"
 existing=$(k get secret "$name" -o json --ignore-not-found)
 if [[ -n $existing ]]; then
   jq -e --arg k "$key" --rawfile expected "$file" '.data[$k] == ($expected | @base64)' <<< "$existing" >/dev/null || fail "Secret $name differs from supplied credential; use explicit credential repair/rotation, never implicit overwrite"
 else
   k create secret generic "$name" --from-file="$key=$file" --dry-run=client -o json | jq --arg owner "$RELEASE" '.metadata.labels={"gsj.io/owner":$owner}' | k create -f - >/dev/null
 fi
}
registry_secret_input() {
 # Create the pull Secret from registry.config_file, or verify the existing one
 # is unchanged. Idempotent, so both secret_inputs and relocated_images_probe
 # call it: the probe has to run BEFORE an upgrade quiesces the application, and
 # it cannot pull from an authenticated registry without this Secret.
 local file secret
 file=$(j .registry.config_file)
 [[ -n $file ]] || return 0
 file=$(resolve_file "$file"); private_file "$file"
 jq -e 'type=="object" and (.auths|type=="object")' "$file" >/dev/null || fail 'invalid registry credential file'
 secret=$(j .registry.pull_secret)
 if ! k get secret "$secret" >/dev/null 2>&1; then k create secret generic "$secret" --type=kubernetes.io/dockerconfigjson --from-file=".dockerconfigjson=$file" >/dev/null; else secret_file "$secret" .dockerconfigjson "$file"; fi
}
secret_inputs() {
 assert_owner
 secret_file "$(j .operator.secret)" password "$OP_PASSWORD"
 local role file secret bundle
 for role in llm ocr; do
   file=$(j ".$role.credential.file"); secret=$(j ".$role.credential.secret")
   if [[ -n $file ]]; then secret_file "$RELEASE-$role-key" key "$(resolve_file "$file")";
   elif [[ -n $secret ]]; then k get secret "$secret" -o json | jq -e '.data.key | type=="string" and length>0' >/dev/null || fail "$role credential Secret lacks key"; fi
 done
 registry_secret_input
 file=$(j .trust.ca_file)
 if [[ -n $file ]]; then
   file=$(resolve_file "$file"); openssl x509 -in "$file" -noout >/dev/null || fail 'invalid CA certificate'
   # The download override may carry delivery CAs; application trust is the
   # host's system bundle plus the site CA only.
   bundle=$(CURL_CA_BUNDLE='' system_ca_bundle)
   cat "$bundle" "$file" > "$GSJ_WORK/ca-bundle.pem"
   k create configmap "$RELEASE-trust" --from-file="bundle.pem=$GSJ_WORK/ca-bundle.pem" --dry-run=client -o json | k apply -f - >/dev/null
 fi
 file=$(j .trust.proxy_file)
 if [[ -n $file ]]; then
   file=$(resolve_file "$file"); private_file "$file"
   jq -e 'type=="object" and (keys|sort)==["HTTPS_PROXY","HTTP_PROXY","NO_PROXY"] and all(.[];type=="string")' "$file" >/dev/null || fail 'proxy_file must contain exactly HTTP_PROXY, HTTPS_PROXY and NO_PROXY strings'
   proxy_file_check "$file"
   # Internal K8s/Forgejo/Chroma bypass is explicit. Proxy values stay in files/Secrets.
   jq --arg ns "$NAMESPACE" --arg release "$RELEASE" '.NO_PROXY = ((.NO_PROXY + ",localhost,.localhost,127.0.0.1,.svc,.cluster.local,"+$release+"-forgejo,"+$release+"-chroma") | split(",")|map(select(.!=""))|unique|join(","))' "$file" > "$GSJ_WORK/proxy.json"
   secret=$(k get secret "$RELEASE-proxy" -o json --ignore-not-found)
   if [[ -n $secret ]]; then
     jq -e --slurpfile proxy "$GSJ_WORK/proxy.json" '.data | with_entries(.value |= @base64d) == $proxy[0]' <<< "$secret" >/dev/null || fail 'proxy credential changed; explicit rotation required'
   else
     jq --arg name "$RELEASE-proxy" '{apiVersion:"v1",kind:"Secret",metadata:{name:$name},type:"Opaque",stringData:.}' "$GSJ_WORK/proxy.json" | k create -f - >/dev/null
   fi
 fi
}
addon_path() { local name=$1 path checksum; path=$(jq -r --arg n "$name" '.addons[$n].path' "$GSJ_PAYLOAD/release.json"); checksum=$(jq -r --arg n "$name" '.addons[$n].sha256' "$GSJ_PAYLOAD/release.json"); [[ $(sha_file "$GSJ_PAYLOAD/$path") == "$checksum" ]] || fail "addon $name integrity failed"; printf '%s' "$GSJ_PAYLOAD/$path"; }
owned_addon_create() {
 local desired=$1 existing kind name ns
 kind=$(jq -r .kind "$desired"); name=$(jq -r .metadata.name "$desired"); ns=$(jq -r '.metadata.namespace // "default"' "$desired")
 existing=$(kubectl --context "$CONTEXT" --namespace "$ns" get "$kind" "$name" -o json --ignore-not-found)
 if [[ -n $existing ]]; then
   # Kubernetes may add defaults; every explicit payload field must still
   # match. In particular images, node paths, roles and ownership cannot drift.
   jq -e --slurpfile desired "$desired" 'def matches($actual;$expected):
     if ($actual|type)!=($expected|type) then false
     elif ($expected|type)=="object" then all($expected|keys[]; . as $key | ($actual|has($key)) and matches($actual[$key];$expected[$key]))
     elif ($expected|type)=="array" then ($actual|length)==($expected|length) and all(range(0;$expected|length); . as $index | matches($actual[$index];$expected[$index]))
     else $actual==$expected end;
     matches(.;$desired[0])' <<< "$existing" >/dev/null || fail "managed dependency differs or has another owner: $kind/$name"
 else
   kubectl --context "$CONTEXT" --namespace "$ns" create -f "$desired" >/dev/null
 fi
}
managed_storage() {
 local payload=$1 owner class ns=gsj-storage item
 class=$(j .storage.class)
 jq -n --arg nsuid "$(k get namespace "$NAMESPACE" -o json | jq -r .metadata.uid)" --arg release "$RELEASE" '{namespace_uid:$nsuid,release:$release}' > "$GSJ_WORK/storage-owner.json"
 owner=$(sha_file "$GSJ_WORK/storage-owner.json"); owner=${owner:0:40}
 jq --slurpfile site "$SITE" --slurpfile manifest "$GSJ_PAYLOAD/release.json" '. + {class:$site[0].storage.class,node:$site[0].storage.node,path:$site[0].storage.backend_path,addon:$manifest[0].addons.localPath}' "$GSJ_WORK/storage-owner.json" > "$STATE_DIR/storage-profile.json"
 kubectl --context "$CONTEXT" create --dry-run=client --validate=false -f "$payload" -o json | jq -s --arg owner "$owner" --arg node "$(j .storage.node)" --arg path "$(j .storage.backend_path)" '{items:[.[]|(.items // [.])[]]} | .items |= map(del(.metadata.creationTimestamp,.spec.template.metadata.creationTimestamp,.status) | .metadata.labels["gsj.io/storage-owner"]=$owner | if .kind=="ConfigMap" and .metadata.name=="local-path-config" then .data["config.json"]=({nodePathMap:[{node:$node,paths:[$path]}]}|tojson) else . end)' > "$GSJ_WORK/storage-payload.json"
 jq '.items[]|select(.kind=="Namespace")' "$GSJ_WORK/storage-payload.json" > "$GSJ_WORK/storage-object.json"
 owned_addon_create "$GSJ_WORK/storage-object.json"
 # The immutable reservation fences all later shared controller writes. A
 # different site must reuse the qualified class, not adopt its controller.
 jq -n --arg ns "$ns" --arg owner "$owner" --rawfile identity "$STATE_DIR/storage-profile.json" '{apiVersion:"v1",kind:"ConfigMap",metadata:{name:"gsj-local-path-owner",namespace:$ns,labels:{"gsj.io/storage-owner":$owner}},immutable:true,data:{"identity.json":$identity}}' > "$GSJ_WORK/storage-object.json"
 owned_addon_create "$GSJ_WORK/storage-object.json"
 while IFS= read -r item; do
   printf '%s\n' "$item" > "$GSJ_WORK/storage-object.json"
   owned_addon_create "$GSJ_WORK/storage-object.json"
 done < <(jq -c '.items[]|select(.kind!="Namespace")' "$GSJ_WORK/storage-payload.json")
 jq -n --arg class "$class" --arg owner "$owner" '{apiVersion:"storage.k8s.io/v1",kind:"StorageClass",metadata:{name:$class,labels:{"gsj.io/managed":"local-path-v1","gsj.io/storage-owner":$owner}},provisioner:"rancher.io/gsj-local-path",volumeBindingMode:"WaitForFirstConsumer",reclaimPolicy:"Retain"}' > "$GSJ_WORK/storage-object.json"
 owned_addon_create "$GSJ_WORK/storage-object.json"
 kubectl --context "$CONTEXT" -n "$ns" rollout status deploy/local-path-provisioner --timeout=300s
}
managed_helm_addon() {
 # A chart release is shared cluster infrastructure. Reserve its exact
 # profile before its first write; never infer ownership from a familiar name.
 local addon=$1 ns=$2 release=$3 chart=$4 values=$5 revision=${6:-} uid owner record existing item kind name object_ns history
 [[ -z $revision || $revision =~ ^[1-9][0-9]*$ ]] || fail 'addon repair requires an explicit positive Helm revision'
 [[ $ns != "$NAMESPACE" ]] || fail 'managed Helm addons require a dedicated namespace; select reuse for shared infrastructure'
 uid=$(k get namespace "$NAMESPACE" -o json | jq -er '.metadata.uid|select(type=="string" and length>0)')
 jq -cnS --arg uid "$uid" --arg namespace "$NAMESPACE" --arg release "$RELEASE" --arg addon "$addon" '{namespace_uid:$uid,namespace:$namespace,release:$release,addon:$addon}' > "$GSJ_WORK/addon-site-owner.json"
 owner=$(sha_file "$GSJ_WORK/addon-site-owner.json"); owner=${owner:0:40}
 if [[ $addon == certManager ]]; then
   # Helm stamps ordinary objects, but creates hooks through a separate path.
   # These three pinned chart maps cover every startup-check hook resource.
   jq --arg owner "$owner" --arg release "$release" --arg ns "$ns" '
     .global.commonLabels["gsj.io/addon-owner"]=$owner |
     .startupapicheck.jobAnnotations["meta.helm.sh/release-name"]=$release |
     .startupapicheck.jobAnnotations["meta.helm.sh/release-namespace"]=$ns |
     .startupapicheck.jobAnnotations["helm.sh/hook"]="post-install,post-upgrade,post-rollback" |
     .startupapicheck.rbac.annotations["meta.helm.sh/release-name"]=$release |
     .startupapicheck.rbac.annotations["meta.helm.sh/release-namespace"]=$ns |
     .startupapicheck.rbac.annotations["helm.sh/hook"]="post-install,post-upgrade,post-rollback" |
     .startupapicheck.serviceAccount.annotations["meta.helm.sh/release-name"]=$release |
     .startupapicheck.serviceAccount.annotations["meta.helm.sh/release-namespace"]=$ns |
     .startupapicheck.serviceAccount.annotations["helm.sh/hook"]="post-install,post-upgrade,post-rollback"
   ' "$values" > "$GSJ_WORK/addon-values.json"
 else
   jq --arg owner "$owner" '.commonLabels["gsj.io/addon-owner"]=$owner' "$values" > "$GSJ_WORK/addon-values.json"
 fi
 HELM_DRIVER=secret helm template "$release" "$chart" --namespace "$ns" --include-crds --values "$GSJ_WORK/addon-values.json" > "$GSJ_WORK/addon-render.yaml"
 # Chart manifests carry explicit namespaces; cert-manager also renders
 # leader-election RBAC in kube-system. Do not force all objects into one ns.
 kubectl --context "$CONTEXT" create --dry-run=client --validate=false -f "$GSJ_WORK/addon-render.yaml" -o json |
   jq -s --arg ns "$ns" --arg owner "$owner" '{items:[.[]|(.items // [.])[]]|map(del(.metadata.creationTimestamp,.spec.template.metadata.creationTimestamp,.status) |
     if .kind=="CustomResourceDefinition" then .metadata.labels["gsj.io/addon-owner"]=$owner else . end)}' > "$GSJ_WORK/addon-render.json"
 jq -e --arg owner "$owner" '.items|length>0 and all(.[]; .metadata.labels["gsj.io/addon-owner"]==$owner and (.metadata.name|type=="string" and length>0))' "$GSJ_WORK/addon-render.json" >/dev/null || fail 'addon chart does not label every named resource with installer ownership'
 jq -cnS --arg ns "$ns" --arg release "$release" --arg chart_sha "$(sha_file "$chart")" --slurpfile owner "$GSJ_WORK/addon-site-owner.json" --slurpfile manifest "$GSJ_PAYLOAD/release.json" --arg addon "$addon" --slurpfile values "$GSJ_WORK/addon-values.json" --slurpfile rendered "$GSJ_WORK/addon-render.json" '
   {format:"gsj.managed-addon/1",owner:$owner[0],namespace:$ns,release:$release,chart_sha256:$chart_sha,addon:$manifest[0].addons[$addon],values:$values[0],
    resources:([$rendered[0].items[]|{apiVersion,kind,name:.metadata.name,namespace:(.metadata.namespace // "")}]|sort_by(.apiVersion,.kind,.namespace,.name))}' > "$GSJ_WORK/addon-profile.json"
 record=gsj-addon-owner
 jq -n --arg ns "$ns" --arg name "$record" --arg owner "$owner" --rawfile identity "$GSJ_WORK/addon-profile.json" '{apiVersion:"v1",kind:"ConfigMap",metadata:{name:$name,namespace:$ns,labels:{"gsj.io/addon-owner":$owner}},immutable:true,data:{"identity.json":$identity}}' > "$GSJ_WORK/addon-owner.json"
 existing=$(kubectl --context "$CONTEXT" --namespace "$ns" get configmap "$record" -o json --ignore-not-found)
 if [[ -n $existing ]]; then
   jq -e --arg owner "$owner" --slurpfile desired "$GSJ_WORK/addon-owner.json" '.immutable==true and .metadata.labels["gsj.io/addon-owner"]==$owner and .data==$desired[0].data' <<< "$existing" >/dev/null || fail 'managed addon profile changed or belongs to another site; addon migration requires an explicit supported operation'
 fi
 [[ -z $revision || -n $existing ]] || fail 'addon repair requires an existing immutable owner record'
 # Check every Helm history record, including a different configured storage
 # driver. This installer uses the Secret driver and cannot adopt either one.
 history=$(kubectl --context "$CONTEXT" --namespace "$ns" get secrets,configmaps -l "owner=helm,name=$release" -o json)
 jq -e --arg owner "$owner" --arg owned "$existing" '.items|all(.[]; $owned!="" and .kind=="Secret" and .metadata.labels["gsj.io/addon-owner"]==$owner)' <<< "$history" >/dev/null || fail 'an existing Helm release has no matching immutable installer owner'
 if [[ -z $revision ]]; then
   jq -e '(.items|sort_by((.metadata.labels.version // "0")|tonumber)|last|.metadata.labels.status // "")|startswith("pending-")|not' <<< "$history" >/dev/null || fail "owned addon $addon has an interrupted Helm operation; use addon-repair --operation $OPERATION --addon $addon --revision $(jq -r '.items|map(.metadata.labels.version|tonumber)|max' <<< "$history") after the previous tools process has stopped"
 else
   jq -e '(.items|sort_by((.metadata.labels.version // "0")|tonumber)|last|.metadata.labels.status // "")|IN("pending-install","pending-upgrade","pending-rollback","failed")' <<< "$history" >/dev/null || fail 'addon repair requires a named pending or failed Helm revision'
 fi
 printf '%s\n' "$history" > "$GSJ_WORK/addon-history.json"
 while IFS= read -r item; do
   kind=$(jq -r .kind <<< "$item"); name=$(jq -r .metadata.name <<< "$item"); object_ns=$(jq -r --arg ns "$ns" '.metadata.namespace // $ns' <<< "$item")
   local actual; actual=$(kubectl --context "$CONTEXT" --namespace "$object_ns" get "$kind" "$name" -o json --ignore-not-found)
   if [[ -n $actual ]]; then
     [[ -n $existing ]] || fail "managed addon resource already exists without its owner record: $kind/$name"
     jq -e --arg owner "$owner" --arg release "$release" --arg ns "$ns" '
       .metadata.labels["gsj.io/addon-owner"]==$owner and
       (.kind=="CustomResourceDefinition" or (.metadata.annotations["meta.helm.sh/release-name"]==$release and .metadata.annotations["meta.helm.sh/release-namespace"]==$ns))
     ' <<< "$actual" >/dev/null || fail "managed addon resource has another owner: $kind/$name"
     if [[ -n $revision ]]; then
       printf '%s\n' "$actual" > "$GSJ_WORK/addon-live-resource.json"
       printf '%s\n' "$item" > "$GSJ_WORK/addon-desired-resource.json"
       owned_resource_matches "$GSJ_WORK/addon-live-resource.json" "$GSJ_WORK/addon-desired-resource.json" || fail 'live addon resource differs from the immutable repair profile'
     fi
   elif [[ -n $revision && $kind == CustomResourceDefinition ]]; then
     fail 'addon repair cannot recreate a missing CRD; restore its identity explicitly'
   fi
 done < <(jq -c '.items[]' "$GSJ_WORK/addon-render.json")
 if [[ $addon == certManager ]]; then jq '.crds.enabled=false' "$GSJ_WORK/addon-values.json" > "$GSJ_WORK/addon-helm-values.json"; else cp "$GSJ_WORK/addon-values.json" "$GSJ_WORK/addon-helm-values.json"; fi
 if [[ -n $revision ]]; then
   kubectl --context "$CONTEXT" get Namespace "$ns" -o json | jq -e --arg owner "$owner" '.metadata.labels["gsj.io/addon-owner"]==$owner and .metadata.labels["pod-security.kubernetes.io/enforce"]=="baseline"' >/dev/null || fail 'managed addon namespace admission or ownership differs'
   repair_managed_addon "$addon" "$ns" "$release" "$chart" "$revision"
   return
 fi
 # Namespace creation follows collision checks and never modifies an existing
 # namespace's admission policy. A namespace created before a failed owner
 # reservation may be reused only by the same site.
 jq -n --arg ns "$ns" --arg owner "$owner" '{apiVersion:"v1",kind:"Namespace",metadata:{name:$ns,labels:{"gsj.io/addon-owner":$owner,"pod-security.kubernetes.io/enforce":"baseline"}}}' > "$GSJ_WORK/addon-namespace.json"
 owned_addon_create "$GSJ_WORK/addon-namespace.json"
 owned_addon_create "$GSJ_WORK/addon-owner.json"
 # Static CRDs are outside Helm's normal upgrade ownership checks. Install
 # them explicitly with create-only exact-payload checks for both charts.
 while IFS= read -r item; do
   printf '%s\n' "$item" > "$GSJ_WORK/addon-object.json"
   owned_addon_create "$GSJ_WORK/addon-object.json"
   kubectl --context "$CONTEXT" wait --for=condition=Established "customresourcedefinition/$(jq -r .metadata.name <<< "$item")" --timeout=120s >/dev/null
 done < <(jq -c '.items[]|select(.kind=="CustomResourceDefinition")' "$GSJ_WORK/addon-render.json")
 # A fresh reservation uses Helm's create-only install, so a competing
 # release appearing after preflight cannot turn this into a foreign upgrade.
 local verb=upgrade
 if jq -e '.items|length==0' <<< "$history" >/dev/null; then verb=install; fi
 HELM_DRIVER=secret helm --kube-context "$CONTEXT" -n "$ns" "$verb" "$release" "$chart" --values "$GSJ_WORK/addon-helm-values.json" --skip-crds --labels "gsj.io/addon-owner=$owner" --wait --wait-for-jobs --timeout=600s
}
addon_owned_run() {
 local logfile=$1 pid rc=0 monitored=false; shift
 assert_owner
 [[ $- == *m* ]] && monitored=true
 # Give the command its own process group so loss of the Lease also stops
 # transport/helper descendants before this function returns.
 set -m
 "$@" > "$logfile" 2>&1 & pid=$!
 GSJ_ADDON_COMMAND_PID=$pid
 $monitored || set +m
 while kill -0 "$pid" 2>/dev/null; do
   if ! (assert_owner) >/dev/null 2>&1; then
     kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
     wait "$pid" 2>/dev/null || true
     GSJ_ADDON_COMMAND_PID=''
     fail 'addon repair lost operation ownership; its named Helm revision must be reconciled'
   fi
   sleep 1
 done
 wait "$pid" || rc=$?
 GSJ_ADDON_COMMAND_PID=''
 (( rc == 0 )) || fail 'owned addon operation failed; inspect its private repair log'
 assert_owner
}
addon_release_decode() {
 # Secret labels are validated separately: Helm omits Release.Labels from its
 # JSON encoding. Decode privately and read only; Helm owns every history write.
 jq -er '.data.release' "$1" | base64 --decode | base64 --decode | gzip -dc > "$2" || fail 'owned Helm history cannot be decoded'
}
addon_protected_state() {
 local ns=$1 output=$2 kind name item file="$GSJ_WORK/addon-protected.jsonl"
 : > "$file"
 kubectl --context "$CONTEXT" --namespace "$ns" get secrets -o json |
   jq -c '.items[]|select(.type!="helm.sh/release.v1")|{namespace:.metadata.namespace,name:.metadata.name,uid:.metadata.uid,type,data,immutable}' >> "$file"
 while IFS= read -r name; do
   item=$(k get Secret "$name" -o json --ignore-not-found)
   if [[ -n $item ]]; then jq -c '{namespace:.metadata.namespace,name:.metadata.name,uid:.metadata.uid,type,data,immutable}' <<< "$item" >> "$file"; fi
 done < <(jq -r --arg release "$RELEASE" '[.operator.secret,.tls.secret,.registry.pull_secret,$release+"-admin-token",$release+"-agent-token",$release+"-webhook",
   (if .tls.profile=="managed-acme" then .tls.issuer+"-account" else "" end),
   (if .llm.credential.file!="" then $release+"-llm-key" else .llm.credential.secret end),
   (if .ocr.credential.file!="" then $release+"-ocr-key" else .ocr.credential.secret end),
   (if .trust.proxy_file!="" then $release+"-proxy" else "" end)]|map(select(type=="string" and length>0))|unique[]' "$SITE")
 jq -s 'sort_by(.namespace,.name)' "$file" > "$output"
}
repair_managed_addon() {
 local addon=$1 ns=$2 release=$3 chart=$4 revision=$5 owner item name version latest_version obj_ns
 assert_owner
 owner=$(jq -r '.metadata.labels["gsj.io/addon-owner"]' "$GSJ_WORK/addon-owner.json")
 latest_version=$(jq -er '.items|map(.metadata.labels.version|tonumber)|max' "$GSJ_WORK/addon-history.json")
 jq -e 'all(.items[];.metadata.uid|type=="string" and length>0)' "$GSJ_WORK/addon-history.json" >/dev/null || fail 'addon Helm history is missing stable object identities'
 jq -e --arg revision "$revision" '.items|any(.[];.metadata.labels.version==$revision)' "$GSJ_WORK/addon-history.json" >/dev/null || fail 'selected addon revision does not exist in the owned history'
 # This is the pinned Helm client's supported, cluster-free serialization of
 # the signed chart bytes and exact reserved configuration, including hooks.
 require_offline_render; KUBECONFIG=/dev/null HELM_DRIVER=secret helm install "$release" "$chart" --namespace "$ns" --values "$GSJ_WORK/addon-helm-values.json" --skip-crds --dry-run=client --output json > "$GSJ_WORK/addon-expected-release.json"
 jq -e '[.items[]|select(.kind=="Secret" or .kind=="PersistentVolumeClaim" or .kind=="Namespace")]|length==0' "$GSJ_WORK/addon-render.json" >/dev/null || fail 'addon repair cannot include chart-managed credentials, claims or namespaces'
 # Equal chart/config/manifest/hook payloads across every retained record rule
 # out rollback's current-minus-target resource deletion path. Timestamps and
 # hook execution results are not source content; no other fields are ignored.
 while IFS= read -r item; do
   printf '%s\n' "$item" > "$GSJ_WORK/addon-history-secret.json"
   version=$(jq -er '.metadata.labels.version|select(test("^[1-9][0-9]*$"))' <<< "$item")
   addon_release_decode "$GSJ_WORK/addon-history-secret.json" "$GSJ_WORK/addon-history-release.json"
   jq -e --slurpfile expected "$GSJ_WORK/addon-expected-release.json" --arg name "$release" --arg ns "$ns" --argjson version "$version" '
     def content: {chart:(.chart|del(.modtime,.schemamodtime)),config:(.config // {}),manifest,hooks:((.hooks // [])|map(del(.last_run)))};
     .name==$name and .namespace==$ns and .version==$version and content==($expected[0]|content)
   ' "$GSJ_WORK/addon-history-release.json" >/dev/null || fail 'addon chart, values, manifest or hooks differ from the immutable reserved profile'
 done < <(jq -c '.items[]' "$GSJ_WORK/addon-history.json")
 : > "$GSJ_WORK/addon-crd-uids.jsonl"
 while IFS= read -r name; do
   kubectl --context "$CONTEXT" get CustomResourceDefinition "$name" -o json | jq -ce '{name:.metadata.name,uid:.metadata.uid}|select(.uid|type=="string" and length>0)' >> "$GSJ_WORK/addon-crd-uids.jsonl"
 done < <(jq -r '.items[]|select(.kind=="CustomResourceDefinition")|.metadata.name' "$GSJ_WORK/addon-render.json")
 addon_protected_state "$ns" "$GSJ_WORK/addon-protected-before.json"
 # Fence a competing Helm writer immediately before mutation using the full
 # named history objects (UID/resourceVersion/data), not a stale status string.
 kubectl --context "$CONTEXT" --namespace "$ns" get secrets,configmaps -l "owner=helm,name=$release" -o json > "$GSJ_WORK/addon-history-current.json"
 jq -e --slurpfile original "$GSJ_WORK/addon-history.json" '(.items|sort_by(.metadata.name))==($original[0].items|sort_by(.metadata.name))' "$GSJ_WORK/addon-history-current.json" >/dev/null || fail 'addon Helm history changed during repair preflight'
 log "Repairing owned addon $addon from explicit Helm revision $revision"
 HELM_DRIVER=secret addon_owned_run "$GSJ_WORK/addon-rollback.log" helm --kube-context "$CONTEXT" -n "$ns" rollback "$release" "$revision" --wait --wait-for-jobs --timeout=600s --history-max=0
 while IFS= read -r item; do
   name=$(jq -r .metadata.name <<< "$item"); obj_ns=$(jq -r --arg ns "$ns" '.metadata.namespace // $ns' <<< "$item")
   addon_owned_run "$GSJ_WORK/addon-rollout.log" kubectl --context "$CONTEXT" --namespace "$obj_ns" rollout status "deployment/$name" --timeout=600s
   kubectl --context "$CONTEXT" --namespace "$obj_ns" get Deployment "$name" -o json |
     jq -e --argjson expected "$item" '([.spec.template.spec.containers[]|{name,image}]|sort_by(.name))==([$expected.spec.template.spec.containers[]|{name,image}]|sort_by(.name))' >/dev/null || fail 'repaired addon controller image differs'
 done < <(jq -c '.items[]|select(.kind=="Deployment")' "$GSJ_WORK/addon-render.json")
 while IFS= read -r item; do
   name=$(jq -r .name <<< "$item")
   kubectl --context "$CONTEXT" get CustomResourceDefinition "$name" -o json | jq -e --arg uid "$(jq -r .uid <<< "$item")" '.metadata.uid==$uid' >/dev/null || fail 'addon repair changed a CRD identity'
 done < "$GSJ_WORK/addon-crd-uids.jsonl"
 addon_protected_state "$ns" "$GSJ_WORK/addon-protected-after.json"
 jq -e --slurpfile before "$GSJ_WORK/addon-protected-before.json" '.==$before[0]' "$GSJ_WORK/addon-protected-after.json" >/dev/null || fail 'addon repair changed a protected credential or Secret identity'
 kubectl --context "$CONTEXT" --namespace "$ns" get secrets,configmaps -l "owner=helm,name=$release" -o json > "$GSJ_WORK/addon-history-after.json"
 # Check old names/UIDs independently; Helm may legitimately update their
 # status or hook result while preserving every retained history record.
 jq -e --arg owner "$owner" --argjson previous "$latest_version" --slurpfile before "$GSJ_WORK/addon-history.json" '
   .items as $after | ($after|length)==($before[0].items|length)+1 and
   all($after[];.kind=="Secret" and .metadata.labels["gsj.io/addon-owner"]==$owner) and
   ([$after[]|select((.metadata.labels.version|tonumber)==($previous+1) and .metadata.labels.status=="deployed")]|length)==1 and
   all($before[0].items[]; . as $old | any($after[];.metadata.name==$old.metadata.name and .metadata.uid==$old.metadata.uid))
 ' "$GSJ_WORK/addon-history-after.json" >/dev/null || fail 'addon repair did not preserve owned history or reach a deployed new revision'
 while IFS= read -r item; do
   printf '%s\n' "$item" > "$GSJ_WORK/addon-history-secret.json"
   version=$(jq -er '.metadata.labels.version|select(test("^[1-9][0-9]*$"))' <<< "$item")
   addon_release_decode "$GSJ_WORK/addon-history-secret.json" "$GSJ_WORK/addon-history-release.json"
   jq -e --slurpfile expected "$GSJ_WORK/addon-expected-release.json" --arg name "$release" --arg ns "$ns" --argjson version "$version" --arg status "$(jq -r .metadata.labels.status <<< "$item")" '
     def content: {chart:(.chart|del(.modtime,.schemamodtime)),config:(.config // {}),manifest,hooks:((.hooks // [])|map(del(.last_run)))};
     .name==$name and .namespace==$ns and .version==$version and .info.status==$status and content==($expected[0]|content)
   ' "$GSJ_WORK/addon-history-release.json" >/dev/null || fail 'repaired addon history content differs from the immutable profile'
 done < <(jq -c '.items[]' "$GSJ_WORK/addon-history-after.json")
 jq --argjson version "$((latest_version+1))" '.items[]|select((.metadata.labels.version|tonumber)==$version)' "$GSJ_WORK/addon-history-after.json" > "$GSJ_WORK/addon-history-secret.json"
 addon_release_decode "$GSJ_WORK/addon-history-secret.json" "$GSJ_WORK/addon-repaired-release.json"
 if [[ $addon == certManager ]]; then
   jq -e '[(.hooks // [])[]|select(.events|index("post-rollback"))] as $hooks | ($hooks|length)==4 and all($hooks[];.last_run.phase=="Succeeded")' "$GSJ_WORK/addon-repaired-release.json" >/dev/null || fail 'cert-manager rollback startup API checks did not complete'
 fi
 assert_owner
 jq -n --arg operation "$OPERATION" --arg addon "$addon" --arg ns "$ns" --arg release "$release" --argjson selected "$revision" --argjson current "$((latest_version+1))" --arg profile "$(sha_file "$GSJ_WORK/addon-profile.json")" '{format:"gsj.addon-repair/1",operation:$operation,addon:$addon,namespace:$ns,release:$release,selected_revision:$selected,deployed_revision:$current,profile_sha256:$profile,credentials_preserved:true,crds_preserved:true,history_preserved:true}' | atomic "$STATE_DIR/addon-repair-$addon.json"
 log "Owned addon $addon repaired; credentials and CRD identities preserved"
}
acme_documents() {
 # Canonical source/target documents share exact specs; only namespace UID
 # ownership changes on a verified empty-target restore.
 local site=$1 uid=$2 prefix=$3 owner
 jq -cS --arg uid "$uid" '.target|{namespace_uid:$uid,namespace,release,purpose:"acme"}' "$site" > "$prefix-identity.json"
 owner=$(sha_file "$prefix-identity.json"); owner=${owner:0:40}
 jq -cS --slurpfile identity "$prefix-identity.json" --arg owner "$owner" '
   . as $s | ($s.public_url|sub("^https://";"")|split("/")[0]|split(":")[0]) as $host |
   {format:"gsj.acme-profile/1",owner:$identity[0],account_secret:($s.tls.issuer+"-account"),
    issuer:{name:$s.tls.issuer,spec:{acme:{email:$s.tls.email,server:$s.tls.acme_server,disableAccountKeyGeneration:true,
      privateKeySecretRef:{name:($s.tls.issuer+"-account")},solvers:[{http01:{ingress:{ingressClassName:$s.ingress.class}}}]}}},
    certificate:{name:$s.tls.secret,spec:{secretName:$s.tls.secret,dnsNames:[$host],issuerRef:{name:$s.tls.issuer,kind:"Issuer"},
      privateKey:{algorithm:"RSA",size:3072,rotationPolicy:"Never"},secretTemplate:{labels:{"gsj.io/acme-owner":$owner}}}}}
 ' "$site" > "$prefix-profile.json"
 jq -n --arg owner "$owner" --slurpfile profile "$prefix-profile.json" --rawfile identity "$prefix-profile.json" '$profile[0] as $p |
   {apiVersion:"v1",kind:"ConfigMap",metadata:{name:($p.owner.release+"-acme-owner"),namespace:$p.owner.namespace,
    labels:{"gsj.io/acme-owner":$owner,"gsj.io/owner":$p.owner.release}},immutable:true,data:{"identity.json":$identity}}' > "$prefix-owner.json"
 jq -n --arg owner "$owner" --slurpfile profile "$prefix-profile.json" '$profile[0] as $p |
   {apiVersion:"cert-manager.io/v1",kind:"Issuer",metadata:{name:$p.issuer.name,namespace:$p.owner.namespace,labels:{"gsj.io/acme-owner":$owner}},spec:$p.issuer.spec}' > "$prefix-issuer.json"
 jq -n --arg owner "$owner" --slurpfile profile "$prefix-profile.json" '$profile[0] as $p |
   {apiVersion:"cert-manager.io/v1",kind:"Certificate",metadata:{name:$p.certificate.name,namespace:$p.owner.namespace,labels:{"gsj.io/acme-owner":$owner}},spec:$p.certificate.spec}' > "$prefix-certificate.json"
}
owned_resource_matches() {
 jq -e --slurpfile expected "$2" '
   # Canonicalize only the positive resource spellings admitted by our site
   # schema. Bound integer arithmetic so distinct large quantities cannot
   # compare equal through floating-point rounding. Original intents stay raw.
   def quantity($kind):
     (if $kind=="cpu" then "^(?<number>[1-9][0-9]*)(?<unit>m)?$"
      else "^(?<number>[1-9][0-9]*)(?<unit>Ki|Mi|Gi|Ti)?$" end) as $pattern |
     if type!="string" then error("unsupported resource quantity")
     elif (test($pattern)|not) then error("unsupported resource quantity")
     else capture($pattern) end |
     if (.number|length)>16 then error("resource quantity exceeds exact comparison bound") else . end |
     (.number|tonumber) as $n |
     (if $kind=="cpu" then (if .unit=="m" then 1 else 1000 end)
      else {"":1,"Ki":1024,"Mi":1048576,"Gi":1073741824,"Ti":1099511627776}[.unit//""] end) as $factor |
     if $n > ((9007199254740991/$factor)|floor) then error("resource quantity exceeds exact comparison bound")
     else $n*$factor end;
   def container_resources:
     if has("resources") and .resources!=null then
       .resources |= reduce ["requests","limits"][] as $part (.;
         if has($part) then .[$part] |= with_entries(
           .key as $kind | if ($kind|IN("cpu","memory")) then .value |= quantity($kind) else . end)
         else . end)
     else . end;
   def defaults:
     if .kind=="Pod" then
       (if .spec.imagePullSecrets==null then .spec.imagePullSecrets=[] else . end) |
       (if .spec|has("containers") then .spec.containers |= map(container_resources) else . end) |
       (if .spec|has("initContainers") then .spec.initContainers |= map(container_resources) else . end)
     else . end;
   def matches($a;$e):
   if ($a|type)!=($e|type) then false
   elif ($e|type)=="object" then all($e|keys[]; . as $k | ($a|has($k)) and matches($a[$k];$e[$k]))
   elif ($e|type)=="array" then ($a|length)==($e|length) and all(range(0;$e|length); . as $i | matches($a[$i];$e[$i]))
   else $a==$e end; matches((.|defaults);($expected[0]|defaults))' "$1" >/dev/null
}
acme_secret_validate() {
 local file=$1 type=$2 owner=$3 host=${4:-} key_hash cert_hash
 jq -e --arg owner "$owner" --arg type "$type" '.kind=="Secret" and .type==$type and .metadata.labels["gsj.io/acme-owner"]==$owner and
   (.data["tls.key"]|type=="string" and length>0) and
   ($type!="kubernetes.io/tls" or (.data["tls.crt"]|type=="string" and length>0))' "$file" >/dev/null || fail 'ACME credential type, contents or ownership differs'
 jq -er '.data["tls.key"]' "$file" | base64 --decode > "$GSJ_WORK/acme-check.key"
 openssl pkey -in "$GSJ_WORK/acme-check.key" -check -noout >/dev/null 2>&1 || fail 'ACME private key is invalid'
 if [[ $type == kubernetes.io/tls ]]; then
   jq -er '.data["tls.crt"]' "$file" | base64 --decode > "$GSJ_WORK/acme-check.crt"
   certificate_names_host "$GSJ_WORK/acme-check.crt" "$host" || fail 'ACME certificate hostname differs'
   key_hash=$(openssl pkey -in "$GSJ_WORK/acme-check.key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)
   cert_hash=$(openssl x509 -in "$GSJ_WORK/acme-check.crt" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)
   [[ $key_hash == "$cert_hash" ]] || fail 'ACME certificate and private key differ'
 fi
 rm -f "$GSJ_WORK/acme-check.key" "$GSJ_WORK/acme-check.crt"
}
acme_validate_bundle() {
 local site=$1 uid=$2 bundle=$3 prefix="$GSJ_WORK/acme-audit" role kind name owner host account_hash expected_hash
 acme_documents "$site" "$uid" "$prefix"
 owner=$(jq -r '.metadata.labels["gsj.io/acme-owner"]' "$prefix-owner.json")
 host=$(jq -r '.certificate.spec.dnsNames[0]' "$prefix-profile.json")
 for role in owner issuer certificate; do
   kind=$(jq -r .kind "$prefix-$role.json"); name=$(jq -r .metadata.name "$prefix-$role.json")
   jq -e --arg kind "$kind" --arg name "$name" '.items[]|select(.kind==$kind and .metadata.name==$name)' "$bundle" > "$prefix-actual.json" || fail 'ACME backup is missing an owned configuration resource'
   owned_resource_matches "$prefix-actual.json" "$prefix-$role.json" || fail 'ACME backup configuration or source owner differs'
   if [[ $role == owner ]]; then expected_hash=$(jq -er '.data.account_key_sha256|select(test("^[a-f0-9]{64}$"))' "$prefix-actual.json") || fail 'ACME account key binding is missing'; fi
 done
 for role in account certificate; do
   if [[ $role == account ]]; then name=$(jq -r .account_secret "$prefix-profile.json"); kind=Opaque;
   else name=$(jq -r .certificate.name "$prefix-profile.json"); kind=kubernetes.io/tls; fi
   jq -e --arg name "$name" '.items[]|select(.kind=="Secret" and .metadata.name==$name)' "$bundle" > "$prefix-actual.json" || fail 'ACME backup is missing an owned credential'
   acme_secret_validate "$prefix-actual.json" "$kind" "$owner" "$host"
   if [[ $role == account ]]; then
     account_hash=$(jq -er '.data["tls.key"]' "$prefix-actual.json" | base64 --decode | openssl dgst -sha256 | awk '{print $NF}')
     [[ $account_hash == "$expected_hash" ]] || fail 'ACME account key differs from its immutable binding'
   fi
 done
}
managed_acme() {
 local uid prefix="$GSJ_WORK/acme" owner role kind name existing_record host account_hash expected_hash staged_key
 uid=$(k get namespace "$NAMESPACE" -o json | jq -er '.metadata.uid|select(type=="string" and length>0)')
 acme_documents "$SITE" "$uid" "$prefix"
 owner=$(jq -r '.metadata.labels["gsj.io/acme-owner"]' "$prefix-owner.json")
 host=$(jq -r '.certificate.spec.dnsNames[0]' "$prefix-profile.json")
 k get ConfigMap "$RELEASE-acme-owner" -o json --ignore-not-found > "$prefix-existing-owner.json"
 existing_record=false
 if [[ -s $prefix-existing-owner.json ]]; then
   owned_resource_matches "$prefix-existing-owner.json" "$prefix-owner.json" || fail 'ACME profile changed or belongs to another owner'
   expected_hash=$(jq -er '.data.account_key_sha256|select(test("^[a-f0-9]{64}$"))' "$prefix-existing-owner.json") || fail 'ACME account key binding is missing'
   existing_record=true
 fi
 # Read every named object before writes. An existing credential is not
 # permission to adopt a foreign Issuer/Certificate with the same name.
 for role in issuer certificate; do
   kind=$(jq -r .kind "$prefix-$role.json"); name=$(jq -r .metadata.name "$prefix-$role.json")
   k get "$kind" "$name" -o json --ignore-not-found > "$prefix-existing-$role.json"
   if [[ -s $prefix-existing-$role.json ]]; then
     $existing_record && owned_resource_matches "$prefix-existing-$role.json" "$prefix-$role.json" || fail 'ACME resource has no matching immutable owner'
   fi
 done
 for role in account tls; do
   if [[ $role == account ]]; then name=$(jq -r .account_secret "$prefix-profile.json"); kind=Opaque;
   else name=$(jq -r .certificate.name "$prefix-profile.json"); kind=kubernetes.io/tls; fi
   k get Secret "$name" -o json --ignore-not-found > "$prefix-existing-$role.json"
   if [[ -s $prefix-existing-$role.json ]]; then
     $existing_record || fail 'ACME credential already exists without its immutable owner'
     acme_secret_validate "$prefix-existing-$role.json" "$kind" "$owner" "$host"
   fi
 done
 [[ -s $prefix-existing-account.json || ! -s $prefix-existing-issuer.json ]] || fail 'ACME account key is missing; restore it explicitly instead of registering a replacement account'
 staged_key="$STATE_DIR/acme/$owner-account.key"
 if [[ -s $prefix-existing-account.json ]]; then
   account_hash=$(jq -er '.data["tls.key"]' "$prefix-existing-account.json" | base64 --decode | openssl dgst -sha256 | awk '{print $NF}')
   [[ $account_hash == "$expected_hash" ]] || fail 'ACME account key differs from its immutable binding'
 else
   # Keep a newly generated key private and durable until the Secret exists.
   # An established/restored owner with no such staged key must never mint one.
   if [[ ! -e $staged_key && ! -L $staged_key ]]; then
     ! $existing_record || fail 'ACME account key is missing; restore the original key before continuing'
     mkdir -p "$STATE_DIR/acme"
     openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$prefix-new-account.key" >/dev/null 2>&1
     cat "$prefix-new-account.key" | immutable_file "$staged_key"
     rm -f "$prefix-new-account.key"
   fi
   private_file "$staged_key"
   openssl pkey -in "$staged_key" -check -noout >/dev/null 2>&1 || fail 'staged ACME account key is invalid'
   account_hash=$(sha_file "$staged_key")
   if $existing_record; then [[ $account_hash == "$expected_hash" ]] || fail 'staged ACME key differs from its immutable binding'; fi
 fi
 jq --arg key_hash "$account_hash" '.data.account_key_sha256=$key_hash' "$prefix-owner.json" > "$prefix-bound-owner.json"
 owned_addon_create "$prefix-bound-owner.json"
 if [[ ! -s $prefix-existing-account.json ]]; then
   # Before an Issuer exists this key cannot have registered a remote account.
   # Once created, retries reuse the actual Secret and never regenerate it.
   jq -n --arg ns "$NAMESPACE" --arg name "$(jq -r .account_secret "$prefix-profile.json")" --arg owner "$owner" --rawfile key "$staged_key" '{apiVersion:"v1",kind:"Secret",metadata:{name:$name,namespace:$ns,labels:{"gsj.io/acme-owner":$owner}},type:"Opaque",data:{"tls.key":($key|@base64)}}' > "$prefix-new-account.json"
   k create -f "$prefix-new-account.json" >/dev/null
   rm -f "$prefix-new-account.json"
 fi
 rm -f "$staged_key"
 owned_addon_create "$prefix-issuer.json"
 owned_addon_create "$prefix-certificate.json"
 k wait --for=condition=Ready "issuer/$(jq -r .issuer.name "$prefix-profile.json")" --timeout=900s
 k wait --for=condition=Ready "certificate/$(jq -r .certificate.name "$prefix-profile.json")" --timeout=900s
}
managed_dependencies() {
 assert_owner
 local ns class image profile chart secret host tlsdir tlsprofile values
 profile=$(j .storage.profile)
 if [[ $profile == managed-local-path && $COMMAND != addon-repair ]]; then
   managed_storage "$(addon_path localPath)"
 fi
 if [[ $(j .ingress.profile) == managed-traefik && ( $COMMAND != addon-repair || $ADDON == traefik ) ]]; then
   ns=$(j .ingress.namespace); class=$(j .ingress.class); chart=$(addon_path traefik)
   image=$(jq -r '.addons.traefik.images.traefik' "$GSJ_PAYLOAD/release.json")
   # Traefik v3 cuts request reads after 60 s. Allow an hour for a large upload
   # (64 MiB needs about 19 KB/s) and never cut streaming responses (SSE, agent
   # turns). Fixed values: the owned addon profile is immutable per site.
   jq -n --arg class "$class" --arg image "$image" --arg service "$(j .ingress.service_type)" --argjson http "$(j .ingress.http_node_port)" --argjson https "$(j .ingress.https_node_port)" '{respondingTimeouts:{readTimeout:"3600s",writeTimeout:"0s"}} as $transport | {image:{registry:($image|split("/")[0]),repository:($image|split("/")[1:]|join("/")|split("@")[0]|split(":")[0]),digest:($image|split("@")[1])},ingressClass:{enabled:true,name:$class,isDefaultClass:false},providers:{kubernetesIngress:{ingressClass:$class}},service:{spec:{type:$service}},ports:{web:{nodePort:$http,transport:$transport},websecure:{nodePort:$https,transport:$transport}},log:{level:"INFO"}}' > "$GSJ_WORK/traefik-values.json"
   # Traefik installed by an earlier release recorded no entrypoint transport.
   # Its immutable owner profile is kept exactly; adopting the timeouts is an
   # explicit addon migration, never a side effect of install, repair or upgrade.
   if kubectl --context "$CONTEXT" --namespace "$ns" get configmap gsj-addon-owner -o json --ignore-not-found |
       jq -e '.data["identity.json"]|fromjson|.values.ports.web|has("transport")|not' >/dev/null 2>&1; then
     jq 'del(.ports.web.transport,.ports.websecure.transport)' "$GSJ_WORK/traefik-values.json" > "$GSJ_WORK/traefik-legacy-values.json"
     mv -f "$GSJ_WORK/traefik-legacy-values.json" "$GSJ_WORK/traefik-values.json"
     log 'Managed Traefik predates entrypoint timeouts; its recorded profile is kept, so requests longer than 60 s can be cut. Adopting the timeouts needs an explicit addon migration.'
   fi
   if [[ $COMMAND == addon-repair ]]; then managed_helm_addon traefik "$ns" "$class" "$chart" "$GSJ_WORK/traefik-values.json" "$REVISION"; return;
   else managed_helm_addon traefik "$ns" "$class" "$chart" "$GSJ_WORK/traefik-values.json"; fi
 fi
 tlsprofile=$(j .tls.profile); secret=$(j .tls.secret); host=$(j .public_url | sed -E 's#https://([^/:]+).*#\1#')
 case "$tlsprofile" in
 existing)
   k get secret "$secret" -o json | jq -e '.type=="kubernetes.io/tls" and .data["tls.crt"] and .data["tls.key"]' >/dev/null || fail 'TLS Secret is unavailable or incomplete';;
 files)
   local crt key; crt=$(resolve_file "$(j .tls.certificate_file)"); key=$(resolve_file "$(j .tls.private_key_file)"); private_file "$key"
   openssl x509 -in "$crt" -noout >/dev/null 2>&1 || fail "tls.certificate_file is not a readable PEM certificate ($(j .tls.certificate_file)); the host was not checked"
   certificate_names_host "$crt" "$host" || fail 'TLS certificate host mismatch'
   if k get secret "$secret" >/dev/null 2>&1; then secret_file "$secret" tls.crt "$crt"; secret_file "$secret" tls.key "$key";
   else k create secret tls "$secret" --cert="$crt" --key="$key" >/dev/null; fi;;
 managed-local-ca)
   tlsdir="$STATE_DIR/tls"; mkdir -p "$tlsdir"
   if ! k get secret "$secret" >/dev/null 2>&1; then
     if [[ ! -f $tlsdir/ca.key ]]; then
       openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 -subj '/CN=GSJ sandbox local CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout "$tlsdir/ca.key" -out "$tlsdir/ca.crt" > "$GSJ_WORK/tls.log" 2>&1
     fi
     openssl req -new -newkey rsa:3072 -nodes -subj "/CN=$host" -keyout "$tlsdir/tls.key" -out "$tlsdir/tls.csr" > "$GSJ_WORK/tls.log" 2>&1
     printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\n' "$host" > "$tlsdir/extensions"
     openssl x509 -req -in "$tlsdir/tls.csr" -CA "$tlsdir/ca.crt" -CAkey "$tlsdir/ca.key" -CAcreateserial -days 365 -sha256 -extfile "$tlsdir/extensions" -out "$tlsdir/tls.crt" > "$GSJ_WORK/tls.log" 2>&1
     k create secret tls "$secret" --cert="$tlsdir/tls.crt" --key="$tlsdir/tls.key" >/dev/null
   fi
   [[ -f $tlsdir/ca.crt ]] || fail 'local CA recovery metadata is missing; restore it before reuse'
   # load_site saved these paths before the operation; never rewrite them here.
   jq -e --arg ca "$tlsdir/ca.crt" '.verification.ca_file==$ca and .tls.ca_file==$ca' "$SITE" >/dev/null || fail 'the operation configuration does not record the managed local CA path'
   log "Local certificate authority: $tlsdir/ca.crt. Browser trust is an explicit operator step.";;
 managed-acme)
   chart=$(addon_path certManager)
   jq -n --slurpfile release "$GSJ_PAYLOAD/release.json" '$release[0].addons.certManager.images as $i | {crds:{enabled:true},image:{repository:($i.controller|split("@")[0]),digest:($i.controller|split("@")[1])},cainjector:{image:{repository:($i.cainjector|split("@")[0]),digest:($i.cainjector|split("@")[1])}},webhook:{image:{repository:($i.webhook|split("@")[0]),digest:($i.webhook|split("@")[1])}},startupapicheck:{image:{repository:($i.startupapicheck|split("@")[0]),digest:($i.startupapicheck|split("@")[1])}},acmesolver:{image:{repository:($i.acmesolver|split("@")[0]),digest:($i.acmesolver|split("@")[1])}}}' > "$GSJ_WORK/cert-values.json"
   if [[ $COMMAND == addon-repair ]]; then managed_helm_addon certManager gsj-cert-manager gsj-cert-manager "$chart" "$GSJ_WORK/cert-values.json" "$REVISION"; return;
   else managed_helm_addon certManager gsj-cert-manager gsj-cert-manager "$chart" "$GSJ_WORK/cert-values.json"; fi
   managed_acme;;
 esac
}
storage_probe() {
 assert_owner
 local name="$RELEASE-storage-${OPERATION:0:8}" image uid volume result=0 probe_claim
 probe_claim=$(j .storage.data.existing_claim); local fresh=false
 if [[ -z $probe_claim ]]; then probe_claim=$name; fresh=true; fi
 image=$(payload_image web)
 if $fresh; then jq -n --arg name "$name" --arg class "$(j .storage.class)" '{apiVersion:"v1",kind:"PersistentVolumeClaim",metadata:{name:$name,labels:{"gsj.io/verification":$name}},spec:{accessModes:["ReadWriteOnce"],storageClassName:$class,resources:{requests:{storage:"1Gi"}}}}' | k create -f - >/dev/null; fi
 cat > "$GSJ_WORK/storage-check.py" <<'PY'
import fcntl, json, os, pathlib, shutil, sqlite3, subprocess, sys, tempfile
root=pathlib.Path('/probe'); v=os.statvfs(root); free=v.f_bavail*v.f_frsize
assert free>=int(sys.argv[1]), 'backend has insufficient measured free space'
p=pathlib.Path(tempfile.mkdtemp(prefix='.gsj-storage-check-',dir=root))
try:
    with (p/'lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        child=subprocess.run([sys.executable,'-c','import fcntl,sys; f=open(sys.argv[1],"w"); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)',str(p/'lock')],capture_output=True)
        assert child.returncode != 0, 'filesystem did not enforce cross-process advisory lock'
    db=sqlite3.connect(p/'probe.db'); assert db.execute('pragma journal_mode=wal').fetchone()[0]=='wal'
    db.execute('create table synthetic (id integer primary key, value text)'); db.execute('insert into synthetic values (1,?)',('GSJ storage verification',)); db.commit()
    assert db.execute('pragma integrity_check').fetchone()[0]=='ok'; db.execute('pragma wal_checkpoint(truncate)'); db.close()
    db=sqlite3.connect(p/'probe.db'); assert db.execute('select value from synthetic where id=1').fetchone()[0]=='GSJ storage verification'; db.close()
    with (p/'pending').open('wb') as out: out.write(b'GSJ fsync test'); out.flush(); os.fsync(out.fileno())
    os.replace(p/'pending',p/'complete'); fd=os.open(p,os.O_RDONLY); os.fsync(fd); os.close(fd)
    print(json.dumps({'status':'passed','backend_available_bytes':free,'filesystem_block_bytes':v.f_frsize,'wal':True,'fsync':True,'cross_process_lock':True}))
finally: shutil.rmtree(p)
PY
 jq -n --arg name "$name" --arg image "$image" --arg node "$(j .storage.node)" --arg claim "$probe_claim" --arg minimum "$(j .storage.minimum_free_bytes)" --rawfile script "$GSJ_WORK/storage-check.py" --argjson pulls "$(jq '.image.pullSecrets|map({name:.})' "$GSJ_WORK/values.pending.json")" '{apiVersion:"v1",kind:"Pod",metadata:{name:$name,labels:{"gsj.io/verification":$name}},spec:{restartPolicy:"Never",automountServiceAccountToken:false,nodeSelector:{"kubernetes.io/hostname":$node},imagePullSecrets:$pulls,containers:[{name:"storage-check",image:$image,command:["python","-c",$script,$minimum],resources:{requests:{cpu:"100m",memory:"128Mi"},limits:{memory:"256Mi"}},volumeMounts:[{name:"probe",mountPath:"/probe"}]}],volumes:[{name:"probe",persistentVolumeClaim:{claimName:$claim}}]}}' | k create -f - >/dev/null
 local end=$((SECONDS+300)) phase=''
 while (( SECONDS < end )); do phase=$(k get pod "$name" -o jsonpath='{.status.phase}'); [[ $phase == Succeeded || $phase == Failed ]] && break; sleep 3; done
 # The check's Pod never ran to an end: the disk was never tested, and the
 # verdict at the bottom must not call it a storage failure. Read what the
 # Pod reported while it still exists. Measured: with no registry.base the
 # pull probe does not run, so a pull Secret that is wrong, an expired token
 # or a node that cannot reach the registry is first met HERE -- the Pod sat
 # in ImagePullBackOff for 300 s and the run ended `storage WAL/locking/
 # fsync/free-space qualification failed`, sending the operator to the disk.
 # The operation's recorded status decides every hint of this check: "owned"
 # is a first install (nothing applied, nothing quiesced: resume repeats this
 # check, and abandon then install again takes a changed site value); after
 # the backup (backup-verified) the deployment is quiesced, abandon refuses,
 # resume continues from the backup WITHOUT this check, and a changed site
 # value is repair's. Every caller writes that status before this check runs.
 local status; status=$(jq -r '.status // ""' "$STATE_DIR/operation.json" 2>/dev/null || true)
 local first=true; [[ $status == owned || -z $status ]] || first=false
 local rerun="The storage check runs again on resume"; $first || rerun="resume continues from the verified backup and does not repeat this check"
 local continue_hint="resume --operation $OPERATION (it continues from the verified backup without repeating this check)"
 local never='' status_note="The Pod's last status is in $STATE_DIR/storage-check-pod.json."
 if [[ $phase != Succeeded && $phase != Failed ]]; then
   # The Pod's status is kept in the state directory: the cleanup below
   # deletes the Pod, and the scheduler's or the runtime's own words are the
   # diagnosis the operator will need. They are not repeated in the refusal.
   local snapshot
   k get pod "$name" -o json > "$STATE_DIR/storage-check-pod.json" 2>/dev/null || : > "$STATE_DIR/storage-check-pod.json"
   # A snapshot that could not be read keeps the phase the poll last saw, and
   # the messages say the status could not be read instead of naming the file.
   snapshot=$(jq -r '.status.phase // ""' "$STATE_DIR/storage-check-pod.json" 2>/dev/null || true)
   [[ -z $snapshot ]] || phase=$snapshot
   [[ -s $STATE_DIR/storage-check-pod.json ]] || status_note="The Pod's last status could not be read (kubectl get failed); its phase is the one the poll last saw."
   never=$(jq -r '
     if (.status.phase // "") == "Succeeded" or (.status.phase // "") == "Failed" then "" else
     ([(.status.containerStatuses // [])[] | (.state.waiting.reason // "") | select(test("^(ErrImage|ImagePull|ImageInspect|InvalidImageName|RegistryUnavailable)"))] | first // "") as $pull
     | ([(.status.conditions // [])[] | select(.type == "PodScheduled" and .status == "False") | (.reason // "Unschedulable")] | first // "") as $sched
     | if $pull != "" then "pull " + $pull elif $sched != "" then "sched " + $sched else "wait " + (.status.phase // "unknown") end end' "$STATE_DIR/storage-check-pod.json" 2>/dev/null || true)
   [[ -n $never || $phase == Succeeded || $phase == Failed ]] || never="wait ${phase:-unknown}"
   # the reason and the phase are the API's words; the message is never read
   # here, and only a value this installer KNOWS is repeated -- any other
   # reason is "other" [review sweep B2]
   case ${never%% *} in
     '') ;;                                        # the Pod ended between the last poll and the snapshot: the phase is the verdict
     pull) never="pull $(known_word "${never#* }" ErrImagePull ImagePullBackOff ErrImageNeverPull ImageInspectError InvalidImageName RegistryUnavailable)";;
     sched) never="sched $(known_word "${never#* }" Unschedulable SchedulerError)";;
     *) never="wait $(known_word "${never#* }" Pending Running Succeeded Failed Unknown unknown)";;
   esac
 fi
 # The Pod's phase is the verdict (the check exits 0 only when every assert
 # held); the log carries its measurements. A log that could not be read is
 # a missing measurement, never a failed check.
 local logs_read=true
 k logs "$name" > "$STATE_DIR/storage-check.json" || logs_read=false
 [[ $phase == Succeeded ]] || result=1
 uid=$(k get pvc "$probe_claim" -o jsonpath='{.metadata.uid}'); volume=$(k get pvc "$probe_claim" -o jsonpath='{.spec.volumeName}')
 k delete pod "$name" --wait=true >/dev/null
 # Only this fresh verification claim's exact bound PV can be made disposable.
 if $fresh && [[ -n $volume ]]; then
   k get pv "$volume" -o json | jq -e --arg uid "$uid" --arg ns "$NAMESPACE" '.spec.claimRef.uid==$uid and .spec.claimRef.namespace==$ns' >/dev/null || fail 'storage-check PV ownership changed'
   k patch pv "$volume" --type=merge -p '{"spec":{"persistentVolumeReclaimPolicy":"Delete"}}' >/dev/null
 fi
 if $fresh; then k delete pvc "$probe_claim" --wait=true >/dev/null; fi
 # The same four words used to end two different stories, and the volume's own
 # phase tells them apart. Released with reclaim policy Delete and nothing able
 # to delete it goes Failed -- measured on a hand-made
 # kubernetes.io/no-provisioner class with storage.data.existing_claim left
 # empty: the temporary claim bound one of the operator's OWN volumes and the
 # patch above marked it Delete. Any other phase is a provisioner or a
 # static-volume deleter still at work, and that volume is not the operator's to
 # touch. (The StorageClass's provisioner string cannot tell these apart: the
 # sig-storage static provisioner, which does delete, uses the same one.)
 if $fresh && [[ -n $volume ]] && ! k wait --for=delete "pv/$volume" --timeout=120s; then
   # This refusal comes before the check's own verdict below; do not let it hide one.
   local note='' phase
   # The note claims only what the Pod established about the check itself.
   if [[ $never == "wait Running" ]]; then note=" The storage check itself was still running when its 300 s wait ran out, so the storage backend was not tested to the end."
   elif [[ -n $never ]]; then note=" The storage check itself never ran (${never#* }), so the storage backend was not tested. $status_note"
   elif [[ $phase == Failed ]]; then
     if $logs_read && [[ -s $STATE_DIR/storage-check.json ]]; then note=" The storage check itself did not pass either; what it printed is in $STATE_DIR/storage-check.json."
     elif $logs_read; then note=" The storage check itself did not pass either (its Pod ended Failed), and it printed nothing."
     else note=" The storage check itself did not pass either (its Pod ended Failed), and what it printed could not be read (kubectl logs failed)."; fi
   elif ! $logs_read; then note=" The storage check itself passed (its Pod ended Succeeded), though its measurements could not be read (kubectl logs failed)."
   fi
   phase=$(k get pv "$volume" -o jsonpath='{.status.phase}' 2>/dev/null || true)
   [[ -z $phase ]] || phase=$(known_word "$phase" Pending Available Bound Released Failed)   # a phase this installer knows, or "other"; unreadable stays unknown [review sweep B2]
   # After the backup a check whose Pod ended Failed (it started, and its own
   # asserts did not hold) is the backend's to correct, and resume will not
   # repeat the check: both refusals say so. A Pod that never ran is not that.
   local backend_note=''
   if ! $first && (( result != 0 )) && [[ -z $never ]]; then backend_note=", and the check itself did not pass (below), so correct the backend first"; fi
   if [[ $phase == Failed ]]; then
     # resume compares the site byte for byte and would refuse the edit this asks for.
     if $first; then RECOVERY_HINT="abandon --operation $OPERATION --reason \"...\" --config $CONFIG --non-interactive once this operation's Lease has gone 180 s unrenewed, then install again with storage.data.existing_claim naming a claim of your own"
     elif [[ -n $backend_note ]]; then RECOVERY_HINT="$continue_hint; a claim of your own in storage.data.existing_claim is a changed storage block, which is refused for an installed release; correct the backend first"
     else RECOVERY_HINT="$continue_hint; a claim of your own in storage.data.existing_claim is a changed storage block, which is refused for an installed release"; fi
     # (no command substitution here: as the last command of an || list its
     # status would be the assignment's, and errexit would end the run silently)
     local own_claim="Name a claim of your own in storage.data.existing_claim, so that no temporary claim is made."
     if ! $first; then own_claim="A claim of your own in storage.data.existing_claim would be a changed storage block, which is refused for an installed release; resume continues without this check$backend_note."; fi
     fail "temporary storage backend cleanup incomplete: PersistentVolume $volume was bound by this check's own temporary claim and marked Delete, and it is now Failed: nothing on this cluster deletes a volume of StorageClass $(j .storage.class). $own_claim $volume accepts no claim until that PersistentVolume object is deleted and created again; anything this check left in its directory is named .gsj-storage-check-*.$note"
   fi
   if ! $first; then RECOVERY_HINT="$continue_hint${backend_note:+; correct the backend first}"; fi
   fail "temporary storage backend cleanup incomplete: PersistentVolume $volume, which this check's own temporary claim had bound, was still present (phase ${phase:-unknown}) 120 s after that claim was deleted. Whatever removes volumes of StorageClass $(j .storage.class) is slow or stuck. Do not delete the volume by hand: look at that provisioner or deleter, then continue with the command the closing line names${backend_note}.$note"
 fi
 # A Pod that never ran is named for what the node reported, never for the
 # disk it did not test. The image is the release's own reference; the
 # runtime's message is not repeated (it names the registry route).
 case $never in
   "pull "*)
     local pull_secret secret_note=''
     pull_secret=$(j '.registry.pull_secret // ""')
     [[ -z $pull_secret ]] || secret_note=" (a corrected credential file needs the pull Secret $pull_secret in namespace $NAMESPACE deleted first, so resume recreates it from the file)"
     if $first; then
       RECOVERY_HINT="resume --operation $OPERATION once the node can pull the image$secret_note; a changed site value (registry.base, registry.config_file) cannot be resumed: abandon --operation $OPERATION --reason \"...\" --config $CONFIG --non-interactive after 180 s and install again from the corrected file, which repeats this check (a repair would apply the change without it)"
     else
       RECOVERY_HINT="resume --operation $OPERATION once the node can pull the image$secret_note (this check is not repeated after the backup); a changed site value (registry.base, registry.config_file) cannot be resumed: repair --operation $OPERATION --config $CONFIG --non-interactive after 180 s"
     fi
     fail "the storage check's Pod could not pull its image $image on node $(j .storage.node) (${never#pull }), so the storage backend was not tested. Check registry.config_file and registry.pull_secret (the credential for that registry), that the node reaches the registry and, with registry.base, that the image was copied there unchanged. $rerun";;
   "sched "*)
     if $first; then
       RECOVERY_HINT="resume --operation $OPERATION once room is freed on node $(j .storage.node) or StorageClass $(j .storage.class) binds claims again; a changed storage.node cannot be resumed: abandon --operation $OPERATION --reason \"...\" --config $CONFIG --non-interactive after 180 s and install again from the corrected file"
     else
       RECOVERY_HINT="resume --operation $OPERATION once room is freed on node $(j .storage.node) or StorageClass $(j .storage.class) binds claims again (this check is not repeated after the backup; a changed storage block is refused for an installed release: the claims stay where they are)"
     fi
     fail "the storage check's Pod was not scheduled (${never#sched }), so the storage backend was not tested. Either no node matched storage.node ($(j .storage.node)) with room for the Pod, or its claim on StorageClass $(j .storage.class) could not be bound. $status_note $rerun";;
   "wait Running")
     if $first; then RECOVERY_HINT="resume --operation $OPERATION once the check can finish; if it stays stuck, its node $(j .storage.node) and StorageClass $(j .storage.class) are where to look"
     else RECOVERY_HINT="$continue_hint"; fi
     fail "the storage check was still running when its 300 s wait ran out, so the storage backend was not tested to the end: the Pod had started and the check itself (locking, WAL, fsync, free space on the claim) had not finished. $status_note Look at its node $(j .storage.node) and StorageClass $(j .storage.class), then resume";;
   "wait "*)
     if $first; then RECOVERY_HINT="resume --operation $OPERATION once the node has pulled the image and bound the claim"
     else RECOVERY_HINT="$continue_hint"; fi
     fail "the storage check did not finish within 300 s (Pod phase ${never#wait }), so the storage backend was not tested: the node was still pulling the image or the claim was still binding when the wait ran out, or the check was stuck. $status_note Look at the node's image pulls and StorageClass $(j .storage.class), then resume";;
 esac
 if (( result != 0 )); then
   if $first; then RECOVERY_HINT="resume --operation $OPERATION once the backend is corrected (resume repeats this check)"
   else RECOVERY_HINT="$continue_hint; correct the backend first"; fi
   fail 'storage WAL/locking/fsync/free-space qualification failed'
 fi
 if $logs_read; then log 'Storage passed WAL, fsync, cross-process locking and actual backend free-space checks'
 else log "Storage passed WAL, fsync, cross-process locking and free-space checks (the check's Pod ended Succeeded); its measurements could not be read: kubectl logs on the check's Pod failed (the kubeconfig may lack pods/log in namespace $NAMESPACE)"; fi
}

read_installed() {
 k get configmap "$RELEASE-installed" -o json --ignore-not-found | jq -r '.data["installed.json"] // empty' > "$GSJ_WORK/installed.json"
 if [[ ! -s $GSJ_WORK/installed.json ]]; then k get configmap "$RELEASE-ready-state" -o json --ignore-not-found | jq -r '.data["installed.json"] // empty' > "$GSJ_WORK/installed.json"; fi
}
storage_identity() {
 local role claim
 for role in data forgejo chroma; do
   claim=$(jq -r --arg role "$role" '.storage[$role].existingClaim' "$GSJ_WORK/values.pending.json"); claim=${claim:-$RELEASE-$role}
   k get pvc "$claim" -o json | jq '{name:.metadata.name,uid:.metadata.uid,volume:.spec.volumeName,storageClass:.spec.storageClassName,requested:.spec.resources.requests.storage,capacity:.status.capacity.storage}'
 done | jq -s 'sort_by(.name)'
}

compatibility() {
 case "${1:-installed}" in
   installed) read_installed;;
   selected) [[ -s $GSJ_WORK/installed.json ]] || fail 'selected source metadata is unavailable';;
   *) fail 'invalid compatibility source selection';;
 esac
 [[ -s $GSJ_WORK/installed.json ]] || return 0
 jq -e --slurpfile site "$SITE" '.site.target == $site[0].target and .site.operator == $site[0].operator and .site.storage == $site[0].storage' "$GSJ_WORK/installed.json" >/dev/null || fail 'upgrade cannot change target, operator or storage identity; use a qualified migration/restore operation'
 jq -e --slurpfile release "$GSJ_PAYLOAD/release.json" '.manifest.model == $release[0].model' "$GSJ_WORK/installed.json" >/dev/null || fail 'model change blocked until both case and decision index migration is supported'
 local source; source=$(jq -r .manifest.identity "$GSJ_WORK/installed.json")
 if [[ $source != "$RELEASE_ID" ]]; then
   jq -e --arg source "$source" '.supported_sources | index($source)' "$GSJ_PAYLOAD/release.json" >/dev/null || fail 'target release does not declare this source-to-target transition'
   [[ $(jq -r .site.schema_version "$GSJ_WORK/installed.json") == gsj.site/1 ]] || fail 'source configuration schema requires an explicit target migration'
 fi
 storage_identity > "$GSJ_WORK/storage.json"
 jq -e --slurpfile actual "$GSJ_WORK/storage.json" '.storage == $actual[0]' "$GSJ_WORK/installed.json" >/dev/null || fail 'persistent storage identity changed; restore bindings before upgrading'
 local actual_ns; actual_ns=$(k get namespace "$NAMESPACE" -o json | jq -r .metadata.uid)
 [[ $(jq -r .namespace_uid "$GSJ_WORK/installed.json") == "$actual_ns" ]] || fail 'namespace was recreated; this is a recovery target, not an upgrade'
 if [[ $(jq -r .manifest.corpus.fingerprint "$GSJ_WORK/installed.json") != $(jq -r .corpus.fingerprint "$GSJ_PAYLOAD/release.json") && $(j .corpus.allow_update) != true ]]; then fail 'corpus change requires explicit corpus.allow_update=true and a pre-migration backup'; fi
}
# GSJ_RUNTIME_HELPER: capacity.py
capacity_host_filesystems() {
 # GNU stat uses statfs on the actual destination, never its configured size.
 # Host Python is deliberately not a prerequisite of the shipped installer.
 local role path identity blocks unit inodes
 : > "$GSJ_WORK/capacity-host.jsonl"
 for role in backup work; do
   if [[ $role == backup ]]; then path=$BACKUP_DIR; else path=$GSJ_WORK; fi
   [[ -d $path && ! -L $path ]] || fail 'capacity destination must be an existing ordinary directory'
   read -r identity blocks unit inodes < <(stat -f -c '%i %a %S %d' -- "$path")
   [[ $identity =~ ^[0-9a-f]+$ && $blocks =~ ^[0-9]+$ && $unit =~ ^[0-9]+$ && $inodes =~ ^[0-9]+$ ]] || fail 'script-host filesystem capacity is unknown; GNU stat is required'
   (( unit > 0 && inodes > 0 )) || fail 'script-host filesystem bytes or free inodes are unknown'
   jq -n --arg role "$role" --arg identity "$identity" --argjson blocks "$blocks" --argjson unit "$unit" --argjson inodes "$inodes" '{key:$role,value:{filesystem_id:$identity,available_bytes:($blocks*$unit),available_inodes:$inodes,block_bytes:$unit}}' >> "$GSJ_WORK/capacity-host.jsonl"
 done
 jq -s 'from_entries' "$GSJ_WORK/capacity-host.jsonl" > "$GSJ_WORK/capacity-host.json"
}
restore_capacity_context() {
 # The historical installed record belongs to the backup's source namespace.
 # Build a separate target context; never relabel that historical record.
 local output=$1 saved="$STATE_DIR/restore-$OPERATION" source="$GSJ_WORK/capacity-restored-source.json" role claim
 local config='' kind candidate="$GSJ_WORK/capacity-restored-candidate.json"
 jq -e --arg op "$OPERATION" --arg target "$RELEASE_ID" '.operation==$op and .target==$target and .kind=="restore" and .status=="restore-files-verified"' "$STATE_DIR/operation.json" >/dev/null || fail 'restored capacity requires the exact file-verified operation'
 jq -e --arg op "$OPERATION" --arg target "$RELEASE_ID" '.format=="gsj.restore/1" and .operation==$op and .release_identity==$target and .status=="files-restored"' "$STATE_DIR/restoration.json" >/dev/null || fail 'restored capacity checkpoint differs'
 for role in files-settings.json files-result.json archive-proof.json bindings.json; do
   [[ -f $saved/$role && ! -L $saved/$role ]] || fail 'restored capacity requires durable archive, file and storage proof'
 done
 restore_validate_result "$saved/files-result.json"
 restore_bindings
 jq -e --arg op "$OPERATION" --arg release "$RELEASE_ID" --slurpfile checkpoint "$STATE_DIR/restoration.json" --slurpfile bindings "$saved/bindings.json" --slurpfile proof "$saved/archive-proof.json" '
   .format=="gsj.restore-files/1" and .operation==$op and .release_identity==$release and
   .namespace_uid==$checkpoint[0].target_namespace_uid and .encrypted_archive_sha256==$checkpoint[0].archive_sha256 and
   .archive_sha256==$proof[0].archive_sha256 and .volumes==$bindings[0]
 ' "$saved/files-settings.json" >/dev/null || fail 'restored file proof is not bound to this target and archive'
 restore_no_writers "$RELEASE-capacity-${OPERATION:0:8}"
 # A backup of a verification-pending source carries only its ready-state
 # record. Use the restored record that describes this archived source release.
 for kind in installed ready-state; do
   [[ -f $saved/ConfigMap/$RELEASE-$kind/intent.json && ! -L $saved/ConfigMap/$RELEASE-$kind/intent.json ]] || continue
   jq -er '.data["installed.json"]' "$saved/ConfigMap/$RELEASE-$kind/intent.json" > "$source" 2>/dev/null || continue
   if jq -e --slurpfile release "$GSJ_PAYLOAD/release.json" --slurpfile checkpoint "$STATE_DIR/restoration.json" --arg ns "$NAMESPACE" --arg name "$RELEASE" '
     .format=="gsj.installed/1" and .manifest==$release[0] and .namespace_uid==$checkpoint[0].source_namespace_uid and
     .site.target.namespace==$ns and .site.target.release==$name
   ' "$source" >/dev/null 2>&1; then config="$saved/ConfigMap/$RELEASE-$kind"; break; fi
 done
 [[ -n $config ]] || fail 'historical source release or namespace differs from the restore proof'
 for role in intent.json attempt.json receipt.json; do
   [[ -f $config/$role && ! -L $config/$role ]] || fail 'historical installed record has no restore ownership receipt'
 done
 k get configmap "${config##*/}" -o json > "$GSJ_WORK/capacity-restored-configmap.json"
 jq -e --arg sha "$(sha_file "$config/intent.json")" --slurpfile intent "$config/intent.json" --slurpfile attempt "$config/attempt.json" --slurpfile receipt "$config/receipt.json" '
   .kind=="ConfigMap" and .metadata.uid==$receipt[0].uid and .metadata.deletionTimestamp==null and
   $receipt[0].intent_sha256==$sha and $attempt[0].intent_sha256==$sha and $attempt[0].attempted==true and
   .metadata.name==$intent[0].metadata.name and .metadata.namespace==$intent[0].metadata.namespace and
   .metadata.labels["gsj.io/restore-operation"]==$intent[0].metadata.labels["gsj.io/restore-operation"] and
   .metadata.annotations["gsj.io/restore-archive-sha256"]==$intent[0].metadata.annotations["gsj.io/restore-archive-sha256"] and
   (.data//{})==($intent[0].data//{}) and (.binaryData//{})==($intent[0].binaryData//{})
 ' "$GSJ_WORK/capacity-restored-configmap.json" >/dev/null || fail 'historical installed resource changed after restore'
 k get namespace "$NAMESPACE" -o json > "$GSJ_WORK/capacity-restored-namespace.json"
 jq -e --slurpfile checkpoint "$STATE_DIR/restoration.json" '.metadata.uid==$checkpoint[0].target_namespace_uid and .metadata.deletionTimestamp==null' "$GSJ_WORK/capacity-restored-namespace.json" >/dev/null || fail 'restored capacity namespace changed'
 k get node "$(j .storage.node)" -o json > "$GSJ_WORK/capacity-restored-node.json"
 jq -e --arg node "$(j .storage.node)" '.metadata.name==$node and (.metadata.uid|type=="string" and length>0) and .metadata.labels["kubernetes.io/hostname"]==$node and any(.status.conditions[];.type=="Ready" and .status=="True")' "$GSJ_WORK/capacity-restored-node.json" >/dev/null || fail 'restored capacity node identity or readiness differs'
 : > "$GSJ_WORK/capacity-restored-storage.jsonl"
 while IFS= read -r claim; do
   k get pvc "$claim" -o json | jq '{name:.metadata.name,uid:.metadata.uid,volume:.spec.volumeName,storageClass:.spec.storageClassName,requested:.spec.resources.requests.storage,capacity:.status.capacity.storage}' >> "$GSJ_WORK/capacity-restored-storage.jsonl"
 done < <(jq -r 'to_entries|sort_by(.value.name)|.[].value.name' "$saved/bindings.json")
 jq -s '.' "$GSJ_WORK/capacity-restored-storage.jsonl" > "$GSJ_WORK/capacity-restored-storage.json"
 jq -n --arg source_sha "$(sha_file "$source")" --arg files_sha "$(sha_file "$saved/files-result.json")" --arg bindings_sha "$(sha_file "$saved/bindings.json")" --slurpfile historical "$source" --slurpfile checkpoint "$STATE_DIR/restoration.json" --slurpfile node "$GSJ_WORK/capacity-restored-node.json" --slurpfile site "$SITE" --slurpfile storage "$GSJ_WORK/capacity-restored-storage.json" '
   {format:"gsj.restore-capacity-context/1",manifest:$historical[0].manifest,site:$site[0],storage:$storage[0],namespace_uid:$checkpoint[0].target_namespace_uid,node_uid:$node[0].metadata.uid,
    restoration:{operation:$checkpoint[0].operation,source_namespace_uid:$checkpoint[0].source_namespace_uid,archive_sha256:$checkpoint[0].archive_sha256,historical_installed_sha256:$source_sha,files_result_sha256:$files_sha,bindings_sha256:$bindings_sha}}
 ' > "$candidate"
 if [[ -e $output || -L $output ]]; then
   [[ -f $output && ! -L $output ]] && cmp -s "$candidate" "$output" || fail 'restored capacity binding changed during measurement'
 else cat "$candidate" | immutable_file "$output"; fi
}
restore_capacity_qualify() {
 local CAPACITY_CONTEXT_FILE="$STATE_DIR/restore-$OPERATION/capacity-context.json"
 restore_capacity_context "$CAPACITY_CONTEXT_FILE"
 capacity_qualify reuse
}
capacity_source_identity() {
 local prefix=$1 uid role claim volume object
 if [[ -n ${CAPACITY_CONTEXT_FILE:-} ]]; then restore_capacity_context "$CAPACITY_CONTEXT_FILE"; fi
 uid=$(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid)
 jq -e --arg ns "$NAMESPACE" --arg release "$RELEASE" --arg uid "$uid" '
   .namespace_uid==$uid and .site.target.namespace==$ns and .site.target.release==$release and
   (.site.storage.node|type=="string" and length>0) and
   (.storage|length)==3 and ([.storage[].name]|unique|length)==3 and ([.storage[].uid]|unique|length)==3
 ' "${CAPACITY_CONTEXT_FILE:-$GSJ_WORK/installed.json}" >/dev/null || fail 'capacity measurement requires the recorded namespace, source node and three PVC identities'
 : > "$prefix-bindings.jsonl"
 for role in data forgejo chroma; do
   claim=$(jq -r --arg role "$role" --arg release "$RELEASE" '.site.storage[$role].existing_claim | if .=="" then $release+"-"+$role else . end' "${CAPACITY_CONTEXT_FILE:-$GSJ_WORK/installed.json}")
   [[ -n $claim && $claim != null ]] || fail 'source PVC role is undefined'
   k get pvc "$claim" -o json > "$prefix-pvc.json"
   jq -e --slurpfile source "${CAPACITY_CONTEXT_FILE:-$GSJ_WORK/installed.json}" --arg claim "$claim" '
     . as $p | .status.phase=="Bound" and (.metadata.deletionTimestamp==null) and
     any($source[0].storage[];.name==$claim and .uid==$p.metadata.uid and .volume==$p.spec.volumeName and .storageClass==$p.spec.storageClassName)
   ' "$prefix-pvc.json" >/dev/null || fail 'source PVC identity or Bound state differs; capacity is unknown'
   volume=$(jq -er .spec.volumeName "$prefix-pvc.json")
   k get pv "$volume" -o json > "$prefix-pv.json"
   jq -e --arg ns "$NAMESPACE" --arg claim "$claim" --slurpfile pvc "$prefix-pvc.json" '
     .metadata.name==$pvc[0].spec.volumeName and (.metadata.uid|type=="string" and length>0) and
     .metadata.deletionTimestamp==null and .status.phase=="Bound" and
     .spec.claimRef.namespace==$ns and .spec.claimRef.name==$claim and .spec.claimRef.uid==$pvc[0].metadata.uid
   ' "$prefix-pv.json" >/dev/null || fail 'source PV no longer binds the recorded PVC identity'
   jq -n --arg role "$role" --slurpfile pvc "$prefix-pvc.json" --slurpfile pv "$prefix-pv.json" '{role:$role,claim:$pvc[0].metadata.name,claim_uid:$pvc[0].metadata.uid,volume:$pv[0].metadata.name,volume_uid:$pv[0].metadata.uid}' >> "$prefix-bindings.jsonl"
 done
 jq -s 'sort_by(.role)' "$prefix-bindings.jsonl" > "$prefix-bindings.json"
 k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json > "$prefix-controllers.json"
 if [[ -n ${CAPACITY_CONTEXT_FILE:-} ]]; then
   jq -e '.items|length==0' "$prefix-controllers.json" >/dev/null || fail 'restored capacity must precede application controllers'
   return
 fi
 jq -e --slurpfile bindings "$prefix-bindings.json" --slurpfile source "${CAPACITY_CONTEXT_FILE:-$GSJ_WORK/installed.json}" --arg release "$RELEASE" '
   ($bindings[0]|map({key:.role,value:.claim})|from_entries) as $claims |
   def mounted($deployment;$container;$path;$sub;$role): any(.items[]; .spec.template.spec as $p |
     .metadata.name==($release+"-"+$deployment) and any($p.containers[]; .name==$container and any(.volumeMounts[]?; .name as $v |
       .mountPath==$path and (.subPath//"")==$sub and (.subPathExpr//"")=="" and
       any($p.volumes[]; .name==$v and .persistentVolumeClaim.claimName==$claims[$role]))));
   (.items|length)==3 and ([.items[].metadata.name]|sort)==([$release+"-web",$release+"-forgejo",$release+"-chroma"]|sort) and
   all(.items[]; (.metadata.uid|type=="string" and length>0) and .spec.template.spec.nodeSelector["kubernetes.io/hostname"]==$source[0].site.storage.node) and
   mounted("forgejo";"forgejo";"/data";"";"forgejo") and mounted("chroma";"chroma";"/data";"";"chroma") and
   mounted("web";"gsj-web";"/data/db";"db";"data") and
   mounted("web";"agent-runner";"/data/runner-workspace";"runner-workspace";"data") and
   mounted("web";"agent-runner";"/runner-home";"runner-home";"data") and
   mounted("web";"gsj-mcp";"/data/cases";"cases";"data")
 ' "$prefix-controllers.json" >/dev/null || fail 'source workload node or database/workspace mount roots differ from the recorded claims'
}
capacity_same_source() {
 local before=$1 after=$2
 cmp -s "$before-bindings.json" "$after-bindings.json" || fail 'storage binding changed during capacity measurement'
 jq -e --slurpfile before "$before-controllers.json" 'def identities: [.items[]|{name:.metadata.name,uid:.metadata.uid,spec}]|sort_by(.name); identities==($before[0]|identities)' "$after-controllers.json" >/dev/null || fail 'source controller identity or specification changed during capacity measurement'
}
capacity_record() {
 local stage=$1 prefix=$2 pod_uid=$3
 jq --arg op "$OPERATION" --arg pod_uid "$pod_uid" --slurpfile source "${CAPACITY_CONTEXT_FILE:-$GSJ_WORK/installed.json}" --slurpfile bindings "$prefix-bindings.json" '. + {operation:$op,storage_identity_verified:true,pod_uid:$pod_uid,namespace_uid:$source[0].namespace_uid,source_release:$source[0].manifest.identity,node:$source[0].site.storage.node,storage_bindings:$bindings[0]} + (if $source[0].format=="gsj.restore-capacity-context/1" then {purpose:"restored-files-before-startup",restoration:$source[0].restoration,node_uid:$source[0].node_uid} else {} end)' "$GSJ_WORK/capacity-report.json" | atomic "$STATE_DIR/capacity-$OPERATION-$stage.json"
 cat "$STATE_DIR/capacity-$OPERATION-$stage.json"
}
capacity_scan_pod() {
 local pod=$1 mode=$2 stage=$3 result=0 pod_uid=''
 if [[ $stage == quiesced ]]; then
   capacity_source_identity "$GSJ_WORK/capacity-quiesced-before"
   cmp -s "$GSJ_WORK/capacity-before-bindings.json" "$GSJ_WORK/capacity-quiesced-before-bindings.json" || fail 'storage binding changed before maintenance capacity measurement'
   k get pod "$pod" -o json > "$GSJ_WORK/capacity-maintenance.json"
   jq -e --arg pod "$pod" --slurpfile bindings "$GSJ_WORK/capacity-quiesced-before-bindings.json" --slurpfile source "${CAPACITY_CONTEXT_FILE:-$GSJ_WORK/installed.json}" "$JQ_IMAGE"'
     . as $pod_object | .spec as $p |
     .metadata.labels["gsj.io/operation"]==$pod and (.metadata.uid|type=="string" and length>0) and
     .spec.automountServiceAccountToken==false and (.spec.containers|length)==1 and
     .spec.nodeSelector["kubernetes.io/hostname"]==$source[0].site.storage.node and
     .spec.containers[0].image==($source[0].manifest.images.web|image_ref($source[0].site.registry.base)) and
     all($bindings[0][]; . as $binding | any($p.containers[0].volumeMounts[]; .name as $v |
       .mountPath==("/volumes/"+(if $binding.role=="data" then "gsj" else $binding.role end)) and
       (.subPath//"")=="" and (.subPathExpr//"")=="" and
       any($p.volumes[];.name==$v and .persistentVolumeClaim.claimName==$binding.claim))) and
     any($p.containers[0].volumeMounts[];.name as $v | .mountPath=="/transfer" and (.subPath//"")=="" and
       any($p.volumes[];.name==$v and ((.emptyDir=={} and .hostPath==null) or ((.hostPath.path|type=="string") and .emptyDir==null))))
   ' "$GSJ_WORK/capacity-maintenance.json" >/dev/null || fail 'actual maintenance Pod does not mount all recorded source roots and ordinary transfer storage'
   pod_uid=$(jq -er .metadata.uid "$GSJ_WORK/capacity-maintenance.json")
 fi
 capacity_host_filesystems
 local volumes='{"forgejo":"/volumes/forgejo","gsj":"/volumes/gsj","chroma":"/volumes/chroma"}'
 local minimum; minimum=$(jq -er '.site.storage.minimum_free_bytes' "${CAPACITY_CONTEXT_FILE:-$GSJ_WORK/installed.json}")
 if [[ $stage == quiesced ]]; then
   k exec -i "$pod" -- python - --volumes "$volumes" --transfer /transfer --hosts "$(cat "$GSJ_WORK/capacity-host.json")" --minimum "$minimum" --mode "$mode" --quiesced < "$GSJ_PAYLOAD/helpers/capacity.py" > "$GSJ_WORK/capacity-report.json" || result=$?
 else
   k exec -i "$pod" -- python - --volumes "$volumes" --transfer /transfer --hosts "$(cat "$GSJ_WORK/capacity-host.json")" --minimum "$minimum" --mode "$mode" < "$GSJ_PAYLOAD/helpers/capacity.py" > "$GSJ_WORK/capacity-report.json" || result=$?
 fi
 assert_owner
 jq -e '.format=="gsj.capacity/1" and (.status|IN("passed","insufficient","unknown"))' "$GSJ_WORK/capacity-report.json" >/dev/null || fail 'capacity scanner did not return a valid measurement'
 if [[ $stage == quiesced ]]; then
   capacity_source_identity "$GSJ_WORK/capacity-quiesced-after"
   capacity_same_source "$GSJ_WORK/capacity-quiesced-before" "$GSJ_WORK/capacity-quiesced-after"
   [[ $(k get pod "$pod" -o json | jq -r .metadata.uid) == "$pod_uid" ]] || fail 'maintenance Pod was replaced during capacity measurement'
   capacity_record "$stage" "$GSJ_WORK/capacity-quiesced-after" "$pod_uid"
 fi
 (( result == 0 )) && [[ $(jq -r .status "$GSJ_WORK/capacity-report.json") == passed ]]
}
capacity_qualify() {
 assert_owner
 local mode=${1:-create} name="$RELEASE-capacity-${OPERATION:0:8}" image existing fingerprint result=0
 [[ $mode == create || $mode == reuse ]] || fail 'invalid capacity qualification mode'
 [[ -f $GSJ_PAYLOAD/helpers/capacity.py && ! -L $GSJ_PAYLOAD/helpers/capacity.py ]] || fail 'signed capacity helper is unavailable'
 capacity_source_identity "$GSJ_WORK/capacity-before"
 capacity_host_filesystems
 # Refuse an obviously full tools filesystem before even creating the reader.
 jq -e 'all(.[];.available_bytes>=536870912 and .available_inodes>=128)' "$GSJ_WORK/capacity-host.json" >/dev/null || fail 'script-host backup or private staging filesystem has insufficient measured space'
 image=$(installed_image web "${CAPACITY_CONTEXT_FILE:-$GSJ_WORK/installed.json}")
 fingerprint=$(sha_file "$GSJ_WORK/capacity-before-bindings.json")
 jq -n --arg name "$name" --arg op "$OPERATION" --arg image "$image" --arg bindings "$fingerprint" --arg transfer "$(j '.storage.transfer_path // ""')" --slurpfile installed "${CAPACITY_CONTEXT_FILE:-$GSJ_WORK/installed.json}" --slurpfile bindings_json "$GSJ_WORK/capacity-before-bindings.json" --slurpfile values "$GSJ_WORK/values.pending.json" '
   {apiVersion:"v1",kind:"Pod",metadata:{name:$name,labels:{"gsj.io/operation":$op},annotations:{"gsj.io/capacity-bindings":$bindings}},spec:{restartPolicy:"Never",automountServiceAccountToken:false,nodeSelector:{"kubernetes.io/hostname":$installed[0].site.storage.node},imagePullSecrets:($values[0].image.pullSecrets|map({name:.})),containers:[{name:"capacity",image:$image,command:["sleep","86400"],resources:{requests:{cpu:"100m",memory:"128Mi"},limits:{memory:"512Mi"}},volumeMounts:([$bindings_json[0][]|{name:.role,mountPath:("/volumes/"+(if .role=="data" then "gsj" else .role end)),readOnly:true}]+[{name:"transfer",mountPath:"/transfer"}])}],volumes:([$bindings_json[0][]|{name:.role,persistentVolumeClaim:{claimName:.claim,readOnly:true}}]+[{name:"transfer"} + (if $transfer=="" then {emptyDir:{}} else {hostPath:{path:($transfer+"/"+$op),type:"DirectoryOrCreate"}} end)])}}' > "$GSJ_WORK/capacity-pod.json"
 k get pod "$name" -o json --ignore-not-found > "$GSJ_WORK/capacity-live-pod.json"
 if [[ -s $GSJ_WORK/capacity-live-pod.json ]]; then
   owned_resource_matches "$GSJ_WORK/capacity-live-pod.json" "$GSJ_WORK/capacity-pod.json" || fail 'capacity reader Pod has another identity or mount specification'
 else
   k create -f "$GSJ_WORK/capacity-pod.json" >/dev/null
 fi
 TRANSFER_HANDBACK_POD=$name
 k wait --for=condition=Ready "pod/$name" --timeout=300s || fail 'actual source storage could not be mounted read-only; capacity remains unknown'
 k get pod "$name" -o json > "$GSJ_WORK/capacity-live-pod.json"
 owned_resource_matches "$GSJ_WORK/capacity-live-pod.json" "$GSJ_WORK/capacity-pod.json" || fail 'capacity reader Pod was mutated by admission; mounted capacity is unproven'
 capacity_scan_pod "$name" "$mode" before || result=$?
 capacity_source_identity "$GSJ_WORK/capacity-after"
 capacity_same_source "$GSJ_WORK/capacity-before" "$GSJ_WORK/capacity-after"
 assert_owner
 # Delete only the exact reader object we measured, using a UID precondition.
 local reader_uid; reader_uid=$(jq -er .metadata.uid "$GSJ_WORK/capacity-live-pod.json")
 [[ $(k get pod "$name" -o json | jq -r .metadata.uid) == "$reader_uid" ]] || fail 'capacity reader Pod was replaced'
 jq -n --arg uid "$reader_uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid}}' > "$GSJ_WORK/capacity-delete.json"
 transfer_handback "$name"
 k delete --raw "/api/v1/namespaces/$NAMESPACE/pods/$name" -f "$GSJ_WORK/capacity-delete.json" >/dev/null
 k wait --for=delete "pod/$name" --timeout=300s >/dev/null
 capacity_record before "$GSJ_WORK/capacity-after" "$reader_uid"
 (( result == 0 )) || fail 'actual source or backup capacity is insufficient or unknown; no application writer was stopped'
 log 'Measured source filesystems and backup staging capacity passed before quiescence'
}
transfer_handback() {
 # Give the per-operation transfer directory back to the operator BEFORE the
 # Pod that mounts it disappears, and on the failure paths that keep it for
 # resume. Only /transfer: the application's own volumes under /volumes stay
 # exactly as they are. An emptyDir transfer owns nothing outside the Pod and
 # needs nothing. A Pod that is gone or not Running is skipped, never a failure.
 local pod=${1:-} object
 [[ -n $pod ]] || return 0
 [[ $(j '.storage.transfer_path // ""') != '' ]] || return 0
 object=$(k get pod "$pod" -o json --ignore-not-found 2>/dev/null) || return 0
 [[ -n $object ]] || return 0
 [[ $(jq -r '.status.phase // ""' <<< "$object") == Running ]] || return 0
 # A refused handback leaves root-owned bytes but never fails the operation it
 # is closing; the operator is told exactly which directory needs root.
 k exec "$pod" -- chown -R "$TRANSFER_OWNER" /transfer >/dev/null ||
   log "The transfer directory of operation ${OPERATION:-} could not be handed back to $TRANSFER_OWNER; removing $(j '.storage.transfer_path')/${OPERATION:-} will need root"
}
maintenance_pod_document() {
 local name=$1 image=$2 cmdfile=$3
 # A configured transfer location is a hostPath, and a hostPath PERSISTS across
 # operations where emptyDir did not: the second maintenance pod would find the
 # first one's snapshot still there and refuse it as "not a new file". Scope it
 # per operation so each gets the fresh directory emptyDir used to give it.
 jq -n --arg name "$name" --arg release "$RELEASE" --arg image "$image" --arg op "$OPERATION" --arg node "$(j .storage.node)" --arg transfer "$(j '.storage.transfer_path // ""')" --argjson pulls "$(jq '.image.pullSecrets|map({name:.})' "$GSJ_WORK/values.pending.json")" --slurpfile values "$GSJ_WORK/values.pending.json" --slurpfile command "$cmdfile" '{apiVersion:"v1",kind:"Pod",metadata:{name:$name,labels:{"gsj.io/operation":$name}},spec:{restartPolicy:"Never",automountServiceAccountToken:false,nodeSelector:{"kubernetes.io/hostname":$node},imagePullSecrets:$pulls,containers:[{name:"maintenance",image:$image,command:$command[0],volumeMounts:[{name:"gsj",mountPath:"/volumes/gsj"},{name:"forgejo",mountPath:"/volumes/forgejo"},{name:"chroma",mountPath:"/volumes/chroma"},{name:"transfer",mountPath:"/transfer"}]}],volumes:((["gsj","forgejo","chroma"]|map(. as $role | {name:$role,persistentVolumeClaim:{claimName:($values[0].storage[(if $role=="gsj" then "data" else $role end)].existingClaim | if .=="" then $release+"-"+(if $role=="gsj" then "data" else $role end) else . end)}}))+[{name:"transfer"} + (if $transfer=="" then {emptyDir:{}} else {hostPath:{path:($transfer+"/"+$op),type:"DirectoryOrCreate"}} end)])}}'
}
registry_base_preflight() {
 # registry.base relocates by the LAST path segment of each repository, so the
 # six must differ there or two images would land on one name. No shipped
 # release collides; this refuses the one that would rather than relocate it
 # wrongly. Read-only, and asked for every verb: it is a fact about the release
 # and the site, not about capacity, so it cannot block a recovery that a
 # correct install would not also have been refused.
 [[ -n $(j '.registry.base // ""') ]] || return 0
 jq -e '[.images[]|.repository|split("/")|last] | length == (unique|length)' "$GSJ_PAYLOAD/release.json" >/dev/null || fail 'registry.base cannot relocate this release: two of its images share a final path segment and would collide under one prefix'
 # The managed add-ons are separate charts with their own pinned images, and
 # registry.base does not move those. Saying so here is cheaper than an
 # ImagePullBackOff in an add-on namespace half an hour in.
 local unmoved
 unmoved=$(jq -r --slurpfile site "$SITE" '$site[0] as $s | [ (if $s.ingress.profile=="managed-traefik" then .addons.traefik.images[] else empty end), (if $s.tls.profile=="managed-acme" then .addons.certManager.images[] else empty end), (if $s.storage.profile=="managed-local-path" then .addons.localPath.images[] else empty end) ] | join(" ")' "$GSJ_PAYLOAD/release.json")
 [[ -z $unmoved ]] || log "registry.base relocates the six application images only. The managed add-on images this site selects are still pulled from where the release names them, so the nodes must reach those registries or mirror them: $unmoved"
}
relocated_images_probe() {
 # Where this deployment's images are pulled from is
 # the one site value that decides whether ANY of its Pods can start, and the
 # only component that can answer is the one that consumes it: the container
 # runtime on the node that will run them. So ask it, once, before anything is
 # applied -- one Pod, one container per image, by digest. The containers never
 # run: their command does not exist, and a container that fails to START has
 # already been PULLED, which is the whole question.
 #
 # WHEN. Whenever the location is site-chosen OR has CHANGED: registry.base is
 # set, or it differs from the base the installed deployment was recorded with.
 # The second half matters most. An upgrade that loses the base -- a stale copy
 # of site.json, a deleted line -- would otherwise render the release's original
 # repositories, the ones this site said its nodes cannot reach, with nothing
 # to catch it until the quiesced application failed to come back.
 #
 # WHERE IN THE CHAIN. Before backup quiesces a running deployment: a refusal
 # here leaves whatever was running, running.
 local base recorded='' pod spent=0 failing_since=-1 status verdict words='' where deadline want
 base=$(j '.registry.base // ""')
 if [[ -s ${GSJ_WORK:-}/installed.json ]]; then recorded=$(jq -r '.site.registry.base // ""' "$GSJ_WORK/installed.json"); fi
 [[ -n $base || $base != "$recorded" ]] || return 0
 # registry.base has no scheme (the schema holds it to host[:port][/path]), so
 # url_origin_only prints it as it is: routed like every printed address, so
 # the URL scan's alias rule sees the wrapper [review B2]
 if [[ -n $base ]]; then where="registry.base ($(url_origin_only "$base"))"; else where="the release's own repositories (this site no longer sets registry.base; the installed deployment used $recorded)"; fi
 deadline=$(j .deadlines.dependencies_seconds)
 want=$(jq '.images|length' "$GSJ_PAYLOAD/release.json")
 pod="gsj-pull-${OPERATION:0:12}"
 registry_secret_input
 log "Proving $(if [[ -n $(j .storage.node) ]]; then printf 'node %s' "$(j .storage.node)"; else printf 'a node (storage.node is not set, so the scheduler picks one)'; fi) can pull all $want images from $where before anything is applied"
 # An earlier run's probe Pod, whatever its operation: the label is this
 # release's alone. Bounded -- a Pod stuck Terminating must not hang the verb.
 k delete pod -l "gsj.io/pull-probe=$RELEASE" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1 || true
 # The label is deliberately NOT gsj.io/owner or app.kubernetes.io/instance:
 # restore refuses a target holding Pods under those, and this Pod is not part
 # of the deployment. cleanup_exit removes it on any exit, the line above
 # removes a predecessor, and sweep removes one a killed installer left behind.
 PROBE_POD=$pod
 if ! jq -n --arg name "$pod" --arg release "$RELEASE" --arg node "$(j .storage.node)" --arg base "$base" --argjson deadline "$deadline" --argjson pulls "$(jq '(.image.pullSecrets // [])|map({name:.})' "$GSJ_WORK/values.pending.json")" --slurpfile r "$GSJ_PAYLOAD/release.json" "$JQ_IMAGE"'
   {apiVersion:"v1",kind:"Pod",metadata:{name:$name,labels:{"gsj.io/pull-probe":$release}},
    spec:{restartPolicy:"Never",automountServiceAccountToken:false,enableServiceLinks:false,imagePullSecrets:$pulls,
          activeDeadlineSeconds:($deadline+300),
          nodeSelector:(if $node=="" then {} else {"kubernetes.io/hostname":$node} end),
          containers:[$r[0].images|to_entries[]|{name:("pull-"+(.key|ascii_downcase)),image:(.value|image_ref($base)),imagePullPolicy:"IfNotPresent",command:["/gsj-pull-probe-never-runs"],resources:{requests:{cpu:"1m",memory:"1Mi"},limits:{memory:"16Mi"}}}]}}' | k create -f - >/dev/null 2>"$GSJ_WORK/pull-probe-create.err"; then
   PROBE_POD=''
   atomic "$STATE_DIR/pull-probe-create.err" < "$GSJ_WORK/pull-probe-create.err"
   fail "the image pull probe could not be created in namespace $NAMESPACE, so whether the node can pull from $where is unproven: $(kubectl_failure_condition "$GSJ_WORK/pull-probe-create.err"); kubectl's own words are kept in $STATE_DIR/pull-probe-create.err. If an admission policy refused it, admit Pods labelled gsj.io/pull-probe in this namespace"
 fi
 while :; do
   status=$(k get pod "$pod" -o json 2>/dev/null) || status='{}'
   # pulled: the runtime reports the image's ID, or the container got as far as
   # being created. `terminated` alone is NOT proof -- a Pod evicted before its
   # pull reports terminated/ContainerStatusUnknown with no imageID.
   verdict=$(jq -r --argjson want "$want" '
     [(.status.containerStatuses // [])[] | {image,
        failed: ((.state.waiting.reason // "") | test("^(ErrImage|ImagePull|ImageInspect|InvalidImageName|RegistryUnavailable)")),
        words: ((.state.waiting.message // .state.waiting.reason // "") | gsub("[\\r\\n\\t]+";" ")),
        pulled: (((.imageID // "") != "") or (.state.running != null)
                 or ((.state.terminated != null) and ((.state.terminated.reason // "") != "ContainerStatusUnknown"))
                 or ((.state.waiting.reason // "") | IN("RunContainerError","CreateContainerError","CrashLoopBackOff")))}] as $c
     | if ($c|length) == $want and all($c[]; .pulled) then "pulled"
       elif any($c[]; .failed) then ([$c[]|select(.failed)]) as $f |
         "failing " + ($f|length|tostring) + " of " + ($want|tostring) + " images: " + ([$f[].image]|join(", ")) + " SAID " + $f[0].words
       else "waiting" end' <<< "$status")
   case "$verdict" in
     pulled) break;;
     failing*)
       (( failing_since >= 0 )) || failing_since=$spent
       # The cause is in the FIRST failure message (ErrImagePull: "not found",
       # "unauthorized", "no such host"); ImagePullBackOff replaces it with
       # "Back-off pulling image". Keep the informative one.
       if [[ -z $words || ( $words == Back-off* && ${verdict#* SAID } != Back-off* ) ]]; then words=${verdict#* SAID }; fi;;
     *) failing_since=-1;;
   esac
   # The kubelet retries a failed pull with backoff, and a registry can stumble
   # once: refuse only a failure that has outlived 90 s of retries -- or one that
   # is still failing when the deadline arrives, which a short
   # deadlines.dependencies_seconds would otherwise turn into a nameless timeout.
   if [[ $verdict == failing* ]] && (( spent - failing_since >= 90 || spent >= deadline )); then
     verdict=${verdict%% SAID *}
     # the Pod's status, kept 0600 for the operator: the runtime's own words
     # live there, never in the refusal (the block below re-declares
     # `status` for the operation's) [review B2]
     printf '%s\n' "$status" | atomic "$STATE_DIR/pull-probe-status.json"
     # The same ImagePullBackOff comes from a changed site (a wrong base, digest or
     # pull Secret: a repair after the correction) and from the node's side (a
     # registry CA it does not trust, DNS, a proxy, a full disk, a rate limit, an
     # outage: resume once it can pull); the probe cannot tell them apart, so the
     # hint names both. A restore stopped here is restore-repair's, not resume's.
     # A restore keeps its site byte for byte (every continuation refuses a
     # changed registry.base or registry.pull_secret), and which verb continues
     # it depends on where it stopped: restoring-* is restore-repair's (resume
     # refuses those phases), restore-files-verified is resume's (or
     # restore-repair's under a corrected program), applying is the repair
     # path's. For an install or upgrade the recorded status decides: "owned"
     # is a first install with nothing applied or quiesced, which must not be
     # sent to repair (it would complete without the storage check); past the
     # backup the deployment is quiesced, abandon refuses, and a changed site
     # value is repair's. Every caller writes that status before this probe.
     # After a restore-program transition only the corrected installer
     # continues the restore: restore-repair before the application starts,
     # repair at applying.
     # In main and resume's owned phase this probe runs BEFORE the backup, so
     # the status is "owned" for an upgrade too: a first install is "owned"
     # WITHOUT an installed record (read before the probe on both paths).
     local kind status; kind=$(jq -r '.kind // ""' "$STATE_DIR/operation.json" 2>/dev/null || true); status=$(jq -r '.status // ""' "$STATE_DIR/operation.json" 2>/dev/null || true)
     local nodeside="once the node can pull (a registry CA the node does not trust, node DNS or a proxy, a full node disk, a rate limit or an outage)"
     if [[ $kind == restore ]]; then
       local verb
       if [[ ${RESTORE_PROGRAM_ACTIVE:-false} == true ]]; then
         case $status in applying) verb="repair --operation $OPERATION with this corrected installer (its recorded program; neither resume nor the source installer continues it)";; *) verb="restore-repair --operation $OPERATION with this corrected installer (its recorded program; neither resume nor the source installer continues it)";; esac
       else case $status in restoring-resources|restoring-files) verb="restore-repair --operation $OPERATION with the exact saved target";; applying) verb="repair --operation $OPERATION with the exact saved target";; *) verb="resume --operation $OPERATION with the exact source installer";; esac; fi
       RECOVERY_HINT="$verb $nodeside, or after correcting the registry's contents (wait 180 s first: this operation's Lease must go unrenewed that long); a changed registry.base or registry.pull_secret cannot continue this restore, whose site is retained byte for byte"
     elif [[ ( $status == owned || -z $status ) && ! -s $GSJ_WORK/installed.json ]]; then
       RECOVERY_HINT="abandon --operation $OPERATION --reason \"...\" --config $CONFIG --non-interactive after 180 s and install again from the corrected file after correcting registry.base, the registry's contents or registry.pull_secret (a repair would complete this first install without the storage check), or resume --operation $OPERATION $nodeside"
     elif [[ $status == owned || -z $status ]]; then
       # the operation's own verb again: an interrupted upgrade is not told to install
       local again="run install again"; [[ $kind != upgrade ]] || again="run upgrade --to VERSION again"
       RECOVERY_HINT="repair --operation $OPERATION --config $CONFIG --non-interactive after correcting registry.base, the registry's contents or registry.pull_secret (wait 180 s first: this operation's Lease must go unrenewed that long before a repair may take it), or abandon --operation $OPERATION --reason \"...\" --config $CONFIG --non-interactive after 180 s and $again from the corrected file (abandon refuses while a backup has left controllers scaled to zero, and says so), or resume --operation $OPERATION $nodeside"
     else
       RECOVERY_HINT="repair --operation $OPERATION --config $CONFIG --non-interactive after correcting registry.base, the registry's contents or registry.pull_secret (wait 180 s first: this operation's Lease must go unrenewed that long before a repair may take it), or resume --operation $OPERATION $nodeside"
     fi
     fail "the node cannot pull this release from $where: ${verdict#failing }. The container runtime reported, of the first, $(pull_failure_condition "$words"); its own words are kept in $STATE_DIR/pull-probe-status.json. The repository is <registry.base>/<the last path segment of the release's repository> and the digest is always the signed release's -- a registry holding different bytes under that name is refused by the pull itself. Check that every digest was copied there unchanged, that the prefix is exact, and that registry.pull_secret carries a credential for that host. The same failure also comes from the node's side, with no site value wrong: a registry CA the container runtime does not trust, the node's DNS or proxy, a full node disk, a registry rate limit or outage -- then continue with the command the closing line names. Helm has applied nothing in this run"
   fi
   if (( spent >= deadline )); then
     RECOVERY_HINT="resume --operation $OPERATION once the registry answers, or repair --operation $OPERATION --config $CONFIG --non-interactive after raising deadlines.dependencies_seconds"
     # the conditions' types and REASONS, each repeated only when it is a
     # value this installer knows (the API does not constrain a reason
     # string); their messages are the scheduler's free text and are kept,
     # never repeated [review sweep B2]
     printf '%s\n' "$status" | atomic "$STATE_DIR/pull-probe-status.json"
     local conditions='' ctype creason
     while IFS=$'\t' read -r ctype creason; do
       [[ -n $ctype ]] || continue
       conditions+="${conditions:+; }$(known_word "$ctype" PodScheduled Initialized ContainersReady Ready PodReadyToStartContainers DisruptionTarget): $(known_word "$creason" Unschedulable SchedulerError ContainersNotReady ContainersNotInitialized PodCompleted PodFailed ReadinessGatesNotReady unknown)"
     done < <(jq -r '(.status.conditions // [])[]|select(.status=="False")|[.type, (.reason // "unknown")]|@tsv' <<< "$status")
     fail "the node did not finish pulling this release's images from $where within deadlines.dependencies_seconds ($deadline s): $conditions; the Pod's status is kept in $STATE_DIR/pull-probe-status.json. Helm has applied nothing in this run"
   fi
   sleep 5; spent=$(( spent + 5 ))
 done
 k delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true; PROBE_POD=''
 log "All $want images pulled from $where by digest"
}
maintenance_pod() {
 local name=$1 image=$2 cmdfile=$3
 k get pvc -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/claims.json"
 maintenance_pod_document "$name" "$image" "$cmdfile" | k create -f - >/dev/null
 # Named before the wait: a Pod that never becomes Ready is still the Pod whose
 # transfer directory cleanup_exit must hand back when the operation stops.
 TRANSFER_HANDBACK_POD=$name
 k wait --for=condition=Ready "pod/$name" --timeout=300s
}
immutable_file() {
 # Publish stdin on the destination filesystem without replacing any entry.
 local target=$1 staged
 staged=$(mktemp "$(dirname "$target")/.gsj-immutable.XXXXXXXX")
 cat > "$staged"; chmod 600 "$staged"; sync "$staged"
 if ! ln "$staged" "$target"; then rm -f "$staged"; fail 'immutable operation artifact already exists'; fi
 rm -f "$staged"; sync "$(dirname "$target")"
}
backup_round_number() {
 jq -er '.backup_round // 0 | select(type=="number" and .==floor and .>=0 and .<=999999)' "$STATE_DIR/operation.json" || fail 'invalid active backup round'
}
backup_stem() {
 [[ $OPERATION =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]] || fail 'invalid maintenance operation identity'
 local round; round=$(backup_round_number)
 printf '%s' "$OPERATION"
 [[ $round == 0 ]] || printf '.r%s' "$round"
}
quiescence_snapshot() {
 printf '%s/quiescence-%s.json' "$STATE_DIR" "$(backup_stem)"
}
backup_archive() {
 local generation intent stem round
 stem=$(backup_stem); round=$(backup_round_number)
 if [[ $round != 0 ]]; then
   intent="$STATE_DIR/backup-round-$OPERATION-$round.json"
   [[ -f $intent && ! -L $intent ]] || fail 'active backup round has no immutable source intent'
   jq -e --arg operation "$OPERATION" --argjson round "$round" --arg archive "$BACKUP_DIR/$stem.tar.gz.enc" '.format=="gsj.backup-round/1" and .operation==$operation and .round==$round and .archive==$archive' "$intent" >/dev/null || fail 'active backup round identity differs'
   [[ -f $STATE_DIR/quiescence-$stem.json && ! -L $STATE_DIR/quiescence-$stem.json ]] && jq -e --slurpfile intent "$intent" '.==$intent[0].source' "$STATE_DIR/quiescence-$stem.json" >/dev/null || fail 'active backup round source snapshot differs from its immutable intent'
 fi
 generation=$(jq -er '.backup_generation // 0 | select(type=="number" and .==floor and .>=0 and .<=999999)' "$STATE_DIR/operation.json") || fail 'invalid active backup generation'
 if [[ $generation == 0 ]]; then printf '%s/%s.tar.gz.enc' "$BACKUP_DIR" "$stem"; return; fi
 intent="$STATE_DIR/backup-generation-$stem-$generation.json"
 [[ -f $intent && ! -L $intent && -f $intent.ready && ! -L $intent.ready ]] || fail 'active backup generation has no immutable preparation proof'
 jq -e --arg operation "$OPERATION" --argjson generation "$generation" --arg archive "$BACKUP_DIR/$stem.g$generation.tar.gz.enc" '.format=="gsj.backup-generation/1" and .operation==$operation and .generation==$generation and .archive==$archive' "$intent" >/dev/null || fail 'active backup generation identity differs'
 [[ $(cat "$intent.ready") == $(sha_file "$intent") ]] || fail 'backup generation preparation proof differs'
 printf '%s/%s.g%s.tar.gz.enc' "$BACKUP_DIR" "$stem" "$generation"
}
backup_pod_name() {
 local generation round suffix='' name hash
 generation=$(jq -r '.backup_generation // 0' "$STATE_DIR/operation.json"); round=$(backup_round_number)
 [[ $round == 0 ]] || suffix="-r$round"
 [[ $generation == 0 ]] || suffix="$suffix-g$generation"
 name="$RELEASE-backup-${OPERATION:0:8}$suffix"
 if (( ${#name} > 63 )); then
   hash=$(printf '%s' "$RELEASE" | openssl dgst -sha256 | awk '{print substr($NF,1,8)}')
   name="${RELEASE:0:20}-backup-${OPERATION:0:8}$suffix-$hash"
 fi
 printf '%s' "$name"
}
backup_storage_bindings() {
 local claim uid volume object
 : > "$GSJ_WORK/backup-bindings.jsonl"
 while IFS=$'\t' read -r claim uid volume; do
   object=$(k get pvc "$claim" -o json)
   jq -e --arg uid "$uid" --arg volume "$volume" '.metadata.uid==$uid and .spec.volumeName==$volume and .status.phase=="Bound" and .metadata.deletionTimestamp==null' <<< "$object" >/dev/null || fail 'backup PVC identity or Bound state changed'
   object=$(k get pv "$volume" -o json)
   jq -e --arg ns "$NAMESPACE" --arg claim "$claim" --arg uid "$uid" --arg volume "$volume" '.metadata.name==$volume and (.metadata.uid|type=="string" and length>0) and .metadata.deletionTimestamp==null and .status.phase=="Bound" and .spec.claimRef.namespace==$ns and .spec.claimRef.name==$claim and .spec.claimRef.uid==$uid' <<< "$object" >/dev/null || fail 'backup PV identity or binding changed'
   jq -n --arg claim "$claim" --arg uid "$uid" --arg volume "$volume" --arg pvuid "$(jq -r .metadata.uid <<< "$object")" '{claim:$claim,claim_uid:$uid,volume:$volume,volume_uid:$pvuid}' >> "$GSJ_WORK/backup-bindings.jsonl"
 done < <(jq -r '.storage[]|[.name,.uid,.volume]|@tsv' "$GSJ_WORK/installed.json")
 jq -s 'sort_by(.claim)' "$GSJ_WORK/backup-bindings.jsonl"
}
backup_source_matches() {
 local source=$1 controllers=$2 initializer=$3
 jq -e --slurpfile source "$source" --slurpfile init "$initializer" --arg release "$RELEASE" "$JQ_IMAGE"'
   $source[0] as $s | ($s.manifest.images|map_values(image_ref($s.site.registry.base))) as $images |
   ($s.status|IN("complete","verification-pending")) and $s.format=="gsj.installed/1" and
   (.items|length)==3 and ([.items[].metadata.name]|sort)==([$release+"-web",$release+"-forgejo",$release+"-chroma"]|sort) and
   all(.items[]; (.metadata.uid|type=="string" and length>0) and .metadata.deletionTimestamp==null) and
   ([.items[].spec.template.spec.containers[]|{key:.name,value:.image}]|from_entries)==
     {"gsj-web":$images.web,"agent-runner":$images.runner,"gsj-mcp":$images.mcp,"forgejo":$images.forgejo,"chroma":$images.chroma} and
   any(.items[]|select(.metadata.name==($release+"-web"));
     any(.spec.template.spec.initContainers[]?; .name=="wait-deps" and .image==$images.web and
       any(.env[]?; .name=="GSJ_DEPLOYMENT_GENERATION" and (.value|startswith($s.manifest.identity+":")) and (.value|split(":")|last|test("^[1-9][0-9]*$")))) and
     any(.spec.template.spec.initContainers[]?; .name=="corpus-copy" and .image==$images.decisionsData and
       .args==["--destination","/source","--manifest-sha256",$s.manifest.corpus.manifest_sha256]) and
     any(.spec.template.spec.initContainers[]?; .name=="corpus-initialize" and .image==$images.web and .command==["python","-m","gsj_deploy.initialize","--settings","/scripts/initializer.json"]) and
     any(.spec.template.spec.volumes[]?; .name=="scripts" and .configMap.name==($release+"-scripts"))) and
   $init[0].manifest_sha256==$s.manifest.corpus.manifest_sha256 and
   $init[0].repair_generation==$s.site.corpus.repair_generation and
   $init[0].model_path=="/app/models/snowflake-arctic-embed-m-v2.0"
 ' "$controllers" >/dev/null
}
read_backup_source() {
 local mode=${1:-current} kind object selected='' candidate snapshot
 [[ $mode == current || $mode == active ]] || fail 'unsupported backup source selection'
 k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/backup-source-controllers.json"
 k get configmap "$RELEASE-scripts" -o json | jq -er '.data["initializer.json"]' > "$GSJ_WORK/backup-source-initializer.json"
 for kind in installed ready-state; do
   object=$(k get configmap "$RELEASE-$kind" -o json --ignore-not-found) || fail 'cannot read recorded backup source'
   [[ -n $object ]] || continue
   jq -e --arg owner "$RELEASE" '.metadata.labels["gsj.io/owner"]==$owner' <<< "$object" >/dev/null || fail 'backup source ConfigMap is not owned by this release'
   candidate="$GSJ_WORK/backup-source-$kind.json"
   jq -er '.data["installed.json"]' <<< "$object" > "$candidate"
   if backup_source_matches "$candidate" "$GSJ_WORK/backup-source-controllers.json" "$GSJ_WORK/backup-source-initializer.json"; then
     if [[ -n $selected ]]; then
       jq -e --slurpfile other "$selected" '{manifest,site,storage,namespace_uid}==($other[0]|{manifest,site,storage,namespace_uid})' "$candidate" >/dev/null || fail 'recorded current backup sources are ambiguous'
       [[ $(jq -r .status "$candidate") != complete ]] || selected=$candidate
     else selected=$candidate; fi
   fi
 done
 [[ -n $selected ]] || fail 'no recorded ready source matches actual containers and corpus initialization; resume the original target or restore its verified backup'
 cp "$selected" "$GSJ_WORK/installed.json"
 capacity_source_identity "$GSJ_WORK/backup-source-validated"
 jq -e --slurpfile before "$GSJ_WORK/backup-source-controllers.json" 'def identities: [.items[]|{name:.metadata.name,uid:.metadata.uid,generation:.metadata.generation,spec}]|sort_by(.name); identities==($before[0]|identities)' "$GSJ_WORK/backup-source-validated-controllers.json" >/dev/null || fail 'source controllers changed while selecting the recorded source'
 if [[ $mode == active ]]; then
   snapshot=$(quiescence_snapshot)
   [[ -f $snapshot && ! -L $snapshot ]] || fail 'active backup source snapshot is missing'
   jq -e --slurpfile saved "$snapshot" '.==$saved[0].installed' "$GSJ_WORK/installed.json" >/dev/null || fail 'actual ready source differs from the active backup round; select a new explicit backup round'
 fi
}
prepare_backup_round() {
 assert_owner
 local round=$1 current previous snapshot intent candidate highest=0 number fingerprint bindings
 [[ $round =~ ^[1-9][0-9]{0,5}$ ]] || fail 'backup round must be a positive bounded integer'
 jq -e '.kind|IN("backup","install","upgrade","repair")' "$STATE_DIR/operation.json" >/dev/null || fail 'backup rounds cannot change another operation kind'
 current=$(backup_round_number); intent="$STATE_DIR/backup-round-$OPERATION-$round.json"
 if [[ $round == "$current" ]]; then
   backup_archive >/dev/null; read_backup_source active
   jq -e --arg target "$(jq -r .target "$STATE_DIR/operation.json")" --arg site "$(sha_file "$SITE")" '.target==$target and .site_sha256==$site' "$intent" >/dev/null || fail 'selected backup round target or configuration differs'
   return
 fi
 previous=$(backup_archive); snapshot=$(quiescence_snapshot)
 # Validate historical bytes and recovery key, without claiming the old
 # writers are still stopped or the old archive contains the current data.
 verified_backup_reuse "$previous" "$snapshot"
 for candidate in "$STATE_DIR/backup-round-$OPERATION-"*.json; do
   [[ -e $candidate || -L $candidate ]] || continue
   [[ -f $candidate && ! -L $candidate ]] || fail 'backup round intent is not an ordinary file'
   number=${candidate##*-}; number=${number%.json}
   [[ $number =~ ^[1-9][0-9]{0,5}$ ]] || fail 'invalid reserved backup round'
   (( number <= highest )) || highest=$number
 done
 if [[ ! -e $intent && ! -L $intent ]]; then
   (( round == highest+1 && round > current )) || fail 'select the next unreserved backup round'
   for candidate in "$BACKUP_DIR/$OPERATION.r$round.tar.gz.enc"* "$STATE_DIR/quiescence-$OPERATION.r$round.json"*; do
     [[ ! -e $candidate && ! -L $candidate ]] || fail 'new backup round path exists without an immutable intent'
   done
 else [[ -f $intent && ! -L $intent ]] || fail 'backup round intent is not an ordinary file'; fi
 read_backup_source current
 capacity_qualify create
 backup_storage_bindings > "$GSJ_WORK/round-bindings.json"
 if jq -e 'has("storage_bindings")' "$snapshot" >/dev/null; then
   jq -e --slurpfile current "$GSJ_WORK/round-bindings.json" '.storage_bindings==$current[0]' "$snapshot" >/dev/null || fail 'source PV identity changed since the previous backup round'
 fi
 fingerprint=$(backup_credential_fingerprint) || fail 'the credential fingerprint could not be read from the cluster; nothing was compared' || fail 'the credential fingerprint could not be read from the cluster; nothing was compared' || fail 'the credential fingerprint could not be read from the cluster; nothing was compared'
 k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/round-controllers.json"
 jq -e --slurpfile before "$GSJ_WORK/backup-source-controllers.json" 'def exact: [.items[]|{name:.metadata.name,uid:.metadata.uid,generation:.metadata.generation,spec}]|sort_by(.name); exact==($before[0]|exact)' "$GSJ_WORK/round-controllers.json" >/dev/null || fail 'source controllers changed while preparing a backup round'
 jq -n --arg operation "$OPERATION" --argjson round "$round" --arg archive "$BACKUP_DIR/$OPERATION.r$round.tar.gz.enc" --arg target "$(jq -r .target "$STATE_DIR/operation.json")" --arg site "$(sha_file "$SITE")" --arg previous "$previous" --arg receipt "$(sha_file "$previous.json")" --arg fingerprint "$fingerprint" --slurpfile installed "$GSJ_WORK/installed.json" --slurpfile controllers "$GSJ_WORK/round-controllers.json" --slurpfile bindings "$GSJ_WORK/round-bindings.json" '{format:"gsj.backup-round/1",operation:$operation,round:$round,archive:$archive,target:$target,site_sha256:$site,previous_archive:$previous,previous_receipt_sha256:$receipt,source:{format:"gsj.quiescence/1",operation:$operation,round:$round,credential_fingerprint:$fingerprint,installed:$installed[0],controllers:$controllers[0],storage_bindings:$bindings[0]}}' > "$GSJ_WORK/round-candidate.json"
 if [[ -f $intent ]]; then
   jq -e --slurpfile saved "$intent" '.==$saved[0]' "$GSJ_WORK/round-candidate.json" >/dev/null || fail 'reserved backup round source or configuration changed'
 else cat "$GSJ_WORK/round-candidate.json" | immutable_file "$intent"; fi
 snapshot="$STATE_DIR/quiescence-$OPERATION.r$round.json"
 if [[ -e $snapshot || -L $snapshot ]]; then
   [[ -f $snapshot && ! -L $snapshot ]] && jq -e --slurpfile intent "$intent" '.==$intent[0].source' "$snapshot" >/dev/null || fail 'reserved backup round snapshot differs'
 else jq '.source' "$intent" | immutable_file "$snapshot"; fi
 jq --argjson round "$round" '.backup_round=$round|.backup_generation=0|del(.backup)' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 log "Prepared new backup round $round from the actual recorded source; previous recovery points remain immutable"
}
backup_credential_fingerprint() {
 # Hash the combined credential/config bundle, not individual low-entropy
 # passwords. Only this digest enters the private quiescence record.
 # Always called inside $(...): a kubectl that failed part-way used to leave
 # a partial snapshot whose digest was then printed -- and read by the caller
 # as "credentials changed". backup_resources checks every read itself and
 # returns 1 (errexit cannot be relied on inside a substitution called from an
 # || list), so a snapshot that could not be taken is a failure of this
 # function, never a digest.
 backup_resources || return 1
 local digest
 digest=$(set -o pipefail;jq -cS '[.items[]|select(.kind=="Secret" or .kind=="ConfigMap")|{kind,name:.metadata.name,namespace:.metadata.namespace,type,data,immutable}]|sort_by(.kind,.namespace,.name)' "$GSJ_WORK/cluster-private.json" | openssl dgst -sha256 | awk '{print $NF}') || return 1
 printf '%s\n' "$digest"
}
backup_partial_inventory() {
 local archive=$1 suffix path
 : > "$GSJ_WORK/backup-partial-inventory.jsonl"
 for suffix in '' .partial .sha256 .resources.enc .resources.enc.partial .resources.enc.sha256 .offbox.json; do
   path="$archive$suffix"
   if [[ -e $path || -L $path ]]; then
     [[ -f $path && ! -L $path ]] || fail 'partial backup artifact is not an ordinary file'
     log 'Hashing a preserved partial backup artifact'
     jq -n --arg suffix "$suffix" --arg sha "$(sha_file "$path")" --argjson bytes "$(wc -c < "$path" | tr -d ' ')" '{suffix:$suffix,sha256:$sha,bytes:$bytes}' >> "$GSJ_WORK/backup-partial-inventory.jsonl"
   fi
 done
 jq -s . "$GSJ_WORK/backup-partial-inventory.jsonl"
}
# GSJ_RUNTIME_HELPER: backup-recovery.py
preserve_backup_pod() {
 local intent=$1 pod uid artifact staged key_hash size helper helper_hash
 pod=$(jq -r '.previous_pod.name // empty' "$intent"); [[ -n $pod ]] || return 0
 uid=$(jq -r .previous_pod.uid "$intent"); artifact="$(jq -r .archive "$intent").previous-pod.enc"
 k get pod "$pod" -o json --ignore-not-found > "$GSJ_WORK/backup-recovery-pod.json"
 if [[ -s $GSJ_WORK/backup-recovery-pod.json ]]; then
   jq -e --slurpfile intent "$intent" '.metadata.uid==$intent[0].previous_pod.uid and .metadata.labels["gsj.io/operation"]==$intent[0].previous_pod.name and .spec==$intent[0].previous_pod.spec' "$GSJ_WORK/backup-recovery-pod.json" >/dev/null || fail 'abandoned maintenance Pod identity/specification differs from the immutable generation intent'
 fi
 if [[ -f $artifact.json && ! -L $artifact.json ]]; then
   [[ -f $artifact && ! -L $artifact ]] || fail 'preserved maintenance bytes are missing'
   jq -e --arg uid "$uid" --arg intent "$(sha_file "$intent")" --arg sha "$(sha_file "$artifact")" '.format=="gsj.pod-preservation/1" and .verified==true and .pod_uid==$uid and .intent_sha256==$intent and .archive_sha256==$sha' "$artifact.json" >/dev/null || fail 'preserved maintenance evidence differs'
   key_hash=$(jq -er .key_check "$artifact.json" | base64 --decode | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$BACKUP_PASSWORD" 2> "$GSJ_WORK/recovery-key-check.log" | openssl dgst -sha256 | awk '{print $NF}') || fail 'maintenance preservation recovery key differs'
   [[ $key_hash == $(jq -r .key_check_sha256 "$artifact.json") ]] || fail 'maintenance preservation recovery key differs'
 elif [[ ! -s $GSJ_WORK/backup-recovery-pod.json ]]; then
   fail 'abandoned maintenance Pod disappeared before its temporary recovery bytes were preserved'
 else
   jq -e --arg uid "$uid" --arg pod "$pod" --slurpfile source "$GSJ_WORK/installed.json" --slurpfile bindings "$GSJ_WORK/capacity-before-bindings.json" "$JQ_IMAGE"'
     .spec as $p |
     .metadata.uid==$uid and .metadata.labels["gsj.io/operation"]==$pod and .spec.automountServiceAccountToken==false and
     (.spec.hostPID//false)==false and (.spec.shareProcessNamespace//false)==false and
     (.spec.initContainers//[]|length)==0 and (.spec.containers|length)==1 and
     .spec.containers[0].name=="maintenance" and .spec.containers[0].command==["sleep","86400"] and
     .spec.containers[0].image==($source[0].manifest.images.web|image_ref($source[0].site.registry.base)) and
     .spec.nodeSelector["kubernetes.io/hostname"]==$source[0].site.storage.node and
     (.spec.volumes|length)==4 and (.spec.containers[0].volumeMounts|length)==4 and
     all($bindings[0][]; . as $b | any($p.containers[0].volumeMounts[]; .name as $v |
       .mountPath==("/volumes/"+(if $b.role=="data" then "gsj" else $b.role end)) and (.subPath//"")=="" and (.subPathExpr//"")=="" and
       any($p.volumes[];.name==$v and .persistentVolumeClaim.claimName==$b.claim))) and
     any(.spec.volumes[];.name=="transfer" and ((.emptyDir=={} and .hostPath==null) or ((.hostPath.path|type=="string") and .emptyDir==null))) and
     any(.spec.containers[0].volumeMounts[];.name=="transfer" and .mountPath=="/transfer" and (.subPath//"")=="" and (.subPathExpr//"")=="")
   ' "$GSJ_WORK/backup-recovery-pod.json" >/dev/null || fail 'abandoned maintenance Pod ownership or process isolation differs'
   assert_owner
   helper_hash=$(sha_file "$GSJ_PAYLOAD/helpers/backup-recovery.py"); helper="/tmp/gsj-backup-recovery-$helper_hash.py"
   k exec -i "$pod" -- python -c 'import hashlib,os,pathlib,stat,sys; p=pathlib.Path(sys.argv[1]); data=sys.stdin.buffer.read(); assert hashlib.sha256(data).hexdigest()==sys.argv[2]; exists=p.exists() or p.is_symlink(); assert not exists or (stat.S_ISREG(p.lstat().st_mode) and not p.is_symlink() and p.read_bytes()==data); fd=None if exists else os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600); out=None if fd is None else os.fdopen(fd,"wb"); out.write(data) if out else None; out.close() if out else None' "$helper" "$helper_hash" < "$GSJ_PAYLOAD/helpers/backup-recovery.py"
   k exec "$pod" -- python "$helper" freeze > "$GSJ_WORK/backup-exec-freeze.json" || fail 'abandoned maintenance exec writers could not be frozen'
   jq -e '.format=="gsj.exec-freeze/1" and .frozen==true' "$GSJ_WORK/backup-exec-freeze.json" >/dev/null || fail 'abandoned maintenance exec writers could not be stopped'
   k exec "$pod" -- python "$helper" inspect > "$GSJ_WORK/backup-transfer-summary.json" || fail 'stopped maintenance transfer bytes could not be measured'
   size=$(jq -er '.archive_upper_bound_bytes|select(type=="number" and .>0)' "$GSJ_WORK/backup-transfer-summary.json")
   capacity_host_filesystems
   jq -e --argjson size "$size" '.backup.available_bytes >= ($size+268435456)' "$GSJ_WORK/capacity-host.json" >/dev/null || fail 'additional space is required to preserve abandoned maintenance bytes; its writers remain stopped'
   if [[ ! -e $artifact && ! -L $artifact ]]; then
     # Every interrupted ciphertext stream keeps its own immutable filename.
     # A retry writes a fresh attempt, never truncates a previous partial.
     staged=$(mktemp "$artifact.partial.XXXXXXXX")
     log 'Preserving stopped maintenance transfer bytes as encrypted recovery evidence'
     k exec "$pod" -- python "$helper" archive | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass "file:$BACKUP_PASSWORD" > "$staged" || fail 'maintenance preservation stream failed; its partial ciphertext and stopped Pod remain intact'
     sync "$staged"
   else
     [[ -f $artifact && ! -L $artifact ]] || fail 'preservation artifact is not an ordinary file'
     staged=$artifact
   fi
   openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$BACKUP_PASSWORD" -in "$staged" | k exec -i "$pod" -- python "$helper" verify > "$GSJ_WORK/backup-transfer-verified.json" || fail 'encrypted maintenance preservation did not verify; the stopped Pod remains intact'
   cmp -s "$GSJ_WORK/backup-transfer-summary.json" "$GSJ_WORK/backup-transfer-verified.json" || fail 'encrypted maintenance preservation differs from stopped source bytes'
   assert_owner
   if [[ $staged != "$artifact" ]]; then ln "$staged" "$artifact" || fail 'preservation artifact already exists'; rm "$staged"; fi
   openssl rand 32 > "$GSJ_WORK/preservation-key-check"
   openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass "file:$BACKUP_PASSWORD" -in "$GSJ_WORK/preservation-key-check" | base64 | tr -d '\n' > "$GSJ_WORK/preservation-key-check.enc"
   jq -n --arg uid "$uid" --arg intent "$(sha_file "$intent")" --arg sha "$(sha_file "$artifact")" --rawfile key_check "$GSJ_WORK/preservation-key-check.enc" --arg key_hash "$(sha_file "$GSJ_WORK/preservation-key-check")" --slurpfile summary "$GSJ_WORK/backup-transfer-verified.json" '{format:"gsj.pod-preservation/1",verified:true,pod_uid:$uid,intent_sha256:$intent,archive_sha256:$sha,key_check:$key_check,key_check_sha256:$key_hash,transfer:$summary[0]}' | immutable_file "$artifact.json"
 fi
 if [[ -s $GSJ_WORK/backup-recovery-pod.json ]]; then
   [[ $(k get pod "$pod" -o json | jq -r .metadata.uid) == "$uid" ]] || fail 'abandoned maintenance Pod was replaced; it will not be deleted'
   assert_owner
   jq -n --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid}}' > "$GSJ_WORK/backup-recovery-delete.json"
   transfer_handback "$pod"
   k delete --raw "/api/v1/namespaces/$NAMESPACE/pods/$pod" -f "$GSJ_WORK/backup-recovery-delete.json" >/dev/null
   k wait --for=delete "pod/$pod" --timeout=300s >/dev/null
 fi
}
prepare_backup_generation() {
 assert_owner
 local generation=$1 snapshot current archive previous intent highest=0 candidate number fingerprint oldpod stem
 [[ $generation =~ ^[1-9][0-9]{0,5}$ ]] || fail 'backup generation must be a positive bounded integer'
 jq -e '.kind|IN("backup","install","upgrade","repair")' "$STATE_DIR/operation.json" >/dev/null || fail 'named backup generation cannot continue a restore or another operation kind'
 snapshot=$(quiescence_snapshot); [[ -f $snapshot && ! -L $snapshot ]] || fail 'named backup generation requires the original quiescence snapshot'
 jq -e '.credential_fingerprint|type=="string" and test("^[a-f0-9]{64}$")' "$snapshot" >/dev/null || fail 'historical backup snapshot has no original credential baseline; a new generation cannot prove preservation'
 current=$(jq -r '.backup_generation // 0' "$STATE_DIR/operation.json")
 stem=$(backup_stem)
 previous=$(backup_archive); archive="$BACKUP_DIR/$stem.g$generation.tar.gz.enc"
 intent="$STATE_DIR/backup-generation-$stem-$generation.json"
 if [[ $generation == "$current" ]]; then
   [[ -f $intent.ready ]] || fail 'active backup generation is not prepared'
   backup_archive >/dev/null; return
 fi
 [[ ! -e $previous.json && ! -L $previous.json ]] || fail 'a verified or damaged backup receipt already exists; preserve and reconcile that recovery point'
 for candidate in "$STATE_DIR/backup-generation-$stem-"*.json; do
   [[ -e $candidate || -L $candidate ]] || continue
   [[ -f $candidate && ! -L $candidate ]] || fail 'backup generation intent is not an ordinary file'
   number=${candidate##*-}; number=${number%.json}
   [[ $number =~ ^[1-9][0-9]{0,5}$ ]] || fail 'invalid reserved backup generation'
   (( number <= highest )) || highest=$number
 done
 if [[ ! -e $intent && ! -L $intent ]]; then
   (( generation == highest+1 && generation > current )) || fail 'select the next unreserved backup generation'
   for candidate in "$archive" "$archive.partial" "$archive.json" "$archive.resources.enc" "$archive.resources.enc.partial" "$archive.sha256" "$archive.resources.enc.sha256"; do
     [[ ! -e $candidate && ! -L $candidate ]] || fail 'new backup generation path already exists without an intent'
   done
 else
   [[ -f $intent && ! -L $intent ]] || fail 'backup generation intent is not an ordinary file'
 fi
 validate_quiescence_snapshot "$snapshot"
 validate_backup_closure "$snapshot"
 k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/generation-controllers.json"
 jq -e --slurpfile saved "$snapshot" 'def specs: [.items[]|{name:.metadata.name,uid:.metadata.uid,spec:(.spec|del(.replicas))}]|sort_by(.name); specs==($saved[0].controllers|specs)' "$GSJ_WORK/generation-controllers.json" >/dev/null || fail 'target controller mutation forbids a new backup generation'
 jq -e --slurpfile saved "$snapshot" '.==$saved[0].installed' "$GSJ_WORK/installed.json" >/dev/null || fail 'installed source metadata changed; refusing a newly labelled source backup'
 fingerprint=$(backup_credential_fingerprint)
 [[ $fingerprint == $(jq -r .credential_fingerprint "$snapshot") ]] || fail 'source credentials/configuration changed; original partial backups are preserved'
 capacity_qualify create
 backup_partial_inventory "$previous" > "$GSJ_WORK/generation-prior-artifacts.json"
 oldpod=$(backup_pod_name)
 k get pod "$oldpod" -o json --ignore-not-found > "$GSJ_WORK/generation-old-pod.json"
 jq -n --arg operation "$OPERATION" --argjson generation "$generation" --arg archive "$archive" --arg previous "$previous" --arg snapshot "$(sha_file "$snapshot")" --arg fingerprint "$fingerprint" --slurpfile artifacts "$GSJ_WORK/generation-prior-artifacts.json" --slurpfile pod "$GSJ_WORK/generation-old-pod.json" '{format:"gsj.backup-generation/1",operation:$operation,generation:$generation,archive:$archive,previous_archive:$previous,quiescence_sha256:$snapshot,credential_fingerprint:$fingerprint,prior_artifacts:$artifacts[0],previous_pod:(if ($pod|length)>0 then {name:$pod[0].metadata.name,uid:$pod[0].metadata.uid,spec:$pod[0].spec} else null end)}' > "$GSJ_WORK/generation-candidate.json"
 if [[ -f $intent ]]; then
   # Pod absence is valid only after the existing intent's preservation proof;
   # all other source and prior-artifact fields must remain byte-equivalent.
   jq -e --slurpfile original "$intent" 'del(.previous_pod)==($original[0]|del(.previous_pod)) and (.previous_pod==null or .previous_pod==$original[0].previous_pod)' "$GSJ_WORK/generation-candidate.json" >/dev/null || fail 'named generation source or preserved artifact bytes changed'
 else
   jq -e '(.prior_artifacts|length)>0 or .previous_pod!=null' "$GSJ_WORK/generation-candidate.json" >/dev/null || fail 'no partial backup requires a new generation; resume the original operation'
   cat "$GSJ_WORK/generation-candidate.json" | immutable_file "$intent"
 fi
 quiesce
 preserve_backup_pod "$intent"
 if [[ ! -f $intent.ready ]]; then sha_file "$intent" | immutable_file "$intent.ready"; fi
 jq --argjson generation "$generation" '.backup_generation=$generation|.status="owned"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 log "Prepared immutable backup generation $generation; all earlier recovery artifacts remain preserved"
}
validate_quiescence_snapshot() {
 local snapshot=$1 actual_ns
 actual_ns=$(k get namespace "$NAMESPACE" -o json | jq -r .metadata.uid)
 jq -e --arg operation "$OPERATION" --arg ns "$NAMESPACE" --arg release "$RELEASE" --arg uid "$actual_ns" '
   .format=="gsj.quiescence/1" and .operation==$operation and
   .installed.namespace_uid==$uid and .installed.site.target.namespace==$ns and .installed.site.target.release==$release and
   (.installed.manifest.identity|type=="string" and length>0) and
   (.controllers.items|length)==3 and ([.controllers.items[].metadata.uid]|unique|length)==3
 ' "$snapshot" >/dev/null || fail 'maintenance snapshot operation, source or namespace identity differs'
 storage_identity > "$GSJ_WORK/quiescence-storage.json"
 jq -e --slurpfile actual "$GSJ_WORK/quiescence-storage.json" '.installed.storage==$actual[0]' "$snapshot" >/dev/null || fail 'maintenance source storage identity changed'
}
backup_closure_state() {
 local snapshot=$1 output=$2 fingerprint
 assert_owner
 validate_quiescence_snapshot "$snapshot"
 jq -e --slurpfile saved "$snapshot" '.==$saved[0].installed' "$GSJ_WORK/installed.json" >/dev/null || fail 'current source differs from its stopped-writer snapshot'
 backup_storage_bindings > "$GSJ_WORK/closure-bindings.json"
 jq -e --slurpfile actual "$GSJ_WORK/closure-bindings.json" '.storage_bindings==$actual[0]' "$snapshot" >/dev/null || fail 'source PV identity differs or the historical snapshot has no PV baseline'
 fingerprint=$(backup_credential_fingerprint)
 [[ $fingerprint == $(jq -r .credential_fingerprint "$snapshot") ]] || fail 'source credentials or configuration changed since quiescence'
 k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/closure-controllers.json"
 jq -e --slurpfile saved "$snapshot" '
   def specs: [.items[]|{name:.metadata.name,uid:.metadata.uid,spec:(.spec|del(.replicas))}]|sort_by(.name);
   specs==($saved[0].controllers|specs) and
   all(.items[]; .metadata.deletionTimestamp==null and .spec.replicas==0 and (.metadata.generation|type=="number" and .==floor and .>0))
 ' "$GSJ_WORK/closure-controllers.json" >/dev/null || fail 'source controllers are not the unchanged stopped writers'
 k get jobs -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/closure-jobs.json"
 jq -e 'all(.items[];(.status.active//0)==0 and any(.status.conditions[]?; (.type|IN("Complete","Failed")) and .status=="True"))' "$GSJ_WORK/closure-jobs.json" >/dev/null || fail 'a provisioning writer is active or can still start'
 k get pods -l "app.kubernetes.io/instance=$RELEASE" -o json | jq -e 'all(.items[]; (.status.phase|IN("Succeeded","Failed")))' >/dev/null || fail 'an application or provisioning writer Pod still exists'
 # Unlabeled Pods can mount the same RWO claims on this node. Like restore,
 # admit only finished Pods and the owned maintenance Pod as claim users.
 k get pods -o json | jq -e --arg pod "$(backup_pod_name)" --argjson claims "$(jq '[.storage[].name]' "$GSJ_WORK/installed.json")" '
   all(.items[]; (.status.phase|IN("Succeeded","Failed")) or (.metadata.name==$pod and .metadata.labels["gsj.io/operation"]==$pod) or
     all(.spec.volumes[]?.persistentVolumeClaim.claimName; . as $name | ($claims|index($name))==null))
 ' >/dev/null || fail 'another Pod mounts the backup source storage; stop it before the backup'
 jq -n --arg operation "$OPERATION" --arg snapshot "$(sha_file "$snapshot")" --arg fingerprint "$fingerprint" --slurpfile source "$snapshot" --slurpfile controllers "$GSJ_WORK/closure-controllers.json" --slurpfile jobs "$GSJ_WORK/closure-jobs.json" --slurpfile bindings "$GSJ_WORK/closure-bindings.json" '{format:"gsj.quiescence-closure/1",operation:$operation,round:($source[0].round//0),snapshot_sha256:$snapshot,namespace_uid:$source[0].installed.namespace_uid,release_identity:$source[0].installed.manifest.identity,credential_fingerprint:$fingerprint,storage_bindings:$bindings[0],controllers:([$controllers[0].items[]|{name:.metadata.name,uid:.metadata.uid,generation:.metadata.generation,replicas:.spec.replicas}]|sort_by(.name)),jobs:([$jobs[0].items[]|{name:.metadata.name,uid:.metadata.uid,generation:.metadata.generation,spec,status}]|sort_by(.name)),writers_absent:true}' > "$output"
}
validate_backup_closure() {
 local snapshot=$1 closure="$1.closure.json"
 [[ -f $closure && ! -L $closure ]] || fail "historical backup has no stopped-writer continuity proof; preserve it and use repair --operation $OPERATION --backup-round $(( $(backup_round_number)+1 )) for a fresh recovery point"
 backup_closure_state "$snapshot" "$GSJ_WORK/closure-current.json"
 jq -e --slurpfile saved "$closure" '.==$saved[0]' "$GSJ_WORK/closure-current.json" >/dev/null || fail "writers or their storage changed after the backup; preserve it and use repair --operation $OPERATION --backup-round $(( $(backup_round_number)+1 ))"
}
backup_quiesce_transition() {
 local snapshot=$1 controllers=$2
 jq -e --slurpfile saved "$snapshot" '
   def specs: [.items[]|{name:.metadata.name,uid:.metadata.uid,spec:(.spec|del(.replicas))}]|sort_by(.name);
   specs==($saved[0].controllers|specs) and
   all(.items[]; . as $now | any($saved[0].controllers.items[];
     .metadata.uid==$now.metadata.uid and (.metadata.generation|type=="number" and .==floor and .>0) and
     (($now.spec.replicas==.spec.replicas and $now.metadata.generation==.metadata.generation) or
      ($now.spec.replicas==0 and $now.metadata.generation==(.metadata.generation+(if .spec.replicas==0 then 0 else 1 end))))))
 ' "$controllers" >/dev/null || fail 'source controllers changed beyond the recorded scale-to-zero transition; a fresh backup round is required'
}
quiesce() {
 assert_owner
 local snapshot; snapshot=$(quiescence_snapshot)
 k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/controllers-current.json"
 if [[ -e $snapshot || -L $snapshot ]]; then
   [[ -f $snapshot && ! -L $snapshot ]] || fail 'maintenance snapshot is not a regular file'
   validate_quiescence_snapshot "$snapshot"
   if [[ -e $snapshot.closure.json || -L $snapshot.closure.json ]]; then
     validate_backup_closure "$snapshot"
     jq '.controllers' "$snapshot" > "$GSJ_WORK/controllers.json"
     log 'Recorded application writers remain stopped'
     return
   fi
   backup_quiesce_transition "$snapshot" "$GSJ_WORK/controllers-current.json"
 else
   # A source receipt cannot certify a partly applied target. Check both its
   # exact workload images and the generation embedded in the init gate.
   jq -e --slurpfile installed "$GSJ_WORK/installed.json" --arg release "$RELEASE" "$JQ_IMAGE"'
     $installed[0] as $s | ($s.manifest.images|map_values(image_ref($s.site.registry.base))) as $images |
     (.items|length)==3 and
     ([.items[].metadata.name]|sort)==([$release+"-web",$release+"-forgejo",$release+"-chroma"]|sort) and
     all(.items[]; (.metadata.uid|type=="string" and length>0)) and
     ([.items[].spec.template.spec.containers[]|{key:.name,value:.image}]|from_entries)==
       {"gsj-web":$images.web,"agent-runner":$images.runner,"gsj-mcp":$images.mcp,"forgejo":$images.forgejo,"chroma":$images.chroma} and
     any(.items[]|select(.metadata.name==($release+"-web"))|.spec.template.spec.initContainers[]?.env[]?;
         .name=="GSJ_DEPLOYMENT_GENERATION" and (.value|startswith($s.manifest.identity+":"))) and
     ($s.status=="complete" or $s.status=="verification-pending")
   ' "$GSJ_WORK/controllers-current.json" >/dev/null || fail 'live controllers do not prove the recorded source release; refusing a backup of a partially changed target'
   local credential_fingerprint; credential_fingerprint=$(backup_credential_fingerprint) || fail 'the credential fingerprint could not be read from the cluster; nothing was compared'
   backup_storage_bindings > "$GSJ_WORK/quiescence-bindings.json"
   jq -n --arg operation "$OPERATION" --argjson round "$(backup_round_number)" --arg fingerprint "$credential_fingerprint" --slurpfile installed "$GSJ_WORK/installed.json" --slurpfile controllers "$GSJ_WORK/controllers-current.json" --slurpfile bindings "$GSJ_WORK/quiescence-bindings.json" '{format:"gsj.quiescence/1",operation:$operation,round:$round,credential_fingerprint:$fingerprint,installed:$installed[0],controllers:$controllers[0],storage_bindings:$bindings[0]}' > "$GSJ_WORK/quiescence-candidate.json"
   validate_quiescence_snapshot "$GSJ_WORK/quiescence-candidate.json"
   backup_quiesce_transition "$GSJ_WORK/quiescence-candidate.json" "$GSJ_WORK/controllers-current.json"
   cat "$GSJ_WORK/quiescence-candidate.json" | immutable_file "$snapshot"
 fi
 jq '.controllers' "$snapshot" > "$GSJ_WORK/controllers.json"
 k get jobs -l "app.kubernetes.io/instance=$RELEASE" -o json | jq -e 'all(.items[];(.status.active//0)==0 and any(.status.conditions[]?; (.type|IN("Complete","Failed")) and .status=="True"))' >/dev/null || fail 'provisioning is still writing or can still start'
 k scale deployment -l "app.kubernetes.io/instance=$RELEASE" --replicas=0 >/dev/null
 k get pods -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/writer-pods.json"
 jq -r '.items[] | select(any(.metadata.ownerReferences[]?; .kind=="ReplicaSet")) | .metadata.name' "$GSJ_WORK/writer-pods.json" > "$GSJ_WORK/writer-pods.list"
 local writer
 while IFS= read -r writer; do k wait --for=delete "pod/$writer" --timeout=300s; done < "$GSJ_WORK/writer-pods.list"
 k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/quiesced-controllers.json"
 backup_quiesce_transition "$snapshot" "$GSJ_WORK/quiesced-controllers.json"
 backup_closure_state "$snapshot" "$GSJ_WORK/closure-candidate.json"
 cat "$GSJ_WORK/closure-candidate.json" | immutable_file "$snapshot.closure.json"
 log 'Application, runner, Forgejo and Chroma writers have stopped'
}
backup_resources() {
 # Snapshot only the installed release and its typed, explicit references.
 # In particular, never list unrelated namespace Secret values into a pipe.
 local refs="$GSJ_WORK/owned-references.json" parts="$GSJ_WORK/cluster-items.jsonl" pvparts="$GSJ_WORK/pv-items.jsonl"
 local kind name claim uid volume object file mode
 jq -e '.storage | type=="array" and length==3 and all(.[]; (.name|type=="string" and length>0) and (.uid|type=="string" and length>0) and (.volume|type=="string" and length>0))' "$GSJ_WORK/installed.json" >/dev/null || fail 'backup requires the three installed PVC identities'
 jq --arg release "$RELEASE" '.site as $s | {
   Secret:([$release+"-admin-token",$release+"-agent-token",$release+"-webhook",$s.operator.secret,$s.tls.secret,$s.registry.pull_secret,
     (if $s.tls.profile=="managed-acme" then $s.tls.issuer+"-account" else "" end),
     (if $s.llm.credential.file!="" then $release+"-llm-key" else $s.llm.credential.secret end),
     (if $s.ocr.credential.file!="" then $release+"-ocr-key" else $s.ocr.credential.secret end),
     (if $s.trust.proxy_file!="" then $release+"-proxy" else "" end)] | map(select(type=="string" and length>0)) | unique),
   ConfigMap:([$release+"-provisioned",(if $s.trust.ca_file!="" then $release+"-trust" else "" end),(if $s.tls.profile=="managed-acme" then $release+"-acme-owner" else "" end)] | map(select(length>0)) | unique),
   Issuer:(if $s.tls.profile=="managed-acme" then [$s.tls.issuer] else [] end),
   Certificate:(if $s.tls.profile=="managed-acme" then [$s.tls.secret] else [] end),
   PersistentVolumeClaim:[.storage[].name]
 }' "$GSJ_WORK/installed.json" > "$refs"
 : > "$parts"; : > "$pvparts"
 # Every read is checked here, by this function: it is also called inside a
 # command substitution (the credential fingerprint) from || lists, where
 # errexit cannot be relied on, so a kubectl that fails part-way must return 1
 # from HERE, never leave a partial snapshot behind a succeeding last command.
 for kind in 'app.kubernetes.io/instance' 'gsj.io/owner'; do
   object=$(k get configmaps,services,ingresses,serviceaccounts,roles,rolebindings,deployments,networkpolicies -l "$kind=$RELEASE" -o json) || return 1
   printf '%s\n' "$object" | jq -c '.items[]' >> "$parts" || return 1
 done
 object=$(k get secrets -l "owner=helm,name=$RELEASE" -o json) || return 1
 printf '%s\n' "$object" | jq -c '.items[]' >> "$parts" || return 1
 for kind in Secret ConfigMap Issuer Certificate; do
   while IFS= read -r name; do
     object=$(k get "$kind" "$name" -o json) || return 1
     printf '%s\n' "$object" | jq -c . >> "$parts" || return 1
   done < <(jq -r --arg kind "$kind" '.[$kind][]' "$refs")
 done
 while IFS=$'\t' read -r claim uid volume; do
   object=$(k get pvc "$claim" -o json) || return 1
   printf '%s\n' "$object" | jq -e --arg uid "$uid" --arg volume "$volume" '.metadata.uid==$uid and .spec.volumeName==$volume' >/dev/null || fail 'PVC identity changed during backup'
   printf '%s\n' "$object" | jq -c . >> "$parts" || return 1
   object=$(k get pv "$volume" -o json) || return 1
   printf '%s\n' "$object" | jq -e --arg ns "$NAMESPACE" --arg uid "$uid" '.spec.claimRef.namespace==$ns and .spec.claimRef.uid==$uid' >/dev/null || fail 'PV binding changed during backup'
   printf '%s\n' "$object" | jq -c . >> "$pvparts" || return 1
 done < <(jq -r '.storage[]|[.name,.uid,.volume]|@tsv' "$GSJ_WORK/installed.json")
 jq -s '{apiVersion:"v1",kind:"List",items:unique_by(.kind+"/"+.metadata.name)}' "$parts" > "$GSJ_WORK/cluster-private.json" || return 1
 if [[ $(jq -r .site.tls.profile "$GSJ_WORK/installed.json") == managed-acme ]]; then
   jq '.site' "$GSJ_WORK/installed.json" > "$GSJ_WORK/acme-backup-site.json"
   acme_validate_bundle "$GSJ_WORK/acme-backup-site.json" "$(jq -r .namespace_uid "$GSJ_WORK/installed.json")" "$GSJ_WORK/cluster-private.json"
 fi
 jq -s '{apiVersion:"v1",kind:"List",items:unique_by(.metadata.name)}' "$pvparts" > "$GSJ_WORK/volumes-private.json" || return 1
 rm -f "$parts" "$pvparts"
 # Explicit inputs only. Paths are not authority to write during restore:
 # destinations are resolved again from the target site and managed TLS home.
 : > "$GSJ_WORK/site-inputs.jsonl"
 while IFS=$'\t' read -r name file; do
   [[ -n $file ]] || continue
   file=$(resolve_file "$file")
   [[ -f $file && ! -L $file ]] || fail 'configured backup input is missing or not a regular file'
   mode=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file")
   base64 < "$file" | tr -d '\n' | jq -Rs --arg name "$name" --argjson mode "$((8#$mode & 0777))" '{name:$name,data:.,mode:$mode}' >> "$GSJ_WORK/site-inputs.jsonl"
 done < <(jq -r '.site as $s | ["operator.password_file","llm.credential.file","ocr.credential.file","registry.config_file","tls.certificate_file","tls.private_key_file","tls.ca_file","trust.ca_file","trust.proxy_file","verification.ca_file","delivery.ca_file","delivery.auth_header_file","backup.ca_file","backup.auth_header_file"][] as $name | ($s|getpath($name|split("."))) as $file | select($file|type=="string" and length>0) | [$name,$file]|@tsv' "$GSJ_WORK/installed.json")
 if [[ $(jq -r .site.tls.profile "$GSJ_WORK/installed.json") == managed-local-ca ]]; then
   for name in ca.key ca.crt; do
     file="$STATE_DIR/tls/$name"
     [[ -f $file && ! -L $file ]] || fail 'managed local CA ownership files are required in the encrypted backup'
     mode=$(stat -c %a "$file" 2>/dev/null || stat -f %Lp "$file")
     base64 < "$file" | tr -d '\n' | jq -Rs --arg name "managed_tls.$name" --argjson mode "$((8#$mode & 0777))" '{name:$name,data:.,mode:$mode}' >> "$GSJ_WORK/site-inputs.jsonl"
   done
 fi
 jq -s '{format:"gsj.site-inputs/1",entries:.}' "$GSJ_WORK/site-inputs.jsonl" > "$GSJ_WORK/site_inputs.json"
 rm -f "$GSJ_WORK/site-inputs.jsonl"
}
offbox_backup() {
 local archive=$1 destination ca auth file expected actual
 destination=$(j .backup.offbox_url); [[ -n $destination ]] || return 0
 [[ $destination == https://* ]] || fail 'off-box backups require HTTPS'
 local args=(--fail --silent --show-error --location --max-redirs 0 --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 7200)
 ca=$(j .backup.ca_file); auth=$(j .backup.auth_header_file)
 if [[ -n $ca ]]; then
   ca=$(resolve_file "$ca"); openssl x509 -in "$ca" -noout >/dev/null || fail 'invalid backup CA certificate'
   cat "$(system_ca_bundle)" "$ca" > "$GSJ_WORK/backup-ca.pem"; args+=(--cacert "$GSJ_WORK/backup-ca.pem")
 fi
 if [[ -n $auth ]]; then
   auth=$(resolve_file "$auth"); header_file "$auth"; cp "$auth" "$GSJ_WORK/backup-authorization"; chmod 600 "$GSJ_WORK/backup-authorization"
   args+=(--header "@$GSJ_WORK/backup-authorization")
 fi
 for file in "$archive" "$archive.resources.enc" "$archive.json"; do
   expected=$(sha_file "$file")
   curl "${args[@]}" --upload-file "$file" "${destination%/}/$(basename "$file")" >/dev/null
   # Hash the remote encrypted bytes as a stream. The destination must support
   # read-after-write; a successful PUT alone is insufficient recovery evidence.
   actual=$(curl "${args[@]}" "${destination%/}/$(basename "$file")" | openssl dgst -sha256 | awk '{print $NF}') || fail 'off-box backup read-back failed'
   [[ $actual == "$expected" ]] || fail 'off-box backup read-back integrity failed'
 done
 jq -n --arg archive "$(basename "$archive")" --arg destination "$destination" '{format:"gsj.offbox-backup/1",archive:$archive,destination:$destination,readback_verified:true}' | atomic "$archive.offbox.json"
 log 'Off-box encrypted backup and recovery metadata verified by read-back'
}
verified_backup_reuse() {
 local archive=$1 snapshot=$2 file key_hash
 for file in "$archive" "$archive.resources.enc" "$archive.json" "$snapshot"; do
   [[ -f $file && ! -L $file ]] || fail 'verified backup is incomplete; reconcile the named operation without replacing its recovery point'
 done
 validate_quiescence_snapshot "$snapshot"
 jq -e --arg operation "$OPERATION" --arg archive "$archive" --arg sha "$(sha_file "$archive")" --arg resources "$(sha_file "$archive.resources.enc")" --arg snapshot "$(sha_file "$snapshot")" --slurpfile source "$snapshot" '
   .format=="gsj.backup/1" and .verified==true and .operation==$operation and .archive==$archive and
   .sha256==$sha and .resources_sha256==$resources and .quiescence_sha256==$snapshot and
   .release_identity==$source[0].installed.manifest.identity and .namespace_uid==$source[0].installed.namespace_uid and
   .storage==$source[0].installed.storage
 ' "$archive.json" >/dev/null || fail 'verified backup receipt, source identity or encrypted bytes differ; original recovery point is preserved'
 if jq -e 'has("closure_sha256")' "$archive.json" >/dev/null; then
   [[ -f $snapshot.closure.json && ! -L $snapshot.closure.json ]] && [[ $(sha_file "$snapshot.closure.json") == $(jq -r .closure_sha256 "$archive.json") ]] || fail 'verified backup stopped-writer closure differs'
 fi
 key_hash=$(jq -er '.key_check' "$archive.json" | base64 --decode | openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$BACKUP_PASSWORD" 2> "$GSJ_WORK/backup-key-check.log" | openssl dgst -sha256 | awk '{print $NF}') || fail 'the supplied recovery key does not match the immutable backup'
 [[ $key_hash == $(jq -r .key_check_sha256 "$archive.json") ]] || fail 'the supplied recovery key does not match the immutable backup'
}
backup_complete() {
 local archive=$1 pod=$2 object destination
 validate_backup_closure "$(quiescence_snapshot)"
 destination=$(j .backup.offbox_url)
 if [[ -e $archive.offbox.json || -L $archive.offbox.json ]]; then
   [[ -f $archive.offbox.json && ! -L $archive.offbox.json ]] || fail 'off-box receipt is not a regular file'
   jq -e --arg destination "$destination" --arg archive "$(basename "$archive")" '.format=="gsj.offbox-backup/1" and .readback_verified==true and .destination==$destination and .archive==$archive' "$archive.offbox.json" >/dev/null || fail 'verified off-box destination differs; use a separate explicit copy operation'
 else
   offbox_backup "$archive"
 fi
 validate_backup_closure "$(quiescence_snapshot)"
 object=$(k get pod "$pod" -o json --ignore-not-found)
 if [[ -n $object ]]; then
   jq -e --arg owner "$pod" '.metadata.labels["gsj.io/operation"]==$owner' <<< "$object" >/dev/null || fail 'backup maintenance pod belongs to another operation'
   transfer_handback "$pod"
   k delete pod "$pod" --wait=true >/dev/null
 fi
 jq --arg backup "$archive" '.status="backup-verified"|.backup=$backup' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 log "Consistent encrypted backup verified: $archive"
}
backup() {
 assert_owner
 local pod archive image snapshot file
 pod=$(backup_pod_name); archive=$(backup_archive)
 snapshot=$(quiescence_snapshot)
 if [[ -e $archive.json || -L $archive.json ]]; then
   verified_backup_reuse "$archive" "$snapshot"
   validate_backup_closure "$snapshot"
   # Reuse certifies only this unchanged source. An older recovery point
   # remains valid history after migration, but cannot stand in for a fresh
   # backup of later data or configuration before another mutation.
   jq -e --slurpfile saved "$snapshot" '.==$saved[0].installed' "$GSJ_WORK/installed.json" >/dev/null || fail 'source release metadata changed after capture; the preserved backup is historical, not a fresh recovery point'
   capacity_qualify reuse
   k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/backup-reuse-controllers.json"
   jq -e --slurpfile saved "$snapshot" 'def source_specs: [.items[]|{name:.metadata.name,uid:.metadata.uid,spec:(.spec|del(.replicas))}]|sort_by(.name); source_specs==($saved[0].controllers|source_specs)' "$GSJ_WORK/backup-reuse-controllers.json" >/dev/null || fail 'source controllers changed after capture; the preserved backup is historical, not a fresh recovery point'
   quiesce
   backup_complete "$archive" "$pod"
   log 'Reused the immutable source backup; no archive was replaced'
   return
 fi
 # A partial archive may be the only surviving source bytes. An ordinary
 # retry must never overwrite it, even when the live target looks ready.
 for file in "$archive" "$archive.partial" "$archive.sha256" "$archive.resources.enc" "$archive.resources.enc.partial" "$archive.resources.enc.sha256" "$archive.offbox.json"; do
   [[ ! -e $file && ! -L $file ]] || fail 'incomplete backup artifacts exist; preserve them and reconcile the named operation before continuing'
 done
 capacity_qualify create
 quiesce
 # A captured source can be continued after scale-to-zero, but never after
 # any other controller-spec or installed-release mutation.
 jq -e --slurpfile saved "$snapshot" 'def source_specs: [.items[]|{name:.metadata.name,uid:.metadata.uid,spec:(.spec|del(.replicas))}]|sort_by(.name); source_specs==($saved[0].controllers|source_specs)' "$GSJ_WORK/controllers-current.json" >/dev/null || fail 'source controllers changed after capture; refusing to archive a partial target'
 jq -e --slurpfile saved "$snapshot" '.==$saved[0].installed' "$GSJ_WORK/installed.json" >/dev/null || fail 'source release metadata changed after capture; original maintenance snapshot is preserved'
 image=$(installed_image web "$GSJ_WORK/installed.json")
 printf '["sleep","86400"]' > "$GSJ_WORK/sleep.json"; maintenance_pod "$pod" "$image" "$GSJ_WORK/sleep.json"
 capacity_scan_pod "$pod" create quiesced || fail 'quiesced source or actual maintenance staging capacity changed; backup and migration did not start'
 printf '{"forgejo":"/volumes/forgejo","gsj":"/volumes/gsj","chroma":"/volumes/chroma"}' > "$GSJ_WORK/volumes.json"
 jq -n --arg identity "$(jq -r .manifest.identity "$GSJ_WORK/installed.json")" --arg generation "$OPERATION" --slurpfile controllers "$GSJ_WORK/controllers.json" --slurpfile installed "$GSJ_WORK/installed.json" '{release_identity:$identity,generation:$generation,quiesced:true,controllers:$controllers[0],installed:$installed[0]}' > "$GSJ_WORK/backup-meta.json"
 k exec -i "$pod" -- sh -c 'umask 077; cat > /transfer/volumes.json' < "$GSJ_WORK/volumes.json"
 k exec -i "$pod" -- sh -c 'umask 077; cat > /transfer/metadata.json' < "$GSJ_WORK/backup-meta.json"
 log 'Checking SQLite integrity and writing the consistent archive; the helper reports byte and entry progress'
 k exec "$pod" -- python -m gsj_deploy.backup create --output /transfer/snapshot.tar.gz --volumes /transfer/volumes.json --metadata /transfer/metadata.json
 k exec "$pod" -- python -m gsj_deploy.backup verify --archive /transfer/snapshot.tar.gz
 # Never stage customer content unencrypted outside the maintenance container.
 k exec "$pod" -- cat /transfer/snapshot.tar.gz | (set -o noclobber; openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass "file:$BACKUP_PASSWORD" > "$archive.partial")
 sync "$archive.partial"
 validate_backup_closure "$snapshot"
 ln "$archive.partial" "$archive" || fail 'backup archive already exists; no bytes replaced'
 rm "$archive.partial"; sha_file "$archive" | immutable_file "$archive.sha256"
 # Resource and secret snapshots are encrypted separately; no values enter logs.
 backup_resources
 local resource_bytes
 resource_bytes=$(wc -c "$GSJ_WORK/cluster-private.json" "$GSJ_WORK/volumes-private.json" "$GSJ_WORK/site_inputs.json" "$GSJ_WORK/installed.json" "$GSJ_WORK/controllers.json" "$STATE_DIR/site.pending.json" | awk 'END {print $1}')
 [[ $resource_bytes =~ ^[0-9]+$ ]] && (( resource_bytes * 2 + 16777216 <= 536870912 )) || fail 'private resource archive exceeds its measured capacity allowance; existing volume backup is preserved'
 tar -czf - -C "$GSJ_WORK" cluster-private.json volumes-private.json site_inputs.json installed.json controllers.json -C "$STATE_DIR" site.pending.json | (set -o noclobber; openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass "file:$BACKUP_PASSWORD" > "$archive.resources.enc.partial")
 sync "$archive.resources.enc.partial"
 validate_backup_closure "$snapshot"
 ln "$archive.resources.enc.partial" "$archive.resources.enc" || fail 'backup resources archive already exists; no bytes replaced'
 rm "$archive.resources.enc.partial"
 sha_file "$archive.resources.enc" | immutable_file "$archive.resources.enc.sha256"
 # Verify transport/decryption bytes with the pod's public archive verifier.
 openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$BACKUP_PASSWORD" -in "$archive" | k exec -i "$pod" -- sh -c 'cat > /transfer/roundtrip.tar.gz'
 k exec "$pod" -- python -m gsj_deploy.backup verify --archive /transfer/roundtrip.tar.gz
 validate_backup_closure "$snapshot"
 # Bind retries to the recovery key without storing it or decrypting customer
 # data onto the script host. This random challenge is independent of content.
 openssl rand 32 > "$GSJ_WORK/backup-key-check"
 openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass "file:$BACKUP_PASSWORD" -in "$GSJ_WORK/backup-key-check" | base64 | tr -d '\n' > "$GSJ_WORK/backup-key-check.enc"
 jq -n --arg operation "$OPERATION" --arg archive "$archive" --arg sha "$(sha_file "$archive")" --arg resources_sha "$(sha_file "$archive.resources.enc")" --arg quiescence "$(sha_file "$snapshot")" --arg closure "$(sha_file "$snapshot.closure.json")" --rawfile key_check "$GSJ_WORK/backup-key-check.enc" --arg key_hash "$(sha_file "$GSJ_WORK/backup-key-check")" --slurpfile source "$snapshot" '{format:"gsj.backup/1",operation:$operation,round:($source[0].round//0),archive:$archive,sha256:$sha,resources_sha256:$resources_sha,quiescence_sha256:$quiescence,closure_sha256:$closure,key_check:$key_check,key_check_sha256:$key_hash,namespace_uid:$source[0].installed.namespace_uid,storage:$source[0].installed.storage,release_identity:$source[0].installed.manifest.identity,verified:true}' | immutable_file "$archive.json"
 backup_complete "$archive" "$pod"
}
restart_backup_source() {
 assert_owner
 local snapshot name uid replicas current deadline all_ready
 snapshot=$(quiescence_snapshot)
 validate_quiescence_snapshot "$snapshot"
 k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/restart-controllers.json"
 jq -e --slurpfile saved "$snapshot" 'def source_specs: [.items[]|{name:.metadata.name,uid:.metadata.uid,spec:(.spec|del(.replicas))}]|sort_by(.name); source_specs==($saved[0].controllers|source_specs)' "$GSJ_WORK/restart-controllers.json" >/dev/null || fail 'source controllers changed; backup restart will not overwrite them'
 jq '.status="backup-restarting"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 while IFS=$'\t' read -r name uid replicas; do
   assert_owner
   [[ $(k get deployment "$name" -o jsonpath='{.metadata.uid}') == "$uid" ]] || fail 'source controller was replaced before restart'
   k scale "deployment/$name" --replicas="$replicas" >/dev/null
 done < <(jq -r '.controllers.items[]|[.metadata.name,.metadata.uid,(.spec.replicas//1)]|@tsv' "$snapshot")
 deadline=$((SECONDS+$(j .deadlines.initialization_seconds)+1800))
 while (( SECONDS < deadline )); do
   assert_owner
   k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json > "$GSJ_WORK/restart-progress.json"
   if jq -e --slurpfile saved "$snapshot" '
     (.items|length)==($saved[0].controllers.items|length) and
     all(.items[]; . as $current | any($saved[0].controllers.items[];
       .metadata.uid==$current.metadata.uid and (.spec.replicas//1)==($current.spec.replicas//1) and
       $current.status.observedGeneration >= $current.metadata.generation and
       ($current.status.availableReplicas//0)==(.spec.replicas//1)))
   ' "$GSJ_WORK/restart-progress.json" >/dev/null; then
     jq '.status="backup-complete"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
     log "Backup operation $OPERATION complete; original controllers and replica counts are ready. Encrypted recovery point: $(backup_archive)"
     return
   fi
   jq -c '{stage:"backup-restarting",controllers:[.items[]|{name:.metadata.name,desired:.spec.replicas,available:(.status.availableReplicas//0)}]}' "$GSJ_WORK/restart-progress.json"
   sleep 20
 done
 fail 'backup is verified but original application restart exceeded its deadline; use named resume'
}
backup_operation() {
 read_installed
 [[ -s $GSJ_WORK/installed.json ]] && jq -e --arg identity "$RELEASE_ID" '.status=="complete" and .manifest.identity==$identity' "$GSJ_WORK/installed.json" >/dev/null || fail 'backup requires the exact completed installed release installer'
 jq -e --slurpfile site "$SITE" '(.site|del(.backup,.delivery,.verification))==($site[0]|del(.backup,.delivery,.verification))' "$GSJ_WORK/installed.json" >/dev/null || fail 'backup cannot change application settings; use the saved site configuration'
 acquire
 read_installed
 jq -e --arg identity "$RELEASE_ID" '.status=="complete" and .manifest.identity==$identity' "$GSJ_WORK/installed.json" >/dev/null || fail 'installed release changed before backup ownership was acquired'
 backup
 restart_backup_source
}
helm_application_projection() {
 # Compare runtime identity, without mistaking equivalent resource-quantity
 # spellings for a different release. API defaults for empty env values and
 # omitted optional container lists are normalized on both sides.
 jq '
   def container: {name,image,command:(.command//[]),args:(.args//[]),
     env:((.env//[])|map(if has("valueFrom") then {name,valueFrom} else {name,value:(.value//"")} end)),
     envFrom:(.envFrom//[]),volumeMounts:((.volumeMounts//[])|map({name,mountPath,readOnly:(.readOnly//false),subPath:(.subPath//""),subPathExpr:(.subPathExpr//"")})),securityContext:(.securityContext//{})};
   def pod: {metadata:{labels:(.metadata.labels//{}),annotations:(.metadata.annotations//{})},spec:{
     containers:(.spec.containers|map(container)),initContainers:((.spec.initContainers//[])|map(container)),
     volumes:(.spec.volumes//[]),imagePullSecrets:(.spec.imagePullSecrets//[]),
     nodeSelector:(.spec.nodeSelector//{}),affinity:(.spec.affinity//{}),
     serviceAccountName:(.spec.serviceAccountName//"default"),
     enableServiceLinks:(if .spec.enableServiceLinks==null then true else .spec.enableServiceLinks end),
     automountServiceAccountToken:(if .spec|has("automountServiceAccountToken") then .spec.automountServiceAccountToken else true end),
     securityContext:(.spec.securityContext//{})}};
   (if type=="array" then . elif .kind=="List" then .items else [.] end) |
   map(if .kind=="Deployment" then {kind,name:.metadata.name,selector:.spec.selector,replicas:.spec.replicas,pod:(.spec.template|pod)}
       elif .kind=="Job" then {kind,name:.metadata.name,pod:(.spec.template|pod)}
       elif .kind=="ConfigMap" then {kind,name:.metadata.name,data:.data} else empty end) | sort_by(.kind,.name)
 ' "$1"
}
helm_application_prepare() {
 local prior revision uid attempt directory current
 k get secrets -l "owner=helm,name=$RELEASE" -o json | jq '{items:[.items[]|{type,metadata:{name:.metadata.name,uid:.metadata.uid,labels:.metadata.labels}}]}' > "$GSJ_WORK/helm-history-before.json"
 jq -e 'all(.items[]; .type=="helm.sh/release.v1" and (.metadata.labels.version|test("^[1-9][0-9]*$")))' "$GSJ_WORK/helm-history-before.json" >/dev/null || fail 'Helm history identity is invalid'
 prior=$(jq '[.items[].metadata.labels.version|tonumber]|max//0' "$GSJ_WORK/helm-history-before.json")
 jq -e --argjson revision "$prior" 'all(.items[]|select((.metadata.labels.version|tonumber)==$revision); (.metadata.labels.status|IN("deployed","failed","superseded","uninstalled")))' "$GSJ_WORK/helm-history-before.json" >/dev/null || fail 'Helm has a pending revision; explicit recovery is required before another application writer'
 revision=$((prior+1))
 current=$(k get job "$RELEASE-provision" -o json --ignore-not-found) || fail 'cannot establish the prior provisioning Job identity'
 uid=''; [[ -z $current ]] || uid=$(jq -er '.metadata.uid|select(type=="string" and length>0)' <<< "$current")
 h template "$RELEASE" "$GSJ_PAYLOAD/chart.tgz" --values "$GSJ_WORK/values.pending.json" \
   --show-only templates/gsj.yaml --show-only templates/forgejo.yaml --show-only templates/chroma.yaml \
   --show-only templates/scripts-configmap.yaml --show-only templates/provision-job.yaml > "$GSJ_WORK/helm-target.yaml"
 # Client-only conversion uses discovery to resolve built-in API kinds; it
 # neither creates nor applies these rendered resources.
 k create --dry-run=client --validate=false -f "$GSJ_WORK/helm-target.yaml" -o json |
   jq -s '{kind:"List",items:[.[]|if .kind=="List" then .items[] else . end]}' > "$GSJ_WORK/helm-target.json"
 # Helm template renders Release.Revision=1. This chart uses Revision only in
 # these generation env values; bind their actual next-history revision.
 jq --arg generation "$RELEASE_ID:$revision" 'walk(if type=="object" and .name?=="GSJ_DEPLOYMENT_GENERATION" and has("value") then .value=$generation else . end)' "$GSJ_WORK/helm-target.json" > "$GSJ_WORK/helm-target-generation.json"
 helm_application_projection "$GSJ_WORK/helm-target-generation.json" > "$GSJ_WORK/helm-expected.json"
 jq -e --arg release "$RELEASE" '([.[]|select(.kind=="Deployment")|.name]|sort)==([$release+"-web",$release+"-forgejo",$release+"-chroma"]|sort) and ([.[]|select(.kind=="Job")|.name]==[$release+"-provision"]) and ([.[]|select(.kind=="ConfigMap")|.name]==[$release+"-scripts"])' "$GSJ_WORK/helm-expected.json" >/dev/null || fail 'signed chart does not match the supported application workload inventory'
 attempt=$(openssl rand -hex 12); directory="$STATE_DIR/helm-applications/$OPERATION/$attempt"
 [[ ! -L $STATE_DIR/helm-applications && ! -L $STATE_DIR/helm-applications/$OPERATION ]] || fail 'Helm target directory is a symlink'
 mkdir -p "$(dirname "$directory")"; mkdir -m 700 "$directory" || fail 'Helm application intent already exists'
 cat "$GSJ_WORK/values.pending.json" | immutable_file "$directory/values.json"
 cat "$GSJ_WORK/helm-expected.json" | immutable_file "$directory/expected.json"
 jq -n --arg operation "$OPERATION" --arg attempt "$attempt" --arg target "$RELEASE_ID" --arg ns "$NAMESPACE" --arg uid "$(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid)" --arg release "$RELEASE" --arg chart "$(sha_file "$GSJ_PAYLOAD/chart.tgz")" --arg values "$(sha_file "$directory/values.json")" --arg expected "$(sha_file "$directory/expected.json")" --arg prior_job "$uid" --argjson revision "$revision" '{format:"gsj.helm-application/1",operation:$operation,attempt:$attempt,target:$target,namespace:$ns,namespace_uid:$uid,release:$release,chart_sha256:$chart,values_sha256:$values,expected_sha256:$expected,prior_job_uid:$prior_job,revision:$revision,generation:($target+":"+($revision|tostring)),template_revision:1}' | immutable_file "$directory/intent.json"
 sync "$directory"; sync "$(dirname "$directory")"; sync "$STATE_DIR/helm-applications"; sync "$STATE_DIR"
 # The pointer and phase commit together, before the Helm process can start.
 jq --arg attempt "$attempt" '.status="applying"|.helm_application=$attempt' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
}
restore_fresh_fail() {
 # A restore whose evidence changed outside its recorded writes has one named
 # recovery; its retained operation is never deleted, reset or replayed. $2
 # overrides which fresh restore it names.
 local fresh="${2:-its verified archive with the exact source installer}"
 RECOVERY_HINT="restore of $fresh in another Kubernetes context whose namespace $NAMESPACE is empty; keep operation $OPERATION retained"
 fail "$1; keep operation $OPERATION retained and restore $fresh in another Kubernetes context whose namespace $NAMESPACE is empty"
}
helm_application_validate() {
 local attempt directory current uid revision name kind object latest
 attempt=$(jq -er '.helm_application|select(type=="string" and test("^[a-f0-9]{24}$"))' "$STATE_DIR/operation.json") || fail 'application phase has no durable Helm target; explicit repair is required'
 directory="$STATE_DIR/helm-applications/$OPERATION/$attempt"
 for name in intent.json values.json expected.json; do [[ -f $directory/$name && ! -L $directory/$name ]] || fail 'saved Helm target is incomplete'; done
 jq -e --arg operation "$OPERATION" --arg attempt "$attempt" --arg target "$RELEASE_ID" --arg ns "$NAMESPACE" --arg release "$RELEASE" '.format=="gsj.helm-application/1" and .operation==$operation and .attempt==$attempt and .target==$target and .namespace==$ns and .release==$release' "$directory/intent.json" >/dev/null || fail 'saved Helm target belongs to another operation or release'
 [[ $(sha_file "$GSJ_PAYLOAD/chart.tgz") == $(jq -r .chart_sha256 "$directory/intent.json") && $(sha_file "$directory/values.json") == $(jq -r .values_sha256 "$directory/intent.json") && $(sha_file "$directory/expected.json") == $(jq -r .expected_sha256 "$directory/intent.json") ]] || fail 'saved Helm chart, configuration or target bytes changed'
 cmp -s "$directory/values.json" "$GSJ_WORK/values.pending.json" || fail 'current configuration differs from the Helm operation target'
 [[ $(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid) == $(jq -r .namespace_uid "$directory/intent.json") ]] || fail 'Helm operation namespace was replaced'
 revision=$(jq -er .revision "$directory/intent.json")
 k get secrets -l "owner=helm,name=$RELEASE" -o json > "$GSJ_WORK/helm-history-current.json"
 # A restore's failed or unwritten revision has its own named repair.
 if jq -e '.kind=="restore"' "$STATE_DIR/operation.json" >/dev/null; then
   latest=$(jq -r --argjson revision "$revision" 'if ([.items[].metadata.labels.version|tonumber]|max//0)<$revision then "unwritten" else ([.items[]|select(.metadata.labels.version==($revision|tostring))][0].metadata.labels.status//"") end' "$GSJ_WORK/helm-history-current.json")
   case "$latest" in
     unwritten) RECOVERY_HINT="repair --operation $OPERATION --config $CONFIG --non-interactive"; fail "the restored application Helm revision $revision was never written; use repair --operation $OPERATION";;
     failed) RECOVERY_HINT="repair --operation $OPERATION --config $CONFIG --non-interactive after fixing the cause"; fail "the restored application Helm revision $revision failed; fix its cause, then use repair --operation $OPERATION";;
     pending-*) restore_fresh_fail "the restored application Helm revision $revision is pending (a Helm client stopped mid-write) and has no continuation";;
   esac
 fi
 jq --argjson revision "$revision" -e '([.items[].metadata.labels.version|tonumber]|max)==$revision' "$GSJ_WORK/helm-history-current.json" >/dev/null || fail 'another Helm revision appeared after the saved application intent'
 k get secret "sh.helm.release.v1.$RELEASE.v$revision" -o json > "$GSJ_WORK/helm-current-revision.json"
 jq -e --arg release "$RELEASE" --arg revision "$revision" '.type=="helm.sh/release.v1" and .metadata.labels.owner=="helm" and .metadata.labels.name==$release and .metadata.labels.version==$revision and .metadata.labels.status=="deployed"' "$GSJ_WORK/helm-current-revision.json" >/dev/null || fail 'the target Helm revision has not completed'
 h get values "$RELEASE" --revision "$revision" --output json > "$GSJ_WORK/helm-stored-values.json"
 jq -e --slurpfile expected "$directory/values.json" '.==$expected[0]' "$GSJ_WORK/helm-stored-values.json" >/dev/null || fail 'Helm stored different values from the immutable application target'
 current=$(k get job "$RELEASE-provision" -o json)
 jq -e --slurpfile intent "$directory/intent.json" '(.metadata.uid|type=="string" and length>0) and .metadata.uid!=$intent[0].prior_job_uid and .metadata.deletionTimestamp==null and .status.succeeded==1 and (.status.active//0)==0 and any(.status.conditions[]?; .type=="Complete" and .status=="True")' <<< "$current" >/dev/null || fail 'a fresh completed target provisioning Job is required; an older successful Job cannot resume this application'
 printf '%s\n' "$current" > "$GSJ_WORK/helm-actual.jsonl"
 while IFS=$'\t' read -r kind name; do
   object=$(k get "$kind" "$name" -o json)
   jq -e --arg release "$RELEASE" --arg ns "$NAMESPACE" '.metadata.annotations["meta.helm.sh/release-name"]==$release and .metadata.annotations["meta.helm.sh/release-namespace"]==$ns and .metadata.deletionTimestamp==null' <<< "$object" >/dev/null || fail 'target application resource Helm ownership differs'
   printf '%s\n' "$object" >> "$GSJ_WORK/helm-actual.jsonl"
 done < <(jq -r '.[]|select(.kind!="Job")|[.kind,.name]|@tsv' "$directory/expected.json")
 jq -s '.' "$GSJ_WORK/helm-actual.jsonl" > "$GSJ_WORK/helm-actual.json"
 helm_application_projection "$GSJ_WORK/helm-actual.json" > "$GSJ_WORK/helm-actual-projection.json"
 jq -e --slurpfile expected "$directory/expected.json" '
   def subset($actual;$want):
     if ($want|type)=="object" then ($actual|type)=="object" and all($want|keys[]; . as $k|subset($actual[$k];$want[$k]))
     elif ($want|type)=="array" then ($actual|type)=="array" and ($actual|length)==($want|length) and all(range(0;$want|length); . as $i|subset($actual[$i];$want[$i]))
     else $actual==$want end;
   subset(.;$expected[0]) and ([.[]|select(.kind=="ConfigMap")|.data]==[$expected[0][]|select(.kind=="ConfigMap")|.data])
 ' "$GSJ_WORK/helm-actual-projection.json" >/dev/null || fail 'live target images, initialization generation, commands, environment, mounts or scripts differ from the exact rendered Helm operation'
}
helm_apply() {
 assert_owner
 if [[ ${STARTUP_HELM_CONTINUATION:-false} == true ]]; then
   startup_helm_stage
 else
   if jq -e '.kind=="restore" and .status=="restore-files-verified"' "$STATE_DIR/operation.json" >/dev/null; then
     restore_capacity_qualify
   elif jq -e '.kind=="restore" and .status=="applying"' "$STATE_DIR/operation.json" >/dev/null; then
     # restore_application_evidence proved this operation's passed pre-startup
     # capacity; application controllers now exist, so it is not re-measured.
     :
   else
     if [[ $(jq -r '.backup_round//0' "$STATE_DIR/operation.json") != 0 ]]; then read_backup_source active
     elif jq -e '.startup_source!=null' "$STATE_DIR/operation.json" >/dev/null; then startup_source_select
     else read_installed; fi
     if [[ -s $GSJ_WORK/installed.json ]]; then capacity_qualify reuse; fi
   fi
   stage_operation_config
   helm_application_prepare
 fi
 local timeout; timeout=$(j .deadlines.dependencies_seconds)
 # Helm4 hookOnly lets post-install provisioning run before waiting for the
 # application whose init gate requires the provisioning generation.
 # A restore re-creates the archived chart objects with kubectl create, so that
 # manager owns their fields and Helm4 server-side apply would refuse the next
 # upgrade that changes one. The Lease makes this installer the release's only
 # writer, so Helm takes those fields over, as Helm3 client-side apply did.
 local monitored=false
 [[ $- == *m* ]] && monitored=true
 set -m
 (set +m; trap - EXIT HUP INT TERM
  h upgrade --install "$RELEASE" "$GSJ_PAYLOAD/chart.tgz" --values "$GSJ_WORK/values.pending.json" --timeout="${timeout}s" ${HELM_APPLY_OWNERSHIP[@]+"${HELM_APPLY_OWNERSHIP[@]}"}
 ) > "$STATE_DIR/helm.log" 2>&1 & HELM_PID=$!
 $monitored || set +m
 while kill -0 "$HELM_PID" 2>/dev/null; do
   assert_owner; log 'Helm provisioning in progress'; k get pods -l "app.kubernetes.io/instance=$RELEASE" -o wide; sleep 15
 done
 local result=0; wait "$HELM_PID" || result=$?; HELM_PID=''
 if (( result != 0 )); then
   tail -n 25 "$STATE_DIR/helm.log" >&2
   if jq -e '.kind=="restore"' "$STATE_DIR/operation.json" >/dev/null; then RECOVERY_HINT="repair --operation $OPERATION --config $CONFIG --non-interactive after fixing the cause"; fi
   fail 'Helm provisioning failed; persistent state was retained'
 fi
 helm_application_validate
 jq '.status="initializing"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
}
initializer_failure() {
 # A failed corpus-copy/corpus-initialize leaves one allowlisted
 # code as its termination message. A running retry is still in progress.
 jq -r '[.items[]|select(.metadata.deletionTimestamp==null)|.status.initContainerStatuses[]?|
   select(.name=="corpus-copy" or .name=="corpus-initialize")|
   (if .state.terminated then (if .state.terminated.exitCode!=0 then .state.terminated.message else null end)
    elif .state.waiting then .lastState.terminated.message else null end)//""|
   capture("^gsj-(?<kind>corpus|copy):(?<code>[a-z0-9]+(-[a-z0-9]+)*)\\s*$")|.kind+":"+.code][0]//empty' "$1"
}
initializer_stop() {
 # Terminal codes never clear by waiting; the others retry inside the Pod.
 # The argument is KIND:CODE from initializer_failure, or a bare corpus CODE.
 local repair="repair --operation $OPERATION --config $CONFIG --non-interactive" kind=corpus code=$1 stopped
 if [[ $code == *:* ]]; then kind=${code%%:*}; code=${code#*:}; fi
 # A restore has no corpus repair: its repair refuses once the application
 # Helm revision completed, and resume repeats a terminal code. Its fresh
 # restore keeps the exact source installer, the only one restore admits
 # (restore_archive): a consent code names its site setting, and a blocked
 # embedding model an earlier archive.
 if [[ -f $STATE_DIR/operation.json ]] && jq -e '.kind=="restore"' "$STATE_DIR/operation.json" >/dev/null; then
   stopped="corpus initialization of this restore stopped terminally (gsj-$kind:$code); resume would repeat this code and repair does not re-initialize a restore. Its case data, verified shards and this operation stay retained for inspection"
   case "$code" in
     terminal-budget-exhausted|deadline-exceeded|checkpoint-identity-mismatch|source-verification-failed|released-vectors-missing|manifest-mismatch|core-mismatch|invalid-settings)
       restore_fresh_fail "$stopped";;
     corpus-update-required)
       restore_fresh_fail "$stopped. The restored decision corpus differs from this release and corpus.allow_update is false; the verified archive is its pre-update backup" \
         'its verified archive with the exact source installer, from a recovery site that sets corpus.allow_update=true,';;
     model-change-blocked)
       restore_fresh_fail "$stopped. This archive's decision index does not match its source release's embedding model" \
         "an earlier verified archive of this deployment with that archive's exact source installer";;
   esac
 fi
 if [[ $kind == copy && $code == source-verification-failed ]]; then
   # The copier re-derives a damaged copy from a verified image by itself; this
   # code means the image payload itself failed its signed hashes.
   RECOVERY_HINT="repair --operation $OPERATION --to VERSION with a verified signed release"
   fail "this release's corpus image payload failed its signed verification (the image is damaged or was replaced); repairing the same release cannot fix it. Re-pull from the trusted registry or select a verified signed release"
 fi
 case "$code" in
   terminal-budget-exhausted|deadline-exceeded|checkpoint-identity-mismatch|source-verification-failed)
     RECOVERY_HINT=$repair
     fail "corpus initialization stopped terminally ($code); case data and verified shards are preserved. After this tools process stops, run: gsj-install.sh $repair";;
   released-vectors-missing)
     # The site declared a sidecar (corpus.vectors_url or vectors_path) and
     # the initializer waited its full window for one that never arrived; it
     # refused rather than embed. Every recovery pipeline stages before it waits,
     # so the named repair re-stages from the saved site's declaration.
     RECOVERY_HINT=$repair
     fail "the site declares released vectors but none were staged for the initializer within its wait; it refused rather than embed. Fix the sidecar source named in the saved site (corpus.vectors_url or vectors_path, with vectors_sha256) or clear the declaration, then run: gsj-install.sh $repair";;
   corpus-update-required)
     RECOVERY_HINT="$repair after setting corpus.allow_update=true"
     fail 'the stored decision corpus differs from this release and corpus.allow_update is false. After a verified backup, set corpus.allow_update=true in the saved site, then run the named repair';;
   model-change-blocked)
     RECOVERY_HINT='the previous release installer or restore its verified backup'
     fail 'the stored decision index uses a different embedding model; model replacement is blocked until case and decision index migration is supported';;
   manifest-mismatch|core-mismatch|invalid-settings)
     RECOVERY_HINT="repair --operation $OPERATION --to VERSION with a corrected signed release"
     fail "this release's corpus payload or initializer settings do not match its signed manifest or core ($code); it cannot initialize";;
   *) log "Corpus $kind step reported $code; the Pod retries it until its deadline";;
 esac
}
wait_application() {
 local end=$((SECONDS+$(j .deadlines.initialization_seconds)+1800)) pod state code
 while (( SECONDS < end )); do
   assert_owner
   helm_application_validate
   state=$(k get deploy "$RELEASE-web" -o json)
   if jq -e '.status.observedGeneration >= .metadata.generation and .status.updatedReplicas==1 and .status.availableReplicas==1 and .status.readyReplicas==1' <<< "$state" >/dev/null; then return; fi
   k get pods -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=gsj" -o json > "$GSJ_WORK/application-pods.json"
   pod=$(jq -r '.items[0].metadata.name // empty' "$GSJ_WORK/application-pods.json")
   if [[ -n $pod ]]; then
     jq -c '.items[0]|{pod:.metadata.name,phase:.status.phase,init:[.status.initContainerStatuses[]?|{name,state}],containers:[.status.containerStatuses[]?|{name,ready,state}]}' "$GSJ_WORK/application-pods.json"
     k logs "$pod" -c corpus-initialize --tail=3 2>/dev/null || true
   fi
   code=$(initializer_failure "$GSJ_WORK/application-pods.json")
   [[ -z $code ]] || initializer_stop "$code"
   sleep 20
 done
 fail 'initialization/startup deadline exceeded; checkpoint and operation remain available for resume'
}
public_verify() {
 local url host port ca connect asset
 url=$(j .public_url); url=${url%/}; host=$(printf '%s' "$url" | sed -E 's#https://([^/:]+).*#\1#'); port=$(printf '%s' "$url" | sed -nE 's#https://[^/:]+:([0-9]+).*#\1#p'); port=${port:-443}
 local args=(--silent --show-error --max-time 30) end code
 ca=$(j .verification.ca_file); [[ -z $ca ]] || args+=(--cacert "$(resolve_file "$ca")")
 connect=$(j .verification.connect_host); [[ -z $connect ]] || args+=(--connect-to "$host:$port:$connect:$(j .verification.connect_port)")
 # Readiness is the listener answering, never a dependency, so a Ready
 # Deployment no longer implies /readyz ok: the door's embedding warm-up and
 # the index heartbeat finish after the listener is up. Wait for the strict
 # /readyz, bounded like the other dependency waits, instead of asserting it
 # once (curl --fail on that first 503 used to end the whole operation).
 # A transport failure (no route, DNS, TLS, the wrong CA) is not a warm-up:
 # curl's own exit code names it after three consecutive attempts, so a
 # misconfigured route is not reported as the application never becoming
 # ready after the whole dependency deadline.
 end=$((SECONDS+$(j .deadlines.dependencies_seconds)))
 local rc transport=0
 while :; do
   rc=0; code=$(curl "${args[@]}" -D "$GSJ_WORK/public-headers" -o "$GSJ_WORK/public-ready.json" -w '%{http_code}' "$url/readyz") || rc=$?
   if (( rc != 0 )); then
     code=000; (( ++transport < 3 )) || fail "public HTTPS route is unreachable (curl exit $rc on $transport consecutive attempts): check public_url, DNS, the ingress and verification.ca_file"
   else transport=0; fi
   if [[ $code == 200 ]] && jq -e '.ok==true or .status=="ready" or .status=="ok"' "$GSJ_WORK/public-ready.json" >/dev/null 2>&1; then break; fi
   (( SECONDS < end )) || fail "public HTTPS route did not reach ready application (last HTTP $code)"
   log "public route: application not ready yet (HTTP $code); waiting"; sleep 5
 done
 args+=(--fail)
 curl "${args[@]}" -D "$GSJ_WORK/spa-headers" "$url/" > "$GSJ_WORK/spa.html"
 jq -Rse 'ascii_downcase | contains("content-security-policy:") and contains("default-src '\''none'\''") and contains("x-content-type-options: nosniff")' "$GSJ_WORK/spa-headers" >/dev/null || fail 'public SPA security headers are missing'
 jq -Rse 'test("<div[^>]*id=\"root\"") and test("<script[^>]*type=\"module\"")' "$GSJ_WORK/spa.html" >/dev/null || fail 'public route did not deliver the packaged application'
 jq -Rsr '[scan("(?:src|href)=\"(/assets/[A-Za-z0-9._/-]+)\"")|.[0]]|unique|.[]' "$GSJ_WORK/spa.html" > "$GSJ_WORK/spa-assets"
 [[ -s $GSJ_WORK/spa-assets ]] || fail 'public SPA has no packaged assets'
 while IFS= read -r asset; do
   curl "${args[@]}" "$url$asset" -o "$GSJ_WORK/spa-asset"
   [[ -s $GSJ_WORK/spa-asset ]] || fail 'public SPA asset is empty'
   if [[ $asset == *.js || $asset == *.css ]]; then
     head -c 256 "$GSJ_WORK/spa-asset" | jq -Rse 'ascii_downcase|contains("<!doctype html")|not' >/dev/null || fail 'SPA asset route returned an HTML fallback'
   fi
 done < "$GSJ_WORK/spa-assets"
 jq -n --arg url "$url" --argjson assets "$(wc -l < "$GSJ_WORK/spa-assets")" '{name:"public-https",status:"passed",url:$url,tls_verified:true,spa:true,security_headers:true,assets_verified:$assets}' > "$STATE_DIR/public-check.json"
}
network_verify() {
 local forge pod start elapsed status=0 body='' rc=0 tries=0
 forge=$(k get pods -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=forgejo" -o json | jq -r '.items[]|select(.status.phase=="Running")|.metadata.name')
 # The allowed pair asserts the strict /readyz, which stays dependency-bearing:
 # guarded and briefly retried, so a heartbeat blip right after the
 # public poll passed names this refusal instead of ending the run with
 # wget's bare exit status.
 until body=$(k exec "$forge" -- wget -q -T 5 -O - "http://$RELEASE-web:8780/readyz" 2>/dev/null) && jq -e '.ok==true or .status=="ready" or .status=="ok"' <<< "$body" >/dev/null 2>&1; do
   rc=$?; (( ++tries < 12 )) || fail "NetworkPolicy allowed pair did not reach application readiness (Forgejo -> $RELEASE-web:8780/readyz, exit $rc after $tries attempts)"
   sleep 5
 done
 printf '%s' "$body" > "$GSJ_WORK/network-allow.json"
 start=$SECONDS
 k exec "$forge" -- wget -q -T 5 -O /dev/null "http://$RELEASE-chroma:8000/api/v2/heartbeat" > "$GSJ_WORK/network-deny.log" 2>&1 || status=$?
 elapsed=$((SECONDS-start))
 # Assert REACHABILITY, not elapsed time. Whether a denied
 # path HANGS (a DROP based CNI: Calico, kindnet) or fails at once (a REJECT
 # based one: k3s through kube-router) is the CNI's choice, not the policy's.
 # The old `elapsed >= 4` clause required the hang, so on a reference k3s
 # cluster a correctly enforced and correctly scoped policy failed in 0 ms and
 # took the whole install down at `verifying`. A nonzero status already proves
 # Forgejo did not reach Chroma; deny_seconds stays in the record so the CNI's
 # behaviour is still visible to whoever reads it.
 (( status != 0 )) || fail 'NetworkPolicy deny was not enforced: Forgejo reached Chroma, which the policy must block'
 pod=$(k get pods -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=gsj" -o json | jq -r '.items[]|select(.status.phase=="Running")|.metadata.name')
 k exec "$pod" -c gsj-web -- python -c "import httpx; r=httpx.get('http://$RELEASE-chroma:8000/api/v2/heartbeat'); r.raise_for_status(); assert isinstance(r.json()['nanosecond heartbeat'],int)" >/dev/null
 jq -n --arg source "$forge" --argjson seconds "$elapsed" '{name:"networkpolicy-deny-allow",status:"passed",source:$source,allow:"Forgejo → web readiness",deny:"Forgejo → Chroma blocked",control:"GSJ → Chroma API heartbeat",deny_seconds:$seconds}' > "$STATE_DIR/network-check.json"
}
verification_new_run() {
 local attempts
 attempts=$(jq -r '.verification_attempts//0' "$STATE_DIR/operation.json")
 (( attempts < 3 )) || fail 'verification retry budget exhausted; explicit repair is required'
 run=$(openssl rand -hex 6); remote="/data/verification/$run"
 settings="$STATE_DIR/verification/$run/settings.json"; mkdir -p "$(dirname "$settings")"
 jq --argjson attempts "$((attempts+1))" '.verification_attempts=$attempts' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 jq -n --slurpfile site "$SITE" --slurpfile release "$GSJ_PAYLOAD/release.json" --rawfile password "$OP_PASSWORD" --arg generation "$generation" --arg run "$run" --arg dir "$remote" --arg forge "http://$RELEASE-forgejo:3000" '$site[0] as $s | {web_url:$s.public_url,forge_url:$forge,mcp_url:"http://127.0.0.1:8790/mcp",operator_login:$s.operator.login,operator_password:($password|sub("[\\r\\n]+$";"")),generation:$generation,run_id:$run,report_dir:$dir,lock_dir:"/data/verification-locks",timeout_seconds:$s.deadlines.verification_seconds,expected_upload_mb:$s.limits.upload_mb,expected_corpus_rows:$release[0].corpus.rows,expected_corpus_fingerprint:$release[0].corpus.fingerprint,corpus_state_path:"/data/bootstrap/state/current.json",db_path:"/data/db/gsj.db",mcp_workspace:"/data/cases",connect_host:$s.verification.connect_host,connect_port:$s.verification.connect_port,ca_file:(if $s.verification.ca_file!="" then $dir+"/ca.crt" else "" end)}' | atomic "$settings"
 jq -n --arg run "$run" --arg release "$RELEASE_ID" --arg generation "$generation" --arg operation "$OPERATION" '{format:"gsj.verification-run/1",run_id:$run,release:$release,generation:$generation,operation:$operation,launched:false,status:"active"}' | atomic "$STATE_DIR/verification-active.json"
}
verification_stage_settings() {
 # Terminal recovery reconstructs settings from secret-free original inputs.
 local public="${settings%/*}/public-settings.json"
 if [[ ! -f $public ]]; then
   [[ -f $settings ]] || fail 'verification target recovery inputs are missing'
   jq 'del(.operator_password)' "$settings" | atomic "$public"
 fi
 if [[ ! -f $settings ]]; then cat "$public" | atomic "$settings"; fi
 # Credentials may be validated/repaired between reconnects. Preserve the
 # original target binding; refresh the protected credential and, for the same
 # canonical origin only, the current site's transport-only route (on every
 # command, as the CA below is staged from the current site).
 jq --rawfile password "$OP_PASSWORD" --slurpfile site "$SITE" '.operator_password=($password|sub("[\\r\\n]+$";"")) | if .web_url==$site[0].public_url then .connect_host=$site[0].verification.connect_host | .connect_port=$site[0].verification.connect_port else . end' "$settings" | atomic "$settings"
 k exec -i "$pod" -c gsj-web -- python -c 'import os,pathlib,sys,tempfile; p=pathlib.Path(sys.argv[1]); p.parent.mkdir(mode=0o700,parents=True,exist_ok=True); fd,tmp=tempfile.mkstemp(dir=p.parent); out=os.fdopen(fd,"wb"); out.write(sys.stdin.buffer.read()); out.flush(); os.fsync(out.fileno()); out.close(); os.replace(tmp,p); fd=os.open(p.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)' "$staged" < "$settings"
 if [[ $(j .verification.ca_file) != '' ]]; then k exec -i "$pod" -c gsj-web -- sh -c "umask 077; mkdir -p '$remote' && cat > '$remote/ca.crt'" < "$(resolve_file "$(j .verification.ca_file)")"; fi
}
verification_route_preflight() {
 # public_verify proves the route from the tools container only; the verifier
 # dials it from gsj-web. Prove TCP and one verified TLS handshake there before
 # any launch, with the verifier's own Python and trust: python:3.13's default
 # context is X.509-strict, which the tools-side curl is not. Inline stdlib on
 # purpose: continuation and old-binding passes run older target images whose
 # verifier has no probe (verify.probe_origin). When the Pod's proxy carries the
 # origin (httpx's own decision from that environment), the verifier goes
 # through it and the route fields are inert. A refused handshake prints only
 # OpenSSL's fixed reason or the error class, never the staged settings.
 local rc=0 url route found resume fresh next reason ca_repair='' wait='each needs the operation Lease unrenewed for 180 seconds, so wait 3 minutes before each'
 url=$(jq -r .web_url "$settings")
 route=$(jq -r 'if (.connect_host//"")!="" then "verification route \(.connect_host):\(.connect_port)" else "its public DNS name" end' "$settings")
 reason=$(k exec "$pod" -c gsj-web -- python -c 'import json,socket,ssl,sys,urllib.request
from urllib.parse import urlsplit
c=json.load(open(sys.argv[1])); u=urlsplit(c["web_url"]); tls=ssl.create_default_context(cafile=c.get("ca_file") or None)
if urllib.request.getproxies().get(u.scheme) and not urllib.request.proxy_bypass(u.hostname): sys.exit(0)
try: raw=socket.create_connection((c.get("connect_host") or u.hostname, c.get("connect_port") or u.port or 443), timeout=10)
except OSError: sys.exit(73)
try: tls.wrap_socket(raw, server_hostname=u.hostname).close()
except OSError as e: print(getattr(e,"verify_message",None) or getattr(e,"reason",None) or type(e).__name__); sys.exit(74)' "$staged") || rc=$?
 (( rc != 0 )) || return 0
 if (( rc == 73 )); then found="cannot reach $(url_origin_only "$url") through $route (origin-unreachable); the tools-side public HTTPS check does not prove the Pod path"
 elif (( rc == 74 )); then
   found="reached $(url_origin_only "$url") through $route, but the TLS handshake failed or the certificate did not pass strict verification for its hostname against verification.ca_file, or the system trust store when that is empty (${reason:+$reason; }origin-tls-failed)"
   # tls-repair reissues only the managed CA's signing extensions and keeps the
   # served certificate: name it for those refusals alone, and never again for
   # the CA it produced (a host OpenSSL laxer than the Pod's would loop).
   case $reason in 'CA cert does not include key usage extension'|'Basic Constraints of CA cert not marked critical'|'Missing Subject Key Identifier')
     if [[ $(j .tls.profile) == managed-local-ca && -f $STATE_DIR/tls/ca.crt && $(jq -r '.after_ca_sha256//""' "$STATE_DIR/tls-repair.json" 2>/dev/null) != "$(sha_file "$STATE_DIR/tls/ca.crt")" ]]; then ca_repair="tls-repair --operation $OPERATION"; fi;;
   esac
 else fail "the verification route preflight could not run in the application Pod (exit $rc); no verifier was started"; fi
 # Name only a correction that reaches this run. The current site's route is
 # staged only for a run of its own public_url (verification_stage_settings).
 [[ $url == "$(j .public_url)" ]] || fail "the application Pod $found. This run belongs to an earlier public_url, whose route the current site does not control. No verifier was started"
 # A continued operation is bound to its exact saved site (the restore-program
 # receipt, the startup Helm continuation intent): no command corrects its route.
 # The continuation's own named resume carries no flag, so its saved intent
 # decides here exactly as resume_operation reads it. tls-repair rewrites only
 # the managed CA's bytes, which neither binds (a first-startup control proof
 # that recorded them refuses on the ready-state record before re-deriving
 # them, and record_ready precedes every verifier).
 if [[ ${RESTORE_PROGRAM_ACTIVE:-false} == true || -n ${CONTINUE_HELM_INSTALLER:-} || -e $STATE_DIR/startup-helm-$OPERATION/intent.json || -L $STATE_DIR/startup-helm-$OPERATION/intent.json ]]; then
   resume="resume --operation $OPERATION with the operation's exact target installer"; fresh='install afresh into an empty namespace'
   if [[ ${RESTORE_PROGRAM_ACTIVE:-false} == true ]]; then
     resume="resume --operation $OPERATION with this installer"
     fresh="restore its verified archive with the exact source installer in another Kubernetes context whose namespace $NAMESPACE is empty"
   fi
   next="If the failure was transient, $resume once the route is reachable"
   RECOVERY_HINT="$resume once the route is reachable, if the failure was transient; otherwise keep operation $OPERATION retained and $fresh"
   if [[ -n $ca_repair ]]; then
     next="With the managed local CA, run $ca_repair, which changes no saved configuration, then $resume; $wait"
     RECOVERY_HINT="$ca_repair, then $resume; $wait"
   elif (( rc == 74 )); then
     # Certificate and trust bytes are not saved configuration: resume
     # re-stages the trust file and dials the served certificate again.
     next="No installer command replaces this certificate: correct it in TLS Secret $(j .tls.secret) or the contents of verification.ca_file at their source, keeping the configured paths, then $resume"
     RECOVERY_HINT="$resume once the certificate served for $(url_origin_only "$url") passes strict verification from the Pod; otherwise keep operation $OPERATION retained and $fresh"
   fi
   fail "the application Pod $found. A continued operation keeps its exact saved configuration, so no command corrects its verification route. $next; otherwise keep operation $OPERATION retained and $fresh. No verifier was started"
 fi
 if (( rc == 73 )); then
   RECOVERY_HINT="resume --operation $OPERATION after correcting verification.connect_host/connect_port"
   fail "the application Pod $found. Set verification.connect_host to the node hostname reachable from Pods and verification.connect_port to the ingress NodePort (30443 with the standard mappings; see OPERATOR.md), or leave both empty for public DNS, then resume. No verifier was started"
 fi
 if [[ -n $ca_repair ]]; then
   RECOVERY_HINT="$ca_repair, then resume --operation $OPERATION; $wait"
   fail "the application Pod $found. tls-repair reissues the managed local CA's signing extensions under its existing key, subject and serial, and keeps the served certificate. No verifier was started"
 fi
 RECOVERY_HINT="resume --operation $OPERATION once the certificate served for $(url_origin_only "$url") passes strict verification from the Pod"
 fail "the application Pod $found. No installer command replaces this certificate: correct it in TLS Secret $(j .tls.secret) or the contents of verification.ca_file at their source, keeping the configured paths, or, if the route reaches another endpoint, correct verification.connect_host/connect_port; then resume. No verifier was started"
}
verification_bot_terminal() {
 # Exit 79 means the verifier spent its durable bot-check
 # attempts. A named resume would only repeat the same failure.
 if [[ -f $STATE_DIR/operation.json ]] && jq -e '.kind=="restore"' "$STATE_DIR/operation.json" >/dev/null; then
   # repair refuses a restore whose application Helm revision completed.
   restore_fresh_fail "the bot contract-hook check failed on every bounded attempt (terminal); resume would repeat it and repair does not re-verify a restore. The verification ledger, owned test data and this operation stay retained for inspection"
 fi
 RECOVERY_HINT="repair --operation $OPERATION (with --to VERSION for a corrected signed release)"
 fail 'the bot contract-hook check failed on every bounded attempt (terminal); named resume cannot pass. The verification ledger and owned test data are retained for the repair to clean up'
}
verification_bot_step() {
 local result="$STATE_DIR/verification/$run/bot-result.json" bot="$STATE_DIR/verification/$run/bot-settings.json"
 k exec "$pod" -c gsj-web -- cat "$remote/ledger.json" | jq --arg forge "http://$RELEASE-forgejo:3000" '. as $ledger | .cases[0] as $case | {generation,run_id,forge_url:$forge,lock_dir:"/data/verification-locks",case_id:$case.id,owner:$case.owner,owner_id:([$ledger.users[]|select(.login==$case.owner)][0].id)}' | atomic "$bot"
 k exec -i "$pod" -c agent-runner -- sh -c "umask 077; cat > '/tmp/gsj-bot-$run.json'" < "$bot"
 rc=0; k exec "$pod" -c agent-runner -- python -m gsj_deploy.verify --bot-negative "/tmp/gsj-bot-$run.json" > "$result.pending" || rc=$?
 (( rc != 78 )) || fail 'another verifier or bot owns the shared lock; no cleanup was launched'
 (( rc != 79 )) || verification_bot_terminal
 (( rc == 0 )) || fail 'bot verification is unresolved; use named resume'
 cat "$result.pending" | atomic "$result"; rm "$result.pending"
 k exec -i "$pod" -c gsj-web -- sh -c "umask 077; cat > '$remote/bot-result.json'" < "$result"
 rc=0; k exec "$pod" -c gsj-web -- python -m gsj_deploy.verify --finish --settings "$staged" --bot-result "$remote/bot-result.json" || rc=$?
 k exec "$pod" -c agent-runner -- rm -f "/tmp/gsj-bot-$run.json"
 rm -f "$bot"
}
verify_application() {
 assert_owner
 local pod run generation remote staged settings rc existing old_binding mode control nsuid active="$STATE_DIR/verification-active.json"
 pod=$(k get pods -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=gsj" -o json | jq -er '[.items[]|select(.status.phase=="Running")]|if length==1 then .[0].metadata.name else error("one application pod required") end')
 generation=$(k get cm "$RELEASE-provisioned" -o json | jq -er .data.generation)
 jq '.status="verifying"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 public_verify; network_verify
 while true; do
   old_binding=false
   if [[ -f $active ]] && jq -e '.status|IN("active","complete","cleaned")' "$active" >/dev/null; then
     jq -e '.format=="gsj.verification-run/1" and (.run_id|test("^[a-f0-9]{12}$"))' "$active" >/dev/null || fail 'invalid saved verification run'
     run=$(jq -r .run_id "$active"); remote="/data/verification/$run"; settings="$STATE_DIR/verification/$run/settings.json"
     [[ -f $settings || -f ${settings%/*}/public-settings.json ]] || fail 'verification target recovery inputs are missing'
     if [[ $(jq -r .release "$active") != "$RELEASE_ID" || $(jq -r .generation "$active") != "$generation" || $(jq -r .operation "$active") != "$OPERATION" || $(jq -r .status "$active") == cleaned ]]; then old_binding=true; fi
   else
     verification_new_run
   fi
   # The operator password stays on the container filesystem, never the data volume.
   staged="/tmp/gsj-verification/$run/settings.json"
   verification_stage_settings
   existing=$(k exec "$pod" -c gsj-web -- python -c 'import json,pathlib,sys; print(json.dumps((pathlib.Path(sys.argv[1])/"ledger.json").is_file()))' "$remote") || fail 'cannot inspect the persistent verification ledger'
   mode=''
   if [[ $existing == true ]]; then
     if $old_binding && [[ $(jq -r .status "$active") == active ]]; then mode=--cleanup; else mode=--resume; fi
   elif [[ $existing != false || $(jq -r .launched "$active") != false ]]; then
     fail 'verification ownership ledger is missing after launch; preserve receipts and reconcile explicitly'
   elif $old_binding; then
     # launched=true is written durably before every verifier exec (below), so an
     # unlaunched run created nothing. One rule for it: under its own binding (a
     # resume after a preflight refusal) it is reused and charges nothing; once
     # its binding changed (repair, repair --to and startup continuations
     # re-apply Helm) it is retired here, and the next pass starts this
     # binding's run, charged one attempt against the current budget.
     k exec "$pod" -c gsj-web -- rm -f "$staged"; rm -f "$settings"
     jq '.status="retired"' "$active" | atomic "$active"
     log "Prior verification run $run was never launched; retired without cleanup, and this binding's fresh run counts as one verification attempt"; continue
   fi
   # Complete/cleaned re-entries make no network calls; only an active run dials the origin.
   [[ $(jq -r .status "$active") != active ]] || verification_route_preflight
   jq '.launched=true' "$active" | atomic "$active"
   rc=0
   if [[ -n $mode ]]; then k exec "$pod" -c gsj-web -- python -m gsj_deploy.verify "$mode" --settings "$staged" || rc=$?;
   else k exec "$pod" -c gsj-web -- python -m gsj_deploy.verify --settings "$staged" || rc=$?; fi
   if (( rc == 76 )); then verification_bot_step; fi
   (( rc != 79 )) || verification_bot_terminal
   if (( rc == 75 || rc == 0 || rc == 77 )); then
     # This helper is entered only from a freshly locked/sealed handoff. Busy
     # or unresolved commands never authorize an A-owned account cleanup Job.
     # Terminal results permit only retirement of recorded control resources.
     rc=0; verification_account_cleanup "$pod" "$run" "$remote" "$(jq -r .generation "$settings")" || rc=$?
   fi
   (( rc != 78 )) || fail 'verification is busy; no stale cleanup handoff was used'
   if (( rc == 80 )); then
     # The round's three durable attempts are spent.
     # Named resume re-enters the same ladder and hits the same wall, so name the
     # command that actually reopens it - repair exports GSJ_CLEANUP_NEW_ROUND,
     # which lets the helper retire the spent round and run three fresh attempts.
     RECOVERY_HINT="repair --operation $OPERATION"
     fail "the durable account-cleanup attempts of verification round $run are spent; named resume would only repeat them. Fix the cause the cleanup Job reported, then run repair --operation $OPERATION to open a new bounded cleanup round (three rounds in all)"
   fi
   if (( rc == 0 || rc == 77 )); then
     control="$STATE_DIR/verification-cleanup-$run/control-report.json"
     nsuid=$(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid)
     jq -e --arg run "$run" --arg uid "$nsuid" '.format=="gsj.verification-control-cleanup/1" and .run_id==$run and .namespace_uid==$uid and .status=="clean"' "$control" >/dev/null || fail 'verification control resource cleanup is unproven'
     k exec "$pod" -c gsj-web -- cat "$remote/report.json" | jq --slurpfile control "$control" --arg run "$run" 'if .run_id==$run then .+{control_cleanup:$control[0]} else error("verification report identity differs") end' | atomic "$STATE_DIR/verification/$run/report.json"
     # Persist terminal proof before deleting protected inputs. A reconnect can
     # reconstruct only those inputs from the original public binding and the
     # current operator credential, then revalidate the sealed remote ledger.
     jq --arg status "$(if (( rc == 0 )); then printf complete; else printf cleaned; fi)" --arg report_sha "$(sha_file "$STATE_DIR/verification/$run/report.json")" --arg control_sha "$(sha_file "$control")" '.status=$status|.report_sha256=$report_sha|.control_sha256=$control_sha' "$active" | atomic "$active"
     k exec "$pod" -c gsj-web -- rm -f "$staged"
     rm -f "$settings"
     if $old_binding; then
       jq '.status="retired"' "$active" | atomic "$active"
       log "Prior verification run $run cleaned under its original identity; starting target-release acceptance"; continue
     fi
     (( rc == 0 )) || fail 'required verification was interrupted or failed; owned resources are clean. Use named resume for a fresh bounded attempt'
     cat "$STATE_DIR/verification/$run/report.json" | atomic "$STATE_DIR/verification.json"
     return
   fi
   fail "verification remains unresolved (exit $rc); retain its ledger and use named resume"
 done
}
record_ready() {
 storage_identity > "$GSJ_WORK/storage.json"
 jq -n --slurpfile manifest "$GSJ_PAYLOAD/release.json" --slurpfile site "$SITE" --slurpfile storage "$GSJ_WORK/storage.json" --arg nsuid "$(k get namespace "$NAMESPACE" -o json | jq -r .metadata.uid)" '{format:"gsj.installed/1",manifest:$manifest[0],site:$site[0],storage:$storage[0],namespace_uid:$nsuid,status:"verification-pending"}' > "$STATE_DIR/ready.json"
 k create configmap "$RELEASE-ready-state" --from-file="installed.json=$STATE_DIR/ready.json" --dry-run=client -o json | jq --arg owner "$RELEASE" '.metadata.labels={"gsj.io/owner":$owner}' | k apply -f - >/dev/null
}

record_installed() {
 assert_owner
 storage_identity > "$GSJ_WORK/storage.json"
 jq -n --slurpfile manifest "$GSJ_PAYLOAD/release.json" --slurpfile site "$SITE" --slurpfile storage "$GSJ_WORK/storage.json" --slurpfile verification "$STATE_DIR/verification.json" --slurpfile public "$STATE_DIR/public-check.json" --slurpfile network "$STATE_DIR/network-check.json" --arg operation "$OPERATION" --arg nsuid "$(k get namespace "$NAMESPACE" -o json | jq -r .metadata.uid)" '{format:"gsj.installed/1",manifest:$manifest[0],site:$site[0],storage:$storage[0],namespace_uid:$nsuid,operation:$operation,verification:{application:$verification[0],public:$public[0],network:$network[0]},status:"complete"}' | atomic "$GSJ_WORK/installed.json"
 k create configmap "$RELEASE-installed" --from-file="installed.json=$GSJ_WORK/installed.json" --dry-run=client -o json | jq --arg owner "$RELEASE" '.metadata.labels={"gsj.io/owner":$owner}' | k apply -f - >/dev/null
 cat "$GSJ_WORK/installed.json" | atomic "$STATE_DIR/installed.json"
 cp "$SITE" "$STATE_DIR/site.json"; cp "$GSJ_WORK/values.pending.json" "$STATE_DIR/values.json"
 jq '.status="complete"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 if [[ $(jq -r '.kind//""' "$STATE_DIR/operation.json") == restore && -f $STATE_DIR/restoration.json ]]; then
   jq '.status="complete"' "$STATE_DIR/restoration.json" | atomic "$STATE_DIR/restoration.json"
 fi
 installation_summary
}
installation_summary() {
 # The install summary: URL, operator login, redacted settings, identities,
 # corpus status, verification results and where the full records live.
 local summary="$STATE_DIR/summary.json"
 # Every URL the summary keeps or prints -- the site's six URL fields
 # (public_url, llm.base_url, ocr.url, corpus.vectors_url,
 # backup.offbox_url, tls.acme_server; llm.allowed_origins are origins by
 # schema) -- goes through url_origin_only, the one function: the origin,
 # never a path, query or userinfo (a path segment is schema-valid and can
 # carry a credential). The full values stay in site.json beside it
 # [review B2].
 jq -n --slurpfile site "$SITE" --slurpfile release "$GSJ_PAYLOAD/release.json" --slurpfile verification "$STATE_DIR/verification.json" --slurpfile public "$STATE_DIR/public-check.json" --slurpfile network "$STATE_DIR/network-check.json" --arg chart "$(sha_file "$GSJ_PAYLOAD/chart.tgz")" --arg operation "$OPERATION" --arg record "$STATE_DIR/installed.json" --arg report "$STATE_DIR/verification.json" \
   --arg public_url "$(url_origin_only "$(j '.public_url // ""')")" --arg llm_url "$(url_origin_only "$(j '.llm.base_url // ""')")" --arg ocr_url "$(url_origin_only "$(j '.ocr.url // ""')")" --arg vectors_url "$(url_origin_only "$(j '.corpus.vectors_url // ""')")" --arg offbox_url "$(url_origin_only "$(j '.backup.offbox_url // ""')")" --arg acme_server "$(url_origin_only "$(j '.tls.acme_server // ""')")" '
   $site[0] as $s | $release[0] as $r | $verification[0] as $v |
   {format:"gsj.install-summary/1",status:"complete",operation:$operation,public_url:$public_url,operator_login:$s.operator.login,
    release:{identity:$r.identity,version:$r.version},
    fingerprints:{chart_sha256:$chart,core:$r.core,model:$r.model,corpus:$r.corpus.fingerprint,corpus_manifest_sha256:$r.corpus.manifest_sha256},
    corpus:{rows:$r.corpus.rows,vectors:$r.corpus.chunks,status:(if any($v.checks[]?;.name=="mcp-tools-corpus-schema" and .status=="passed") then "verified" else "unverified" end)},
    verification:({status:$v.status,coverage:(if ([$v.checks[]?|select(.status=="skipped")]|length)>0 then "partial" else "full" end),
                  checks_passed:([$v.checks[]?|select(.status=="passed")]|length),checks_skipped:([$v.checks[]?|select(.status=="skipped")]|length),checks:($v.checks//[]|length),
                  skipped:[$v.checks[]?|select(.status=="skipped")|{name,reason}],endpoints:($v.endpoints//{}),
                  public_https:$public[0].status,networkpolicy:$network[0].status}
                 + (if $v.ocr_http_status != null then {ocr_http_status:$v.ocr_http_status} else {} end)),
    settings:(reduce (["operator","password_file"],["llm","credential","file"],["ocr","credential","file"],["registry","config_file"],["tls","private_key_file"],["trust","proxy_file"],["backup","passphrase_file"],["backup","auth_header_file"],["delivery","auth_header_file"]) as $p
      ($s; if (getpath($p)//"")!="" then setpath($p;"(protected file)") else . end)
      | reduce ([["public_url"],$public_url],[["llm","base_url"],$llm_url],[["ocr","url"],$ocr_url],[["corpus","vectors_url"],$vectors_url],[["backup","offbox_url"],$offbox_url],[["tls","acme_server"],$acme_server]) as $u
      (.; if (getpath($u[0])//"")!="" then setpath($u[0];$u[1]) else . end)),
    installed_record:$record,verification_report:$report}' | atomic "$summary"
 cat "$summary"
 if [[ $(jq -r .verification.coverage "$summary") == partial ]]; then
   # A partial verification must be unmistakable, on screen as in the record:
   # the word, the counts, every skipped check with its reason, and what stayed
   # unexercised -- said per REASON the probe recorded (never "the agent cannot
   # answer": a gateway without /models answers turns, and a per-case LLM may
   # serve; what is established is which checks stayed skipped). An endpoint that
   # is configured but did not answer, refused the request or could not read
   # the test page must not be met with "set it": the operator would edit a
   # site value that was right.
   log "GSJ installation complete, verification PARTIAL: $VERSION at $(url_origin_only "$(j .public_url)"). $(jq -r '"\(.verification.checks_passed) of \(.verification.checks) application checks ran and passed; \(.verification.checks_skipped) skipped: " + ([.verification.skipped[]|"\(.name) (\(.reason))"]|join(", "))' "$summary"). $(jq -r '(.verification.skipped|map(.reason)|unique) as $r
     | ([$r[]|select(startswith("llm-"))]|first // "") as $llm
     | ([$r[]|select(startswith("ocr-"))]|first // "") as $ocr
     | ([ (if $llm == "llm-absent" then "Until an LLM endpoint is set, the two agent checks stay skipped (the site sets no LLM endpoint): set llm.base_url and llm.model in the site file (an LLM chosen per case under Einstellungen serves that case, but the acceptance probes only the site endpoint)"
           elif $llm == "llm-no-model-list" then "Until the LLM endpoint at llm.base_url answers the acceptance probe with a model list, the two agent checks stay skipped: it is configured, but no model list came back (the endpoint was unreachable from the Pods, refused the request, or is not an OpenAI-compatible root), so check that it is up and reachable from the Pods, that its credential is right and that llm.base_url is the OpenAI root ending in /v1"
           elif $llm != "" then "Until the LLM endpoint answers, the two agent checks stay skipped (" + $llm + ")" else empty end),
          (if $ocr == "ocr-absent" then "Until an OCR endpoint is set, the scanned-page check stays skipped and scanned pages cannot be read: set ocr.url and ocr.model in the site file"
           elif $ocr == "ocr-unreachable" then "Until the OCR endpoint at ocr.url gives an HTTP answer to the acceptance probe, the scanned-page check stays skipped: it is configured, but no HTTP answer came back from the Pods, so check that it is up and reachable from the Pods (the address, a proxy, TLS)"
           elif $ocr == "ocr-not-a-chat-completion" then "Until the OCR endpoint at ocr.url answers the acceptance probe with a chat completion, the scanned-page check stays skipped: it answered HTTP 200 with a body that is not a chat completion, so check that ocr.url is the complete chat-completions route"
           elif $ocr == "ocr-refused" then ((.verification.ocr_http_status // 0) as $h | "Until the OCR endpoint at ocr.url accepts the recognition request, the scanned-page check stays skipped: it answered HTTP " + (if $h == 0 then "?" else ($h|tostring) end) + " to the acceptance probe" + (if $h == 401 or $h == 403 then ", so check its credential (ocr.credential)" elif $h == 404 then ", so check that ocr.url is the complete chat-completions route and that ocr.model names a model the endpoint serves (a missing model answers 404 too)" elif $h == 400 or $h == 422 or $h == 415 then ", so check ocr.model and that the endpoint takes an image" elif $h == 500 then ", so the endpoint failed on the request: a text-only model answers 500 to an image (replace ocr.url and ocr.model with a vision-capable endpoint), or the server itself is failing" elif $h >= 502 and $h <= 504 then ", so a gateway or the server reported it could not serve the request (a busy or starting server): try again, then check that the model is up" elif $h >= 500 then ", so the server answered an error: check the endpoint itself" elif $h == 429 then ", so it is rate-limited: try again later" else ", so check ocr.url, ocr.model and its credential" end))
           elif $ocr == "ocr-no-page-text" then "Until ocr.url names an endpoint that reads images, the scanned-page check stays skipped: the configured one answered the acceptance probe without the text of the test page, so scanned pages would be stored as whatever it answers (a model that does not read images earns this, and so does one that paraphrased the page); replace ocr.url and ocr.model with a vision-capable endpoint"
           elif $ocr != "" then "Until the OCR endpoint reads images, the scanned-page check stays skipped (" + $ocr + ")" else empty end) ]
        | join(". ")) + ". Then run install again with the site file: the acceptance then exercises what answers."' "$summary") Summary: $summary"
 else
   log "Complete GSJ installation verified: $VERSION at $(url_origin_only "$(j .public_url)"). Summary: $summary"
 fi
}
verify_target() {
 local descriptor=$1 signature=$2 installer=$3 requested=$4
 openssl dgst -sha256 -verify "$GSJ_PAYLOAD/trust/release.pem" -signature "$signature" "$descriptor" >/dev/null 2>&1 || fail 'target release signature is invalid'
 jq -e --arg version "$requested" --arg trust "$(sha_file "$GSJ_PAYLOAD/trust/release.pem")" '.schema=="gsj.installer-descriptor/1" and .signature=="RSA-SHA256" and .version==$version and .trustKeySha256==$trust and (.installer.sha256|test("^[a-f0-9]{64}$")) and (.installer.bytes|type=="number")' "$descriptor" >/dev/null || fail 'signed release descriptor does not match requested target/trust root'
 [[ $(sha_file "$installer") == $(jq -r .installer.sha256 "$descriptor") ]] || fail 'target installer integrity failed'
 [[ $(wc -c < "$installer" | tr -d ' ') == $(jq -r .installer.bytes "$descriptor") ]] || fail 'target installer length differs from signed descriptor'
}
acquire_target() {
 local version=$1 base descriptor signature target
 [[ $version =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || fail 'invalid target version'
 # Say what the empty endpoint MEANS. A qualification build
 # carries release_base_url:"" by design, and every --to path (upgrade --to,
 # repair --to, and the corrected-release recoveries the reason-code table
 # names) resolves through here -- so an operator holding such a build must be
 # told that the option itself is unavailable to them, not merely that a URL
 # is missing. Measured on a reference cluster: 6 s, rc=1.
 base=$(jq -r '.release_base_url // empty' "$GSJ_PAYLOAD/release.json"); [[ $base == https://* ]] || fail "this release carries no HTTPS release directory (release_base_url is empty), so it cannot fetch another version: every --to option is unavailable with this executable. That is how a qualification build is packaged. To move to $version, obtain that release's own signed installer through the channel your release notes name and run IT directly; for a corpus or settings problem, the plain 'repair --operation ID --config site.json' reapplies THIS release and does not need a distribution endpoint"
 descriptor="$STATE_DIR/target-$version.json"; signature="$STATE_DIR/target-$version.sig"; target="$STATE_DIR/target-$version.sh"
 download_curl --fail --silent --show-error --location --proto '=https' --max-time 120 "$base/$version/installer-descriptor.json" -o "$descriptor.partial"
 download_curl --fail --silent --show-error --location --proto '=https' --max-time 120 "$base/$version/installer-descriptor.sig" -o "$signature.partial"
 openssl dgst -sha256 -verify "$GSJ_PAYLOAD/trust/release.pem" -signature "$signature.partial" "$descriptor.partial" >/dev/null 2>&1 || fail 'target release signature is invalid; no code executed'
 jq -e --arg version "$version" '.version==$version and .installer.name=="gsj-install.sh"' "$descriptor.partial" >/dev/null || fail 'signed descriptor is for a different release'
 fetch "$base/$version/gsj-install.sh" "$target" "$(jq -r .installer.sha256 "$descriptor.partial")"
 verify_target "$descriptor.partial" "$signature.partial" "$target" "$version"
 mv "$descriptor.partial" "$descriptor"; mv "$signature.partial" "$signature"
 local next=("$COMMAND" --config "$CONFIG" --expected-version "$version")
 if [[ $COMMAND == repair ]]; then
   next+=(--operation "$RESUME_ID")
   [[ -z ${BACKUP_ROUND:-} ]] || next+=(--backup-round "$BACKUP_ROUND")
   [[ -z ${SOURCE_INSTALLER:-} ]] || next+=(--source-installer "$SOURCE_INSTALLER")
   [[ -z ${CONTINUE_HELM_INSTALLER:-} ]] || next+=(--continue-helm-installer "$CONTINUE_HELM_INSTALLER")
   [[ -z ${CONTINUE_FROM_PROGRAM:-} ]] || next+=(--continue-from-program "$CONTINUE_FROM_PROGRAM")
 fi
 if $INTERACTIVE; then next+=(--interactive); else next+=(--non-interactive); fi
 log "Verified target $version; executing that release's installer"
 bash "$target" "${next[@]}"
}
resume_operation() {
 local current holder age phase record="$STATE_DIR/operation.json" recovering_intent=false
 [[ -n $RESUME_ID ]] || fail 'resume requires --operation ID'
 current=$(lease_read); holder=$(jq -r '.spec.holderIdentity // ""' <<< "$current")
 [[ $holder == "$RESUME_ID" ]] || fail 'resume identity differs from the persistent operation owner'
 age=$(jq -r 'now - (.spec.renewTime | sub("\\.[0-9]+Z$";"Z") | fromdateiso8601) | floor' <<< "$current")
 (( age >= 180 )) || lease_still_live 'the prior installer lease' "$age"
 if [[ ! -f $record || $(jq -r .operation "$record") != "$RESUME_ID" ]]; then
   recover_operation_intent "$RESUME_ID" validate
   record="$GSJ_WORK/recovered-operation.json"; recovering_intent=true
 fi
 phase=$(jq -r .status "$record")
 # Before application startup only restore-repair re-proves a corrected
 # program's receipt, Helm ancestry and restored bytes (restore_program_validate).
 [[ ${RESTORE_PROGRAM_ACTIVE:-false} != true || $phase =~ ^(applying|initializing|verifying|complete)$ ]] || fail "this restore is continued by its corrected program with restore-repair --operation $RESUME_ID until application startup"
 if [[ $phase == repair-prepared ]]; then COMMAND=repair; repair_operation; return; fi
 [[ $(jq -r .target "$record") == "$RELEASE_ID" ]] || fail 'resume must use the exact target release installer'
 if [[ $(jq -r .kind "$record") == restore && $phase == owned ]]; then
   COMMAND=restore-repair; restore_archive; return
 fi
 OPERATION=$RESUME_ID
 jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
 LEASE_ACQUIRED=true
 if $recovering_intent; then
   LEASE_RESOURCE_VERSION=$(lease_read | jq -er .metadata.resourceVersion)
   recover_operation_intent "$RESUME_ID" promote
 fi
 rm -f "$STATE_DIR/lease-lost"; start_renewal
 if ! retained_site_matches "$SITE" "$STATE_DIR/site.pending.json"; then
   # Only a verifying operation (the one phase the route preflight stops in) may
   # correct its transport-only verification route: compile.jq never reads it,
   # and URL, Host, SNI and verification.ca_file stay pinned by the unchanged
   # comparison below. Every other phase and key stays byte-exact.
   [[ $phase == verifying ]] || fail 'resume configuration changed; use an explicit repair after reviewing the saved operation'
   # A startup Helm continuation's intent binds these exact site bytes.
   [[ ! -e $STATE_DIR/startup-helm-$RESUME_ID/intent.json && ! -L $STATE_DIR/startup-helm-$RESUME_ID/intent.json ]] || fail 'a continued operation keeps its exact saved configuration, including its verification route; resume it with that saved site'
   jq --slurpfile o "$STATE_DIR/site.pending.json" '.verification.connect_host=$o[0].verification.connect_host | .verification.connect_port=$o[0].verification.connect_port' "$SITE" > "$GSJ_WORK/site.retained-route.json"
   retained_site_matches "$GSJ_WORK/site.retained-route.json" "$STATE_DIR/site.pending.json" || fail 'resume configuration changed; use an explicit repair after reviewing the saved operation'
   local route='.verification|if .connect_host=="" then "public DNS" else "\(.connect_host):\(.connect_port)" end'
   log "Verification route corrected for resume: $(jq -r "$route" "$STATE_DIR/site.pending.json") -> $(j "$route")"
   assert_owner
   jq --slurpfile s "$SITE" '.verification.connect_host=$s[0].verification.connect_host | .verification.connect_port=$s[0].verification.connect_port' "$STATE_DIR/site.pending.json" | atomic "$STATE_DIR/site.pending.json"
 fi
 if [[ $(jq -r '.kind//""' "$STATE_DIR/operation.json") == backup ]]; then
   if [[ $(jq -r '.backup_round//0' "$STATE_DIR/operation.json") != 0 ]]; then read_backup_source active
   else read_installed; fi
   case "$phase" in
     owned|backup-verified) backup; restart_backup_source;;
     backup-restarting) verified_backup_reuse "$(backup_archive)" "$(quiescence_snapshot)"; restart_backup_source;;
     backup-complete) log 'Backup operation is already complete';;
     *) fail "backup stopped in unsupported phase $phase; its original recovery point is preserved";;
   esac
   return
 fi
 case "$phase" in
 owned)
   [[ $(jq -r .kind "$STATE_DIR/operation.json") == install || $(jq -r .kind "$STATE_DIR/operation.json") == upgrade ]] || fail 'owned phase does not belong to an application installation'
   # An owned install has not applied yet (applying is set before Helm runs),
   # so any Helm history of the target name is foreign: the install refusal
   # holds here too — an install interrupted between its Lease and its
   # apply is continued by resume, and the refusal itself points there.
   refuse_foreign_release "$(jq -r .kind "$STATE_DIR/operation.json")"
   compatibility
   if [[ $(jq -r .kind "$STATE_DIR/operation.json") == upgrade ]]; then
     [[ -s $GSJ_WORK/installed.json ]] && jq -e '.status=="complete"' "$GSJ_WORK/installed.json" >/dev/null || fail 'resumed upgrade requires its completed source release'
   fi
   relocated_images_probe
   if [[ -s $GSJ_WORK/installed.json ]]; then backup; fi
   # A declared sidecar must be there for every (re)initialization, so every
   # pipeline that applies stages before it waits; staging is idempotent and a
   # no-op without a declaration (see the install pipeline).
   secret_inputs; managed_dependencies; storage_probe; helm_apply; stage_vectors; wait_application;;
 restore-files-verified)
   [[ $(jq -r .kind "$STATE_DIR/operation.json") == restore ]] || fail 'file-restore phase is not owned by a restore operation'
   restore_finish_pod; secret_inputs; relocated_images_probe; helm_apply; stage_vectors; wait_application;;
 restoring-resources|restoring-files) fail 'restore stopped before file verification; use restore-repair --operation ID with the exact saved target';;
 initializing) stage_vectors; wait_application;;
 verifying) wait_application;;
 applying)
   # A previous release may still be available if the client stopped before
   # launching Helm. The immutable target and a fresh Job must match first.
   helm_application_validate; stage_vectors; wait_application;;
 backup-verified) secret_inputs; relocated_images_probe; managed_dependencies; helm_apply; stage_vectors; wait_application;;
 complete) log 'Operation is already complete'; return;;
 *) fail "operation stopped in $phase; inspect saved state before explicit repair";;
 esac
 record_ready; verify_application; record_installed
}
# GSJ_RUNTIME_HELPER: startup-source-proof.py
# GSJ_RUNTIME_HELPER: startup-runtime-preflight.py
read_repair_backup_source() {
 if [[ -n ${BACKUP_ROUND:-} ]]; then read_backup_source current
 elif [[ $(jq -r '.backup_round//0' "$STATE_DIR/operation.json") != 0 ]]; then read_backup_source active
 else
   read_installed
   if [[ ! -s $GSJ_WORK/installed.json ]] && { [[ -n ${SOURCE_INSTALLER:-} ]] || jq -e '.startup_source!=null' "$STATE_DIR/operation.json" >/dev/null; }; then startup_source_select; fi
 fi
}
prepare_repair_backup() {
 assert_owner
 local prior=$1 source previous file pod
 source=$(jq -r .manifest.identity "$GSJ_WORK/installed.json")
 if jq -e '.repair_backup!=null' "$STATE_DIR/operation.json" >/dev/null; then
   jq -e --arg prior "$prior" --arg source "$source" --arg site "$(sha_file "$SITE")" '.repair_backup.prior_target==$prior and .repair_backup.source==$source and .repair_backup.site_sha256==$site' "$STATE_DIR/operation.json" >/dev/null || fail 'repair backup belongs to a different saved source/target transition or configuration'
   previous=$(jq -er .repair_backup.installer "$STATE_DIR/operation.json")
   [[ $previous != "$RELEASE_ID" ]] || return 0
   jq -e --arg previous "$previous" '.supported_sources|index($previous)' "$GSJ_PAYLOAD/release.json" >/dev/null || fail 'replacement repair installer does not declare the prior repair program'
   jq -e '.status=="repair-backing-up" and (.backup_round//0)==0 and (.backup_generation//0)==0' "$STATE_DIR/operation.json" >/dev/null || fail 'replacement repair program requires an unchanged pre-backup operation'
   # A corrected signed installer may replace a failed capacity precheck.
   # Once quiescence or any archive has started, the original recovery record
   # is authoritative and this narrower transition is no longer available.
   for file in "$STATE_DIR/quiescence-$OPERATION"* "$STATE_DIR/backup-round-$OPERATION-"* "$STATE_DIR/backup-generation-$OPERATION"* "$BACKUP_DIR/$OPERATION"*; do
     [[ ! -e $file && ! -L $file ]] || fail 'backup or quiescence has started; preserve and resume its recorded recovery program'
   done
   pod=$(k get pod "$(backup_pod_name)" -o json --ignore-not-found)
   [[ -z $pod ]] || fail 'a maintenance writer exists; the repair program cannot be replaced'
   cp "$GSJ_WORK/installed.json" "$GSJ_WORK/repair-backup-selected.json"
   read_backup_source current
   jq -e --slurpfile selected "$GSJ_WORK/repair-backup-selected.json" '.==$selected[0]' "$GSJ_WORK/installed.json" >/dev/null || fail 'actual source differs from the selected pre-backup repair context'
   k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json | jq -e '
     (.items|length)==3 and all(.items[];.spec.replicas==1 and .status.observedGeneration==.metadata.generation and .status.readyReplicas==1 and .status.availableReplicas==1)
   ' >/dev/null || fail 'source writers are no longer in the original ready state'
   jq --arg installer "$RELEASE_ID" '.repair_backup_history=((.repair_backup_history//[])+[.repair_backup+{status:"superseded-before-backup",replacement_installer:$installer}])|.repair_backup.installer=$installer' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
   log 'Replaced the failed pre-backup repair program; original source and prior intent are preserved'
 else
   jq --arg installer "$RELEASE_ID" --arg prior "$prior" --arg source "$source" --arg site "$(sha_file "$SITE")" '.repair_backup={installer:$installer,prior_target:$prior,source:$source,site_sha256:$site,prior_status:.status}' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 fi
}
prepare_repair_transition() {
 assert_owner
 local source=$1 intent uid
 jq -e '.corpus.repair_generation<2147483647' "$SITE" >/dev/null || fail 'corpus repair generation is exhausted'
 jq '.corpus.repair_generation += 1' "$SITE" > "$GSJ_WORK/repair-site.json"
 jq --slurpfile release "$GSJ_PAYLOAD/release.json" -f "$GSJ_PAYLOAD/compile.jq" "$GSJ_WORK/repair-site.json" > "$GSJ_WORK/repair-values.json"
 uid=$(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid)
 intent="repair-transition-$OPERATION-$(sha_file "$GSJ_WORK/repair-site.json")-$(sha_file "$GSJ_PAYLOAD/release.json").json"
 jq -n --arg operation "$OPERATION" --arg source "$source" --arg target "$RELEASE_ID" --arg uid "$uid" --arg release "$(sha_file "$GSJ_PAYLOAD/release.json")" --slurpfile before "$SITE" --slurpfile after "$GSJ_WORK/repair-site.json" --slurpfile values "$GSJ_WORK/repair-values.json" --slurpfile saved "$STATE_DIR/site.pending.json" --slurpfile prior_values "$STATE_DIR/values.pending.json" '{format:"gsj.repair-transition/1",operation:$operation,source:$source,target:$target,namespace_uid:$uid,release_sha256:$release,site_before:$before[0],site_after:$after[0],values_after:$values[0],saved_site:$saved[0],saved_values:$prior_values[0]}' > "$GSJ_WORK/repair-transition.json"
 if [[ -e $STATE_DIR/$intent || -L $STATE_DIR/$intent ]]; then
   [[ -f $STATE_DIR/$intent && ! -L $STATE_DIR/$intent ]] && cmp -s "$GSJ_WORK/repair-transition.json" "$STATE_DIR/$intent" || fail 'reserved repair transition differs'
 else cat "$GSJ_WORK/repair-transition.json" | immutable_file "$STATE_DIR/$intent"; fi
 # Publish the recovery pointer before changing any reusable configuration.
 jq --arg file "$intent" --arg sha "$(sha_file "$STATE_DIR/$intent")" '.status="repair-prepared"|.repair_transition={file:$file,sha256:$sha}' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
}
finish_repair_transition() {
 assert_owner
 local file intent uid path config_after derived
 file=$(jq -er '.repair_transition.file|select(test("^repair-transition-[a-f0-9]{24}-[a-f0-9]{64}-[a-f0-9]{64}\\.json$"))' "$STATE_DIR/operation.json")
 intent="$STATE_DIR/$file"
 [[ -f $intent && ! -L $intent && $(sha_file "$intent") == $(jq -r .repair_transition.sha256 "$STATE_DIR/operation.json") ]] || fail 'repair transition intent is missing or changed'
 uid=$(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid)
 jq -e --arg operation "$OPERATION" --arg target "$RELEASE_ID" --arg uid "$uid" --arg release "$(sha_file "$GSJ_PAYLOAD/release.json")" --slurpfile op "$STATE_DIR/operation.json" '
   .format=="gsj.repair-transition/1" and .operation==$operation and .target==$target and .namespace_uid==$uid and .release_sha256==$release and
   $op[0].operation==$operation and $op[0].status=="repair-prepared" and $op[0].target==.source and
   (.site_after|.corpus.repair_generation-=1)==.site_before
 ' "$intent" >/dev/null || fail 'repair transition identity or generation differs'
 # Only the recorded before/after values can participate in interrupted
 # publication. A new site edit requires reviewing this pending transition.
 jq -e --slurpfile intent "$intent" '.==$intent[0].site_before or .==$intent[0].site_after' "$SITE" >/dev/null || fail 'repair site changed during configuration publication'
 # load_site derives the two managed-local-ca trust paths into $SITE, and once
 # this state directory holds an operation it leaves a saved file that lacks
 # them alone -- so a second site file, or one regenerated from a template,
 # never receives them. That derivation is not an operator's edit: compare what
 # load_site builds from the saved file, not the raw merge. Measured on a real
 # repair: the raw comparison refused the UNEDITED file here,
 # after the backup, with every controller at zero and no file either verb took.
 # load_site overrides whatever those two keys say under this profile, so the
 # comparison does too; and a later run that finds no operation in this state
 # directory writes them into the file itself, as a first run always has.
 derived='if .tls.profile=="managed-local-ca" then .tls.ca_file=$ca | .verification.ca_file=$ca else . end'
 jq -es --arg ca "$STATE_DIR/tls/ca.crt" --slurpfile intent "$intent" "(.[0]*.[1] | $derived) as \$site | \$site==\$intent[0].site_before or \$site==\$intent[0].site_after" "$GSJ_PAYLOAD/defaults.json" "$CONFIG" >/dev/null || fail 'saved configuration changed during repair publication'
 jq -e --slurpfile intent "$intent" '.==$intent[0].saved_site or .==$intent[0].site_after' "$STATE_DIR/site.pending.json" >/dev/null || fail 'pending repair site belongs to a different transition'
 jq -e --slurpfile intent "$intent" '.==$intent[0].saved_values or .==$intent[0].values_after' "$STATE_DIR/values.pending.json" >/dev/null || fail 'pending repair chart values belong to a different transition'
 if [[ -f $(quiescence_snapshot) ]]; then
   read_repair_backup_source; validate_backup_closure "$(quiescence_snapshot)"
 fi
 # The operator's own file receives the ONE value this transition changes --
 # corpus.repair_generation -- and keeps every key they wrote, in their order
 # (jq re-serialises the file: layout changes, content does not). Writing the
 # complete merged site there pinned this release's defaults into a file left
 # minimal on purpose, so a later release's changed default was silently
 # overridden. The narrow file is used only on proof: merged with THIS
 # installer's defaults -- and load_site's own trust-path derivation, above --
 # it must give the same bytes the complete site gives. load_site rebuilds $SITE
 # from that same merge and derivation (validate.jq, between them, rewrites
 # nothing), and resume and the named repairs compare the result with cmp. Without the proof -- or if any step of it
 # fails -- the complete site is written, as every earlier release did.
 # (--interactive is a different route: the wizard writes a complete file.)
 # The trade, stated: the file now follows a LATER release's defaults, exactly
 # as a site that never ran a repair does -- including where that refuses. An
 # upgrade compares .site.storage whole, so a release that changes a storage
 # default refuses both; the complete write had made a repaired site immune.
 config_after="$GSJ_WORK/repair-config-complete.json"
 jq '.site_after' "$intent" > "$config_after"
 if jq --slurpfile intent "$intent" '.corpus.repair_generation=$intent[0].site_after.corpus.repair_generation' "$CONFIG" > "$GSJ_WORK/repair-config-narrow.json" 2>/dev/null &&
    jq -s --arg ca "$STATE_DIR/tls/ca.crt" ".[0] * .[1] | $derived" "$GSJ_PAYLOAD/defaults.json" "$GSJ_WORK/repair-config-narrow.json" > "$GSJ_WORK/repair-config-narrow.merged.json" 2>/dev/null &&
    jq -s --arg ca "$STATE_DIR/tls/ca.crt" ".[0] * .[1] | $derived" "$GSJ_PAYLOAD/defaults.json" "$config_after" > "$GSJ_WORK/repair-config-complete.merged.json" 2>/dev/null &&
    cmp -s "$GSJ_WORK/repair-config-narrow.merged.json" "$GSJ_WORK/repair-config-complete.merged.json"; then
   config_after="$GSJ_WORK/repair-config-narrow.json"
 else
   log 'The saved site file plus this release defaults does not reproduce the recorded repair configuration byte for byte; writing the complete configuration into it instead of one value'
 fi
 for path in "$SITE" "$CONFIG" "$STATE_DIR/site.pending.json"; do
   assert_owner
   if [[ $path == "$CONFIG" ]]; then atomic "$path" < "$config_after"; else jq '.site_after' "$intent" | atomic "$path"; fi
 done
 for path in "$GSJ_WORK/values.pending.json" "$STATE_DIR/values.pending.json"; do
   assert_owner; jq '.values_after' "$intent" | atomic "$path"
 done
 jq --slurpfile intent "$intent" '.target=$intent[0].target|.repair_source=$intent[0].source|.status="backup-verified"|.repair_transition_history=((.repair_transition_history//[])+[.repair_transition])|del(.repair_transition,.verification_attempts)' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 log "Explicit corpus repair generation $(j .corpus.repair_generation); case data and credentials are preserved"
}
repair_operation() {
 local current holder age pod prior_target
 [[ -n $RESUME_ID ]] || fail 'repair requires --operation ID of the failed deployment'
 current=$(lease_read); holder=$(jq -r '.spec.holderIdentity // ""' <<< "$current")
 [[ $holder == "$RESUME_ID" ]] || fail 'repair does not own the named failed operation'
 age=$(jq -r 'now - (.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$current")
 (( age >= 180 )) || lease_still_live 'the prior installer' "$age" 'repair takes the Lease only after that'
 [[ -f $STATE_DIR/operation.json && $(jq -r .operation "$STATE_DIR/operation.json") == "$RESUME_ID" ]] || fail 'repair requires the exact saved operation metadata'
 # Repair, and repair alone, permits one new bounded account-cleanup round
 # for a run whose three durable attempts are spent. A named resume re-enters
 # the same ladder, so it never carries this signal and is told to repair.
 export GSJ_CLEANUP_NEW_ROUND=1
 # A restore never takes the backup/repair-generation path below: its source
 # record is historical and its values stay the restored target's.
 if jq -e '.kind=="restore"' "$STATE_DIR/operation.json" >/dev/null; then restore_application_repair "$current"; return; fi
 prior_target=$(jq -r .target "$STATE_DIR/operation.json")
 if [[ -n ${CONTINUE_HELM_INSTALLER:-} ]]; then startup_helm_continue "$current"; return; fi
 if [[ $(jq -r .status "$STATE_DIR/operation.json") == repair-prepared ]]; then
   [[ -z ${BACKUP_ROUND:-} ]] || fail 'finish the pending repair transition before selecting another backup round'
   OPERATION=$RESUME_ID
   jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
   LEASE_ACQUIRED=true; rm -f "$STATE_DIR/lease-lost"; start_renewal
   finish_repair_transition
   secret_inputs; relocated_images_probe; managed_dependencies; helm_apply; stage_vectors; wait_application; record_ready; verify_application; record_installed
   return
 fi
 if [[ $prior_target != "$RELEASE_ID" ]]; then
   # A failed first release may need a corrected signed installer. Only a
   # ready record or explicit authenticated startup data proof admits this
   # path; the target must declare its exact compatibility transition.
   read_repair_backup_source
   [[ -s $GSJ_WORK/installed.json ]] && jq -e --arg source "$prior_target" '(.status|IN("verification-pending","startup-unverified","startup-complete")) and .manifest.identity==$source' "$GSJ_WORK/installed.json" >/dev/null || fail 'replacement repair requires a recorded verification-pending source or an authenticated explicit first-startup predecessor'
   compatibility selected
 fi
 OPERATION=$RESUME_ID; jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
 LEASE_ACQUIRED=true
 rm -f "$STATE_DIR/lease-lost"; start_renewal
 read_repair_backup_source
 if [[ -s $GSJ_WORK/installed.json ]] && jq -e '.status|IN("startup-unverified","startup-complete")' "$GSJ_WORK/installed.json" >/dev/null; then startup_source_complete; fi
 if [[ -n ${BACKUP_ROUND:-} ]]; then
   prepare_backup_round "$BACKUP_ROUND"
   read_backup_source active
 fi
 if [[ -s $GSJ_WORK/installed.json ]]; then
   compatibility selected
   # The new installer may be repairing a failed, older target. Preserve that
   # distinction before backup so an interrupted archive has a named recovery
   # path without falsely recording the new target as already applied.
   prepare_repair_backup "$prior_target"
   jq '.status="repair-backing-up"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
   backup
   jq --arg archive "$(backup_archive)" --slurpfile receipt "$(backup_archive).json" '.repair_backup_history=((.repair_backup_history//[])+[(.repair_backup|.observed_source=.source|del(.source))+{status:"backup-verified",archive:$archive,archive_source:$receipt[0].release_identity}])|del(.repair_backup)' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 fi
 # Stop the old initializer first. A Lease expiry never bypasses its flock.
 if k get deploy "$RELEASE-web" >/dev/null 2>&1; then
   k scale deploy "$RELEASE-web" --replicas=0 >/dev/null
   k wait --for=delete pod -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=gsj" --timeout=300s
 fi
 prepare_repair_transition "$prior_target"
 finish_repair_transition
 secret_inputs; relocated_images_probe; managed_dependencies; helm_apply; stage_vectors; wait_application; record_ready; verify_application; record_installed
}
restore_resource() {
 # Persist a create intent before the API call. A lost create response can be
 # reconciled only against that intent and its operation-bound metadata.
 local source=$1 kind name directory object expected uid
 kind=$(jq -er .kind "$source"); name=$(jq -er .metadata.name "$source")
 [[ $kind =~ ^(Secret|ConfigMap|PersistentVolumeClaim|Pod)$ && $name =~ ^[a-z0-9][a-z0-9.-]*$ ]] || fail 'unsupported restore resource'
 directory="$STATE_DIR/restore-$OPERATION/$kind/$name"; mkdir -p "$directory"
 expected="$GSJ_WORK/restore-resource.json"
 jq --arg operation "$OPERATION" --arg ns "$NAMESPACE" --arg sha "$(jq -r .archive_sha256 "$STATE_DIR/restoration.json")" '
   .metadata.namespace=$ns | .metadata.labels["gsj.io/restore-operation"]=$operation |
   .metadata.annotations["gsj.io/restore-archive-sha256"]=$sha
 ' "$source" > "$expected"
 if [[ -f $directory/intent.json ]]; then
   jq -e --slurpfile expected "$expected" '.==$expected[0]' "$directory/intent.json" >/dev/null || fail 'restore resource intent changed'
 else cat "$expected" | immutable_file "$directory/intent.json"; fi
 object=$(k get "$kind" "$name" -o json --ignore-not-found) || fail 'cannot inspect restore resource'
 if [[ -z $object ]]; then
   [[ ! -f $directory/receipt.json ]] || fail 'a previously restored resource disappeared; its identity cannot be recreated by retry'
   if [[ ! -f $directory/attempt.json ]]; then
     jq -n --arg sha "$(sha_file "$directory/intent.json")" '{intent_sha256:$sha,attempted:true}' | immutable_file "$directory/attempt.json"
   fi
   assert_owner
   # A failed response is not absence: the next read establishes the outcome.
   k create -f "$directory/intent.json" > "$directory/create.log" 2>&1 || true
   object=$(k get "$kind" "$name" -o json --ignore-not-found) || fail 'restore create outcome is unknown'
 fi
 [[ -n $object && -f $directory/attempt.json ]] || fail 'restore resource belongs to another writer or creation did not complete'
 jq -e --arg sha "$(sha_file "$directory/intent.json")" '.attempted==true and .intent_sha256==$sha' "$directory/attempt.json" >/dev/null || fail 'restore create intent is unproven'
 jq -e --slurpfile expected "$directory/intent.json" '
   def subset($actual;$want):
     if ($want|type)=="object" then ($actual|type)=="object" and all($want|keys[]; . as $k | subset($actual[$k];$want[$k]))
     elif ($want|type)=="array" then ($actual|type)=="array" and ($actual|length)==($want|length) and all(range(0;$want|length); . as $i | subset($actual[$i];$want[$i]))
     else $actual==$want end;
   # Kubernetes omits an explicitly empty imagePullSecrets list. Normalize
   # only that absent Pod field; nonempty expected credentials stay exact.
   (if .kind=="Pod" and $expected[0].spec.imagePullSecrets==[] and (.spec|has("imagePullSecrets")|not)
    then .spec.imagePullSecrets=[] else . end) |
   subset(.;$expected[0]) and (.metadata.uid|type=="string" and length>0) and .metadata.deletionTimestamp==null and
   (if .kind=="Secret" then (.data//{})==($expected[0].data//{}) and (.type//"Opaque")==($expected[0].type//"Opaque")
    elif .kind=="ConfigMap" then (.data//{})==($expected[0].data//{}) and (.binaryData//{})==($expected[0].binaryData//{})
    elif .kind=="Pod" then (.spec.initContainers//[]|length)==0 and .metadata.deletionTimestamp==null else true end)
 ' <<< "$object" >/dev/null || fail 'restore resource differs from its exact ownership and payload intent'
 uid=$(jq -r .metadata.uid <<< "$object")
 if [[ -f $directory/receipt.json ]]; then
   jq -e --arg uid "$uid" --arg sha "$(sha_file "$directory/intent.json")" '.uid==$uid and .intent_sha256==$sha' "$directory/receipt.json" >/dev/null || fail 'restored resource UID or receipt changed'
 else
   jq -n --arg uid "$uid" --arg sha "$(sha_file "$directory/intent.json")" '{uid:$uid,intent_sha256:$sha}' | immutable_file "$directory/receipt.json"
 fi
}
restore_resource_list() {
 local list=$1 number count
 count=$(jq '.items|length' "$list")
 for ((number=0; number<count; number++)); do
   jq --argjson number "$number" '.items[$number]' "$list" > "$GSJ_WORK/restore-one.json"
   restore_resource "$GSJ_WORK/restore-one.json"
 done
}
restore_no_writers() {
 local pod=${1:-} claims
 jq '.references' "$STATE_DIR/restoration.json" > "$GSJ_WORK/restore-references.json"
 claims=$(jq '[.PersistentVolumeClaim[]]' "$GSJ_WORK/restore-references.json")
 k get deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs -o json > "$GSJ_WORK/restore-controllers.json"
 jq -e --arg release "$RELEASE" --argjson claims "$claims" '
   all(.items[]; .metadata.labels["app.kubernetes.io/instance"]!=$release and
     ([.spec.template.spec.volumes[]?.persistentVolumeClaim.claimName,
       .spec.jobTemplate.spec.template.spec.volumes[]?.persistentVolumeClaim.claimName] |
       all(.[]; . as $name | ($claims|index($name))==null)))
 ' "$GSJ_WORK/restore-controllers.json" >/dev/null || fail 'restore destination has an application controller; no file replay is allowed'
 k get pods -o json > "$GSJ_WORK/restore-pods.json"
 jq -e --arg pod "$pod" --argjson claims "$claims" '
   all(.items[]|select(.metadata.name!=$pod);
     all(.spec.volumes[]?.persistentVolumeClaim.claimName; . as $name | ($claims|index($name))==null))
 ' "$GSJ_WORK/restore-pods.json" >/dev/null || fail 'another Pod mounts restore storage; no file replay is allowed'
}
restore_bindings() {
 local role key claim uid volume
 : > "$GSJ_WORK/restore-bindings.jsonl"
 for role in forgejo gsj chroma; do
   key=$role; [[ $role != gsj ]] || key=data
   claim=$(jq -r --arg key "$key" '.storage[$key].existingClaim' "$GSJ_WORK/values.pending.json"); claim=${claim:-$RELEASE-$key}
   uid=$(jq -er .uid "$STATE_DIR/restore-$OPERATION/PersistentVolumeClaim/$claim/receipt.json")
   k get pvc "$claim" -o json > "$GSJ_WORK/restore-claim.json"
   jq -e --arg uid "$uid" '.metadata.uid==$uid and .status.phase=="Bound" and (.spec.volumeName|type=="string" and length>0)' "$GSJ_WORK/restore-claim.json" >/dev/null || fail 'restored PVC identity or binding is unproven'
   volume=$(jq -r .spec.volumeName "$GSJ_WORK/restore-claim.json")
   k get pv "$volume" -o json > "$GSJ_WORK/restore-volume.json"
   jq -e --arg uid "$uid" --arg ns "$NAMESPACE" --arg name "$claim" '.spec.claimRef.uid==$uid and .spec.claimRef.namespace==$ns and .spec.claimRef.name==$name and (.metadata.uid|type=="string" and length>0)' "$GSJ_WORK/restore-volume.json" >/dev/null || fail 'restored PV claim ownership is unproven'
   jq -n --arg role "$role" --arg name "$claim" --arg uid "$uid" --slurpfile pv "$GSJ_WORK/restore-volume.json" '{key:$role,value:{name:$name,uid:$uid,pv_name:$pv[0].metadata.name,pv_uid:$pv[0].metadata.uid,root:("/volumes/"+$role)}}' >> "$GSJ_WORK/restore-bindings.jsonl"
 done
 jq -s 'from_entries' "$GSJ_WORK/restore-bindings.jsonl" > "$GSJ_WORK/restore-bindings.json"
 local saved="$STATE_DIR/restore-$OPERATION/bindings.json"
 if [[ -f $saved ]]; then
   jq -e --slurpfile actual "$GSJ_WORK/restore-bindings.json" '.==$actual[0]' "$saved" >/dev/null || fail 'restore storage bindings changed after file ownership was recorded'
 else cat "$GSJ_WORK/restore-bindings.json" | immutable_file "$saved"; fi
}
# GSJ_RUNTIME_HELPER: restore-files.py
restore_files() {
 local pod=$1 expected=$2 image=$3 received="$GSJ_WORK/restore-archive-verified.json" saved="$STATE_DIR/restore-$OPERATION" rc=0 uid
 printf '["sleep","86400"]' > "$GSJ_WORK/restore-command.json"
 maintenance_pod_document "$pod" "$image" "$GSJ_WORK/restore-command.json" > "$GSJ_WORK/restore-pod.json"
 restore_resource "$GSJ_WORK/restore-pod.json"
 TRANSFER_HANDBACK_POD=$pod
 k wait --for=condition=Ready "pod/$pod" --timeout=300s
 restore_no_writers "$pod"; restore_bindings; assert_owner
 log 'Transferring and verifying the immutable restore archive; existing partial data remains owned by this operation'
 local remote="/transfer/snapshot-$(jq -r .archive_sha256 "$STATE_DIR/restoration.json").tar.gz"
 # The receiver verifies the complete archive before publishing it. Broken
 # streams leave a private temporary file, never a misleading final archive.
 openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$BACKUP_PASSWORD" -in "$ARCHIVE" |
   k exec -i "$pod" -- python -c '
import hashlib,json,os,pathlib,sys,tempfile
from gsj_deploy.backup import verify
p=pathlib.Path(sys.argv[1]); fd,tmp=tempfile.mkstemp(prefix=".gsj-transfer-",dir=p.parent)
with os.fdopen(fd,"wb") as out:
    for block in iter(lambda:sys.stdin.buffer.read(1024*1024),b""): out.write(block)
    out.flush(); os.fsync(out.fileno())
proof=verify(tmp)
if proof["metadata"]["release_identity"]!=sys.argv[2]: raise ValueError("restore archive release differs")
try: os.link(tmp,p)
except FileExistsError:
    if p.is_symlink() or not p.is_file(): raise ValueError("restore archive destination is not an ordinary file")
    old=verify(p)
    if old["archive_sha256"]!=proof["archive_sha256"]: raise ValueError("immutable restore archive differs")
os.unlink(tmp); fd=os.open(p.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
print(json.dumps({k:v for k,v in proof.items() if k!="metadata"},sort_keys=True))
' "$remote" "$expected" > "$received"
 jq -e '(.archive_sha256|test("^[a-f0-9]{64}$")) and (.manifest_sha256|test("^[a-f0-9]{64}$")) and .entries>0' "$received" >/dev/null || fail 'complete restore archive verification is unproven'
 if [[ -f $saved/archive-proof.json ]]; then
   jq -e --slurpfile actual "$received" '.==$actual[0]' "$saved/archive-proof.json" >/dev/null || fail 'restore archive proof changed'
 else cat "$received" | immutable_file "$saved/archive-proof.json"; fi
 jq -n --arg operation "$OPERATION" --arg identity "$expected" --arg uid "$(jq -r .target_namespace_uid "$STATE_DIR/restoration.json")" --arg encrypted "$(jq -r .archive_sha256 "$STATE_DIR/restoration.json")" --slurpfile proof "$received" --slurpfile bindings "$saved/bindings.json" '{format:"gsj.restore-files/1",operation:$operation,release_identity:$identity,namespace_uid:$uid,archive_sha256:$proof[0].archive_sha256,encrypted_archive_sha256:$encrypted,volumes:$bindings[0]}' > "$GSJ_WORK/restore-files-settings.json"
 if [[ -f $saved/files-settings.json ]]; then
   jq -e --slurpfile actual "$GSJ_WORK/restore-files-settings.json" '.==$actual[0]' "$saved/files-settings.json" >/dev/null || fail 'restore file binding changed'
 else cat "$GSJ_WORK/restore-files-settings.json" | immutable_file "$saved/files-settings.json"; fi
 # These code/config files are immutable for this exact release operation.
 local source destination
 for source in "$GSJ_PAYLOAD/helpers/restore-files.py" "$saved/files-settings.json"; do
   destination="/transfer/$(basename "$source")"
   k exec -i "$pod" -- python -c '
import os,pathlib,sys,tempfile
p=pathlib.Path(sys.argv[1]); data=sys.stdin.buffer.read(); fd,tmp=tempfile.mkstemp(dir=p.parent)
with os.fdopen(fd,"wb") as out: out.write(data); out.flush(); os.fsync(out.fileno())
try: os.link(tmp,p)
except FileExistsError:
    if p.is_symlink() or p.read_bytes()!=data: raise ValueError("immutable restore input differs")
os.unlink(tmp); fd=os.open(p.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
' "$destination" < "$source"
 done
 restore_no_writers "$pod"; restore_bindings; assert_owner
 k exec "$pod" -- python /transfer/restore-files.py --archive "$remote" --settings /transfer/files-settings.json > "$saved/files-result.pending.json" || rc=$?
 (( rc != 78 )) || fail 'the earlier restore process still owns the file lock; wait and use named restore-repair'
 (( rc == 0 )) || fail 'restore files are incomplete; journal and data remain available to named restore-repair'
 restore_validate_result "$saved/files-result.pending.json"
 restore_no_writers "$pod"; restore_bindings; assert_owner
 cat "$saved/files-result.pending.json" | atomic "$saved/files-result.json"
 jq '.status="files-restored"|.transformation="new storage bindings from verified backup; identities/content preserved"' "$STATE_DIR/restoration.json" | atomic "$STATE_DIR/restoration.json"
 jq '.status="restore-files-verified"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 restore_finish_pod
}
restore_validate_result() {
 local result=$1 saved="$STATE_DIR/restore-$OPERATION"
 jq -e --arg operation "$OPERATION" --arg sha "$(sha_file "$saved/files-settings.json")" --slurpfile settings "$saved/files-settings.json" --slurpfile proof "$saved/archive-proof.json" '
   .format=="gsj.restore-files-result/1" and .status=="complete" and .restored==true and .operation==$operation and
   .settings_file_sha256==$sha and .namespace_uid==$settings[0].namespace_uid and .release_identity==$settings[0].release_identity and
   .archive_sha256==$settings[0].archive_sha256 and .encrypted_archive_sha256==$settings[0].encrypted_archive_sha256 and
   .manifest_sha256==$proof[0].manifest_sha256 and .entries==$proof[0].entries
 ' "$result" >/dev/null || fail 'restore file completion does not match the exact archive and target binding'
}
restore_finish_pod() {
 local pod uid object saved="$STATE_DIR/restore-$OPERATION"
 pod=$(jq -er .pod "$STATE_DIR/restoration.json")
 [[ $(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid) == $(jq -er .target_namespace_uid "$STATE_DIR/restoration.json") ]] || fail 'restore target namespace identity changed'
 restore_validate_result "$saved/files-result.json"
 restore_no_writers "$pod"; restore_bindings; assert_owner
 uid=$(jq -er .uid "$saved/Pod/$pod/receipt.json")
 object=$(k get pod "$pod" -o json --ignore-not-found) || fail 'cannot establish restore Pod cleanup state'
 if [[ -z $object ]]; then return; fi
 [[ $(jq -r .metadata.uid <<< "$object") == "$uid" ]] || fail 'restore Pod identity changed before cleanup'
 jq -n --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid}}' > "$GSJ_WORK/restore-pod-delete.json"
 transfer_handback "$pod"
 k delete --raw "/api/v1/namespaces/$NAMESPACE/pods/$pod" -f "$GSJ_WORK/restore-pod-delete.json" >/dev/null
 k wait --for=delete "pod/$pod" --timeout=300s >/dev/null
}
restore_program_select() {
 [[ ${RESTORE_PROGRAM_SELECTED:-false} != true ]] || return 0
 # resume and repair select a restore's program only for their saved restore;
 # resume would read a symlinked record without this selection.
 if [[ $COMMAND != restore-repair ]]; then
   [[ ! -L $STATE_DIR/operation.json ]] || fail 'operation metadata is not ordinary state'
   [[ -f $STATE_DIR/operation.json ]] && jq -e --arg id "$RESUME_ID" '.operation==$id and .kind=="restore"' "$STATE_DIR/operation.json" >/dev/null || return 0
 fi
 RESTORE_PROGRAM_SELECTED=true; RESTORE_PROGRAM_ACTIVE=false
 local checkpoint="$STATE_DIR/restoration.json" target directory installer file
 if [[ ! -f $checkpoint || -L $checkpoint ]]; then
   [[ -z ${SOURCE_INSTALLER:-} ]] || fail 'corrected restore program requires the recorded completed file-restore checkpoint'
   return
 fi
 [[ $RESUME_ID =~ ^[a-f0-9]{24}$ ]] || fail 'restore program continuation requires its exact operation ID'
 directory="$STATE_DIR/restore-$RESUME_ID"
 target=$(jq -er --arg op "$RESUME_ID" '.operation==$op and .format=="gsj.restore/1"|select(.)' "$checkpoint" >/dev/null && jq -er '.release_identity|select(type=="string" and length>0)' "$checkpoint") || fail 'restore program checkpoint identity differs'
 if [[ $target == "$RELEASE_ID" && ! -e $directory/program-transition.json && ! -L $directory/program-transition.json ]]; then
   [[ -z ${SOURCE_INSTALLER:-} ]] || fail 'restore program replacement must select a different signed program'
   return
 fi
 [[ -d $directory && ! -L $directory ]] || fail 'restore program evidence directory is unavailable'
 RESTORE_PROGRAM_ID=$RELEASE_ID
 [[ ! -L $directory/program-predecessor && ( ! -e $directory/program-predecessor || -d $directory/program-predecessor ) ]] || fail 'restore predecessor evidence is not ordinary state'
 if [[ -e $directory/program-transition.json || -L $directory/program-transition.json ]]; then
   [[ -f $directory/program-transition.json && ! -L $directory/program-transition.json ]] || fail 'restore program transition is not an ordinary file'
   jq -e --arg target "$target" --arg op "$RESUME_ID" '.format=="gsj.restore-program-transition/1" and (.program|type=="string" and length>0) and .program!=$target and .target==$target and .previous_program==$target and .operation==$op' "$directory/program-transition.json" >/dev/null || fail 'restore program transition belongs to a different program or target'
   jq -e --arg program "$RESTORE_PROGRAM_ID" '.program==$program' "$directory/program-transition.json" >/dev/null || fail "this restore is continued by its recorded program $(jq -r .program "$directory/program-transition.json"); use that installer (after a restore-program transition neither the source release nor another program continues it)"
 else
   [[ $COMMAND != resume ]] || fail 'resume must use the exact source installer of this restore'
   [[ $COMMAND != repair || -n ${SOURCE_INSTALLER:-} ]] || fail 'repair must use the exact source installer of this restore'
   [[ -n ${SOURCE_INSTALLER:-} ]] || fail 'restore uses another release; explicitly select its signed --source-installer for corrected-program continuation'
 fi
 jq -e --arg target "$target" '.supported_sources|index($target)' "$GSJ_PAYLOAD/release.json" >/dev/null || fail 'corrected restore program does not declare the exact original target'
 [[ ! -e $GSJ_WORK/restore-program && ! -L $GSJ_WORK/restore-program ]] || fail 'restore program work directory already exists'
 mkdir -m 700 "$GSJ_WORK/restore-program"
 cp "$GSJ_PAYLOAD/release.json" "$GSJ_WORK/restore-program/program-release.json"
 installer=${SOURCE_INSTALLER:-$directory/program-predecessor/gsj-install.sh}
 authenticate_predecessor "$installer" "$target" "$GSJ_WORK/restore-program/predecessor"
 for file in gsj-install.sh installer-descriptor.json installer-descriptor.sig; do
   if [[ -e $directory/program-predecessor/$file || -L $directory/program-predecessor/$file ]]; then
     [[ -f $directory/program-predecessor/$file && ! -L $directory/program-predecessor/$file ]] && cmp -s "$GSJ_WORK/restore-program/predecessor/$file" "$directory/program-predecessor/$file" || fail 'retained restore predecessor bytes differ'
   fi
 done
 GSJ_PAYLOAD=$PREDECESSOR_PAYLOAD; RELEASE_ID=$target; VERSION=$(jq -er .version "$GSJ_PAYLOAD/release.json")
 jq --slurpfile schema "$GSJ_PAYLOAD/site.schema.json" -f "$GSJ_PAYLOAD/validate.jq" "$SITE" > "$GSJ_WORK/restore-program/validated-site.json"
 jq -e --slurpfile site "$SITE" '.==$site[0]' "$GSJ_WORK/restore-program/validated-site.json" >/dev/null || fail 'restore configuration does not satisfy the exact source schema'
 retained_site_matches "$SITE" "$STATE_DIR/site.pending.json" || fail 'restore program configuration differs from the retained operation'
 jq --slurpfile release "$GSJ_PAYLOAD/release.json" -f "$GSJ_PAYLOAD/compile.jq" "$SITE" > "$GSJ_WORK/values.pending.json"
 RESTORE_PROGRAM_ACTIVE=true
}
restore_program_resources() {
 local saved="$STATE_DIR/restore-$OPERATION" kind name directory object file
 : > "$GSJ_WORK/restore-program/resource-inventory.jsonl"
 jq -s '{items:[.[].items[]]}' "$GSJ_WORK/restorable-secrets.json" "$GSJ_WORK/restorable-claims.json" > "$GSJ_WORK/restore-program/expected-resources.json"
 while IFS=$'\t' read -r kind name; do
   [[ $kind =~ ^(Secret|ConfigMap|PersistentVolumeClaim)$ && $name =~ ^[a-z0-9][a-z0-9.-]*$ ]] || fail 'restore program resource inventory is invalid'
   directory="$saved/$kind/$name"
   [[ -d $directory && ! -L $directory && ! -L $saved/$kind ]] || fail 'restored resource evidence directory is unavailable'
   for file in intent.json attempt.json receipt.json; do [[ -f $directory/$file && ! -L $directory/$file ]] || fail 'restored resource identity evidence is incomplete'; done
   jq -e --arg sha "$(sha_file "$directory/intent.json")" '.attempted==true and .intent_sha256==$sha' "$directory/attempt.json" >/dev/null || fail 'restored resource create attempt differs'
   object=$(k get "$kind" "$name" -o json) || fail 'restored resource is unavailable'
   jq -e --arg sha "$(sha_file "$directory/intent.json")" --arg uid "$(jq -er .metadata.uid <<< "$object")" '.uid==$uid and .intent_sha256==$sha' "$directory/receipt.json" >/dev/null || fail 'restored resource UID or intent changed'
   printf '%s\n' "$object" > "$GSJ_WORK/restore-program/resource.json"
   # secret_inputs re-derives the non-secret trust bundle from the tools host
   # before every Helm apply: compare it by UID and restore metadata only.
   if [[ $kind == ConfigMap && $name == "$RELEASE-trust" ]]; then jq --slurpfile i "$directory/intent.json" '.data=$i[0].data|.binaryData=$i[0].binaryData' <<< "$object" > "$GSJ_WORK/restore-program/resource.json"; fi
   owned_resource_matches "$GSJ_WORK/restore-program/resource.json" "$directory/intent.json" || fail 'restored resource payload differs from its original intent'
   jq -e --arg op "$OPERATION" --arg archive "$(jq -r .archive_sha256 "$STATE_DIR/restoration.json")" --slurpfile intent "$directory/intent.json" '
     .metadata.deletionTimestamp==null and .metadata.labels["gsj.io/restore-operation"]==$op and .metadata.annotations["gsj.io/restore-archive-sha256"]==$archive and
     (if .kind=="Secret" then {data,type,immutable}==($intent[0]|{data,type,immutable})
      elif .kind=="ConfigMap" then {data,binaryData,immutable}==($intent[0]|{data,binaryData,immutable}) else true end)
   ' "$GSJ_WORK/restore-program/resource.json" >/dev/null || fail 'restored credential, trust or ownership bytes changed'
   # Credentials and ordinary ConfigMap contents remain the authenticated
   # archive's bytes. The ACME owner alone was explicitly rebound to target UID.
   if [[ $kind == Secret || $kind == ConfigMap ]]; then
     if [[ $kind == ConfigMap && $(j .tls.profile) == managed-acme && $name == "$RELEASE-acme-owner" ]]; then
       acme_documents "$SITE" "$(jq -r .target_namespace_uid "$STATE_DIR/restoration.json")" "$GSJ_WORK/restore-program/acme"
       jq --slurpfile archived "$GSJ_WORK/restore-program/expected-resources.json" --arg name "$name" '.data.account_key_sha256=([$archived[0].items[]|select(.kind=="ConfigMap" and .metadata.name==$name)|.data.account_key_sha256][0])' "$GSJ_WORK/restore-program/acme-owner.json" > "$GSJ_WORK/restore-program/expected-one.json"
     else jq --arg kind "$kind" --arg name "$name" '.items[]|select(.kind==$kind and .metadata.name==$name)' "$GSJ_WORK/restore-program/expected-resources.json" > "$GSJ_WORK/restore-program/expected-one.json"; fi
     jq -e --slurpfile expected "$GSJ_WORK/restore-program/expected-one.json" '(.data//{})==($expected[0].data//{}) and (.binaryData//{})==($expected[0].binaryData//{}) and (if .kind=="Secret" then (.type//"Opaque")==($expected[0].type//"Opaque") else true end)' "$directory/intent.json" >/dev/null || fail 'restored resource intent differs from the authenticated archive'
   fi
   jq -cn --arg kind "$kind" --arg name "$name" --arg uid "$(jq -r .uid "$directory/receipt.json")" --arg intent "$(sha_file "$directory/intent.json")" --arg receipt "$(sha_file "$directory/receipt.json")" '{kind:$kind,name:$name,uid:$uid,intent_sha256:$intent,receipt_sha256:$receipt}' >> "$GSJ_WORK/restore-program/resource-inventory.jsonl"
 done < <(jq -r '.items|sort_by(.kind,.metadata.name)[]|[.kind,.metadata.name]|@tsv' "$GSJ_WORK/restore-program/expected-resources.json")
 jq -s . "$GSJ_WORK/restore-program/resource-inventory.jsonl" > "$GSJ_WORK/restore-program/resource-inventory.json"
}
restore_original_evidence() {
 # The original restore intent, its Lease binding and the durable file proofs.
 local current=$1 saved="$STATE_DIR/restore-$OPERATION" original="$STATE_DIR/operation-intents/$OPERATION" file
 for file in files-settings.json files-result.json archive-proof.json bindings.json; do [[ -f $saved/$file && ! -L $saved/$file ]] || fail 'restore program requires retained complete file and storage proofs'; done
 [[ -d $original && ! -L $original && ! -L $STATE_DIR/operation-intents ]] || fail 'restore program requires its original immutable operation intent'
 for file in intent.json site.json values.json release.json; do [[ -f $original/$file && ! -L $original/$file ]] || fail 'original restore intent is incomplete'; done
 jq -e --arg op "$OPERATION" --arg target "$RELEASE_ID" --arg context "$CONTEXT" --arg ns "$NAMESPACE" --arg name "$RELEASE" --arg site "$(sha_file "$original/site.json")" --arg values "$(sha_file "$original/values.json")" --arg release "$(sha_file "$original/release.json")" --slurpfile checkpoint "$STATE_DIR/restoration.json" '
   .format=="gsj.operation-intent/1" and .record=={operation:$op,target:$target,kind:"restore",status:"owned"} and .context==$context and .namespace==$ns and .release==$name and .namespace_uid==$checkpoint[0].target_namespace_uid and
   .site_sha256==$site and .values_sha256==$values and .release_sha256==$release and .archive=={path:$checkpoint[0].archive,sha256:$checkpoint[0].archive_sha256,resources_sha256:$checkpoint[0].resources_sha256,metadata_sha256:$checkpoint[0].metadata_sha256}
 ' "$original/intent.json" >/dev/null || fail 'original restore source, archive or namespace intent differs'
 retained_site_matches "$SITE" "$original/site.json" && cmp -s "$GSJ_WORK/values.pending.json" "$original/values.json" && cmp -s "$GSJ_PAYLOAD/release.json" "$original/release.json" || fail 'restore program target manifest or configuration differs from the original intent'
 jq -e --arg op "$OPERATION" --arg name "$RELEASE-operation" --arg sha "$(sha_file "$original/intent.json")" --slurpfile intent "$original/intent.json" '.metadata.name==$name and .spec.holderIdentity==$op and .metadata.annotations["gsj.io/operation-intent-sha256"]==$sha and .spec.acquireTime==$intent[0].acquire_time and ($intent[0].prior_lease_uid=="" or .metadata.uid==$intent[0].prior_lease_uid)' <<< "$current" >/dev/null || fail 'restore program Lease differs from the immutable original operation'
 restore_validate_result "$saved/files-result.json"
 jq -e --arg op "$OPERATION" --arg target "$RELEASE_ID" --slurpfile checkpoint "$STATE_DIR/restoration.json" --slurpfile proof "$saved/archive-proof.json" --slurpfile bindings "$saved/bindings.json" '
   .format=="gsj.restore-files/1" and .operation==$op and .release_identity==$target and .namespace_uid==$checkpoint[0].target_namespace_uid and
   .encrypted_archive_sha256==$checkpoint[0].archive_sha256 and .archive_sha256==$proof[0].archive_sha256 and .volumes==$bindings[0] and ($proof[0].entries|type=="number" and .>0)
 ' "$saved/files-settings.json" >/dev/null || fail 'restore file proof does not describe this exact archive and target storage'
}
restore_program_validate() {
 local current=$1 saved="$STATE_DIR/restore-$OPERATION" original="$STATE_DIR/operation-intents/$OPERATION" pod object
 [[ ${RESTORE_PROGRAM_ACTIVE:-false} == true ]] || return 0
 jq -e '.status=="files-restored"' "$STATE_DIR/restoration.json" >/dev/null && jq -e '.status=="restore-files-verified" and .helm_application==null' "$STATE_DIR/operation.json" >/dev/null || fail 'corrected restore program requires completed files before any application Helm attempt'
 # Only the pointer (checked above) commits an application Helm attempt, before
 # Helm can start. An attempt directory without it is an interrupted
 # helm_application_prepare and is ignored; the ancestry check below still
 # refuses any target Helm record.
 [[ ! -L $STATE_DIR/helm-applications && ! -L $STATE_DIR/helm-applications/$OPERATION ]] || fail 'saved Helm target directory is not ordinary state'
 restore_original_evidence "$current"
 restore_no_writers ''; restore_bindings
 pod=$(jq -er .pod "$STATE_DIR/restoration.json")
 object=$(k get pod "$pod" -o json --ignore-not-found) || fail 'restore maintenance Pod state is unknown'
 [[ -z $object ]] || fail 'corrected restore program requires the retired restore Pod; retain its evidence for exact-owner recovery'
 restore_program_resources
 # Restore carries opaque source Helm records along with credentials. They
 # are ancestry, not evidence that a target Helm writer has run. Admit only
 # their exact restored UID/payload receipts; extra/changed history refuses.
 k get secrets,configmaps -o json > "$GSJ_WORK/restore-program/current-history.json"
 jq -e --arg release "$RELEASE" --slurpfile expected "$GSJ_WORK/restore-program/expected-resources.json" --slurpfile inventory "$GSJ_WORK/restore-program/resource-inventory.json" '
   def history: (.metadata.labels.owner=="helm" and .metadata.labels.name==$release) or (.metadata.name|startswith("sh.helm.release.v1."+$release+".v"));
   [.items[]|select(history)|{kind,name:.metadata.name,uid:.metadata.uid}]|sort_by(.kind,.name) ==
   ([$expected[0].items[]|select(history)|. as $e|$inventory[0][]|select(.kind==$e.kind and .name==$e.metadata.name)|{kind,name,uid}]|sort_by(.kind,.name))
 ' "$GSJ_WORK/restore-program/current-history.json" >/dev/null || {
   # After the receipt this program owns the restore, and a target Helm record
   # without its pointer is no write of this operation.
   [[ ! -f $saved/program-transition.json ]] || restore_fresh_fail 'restore Helm ancestry has changed or a target Helm record appeared after the restore-program transition'
   fail 'restore Helm ancestry has changed or a target Helm record appeared; continue with the exact source installer that owns this restore'
 }
 jq -n --arg program "$RESTORE_PROGRAM_ID" --arg target "$RELEASE_ID" --arg op "$OPERATION" --arg program_manifest "$(sha_file "$GSJ_WORK/restore-program/program-release.json")" --arg installer "$(sha_file "$GSJ_WORK/restore-program/predecessor/gsj-install.sh")" --arg manifest "$(sha_file "$GSJ_PAYLOAD/release.json")" --arg original "$(sha_file "$original/intent.json")" --arg checkpoint "$(sha_file "$STATE_DIR/restoration.json")" --arg operation "$(sha_file "$STATE_DIR/operation.json")" --arg settings "$(sha_file "$saved/files-settings.json")" --arg result "$(sha_file "$saved/files-result.json")" --arg archive_proof "$(sha_file "$saved/archive-proof.json")" --arg site "$(sha_file "$SITE")" --arg values "$(sha_file "$GSJ_WORK/values.pending.json")" --argjson lease "$current" --slurpfile resources "$GSJ_WORK/restore-program/resource-inventory.json" --slurpfile bindings "$saved/bindings.json" --slurpfile restore "$STATE_DIR/restoration.json" '
   {format:"gsj.restore-program-transition/1",operation:$op,program:$program,previous_program:$target,target:$target,program_manifest_sha256:$program_manifest,source_installer_sha256:$installer,target_manifest_sha256:$manifest,
    original_intent_sha256:$original,original_checkpoint_sha256:$checkpoint,original_operation_sha256:$operation,site_sha256:$site,values_sha256:$values,
    source_namespace_uid:$restore[0].source_namespace_uid,target_namespace_uid:$restore[0].target_namespace_uid,archive_sha256:$restore[0].archive_sha256,resources_sha256:$restore[0].resources_sha256,metadata_sha256:$restore[0].metadata_sha256,
    file_settings_sha256:$settings,file_result_sha256:$result,archive_proof_sha256:$archive_proof,storage:$bindings[0],restored_resources:$resources[0],
    lease:{uid:$lease.metadata.uid,holder:$lease.spec.holderIdentity,acquire_time:$lease.spec.acquireTime,annotations:($lease.metadata.annotations//{})},status:"files-restored-before-helm"}
 ' > "$GSJ_WORK/restore-program/transition.json"
 if [[ -e $saved/program-transition.json || -L $saved/program-transition.json ]]; then
   [[ -f $saved/program-transition.json && ! -L $saved/program-transition.json ]] && cmp -s "$GSJ_WORK/restore-program/transition.json" "$saved/program-transition.json" || fail 'restore program receipt no longer matches the preserved evidence'
 fi
}
restore_program_publish() {
 [[ ${RESTORE_PROGRAM_ACTIVE:-false} == true ]] || return 0
 local saved="$STATE_DIR/restore-$OPERATION" working="$GSJ_WORK/restore-program" file
 [[ ! -f $saved/program-transition.json ]] || return 0
 assert_owner
 [[ -d $saved/program-predecessor ]] || mkdir -m 700 "$saved/program-predecessor"
 for file in gsj-install.sh installer-descriptor.json installer-descriptor.sig; do startup_intent_file "$working/predecessor/$file" "$saved/program-predecessor/$file"; done
 startup_intent_file "$STATE_DIR/restoration.json" "$saved/program-original-restoration.json"
 startup_intent_file "$STATE_DIR/operation.json" "$saved/program-original-operation.json"
 startup_intent_file "$working/transition.json" "$saved/program-transition.json"
}
restore_resume_owner() {
 local current age checkpoint="$STATE_DIR/restoration.json"
 [[ $RESUME_ID =~ ^[a-f0-9]{24}$ && -f $checkpoint ]] || fail 'restore-repair requires the saved restore operation ID'
 jq -e --arg id "$RESUME_ID" --arg release "$RELEASE_ID" '.format=="gsj.restore/1" and .operation==$id and .release_identity==$release and (.status|IN("creating-resources","restoring-files","files-restored"))' "$checkpoint" >/dev/null || fail 'restore-repair requires an interrupted resource or file restore; use resume for application startup'
 jq -e --arg id "$RESUME_ID" --arg target "$RELEASE_ID" '.operation==$id and .target==$target and .kind=="restore" and (.status|IN("owned","restoring-resources","restoring-files","restore-files-verified"))' "$STATE_DIR/operation.json" >/dev/null || fail 'saved restore operation differs'
 retained_site_matches "$SITE" "$STATE_DIR/site.pending.json" || fail 'restore repair configuration changed'
 [[ $(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid) == $(jq -er .target_namespace_uid "$checkpoint") ]] || fail 'restore namespace identity changed'
 current=$(lease_read)
 [[ $(jq -r .spec.holderIdentity <<< "$current") == "$RESUME_ID" ]] || fail 'restore-repair does not own the named operation'
 age=$(jq -r 'now-(.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$current")
 (( age >= 180 )) || lease_still_live 'the previous restore installer' "$age"
 OPERATION=$RESUME_ID
 restore_program_validate "$current"
 jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
 LEASE_ACQUIRED=true; rm -f "$STATE_DIR/lease-lost"; start_renewal
 restore_program_validate "$(lease_read)"
 restore_program_publish
}
restore_application_evidence() {
 # Read-only; $1 is the Lease as read. Every refusal precedes any write. Sets
 # RESTORE_FAILED_* only when the pointer revision is this operation's failure.
 local current=$1 saved="$STATE_DIR/restore-$OPERATION" apps="$STATE_DIR/helm-applications/$OPERATION" w="$GSJ_WORK/restore-application"
 local repair="repair --operation $OPERATION --config $CONFIG --non-interactive" pointer revision state rc written=false pull kind name directory file attempt pod object uid key claim claims
 local unread="restore evidence could not be read; rerun $repair once the Kubernetes API answers"
 rm -rf "$w"; mkdir -m 700 "$w"
 k get jobs -l "app.kubernetes.io/instance=$RELEASE" -o json > "$w/jobs.json" || { RECOVERY_HINT=$repair; fail "$unread"; }
 jq -e 'all(.items[];(.status.active//0)==0)' "$w/jobs.json" >/dev/null || { RECOVERY_HINT=$repair; fail "the failed revision's provisioning Job is still active; wait until it completes or fails (activeDeadlineSeconds), then rerun $repair"; }
 pointer=$(jq -er '.helm_application|select(type=="string" and test("^[a-f0-9]{24}$"))' "$STATE_DIR/operation.json") || restore_fresh_fail 'the application phase has no durable Helm target'
 [[ ! -L $STATE_DIR/helm-applications && ! -L $apps && -d $apps/$pointer && ! -L $apps/$pointer && -f $apps/$pointer/intent.json && ! -L $apps/$pointer/intent.json ]] || restore_fresh_fail 'the saved Helm target is not ordinary state'
 revision=$(jq -er '.revision|select(type=="number" and .==floor and .>0)' "$apps/$pointer/intent.json") || restore_fresh_fail 'the saved Helm target has no revision'
 k get secrets,configmaps -l "owner=helm,name=$RELEASE" -o json > "$w/history-private.json" || { RECOVERY_HINT=$repair; fail "$unread"; }
 state=$(jq -r --arg r "$revision" '[.items[]|select(.metadata.labels.version==$r)]|if length==0 then "absent" elif length==1 then (.[0].metadata.labels.status//"") else "ambiguous" end' "$w/history-private.json")
 RESTORE_FAILED_ATTEMPT=''; RESTORE_FAILED_REVISION=''; RESTORE_FAILED_SECRET_UID=''
 case "$state" in
   failed) RESTORE_FAILED_ATTEMPT=$pointer; RESTORE_FAILED_REVISION=$revision
     RESTORE_FAILED_SECRET_UID=$(jq -er --arg r "$revision" '.items[]|select(.metadata.labels.version==$r)|.metadata.uid|select(type=="string" and length>0)' "$w/history-private.json") || restore_fresh_fail 'the failed Helm revision has no stable identity';;
   absent) ;;
   deployed) fail "the restored application Helm revision $revision completed; use resume --operation $OPERATION with this installer";;
   pending-*) restore_fresh_fail "Helm revision $revision is pending: a Helm client stopped mid-write, and a pending revision has no continuation";;
   *) restore_fresh_fail "Helm revision $revision is '$state', not a failed or unwritten attempt of this operation";;
 esac
 if [[ -n $RESTORE_FAILED_ATTEMPT ]] || jq -e '(.helm_application_history//[])|length>0' "$STATE_DIR/operation.json" >/dev/null; then written=true; fi
 # Identity runs with errexit in a subshell. A named refusal marks itself
 # before it exits; any other exit is a read that did not complete, not drift.
 # Local evidence is never retried: every read of it refuses explicitly.
 set +e
 (
   set -e
   fail() { printf 'GSJ: %s\n' "$*" >&2; : > "$w/refused"; exit 1; }
   [[ -d $saved && ! -L $saved ]] || fail 'restore evidence is not ordinary state'
   [[ -f $STATE_DIR/restoration.json && ! -L $STATE_DIR/restoration.json ]] || fail 'the restore checkpoint is not an ordinary file'
   jq -e --arg op "$OPERATION" --arg target "$RELEASE_ID" '.format=="gsj.restore/1" and .operation==$op and .release_identity==$target and .status=="files-restored"' "$STATE_DIR/restoration.json" >/dev/null || fail 'the restore checkpoint differs'
   uid=$(k get namespace "$NAMESPACE" -o json --ignore-not-found | jq -r '.metadata.uid // empty')
   [[ $uid == $(jq -er .target_namespace_uid "$STATE_DIR/restoration.json") ]] || fail 'restore target namespace identity changed'
   restore_original_evidence "$current"
   # restore_bindings mixes each claim's local create receipt with API reads:
   # a missing receipt is local damage, refused here rather than retried.
   for key in forgejo data chroma; do
     claim=$(jq -r --arg key "$key" '.storage[$key].existingClaim' "$GSJ_WORK/values.pending.json"); claim=${claim:-$RELEASE-$key}
     file="$saved/PersistentVolumeClaim/$claim/receipt.json"
     [[ -f $file && ! -L $file ]] && jq -e '.uid|type=="string" and length>0' "$file" >/dev/null || fail "restored claim $claim has no readable create receipt"
   done
   restore_bindings
   file="$STATE_DIR/capacity-$OPERATION-before.json"
   [[ -f $file && ! -L $file ]] || fail 'the recorded pre-startup capacity pass is missing'
   jq -e --arg op "$OPERATION" --arg files "$(sha_file "$saved/files-result.json")" --arg bindings "$(sha_file "$saved/bindings.json")" --slurpfile checkpoint "$STATE_DIR/restoration.json" '
     .format=="gsj.capacity/1" and .status=="passed" and .purpose=="restored-files-before-startup" and .operation==$op and
     .namespace_uid==$checkpoint[0].target_namespace_uid and .restoration.operation==$op and .restoration.archive_sha256==$checkpoint[0].archive_sha256 and
     .restoration.files_result_sha256==$files and .restoration.bindings_sha256==$bindings
   ' "$file" >/dev/null || fail 'the recorded pre-startup capacity pass did not pass for these restored files and bindings'
   # Restored resources keep their receipt UID, restore metadata and archived
   # bytes; the trust bundle (secret_inputs) and chart-owned scripts by identity.
   # A restore-program receipt lists the resources its program proved at
   # takeover, each needing its saved directory; without a receipt, every saved
   # directory is a restored resource.
   if [[ -e $saved/program-transition.json || -L $saved/program-transition.json ]]; then
     [[ -f $saved/program-transition.json && ! -L $saved/program-transition.json ]] && jq -e '.restored_resources|type=="array" and length>0 and all(.[]; type=="object" and (.kind|type)=="string" and (.name|type)=="string")' "$saved/program-transition.json" >/dev/null || fail 'the restore program receipt lists no restored resources'
     jq -r '.restored_resources[]|[.kind,.name]|@tsv' "$saved/program-transition.json" > "$w/resources.tsv"
   else
     : > "$w/resources.tsv"
     for kind in Secret ConfigMap PersistentVolumeClaim; do
       [[ -d $saved/$kind && ! -L $saved/$kind ]] || fail 'restored resource evidence is not ordinary state'
       for directory in "$saved/$kind"/*; do printf '%s\t%s\n' "$kind" "${directory##*/}" >> "$w/resources.tsv"; done
     done
   fi
   : > "$w/inventory.jsonl"; : > "$w/ancestry-private.jsonl"
   while IFS=$'\t' read -r kind name; do
     directory="$saved/$kind/$name"
     [[ $kind =~ ^(Secret|ConfigMap|PersistentVolumeClaim)$ && $name =~ ^[a-z0-9][a-z0-9.-]*$ && -d $saved/$kind && ! -L $saved/$kind && -d $directory && ! -L $directory ]] || fail 'restored resource evidence is not ordinary state'
     for file in intent.json attempt.json receipt.json; do [[ -f $directory/$file && ! -L $directory/$file ]] || fail 'restored resource identity evidence is incomplete'; done
     jq -e --arg sha "$(sha_file "$directory/intent.json")" '.attempted==true and .intent_sha256==$sha' "$directory/attempt.json" >/dev/null && jq -e --arg sha "$(sha_file "$directory/intent.json")" '.intent_sha256==$sha and (.uid|type=="string" and length>0)' "$directory/receipt.json" >/dev/null || fail 'restored resource create evidence differs'
     jq -cn --arg kind "$kind" --arg name "$name" --arg uid "$(jq -r .uid "$directory/receipt.json")" --arg intent "$(sha_file "$directory/intent.json")" --arg receipt "$(sha_file "$directory/receipt.json")" '{kind:$kind,name:$name,uid:$uid,intent_sha256:$intent,receipt_sha256:$receipt}' >> "$w/inventory.jsonl"
     if jq -e --arg release "$RELEASE" '.kind=="Secret" and .metadata.labels.owner=="helm" and .metadata.labels.name==$release' "$directory/intent.json" >/dev/null; then
       jq -c --arg uid "$(jq -r .uid "$directory/receipt.json")" '{name:.metadata.name,uid:$uid,data,version:(.metadata.labels.version|tonumber),deployed:(.metadata.labels.status=="deployed")}' "$directory/intent.json" >> "$w/ancestry-private.jsonl" || fail 'restored Helm history evidence is malformed'
       continue
     fi
     object=$(k get "$kind" "$name" -o json --ignore-not-found)
     jq -e --arg op "$OPERATION" --arg uid "$(jq -r .uid "$directory/receipt.json")" --arg archive "$(jq -r .archive_sha256 "$STATE_DIR/restoration.json")" --arg scripts "$RELEASE-scripts" --arg trust "$RELEASE-trust" --slurpfile intent "$directory/intent.json" '
       .metadata.uid==$uid and .metadata.deletionTimestamp==null and
       .metadata.labels["gsj.io/restore-operation"]==$op and .metadata.annotations["gsj.io/restore-archive-sha256"]==$archive and
       (if .kind=="Secret" then {data,type,immutable}==($intent[0]|{data,type,immutable})
        elif .kind=="ConfigMap" and (.metadata.name|IN($scripts,$trust)|not) then {data,binaryData,immutable}==($intent[0]|{data,binaryData,immutable})
        else true end)
     ' <<< "${object:-null}" >/dev/null || fail "restored $kind $name identity or bytes changed"
   done < "$w/resources.tsv"
   jq -s 'sort_by(.kind,.name)' "$w/inventory.jsonl" > "$w/inventory.json"
   jq -s . "$w/ancestry-private.jsonl" > "$w/ancestry-private.json"
   pod=$(jq -er '.pod|select(type=="string" and length>0)' "$STATE_DIR/restoration.json") || fail 'the restore checkpoint names no maintenance Pod'
   object=$(k get pod "$pod" -o json --ignore-not-found)
   [[ -z $object ]] || fail 'the restore maintenance Pod still exists'
   if [[ -e $saved/program-transition.json || -L $saved/program-transition.json ]]; then
     [[ ! -L $saved/program-predecessor ]] || fail 'restore program evidence is not ordinary state'
     for file in program-transition.json program-original-restoration.json program-original-operation.json program-predecessor/gsj-install.sh; do [[ -f $saved/$file && ! -L $saved/$file ]] || fail 'restore program receipt evidence is incomplete'; done
     cmp -s "$STATE_DIR/restoration.json" "$saved/program-original-restoration.json" || fail 'the restore checkpoint changed after the program transition'
     jq -e --arg op "$OPERATION" --arg program "${RESTORE_PROGRAM_ID:-}" --arg target "$RELEASE_ID" \
       --arg program_manifest "$(sha_file "$GSJ_WORK/restore-program/program-release.json")" --arg installer "$(sha_file "$saved/program-predecessor/gsj-install.sh")" \
       --arg manifest "$(sha_file "$GSJ_PAYLOAD/release.json")" --arg original "$(sha_file "$STATE_DIR/operation-intents/$OPERATION/intent.json")" \
       --arg checkpoint "$(sha_file "$STATE_DIR/restoration.json")" --arg operation "$(sha_file "$saved/program-original-operation.json")" \
       --arg site "$(sha_file "$SITE")" --arg values "$(sha_file "$GSJ_WORK/values.pending.json")" --arg settings "$(sha_file "$saved/files-settings.json")" \
       --arg result "$(sha_file "$saved/files-result.json")" --arg proof "$(sha_file "$saved/archive-proof.json")" --argjson lease "$current" \
       --slurpfile restore "$STATE_DIR/restoration.json" --slurpfile bindings "$saved/bindings.json" --slurpfile resources "$w/inventory.json" '
       .format=="gsj.restore-program-transition/1" and .operation==$op and .program==$program and .previous_program==$target and .target==$target and .status=="files-restored-before-helm" and
       .program_manifest_sha256==$program_manifest and .source_installer_sha256==$installer and .target_manifest_sha256==$manifest and
       .original_intent_sha256==$original and .original_checkpoint_sha256==$checkpoint and .original_operation_sha256==$operation and
       .site_sha256==$site and .values_sha256==$values and .file_settings_sha256==$settings and .file_result_sha256==$result and .archive_proof_sha256==$proof and
       ({source_namespace_uid,target_namespace_uid,archive_sha256,resources_sha256,metadata_sha256}==($restore[0]|{source_namespace_uid,target_namespace_uid,archive_sha256,resources_sha256,metadata_sha256})) and
       .storage==$bindings[0] and .restored_resources==$resources[0] and
       .lease=={uid:$lease.metadata.uid,holder:$lease.spec.holderIdentity,acquire_time:$lease.spec.acquireTime,annotations:($lease.metadata.annotations//{})}
     ' "$saved/program-transition.json" >/dev/null || fail 'restore program receipt no longer matches the preserved evidence'
   fi
   # This operation's Helm attempts: the pointer and every recorded failure.
   jq -e '(.helm_application_history//[]) as $h | ($h|type)=="array" and all($h[]; (.attempt|type=="string" and test("^[a-f0-9]{24}$")) and (.revision|type=="number") and (.release_secret_uid|type=="string" and length>0) and .status=="failed") and ([$h[].attempt]|length==(unique|length))' "$STATE_DIR/operation.json" >/dev/null || fail 'recorded failed Helm attempts are malformed'
   : > "$w/attempts.jsonl"
   for attempt in $(jq -r '[.helm_application,(.helm_application_history//[])[].attempt]|unique[]' "$STATE_DIR/operation.json"); do
     directory="$apps/$attempt"
     [[ -d $directory && ! -L $directory ]] || fail 'a recorded Helm attempt is not ordinary state'
     for file in intent.json values.json expected.json; do [[ -f $directory/$file && ! -L $directory/$file ]] || fail 'a recorded Helm attempt is incomplete'; done
     jq -e --arg op "$OPERATION" --arg attempt "$attempt" --arg target "$RELEASE_ID" --arg ns "$NAMESPACE" --arg release "$RELEASE" --arg chart "$(sha_file "$GSJ_PAYLOAD/chart.tgz")" --arg values "$(sha_file "$directory/values.json")" --arg expected "$(sha_file "$directory/expected.json")" --slurpfile checkpoint "$STATE_DIR/restoration.json" '
       .format=="gsj.helm-application/1" and .operation==$op and .attempt==$attempt and .target==$target and .namespace==$ns and .release==$release and
       .namespace_uid==$checkpoint[0].target_namespace_uid and .chart_sha256==$chart and .values_sha256==$values and .expected_sha256==$expected and
       (.revision|type=="number" and .==floor and .>0)
     ' "$directory/intent.json" >/dev/null || fail 'a recorded Helm attempt belongs to another target, chart or configuration'
     cmp -s "$directory/values.json" "$GSJ_WORK/values.pending.json" || fail 'a recorded Helm attempt used other values'
     jq -c '{attempt,revision}' "$directory/intent.json" >> "$w/attempts.jsonl"
   done
   jq -s 'map({key:.attempt,value:.revision})|from_entries' "$w/attempts.jsonl" > "$w/attempts.json"
   jq -e --arg pointer "$pointer" --arg failed "$RESTORE_FAILED_SECRET_UID" --slurpfile op "$STATE_DIR/operation.json" --slurpfile revisions "$w/attempts.json" --slurpfile ancestry "$w/ancestry-private.json" '
     $revisions[0] as $rev | $rev[$pointer] as $r | ($op[0].helm_application_history//[]) as $h |
     # Recorded failures precede the pointer, which is recorded only as its live failure.
     all($h[]; .revision==$rev[.attempt] and (if .attempt==$pointer then $failed!="" and .release_secret_uid==$failed else .revision<$r end)) and
     # Live history: restored ancestry by UID and bytes, or failed attempts of this operation.
     all(.items[]; . as $s | .kind=="Secret" and .type=="helm.sh/release.v1" and ((.metadata.labels.version//"")|test("^[1-9][0-9]*$")) and
       ((.metadata.labels.version|tonumber) as $v |
        any($ancestry[0][]; .name==$s.metadata.name and .uid==$s.metadata.uid and .data==$s.data and .version==$v) or
        ($v==$r and $failed!="" and $s.metadata.uid==$failed and $s.metadata.labels.status=="failed") or
        any($h[]; .attempt!=$pointer and .revision==$v and .release_secret_uid==$s.metadata.uid and $s.metadata.labels.status=="failed"))) and
     # Helm prunes old revisions (history-max 10) but never the last deployed one.
     (([$ancestry[0][]|select(.deployed)]|max_by(.version)) as $d | $d==null or any(.items[]; .metadata.name==$d.name and .metadata.uid==$d.uid))
   ' "$w/history-private.json" >/dev/null || fail "Helm history holds records outside the restored ancestry and this operation's attempts"
   if [[ -n $RESTORE_FAILED_ATTEMPT ]]; then
     jq --arg r "$revision" '.items[]|select(.metadata.labels.version==$r)' "$w/history-private.json" > "$w/failed-secret-private.json"
     addon_release_decode "$w/failed-secret-private.json" "$w/failed-release-private.json"
     require_offline_render; KUBECONFIG=/dev/null HELM_DRIVER=secret helm install "$RELEASE" "$GSJ_PAYLOAD/chart.tgz" --namespace "$NAMESPACE" --values "$apps/$pointer/values.json" --dry-run=client --output json > "$w/signed-target-private.json"
     jq -e --arg name "$RELEASE" --arg ns "$NAMESPACE" --argjson revision "$revision" --slurpfile signed "$w/signed-target-private.json" '.name==$name and .namespace==$ns and .version==$revision and .info.status=="failed" and (.chart|del(.modtime,.schemamodtime))==($signed[0].chart|del(.modtime,.schemamodtime)) and .config==$signed[0].config' "$w/failed-release-private.json" >/dev/null || fail 'the failed Helm revision is not the signed chart and configuration of this operation'
   fi
   # Writers: only the release Deployments (after a Helm write), their
   # ReplicaSets and the provisioning Job may exist or mount restored claims.
   k get deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs -o json > "$w/controllers.json"
   k get pods -o json > "$w/pods.json"
   claims=$(jq -ce '[.references.PersistentVolumeClaim[]?]|select(length>0 and all(.[]; type=="string"))' "$STATE_DIR/restoration.json") || fail 'the restore checkpoint names no restored claims'
   jq -e --arg release "$RELEASE" --arg ns "$NAMESPACE" --argjson written "$written" --argjson claims "$claims" --slurpfile pods "$w/pods.json" '
     def mounts: [(.spec.template.spec.volumes, .spec.jobTemplate.spec.template.spec.volumes, .spec.volumes)[]?.persistentVolumeClaim.claimName] | any(.[]; . as $n | $claims|index($n));
     def ran: .state.running!=null or .state.terminated!=null or .lastState.terminated!=null;
     [.items[]|select(.kind=="Deployment" and $written and (.metadata.name|IN($release+"-web",$release+"-forgejo",$release+"-chroma")) and
       .metadata.annotations["meta.helm.sh/release-name"]==$release and .metadata.annotations["meta.helm.sh/release-namespace"]==$ns)|.metadata.uid] as $deployments |
     [.items[]|select(.kind=="ReplicaSet" and any(.metadata.ownerReferences[]?; .kind=="Deployment" and (.uid|IN($deployments[]))))|.metadata.uid] as $sets |
     [.items[]|select(.kind=="Job" and $written and .metadata.name==($release+"-provision"))|.metadata.uid] as $jobs |
     all(.items[]; (.metadata.labels["app.kubernetes.io/instance"]!=$release and (mounts|not)) or (.metadata.uid|IN($deployments[],$sets[],$jobs[]))) and
     all($pods[0].items[]; (mounts|not) or any(.metadata.ownerReferences[]?; .uid|IN($sets[],$jobs[]))) and
     all($pods[0].items[]|select(.metadata.labels["app.kubernetes.io/instance"]==$release and .metadata.labels["app.kubernetes.io/component"]=="gsj");
       all(.status.containerStatuses[]?; ran|not) and all(.status.initContainerStatuses[]?|select(.name!="wait-deps"); ran|not))
   ' "$w/controllers.json" >/dev/null || fail 'a writer outside the failed revision mounts the restored claims, or the GSJ application or its initializers already ran'
 )
 rc=$?; set -e
 [[ ! -e $w/refused ]] || restore_fresh_fail "restored identity, evidence or Helm history does not match this operation's recorded writes"
 (( rc == 0 )) || { RECOVERY_HINT=$repair; fail "$unread (exit $rc)"; }
 pull=$(jq -r --arg release "$RELEASE" '[.items[]|select(.metadata.labels["app.kubernetes.io/instance"]==$release)|.metadata.name as $pod|(.status.initContainerStatuses[]?,.status.containerStatuses[]?)|select((.state.waiting.reason//"")|IN("ErrImagePull","ImagePullBackOff","InvalidImageName"))|"\($pod)/\(.name) (\(.state.waiting.reason))"][0]//empty' "$w/pods.json")
 [[ -z $pull ]] || { RECOVERY_HINT=$repair; fail "image pull is failing for $pull; repair never changes restored pull credentials: fix registry reachability, mirrors or the node image cache, let the kubelet retry, then rerun $repair"; }
}
restore_application_repair() {
 # repair_operation proved the Lease holder, its 180 s silence and this saved
 # operation. Re-apply the same signed chart and values of a restore whose
 # application Helm revision failed; nothing restored is recreated or rotated.
 local current=$1 status reapplied owner='this installer'
 OPERATION=$RESUME_ID
 [[ $OPERATION =~ ^[a-f0-9]{24}$ ]] || fail 'restore application repair requires the saved restore operation ID'
 [[ -z ${BACKUP_ROUND:-} && -z ${CONTINUE_HELM_INSTALLER:-} ]] || fail 'restore application repair cannot select a backup round or startup Helm continuation'
 jq -e --arg target "$RELEASE_ID" '.target==$target' "$STATE_DIR/operation.json" >/dev/null || fail 'restore application repair requires the exact recorded target release'
 # A corrected program without a recorded transition does not own this restore.
 [[ ${RESTORE_PROGRAM_ACTIVE:-false} != true || -f $STATE_DIR/restore-$OPERATION/program-transition.json ]] || owner='its exact source installer'
 status=$(jq -r .status "$STATE_DIR/operation.json")
 case "$status" in
   applying) ;;
   initializing|verifying) fail "the restored application Helm revision completed; use resume --operation $OPERATION with $owner";;
   complete) fail "the restore is complete; use resume --operation $OPERATION with $owner, which finishes the operation and releases its Lease";;
   owned|restoring-resources|restoring-files|restore-files-verified) fail "the restore has not started its application; use restore-repair --operation $OPERATION";;
   *) fail "restore stopped in $status; inspect saved state";;
 esac
 [[ $owner == 'this installer' ]] || fail 'a corrected program without a recorded restore-program transition can take over a restore only before application startup (restore-repair --source-installer); repair this restore with its exact source installer'
 retained_site_matches "$SITE" "$STATE_DIR/site.pending.json" || fail 'restore repair configuration changed'
 restore_application_evidence "$current"
 jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
 LEASE_ACQUIRED=true; rm -f "$STATE_DIR/lease-lost"; start_renewal
 current=$(lease_read) || { RECOVERY_HINT="repair --operation $OPERATION --config $CONFIG --non-interactive"; fail "the renewed operation Lease could not be read; rerun repair --operation $OPERATION once the Kubernetes API answers"; }
 restore_application_evidence "$current"
 reapplied='whose last Helm attempt was never written'
 if [[ -n $RESTORE_FAILED_ATTEMPT ]]; then
   assert_owner
   jq --arg attempt "$RESTORE_FAILED_ATTEMPT" --argjson revision "$RESTORE_FAILED_REVISION" --arg uid "$RESTORE_FAILED_SECRET_UID" 'if any((.helm_application_history//[])[]; .attempt==$attempt) then . else .helm_application_history=((.helm_application_history//[])+[{attempt:$attempt,revision:$revision,release_secret_uid:$uid,status:"failed"}]) end' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
   reapplied="after failed Helm revision $RESTORE_FAILED_REVISION"
 fi
 log "Re-applying restore target $RELEASE_ID $reapplied; restored credentials and claim identities are unchanged; Forgejo, Chroma and the provisioning Job of a failed revision may already have run on the restored claims; the GSJ application and its corpus initializers never started (only wait-deps may have run); capacity was measured before startup"
 secret_inputs; relocated_images_probe; helm_apply; stage_vectors; wait_application; record_ready; verify_application; record_installed
}
restore_archive() {
 local recovering=false new_checkpoint=false
 if [[ $COMMAND == restore-repair ]]; then
   restore_program_select
   recovering=true
   if [[ ! -e $STATE_DIR/restoration.json && ! -L $STATE_DIR/restoration.json ]]; then
     # The Lease may have committed before local restore bookkeeping. Its
     # signed-release-bound intent already identifies the exact archive.
     recover_operation_intent "$RESUME_ID" validate
     jq -e '.kind=="restore" and .status=="owned"' "$GSJ_WORK/recovered-operation.json" >/dev/null || fail 'operation intent is not an unstarted restore'
     ARCHIVE=$(jq -er .archive.path "$STATE_DIR/operation-intents/$RESUME_ID/intent.json")
     new_checkpoint=true
   else
     [[ -f $STATE_DIR/restoration.json && ! -L $STATE_DIR/restoration.json ]] || fail 'restore checkpoint is not an ordinary file'
     [[ -z $ARCHIVE || $ARCHIVE == $(jq -r .archive "$STATE_DIR/restoration.json") ]] || fail 'restore repair cannot select another archive'
     ARCHIVE=$(jq -r .archive "$STATE_DIR/restoration.json")
   fi
 else
   [[ ! -e $STATE_DIR/restoration.json && ! -L $STATE_DIR/restoration.json ]] || fail 'restore checkpoint already exists; use restore-repair --operation ID for its recorded resource/file phase or resume for application startup'
 fi
 [[ -n $ARCHIVE ]] || fail 'restore requires --archive BACKUP.tar.gz.enc'
 ARCHIVE="$(cd -- "$(dirname -- "$ARCHIVE")" && pwd -P)/$(basename -- "$ARCHIVE")"
 local metadata="$ARCHIVE.json" resources pod image expected kind name object role claim file key recovered mode value_name backup_auth_destination_changed=false
 [[ -f $metadata && -f $ARCHIVE.resources.enc ]] || fail 'backup manifest and encrypted resource metadata are required'
 jq -e '.format=="gsj.backup/1" and .verified==true and (.sha256|test("^[a-f0-9]{64}$")) and (.resources_sha256|test("^[a-f0-9]{64}$"))' "$metadata" >/dev/null || fail 'unverified backup metadata'
 [[ $(sha_file "$ARCHIVE") == $(jq -r .sha256 "$metadata") && $(sha_file "$ARCHIVE.resources.enc") == $(jq -r .resources_sha256 "$metadata") ]] || fail 'backup transport integrity failed'
 if $recovering && ! $new_checkpoint; then
   jq -e --arg sha "$(sha_file "$ARCHIVE")" --arg resources "$(sha_file "$ARCHIVE.resources.enc")" --arg metadata "$(sha_file "$metadata")" '.archive_sha256==$sha and .resources_sha256==$resources and .metadata_sha256==$metadata' "$STATE_DIR/restoration.json" >/dev/null || fail 'restore repair archive or recovery metadata changed'
 fi
 expected=$(jq -r .release_identity "$metadata"); [[ $expected == "$RELEASE_ID" ]] || fail 'restore must use the exact source release installer'
 resources=$(mktemp -d "$GSJ_WORK/restored-resources.XXXXXXXX")
 openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$BACKUP_PASSWORD" -in "$ARCHIVE.resources.enc" -out "$GSJ_WORK/resources.tar.gz"
 # Check both names and types. Allowed names alone still admit hard/symbolic
 # links and device entries. BusyBox prints hard links with a '-' prefix plus
 # an arrow, so type prefixes alone are insufficient across supported tools.
 tar -tzf "$GSJ_WORK/resources.tar.gz" | LC_ALL=C sort > "$GSJ_WORK/resource-members"
 printf '%s\n' cluster-private.json controllers.json installed.json site.pending.json site_inputs.json volumes-private.json | LC_ALL=C sort > "$GSJ_WORK/expected-members"
 cmp "$GSJ_WORK/resource-members" "$GSJ_WORK/expected-members" >/dev/null || fail 'backup resource archive has unexpected paths'
 LC_ALL=C tar -tvzf "$GSJ_WORK/resources.tar.gz" | awk 'substr($0,1,1)!="-" || index($0," -> ") || index($0," link to ") {bad=1} END {exit bad}' || fail 'backup resource archive must contain regular files only'
 tar -xzf "$GSJ_WORK/resources.tar.gz" -C "$resources" --no-same-owner
 chmod 600 "$resources/"*.json
 # An identity string alone cannot authorize a different core, model, schema,
 # image or corpus. Restore uses precisely the archived immutable release.
 jq -e --slurpfile release "$GSJ_PAYLOAD/release.json" --arg name "$RELEASE" --arg ns "$NAMESPACE" '.format=="gsj.installed/1" and .manifest==$release[0] and .site.schema_version=="gsj.site/1" and .site.target.release==$name and .site.target.namespace==$ns' "$resources/installed.json" >/dev/null || fail 'backup release/core/model/configuration schema differs from this installer'
 jq '.site' "$resources/installed.json" | jq --slurpfile schema "$GSJ_PAYLOAD/site.schema.json" -f "$GSJ_PAYLOAD/validate.jq" > "$GSJ_WORK/restore-source-site.json"
 jq -e --slurpfile target "$SITE" '.tls.profile==$target[0].tls.profile' "$GSJ_WORK/restore-source-site.json" >/dev/null || fail 'restore cannot change ownership of the TLS profile'
 jq -e --slurpfile target "$SITE" '
   def acme: {tls:(.tls|{issuer,email,acme_server,secret}),ingress_class:.ingress.class};
   .tls.profile!="managed-acme" or (acme==($target[0]|acme))
 ' "$GSJ_WORK/restore-source-site.json" >/dev/null || fail 'restore cannot change the ACME account, issuer or solver identity'
 jq --slurpfile release "$GSJ_PAYLOAD/release.json" -f "$GSJ_PAYLOAD/compile.jq" "$GSJ_WORK/restore-source-site.json" > "$GSJ_WORK/restore-source-values.json"
 # Context, node and StorageClass may relocate. Account, endpoint/model/auth,
 # trust, public host, and typed resource references must retain their identity.
 jq -e --slurpfile target "$GSJ_WORK/values.pending.json" '
   def identities: {fullnameOverride,operator,llm,ocr,selfhostedKey,trust,pulls:.image.pullSecrets,tls:.ingress.tls,host:.ingress.host,
     claims:(. as $v | ["data","forgejo","chroma"] | map(. as $role | $v.storage[$role].existingClaim | if .=="" then $v.fullnameOverride+"-"+$role else . end))};
   identities == ($target[0]|identities)' "$GSJ_WORK/restore-source-values.json" >/dev/null || fail 'restore target changes an account, inference/trust setting or resource reference'
 jq --arg release "$RELEASE" --slurpfile site "$GSJ_WORK/restore-source-site.json" '$site[0] as $s | {
   Secret:([$release+"-admin-token",$release+"-agent-token",$release+"-webhook",.operator.existingSecret,.selfhostedKey.existingSecret,.ocr.existingSecret,.image.pullSecrets[],.ingress.tls[].secretName,.trust.proxySecret,(if $s.tls.profile=="managed-acme" then $s.tls.issuer+"-account" else "" end)]|map(select(.!=""))|unique),
   ConfigMap:([$release+"-provisioned",.trust.caConfigMap,(if $s.tls.profile=="managed-acme" then $release+"-acme-owner" else "" end)]|map(select(.!=""))|unique),
   Issuer:(if $s.tls.profile=="managed-acme" then [$s.tls.issuer] else [] end),
   Certificate:(if $s.tls.profile=="managed-acme" then [$s.tls.secret] else [] end),
   PersistentVolumeClaim:(. as $v|["data","forgejo","chroma"]|map(. as $role|$v.storage[$role].existingClaim|if .=="" then $release+"-"+$role else . end))
 }' "$GSJ_WORK/restore-source-values.json" > "$GSJ_WORK/restore-references.json"
 jq -e --arg ns "$NAMESPACE" --arg release "$RELEASE" --slurpfile refs "$GSJ_WORK/restore-references.json" --slurpfile installed "$resources/installed.json" '
   .kind=="List" and (.items|type=="array") and
   ([.items[]|.kind+"/"+.metadata.name]|length== (unique|length)) and
   all(.items[]; .kind as $k|["Secret","ConfigMap","PersistentVolumeClaim","Service","Ingress","ServiceAccount","Role","RoleBinding","Deployment","NetworkPolicy","Issuer","Certificate"]|index($k)) and
   all(.items[]; (.metadata.namespace // $ns)==$ns and (.metadata.name|test("^[a-z0-9][a-z0-9.-]*$"))) and
   all(.items[]|select(.kind=="Secret"); .metadata.name as $n|($refs[0].Secret|index($n))!=null or (.metadata.labels.owner=="helm" and .metadata.labels.name==$release)) and
   all(.items[]|select(.kind=="ConfigMap"); .metadata.name as $n|($refs[0].ConfigMap|index($n))!=null or .metadata.labels["app.kubernetes.io/instance"]==$release or .metadata.labels["gsj.io/owner"]==$release) and
   ([.items[]|select(.kind=="Secret")|.metadata.name] as $names|all($refs[0].Secret[]; . as $n|($names|index($n))!=null)) and
   ([.items[]|select(.kind=="ConfigMap")|.metadata.name] as $names|all($refs[0].ConfigMap[]; . as $n|($names|index($n))!=null)) and
   ([.items[]|select(.kind=="Issuer")|.metadata.name]|sort)==($refs[0].Issuer|sort) and
   ([.items[]|select(.kind=="Certificate")|.metadata.name]|sort)==($refs[0].Certificate|sort) and
   ([.items[]|select(.kind=="PersistentVolumeClaim")|{name:.metadata.name,uid:.metadata.uid,volume:.spec.volumeName}]|sort_by(.name)) == ($installed[0].storage|map({name,uid,volume})|sort_by(.name)) and
   ([.items[]|select(.kind=="PersistentVolumeClaim")|.metadata.name]|sort)==($refs[0].PersistentVolumeClaim|sort) and ($refs[0].PersistentVolumeClaim|unique|length)==3
 ' "$resources/cluster-private.json" >/dev/null || fail 'backup has missing, duplicate, foreign or inconsistent resource identities'
 if [[ $(j .tls.profile) == managed-acme ]]; then
   acme_validate_bundle "$GSJ_WORK/restore-source-site.json" "$(jq -r .namespace_uid "$resources/installed.json")" "$resources/cluster-private.json"
 fi
 jq '.items |= map(select(.kind=="Secret" or .kind=="ConfigMap") | del(.metadata.uid,.metadata.resourceVersion,.metadata.creationTimestamp,.metadata.managedFields,.metadata.ownerReferences,.metadata.generation,.metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]))' "$resources/cluster-private.json" > "$GSJ_WORK/restorable-secrets.json"
 jq --arg class "$(j .storage.class)" '.items |= map(select(.kind=="PersistentVolumeClaim") | del(.metadata.uid,.metadata.resourceVersion,.metadata.creationTimestamp,.metadata.managedFields,.metadata.ownerReferences,.metadata.annotations,.status,.spec.volumeName,.spec.dataSource,.spec.dataSourceRef) | .spec.storageClassName=$class)' "$resources/cluster-private.json" > "$GSJ_WORK/restorable-claims.json"
 jq -e '
   .format=="gsj.site-inputs/1" and (.entries|type=="array") and
   ([.entries[].name]|length==(unique|length)) and
   all(.entries[]; (.name as $n|["operator.password_file","llm.credential.file","ocr.credential.file","registry.config_file","tls.certificate_file","tls.private_key_file","tls.ca_file","trust.ca_file","trust.proxy_file","verification.ca_file","delivery.ca_file","delivery.auth_header_file","backup.ca_file","backup.auth_header_file","managed_tls.ca.key","managed_tls.ca.crt"]|index($n))!=null and
     (.data|type=="string" and test("^[A-Za-z0-9+/]*={0,2}$")) and (.mode|type=="number" and floor==. and .>=0 and .<=511))
 ' "$resources/site_inputs.json" >/dev/null || fail 'backup protected-input inventory is invalid'
 if [[ $(jq -r '.backup.offbox_url // ""' "$GSJ_WORK/restore-source-site.json") != "$(j .backup.offbox_url)" ]]; then
   backup_auth_destination_changed=true
 fi
 mkdir -p "$GSJ_WORK/restore-inputs"; : > "$GSJ_WORK/restore-inputs.jsonl"
 # Stage and compare every explicit input before any Kubernetes mutation.
 # Snapshot entries preserve exact bytes/modes. Typed cluster references are
 # the fallback for credentials, registry, proxy, TLS, and the public CA bundle.
 for value_name in operator.password_file llm.credential.file ocr.credential.file registry.config_file tls.certificate_file tls.private_key_file tls.ca_file trust.ca_file trust.proxy_file verification.ca_file delivery.ca_file delivery.auth_header_file backup.ca_file backup.auth_header_file managed_tls.ca.key managed_tls.ca.crt; do
   case "$value_name" in
     managed_tls.*)
       [[ $(j .tls.profile) == managed-local-ca ]] || continue
       file="$STATE_DIR/tls/${value_name#managed_tls.}";;
     *) file=$(jq -r --arg name "$value_name" 'getpath($name|split(".")) // ""' "$SITE"); [[ -n $file ]] || continue; file=$(resolve_file "$file");;
   esac
   jq -ne --arg path "$file" '$path|test("[\u0000-\u001f\u007f]")|not' >/dev/null || fail 'restore input path contains control characters'
   recovered="$GSJ_WORK/restore-inputs/$value_name"; mode=384; name=''; key=''
   case "$value_name" in
     operator.password_file) name=$(j .operator.secret); key=password;;
     llm.credential.file) name=$(jq -r .selfhostedKey.existingSecret "$GSJ_WORK/restore-source-values.json"); key=key;;
     ocr.credential.file) name=$(jq -r .ocr.existingSecret "$GSJ_WORK/restore-source-values.json"); key=key;;
     registry.config_file) name=$(j .registry.pull_secret); key=.dockerconfigjson;;
     tls.certificate_file) name=$(j .tls.secret); key=tls.crt;;
     tls.private_key_file) name=$(j .tls.secret); key=tls.key;;
   esac
   if [[ $value_name == backup.auth_header_file && $backup_auth_destination_changed == true ]]; then
     # A saved header is authorized for its saved destination only. A target
     # with a different destination must supply its own protected credential;
     # never recover or silently reuse the old destination's header there.
     [[ -f $file && ! -L $file ]] || fail 'backup destination changed; supply a different protected backup.auth_header_file before restoring'
     private_file "$file"
     if jq -e --arg name "$value_name" 'any(.entries[];.name==$name)' "$resources/site_inputs.json" >/dev/null; then
       jq -r --arg name "$value_name" '.entries[]|select(.name==$name)|.data' "$resources/site_inputs.json" | base64 --decode > "$GSJ_WORK/archived-backup-auth"
       if cmp -s "$file" "$GSJ_WORK/archived-backup-auth"; then
         fail 'backup destination changed; the archived authentication header cannot be reused for the new destination'
       fi
     fi
     cp "$file" "$recovered"
   elif jq -e --arg name "$value_name" 'any(.entries[];.name==$name)' "$resources/site_inputs.json" >/dev/null; then
     jq -r --arg name "$value_name" '.entries[]|select(.name==$name)|.data' "$resources/site_inputs.json" | base64 --decode > "$recovered"
     mode=$(jq -r --arg name "$value_name" '.entries[]|select(.name==$name)|.mode' "$resources/site_inputs.json")
   elif [[ -n $key ]]; then
     jq -er --arg name "$name" --arg key "$key" '.items[]|select(.kind=="Secret" and .metadata.name==$name)|.data[$key]' "$GSJ_WORK/restorable-secrets.json" | base64 --decode > "$recovered"
   elif [[ $value_name == trust.proxy_file ]]; then
     jq -e --arg name "$RELEASE-proxy" '.items[]|select(.kind=="Secret" and .metadata.name==$name)|.data|with_entries(.value|=@base64d)' "$GSJ_WORK/restorable-secrets.json" > "$recovered"
   elif [[ $value_name == trust.ca_file ]]; then
     jq -jer --arg name "$RELEASE-trust" '.items[]|select(.kind=="ConfigMap" and .metadata.name==$name)|.data["bundle.pem"]' "$GSJ_WORK/restorable-secrets.json" > "$recovered"
   elif [[ $value_name == tls.ca_file || $value_name == verification.ca_file ]] && jq -e 'any(.entries[];.name=="managed_tls.ca.crt")' "$resources/site_inputs.json" >/dev/null; then
     jq -r '.entries[]|select(.name=="managed_tls.ca.crt")|.data' "$resources/site_inputs.json" | base64 --decode > "$recovered"
   else
     fail 'backup cannot reconstruct a configured protected input'
   fi
   [[ -s $recovered ]] || fail 'restored protected input is empty'
   if [[ -n $key ]]; then
     jq -e --arg name "$name" --arg key "$key" --rawfile expected "$recovered" '.items[]|select(.kind=="Secret" and .metadata.name==$name)|.data[$key]==($expected|(if $key=="password" then sub("\\n+$";"") else . end)|@base64)' "$GSJ_WORK/restorable-secrets.json" >/dev/null || fail 'backup input differs from its actual credential Secret'
   fi
   if [[ $value_name == trust.proxy_file ]]; then
     jq --arg release "$RELEASE" '.NO_PROXY=((.NO_PROXY+",localhost,.localhost,127.0.0.1,.svc,.cluster.local,"+$release+"-forgejo,"+$release+"-chroma")|split(",")|map(select(.!=""))|unique|join(","))' "$recovered" > "$GSJ_WORK/restored-proxy-normalized.json"
     jq -e --arg name "$RELEASE-proxy" --slurpfile expected "$GSJ_WORK/restored-proxy-normalized.json" '.items[]|select(.kind=="Secret" and .metadata.name==$name)|(.data|with_entries(.value|=@base64d))==$expected[0]' "$GSJ_WORK/restorable-secrets.json" >/dev/null || fail 'backup proxy input differs from its actual Secret'
   fi
   case "$value_name" in
     tls.certificate_file|tls.ca_file|trust.ca_file|verification.ca_file|delivery.ca_file|backup.ca_file|managed_tls.ca.crt) :;;
     *) (( (mode & 077) == 0 )) || fail 'backup credential input has unsafe permissions'; if [[ -e $file || -L $file ]]; then private_file "$file"; fi;;
   esac
   if [[ -e $file || -L $file ]]; then
     [[ -f $file && ! -L $file ]] || fail 'restore input collides with a non-regular file'
     cmp "$file" "$recovered" >/dev/null || fail 'restore input differs from an existing file; existing bytes are preserved'
   fi
   jq -n --arg name "$value_name" --arg file "$file" --arg staged "$recovered" --argjson mode "$mode" '{name:$name,file:$file,staged:$staged,mode:$mode}' >> "$GSJ_WORK/restore-inputs.jsonl"
 done
 # Two logical inputs may share a path only when their recovered bytes agree.
 while IFS= read -r file; do
   recovered=''
   while IFS= read -r name; do
     [[ -z $recovered ]] || cmp "$recovered" "$name" >/dev/null || fail 'restore inputs map different bytes to the same path'
     recovered=$name
   done < <(jq -r --arg file "$file" 'select(.file==$file)|.staged' "$GSJ_WORK/restore-inputs.jsonl")
 done < <(jq -sr 'map(.file)|unique[]' "$GSJ_WORK/restore-inputs.jsonl")
 # API failures are not evidence of absence. Check every intended name before
 # acquiring a writer, then use Kubernetes create (never apply/replace).
 if ! $recovering || $new_checkpoint; then
 for name in "app.kubernetes.io/instance=$RELEASE" "gsj.io/owner=$RELEASE"; do
   object=$(k get deployments,pods,jobs,configmaps,services,ingresses,serviceaccounts,roles,rolebindings,networkpolicies -l "$name" -o json) || fail 'cannot establish empty restore target'
   jq -e '.items|length==0' <<< "$object" >/dev/null || fail 'restore requires an empty target deployment'
 done
 object=$(k get secrets -l "owner=helm,name=$RELEASE" -o json) || fail 'cannot establish empty Helm history'
 jq -e '.items|length==0' <<< "$object" >/dev/null || fail 'restore target already has Helm history'
 while IFS=$'\t' read -r kind name; do
   # A fresh cluster may not have cert-manager's API yet. An absent CRD proves
   # no corresponding custom resource can collide; any API error still fails.
   case "$kind" in
     Issuer|Certificate)
       if [[ $kind == Issuer ]]; then object=issuers.cert-manager.io; else object=certificates.cert-manager.io; fi
       object=$(k get CustomResourceDefinition "$object" -o json --ignore-not-found) || fail 'cannot establish restore ACME API identity'
       [[ -n $object ]] || continue;;
   esac
   object=$(k get "$kind" "$name" -o json --ignore-not-found) || fail 'cannot establish restore resource absence'
   [[ -z $object ]] || fail 'restore target resource already exists; no existing data will be overwritten'
 done < <(jq -r '.items[]|[.kind,.metadata.name]|@tsv' "$resources/cluster-private.json")
   if $new_checkpoint; then
     recover_operation_intent "$RESUME_ID" validate
     local lease age
     lease=$(lease_read)
     [[ $(jq -r .spec.holderIdentity <<< "$lease") == "$RESUME_ID" ]] || fail 'restore intent owner changed'
     age=$(jq -r 'now-(.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$lease")
     (( age >= 180 )) || lease_still_live 'the previous restore installer' "$age"
     OPERATION=$RESUME_ID
     jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$lease" | k replace -f - >/dev/null
     LEASE_ACQUIRED=true; LEASE_RESOURCE_VERSION=$(lease_read | jq -er .metadata.resourceVersion)
     recover_operation_intent "$RESUME_ID" promote
     rm -f "$STATE_DIR/lease-lost"; start_renewal
   else acquire; fi
   jq -n --arg archive "$ARCHIVE" --arg operation "$OPERATION" --arg identity "$RELEASE_ID" --arg sha "$(sha_file "$ARCHIVE")" --arg resources "$(sha_file "$ARCHIVE.resources.enc")" --arg metadata "$(sha_file "$metadata")" --arg target_uid "$(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid)" --arg source_uid "$(jq -r .namespace_uid "$resources/installed.json")" --slurpfile refs "$GSJ_WORK/restore-references.json" '{format:"gsj.restore/1",archive:$archive,archive_sha256:$sha,resources_sha256:$resources,metadata_sha256:$metadata,operation:$operation,release_identity:$identity,source_namespace_uid:$source_uid,target_namespace_uid:$target_uid,references:$refs[0],status:"creating-resources"}' | immutable_file "$STATE_DIR/restoration.json"
   jq '.status="restoring-resources"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 else
   restore_resume_owner
 fi
 assert_owner
 if [[ $(jq -r .status "$STATE_DIR/restoration.json") == files-restored ]]; then
   # The durable file proof precedes both phase updates and Pod retirement.
   # Reconcile the valid proof even if interruption separated those writes.
   restore_finish_pod
   jq '.status="restore-files-verified"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
   secret_inputs; relocated_images_probe; helm_apply; stage_vectors; wait_application; record_ready; verify_application; record_installed
   jq '.status="complete"' "$STATE_DIR/restoration.json" | atomic "$STATE_DIR/restoration.json"
   return
 fi
 restore_no_writers "$(jq -r '.pod//""' "$STATE_DIR/restoration.json")"
 if [[ $(j .tls.profile) == managed-acme ]]; then
   # Source ownership was checked before the first mutation. Bind reconstructed
   # config to the new namespace UID; copy the archived credential data exactly.
   object=$(k get namespace "$NAMESPACE" -o json | jq -er '.metadata.uid|select(type=="string" and length>0)')
   acme_documents "$SITE" "$object" "$GSJ_WORK/acme-restored"
   jq --slurpfile owner "$GSJ_WORK/acme-restored-owner.json" --slurpfile profile "$GSJ_WORK/acme-restored-profile.json" '
     $profile[0] as $p | ($owner[0].metadata.labels["gsj.io/acme-owner"]) as $owner_label |
     .items |= map(if .kind=="ConfigMap" and .metadata.name==$owner[0].metadata.name then .data.account_key_sha256 as $hash | $owner[0] | .data.account_key_sha256=$hash
       elif .kind=="Secret" and (.metadata.name==$p.account_secret or .metadata.name==$p.certificate.name)
       then .metadata.labels["gsj.io/acme-owner"]=$owner_label else . end)
   ' "$GSJ_WORK/restorable-secrets.json" > "$GSJ_WORK/restorable-secrets-acme.json"
   mv "$GSJ_WORK/restorable-secrets-acme.json" "$GSJ_WORK/restorable-secrets.json"
 fi
 restore_resource_list "$GSJ_WORK/restorable-secrets.json"
 restore_resource_list "$GSJ_WORK/restorable-claims.json"
 while IFS=$'\t' read -r file recovered mode; do
   if [[ ! -e $file && ! -L $file ]]; then
     mkdir -p "$(dirname "$file")"; name=$(mktemp "$(dirname "$file")/.gsj-restored.XXXXXXXX")
     cat "$recovered" > "$name"; chmod "$(printf '%o' "$mode")" "$name"
     sync "$name"
     ln "$name" "$file" || fail 'protected input appeared during restore; reconcile it explicitly'
     rm -f "$name"
     sync "$(dirname "$file")"
   else
     [[ -f $file && ! -L $file ]] && cmp "$file" "$recovered" >/dev/null || fail 'protected input changed during restore; existing bytes were preserved'
   fi
 done < <(jq -r '[.file,.staged,.mode]|@tsv' "$GSJ_WORK/restore-inputs.jsonl")
 # restore's own maintenance Pod is the first thing to pull from a recovery
 # site's registry.base; ask before it, not 300 s into its Ready timeout.
 relocated_images_probe
 managed_dependencies
 pod="$RELEASE-restore-${OPERATION:0:8}"; image=$(payload_image web)
 jq --arg pod "$pod" '.status="restoring-files"|.pod=$pod' "$STATE_DIR/restoration.json" | atomic "$STATE_DIR/restoration.json"
 jq '.status="restoring-files"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 restore_files "$pod" "$expected" "$image"
 secret_inputs; helm_apply; stage_vectors; wait_application; record_ready; verify_application; record_installed
 jq '.status="complete"' "$STATE_DIR/restoration.json" | atomic "$STATE_DIR/restoration.json"
}

reissue_local_ca() {
 local directory=$1 output=$2 key_public cert_public serial
 private_file "$directory/ca.key"
 [[ $(openssl x509 -in "$directory/ca.crt" -noout -subject -nameopt RFC2253) == 'subject=CN=GSJ sandbox local CA' ]] || fail 'CA subject is outside the managed sandbox profile'
 key_public=$(openssl pkey -in "$directory/ca.key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')
 cert_public=$(openssl x509 -in "$directory/ca.crt" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')
 [[ $key_public == "$cert_public" ]] || fail 'managed CA key does not match the saved certificate'
 serial=$(openssl x509 -in "$directory/ca.crt" -noout -serial); serial=${serial#serial=}
 openssl req -x509 -key "$directory/ca.key" -sha256 -days 3650 -set_serial "0x$serial" -subj '/CN=GSJ sandbox local CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out "$output" > "$GSJ_WORK/tls-repair.log" 2>&1
}
tls_repair() {
 local current age directory="$STATE_DIR/tls" before secret host
 [[ $(j .tls.profile) == managed-local-ca ]] || fail 'tls-repair applies only to the managed local CA profile'
 [[ $RESUME_ID =~ ^[a-f0-9]{24}$ ]] || fail 'tls-repair requires the failed operation ID'
 current=$(lease_read)
 [[ $(jq -r .spec.holderIdentity <<< "$current") == "$RESUME_ID" ]] || fail 'TLS repair does not own the failed operation'
 age=$(jq -r 'now-(.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$current")
 (( age >= 180 )) || lease_still_live 'the previous installer' "$age"
 OPERATION=$RESUME_ID; LEASE_ACQUIRED=true
 jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
 start_renewal
 before=$(sha_file "$directory/ca.crt")
 secret=$(j .tls.secret); host=$(j .public_url | sed -E 's#https://([^/:]+).*#\1#')
 k get secret "$secret" -o json > "$GSJ_WORK/tls-secret.json"
 jq -r '.data["tls.crt"]' "$GSJ_WORK/tls-secret.json" | base64 --decode > "$GSJ_WORK/tls-leaf.crt"
 reissue_local_ca "$directory" "$GSJ_WORK/reissued-ca.crt"
 openssl verify -x509_strict -verify_hostname "$host" -CAfile "$GSJ_WORK/reissued-ca.crt" "$GSJ_WORK/tls-leaf.crt" >/dev/null || fail 'reissued CA does not validate the unchanged server certificate'
 assert_owner
 [[ $(sha_file "$directory/ca.crt") == "$before" ]] || fail 'CA changed during repair'
 [[ $(k get secret "$secret" -o jsonpath='{.metadata.resourceVersion}') == $(jq -r .metadata.resourceVersion "$GSJ_WORK/tls-secret.json") ]] || fail 'server certificate changed during repair'
 [[ -f $directory/ca.before-$before.crt ]] || cat "$directory/ca.crt" | atomic "$directory/ca.before-$before.crt"
 cat "$GSJ_WORK/reissued-ca.crt" | atomic "$directory/ca.crt"
 jq -n --arg operation "$RESUME_ID" --arg before "$before" --arg after "$(sha_file "$directory/ca.crt")" '{operation:$operation,before_ca_sha256:$before,after_ca_sha256:$after,ca_key_preserved:true,ca_subject_and_serial_preserved:true,server_certificate_and_key_preserved:true,strict_chain_verified:true}' | atomic "$STATE_DIR/tls-repair.json"
 stop_owned_process_group "${RENEWER:-}"; RENEWER=''; OPERATION=''; LEASE_ACQUIRED=false
 log "Managed CA repaired with its existing key; unchanged server certificate passed strict chain verification. Wait until the operation Lease has been unrenewed for 180 seconds, then run resume --operation $RESUME_ID with the installer that owns the operation"
}
credential_repair() {
 local current age pod="$RELEASE-credential-${RESUME_ID:0:8}" secret image input_sha rc=0
 [[ $RESUME_ID =~ ^[a-f0-9]{24}$ ]] || fail 'credential-repair requires the failed operation ID'
 current=$(lease_read)
 [[ $(jq -r .spec.holderIdentity <<< "$current") == "$RESUME_ID" ]] || fail 'credential repair does not own the failed operation'
 age=$(jq -r 'now-(.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$current")
 (( age >= 180 )) || lease_still_live 'the previous installer' "$age"
 k get jobs -l "app.kubernetes.io/instance=$RELEASE" -o json | jq -e 'all(.items[];(.status.active//0)==0)' >/dev/null || fail 'provisioning is still active'
 OPERATION=$RESUME_ID; LEASE_ACQUIRED=true
 jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
 start_renewal
 # Freeze both the candidate bytes and the Secret resourceVersion before the
 # identity request. Neither a changed file nor a concurrent Secret writer may
 # turn successful validation into an update of different credentials.
 input_sha=$(sha_file "$OP_PASSWORD"); cp "$OP_PASSWORD" "$GSJ_WORK/credential-original"
 [[ $(sha_file "$GSJ_WORK/credential-original") == "$input_sha" ]] || fail 'operator input changed while preparing repair'
 jq -jn --rawfile password "$GSJ_WORK/credential-original" '$password|sub("\n+$";"")' > "$GSJ_WORK/credential-candidate"
 jq -Rse 'length>0 and (any(explode[]; .<32 or .==127)|not)' "$GSJ_WORK/credential-candidate" >/dev/null || fail 'operator password contains unsupported control characters'
 secret=$(j .operator.secret); k get secret "$secret" -o json > "$GSJ_WORK/credential-secret.json"
 image=$(payload_image web)
 jq -n --arg name "$pod" --arg release "$RELEASE" --arg image "$image" --argjson pulls "$(jq '.image.pullSecrets|map({name:.})' "$GSJ_WORK/values.pending.json")" '{apiVersion:"v1",kind:"Pod",metadata:{name:$name,labels:{"app.kubernetes.io/name":"gsj","app.kubernetes.io/instance":$release,"app.kubernetes.io/component":"gsj","gsj.io/credential-repair":$name}},spec:{automountServiceAccountToken:false,restartPolicy:"Never",imagePullSecrets:$pulls,containers:[{name:"validate",image:$image,command:["sleep","600"],readinessProbe:{exec:{command:["false"]},periodSeconds:2},resources:{requests:{cpu:"100m",memory:"128Mi"},limits:{memory:"256Mi"}}}]}}' | k create -f - >/dev/null
 k wait --for=jsonpath='{.status.phase}'=Running "pod/$pod" --timeout=180s
 jq -n --rawfile password "$GSJ_WORK/credential-candidate" --arg login "$(j .operator.login)" --arg forge "http://$RELEASE-forgejo:3000" '{password:$password,login:$login,forge:$forge}' | k exec -i "$pod" -c validate -- python -c 'import httpx,json,sys; x=json.load(sys.stdin); r=httpx.get(x["forge"]+"/api/v1/user",auth=(x["login"],x["password"]),timeout=15); assert r.status_code==200,"operator credential refused"; u=r.json(); assert u["login"]==x["login"] and u["is_admin"] is True,"operator identity/role differs"; print("Operator identity and role verified")' || rc=$?
 k delete pod "$pod" --wait=true >/dev/null
 (( rc == 0 )) || fail 'credential repair refused; no password or Secret changed'
 assert_owner
 [[ $(sha_file "$OP_PASSWORD") == "$input_sha" ]] || fail 'operator input changed during validation; no credential updated'
 jq --rawfile password "$GSJ_WORK/credential-candidate" '.data.password=($password|@base64)' "$GSJ_WORK/credential-secret.json" | k replace -f - >/dev/null
 cat "$GSJ_WORK/credential-candidate" | atomic "$OP_PASSWORD"
 jq -n --arg operation "$RESUME_ID" --arg name "$secret" '{operation:$operation,secret:$name,key:"password",identity_verified:true,account_password_changed:false}' | atomic "$STATE_DIR/credential-repair.json"
 stop_owned_process_group "${RENEWER:-}"; RENEWER=''
 # Keep the failed deployment's identity; only its original installer resumes it.
 OPERATION=''; LEASE_ACQUIRED=false
 log 'Operator Secret repaired after actual identity verification; resume the original deployment operation'
}

backup_repair_operation() {
 local current age renewed
 [[ $RESUME_ID =~ ^[a-f0-9]{24}$ && $GENERATION =~ ^[1-9][0-9]{0,5}$ ]] || fail 'backup-repair requires --operation ID and a positive --generation'
 jq -e --arg id "$RESUME_ID" --arg target "$RELEASE_ID" '.operation==$id and (if .repair_backup!=null then .repair_backup.installer==$target and .repair_backup.prior_target==.target else .target==$target end) and (.kind|IN("backup","install","upgrade","repair")) and (.status|IN("owned","repair-backing-up"))' "$STATE_DIR/operation.json" >/dev/null || fail 'backup-repair requires the exact operation stopped before backup verification'
 if jq -e '.repair_backup!=null' "$STATE_DIR/operation.json" >/dev/null; then
   [[ $(sha_file "$SITE") == $(jq -er .repair_backup.site_sha256 "$STATE_DIR/operation.json") ]] || fail 'repair backup configuration changed'
 else retained_site_matches "$SITE" "$STATE_DIR/site.pending.json" || fail 'backup repair configuration changed'; fi
 current=$(lease_read)
 [[ $(jq -r .spec.holderIdentity <<< "$current") == "$RESUME_ID" ]] || fail 'backup-repair does not own the recorded failed operation'
 renewed=$(jq -r .spec.renewTime <<< "$current")
 age=$(jq -r 'now-(.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$current")
 (( age >= 180 )) || lease_still_live 'the previous installer' "$age"
 OPERATION=$RESUME_ID
 jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
 LEASE_ACQUIRED=true; rm -f "$STATE_DIR/lease-lost"; start_renewal
 read_repair_backup_source
 if jq -e '.repair_backup!=null' "$STATE_DIR/operation.json" >/dev/null; then
   jq -e --slurpfile source "$GSJ_WORK/installed.json" '.repair_backup.source==$source[0].manifest.identity' "$STATE_DIR/operation.json" >/dev/null || fail 'repair backup source linkage differs from the installed source'
 fi
 prepare_backup_generation "$GENERATION"; backup; assert_owner
 stop_owned_process_group "${RENEWER:-}"; RENEWER=''
 current=$(lease_read)
 [[ $(jq -r .spec.holderIdentity <<< "$current") == "$OPERATION" ]] || fail 'operation owner changed after backup recovery'
 jq --arg renewed "$renewed" '.spec.renewTime=$renewed' <<< "$current" | k replace -f - >/dev/null
 OPERATION=''; LEASE_ACQUIRED=false
 if jq -e '.repair_backup!=null' "$STATE_DIR/operation.json" >/dev/null; then
   log "Backup generation $GENERATION verified. Earlier recovery artifacts remain preserved. Use this installer with repair --operation $RESUME_ID to continue the recorded repair."
 else
   log "Backup generation $GENERATION verified. Earlier recovery artifacts remain preserved. Use resume --operation $RESUME_ID to continue the original operation."
 fi
}
addon_repair_operation() {
 local current age renewed
 [[ $RESUME_ID =~ ^[a-f0-9]{24}$ && $REVISION =~ ^[1-9][0-9]*$ ]] || fail 'addon-repair requires --operation ID and a positive --revision'
 case "$ADDON" in
   traefik) [[ $(j .ingress.profile) == managed-traefik ]] || fail 'Traefik repair requires the managed ingress profile';;
   certManager) [[ $(j .tls.profile) == managed-acme ]] || fail 'cert-manager repair requires the managed ACME profile';;
   *) fail 'addon-repair supports only traefik or certManager';;
 esac
 [[ -f $STATE_DIR/operation.json ]] && jq -e --arg id "$RESUME_ID" --arg target "$RELEASE_ID" '.operation==$id and .target==$target and (.status|IN("complete","backup-complete")|not)' "$STATE_DIR/operation.json" >/dev/null || fail 'addon-repair requires the exact failed operation and immutable installer'
 retained_site_matches "$SITE" "$STATE_DIR/site.pending.json" || fail 'addon repair configuration differs from its saved profile'
 current=$(lease_read)
 [[ $(jq -r '.spec.holderIdentity//""' <<< "$current") == "$RESUME_ID" ]] || fail 'addon-repair does not own the recorded failed operation'
 renewed=$(jq -r .spec.renewTime <<< "$current")
 age=$(jq -r 'now-(.spec.renewTime|sub("\\.[0-9]+Z$";"Z")|fromdateiso8601)|floor' <<< "$current")
 (( age >= 180 )) || lease_still_live 'the previous installer' "$age"
 OPERATION=$RESUME_ID
 jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
 LEASE_ACQUIRED=true; rm -f "$STATE_DIR/lease-lost"; start_renewal
 managed_dependencies
 assert_owner
 stop_owned_process_group "${RENEWER:-}"; RENEWER=''
 current=$(lease_read)
 [[ $(jq -r .spec.holderIdentity <<< "$current") == "$OPERATION" ]] || fail 'operation owner changed after addon recovery'
 jq --arg renewed "$renewed" '.spec.renewTime=$renewed' <<< "$current" | k replace -f - >/dev/null
 OPERATION=''; LEASE_ACQUIRED=false
 log "Owned $ADDON revision $REVISION repaired. The failed application operation remains reserved for named resume or repair."
}

configure_interaction() {
 $INTERACTIVE && $NON_INTERACTIVE && fail 'choose one interaction mode'
 if $INTERACTIVE; then
   if [[ $COMMAND == upgrade && -z $TO && -z ${EXPECTED_VERSION:-} ]]; then TO=$(ask 'Target release version' "$(jq -r .version "$GSJ_PAYLOAD/release.json")"); fi
   if [[ ( $COMMAND == upgrade || $COMMAND == repair ) && -n $TO ]]; then
     # The saved source configuration supplies only the current transport and
     # target identity here. The verified target installer owns its wizard.
     [[ -f $CONFIG && ! -L $CONFIG ]] || fail 'select the existing saved site configuration before acquiring an interactive target release'
     log "Selected release $TO will run its own configuration wizard after signature verification"
   else wizard; fi
 elif ! $NON_INTERACTIVE; then fail 'select --interactive or --non-interactive'; fi
}
main() {
 COMMAND=${1:-help}; [[ $# == 0 ]] || shift
 CONFIG=site.json; CONTEXT_ARG=''; TO=''; EXPECTED_VERSION=''; RESUME_ID=''; ARCHIVE=''; ADDON=''; REVISION=''; GENERATION=''; BACKUP_ROUND=''; SOURCE_INSTALLER=''; CONTINUE_HELM_INSTALLER=''; ABANDON_REASON=''; CONTINUE_FROM_PROGRAM=''; INTERACTIVE=false; NON_INTERACTIVE=false; FETCH_TOOLS=false
 while (( $# )); do
   case "$1" in
     --config) CONFIG=$2; shift 2;; --context) CONTEXT_ARG=$2; shift 2;; --to) TO=$2; shift 2;;
     --operation) RESUME_ID=$2; shift 2;; --archive) ARCHIVE=$2; shift 2;; --expected-version) EXPECTED_VERSION=$2; shift 2;;
     --addon) ADDON=$2; shift 2;; --revision) REVISION=$2; shift 2;;
     --generation) GENERATION=$2; shift 2;;
     --backup-round) BACKUP_ROUND=$2; shift 2;;
     --source-installer) SOURCE_INSTALLER=$2; shift 2;;
     --continue-helm-installer) CONTINUE_HELM_INSTALLER=$2; shift 2;;
     --continue-from-program) CONTINUE_FROM_PROGRAM=$2; shift 2;;
     --reason) ABANDON_REASON=$2; shift 2;;
     --interactive) INTERACTIVE=true; shift;; --non-interactive) NON_INTERACTIVE=true; shift;;
     --fetch-tools) FETCH_TOOLS=true; shift;;
     *) fail "unknown argument: $1";;
   esac
 done
 if [[ $COMMAND == help || $COMMAND == --help ]]; then
   printf '%s\n' 'gsj-install.sh inspect [--context NAME]' 'any command also accepts --fetch-tools (download this release'"'"'s pinned helm/kubectl/jq instead of using the ones installed here)' 'gsj-install.sh install --interactive [--config site.json]' 'gsj-install.sh install --config site.json --non-interactive' 'gsj-install.sh upgrade --to VERSION --config site.json [--interactive|--non-interactive]' 'gsj-install.sh resume --operation ID --config site.json --non-interactive' 'gsj-install.sh repair --operation ID [--to VERSION] [--backup-round N | --source-installer PATH | --continue-helm-installer PATH [--continue-from-program PATH]] --config site.json --non-interactive' 'gsj-install.sh credential-repair --operation ID --config site.json --non-interactive' 'gsj-install.sh tls-repair --operation ID --config site.json --non-interactive' 'gsj-install.sh lease-repair --operation ID --config site.json --non-interactive' 'gsj-install.sh abandon --operation ID --reason TEXT --config site.json --non-interactive' 'gsj-install.sh sweep --config site.json --reason "why" --non-interactive' 'gsj-install.sh addon-repair --operation ID --addon traefik|certManager --revision N --config site.json --non-interactive' 'gsj-install.sh backup --config site.json [--interactive|--non-interactive]' 'gsj-install.sh backup-repair --operation ID --generation N --config site.json --non-interactive' 'gsj-install.sh restore --archive BACKUP.tar.gz.enc --config site.json --non-interactive' 'gsj-install.sh restore-repair --operation ID [--source-installer PATH] --config site.json --non-interactive'
   return
 fi
 [[ -z $BACKUP_ROUND || ( $COMMAND == repair && $BACKUP_ROUND =~ ^[1-9][0-9]{0,5}$ ) ]] || fail '--backup-round requires repair and a positive bounded round number'
 [[ -z $SOURCE_INSTALLER || ( ( $COMMAND == repair || $COMMAND == restore-repair ) && -z $BACKUP_ROUND ) ]] || fail '--source-installer applies only to first-startup or corrected-program restore repair without a backup round'
 [[ -z $CONTINUE_HELM_INSTALLER || ( $COMMAND == repair && -z $SOURCE_INSTALLER && -z $BACKUP_ROUND ) ]] || fail '--continue-helm-installer applies only to explicit partial startup repair without another source or backup round'
 [[ -z $CONTINUE_FROM_PROGRAM || ( $COMMAND == repair && -n $CONTINUE_HELM_INSTALLER ) ]] || fail '--continue-from-program requires explicit --continue-helm-installer repair'
 [[ -z $GENERATION || ( $COMMAND == backup-repair && $GENERATION =~ ^[1-9][0-9]{0,5}$ ) ]] || fail '--generation requires backup-repair and a positive bounded generation number'
 # The verified child of --to receives --expected-version; interactive mode prompts.
 [[ $COMMAND != upgrade || -n $TO || -n $EXPECTED_VERSION ]] || $INTERACTIVE || fail 'non-interactive upgrade requires --to VERSION; repeat the installed release with --to <installed version>'
 bootstrap; install_exit_traps
 source "$GSJ_PAYLOAD/helpers/verification-cleanup.sh"
 source "$GSJ_PAYLOAD/helpers/startup-recovery.sh"
 # Startup proof inputs are separately inventoried signed helpers.
 if [[ -f $GSJ_PAYLOAD/helpers/lease-repair-source-release.json && $COMMAND != inspect && $COMMAND != lease-repair ]]; then fail 'this signed recovery bundle supports only inspect and lease-repair; use the original application installer for other commands'; fi
 if [[ $COMMAND == inspect ]]; then inspect_cluster; return; fi
 [[ -z $EXPECTED_VERSION || $EXPECTED_VERSION == $(jq -er .version "$GSJ_PAYLOAD/release.json") ]] || fail 'downloaded installer embeds a different release version'
 configure_interaction
 load_site
 helm_verb_preflight
 (CONTEXT_ARG="$CONTEXT"; inspect_cluster) | tee "$STATE_DIR/inspection.json"
 # An explicit version always names the authenticated distribution artifact,
 # including a repeat of this version. The verified child receives only
 # --expected-version, so it owns configuration without reacquiring itself.
 if [[ ( $COMMAND == upgrade || $COMMAND == repair ) && -n $TO ]]; then acquire_target "$TO"; return; fi
 # A restore's recorded program also owns its resume and repair.
 if [[ $COMMAND == restore-repair || $COMMAND == resume || $COMMAND == repair ]]; then restore_program_select; fi
 preflight
 if [[ $COMMAND == resume ]]; then resume_operation; return; fi
 if [[ $COMMAND == repair ]]; then repair_operation; return; fi
 if [[ $COMMAND == credential-repair ]]; then credential_repair; return; fi
 if [[ $COMMAND == tls-repair ]]; then tls_repair; return; fi
 if [[ $COMMAND == lease-repair ]]; then lease_repair; return; fi
 if [[ $COMMAND == abandon ]]; then abandon_operation; return; fi
 if [[ $COMMAND == sweep ]]; then sweep_target; return; fi
 if [[ $COMMAND == addon-repair ]]; then addon_repair_operation; return; fi
 if [[ $COMMAND == backup ]]; then backup_operation; return; fi
 if [[ $COMMAND == backup-repair ]]; then backup_repair_operation; return; fi
 if [[ $COMMAND == restore || $COMMAND == restore-repair ]]; then restore_archive; return; fi
 [[ $COMMAND == install || $COMMAND == upgrade ]] || fail 'unsupported operation'
 endpoint_preflight
 read_installed
 if [[ $COMMAND == upgrade ]]; then [[ -s $GSJ_WORK/installed.json ]] && jq -e '.status=="complete"' "$GSJ_WORK/installed.json" >/dev/null || fail 'upgrade requires a completed installed-release record'; fi
 compatibility; acquire
 # A preceding operation may have completed between the read-only preview
 # and acquiring the lease. Reconcile the actual source again under ownership.
 compatibility
 # Before backup: backup quiesces a running deployment, and a refused pull must
 # leave what was running, running.
 relocated_images_probe
 if [[ -s $GSJ_WORK/installed.json ]]; then backup; fi
 # stage_vectors sits between the apply and the wait: the PVCs exist, and the
 # initializer is still held behind wait-deps' provisioning marker.
 secret_inputs; managed_dependencies; storage_probe; helm_apply; stage_vectors; wait_application; record_ready; verify_application; record_installed
}
# ENTRY POINT
main "$@"
exit 0
__GSJ_PAYLOAD_BELOW__
