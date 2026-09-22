#!/usr/bin/env bash
# Source this helper from the verified installer payload. The actual operation
# runs in a NEW Bash process: a caller's `function || rc=$?` must not disable
# errexit inside this mutation boundary.
verification_account_cleanup() {
 CONTEXT="$CONTEXT" NAMESPACE="$NAMESPACE" RELEASE="$RELEASE" STATE_DIR="$STATE_DIR" \
 OPERATION="$OPERATION" GSJ_WORK="$GSJ_WORK" bash "${BASH_SOURCE[0]}" "$@"
}
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0
set -Eeuo pipefail
umask 077
vc_fail() { printf 'GSJ: verification account cleanup incomplete: %s\n' "$*" >&2; exit 1; }
# A spent ROUND is not an ordinary refusal: only repair may open a new one, so
# the caller must name repair, not resume, and this carries its own exit code.
vc_spent() { printf 'GSJ: verification account cleanup incomplete: %s\n' "$*" >&2; exit 80; }
vc_k() { kubectl --context "$CONTEXT" --namespace "$NAMESPACE" "$@"; }
vc_save() {
 local source=$1 target=$2
 cat "$source" > "$target.pending.$$"
 chmod 600 "$target.pending.$$"; sync "$target.pending.$$"
 mv -f "$target.pending.$$" "$target"; sync "$(dirname "$target")"
}
vc_report() {
 vc_k exec "$pod" -c gsj-web -- cat "$remote/report.json" > "$work/report.json"
 jq -e --argjson code "$code" '.status==(if $code==0 then "passed" else "cleaned-reverify-required" end)' "$work/report.json" >/dev/null || vc_fail 'terminal verification report differs'
 vc_save "$work/report.json" "$STATE_DIR/verification.json"
}
vc_sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f1; else shasum -a 256 "$1" | cut -d ' ' -f1; fi; }
vc_owner() {
 [[ ! -f $STATE_DIR/lease-lost ]] || vc_fail 'operation lease was lost'
 [[ $(vc_k get lease "$RELEASE-operation" -o json | jq -er '.spec.holderIdentity') == "$OPERATION" ]] || vc_fail 'operation owner changed'
 [[ $(vc_k get namespace "$NAMESPACE" -o json | jq -er '.metadata.uid') == "$namespace_uid" ]] || vc_fail 'namespace identity changed'
}
vc_spec() {
 jq -jSc '.spec | del(.selector,.manualSelector,.template.metadata.creationTimestamp) |
   .template.metadata.labels |= del(.["batch.kubernetes.io/controller-uid"],.["batch.kubernetes.io/job-name"],.["controller-uid"],.["job-name"])' "$1"
}
vc_validate_plan() {
 jq -e --arg name "$plan" --arg ns "$NAMESPACE" --arg release "$RELEASE" --arg run "$run" --arg uid "$namespace_uid" --arg digest "$ownership_sha" '
   .apiVersion=="v1" and .kind=="ConfigMap" and .immutable==true and
   .metadata.name==$name and .metadata.namespace==$ns and (.metadata.uid|type=="string" and length>0) and
   .metadata.labels["gsj.io/owner"]==$release and .metadata.labels["gsj.io/verification"]==$run and
   .metadata.labels["gsj.io/namespace-uid"]==$uid and .metadata.annotations["gsj.io/ownership-sha256"]==$digest and
   (.data|keys)==["job-spec.json","owned-users.json","receipt.json"]' "$work/plan.json" >/dev/null || vc_fail 'cleanup intent identity differs'
 jq -j '.data["owned-users.json"]' "$work/plan.json" > "$work/plan-owned.json"
 cmp -s "$work/owned.json" "$work/plan-owned.json" || vc_fail 'immutable ownership bytes differ'
 jq -j '.data["job-spec.json"]' "$work/plan.json" > "$work/spec.json"
 [[ $(vc_sha "$work/spec.json") == "$(jq -r '.metadata.annotations["gsj.io/template-sha256"]' "$work/plan.json")" ]] || vc_fail 'cleanup template digest differs'
 jq -e --arg generation "$generation" --arg plan "$plan" '
   .backoffLimit==0 and .activeDeadlineSeconds==300 and .parallelism==1 and .completions==1 and
   .template.spec.restartPolicy=="Never" and (.template.spec.containers|length)==1 and
   .template.spec.containers[0].name=="provision" and
   .template.spec.containers[0].command==["python","/scripts/provision.py","cleanup-users","/verification/owned-users.json"] and
   [.template.spec.containers[0].env[]|select(.name=="GSJ_DEPLOYMENT_GENERATION")]==[{name:"GSJ_DEPLOYMENT_GENERATION",value:$generation}] and
   [.template.spec.volumes[]|select(.name=="verification")][0].configMap.name==$plan' "$work/spec.json" >/dev/null || vc_fail 'cleanup template contract differs'
 jq -j '.data["receipt.json"]' "$work/plan.json" > "$work/receipt.json"
 # An intent written before rounds existed carries no round and is round 1.
 jq -e --arg run "$run" --arg generation "$generation" --arg uid "$namespace_uid" --arg digest "$ownership_sha" --argjson attempt "$attempt" --argjson round "$round" '
   .format=="gsj.verification-cleanup-attempt/1" and .run_id==$run and .generation==$generation and
   .namespace_uid==$uid and .ownership_sha256==$digest and .attempt==$attempt and .max_attempts==3 and
   (.round//1)==$round' "$work/receipt.json" >/dev/null || vc_fail 'cleanup attempt budget record differs'
 if [[ -s $saved/attempt-$attempt.json ]]; then
   [[ $(jq -er .metadata.uid "$saved/attempt-$attempt.json") == $(jq -er .metadata.uid "$work/plan.json") ]] || vc_fail 'cleanup intent UID changed'
 fi
}
vc_validate_job() {
 local plan_uid expected_uid
 plan_uid=$(jq -er '.metadata.uid' "$work/plan.json")
 expected_uid=$(jq -r '.metadata.annotations["gsj.io/job-uid"] // ""' "$work/plan.json")
 jq -e --arg name "$job" --arg ns "$NAMESPACE" --arg release "$RELEASE" --arg run "$run" --arg uid "$namespace_uid" --arg digest "$ownership_sha" --arg plan "$plan" --arg plan_uid "$plan_uid" --arg expected_uid "$expected_uid" '
   .apiVersion=="batch/v1" and .kind=="Job" and .metadata.name==$name and .metadata.namespace==$ns and
   (.metadata.uid|type=="string" and length>0) and ($expected_uid=="" or .metadata.uid==$expected_uid) and
   .metadata.labels["gsj.io/owner"]==$release and .metadata.labels["gsj.io/verification"]==$run and
   .metadata.labels["gsj.io/namespace-uid"]==$uid and .metadata.annotations["gsj.io/ownership-sha256"]==$digest and
   .metadata.ownerReferences==[{apiVersion:"v1",kind:"ConfigMap",name:$plan,uid:$plan_uid,controller:false,blockOwnerDeletion:false}]' "$work/job.json" >/dev/null || vc_fail 'cleanup Job ownership differs'
 vc_spec "$work/job.json" > "$work/actual-spec.json"
 cmp -s "$work/spec.json" "$work/actual-spec.json" || vc_fail 'cleanup Job template differs'
}
vc_record_job_uid() {
 # The Job's UID recorded on its plan, CAS on the plan's exact uid and
 # resourceVersion; shared by the create path and the adoption of a Job whose
 # create reply was lost.
 jq -n --arg uid "$(jq -r .metadata.uid "$work/plan.json")" --arg rv "$(jq -r .metadata.resourceVersion "$work/plan.json")" --arg job_uid "$job_uid" '[{op:"test",path:"/metadata/uid",value:$uid},{op:"test",path:"/metadata/resourceVersion",value:$rv},{op:"add",path:"/metadata/annotations/gsj.io~1job-uid",value:$job_uid}]' > "$work/patch.json"
 vc_owner
 vc_k patch configmap "$plan" --type=json --patch-file "$work/patch.json" -o json > "$work/plan.json"
 vc_validate_plan; vc_validate_job
}
vc_delete_uid() {
 local kind=$1 name=$2 uid=$3 resource path deadline current
 case "$kind" in pod) resource=pods; path="/api/v1/namespaces/$NAMESPACE/pods/$name";; job) resource=jobs; path="/apis/batch/v1/namespaces/$NAMESPACE/jobs/$name";; configmap) resource=configmaps; path="/api/v1/namespaces/$NAMESPACE/configmaps/$name";; *) vc_fail 'invalid cleanup resource kind';; esac
 vc_owner
 jq -n --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid},propagationPolicy:"Foreground"}' > "$work/delete-options.json"
 # kubectl v1.35.8 delete.go:297 and rawhttp/raw.go:45 send -f as the raw
 # DELETE body. HTTP409 never falls back to a delete without preconditions.
 if ! vc_k delete --raw "$path" -f "$work/delete-options.json" > "$work/delete-response.json" 2> "$work/delete-error"; then
   current=$(vc_k get "$resource" "$name" -o json --ignore-not-found)
   [[ -z $current ]] || vc_fail 'UID-preconditioned cleanup deletion refused'
 fi
 deadline=$((SECONDS+120))
 while :; do
   current=$(vc_k get "$resource" "$name" -o json --ignore-not-found)
   [[ -n $current ]] || return 0
   [[ $(jq -er '.metadata.uid' <<< "$current") == "$uid" ]] || vc_fail 'cleanup resource was replaced during deletion'
   (( SECONDS < deadline )) || vc_fail 'cleanup resource deletion is still pending'
   sleep 1
 done
}

vc_mark_finalized() {
 local marker
 marker=$(jq -r '.metadata.annotations["gsj.io/finalized-code"] // ""' "$work/plan.json")
 # A later explicit abort may demote a previously passed run from 0 to 77; 75
 # marks a round retired while the verification itself was still unresolved.
 [[ -z $marker || $marker == 0 || $marker == 75 || $marker == 77 ]] || vc_fail 'invalid retirement marker'
 if [[ -z $marker ]]; then
   jq -n --arg uid "$(jq -r .metadata.uid "$work/plan.json")" --arg rv "$(jq -r .metadata.resourceVersion "$work/plan.json")" --arg code "$code"      '[{op:"test",path:"/metadata/uid",value:$uid},{op:"test",path:"/metadata/resourceVersion",value:$rv},{op:"add",path:"/metadata/annotations/gsj.io~1finalized-code",value:$code}]' > "$work/patch.json"
   vc_owner
   vc_k patch configmap "$plan" --type=json --patch-file "$work/patch.json" -o json > "$work/updated-plan.json"
   mv "$work/updated-plan.json" "$work/plan.json"
   vc_validate_plan
 fi
 vc_save "$work/plan.json" "$saved/attempt-$attempt.json"
}
vc_control_record() {
 local kind=$1 name=$2 uid=$3 phase=$4 disposition=$5
 jq -cn --arg kind "$kind" --arg name "$name" --arg uid "$uid" --arg phase "$phase" --arg disposition "$disposition"    '{kind:$kind,name:$name,uid:$uid,phase:$phase,disposition:$disposition}' >> "$work/control-items.jsonl"
 jq -s --arg run "$run" --arg namespace_uid "$namespace_uid"    '{format:"gsj.verification-control-cleanup/1",run_id:$run,namespace_uid:$namespace_uid,status:"incomplete",resources:.}'    "$work/control-items.jsonl" > "$work/control-report.json"
 vc_save "$work/control-report.json" "$saved/control-report.json"
}
vc_terminal_pods() {
 local pod_name pod_uid phase
 # Select by actual owner UID across the namespace: a missing Job or labels
 # alone never establishes that an old Pod cannot still write.
 vc_k get pods -o json > "$work/control-pods.json"
 jq --arg uid "$job_uid" '[.items[]|select(any(.metadata.ownerReferences[]?;.kind=="Job" and .uid==$uid))]'    "$work/control-pods.json" > "$work/owned-pods.json"
 jq -c '.[]' "$work/owned-pods.json" > "$work/owned-pods.jsonl"
 while IFS= read -r item; do
   pod_name=$(jq -er .metadata.name <<< "$item"); pod_uid=$(jq -er .metadata.uid <<< "$item")
   phase=$(jq -r '.status.phase // "Unknown"' <<< "$item")
   vc_control_record Pod "$pod_name" "$pod_uid" "$phase" inspected
   jq -e '(.status.phase=="Succeeded" or .status.phase=="Failed") and
     ((.status.containerStatuses // [])+(.status.initContainerStatuses // [])+(.status.ephemeralContainerStatuses // []) | all(.state.running==null))'      <<< "$item" >/dev/null || vc_fail 'owned cleanup Pod has not stopped; evidence retained'
   jq '{metadata:{name:.metadata.name,uid:.metadata.uid,ownerReferences:.metadata.ownerReferences},
     status:{phase:.status.phase,containers:[.status.containerStatuses[]?|{name,state:{terminated:{exitCode:.state.terminated.exitCode,reason:.state.terminated.reason}}}]}}'      <<< "$item" > "$work/pod-evidence.json"
   vc_save "$work/pod-evidence.json" "$saved/$pod_uid.json"
   if [[ $phase == Failed ]]; then
     if vc_k logs "$pod_name" -c provision --tail=80 --limit-bytes=16384 > "$work/failure.log" 2> "$work/failure-error"; then
       # The fixed cleanup entrypoint emits no credentials. Retain only its
       # bounded typed failure lines, never arbitrary container output.
       awk '/^\[provision\] FATAL:/ {print substr($0,1,256)}' "$work/failure.log" > "$work/failure-sanitized.log"
       vc_save "$work/failure-sanitized.log" "$saved/$pod_uid-failure.log"
     fi
   fi
 done < "$work/owned-pods.jsonl"
}
vc_retire_terminal() {
 local has_job from_saved pod_name pod_uid
 : > "$work/control-items.jsonl"
 # No account Job is ever created here. The fresh verifier result proves
 # application cleanup; exact ownership and stopped Pods gate retirement.
 for attempt in 1 2 3; do
   plan="$base-a$attempt"; job="$plan"; from_saved=false
   vc_k get configmap "$plan" -o json --ignore-not-found > "$work/plan.json"
   vc_k get job "$job" -o json --ignore-not-found > "$work/job.json"
   if [[ ! -s $work/plan.json ]]; then
     [[ ! -s $work/job.json ]] || vc_fail 'terminal cleanup Job has no ownership intent'
     if [[ ! -s $saved/attempt-$attempt.json ]]; then continue; fi
     cp "$saved/attempt-$attempt.json" "$work/plan.json"; from_saved=true
   fi
   vc_validate_plan
   plan_uid=$(jq -er .metadata.uid "$work/plan.json")
   job_uid=$(jq -r '.metadata.annotations["gsj.io/job-uid"] // ""' "$work/plan.json")
   vc_control_record ConfigMap "$plan" "$plan_uid" immutable inspected
   if [[ -z $job_uid ]]; then
     # An open sub-case found by running it: a plan whose Job UID was never
     # recorded, because the create reply was lost. The Job's name is
     # deterministic, so the cluster is asked instead of guessing:
     # present under OUR exact identity (labels, namespace UID, ownership
     # digest, owner reference to THIS plan, the template) -> its UID is
     # adopted and recorded on the plan BEFORE anything is deleted, the same
     # write the create path makes; absent -> no Job ever came into being under
     # this intent, so nothing account-bearing can be orphaned by retiring it.
     if [[ -s $work/job.json ]]; then
       vc_validate_job
       job_uid=$(jq -er .metadata.uid "$work/job.json")
       vc_record_job_uid
       vc_control_record Job "$job" "$job_uid" adopted recorded
     else
       vc_control_record Job "$job" '' never-created retired
     fi
   fi
   has_job=false
   if [[ -s $work/job.json ]]; then
     has_job=true; vc_validate_job
     vc_save "$work/job.json" "$saved/attempt-$attempt-job.json"
     vc_control_record Job "$job" "$job_uid" "$(jq -r '[.status.conditions[]?|select(.status=="True")|.type]|join(",")' "$work/job.json")" inspected
     jq -e 'any(.status.conditions[]?;(.type=="Complete" or .type=="Failed") and .status=="True")' "$work/job.json" >/dev/null || vc_fail 'terminal cleanup still has an active Job'
   fi
   vc_terminal_pods
   if ! $from_saved; then vc_mark_finalized; fi
   if $has_job; then vc_delete_uid job "$job" "$job_uid"; fi
   while IFS= read -r item; do
     pod_name=$(jq -er .metadata.name <<< "$item"); pod_uid=$(jq -er .metadata.uid <<< "$item")
     vc_delete_uid pod "$pod_name" "$pod_uid"
     vc_control_record Pod "$pod_name" "$pod_uid" absent removed
   done < "$work/owned-pods.jsonl"
   vc_delete_uid configmap "$plan" "$plan_uid"
   # Re-read all Pods by the recorded controller UID after deletion.
   vc_k get pods -o json | jq -e --arg uid "$job_uid"      'all(.items[]; all(.metadata.ownerReferences[]?;.kind!="Job" or .uid!=$uid))' >/dev/null || vc_fail 'cleanup Pod residue remains'
   vc_control_record Job "$job" "$job_uid" absent removed
   vc_control_record ConfigMap "$plan" "$plan_uid" absent removed
 done
 jq -s --arg run "$run" --arg namespace_uid "$namespace_uid"    '{format:"gsj.verification-control-cleanup/1",run_id:$run,namespace_uid:$namespace_uid,status:"clean",resources:.}'    "$work/control-items.jsonl" > "$work/control-report.json"
 vc_save "$work/control-report.json" "$saved/control-report.json"
}
vc_open_round() {
 # A spent ladder used to be a dead end - resume re-entered it and repair
 # walked into the same wall. Only repair may open a new ROUND, which retires
 # the spent one exactly as a terminal result does (stopped Jobs and Pods only,
 # evidence and sanitized FATAL lines saved first, deletions by recorded UID),
 # MOVES its saved state under round-N/ - retained, never deleted - and then
 # runs three fresh attempts under round-suffixed immutable names.
 local entry
 vc_retire_terminal
 mkdir -p "$saved/round-$round"
 for entry in "$saved"/*; do
   [[ -e $entry ]] || continue
   case "${entry##*/}" in round-*) continue;; esac
   mv -f "$entry" "$saved/round-$round/"
 done
 sync "$saved/round-$round"; sync "$saved"
 vc_save "$work/owned.json" "$saved/owned-users.json"
 printf 'GSJ: cleanup round %s is retired and archived in round-%s; bounded round %s begins\n' "$round" "$round" "$((round+1))" >&2
 round=$((round+1)); base="${RELEASE:0:25}-verify-$run-r$round"
}

[[ $# == 4 ]] || vc_fail 'expected pod, run, remote directory and sealed generation'
pod=$1; run=$2; remote=$3; generation=$4
[[ $run =~ ^[a-f0-9]{8,16}$ && $pod =~ ^[a-z0-9][a-z0-9.-]*$ && $remote == "/data/verification/$run" && -n $generation ]] || vc_fail 'invalid verification identity'
: "${CONTEXT:?}" "${NAMESPACE:?}" "${RELEASE:?}" "${STATE_DIR:?}" "${OPERATION:?}" "${GSJ_WORK:?}"
work=$(mktemp -d "$GSJ_WORK/verification-cleanup.XXXXXXXX")
saved="$STATE_DIR/verification-cleanup-$run"; mkdir -p "$saved"
namespace_uid=$(vc_k get namespace "$NAMESPACE" -o json | jq -er '.metadata.uid')
vc_owner
# Reacquire the verifier lock and validate the sealed digests. A stale file
# alone is never authorization to launch an A-bearing Job.
code=0
vc_k exec "$pod" -c gsj-web -- python -m gsj_deploy.verify --resume --settings "/tmp/gsj-verification/$run/settings.json" > "$work/resume.log" || code=$?
if (( code == 78 )); then exit 78; fi
terminal=false
if (( code == 0 || code == 77 )); then terminal=true; fi
(( code == 75 || code == 0 || code == 77 )) || vc_fail 'fresh sealed verification handoff unavailable'
vc_k exec "$pod" -c gsj-web -- cat "$remote/cleanup-users.json" > "$work/owned.json"
jq -e --arg run "$run" --arg generation "$generation" '
 .generation==$generation and .run_id==$run and (.users|type)=="array" and (.users|length)<=2 and
 all(.users[]; . as $u | ($u.login=="gsj-verify-"+$run+"-a" or $u.login=="gsj-verify-"+$run+"-b") and
   ($u.id|type)=="number" and $u.id>0 and ($u.id|floor)==$u.id) and
 ([.users[].login]|unique|length)==(.users|length) and ([.users[].id]|unique|length)==(.users|length)' "$work/owned.json" >/dev/null || vc_fail 'sealed disposable ownership is invalid'
jq -jSc . "$work/owned.json" > "$work/owned-canonical.json"; ownership_sha=$(vc_sha "$work/owned-canonical.json")
vc_save "$work/owned.json" "$saved/owned-users.json"
# The ladder runs in bounded ROUNDS. Round 1 keeps the original names; every
# archived round-N/ under the saved state proves one spent round, so the live
# round is derived from the evidence and never from a separate record.
round=1; while [[ -d $saved/round-$round ]]; do round=$((round+1)); done
base="${RELEASE:0:25}-verify-$run"; (( round == 1 )) || base="$base-r$round"
if $terminal; then
 vc_retire_terminal
 vc_report
 exit "$code"
fi
jq -e '(.users|length)>0' "$work/owned.json" >/dev/null || vc_fail 'empty account handoff cannot launch a Job'
while :; do
for attempt in 1 2 3; do
 plan="$base-a$attempt"; job="$plan"
 vc_owner
 vc_k get configmap "$plan" -o json --ignore-not-found > "$work/plan.json"
 new_plan=false
 if [[ ! -s $work/plan.json ]]; then
   vc_k get job "$RELEASE-provision" -o json > "$work/provision.json"
   jq -e --arg release "$RELEASE" '.metadata.labels["app.kubernetes.io/instance"]==$release and
     (.spec.template.spec.containers|length)==1 and .spec.template.spec.containers[0].name=="provision"' "$work/provision.json" >/dev/null || vc_fail 'provisioning template ownership differs'
   jq --arg name "$job" --arg ns "$NAMESPACE" --arg release "$RELEASE" --arg run "$run" --arg uid "$namespace_uid" --arg digest "$ownership_sha" --arg generation "$generation" '
     .metadata={name:$name,namespace:$ns,labels:{"gsj.io/owner":$release,"gsj.io/verification":$run,"gsj.io/namespace-uid":$uid},annotations:{"gsj.io/ownership-sha256":$digest}} |
     del(.status,.spec.selector,.spec.manualSelector,.spec.ttlSecondsAfterFinished) |
     .spec.backoffLimit=0 | .spec.activeDeadlineSeconds=300 | .spec.parallelism=1 | .spec.completions=1 |
     .spec.template.metadata={labels:{"app.kubernetes.io/instance":$release,"gsj.io/verification":$run,"gsj.io/provisioner":$release}} |
     del(.spec.template.spec.initContainers) |
     .spec.template.spec.restartPolicy="Never" |
     .spec.template.spec.containers=[(.spec.template.spec.containers[0] |
       .command=["python","/scripts/provision.py","cleanup-users","/verification/owned-users.json"] |
       .env=([.env[]|select(.name!="GSJ_DEPLOYMENT_GENERATION")]+[{name:"GSJ_DEPLOYMENT_GENERATION",value:$generation}]) |
       .volumeMounts=[{name:"scripts",mountPath:"/scripts",readOnly:true},{name:"verification",mountPath:"/verification",readOnly:true}])] |
     .spec.template.spec.volumes=[(.spec.template.spec.volumes[]|select(.name=="scripts")),{name:"verification",configMap:{name:$name,defaultMode:420}}]
   ' "$work/provision.json" > "$work/job-plan.json"
   vc_spec "$work/job-plan.json" > "$work/spec.json"; template_sha=$(vc_sha "$work/spec.json")
   jq -jcnS --arg run "$run" --arg generation "$generation" --arg uid "$namespace_uid" --arg digest "$ownership_sha" --argjson attempt "$attempt" --argjson round "$round" '{format:"gsj.verification-cleanup-attempt/1",run_id:$run,generation:$generation,namespace_uid:$uid,ownership_sha256:$digest,round:$round,attempt:$attempt,max_attempts:3}' > "$work/receipt.json"
   jq -n --arg name "$plan" --arg ns "$NAMESPACE" --arg release "$RELEASE" --arg run "$run" --arg uid "$namespace_uid" --arg digest "$ownership_sha" --arg template "$template_sha" --rawfile owned "$work/owned.json" --rawfile spec "$work/spec.json" --rawfile receipt "$work/receipt.json" '
     {apiVersion:"v1",kind:"ConfigMap",metadata:{name:$name,namespace:$ns,labels:{"gsj.io/owner":$release,"gsj.io/verification":$run,"gsj.io/namespace-uid":$uid},annotations:{"gsj.io/ownership-sha256":$digest,"gsj.io/template-sha256":$template}},immutable:true,data:{"owned-users.json":$owned,"job-spec.json":$spec,"receipt.json":$receipt}}' > "$work/new-plan.json"
   vc_owner
   # Never apply/replace an existing intent. A lost create response is
   # reconciled by reading the exact immutable data before any next action.
   if vc_k create -f "$work/new-plan.json" -o json > "$work/plan.json"; then new_plan=true
   else
     vc_k get configmap "$plan" -o json > "$work/plan.json"
     jq -e --slurpfile wanted "$work/new-plan.json" '.data==$wanted[0].data' "$work/plan.json" >/dev/null || vc_fail 'cleanup intent collision'
   fi
 fi
 vc_validate_plan
 vc_save "$work/plan.json" "$saved/attempt-$attempt.json"
 vc_k get job "$job" -o json --ignore-not-found > "$work/job.json"
 if [[ ! -s $work/job.json ]]; then
   if [[ $new_plan != true ]]; then
     # An old durable intent consumes an attempt even when the creation
     # response/outcome was lost. Never guess that it was never submitted.
     printf 'GSJ: cleanup attempt %s has an unknown missing Job; preserving intent\n' "$attempt" >&2
     continue
   fi
   plan_uid=$(jq -er '.metadata.uid' "$work/plan.json")
   jq -n --arg name "$job" --arg ns "$NAMESPACE" --arg release "$RELEASE" --arg run "$run" --arg uid "$namespace_uid" --arg digest "$ownership_sha" --arg plan_uid "$plan_uid" --slurpfile spec "$work/spec.json" '
     {apiVersion:"batch/v1",kind:"Job",metadata:{name:$name,namespace:$ns,labels:{"gsj.io/owner":$release,"gsj.io/verification":$run,"gsj.io/namespace-uid":$uid},annotations:{"gsj.io/ownership-sha256":$digest},ownerReferences:[{apiVersion:"v1",kind:"ConfigMap",name:$name,uid:$plan_uid,controller:false,blockOwnerDeletion:false}]},spec:$spec[0]}' > "$work/new-job.json"
   vc_owner
   vc_k create -f "$work/new-job.json" -o json > "$work/job.json" || vc_k get job "$job" -o json > "$work/job.json"
 fi
 vc_validate_job
 job_uid=$(jq -er '.metadata.uid' "$work/job.json")
 if [[ $(jq -r '.metadata.annotations["gsj.io/job-uid"] // ""' "$work/plan.json") == '' ]]; then
   vc_record_job_uid
 fi
 if ! jq -e 'any(.status.conditions[]?;(.type=="Complete" or .type=="Failed") and .status=="True")' "$work/job.json" >/dev/null; then
   vc_k wait --for=condition=complete "job/$job" --timeout=310s > "$work/wait.log" 2>&1 || true
   vc_k get job "$job" -o json > "$work/job.json"; vc_validate_job
 fi
 vc_save "$work/job.json" "$saved/attempt-$attempt-job.json"
 if jq -e 'any(.status.conditions[]?;.type=="Failed" and .status=="True")' "$work/job.json" >/dev/null; then
   printf 'GSJ: cleanup attempt %s failed; owned Job and intent retained\n' "$attempt" >&2
   continue
 fi
 jq -e 'any(.status.conditions[]?;.type=="Complete" and .status=="True")' "$work/job.json" >/dev/null || vc_fail 'cleanup Job still active; resume the existing attempt'
 vc_k get pods -l "batch.kubernetes.io/job-name=$job" -o json > "$work/pods.json"
 jq -er --arg uid "$job_uid" '[.items[]|select(any(.metadata.ownerReferences[]?;.kind=="Job" and .uid==$uid))|select(.status.phase=="Succeeded")|select(any(.status.containerStatuses[]?;.name=="provision" and .state.terminated.exitCode==0))]|if length==1 then .[0].metadata.name else error("ambiguous cleanup completion pod") end' "$work/pods.json" > "$work/success-pod"
 success_pod=$(cat "$work/success-pod")
 success_uid=$(jq -er --arg name "$success_pod" '.items[]|select(.metadata.name==$name)|.metadata.uid' "$work/pods.json")
 vc_k logs "$success_pod" -c provision > "$work/cleanup-result.json"
 [[ $(vc_k get pod "$success_pod" -o json | jq -er '.metadata.uid') == "$success_uid" ]] || vc_fail 'cleanup evidence pod changed'
 jq -e --slurpfile owned "$work/owned.json" '.generation==$owned[0].generation and
   ([.users[]|select(.deleted==true or .already_absent==true)|{login,id}]|sort_by(.login))==($owned[0].users|sort_by(.login)) and
   (.users|length)==($owned[0].users|length)' "$work/cleanup-result.json" >/dev/null || vc_fail 'cleanup result identity differs'
 vc_save "$work/cleanup-result.json" "$saved/cleanup-result.json"
 vc_owner
 vc_k exec -i "$pod" -c gsj-web -- sh -c "umask 077; cat > '$remote/cleanup-result.json'" < "$saved/cleanup-result.json"
 code=0
 vc_k exec "$pod" -c gsj-web -- python -m gsj_deploy.verify --finalize-cleanup "$remote/cleanup-result.json" --report-dir "$remote" > "$work/finalize.log" || code=$?
 if (( code == 78 )); then exit 78; fi
 (( code == 0 || code == 77 )) || vc_fail 'verifier rejected exact account cleanup'
 vc_mark_finalized
 vc_retire_terminal
 vc_report
 exit "$code"
done
# The round is spent. Three rounds is the whole budget; beyond it no command
# opens another, and the evidence of all of them stays retained for inspection.
(( round < 3 )) || vc_fail "all 3 bounded cleanup rounds are exhausted; failed/unknown evidence retained and no further round is permitted"
# Only repair exports the signal. A named resume re-enters this same ladder, so
# it is told what actually reopens the run instead of being sent back into it.
[[ ${GSJ_CLEANUP_NEW_ROUND:-} == 1 ]] || vc_spent "all three durable cleanup attempts of round $round are exhausted; failed/unknown evidence retained. Fix the cause the Job reported, then repair --operation ID opens a new bounded cleanup round"
# One repair opens one round: spend the signal before the fresh attempts run.
GSJ_CLEANUP_NEW_ROUND=0
vc_open_round
done
