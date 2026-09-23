# Explicit recovery of a signed first startup. This file never declares readiness.
authenticate_predecessor() {
 local installer=$1 expected=$2 directory=$3 parent descriptor signature version marker count file
 parent=$(cd "$(dirname "$installer")" && pwd); installer="$parent/$(basename "$installer")"
 descriptor="$parent/installer-descriptor.json"; signature="$parent/installer-descriptor.sig"
 for file in "$installer" "$descriptor" "$signature"; do
   [[ -f $file && ! -L $file ]] || fail 'source installer and its detached signature must be regular files'
 done
 # The current installer's out-of-band trust root is authoritative. Never use
 # a key supplied alongside the predecessor and never execute its Bash header.
 openssl dgst -sha256 -verify "$GSJ_PAYLOAD/trust/release.pem" -signature "$signature" "$descriptor" >/dev/null 2>&1 || fail 'source installer signature is invalid'
 version=$(jq -er '.version|select(type=="string" and length>0)' "$descriptor")
 verify_target "$descriptor" "$signature" "$installer" "$version"
 jq -e --arg identity "$expected" '.releaseId==$identity and .installer.name=="gsj-install.sh" and (.manifestSha256|test("^[a-f0-9]{64}$"))' "$descriptor" >/dev/null || fail 'signed predecessor is not the exact failed source release'
 [[ ! -e $directory && ! -L $directory ]] || fail 'predecessor extraction destination already exists'
 mkdir -m 700 "$directory"; mkdir -m 700 "$directory/payload"
 count=$(awk '/^__GSJ_PAYLOAD_BELOW__$/ {n++} END {print n+0}' "$installer")
 [[ $count == 1 ]] || fail 'source installer payload boundary is ambiguous'
 marker=$(awk '/^__GSJ_PAYLOAD_BELOW__$/ {print NR; exit}' "$installer")
 head -n "$marker" "$installer" > "$directory/runtime.sh"
 tail -n "+$((marker+1))" "$installer" | base64 --decode > "$directory/payload.tar.gz" || fail 'source installer payload is not valid base64'
 tar -tzf "$directory/payload.tar.gz" > "$directory/members"
 [[ -s $directory/members ]] && awk '
   !/^[A-Za-z0-9_.\/-]+$/ || /^\// || /(^|\/)\.\.?($|\/)/ || /\/\// || /\/$/ {exit 1}
   {if (seen[$0]++) exit 1}
 ' "$directory/members" || fail 'source payload has unsafe or duplicate paths'
 tar -tvzf "$directory/payload.tar.gz" | awk 'substr($0,1,1)!="-" {exit 1}' || fail 'source payload must contain regular files only'
 tar -xzf "$directory/payload.tar.gz" --no-same-owner --no-same-permissions --keep-old-files -C "$directory/payload"
 [[ $(sha_file "$directory/payload/release.json") == $(jq -r .manifestSha256 "$descriptor") ]] || fail 'signed source manifest hash differs'
 jq -e --arg expected "$expected" --arg runtime "$(sha_file "$directory/runtime.sh")" --arg trust "$(sha_file "$GSJ_PAYLOAD/trust/release.pem")" '.identity==$expected and .runtimeSha256==$runtime and .trustKeySha256==$trust' "$directory/payload/release.json" >/dev/null || fail 'source manifest, runtime or trust identity differs'
 (cd "$directory/payload"; if command -v sha256sum >/dev/null; then sha256sum -c SHA256SUMS >/dev/null; else shasum -a 256 -c SHA256SUMS >/dev/null; fi) || fail 'source payload hashes differ'
 while IFS=$'\t' read -r file count; do
   [[ -f $directory/payload/$file && $(sha_file "$directory/payload/$file") == "$count" ]] || fail 'source payload inventory differs'
 done < <(jq -r '.payloadInventory|to_entries[]|[.key,.value.sha256]|@tsv' "$directory/payload/release.json")
 cp "$installer" "$directory/gsj-install.sh"; cp "$descriptor" "$directory/installer-descriptor.json"; cp "$signature" "$directory/installer-descriptor.sig"
 PREDECESSOR_PAYLOAD="$directory/payload"
}

startup_source_projection_matches() {
 jq -e --slurpfile expected "$2" '
   def subset($actual;$want):
     if ($want|type)=="object" then ($actual|type)=="object" and all($want|keys[]; . as $k|subset($actual[$k];$want[$k]))
     elif ($want|type)=="array" then ($actual|type)=="array" and ($actual|length)==($want|length) and all(range(0;$want|length); . as $i|subset($actual[$i];$want[$i]))
     else $actual==$want end;
   subset(.;$expected[0]) and ([.[]|select(.kind=="ConfigMap")|.data]==[$expected[0][]|select(.kind=="ConfigMap")|.data])
 ' "$1" >/dev/null
}

startup_source_site_matches() {
 local site=$1 original=$2 directory=$3 namespace_uid=$4 tlsdir="$STATE_DIR/tls" file mode owner secret host key_hash cert_hash
 printf 'null\n' > "$directory/derived-ca.json"
 if jq -e --slurpfile original "$original" '.==$original[0]' "$site" >/dev/null; then return; fi
 # Older installers filled these two generated trust paths after acquiring
 # the immutable operation intent. Qualify that exact derivation; never
 # accept arbitrary edits just because they leave Helm values unchanged.
 jq -e --arg ca "$tlsdir/ca.crt" --slurpfile original "$original" '
   $original[0] as $o |
   $o.tls.profile=="managed-local-ca" and .tls.profile=="managed-local-ca" and
   $o.tls.ca_file=="" and $o.verification.ca_file=="" and
   .tls.ca_file==$ca and .verification.ca_file==$ca and
   del(.tls.ca_file,.verification.ca_file)==($o|del(.tls.ca_file,.verification.ca_file))
 ' "$site" >/dev/null || fail 'modern source site differs from its immutable operation intent'
 [[ -d $tlsdir && ! -L $tlsdir ]] || fail 'derived local CA directory is not owned ordinary state'
 mode=$(stat -c %a "$tlsdir" 2>/dev/null || stat -f %Lp "$tlsdir")
 owner=$(stat -c %u "$tlsdir" 2>/dev/null || stat -f %u "$tlsdir")
 (( (8#$mode & 077) == 0 )) && [[ $owner == $(id -u) ]] || fail 'derived local CA directory ownership or permissions differ'
 for file in ca.crt ca.key tls.crt tls.key; do
   [[ -f $tlsdir/$file && ! -L $tlsdir/$file ]] || fail 'derived local CA evidence requires regular retained files'
   mode=$(stat -c %a "$tlsdir/$file" 2>/dev/null || stat -f %Lp "$tlsdir/$file")
   owner=$(stat -c %u "$tlsdir/$file" 2>/dev/null || stat -f %u "$tlsdir/$file")
   (( (8#$mode & 022) == 0 )) && [[ $owner == $(id -u) ]] || fail 'derived local CA file ownership or permissions differ'
 done
 private_file "$tlsdir/ca.key"; private_file "$tlsdir/tls.key"
 [[ $(openssl x509 -in "$tlsdir/ca.crt" -noout -subject -nameopt RFC2253 2>/dev/null) == 'subject=CN=GSJ sandbox local CA' ]] || fail 'derived CA is outside the managed local profile'
 openssl verify -x509_strict -check_ss_sig -CAfile "$tlsdir/ca.crt" "$tlsdir/ca.crt" "$tlsdir/tls.crt" >/dev/null 2>&1 || fail 'derived local CA or leaf chain is invalid'
 host=$(jq -r '.public_url|sub("^https://";"")|split(":")[0]|split("/")[0]' "$site")
 certificate_names_host "$tlsdir/tls.crt" "$host" || fail 'derived local certificate hostname differs'
 for file in ca tls; do
   key_hash=$(openssl pkey -in "$tlsdir/$file.key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')
   cert_hash=$(openssl x509 -in "$tlsdir/$file.crt" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')
   [[ $key_hash == "$cert_hash" ]] || fail 'derived local certificate and retained private key differ'
 done
 secret=$(jq -er .tls.secret "$original")
 k get secret "$secret" -o json > "$directory/local-ca-secret-private.json"
 jq -e --arg name "$secret" --arg namespace "$NAMESPACE" '.kind=="Secret" and .type=="kubernetes.io/tls" and .metadata.name==$name and .metadata.namespace==$namespace and (.metadata.uid|type=="string" and length>0) and .metadata.deletionTimestamp==null and all(.data["tls.crt"],.data["tls.key"];type=="string" and length>0)' "$directory/local-ca-secret-private.json" >/dev/null || fail 'derived local TLS Secret identity or type differs'
 for file in crt key; do
   cert_hash=$(jq -er --arg key "tls.$file" '.data[$key]' "$directory/local-ca-secret-private.json" | base64 --decode | openssl dgst -sha256 | awk '{print $NF}')
   [[ $cert_hash == $(sha_file "$tlsdir/tls.$file") ]] || fail 'current TLS Secret differs from the retained local certificate/key'
 done
 jq -n --arg namespace_uid "$namespace_uid" --arg ca "$(sha_file "$tlsdir/ca.crt")" --arg certificate "$(sha_file "$tlsdir/tls.crt")" --arg original "$(sha_file "$original")" --slurpfile secret "$directory/local-ca-secret-private.json" '{format:"gsj.startup-derived-local-ca/1",namespace_uid:$namespace_uid,original_site_sha256:$original,ca_sha256:$ca,certificate_sha256:$certificate,tls_secret:{name:$secret[0].metadata.name,uid:$secret[0].metadata.uid},chain_verified:true,private_key_match:true}' > "$directory/derived-ca.json"
}

startup_source_control() {
 local directory=$1 source=$2 values=$3 site=$4 revision object kind name uid prior attempt intent runtime
 runtime="$(dirname "$source")/runtime.sh"
 printf 'null\n' > "$directory/derived-ca.json"
 # A first-startup proof is never a fallback for an existing application record.
 for kind in installed ready-state; do
   object=$(k get configmap "$RELEASE-$kind" -o json --ignore-not-found)
   [[ -z $object ]] || fail 'startup recovery cannot replace an installed or ready source record'
 done
 k get secrets -l "owner=helm,name=$RELEASE" -o json > "$directory/history-private.json"
 jq -e --arg release "$RELEASE" '(.items|length)>0 and all(.items[];.type=="helm.sh/release.v1" and .metadata.labels.owner=="helm" and .metadata.labels.name==$release and (.metadata.labels.version|test("^[1-9][0-9]*$")) and (.metadata.uid|type=="string" and length>0))' "$directory/history-private.json" >/dev/null || fail 'failed source Helm history is missing or malformed'
 revision=$(jq '[.items[].metadata.labels.version|tonumber]|max' "$directory/history-private.json")
 jq --argjson revision "$revision" '.items[]|select((.metadata.labels.version|tonumber)==$revision)' "$directory/history-private.json" > "$directory/latest-private.json"
 addon_release_decode "$directory/latest-private.json" "$directory/stored-private.json"
 jq -e --arg release "$RELEASE" --arg namespace "$NAMESPACE" --argjson revision "$revision" '.name==$release and .namespace==$namespace and .version==$revision and .info.status=="deployed"' "$directory/stored-private.json" >/dev/null || fail 'failed startup requires a completed Helm provisioning revision; pending Helm needs separate repair'
 jq '.config' "$directory/stored-private.json" > "$directory/stored-values.json"
 jq -e --slurpfile expected "$values" '.==$expected[0]' "$directory/stored-values.json" >/dev/null || fail 'source Helm values differ from the saved failed operation'
 require_offline_render; KUBECONFIG=/dev/null HELM_DRIVER=secret helm install "$RELEASE" "$source/chart.tgz" --namespace "$NAMESPACE" --values "$values" --dry-run=client --output json > "$directory/rendered-release.json"
 # Compare Helm's normalized chart serialization, not its unrecoverable tar metadata.
 jq -e --slurpfile signed "$directory/rendered-release.json" '(.chart|del(.modtime,.schemamodtime))==($signed[0].chart|del(.modtime,.schemamodtime)) and .config==$signed[0].config' "$directory/stored-private.json" >/dev/null || fail 'stored Helm chart or configuration is not the authenticated predecessor'
 h template "$RELEASE" "$source/chart.tgz" --values "$values" --show-only templates/gsj.yaml --show-only templates/forgejo.yaml --show-only templates/chroma.yaml --show-only templates/scripts-configmap.yaml --show-only templates/provision-job.yaml > "$directory/expected.yaml"
 k create --dry-run=client --validate=false -f "$directory/expected.yaml" -o json | jq -s '{kind:"List",items:[.[]|if .kind=="List" then .items[] else . end]}' > "$directory/expected-resources.json"
 jq --arg generation "$(jq -r .identity "$source/release.json"):$revision" 'walk(if type=="object" and .name?=="GSJ_DEPLOYMENT_GENERATION" and has("value") then .value=$generation else . end)' "$directory/expected-resources.json" > "$directory/expected-generation.json"
 helm_application_projection "$directory/expected-generation.json" > "$directory/expected.json"
 jq -e --arg release "$RELEASE" '([.[]|select(.kind=="Deployment")|.name]|sort)==([$release+"-web",$release+"-forgejo",$release+"-chroma"]|sort) and ([.[]|select(.kind=="Job")|.name]==[$release+"-provision"]) and ([.[]|select(.kind=="ConfigMap")|.name]==[$release+"-scripts"])' "$directory/expected.json" >/dev/null || fail 'signed predecessor has an unsupported workload inventory'
 : > "$directory/actual.jsonl"
 while IFS=$'\t' read -r kind name; do
   object=$(k get "$kind" "$name" -o json)
   jq -e '.metadata.deletionTimestamp==null and (.metadata.uid|type=="string" and length>0)' <<< "$object" >/dev/null || fail 'source workload is absent or being replaced'
   if [[ $kind == Job ]]; then
     jq -e '.status.succeeded==1 and (.status.active//0)==0 and any(.status.conditions[]?;.type=="Complete" and .status=="True")' <<< "$object" >/dev/null || fail 'source provisioning is incomplete or still writable'
   else
     jq -e --arg release "$RELEASE" --arg namespace "$NAMESPACE" '.metadata.annotations["meta.helm.sh/release-name"]==$release and .metadata.annotations["meta.helm.sh/release-namespace"]==$namespace' <<< "$object" >/dev/null || fail 'source workload Helm ownership differs'
   fi
   printf '%s\n' "$object" >> "$directory/actual.jsonl"
 done < <(jq -r '.[]|[.kind,.name]|@tsv' "$directory/expected.json")
 jq -s '.' "$directory/actual.jsonl" > "$directory/actual.json"
 helm_application_projection "$directory/actual.json" > "$directory/actual-projection.json"
 # The durable intent permits only its own recorded scale-to-zero transition.
 if [[ -n ${STARTUP_SAVED_DIR:-} ]]; then
   jq '{items:[.[]|select(.kind=="Deployment")]}' "$directory/actual.json" > "$directory/controllers.json"
   backup_quiesce_transition "$STARTUP_SAVED_DIR/quiescence-intent.json" "$directory/controllers.json"
   jq 'map(if .kind=="Deployment" then del(.replicas) else . end)' "$directory/actual-projection.json" > "$directory/actual-comparable.json"
   jq 'map(if .kind=="Deployment" then del(.replicas) else . end)' "$directory/expected.json" > "$directory/expected-comparable.json"
 else
   cp "$directory/actual-projection.json" "$directory/actual-comparable.json"; cp "$directory/expected.json" "$directory/expected-comparable.json"
 fi
 startup_source_projection_matches "$directory/actual-comparable.json" "$directory/expected-comparable.json" || fail 'live source images, commands, environment, mounts, scripts or provisioning differ'
 jq -r '.[]|select(.kind=="ConfigMap")|.data["initializer.json"]' "$directory/actual.json" > "$directory/initializer.json"
 uid=$(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid)
 attempt=$(jq -r '.helm_application//empty' "$STATE_DIR/operation.json")
 if [[ -f $runtime ]] && awk '/^helm_application_prepare\(\) \{/ {found=1} END {exit !found}' "$runtime"; then
   [[ -n $attempt ]] || fail 'modern predecessor is missing its durable Helm application intent'
 fi
 if [[ -n $attempt ]]; then
   [[ $attempt =~ ^[a-f0-9]{24}$ ]] || fail 'invalid saved Helm application identity'
   intent="$STATE_DIR/helm-applications/$OPERATION/$attempt"
   jq -e --arg operation "$OPERATION" --arg uid "$uid" --arg target "$(jq -r .identity "$source/release.json")" --arg chart "$(sha_file "$source/chart.tgz")" --argjson revision "$revision" '.format=="gsj.helm-application/1" and .operation==$operation and .namespace_uid==$uid and .target==$target and .chart_sha256==$chart and .revision==$revision' "$intent/intent.json" >/dev/null || fail 'source differs from its modern Helm application intent'
   [[ $(sha_file "$intent/expected.json") == $(jq -r .expected_sha256 "$intent/intent.json") && $(sha_file "$intent/values.json") == $(jq -r .values_sha256 "$intent/intent.json") ]] || fail 'saved source Helm intent bytes changed'
   jq -e --slurpfile saved "$intent/values.json" '.==$saved[0]' "$values" >/dev/null || fail 'saved source intent values differ'
   jq -e --slurpfile intent "$intent/intent.json" 'all(.[]|select(.kind=="Job");.metadata.uid!=$intent[0].prior_job_uid)' "$directory/actual.json" >/dev/null || fail 'modern startup requires its fresh provisioning Job, not an older completed hook'
 fi
 if [[ -f $runtime ]] && awk '/^create_operation_intent\(\) \{/ {found=1} END {exit !found}' "$runtime"; then
   intent="$STATE_DIR/operation-intents/$OPERATION"
   for name in intent.json site.json values.json release.json; do [[ -f $intent/$name && ! -L $intent/$name ]] || fail 'modern predecessor operation intent is incomplete'; done
   jq -e --arg operation "$OPERATION" --arg target "$(jq -r .identity "$source/release.json")" --arg context "$CONTEXT" --arg ns "$NAMESPACE" --arg uid "$uid" --arg release "$RELEASE" --arg site "$(sha_file "$intent/site.json")" --arg values "$(sha_file "$intent/values.json")" --arg manifest "$(sha_file "$intent/release.json")" '.format=="gsj.operation-intent/1" and .record.operation==$operation and .record.target==$target and .record.kind=="install" and .context==$context and .namespace==$ns and .namespace_uid==$uid and .release==$release and .site_sha256==$site and .values_sha256==$values and .release_sha256==$manifest' "$intent/intent.json" >/dev/null || fail 'modern source operation intent identity differs'
   cmp -s "$source/release.json" "$intent/release.json" || fail 'modern operation names a different signed predecessor manifest'
   startup_source_site_matches "$site" "$intent/site.json" "$directory" "$uid"
   jq -e --slurpfile saved "$intent/values.json" '.==$saved[0]' "$values" >/dev/null || fail 'modern source values differ from its immutable operation intent'
   object=$(lease_read)
   jq -e --arg operation "$OPERATION" --arg sha "$(sha_file "$intent/intent.json")" --slurpfile intent "$intent/intent.json" '.spec.holderIdentity==$operation and .metadata.annotations["gsj.io/operation-intent-sha256"]==$sha and .spec.acquireTime==$intent[0].acquire_time and ($intent[0].prior_lease_uid=="" or .metadata.uid==$intent[0].prior_lease_uid)' <<< "$object" >/dev/null || fail 'source Lease is not bound to its immutable modern operation intent'
 fi
 jq -n --slurpfile manifest "$source/release.json" --slurpfile site "$site" --slurpfile storage "$GSJ_WORK/storage.json" --arg uid "$uid" '{format:"gsj.installed/1",status:"startup-unverified",manifest:$manifest[0],site:$site[0],storage:$storage[0],namespace_uid:$uid,application_readiness_verified:false}' > "$GSJ_WORK/installed.json"
 capacity_source_identity "$directory/storage"
 k get configmap "$RELEASE-provisioned" -o json > "$directory/provisioned.json"
 jq -e --arg generation "$(jq -r .identity "$source/release.json"):$revision" --arg identity "$(jq -r .identity "$source/release.json")" '.data.status=="provisioned" and .data.generation==$generation and .data.release_identity==$identity' "$directory/provisioned.json" >/dev/null || fail 'source credential marker does not match its exact generation'
 jq -n --arg operation "$OPERATION" --arg generation "$(jq -r .identity "$source/release.json"):$revision" --arg manifest "$(sha_file "$source/release.json")" --arg chart "$(sha_file "$source/chart.tgz")" --arg values "$(sha_file "$values")" --arg site "$(sha_file "$site")" --arg expected "$(sha_file "$directory/expected.json")" --arg uid "$uid" --arg history "$(sha_file "$directory/history-private.json")" --slurpfile actual "$directory/actual.json" --slurpfile storage "$directory/storage-bindings.json" --slurpfile ca "$directory/derived-ca.json" '{format:"gsj.startup-source-control/1",operation:$operation,generation:$generation,namespace_uid:$uid,manifest_sha256:$manifest,chart_sha256:$chart,values_sha256:$values,site_sha256:$site,expected_sha256:$expected,helm_history_sha256:$history,resources:[$actual[0][]|{kind,name:.metadata.name,uid:.metadata.uid}],storage_bindings:$storage[0],application_readiness_verified:false} | if $ca[0]==null then . else . + {derived_local_ca:$ca[0]} end' > "$directory/control.json"
}

startup_source_select() {
 local prior installer directory saved='' file
 OPERATION=${OPERATION:-$RESUME_ID}
 prior=$(jq -er '.startup_source.release_identity // .target' "$STATE_DIR/operation.json")
 if jq -e '.startup_source!=null' "$STATE_DIR/operation.json" >/dev/null; then
   saved="$STATE_DIR/startup-source-$OPERATION"
   [[ -d $saved && ! -L $saved ]] || fail 'saved startup recovery evidence is missing'
   installer="$saved/gsj-install.sh"
   [[ -z ${SOURCE_INSTALLER:-} || $(sha_file "$SOURCE_INSTALLER") == $(sha_file "$installer") ]] || fail 'selected predecessor differs from the reserved startup recovery'
 else
   [[ -n ${SOURCE_INSTALLER:-} ]] || fail 'failed first startup requires --source-installer with the exact signed predecessor'
   installer=$SOURCE_INSTALLER
   # Earlier installers recorded no operation kind. With no installed record,
   # no pre-migration backup and no restore checkpoint, such a record can only
   # be the unfinished first install this path recovers.
   local legacy=false
   [[ -e $STATE_DIR/restoration.json || -L $STATE_DIR/restoration.json ]] || legacy=true
   jq -e --arg operation "$OPERATION" --argjson legacy "$legacy" '.operation==$operation and (.kind=="install" or ($legacy and (has("kind")|not) and (has("backup")|not))) and (.status|IN("owned","applying","initializing","startup-proving"))' "$STATE_DIR/operation.json" >/dev/null || fail 'startup recovery applies only to an unfinished first install'
 fi
 directory=$(mktemp -d "$GSJ_WORK/startup-control.XXXXXXXX")
 authenticate_predecessor "$installer" "$prior" "$directory/predecessor"
 if [[ -n $saved ]]; then
   for file in control.json site.json values.json quiescence-intent.json; do [[ -f $saved/$file && ! -L $saved/$file ]] || fail 'startup recovery intent is incomplete'; done
   [[ $(sha_file "$saved/control.json") == $(jq -r .startup_source.control_sha256 "$STATE_DIR/operation.json") ]] || fail 'startup recovery control proof changed'
   [[ $(sha_file "$saved/quiescence-intent.json") == $(jq -r .startup_source.quiescence_sha256 "$STATE_DIR/operation.json") ]] || fail 'startup source controller/credential intent changed'
   cp "$saved/site.json" "$directory/site.json"; cp "$saved/values.json" "$directory/values.json"
 else
   jq -s '.[0]*.[1]' "$PREDECESSOR_PAYLOAD/defaults.json" "$STATE_DIR/site.pending.json" | jq --slurpfile schema "$PREDECESSOR_PAYLOAD/site.schema.json" -f "$PREDECESSOR_PAYLOAD/validate.jq" > "$directory/site.json"
   jq --slurpfile release "$PREDECESSOR_PAYLOAD/release.json" -f "$PREDECESSOR_PAYLOAD/compile.jq" "$directory/site.json" > "$directory/values.json"
   jq -e --slurpfile saved "$STATE_DIR/values.pending.json" '.==$saved[0]' "$directory/values.json" >/dev/null || fail 'saved first-startup configuration does not compile to its signed predecessor values'
 fi
 storage_identity > "$GSJ_WORK/storage.json"
 STARTUP_SAVED_DIR=$saved startup_source_control "$directory" "$PREDECESSOR_PAYLOAD" "$directory/values.json" "$directory/site.json"
 if [[ -n $saved ]]; then
   cmp -s "$directory/control.json" "$saved/control.json" || fail 'authenticated startup control or storage identities changed'
   cmp -s "$directory/initializer.json" "$saved/initializer.json" || fail 'saved source initializer differs from its signed scripts'
   helm_application_projection "$saved/actual.json" > "$directory/saved-actual-projection.json"
   startup_source_projection_matches "$directory/saved-actual-projection.json" "$directory/expected.json" || fail 'saved source workload templates differ from the authenticated chart'
   jq -e --slurpfile control "$saved/control.json" '[.[]|{kind,name:.metadata.name,uid:.metadata.uid}]==$control[0].resources' "$saved/actual.json" >/dev/null || fail 'saved source workload identities changed'

   if [[ -f $saved/source.json ]]; then
     jq -e --arg control "$(sha_file "$saved/control.json")" --arg proof "$(sha_file "$saved/data-proof.json")" --arg credential "$(sha_file "$saved/credentials.json")" '.status=="startup-complete" and .application_readiness_verified==false and .startup_proof.control_sha256==$control and .startup_proof.data_sha256==$proof and .startup_proof.credentials_sha256==$credential' "$saved/source.json" >/dev/null || fail 'completed startup evidence is missing or changed'
     jq -e --slurpfile actual "$GSJ_WORK/installed.json" '{manifest,site,storage,namespace_uid}==($actual[0]|{manifest,site,storage,namespace_uid})' "$saved/source.json" >/dev/null || fail 'completed startup source differs from its authenticated inputs'
     cp "$saved/source.json" "$GSJ_WORK/installed.json"
   fi
 fi
 STARTUP_CONTROL_DIR=$directory
}

startup_owned_pod() {
 local name=$1 document=$2 directory="$STATE_DIR/startup-source-$OPERATION/pods" object uid
 mkdir -p "$directory"; chmod 700 "$directory"
 jq --arg op "$OPERATION" --arg control "$(jq -r .startup_source.control_sha256 "$STATE_DIR/operation.json")" '.metadata.labels["gsj.io/startup-source"]=$op|.metadata.annotations["gsj.io/startup-control"]=$control' "$document" > "$GSJ_WORK/startup-pod.json"
 if [[ -f $directory/$name.json ]]; then
   cmp -s "$GSJ_WORK/startup-pod.json" "$directory/$name.json" || fail 'startup proof Pod template changed'
 else
   object=$(k get pod "$name" -o json --ignore-not-found); [[ -z $object ]] || fail 'startup proof Pod name is already occupied'
   cat "$GSJ_WORK/startup-pod.json" | immutable_file "$directory/$name.json"
 fi
 object=$(k get pod "$name" -o json --ignore-not-found)
 if [[ -z $object ]]; then
   [[ ! -f $directory/$name.uid ]] || fail 'recorded startup proof Pod disappeared; preserve evidence and reconcile the named operation'
   assert_owner; k create -f "$directory/$name.json" -o json > "$GSJ_WORK/startup-pod-live.json"
 else printf '%s\n' "$object" > "$GSJ_WORK/startup-pod-live.json"; fi
 owned_resource_matches "$GSJ_WORK/startup-pod-live.json" "$directory/$name.json" || fail 'saved startup proof Pod identity or template differs'
 jq -e '.metadata.deletionTimestamp==null and ((.status.phase//"Pending")|IN("Pending","Running"))' "$GSJ_WORK/startup-pod-live.json" >/dev/null || fail 'startup proof Pod is terminating or terminal; retain its named evidence for reconciliation'
 uid=$(jq -er .metadata.uid "$GSJ_WORK/startup-pod-live.json")
 if [[ -f $directory/$name.uid ]]; then [[ $(cat "$directory/$name.uid") == "$uid" ]] || fail 'startup proof Pod UID changed'
 else printf '%s\n' "$uid" | immutable_file "$directory/$name.uid"; fi
 k wait --for=jsonpath='{.status.phase}'=Running "pod/$name" --timeout=300s >/dev/null
}

startup_delete_pod() {
 local name=$1 directory="$STATE_DIR/startup-source-$OPERATION/pods" object uid
 uid=$(cat "$directory/$name.uid"); object=$(k get pod "$name" -o json --ignore-not-found)
 if [[ -n $object ]]; then
   [[ $(jq -r .metadata.uid <<< "$object") == "$uid" ]] || fail 'startup proof Pod was replaced before cleanup'
   assert_owner
   jq -n --arg uid "$uid" '{apiVersion:"v1",kind:"DeleteOptions",preconditions:{uid:$uid}}' > "$GSJ_WORK/startup-delete.json"
   k delete --raw "/api/v1/namespaces/$NAMESPACE/pods/$name" -f "$GSJ_WORK/startup-delete.json" >/dev/null
   k wait --for=delete "pod/$name" --timeout=300s >/dev/null
 fi
 [[ -f $directory/$name.deleted ]] || printf '%s\n' "$uid" | immutable_file "$directory/$name.deleted"
}

startup_source_credentials() {
 local saved=$1 pod="gsj-startup-credentials-$OPERATION" script_hash
 if [[ ! -f $saved/credentials.json ]]; then
   # This remains a provisioning home: use its exact source image, service
   # account and script/secret mounts, but invoke only read-only identity calls.
   jq --arg name "$pod" --arg release "$RELEASE" '.[]|select(.kind=="Job")|{apiVersion:"v1",kind:"Pod",metadata:{name:$name,labels:{"gsj.io/provisioner":$release}},spec:(.spec.template.spec|del(.initContainers)|.containers=[.containers[]|select(.name=="provision")|.command=["sh","-c","while :; do sleep 3600; done"]|del(.args)|.volumeMounts=((.volumeMounts//[])+[{name:"gsj-startup-api",mountPath:"/var/run/secrets/kubernetes.io/serviceaccount",readOnly:true}])]|.restartPolicy="Never"|.automountServiceAccountToken=false|.volumes=((.volumes//[])+[{name:"gsj-startup-api",projected:{defaultMode:420,sources:[{serviceAccountToken:{path:"token",expirationSeconds:3600}},{configMap:{name:"kube-root-ca.crt",items:[{key:"ca.crt",path:"ca.crt"}]}},{downwardAPI:{items:[{path:"namespace",fieldRef:{apiVersion:"v1",fieldPath:"metadata.namespace"}}]}}]}}]))}' "$saved/actual.json" > "$GSJ_WORK/startup-credentials-pod.json"
   startup_owned_pod "$pod" "$GSJ_WORK/startup-credentials-pod.json"
   script_hash=$(jq -jr '.[]|select(.kind=="ConfigMap")|.data["provision.py"]' "$saved/actual.json" | openssl dgst -sha256 | awk '{print $NF}')
   addon_owned_run "$GSJ_WORK/startup-credentials-result.json" k exec "$pod" -- python -B -c 'import hashlib,json,pathlib,runpy,sys; assert hashlib.sha256(pathlib.Path("/scripts/provision.py").read_bytes()).hexdigest()==sys.argv[1],"provision source changed"; m=runpy.run_path("/scripts/provision.py"); a=m["_identity"](m["_token"](m["SECRET_A"],"admin_token"),"gsj-admin",admin=True); b=m["_identity"](m["_token"](m["SECRET_B"],"bot_token"),m["BOT_ACCOUNT"],admin=False); o=m["_operator"](); m["_secret_value"](m["_secret_get"](m["SECRET_C"]),m["SECRET_C"]); print(json.dumps({"format":"gsj.startup-credentials/1","admin_id":a,"bot_id":b,"operator_id":o,"credentials_validated":True}))' "$script_hash"
   jq -e '.format=="gsj.startup-credentials/1" and .credentials_validated==true and all(.admin_id,.bot_id,.operator_id;type=="number" and .==floor and .>0)' "$GSJ_WORK/startup-credentials-result.json" >/dev/null || fail 'source credential validation did not return exact identities'
   cat "$GSJ_WORK/startup-credentials-result.json" | immutable_file "$saved/credentials.json"
 fi
 startup_delete_pod "$pod"
}

startup_prepare_data_pod() {
 local saved=$1 pod="gsj-startup-data-$OPERATION"
 jq --arg name "$pod" --slurpfile source "$GSJ_WORK/installed.json" 'def image_ref($base): (if ($base // "") == "" then . else .repository = ($base + "/" + (.repository | split("/") | last)) end) | .repository + "@" + .digest; .[]|select(.kind=="Deployment" and (.metadata.name|endswith("-web")))|.spec.template as $t|{apiVersion:"v1",kind:"Pod",metadata:{name:$name,labels:$t.metadata.labels},spec:{restartPolicy:"Never",automountServiceAccountToken:false,nodeSelector:$t.spec.nodeSelector,imagePullSecrets:($t.spec.imagePullSecrets//[]),securityContext:($t.spec.securityContext//{}),containers:[{name:"source-proof",image:($source[0].manifest.images.web|image_ref($source[0].site.registry.base)),command:["sh","-c","while :; do sleep 3600; done"],resources:{requests:{cpu:"100m",memory:"512Mi"},limits:{cpu:"1000m",memory:"1536Mi"}},readinessProbe:{exec:{command:["false"]}},volumeMounts:[{name:"data",mountPath:"/volumes/gsj",readOnly:true},{name:"transfer",mountPath:"/transfer"}]}],volumes:[{name:"data",persistentVolumeClaim:{claimName:($source[0].site.storage.data.existing_claim|if .=="" then $source[0].site.target.release+"-data" else . end),readOnly:true}},{name:"transfer",emptyDir:{}}]}}' "$saved/actual.json" > "$GSJ_WORK/startup-data-pod.json"
 startup_owned_pod "$pod" "$GSJ_WORK/startup-data-pod.json"
 jq -n --arg operation "$OPERATION" --arg control "$(sha_file "$saved/control.json")" --slurpfile source "$GSJ_WORK/installed.json" --slurpfile initializer "$saved/initializer.json" --slurpfile proof "$saved/control.json" '$source[0] as $s|{format:"gsj.startup-source-settings/1",operation:$operation,release_identity:$s.manifest.identity,namespace_uid:$s.namespace_uid,generation:$proof[0].generation,control_sha256:$control,corpus_manifest_sha256:$s.manifest.corpus.manifest_sha256,corpus_fingerprint:$s.manifest.corpus.fingerprint,core_commit:$s.manifest.core.commit,model:$s.manifest.model,rows:$s.manifest.corpus.rows,vectors:$s.manifest.corpus.chunks,initializer:$initializer[0],paths:{db:"/volumes/gsj/db/gsj.db",source:("/volumes/gsj/bootstrap/corpora/"+$s.manifest.corpus.manifest_sha256),state:"/volumes/gsj/bootstrap/state",model_path:"/app/models/snowflake-arctic-embed-m-v2.0"},deadline_seconds:$s.site.deadlines.initialization_seconds}' > "$GSJ_WORK/startup-data-settings.json"
 k exec -i "$pod" -- sh -c 'umask 077; cat > /transfer/startup-source-settings.json' < "$GSJ_WORK/startup-data-settings.json"
}

startup_proof_progress() {
 local private=$1 public=$2 count
 # Only this explicit metadata schema can cross the transport log boundary.
 # Malformed lines, arbitrary tool stderr and extra fields are never printed.
 jq -Rc 'fromjson? | select(type=="object" and ((keys|sort)==(["event","rows","shard","vectors"]|sort))) |
   select((.event|IN("source-shard-start","source-shard-verified")) and (.shard|type=="string" and test("^[0-9]{1,20}$")) and all(.rows,.vectors;type=="number" and .==floor and .>=0))' "$private" > "$GSJ_WORK/startup-progress-public.jsonl"
 count=$(wc -l < "$GSJ_WORK/startup-progress-public.jsonl"); count=$((count+0))
 if (( count > STARTUP_PROGRESS_LINES )); then sed -n "$((STARTUP_PROGRESS_LINES+1)),${count}p" "$GSJ_WORK/startup-progress-public.jsonl" >&2; fi
 cp "$GSJ_WORK/startup-progress-public.jsonl" "$public"
 STARTUP_PROGRESS_LINES=$count
}

startup_proof_run() {
 local result=$1 pid rc=0 monitored=false ticks=0
 local progress="$STATE_DIR/startup-source-$OPERATION/progress.jsonl" private="$1.progress-private"
 shift
 assert_owner
 [[ $- == *m* ]] && monitored=true
 set -m
 "$@" > "$result" 2> "$private" & pid=$!
 GSJ_ADDON_COMMAND_PID=$pid
 $monitored || set +m
 STARTUP_PROGRESS_LINES=0
 log "Read-only source inventory proof started; safe shard progress: $progress"
 while kill -0 "$pid" 2>/dev/null; do
   if ! (assert_owner) >/dev/null 2>&1; then
     stop_owned_process_group "$pid"; GSJ_ADDON_COMMAND_PID=''
     fail 'source proof lost operation ownership; original data and partial evidence are preserved'
   fi
   startup_proof_progress "$private" "$progress"
   ticks=$((ticks+1)); if (( ticks % 15 == 0 )); then log 'Read-only source inventory proof is still running'; fi
   sleep 1
 done
 wait "$pid" || rc=$?
 GSJ_ADDON_COMMAND_PID=''
 startup_proof_progress "$private" "$progress"
 if (( rc != 0 )); then
   # The receipt the refusal names must outlive the working directory, which
   # is removed at exit; and exit 78 is the helpers' lock code, not a failed
   # inventory.
   local receipt="$STATE_DIR/startup-source-$OPERATION/proof-private.log"
   mkdir -p "$STATE_DIR/startup-source-$OPERATION"; cp "$private" "$receipt" 2>/dev/null || : > "$receipt"; chmod 600 "$receipt"
   if (( rc == 78 )); then fail "source inventory proof did not run: another verifier, restore or source proof holds the lock (exit 78); wait, then resume"; fi
   fail "source inventory proof did not complete (exit $rc); the corpus was not judged. Its private receipt is at $receipt and the safe shard progress at $progress"
 fi
 assert_owner
}

startup_intent_file() {
 local source=$1 target=$2
 if [[ -e $target || -L $target ]]; then
   [[ -f $target && ! -L $target ]] && cmp -s "$source" "$target" || fail 'interrupted startup evidence differs; original bytes are preserved'
 else cat "$source" | immutable_file "$target"; fi
}

startup_scale_web() {
 local object=$1 replicas=$2 attempt
 [[ $replicas == 0 || $replicas == 1 ]] || fail 'startup scale requires a supported replica count'
 jq -e --arg name "$RELEASE-web" '.kind=="Deployment" and .metadata.name==$name and .metadata.deletionTimestamp==null and all(.metadata.uid,.metadata.resourceVersion;type=="string" and length>0)' "$object" >/dev/null || fail 'startup scale controller identity is incomplete'
 # Scale restricts the write to replicas and preserves UID/RV preconditions.
 # Its JSON representation can omit zero; add supports either representation.
 # With the pinned Kubernetes API, scaling to zero releases the replica field
 # so the next Helm apply can claim it. Top-level JSON patch would retain it.
 cp "$object" "$GSJ_WORK/startup-scale-observed.json"
 for attempt in 1 2 3; do
   jq --argjson replicas "$replicas" '[{op:"test",path:"/metadata/uid",value:.metadata.uid},{op:"test",path:"/metadata/resourceVersion",value:.metadata.resourceVersion},{op:"add",path:"/spec/replicas",value:$replicas}]' "$GSJ_WORK/startup-scale-observed.json" > "$GSJ_WORK/startup-scale.json"
   assert_owner
   if k patch deployment "$RELEASE-web" --subresource=scale --field-manager=gsj-startup-scale --request-timeout=60s --type=json --patch-file "$GSJ_WORK/startup-scale.json" > /dev/null 2> "$GSJ_WORK/startup-scale-error.private"; then return; fi
   [[ $attempt != 3 ]] || break
   k get deployment "$RELEASE-web" --request-timeout=60s -o json > "$GSJ_WORK/startup-scale-latest.json" || fail 'startup scale could not revalidate the original controller after refusal'
   # Status writers can advance RV just after the target template is staged.
   # Revalidate the entire object before using a newer RV. A lost successful
   # write changes replicas/generation and is left for explicit named replay.
   jq -e --slurpfile observed "$GSJ_WORK/startup-scale-observed.json" '
     .metadata.resourceVersion!=$observed[0].metadata.resourceVersion and
     (del(.status,.metadata.resourceVersion,.metadata.managedFields)==
       ($observed[0]|del(.status,.metadata.resourceVersion,.metadata.managedFields)))
   ' "$GSJ_WORK/startup-scale-latest.json" >/dev/null || fail 'startup scale refused; controller identity, specification or generation changed, or no status-only retry is justified'
   cp "$GSJ_WORK/startup-scale-latest.json" "$GSJ_WORK/startup-scale-observed.json"
 done
 fail 'startup scale exhausted three guarded attempts; retain the current state and resume by its named operation'
}

startup_source_complete() {
 assert_owner
 local saved="$STATE_DIR/startup-source-$OPERATION" file fingerprint pod="gsj-startup-data-$OPERATION" web uid snapshot
 if ! jq -e '.startup_source!=null' "$STATE_DIR/operation.json" >/dev/null; then
   [[ ! -L $saved && ( ! -e $saved || -d $saved ) ]] || fail 'startup intent directory is not an ordinary directory'
   capacity_qualify create
   [[ -d $saved ]] || mkdir -m 700 "$saved"
   for file in control.json site.json values.json initializer.json; do startup_intent_file "$STARTUP_CONTROL_DIR/$file" "$saved/$file"; done
   for file in gsj-install.sh installer-descriptor.json installer-descriptor.sig; do startup_intent_file "$STARTUP_CONTROL_DIR/predecessor/$file" "$saved/$file"; done
   if [[ -f $saved/actual.json && ! -L $saved/actual.json ]]; then
     helm_application_projection "$saved/actual.json" > "$GSJ_WORK/startup-saved-projection.json"
     startup_source_projection_matches "$GSJ_WORK/startup-saved-projection.json" "$STARTUP_CONTROL_DIR/expected.json" || fail 'partially recorded startup workloads differ from the signed source'
     jq -e --slurpfile control "$saved/control.json" '[.[]|{kind,name:.metadata.name,uid:.metadata.uid}]==$control[0].resources' "$saved/actual.json" >/dev/null || fail 'partially recorded startup workload identities differ'
   else startup_intent_file "$STARTUP_CONTROL_DIR/actual.json" "$saved/actual.json"; fi
   fingerprint=$(backup_credential_fingerprint) || fail 'the credential fingerprint could not be read from the cluster; nothing was compared'
   backup_storage_bindings > "$GSJ_WORK/startup-bindings.json"
   jq -n --arg operation "$OPERATION" --arg fingerprint "$fingerprint" --slurpfile installed "$GSJ_WORK/installed.json" --slurpfile actual "$saved/actual.json" --slurpfile bindings "$GSJ_WORK/startup-bindings.json" '{format:"gsj.quiescence/1",operation:$operation,round:0,credential_fingerprint:$fingerprint,installed:$installed[0],controllers:{items:[$actual[0][]|select(.kind=="Deployment")]},storage_bindings:$bindings[0]}' > "$GSJ_WORK/startup-quiescence-intent.json"
   startup_intent_file "$GSJ_WORK/startup-quiescence-intent.json" "$saved/quiescence-intent.json"
   # The pointer commits before any application scale operation.
   jq --arg control "$(sha_file "$saved/control.json")" --arg quiescence "$(sha_file "$saved/quiescence-intent.json")" --arg identity "$(jq -r .manifest.identity "$GSJ_WORK/installed.json")" '.startup_source={release_identity:$identity,control_sha256:$control,quiescence_sha256:$quiescence}|.status="startup-proving"' "$STATE_DIR/operation.json" | atomic "$STATE_DIR/operation.json"
 fi
 fingerprint=$(backup_credential_fingerprint) || fail 'the credential fingerprint could not be read from the cluster; nothing was compared'
 [[ $fingerprint == $(jq -r .credential_fingerprint "$saved/quiescence-intent.json") ]] || fail 'startup credentials/configuration changed during recovery'
 if [[ ! -f $saved/source.json ]]; then
   if [[ ! -f $saved/data-proof.json ]]; then
     startup_prepare_data_pod "$saved"
     addon_owned_run "$GSJ_WORK/startup-runtime-preflight.json" k exec -i "$pod" -- python -B - "$(jq -r .manifest.core.commit "$GSJ_WORK/installed.json")" --settings /transfer/startup-source-settings.json < "$GSJ_PAYLOAD/helpers/startup-runtime-preflight.py"
     jq -e '.status=="passed" and .startup_complete==true' "$GSJ_WORK/startup-runtime-preflight.json" >/dev/null || fail 'source runtime or corpus startup is incomplete; no source writer was stopped'
   fi
   web=$(k get deployment "$RELEASE-web" -o json); uid=$(jq -r .metadata.uid <<< "$web")
   jq -e --arg uid "$uid" --arg name "$RELEASE-web" 'any(.controllers.items[];.metadata.name==$name and .metadata.uid==$uid)' "$saved/quiescence-intent.json" >/dev/null || fail 'source web controller was replaced'
   if [[ $(jq -r .spec.replicas <<< "$web") != 0 ]]; then
     printf '%s\n' "$web" > "$GSJ_WORK/startup-stop-web.json"
     startup_scale_web "$GSJ_WORK/startup-stop-web.json" 0
   fi
   k get pods -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=gsj" -o json | jq -r '.items[]|select(any(.metadata.ownerReferences[]?;.kind=="ReplicaSet"))|.metadata.name' > "$GSJ_WORK/startup-writer-pods"
   local writer
   while IFS= read -r writer; do k wait --for=delete "pod/$writer" --timeout=300s >/dev/null; done < "$GSJ_WORK/startup-writer-pods"
   k get pods -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=gsj" -o json | jq -e 'all(.items[];any(.metadata.ownerReferences[]?;.kind=="ReplicaSet")|not)' >/dev/null || fail 'an application writer Pod remains'
   startup_source_credentials "$saved"
   if [[ ! -f $saved/data-proof.json ]]; then
     startup_proof_run "$GSJ_WORK/startup-data-result.json" k exec -i "$pod" -- python -B - --settings /transfer/startup-source-settings.json < "$GSJ_PAYLOAD/helpers/startup-source-proof.py"
     jq -e --arg control "$(sha_file "$saved/control.json")" --arg settings "$(sha_file "$GSJ_WORK/startup-data-settings.json")" '.format=="gsj.startup-source-data-proof/1" and .status=="startup-complete" and .control_sha256==$control and .settings_file_sha256==$settings and .application_readiness_verified==false and .schema_ready==true and .sqlite_quick_check==true and .inventory_verified==true and .model_loaded==true and .document_embeddings_performed==0' "$GSJ_WORK/startup-data-result.json" >/dev/null || fail 'source data proof is incomplete or for another control generation'
     cat "$GSJ_WORK/startup-data-result.json" | immutable_file "$saved/data-proof.json"
   fi
   startup_delete_pod "$pod"
   # Re-check source identities after both actual read-only runtime proofs.
   startup_source_select
   local current; current=$(backup_credential_fingerprint) || fail 'the credential fingerprint could not be read from the cluster; nothing was compared'
   [[ $current == "$fingerprint" ]] || fail 'source credentials changed during proof'
   jq --arg control "$(sha_file "$saved/control.json")" --arg proof "$(sha_file "$saved/data-proof.json")" --arg credential "$(sha_file "$saved/credentials.json")" '.status="startup-complete"|.startup_proof={control_sha256:$control,data_sha256:$proof,credentials_sha256:$credential}|.application_readiness_verified=false' "$GSJ_WORK/installed.json" | immutable_file "$saved/source.json"
 fi
 cp "$saved/source.json" "$GSJ_WORK/installed.json"
 snapshot=$(quiescence_snapshot)
 jq --slurpfile source "$GSJ_WORK/installed.json" '.installed=$source[0]' "$saved/quiescence-intent.json" > "$GSJ_WORK/startup-backup-snapshot.json"
 startup_intent_file "$GSJ_WORK/startup-backup-snapshot.json" "$snapshot"
 log 'Authenticated startup data and credentials proved; application readiness remains unverified'
}

# Continue only the qualified first-startup replica-ownership failure. The
# corrected program executes an authenticated earlier target; its own release
# identity is recorded separately and is never presented as already installed.
startup_helm_render() {
 local payload=$1 values=$2 revision=$3 output=$4
 h template "$RELEASE" "$payload/chart.tgz" --values "$values" \
   --show-only templates/gsj.yaml --show-only templates/forgejo.yaml --show-only templates/chroma.yaml \
   --show-only templates/scripts-configmap.yaml --show-only templates/provision-job.yaml > "$output.yaml"
 k create --dry-run=client --validate=false -f "$output.yaml" -o json | jq -s --arg generation "$(jq -r .identity "$payload/release.json"):$revision" \
   '[.[]|if .kind=="List" then .items[] else . end] | walk(if type=="object" and .name?=="GSJ_DEPLOYMENT_GENERATION" and has("value") then .value=$generation else . end)' > "$output"
}

startup_helm_credentials_match() {
 local directory=$1 kind name current
 : > "$directory/credentials-current.jsonl"
 while IFS=$'\t' read -r kind name; do
   current=$(k get "$kind" "$name" -o json)
   jq -e --arg kind "$kind" --arg name "$name" --slurpfile archived "$directory/resources-private.json" '
     . as $now | [$archived[0].items[]|select(.kind==$kind and .metadata.name==$name)] as $old |
     ($old|length)==1 and .metadata.uid==$old[0].metadata.uid and .metadata.deletionTimestamp==null and
     {kind,type,data,binaryData,immutable}==($old[0]|{kind,type,data,binaryData,immutable})
   ' <<< "$current" >/dev/null || fail 'a preserved credential or trust resource changed after source backup'
   jq -c '{kind,name:.metadata.name,uid:.metadata.uid,type,data,binaryData,immutable}' <<< "$current" >> "$directory/credentials-current.jsonl"
 done < <(jq -r --arg release "$RELEASE" '.items[]|select((.kind=="Secret" and .type!="helm.sh/release.v1") or (.kind=="ConfigMap" and (.metadata.name|IN($release+"-scripts",$release+"-provisioned",$release+"-installed",$release+"-ready-state")|not)))|[.kind,.metadata.name]|@tsv' "$directory/resources-private.json")
 [[ -s $directory/credentials-current.jsonl ]] || fail 'historical credential inventory is missing'
 jq -s 'sort_by(.kind,.name)' "$directory/credentials-current.jsonl" > "$directory/credentials-current-private.json"
}

startup_helm_source_evidence() {
 local directory=$1 saved="$STATE_DIR/startup-source-$OPERATION" file archive snapshot kind name current
 for file in control.json quiescence-intent.json source.json data-proof.json credentials.json actual.json; do
   [[ -f $saved/$file && ! -L $saved/$file ]] || fail 'startup Helm continuation requires the original completed source evidence'
 done
 jq -e --arg control "$(sha_file "$saved/control.json")" --arg intent "$(sha_file "$saved/quiescence-intent.json")" '.startup_source.control_sha256==$control and .startup_source.quiescence_sha256==$intent' "$STATE_DIR/operation.json" >/dev/null || fail 'startup source intent bytes changed'
 jq -e --arg control "$(sha_file "$saved/control.json")" --arg data "$(sha_file "$saved/data-proof.json")" --arg credentials "$(sha_file "$saved/credentials.json")" '.status=="startup-complete" and .application_readiness_verified==false and .startup_proof=={control_sha256:$control,data_sha256:$data,credentials_sha256:$credentials}' "$saved/source.json" >/dev/null || fail 'startup data or credential proof bytes changed'
 authenticate_predecessor "$saved/gsj-install.sh" "$(jq -r .startup_source.release_identity "$STATE_DIR/operation.json")" "$directory/source"
 jq -e --slurpfile manifest "$PREDECESSOR_PAYLOAD/release.json" '.manifest==$manifest[0]' "$saved/source.json" >/dev/null || fail 'startup proof does not name the authenticated original source'
 jq -e --slurpfile source "$saved/source.json" --slurpfile control "$saved/control.json" --arg operation "$OPERATION" '.format=="gsj.startup-source-data-proof/1" and .operation==$operation and .control_sha256==$source[0].startup_proof.control_sha256 and .generation==$control[0].generation and .rows==$source[0].manifest.corpus.rows and .vectors==$source[0].manifest.corpus.chunks and .release_identity==$source[0].manifest.identity and .namespace_uid==$source[0].namespace_uid and .core_commit==$source[0].manifest.core.commit and .model==$source[0].manifest.model and .corpus_manifest_sha256==$source[0].manifest.corpus.manifest_sha256 and .corpus_fingerprint==$source[0].manifest.corpus.fingerprint and .application_readiness_verified==false and .inventory_verified==true and .schema_ready==true and .sqlite_quick_check==true and .model_loaded==true and .document_embeddings_performed==0' "$saved/data-proof.json" >/dev/null || fail 'startup source content proof is incomplete'
 if awk '/^create_operation_intent\(\) \{/ {found=1} END {exit !found}' "$directory/source/runtime.sh"; then
   local original="$STATE_DIR/operation-intents/$OPERATION/intent.json" lease
   [[ -f $original && ! -L $original ]] || fail 'modern source operation intent is missing'
   jq -e --arg op "$OPERATION" --arg context "$CONTEXT" --arg ns "$NAMESPACE" --arg release "$RELEASE" --slurpfile source "$saved/source.json" '.format=="gsj.operation-intent/1" and .record.operation==$op and .record.kind=="install" and .record.target==$source[0].manifest.identity and .context==$context and .namespace==$ns and .namespace_uid==$source[0].namespace_uid and .release==$release' "$original" >/dev/null || fail 'modern original operation identity differs'
   lease=$(lease_read)
   jq -e --arg op "$OPERATION" --arg sha "$(sha_file "$original")" --slurpfile original "$original" '.spec.holderIdentity==$op and .metadata.annotations["gsj.io/operation-intent-sha256"]==$sha and .spec.acquireTime==$original[0].acquire_time and ($original[0].prior_lease_uid=="" or .metadata.uid==$original[0].prior_lease_uid)' <<< "$lease" >/dev/null || fail 'startup continuation Lease is not the original modern operation'
 fi
 cp "$saved/source.json" "$GSJ_WORK/installed.json"
 archive=$(backup_archive); snapshot=$(quiescence_snapshot)
 # This checks historical encrypted bytes and their stopped-writer closure.
 # It does not claim the restarted Forgejo/Chroma are still quiesced.
 verified_backup_reuse "$archive" "$snapshot"
 [[ -f $snapshot.closure.json && ! -L $snapshot.closure.json ]] || fail 'startup continuation requires its verified stopped-writer closure'
 jq -e --slurpfile source "$saved/source.json" '.installed==$source[0]' "$snapshot" >/dev/null || fail 'historical backup is not the proved first-startup source'
 jq -e --arg snapshot "$(sha_file "$snapshot")" '.format=="gsj.quiescence-closure/1" and .snapshot_sha256==$snapshot and .writers_absent==true and all(.controllers[];.replicas==0)' "$snapshot.closure.json" >/dev/null || fail 'historical stopped-writer closure is incomplete'
 backup_storage_bindings > "$directory/current-bindings.json"
 jq -e --slurpfile bindings "$directory/current-bindings.json" '.storage_bindings==$bindings[0]' "$snapshot" >/dev/null || fail 'startup source PV or PVC was replaced'
 openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$BACKUP_PASSWORD" -in "$archive.resources.enc" > "$directory/resources-private.tar.gz" 2> "$directory/decrypt.log" || fail 'historical resource archive cannot be decrypted'
 # Read exactly one named member to stdout; do not extract archive paths.
 [[ $(tar -tzf "$directory/resources-private.tar.gz" | awk '$0=="cluster-private.json" {n++} END {print n+0}') == 1 ]] || fail 'historical resource inventory is ambiguous'
 tar -xOzf "$directory/resources-private.tar.gz" cluster-private.json > "$directory/resources-private.json"
 jq -e '.kind=="List" and (.items|type=="array")' "$directory/resources-private.json" >/dev/null || fail 'historical resources are malformed'
 startup_helm_credentials_match "$directory"
}

startup_helm_stored_payload() {
 local release=$1 revision=$2 output=$3 normalize=${4:-false} source kind
 : > "$output.jsonl"
 for kind in manifest hooks; do
   if [[ $kind == manifest ]]; then jq -r .manifest "$release" > "$output.$kind.yaml"
   else jq -r '[.hooks[]?.manifest]|join("\n---\n")' "$release" > "$output.$kind.yaml"; fi
   if [[ -s $output.$kind.yaml ]] && [[ $(tr -d '[:space:]' < "$output.$kind.yaml") != '' ]]; then
     k create --dry-run=client --validate=false -f "$output.$kind.yaml" -o json | jq -s --arg kind "$kind" --arg generation "$RELEASE_ID:$revision" --argjson normalize "$normalize" '{kind:$kind,objects:([.[]|if .kind=="List" then .items[] else . end] | (if $normalize then walk(if type=="object" and .name?=="GSJ_DEPLOYMENT_GENERATION" and has("value") then .value=$generation else . end) else . end) | sort_by(.kind,.metadata.namespace,.metadata.name))}' >> "$output.jsonl"
   else jq -n --arg kind "$kind" '{kind:$kind,objects:[]}' >> "$output.jsonl"; fi
 done
 jq -s . "$output.jsonl" > "$output"
}

startup_helm_auxiliary_matches() {
 local directory=$1 kind name current
 while IFS=$'\t' read -r kind name; do
   case "$kind" in Service|ServiceAccount|Role|RoleBinding|NetworkPolicy|PersistentVolumeClaim|Ingress) ;;
     *) fail 'failed target contains an unsupported auxiliary resource';; esac
   jq --arg kind "$kind" --arg name "$name" '.[]|select(.kind=="manifest")|.objects[]|select(.kind==$kind and .metadata.name==$name)' "$directory/failed-payload-private.json" > "$directory/auxiliary-expected.json"
   current=$(k get "$kind" "$name" -o json)
   jq -e --arg kind "$kind" --arg name "$name" --arg ns "$NAMESPACE" --arg release "$RELEASE" --slurpfile source "$directory/resources-private.json" '
     . as $now | .metadata.namespace==$ns and .metadata.deletionTimestamp==null and
     .metadata.annotations["meta.helm.sh/release-name"]==$release and .metadata.annotations["meta.helm.sh/release-namespace"]==$ns and
     any($source[0].items[];.kind==$kind and .metadata.name==$name and .metadata.uid==$now.metadata.uid)
   ' <<< "$current" >/dev/null || fail 'an auxiliary target resource has foreign or replaced ownership'
   printf '%s\n' "$current" > "$directory/auxiliary-current.json"
   owned_resource_matches "$directory/auxiliary-current.json" "$directory/auxiliary-expected.json" || fail 'an auxiliary target resource differs from the authenticated failed release'
 done < <(jq -r --arg scripts "$RELEASE-scripts" '.[]|select(.kind=="manifest")|.objects[]|select(.kind!="Deployment" and (.kind!="ConfigMap" or .metadata.name!=$scripts))|[.kind,.metadata.name]|@tsv' "$directory/failed-payload-private.json")
}

startup_helm_failed_target() {
 local directory=$1 payload=$2 attempt=$3 intent="$STATE_DIR/helm-applications/$OPERATION/$3" file revision latest object
 for file in intent.json values.json expected.json; do [[ -f $intent/$file && ! -L $intent/$file ]] || fail 'failed Helm target intent is incomplete'; done
 jq -e --arg op "$OPERATION" --arg attempt "$attempt" --arg target "$RELEASE_ID" --arg ns "$NAMESPACE" --arg release "$RELEASE" --arg chart "$(sha_file "$payload/chart.tgz")" --arg values "$(sha_file "$intent/values.json")" --arg expected "$(sha_file "$intent/expected.json")" '.format=="gsj.helm-application/1" and .operation==$op and .attempt==$attempt and .target==$target and .namespace==$ns and .release==$release and .chart_sha256==$chart and .values_sha256==$values and .expected_sha256==$expected' "$intent/intent.json" >/dev/null || fail 'failed Helm target bytes or identity changed'
 cmp -s "$intent/values.json" "$GSJ_WORK/values.pending.json" || fail 'continuation configuration differs from the failed Helm target'
 [[ $(k get namespace "$NAMESPACE" -o json | jq -er .metadata.uid) == $(jq -r .namespace_uid "$intent/intent.json") ]] || fail 'startup continuation namespace was replaced'
 revision=$(jq -er .revision "$intent/intent.json")
 k get secrets -l "owner=helm,name=$RELEASE" -o json > "$directory/history-private.json"
 jq -e --arg release "$RELEASE" --argjson revision "$revision" '([.items[].metadata.labels.version|tonumber]|max)==$revision and all(.items[];.type=="helm.sh/release.v1" and .metadata.labels.owner=="helm" and .metadata.labels.name==$release and (.metadata.uid|type=="string" and length>0))' "$directory/history-private.json" >/dev/null || fail 'another Helm writer appeared after the failed target'
 jq --argjson revision "$revision" '.items[]|select((.metadata.labels.version|tonumber)==$revision)' "$directory/history-private.json" > "$directory/failed-secret-private.json"
 jq -e '.metadata.labels.status=="failed"' "$directory/failed-secret-private.json" >/dev/null || fail 'only the recorded failed Helm apply can use startup continuation'
 addon_release_decode "$directory/failed-secret-private.json" "$directory/failed-release-private.json"
 require_offline_render; KUBECONFIG=/dev/null HELM_DRIVER=secret helm install "$RELEASE" "$payload/chart.tgz" --namespace "$NAMESPACE" --values "$intent/values.json" --dry-run=client --output json > "$directory/signed-target-private.json"
 jq -e --arg name "$RELEASE" --arg ns "$NAMESPACE" --argjson revision "$revision" --slurpfile signed "$directory/signed-target-private.json" '.name==$name and .namespace==$ns and .version==$revision and .info.status=="failed" and (.chart|del(.modtime,.schemamodtime))==($signed[0].chart|del(.modtime,.schemamodtime)) and .config==$signed[0].config and (.info.description|contains("kubectl-patch") and contains(".spec.replicas"))' "$directory/failed-release-private.json" >/dev/null || fail 'failed Helm history is not the authenticated replica-conflict target'
 startup_helm_stored_payload "$directory/failed-release-private.json" "$revision" "$directory/failed-payload-private.json"
 startup_helm_stored_payload "$directory/signed-target-private.json" "$revision" "$directory/signed-payload-private.json" true
 jq -e --slurpfile signed "$directory/signed-payload-private.json" '.==$signed[0]' "$directory/failed-payload-private.json" >/dev/null || fail 'failed Helm manifests differ from the authenticated chart'
 jq -e --slurpfile signed "$directory/signed-target-private.json" 'def hooks: [.hooks[]?|del(.last_run,.manifest)]|sort_by(.name); hooks==($signed[0]|hooks)' "$directory/failed-release-private.json" >/dev/null || fail 'failed Helm hook policy differs from the authenticated chart'
 # Every earlier history Secret must retain its exact UID and opaque bytes.
 jq -e --argjson revision "$revision" --slurpfile archive "$directory/resources-private.json" '
   def prior: [.items[]|select(.type=="helm.sh/release.v1")|{name:.metadata.name,uid:.metadata.uid,data}]|sort_by(.name);
   {items:[.items[]|select((.metadata.labels.version|tonumber)<$revision)]}|prior==($archive[0]|prior)
 ' "$directory/history-private.json" >/dev/null || fail 'prior Helm history changed after the proved source backup'
 startup_helm_auxiliary_matches "$directory"
 startup_helm_render "$payload" "$intent/values.json" "$revision" "$directory/failed-resources.json"
 helm_application_projection "$directory/failed-resources.json" > "$directory/failed-projection.json"
 cmp -s "$directory/failed-projection.json" "$intent/expected.json" || fail 'failed target projection differs from the authenticated chart'
}

startup_helm_live_partial() {
 local directory=$1 failed=$2 next=${3:-} object name kind saved="$STATE_DIR/startup-source-$OPERATION" current
 current="$directory/live.jsonl"
 : > "$current"
 for kind in installed ready-state; do
   [[ -z $(k get configmap "$RELEASE-$kind" -o json --ignore-not-found) ]] || fail 'a ready application must use ordinary repair, not startup continuation'
 done
 while IFS=$'\t' read -r kind name; do
   object=$(k get "$kind" "$name" -o json --show-managed-fields)
   jq -e --arg kind "$kind" --arg name "$name" --slurpfile source "$saved/actual.json" '
     . as $now | any($source[0][];.kind==$kind and .metadata.name==$name and .metadata.uid==$now.metadata.uid) and .metadata.deletionTimestamp==null
   ' <<< "$object" >/dev/null || fail 'a partial-target resource was replaced'
   if [[ $kind != Job ]]; then
     jq -e --arg release "$RELEASE" --arg ns "$NAMESPACE" '.metadata.annotations["meta.helm.sh/release-name"]==$release and .metadata.annotations["meta.helm.sh/release-namespace"]==$ns' <<< "$object" >/dev/null || fail 'partial-target Helm ownership changed'
   else
     jq -e '.status.succeeded==1 and (.status.active//0)==0 and any(.status.conditions[]?;.type=="Complete" and .status=="True")' <<< "$object" >/dev/null || fail 'source provisioning Job is no longer complete'
   fi
   printf '%s\n' "$object" >> "$current"
 done < <(jq -r '.[]|[.kind,.name]|@tsv' "$failed")
 jq -s . "$current" > "$directory/live.json"
 helm_application_projection "$directory/live.json" > "$directory/live-projection.json"
 helm_application_projection "$saved/actual.json" > "$directory/source-projection.json"
 if [[ -z $next ]]; then printf '[]' > "$directory/next-projection.json"; else cp "$next" "$directory/next-projection.json"; fi
 jq -e --arg web "$RELEASE-web" --slurpfile source "$directory/source-projection.json" --slurpfile failed "$failed" --slurpfile next "$directory/next-projection.json" '
   def subset($a;$b): if ($b|type)=="object" then ($a|type)=="object" and all($b|keys[];. as $k|subset($a[$k];$b[$k])) elif ($b|type)=="array" then ($a|type)=="array" and ($a|length)==($b|length) and all(range(0;$b|length);. as $i|subset($a[$i];$b[$i])) else $a==$b end;
   all(.[];. as $a|
     if .kind=="Deployment" and .name==$web then
       any($source[0][];.kind==$a.kind and .name==$a.name and $a.replicas==0 and subset($a;(.replicas=0))) or
       any($next[0][];.kind==$a.kind and .name==$a.name and ($a.replicas|IN(0,1)) and subset(($a|del(.replicas));del(.replicas)))
     elif .kind=="Job" then any($source[0][];.kind==$a.kind and .name==$a.name and subset($a;.))
     else any($failed[0][];.kind==$a.kind and .name==$a.name and subset($a;.) and (if .kind=="ConfigMap" then .data==$a.data else true end)) end)
 ' "$directory/live-projection.json" >/dev/null || fail 'partial application is outside the exact source, failed target or staged continuation'
 # The observed failure leaves only our legacy replica field claim on web.
 if [[ -z $next ]]; then
   jq -e --arg web "$RELEASE-web" --slurpfile closure "$(quiescence_snapshot).closure.json" '
     .[]|select(.metadata.name==$web)| . as $web |
     any($closure[0].controllers[];.uid==$web.metadata.uid and .generation==$web.metadata.generation and .replicas==$web.spec.replicas) and
     [.metadata.managedFields[]?|select(.fieldsV1["f:spec"]["f:replicas"]!=null)|{manager,operation,subresource:(.subresource//"")}]==[{manager:"kubectl-patch",operation:"Update",subresource:""}]
   ' "$directory/live.json" >/dev/null || fail 'startup web is outside the recorded stopped legacy replica conflict'
 fi
 jq -e --arg web "$RELEASE-web" --slurpfile closure "$(quiescence_snapshot).closure.json" --slurpfile next "$directory/next-projection.json" '
   all(.[]|select(.kind=="Deployment"); . as $now |
     any($closure[0].controllers[]; .uid==$now.metadata.uid and
       (if $now.metadata.name!=$web then $now.metadata.generation==(.generation+1) and $now.spec.replicas==1
        elif any($next[0][]; .kind=="Deployment" and .name==$web and
          .pod.spec.initContainers[0].env==($now.spec.template.spec.initContainers[0].env))
        then $now.metadata.generation==(.generation+1+$now.spec.replicas)
        else $now.metadata.generation==.generation and $now.spec.replicas==0 end)))
 ' "$directory/live.json" >/dev/null || fail 'controller generations show writes outside the recorded partial apply or target staging'
 k get configmap "$RELEASE-provisioned" -o json | jq -e --slurpfile control "$saved/control.json" '.data.generation==$control[0].generation' >/dev/null || fail 'provisioning generation changed outside the saved first-startup source'
 k get deploy -l "app.kubernetes.io/instance=$RELEASE" -o json | jq -e --slurpfile source "$saved/actual.json" '[.items[]|{name:.metadata.name,uid:.metadata.uid}]|sort_by(.name)==([$source[0][]|select(.kind=="Deployment")|{name:.metadata.name,uid:.metadata.uid}]|sort_by(.name))' >/dev/null || fail 'unexpected application controller exists'
 k get jobs -l "app.kubernetes.io/instance=$RELEASE" -o json | jq -e --slurpfile source "$saved/actual.json" '[.items[]|{name:.metadata.name,uid:.metadata.uid}]|sort_by(.name)==([$source[0][]|select(.kind=="Job")|{name:.metadata.name,uid:.metadata.uid}]|sort_by(.name))' >/dev/null || fail 'another provisioning Job appeared'
 k get pods -l "app.kubernetes.io/instance=$RELEASE,app.kubernetes.io/component=gsj" -o json | jq -e '
   all(.items[]; all(.status.containerStatuses[]?;.state.running==null and .state.terminated==null) and all(.status.initContainerStatuses[]?|select(.name!="wait-deps");.state.running==null and .state.terminated==null))
 ' >/dev/null || fail 'application initialization already ran; use its recorded target or a new consistent recovery point'
}

startup_helm_successor() {
 local directory="$STATE_DIR/startup-helm-$OPERATION" attempt=$1 target file
 [[ $attempt =~ ^[a-f0-9]{24}$ ]] || fail 'invalid successor Helm attempt'
 target="$STATE_DIR/helm-applications/$OPERATION/$attempt"
 for file in intent.json values.json expected.json; do [[ -f $target/$file && ! -L $target/$file ]] || fail 'successor Helm intent is incomplete'; done
 jq -e --arg operation "$OPERATION" --arg attempt "$attempt" --arg target "$RELEASE_ID" --arg ns "$NAMESPACE" --arg release "$RELEASE" --arg chart "$(sha_file "$GSJ_PAYLOAD/chart.tgz")" --arg values "$(sha_file "$target/values.json")" --arg expected "$(sha_file "$target/expected.json")" --slurpfile continuation "$directory/intent.json" --slurpfile control "$STATE_DIR/startup-source-$OPERATION/control.json" --slurpfile source "$STATE_DIR/startup-source-$OPERATION/actual.json" '
   . as $intent | .namespace_uid==$control[0].namespace_uid and any($source[0][];.kind=="Job" and .metadata.uid==$intent.prior_job_uid) and
   .format=="gsj.helm-application/1" and .operation==$operation and .attempt==$attempt and .target==$target and .namespace==$ns and .release==$release and
   .chart_sha256==$chart and .values_sha256==$values and .expected_sha256==$expected and
   .revision==($continuation[0].failed_revision+1) and .generation==($target+":"+(.revision|tostring)) and $attempt!=$continuation[0].failed_attempt
 ' "$target/intent.json" >/dev/null || fail 'successor Helm identity, revision or bytes changed'
 cmp -s "$target/values.json" "$GSJ_WORK/values.pending.json" || fail 'successor configuration differs from the unchanged failed target'
}

startup_helm_stage() {
 local directory="$STATE_DIR/startup-helm-$OPERATION" attempt target current uid revision marker
 attempt=$(jq -er .helm_application "$STATE_DIR/operation.json"); target="$STATE_DIR/helm-applications/$OPERATION/$attempt"
 startup_helm_successor "$attempt"
 revision=$(jq -er .revision "$target/intent.json")
 jq -e --argjson revision "$revision" --arg attempt "$attempt" '.failed_attempt!=$attempt and ($revision==(.failed_revision+1))' "$directory/intent.json" >/dev/null || fail 'continuation next Helm attempt is not its exact successor'
 [[ $(sha_file "$target/values.json") == $(jq -r .values_sha256 "$target/intent.json") && $(sha_file "$target/expected.json") == $(jq -r .expected_sha256 "$target/intent.json") ]] || fail 'continuation successor intent bytes changed'
 startup_helm_render "$GSJ_PAYLOAD" "$target/values.json" "$revision" "$GSJ_WORK/startup-next-resources.json"
 helm_application_projection "$GSJ_WORK/startup-next-resources.json" > "$GSJ_WORK/startup-next-projection.json"
 cmp -s "$GSJ_WORK/startup-next-projection.json" "$target/expected.json" || fail 'successor Helm target differs from its signed chart'
 startup_helm_live_partial "$GSJ_WORK/startup-continuation" "$directory/failed-projection.json" "$target/expected.json"
 jq --arg web "$RELEASE-web" '.[]|select(.kind=="Deployment" and .metadata.name==$web)' "$GSJ_WORK/startup-next-resources.json" > "$GSJ_WORK/startup-next-web.json"
 # First init must be the exact script/marker barrier for the new, not-yet
 # provisioned Helm revision. No corpus or application process may precede it.
 jq -e --arg generation "$RELEASE_ID:$revision" --arg marker "$RELEASE-provisioned" '.spec.replicas==1 and .spec.template.spec.initContainers[0].name=="wait-deps" and .spec.template.spec.initContainers[0].command==["python","/scripts/wait-deps.py"] and any(.spec.template.spec.initContainers[0].env[];.name=="GSJ_DEPLOYMENT_GENERATION" and .value==$generation) and any(.spec.template.spec.initContainers[0].env[];.name=="WAIT_MARKER" and .value==$marker)' "$GSJ_WORK/startup-next-web.json" >/dev/null || fail 'successor application lacks its exact first-init provisioning barrier'
 marker=$(k get configmap "$RELEASE-provisioned" -o json)
 jq -e --arg generation "$RELEASE_ID:$revision" '.data.generation!=$generation' <<< "$marker" >/dev/null || fail 'successor provisioning already ran outside this continuation'
 current=$(jq --arg web "$RELEASE-web" '.[]|select(.kind=="Deployment" and .metadata.name==$web)' "$GSJ_WORK/startup-continuation/live.json"); uid=$(jq -r .metadata.uid <<< "$current")
 jq -e --arg uid "$uid" --arg name "$RELEASE-web" 'any(.resources[];.kind=="Deployment" and .name==$name and .uid==$uid)' "$STATE_DIR/startup-source-$OPERATION/control.json" >/dev/null || fail 'continuation web UID changed'
 helm_application_projection <(printf '%s' "$current") | jq 'map(del(.replicas))' > "$GSJ_WORK/startup-stage-current.json"
 helm_application_projection "$GSJ_WORK/startup-next-web.json" | jq 'map(del(.replicas))' > "$GSJ_WORK/startup-stage-expected.json"
 if ! startup_source_projection_matches "$GSJ_WORK/startup-stage-current.json" "$GSJ_WORK/startup-stage-expected.json"; then
   [[ $(jq -r .spec.replicas <<< "$current") == 0 ]] || fail 'old application must remain stopped while staging the exact target'
   jq --arg uid "$uid" --arg rv "$(jq -r .metadata.resourceVersion <<< "$current")" --arg ns "$NAMESPACE" --arg release "$RELEASE" 'del(.spec.replicas)|.metadata.uid=$uid|.metadata.resourceVersion=$rv|.metadata.namespace=$ns|.metadata.annotations["meta.helm.sh/release-name"]=$release|.metadata.annotations["meta.helm.sh/release-namespace"]=$ns' "$GSJ_WORK/startup-next-web.json" > "$GSJ_WORK/startup-stage-web.json"
   assert_owner
   k apply --server-side --field-manager=helm --request-timeout=60s -f "$GSJ_WORK/startup-stage-web.json" >/dev/null
 fi
 current=$(k get deployment "$RELEASE-web" -o json)
 [[ $(jq -r .metadata.uid <<< "$current") == "$uid" ]] || fail 'staged application was replaced'
 helm_application_projection <(printf '%s' "$current") | jq 'map(del(.replicas))' > "$GSJ_WORK/startup-stage-current.json"
 startup_source_projection_matches "$GSJ_WORK/startup-stage-current.json" "$GSJ_WORK/startup-stage-expected.json" || fail 'the exact successor template was not staged'
 if [[ $(jq -r .spec.replicas <<< "$current") == 0 ]]; then
   printf '%s\n' "$current" > "$GSJ_WORK/startup-scale-current.json"
   startup_scale_web "$GSJ_WORK/startup-scale-current.json" 1
 else [[ $(jq -r .spec.replicas <<< "$current") == 1 ]] || fail 'staged application replica count differs'; fi
 log 'Exact signed target template staged; its new provisioning generation gates initialization'
}

startup_helm_program_authorize() {
 local directory=$1 working=$2 program=$3 previous installer file receipt="$1/program-transition.json"
 STARTUP_PROGRAM_REPLACE=false
 [[ ! -L $directory/program-predecessor && ( ! -e $directory/program-predecessor || -d $directory/program-predecessor ) ]] || fail 'program predecessor evidence is not an ordinary directory'
 if [[ ! -f $directory/intent.json ]]; then
   [[ -z ${CONTINUE_FROM_PROGRAM:-} && ! -e $receipt && ! -L $receipt ]] || fail 'program replacement requires the original saved continuation intent'
   return
 fi
 previous=$(jq -er '.program|select(type=="string" and length>0)' "$directory/intent.json")
 if [[ -e $receipt || -L $receipt ]]; then
   [[ -f $receipt && ! -L $receipt ]] || fail 'saved program transition is not an ordinary file'
   jq -e --arg previous "$previous" --arg program "$program" '.format=="gsj.startup-helm-program-transition/1" and .from_program==$previous and .to_program==$program and $previous!=$program' "$receipt" >/dev/null || fail 'saved program transition selects a different program; original evidence is preserved'
 elif [[ $program == "$previous" ]]; then
   [[ -z ${CONTINUE_FROM_PROGRAM:-} ]] || fail 'program replacement must select a different signed program'
   return
 else
   [[ -n ${CONTINUE_FROM_PROGRAM:-} ]] || fail 'saved continuation program differs; explicit --continue-from-program is required'
 fi
 jq -e --arg previous "$previous" '.supported_sources|index($previous)' "$GSJ_PAYLOAD/release.json" >/dev/null || fail 'corrected program does not declare the saved prior continuation program'
 installer=${CONTINUE_FROM_PROGRAM:-$directory/program-predecessor/gsj-install.sh}
 authenticate_predecessor "$installer" "$previous" "$working/prior-program"
 for file in gsj-install.sh installer-descriptor.json installer-descriptor.sig; do
   if [[ -e $directory/program-predecessor/$file || -L $directory/program-predecessor/$file ]]; then
     [[ -f $directory/program-predecessor/$file && ! -L $directory/program-predecessor/$file ]] && cmp -s "$working/prior-program/$file" "$directory/program-predecessor/$file" || fail 'retained prior program evidence differs; original bytes are preserved'
   fi
 done
 STARTUP_PROGRAM_REPLACE=true
}

startup_helm_program_binding() {
 local directory=$1 working=$2 program=$3 current=$4 next=$5 target="$STATE_DIR/helm-applications/$OPERATION/$5"
 $STARTUP_PROGRAM_REPLACE || return 0
 [[ $next != $(jq -r .failed_attempt "$directory/intent.json") ]] || fail 'program replacement requires the already saved staged successor'
 jq -n --arg program "$program" --arg prior_installer "$(sha_file "$working/prior-program/gsj-install.sh")" --arg continuation "$(sha_file "$directory/intent.json")" --arg intent "$(sha_file "$target/intent.json")" --arg values "$(sha_file "$target/values.json")" --arg expected "$(sha_file "$target/expected.json")" --argjson lease "$current" --arg web "$RELEASE-web" --slurpfile original "$directory/intent.json" --slurpfile successor "$target/intent.json" --slurpfile control "$STATE_DIR/startup-source-$OPERATION/control.json" --slurpfile closure "$(quiescence_snapshot).closure.json" '
   ($control[0].resources[]|select(.kind=="Deployment" and .name==$web)|.uid) as $uid |
   {format:"gsj.startup-helm-program-transition/1",from_program:$original[0].program,to_program:$program,prior_installer_sha256:$prior_installer,
    binding:{continuation_sha256:$continuation,operation:$original[0].operation,target:$original[0].target,namespace_uid:$control[0].namespace_uid,
      source_proof_sha256:$original[0].source_proof_sha256,historical_backup_receipt_sha256:$original[0].historical_backup_receipt_sha256,
      credential_inventory_sha256:$original[0].credential_inventory_sha256,site_sha256:$original[0].site_sha256,
      successor:{attempt:$successor[0].attempt,revision:$successor[0].revision,intent_sha256:$intent,values_sha256:$values,expected_sha256:$expected},
      lease:{uid:$lease.metadata.uid,holder:$lease.spec.holderIdentity,acquire_time:$lease.spec.acquireTime,annotations:($lease.metadata.annotations//{})}},
    staged_web:{uid:$uid,generation:([$closure[0].controllers[]|select(.uid==$uid)|.generation][0]+1),replicas:0}}
 ' > "$working/program-transition.json"
 jq -e --arg operation "$OPERATION" 'all(.binding.lease.uid,.binding.lease.acquire_time,.binding.namespace_uid,.staged_web.uid;type=="string" and length>0) and .binding.lease.holder==$operation and (.staged_web.generation|type=="number" and .>0)' "$working/program-transition.json" >/dev/null || fail 'program transition lacks the original Lease, namespace or stopped controller identity'
 if [[ -f $directory/program-transition.json ]]; then
   cmp -s "$working/program-transition.json" "$directory/program-transition.json" || fail 'saved program transition source, backup, credentials or successor binding differs'
 fi
}

startup_helm_program_stopped() {
 local directory=$1 working=$2 next=$3
 $STARTUP_PROGRAM_REPLACE || return 0
 [[ ! -f $directory/program-transition.json ]] || return 0
 # A new program can replace only the observed pre-Helm, already-staged zero.
 # Existing receipt retries still pass the ordinary successor/live validators.
 jq --arg web "$RELEASE-web" '[.[]|select(.kind=="Deployment" and .name==$web)]' "$working/live-projection.json" > "$working/program-web-live.json"
 jq --arg web "$RELEASE-web" '[.[]|select(.kind=="Deployment" and .name==$web)|.replicas=0]' "$STATE_DIR/helm-applications/$OPERATION/$next/expected.json" > "$working/program-web-expected.json"
 [[ $(jq length "$working/program-web-expected.json") == 1 ]] && startup_source_projection_matches "$working/program-web-live.json" "$working/program-web-expected.json" || fail 'program replacement requires the exact successor template still stopped at zero'
 jq -e --arg web "$RELEASE-web" --slurpfile transition "$working/program-transition.json" '
   any(.[];.kind=="Deployment" and .metadata.name==$web and .metadata.uid==$transition[0].staged_web.uid and .metadata.generation==$transition[0].staged_web.generation and .spec.replicas==0)
 ' "$working/live.json" >/dev/null || fail 'program replacement stopped controller UID or generation differs'
}

startup_helm_program_publish() {
 local directory=$1 working=$2 file
 $STARTUP_PROGRAM_REPLACE || return 0
 [[ ! -f $directory/program-transition.json ]] || return 0
 [[ ! -L $directory/program-predecessor && ( ! -e $directory/program-predecessor || -d $directory/program-predecessor ) ]] || fail 'program predecessor evidence is not an ordinary directory'
 [[ -d $directory/program-predecessor ]] || mkdir -m 700 "$directory/program-predecessor"
 for file in gsj-install.sh installer-descriptor.json installer-descriptor.sig; do startup_intent_file "$working/prior-program/$file" "$directory/program-predecessor/$file"; done
 startup_intent_file "$working/program-transition.json" "$directory/program-transition.json"
}

startup_helm_continue() {
 local current=$1 directory="$STATE_DIR/startup-helm-$RESUME_ID" working="$GSJ_WORK/startup-continuation" program=$RELEASE_ID target attempt revision payload next latest
 OPERATION=$RESUME_ID
 [[ ! -L $directory && ( ! -e $directory || -d $directory ) ]] || fail 'continuation evidence directory is not ordinary state'
 if [[ -e $directory/intent.json || -L $directory/intent.json ]]; then
   [[ -f $directory/intent.json && ! -L $directory/intent.json ]] || fail 'continuation intent is not an ordinary file'
 fi
 [[ -z ${BACKUP_ROUND:-} && -z ${SOURCE_INSTALLER:-} ]] || fail 'Helm continuation cannot select another backup round or source'
 jq -e --arg operation "$OPERATION" '.operation==$operation and .kind=="install" and .status=="applying" and .startup_source!=null and (.backup_round//0)==0' "$STATE_DIR/operation.json" >/dev/null || fail 'Helm continuation applies only to the saved partial first-startup repair'
 target=$(jq -er .target "$STATE_DIR/operation.json")
 [[ $program == "$target" ]] || jq -e --arg target "$target" '.supported_sources|index($target)' "$GSJ_PAYLOAD/release.json" >/dev/null || fail 'corrected program does not declare the failed signed target'
 [[ ! -e $working && ! -L $working ]] || fail 'continuation working directory already exists'; mkdir -m 700 "$working"
 startup_helm_program_authorize "$directory" "$working" "$program"
 authenticate_predecessor "$CONTINUE_HELM_INSTALLER" "$target" "$working/target"
 payload=$PREDECESSOR_PAYLOAD
 # Keep current helper functions, but all application images, chart, config,
 # version and final acceptance now belong to the explicitly selected target.
 GSJ_PAYLOAD=$payload; RELEASE_ID=$target; VERSION=$(jq -r .version "$payload/release.json")
 jq --slurpfile schema "$payload/site.schema.json" -f "$payload/validate.jq" "$SITE" > "$working/site.json"
 cmp -s "$working/site.json" "$SITE" || jq -e --slurpfile site "$SITE" '.==$site[0]' "$working/site.json" >/dev/null || fail 'current configuration does not satisfy the signed target schema'
 cmp -s "$SITE" "$STATE_DIR/site.pending.json" || fail 'continuation requires the exact saved target configuration'
 jq --slurpfile release "$payload/release.json" -f "$payload/compile.jq" "$SITE" > "$GSJ_WORK/values.pending.json"
 if [[ -f $directory/intent.json && ! -L $directory/intent.json ]]; then
   jq -e --arg program "$program" --argjson replacement "$STARTUP_PROGRAM_REPLACE" --arg target "$target" --arg operation "$OPERATION" --arg script "$(sha_file "$CONTINUE_HELM_INSTALLER")" --arg site "$(sha_file "$SITE")" '.format=="gsj.startup-helm-continuation/1" and (.program==$program or $replacement) and .target==$target and .operation==$operation and .installer_sha256==$script and .site_sha256==$site' "$directory/intent.json" >/dev/null || fail 'saved continuation program, installer or configuration differs'
   local evidence
   for evidence in failed-projection.json failed-secret-private.json; do [[ -f $directory/$evidence && ! -L $directory/$evidence ]] || fail 'saved continuation target evidence is not an ordinary file'; done
   [[ $(sha_file "$directory/failed-projection.json") == $(jq -r .failed_projection_sha256 "$directory/intent.json") && $(sha_file "$directory/failed-secret-private.json") == $(jq -r .failed_secret_sha256 "$directory/intent.json") ]] || fail 'saved continuation target evidence changed'
   attempt=$(jq -r .failed_attempt "$directory/intent.json")
 else attempt=$(jq -er .helm_application "$STATE_DIR/operation.json"); fi
 [[ $attempt =~ ^[a-f0-9]{24}$ ]] || fail 'invalid failed Helm attempt'
 startup_helm_source_evidence "$working"
 compatibility selected
 next=$(jq -er '.helm_application|select(type=="string" and test("^[a-f0-9]{24}$"))' "$STATE_DIR/operation.json") || fail 'invalid current Helm attempt'
 if [[ -f $directory/intent.json ]]; then
   jq -e --arg proof "$(sha_file "$STATE_DIR/startup-source-$OPERATION/source.json")" --arg backup "$(sha_file "$(backup_archive).json")" --arg credentials "$(sha_file "$working/credentials-current-private.json")" '.source_proof_sha256==$proof and .historical_backup_receipt_sha256==$backup and .credential_inventory_sha256==$credentials' "$directory/intent.json" >/dev/null || fail 'continuation source evidence changed'
 fi
 if [[ $next != "$attempt" ]]; then
   [[ -f $directory/intent.json ]] || fail 'an unrecorded continuation writer exists'
   startup_helm_successor "$next"
   startup_helm_program_binding "$directory" "$working" "$program" "$current" "$next"
   revision=$(jq -r .revision "$STATE_DIR/helm-applications/$OPERATION/$next/intent.json")
   latest=$(k get secret "sh.helm.release.v1.$RELEASE.v$revision" -o json --ignore-not-found)
   if [[ -n $latest ]]; then
     [[ $STARTUP_PROGRAM_REPLACE != true || -f $directory/program-transition.json ]] || fail 'a new continuation program cannot replace one after successor Helm writes began'
     # A completed actual target resumes through the ordinary exact target
     # validator. Pending/failed successor Helm writes are never retried blind.
     jq -e '.metadata.labels.status=="deployed"' <<< "$latest" >/dev/null || fail 'continuation Helm successor is pending or failed; retain its evidence for explicit reconciliation'
     helm_application_validate
     jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
     LEASE_ACQUIRED=true; rm -f "$STATE_DIR/lease-lost"; start_renewal
     wait_application; record_ready; verify_application; record_installed; return
   fi
 fi
 [[ $STARTUP_PROGRAM_REPLACE != true || $next != "$attempt" ]] || fail 'program replacement requires the already saved staged successor'
 startup_helm_failed_target "$working" "$payload" "$attempt"
 if [[ $next == "$attempt" ]]; then startup_helm_live_partial "$working" "$working/failed-projection.json"
 else startup_helm_live_partial "$working" "$working/failed-projection.json" "$STATE_DIR/helm-applications/$OPERATION/$next/expected.json"; fi
 startup_helm_program_stopped "$directory" "$working" "$next"
 # Renew only after every source/target/storage/credential refusal above.
 jq --arg now "$(date -u +%FT%T.000000Z)" '.spec.renewTime=$now' <<< "$current" | k replace -f - >/dev/null
 LEASE_ACQUIRED=true; rm -f "$STATE_DIR/lease-lost"; start_renewal; assert_owner
 startup_helm_credentials_match "$working"
 startup_helm_live_partial "$working" "$working/failed-projection.json" "$(if [[ $next != "$attempt" ]]; then printf '%s' "$STATE_DIR/helm-applications/$OPERATION/$next/expected.json"; fi)"
 startup_helm_program_stopped "$directory" "$working" "$next"
 startup_helm_program_publish "$directory" "$working"
 if [[ ! -f $directory/intent.json ]]; then
   [[ ! -L $directory && ( ! -e $directory || -d $directory ) ]] || fail 'continuation evidence directory is not ordinary state'
   [[ -d $directory ]] || mkdir -m 700 "$directory"
   startup_intent_file "$working/failed-projection.json" "$directory/failed-projection.json"
   startup_intent_file "$STATE_DIR/operation.json" "$directory/original-operation.json"
   startup_intent_file "$working/failed-secret-private.json" "$directory/failed-secret-private.json"
   if [[ -e $directory/original-live-private.json || -L $directory/original-live-private.json ]]; then
     [[ -f $directory/original-live-private.json && ! -L $directory/original-live-private.json ]] || fail 'original partial-target evidence is not an ordinary file'
   else startup_intent_file "$working/live.json" "$directory/original-live-private.json"; fi
   if [[ -f $STATE_DIR/helm.log && ! -L $STATE_DIR/helm.log ]]; then startup_intent_file "$STATE_DIR/helm.log" "$directory/original-helm.log"; fi
   jq -n --arg op "$OPERATION" --arg program "$program" --arg target "$target" --arg installer "$(sha_file "$CONTINUE_HELM_INSTALLER")" --arg site "$(sha_file "$SITE")" --arg attempt "$attempt" --argjson revision "$(jq -r .revision "$STATE_DIR/helm-applications/$OPERATION/$attempt/intent.json")" --arg proof "$(sha_file "$STATE_DIR/startup-source-$OPERATION/source.json")" --arg backup "$(sha_file "$(backup_archive).json")" --arg credentials "$(sha_file "$working/credentials-current-private.json")" --arg projection "$(sha_file "$directory/failed-projection.json")" --arg failed_secret "$(sha_file "$directory/failed-secret-private.json")" '{format:"gsj.startup-helm-continuation/1",operation:$op,program:$program,target:$target,installer_sha256:$installer,site_sha256:$site,failed_attempt:$attempt,failed_revision:$revision,source_proof_sha256:$proof,historical_backup_receipt_sha256:$backup,credential_inventory_sha256:$credentials,failed_projection_sha256:$projection,failed_secret_sha256:$failed_secret}' | immutable_file "$directory/intent.json"
 fi
 jq -e --arg proof "$(sha_file "$STATE_DIR/startup-source-$OPERATION/source.json")" --arg backup "$(sha_file "$(backup_archive).json")" --arg credentials "$(sha_file "$working/credentials-current-private.json")" '.source_proof_sha256==$proof and .historical_backup_receipt_sha256==$backup and .credential_inventory_sha256==$credentials' "$directory/intent.json" >/dev/null || fail 'continuation source evidence changed'
 if [[ $next == "$attempt" ]]; then helm_application_prepare; fi
 STARTUP_HELM_CONTINUATION=true
 helm_apply; wait_application; record_ready; verify_application; record_installed
 log 'The explicitly selected signed target completed; a later release remains a separate declared repair or upgrade'
}
