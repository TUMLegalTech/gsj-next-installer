. as $s | $release[0] as $r |
# registry.base relocates an image and nothing else: the repository becomes
# <base>/<last path segment of the release's repository>, and the DIGEST is
# always the signed release's. A by-digest reference cannot resolve to other
# content, so a registry that does not hold these exact bytes fails the pull.
def image($key): $r.images[$key]
  | (if ($s.registry.base // "") == "" then . else .repository = ($s.registry.base + "/" + (.repository | split("/") | last)) end)
  | {repository, digest, tag:""};
{
 fullnameOverride: $s.target.release,
 deployment:{identity:$r.identity},
 image:{gsjNextTag:$r.core.tag, web:image("web"), runner:image("runner"),mcp:image("mcp"),forgejo:image("forgejo"),chroma:image("chroma"),corpus:image("decisionsData"),pullSecrets:([$s.registry.pull_secret] | map(select(. != "")))},
 corpus:{enabled:true, manifestSha256:$r.corpus.manifest_sha256,deadlineSeconds:$s.deadlines.initialization_seconds,attempts:$s.deadlines.attempts,repairGeneration:$s.corpus.repair_generation,allowUpdate:$s.corpus.allow_update,releasedVectors:((($s.corpus.vectors_url//"")!="") or (($s.corpus.vectors_path//"")!="")),resources:$s.resources.initializer},
 startup:{dependencyDeadlineSeconds:$s.deadlines.dependencies_seconds,progressDeadlineSeconds:($s.deadlines.dependencies_seconds+$s.deadlines.initialization_seconds+1800),modelFailureThreshold:180},
 web:{publicUrl:$s.public_url,uploadMaxMB:$s.limits.upload_mb,worktreeBudgetMB:$s.limits.worktree_cache_mb},
 # The class's controller picks the proxy limits the chart renders. The managed
 # Traefik is known; a reused class's spec.controller arrives as
 # --arg ingress_controller, and without it the chart keeps ingress-nginx.
 ingress:{enabled:true,className:$s.ingress.class,controller:(if $s.ingress.profile=="managed-traefik" then "traefik.io/ingress-controller" else ($ARGS.named.ingress_controller // "k8s.io/ingress-nginx") end),host:($s.public_url | capture("^https://(?<host>[^:/]+)").host),tls:[{secretName:$s.tls.secret,hosts:[($s.public_url | capture("^https://(?<host>[^:/]+)").host)]}]},
 networkPolicy:{enabled:true,ingressControllerNamespace:$s.ingress.namespace},
 operator:{login:$s.operator.login,existingSecret:$s.operator.secret,password:"",autogenPassword:false},
 agent:{turnTimeout:$s.limits.turn_seconds},
 llm:({model:(if $s.llm.base_url == "" then "" else "openai@"+$s.llm.base_url+"#"+$s.llm.model end),contextWindow:$s.llm.context_window,outputTokens:$s.llm.output_tokens,modelFlags:($s.llm.flags|join(",")),keyedOrigins:($s.llm.allowed_origins|join(","))}
      + (if $s.llm.base_url == "" then {absent:true} else {} end)),
 ocr:{url:$s.ocr.url,model:$s.ocr.model,existingSecret:(if $s.ocr.credential.file != "" then $s.target.release+"-ocr-key" else $s.ocr.credential.secret end)},
 selfhostedKey:{value:"",existingSecret:(if $s.llm.credential.file != "" then $s.target.release+"-llm-key" else $s.llm.credential.secret end)},
 placement:{nodeSelector:(if $s.storage.node != "" then {"kubernetes.io/hostname":$s.storage.node} else {} end)},
 storage: (reduce ["data","forgejo","chroma"][] as $k ({}; .[$k]={size:$s.storage[$k].size,className:$s.storage.class,existingClaim:$s.storage[$k].existing_claim})),
 resources:($s.resources | del(.initializer)),
 trust:{caConfigMap:(if $s.trust.ca_file != "" then $s.target.release+"-trust" else "" end),proxySecret:(if $s.trust.proxy_file != "" then $s.target.release+"-proxy" else "" end)},
 retention:{keepClaims:true}
}
