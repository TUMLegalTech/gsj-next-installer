def validate($s; $path):
  . as $v |
  if ($s.type == "integer" and (type != "number" or floor != .)) or
     ($s.type != "integer" and type != $s.type) then error($path + ": invalid type") else . end |
  if $s.enum and ($s.enum | index($v) | not) then error($path + ": unsupported value") else . end |
  if type == "object" then
    if ($s.additionalProperties == false) and ((keys - ($s.properties | keys)) | length > 0)
    then error($path + ": unknown setting") else . end |
    if (($s.required // []) - keys | length) > 0 then error($path + ": missing required setting") else . end |
    reduce keys[] as $k (. ; .[$k] = (.[$k] | validate($s.properties[$k]; $path + "." + $k)))
  elif type == "array" then
    if $s.uniqueItems and (unique | length) != length then error($path + ": duplicate setting") else . end |
    map(validate($s.items; $path + "[]"))
  elif type == "string" then
    if $s.minLength and length < $s.minLength then error($path + ": required value is empty") else . end |
    if $s.pattern and (test($s.pattern) | not) then error($path + ": invalid format" + (if $s["x-format-hint"] then " -- expected " + $s["x-format-hint"] else "" end)) else . end
  elif type == "number" then
    if ($s.minimum and . < $s.minimum) or ($s.maximum and . > $s.maximum)
    then error($path + ": outside supported range") else . end
  else . end;
def cpu_millis: if endswith("m") then rtrimstr("m")|tonumber else tonumber*1000 end;
def memory_bytes:
  capture("^(?<number>[1-9][0-9]*)(?<unit>Ki|Mi|Gi|Ti)?$") |
  (.number|tonumber) * ({"":1,Ki:1024,Mi:1048576,Gi:1073741824,Ti:1099511627776}[.unit//""]);
validate($schema[0]; "site") |
if any(.resources[]; (.requests.memory|memory_bytes)>(.limits.memory|memory_bytes) or
  (.limits.cpu!=null and (.requests.cpu|cpu_millis)>(.limits.cpu|cpu_millis)))
then error("resources: request exceeds container limit") else . end |
if .llm.context_window > 0 and .llm.output_tokens > .llm.context_window then error("llm: output exceeds context") else . end |
if any([.llm.credential,.ocr.credential][]; .file != "" and .secret != "") then error("credential: choose one file or Secret") else . end |
if .registry.config_file != "" and .registry.pull_secret == "" then error("registry.pull_secret required with config_file") else . end |
if ((.registry.base // "") != "") and ((.registry.base | split("/")[0]) as $host | ($host | test("[.:]") | not) and $host != "localhost")
then error("registry.base: the first component must be a registry HOST -- it needs a dot, a port or to be localhost. A container runtime reads a bare name such as myregistry/team as docker.io/myregistry/team, so the pulls would go to Docker Hub") else . end |
if .tls.profile == "files" and (.tls.certificate_file == "" or .tls.private_key_file == "") then error("tls: certificate and private key required") else . end |
if .tls.profile == "managed-acme" and (.tls.email == "" or .tls.issuer == "") then error("tls: ACME email and issuer required") else . end |
if .storage.profile == "managed-local-path" and .storage.node == "" then error("storage: managed local storage requires a fixed node") else . end |
if .verification.connect_host == "" and .verification.connect_port != 0 then error("verification: connect_host required") else . end |
if .verification.connect_host != "" and .verification.connect_port == 0 then error("verification: connect_port required with connect_host") else . end
 |
if .backup.offbox_url == "" and (.backup.ca_file != "" or .backup.auth_header_file != "") then error("backup: offbox_url required with destination credentials or CA") else . end |
if .operator.login == "gsj-admin" or .operator.login == "agent" or .operator.login == "system" then error("operator.login: reserved identity") else . end |
(.public_url | capture("^https://[^:/]+(?::(?<port>[0-9]+))?/?$").port // "443" | tonumber) as $port |
if $port < 1 or $port > 65535 then error("public_url: invalid port") else . end
