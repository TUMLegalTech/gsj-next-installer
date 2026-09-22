# Example site files

Each file is a site configuration an operator could start from: a partial
`gsj.site/1` document that the installer deep-merges over `defaults.json`,
validates against `site.schema.json` and compiles into the chart's values
(`compile.jq`). The paths and hostnames are placeholders under `example.org`;
the corpus lines name the public vector release the operator guide documents.

They are also the installer's contract fixtures: `tests/test_contract.py`
validates, compiles and renders every file here against the pinned product
chart, so a chart change that breaks one of them fails the suite.

| file | what it exercises |
|---|---|
| `reuse-ingress-files-tls.site.json` | the operator guide's reference site: a reused ingress-nginx, TLS from files, local-path storage, credentials from files, the public corpus vectors |
| `existing-claims.site.json` | storage the operator brings: three existing PersistentVolumeClaims |
| `existing-tls-corporate-ca.site.json` | an existing TLS Secret behind a corporate CA the acceptance verifier must trust |
| `managed-traefik-acme-local-path.site.json` | every managed profile at once: the installer's own Traefik, ACME certificates and its local-path provisioner |
| `no-egress-registry-prefix.site.json` | a registry that mandates a path prefix (`registry.base`) and corpus vectors staged on local disk instead of fetched |
