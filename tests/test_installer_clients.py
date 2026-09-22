"""The client preflight: the installer uses the tools the consumer has.

The installer used to download and pin helm, kubectl and jq on every run. It
now READS what is installed and either proceeds or refuses in the first
seconds — before the payload is unpacked, before the site is read, before the
Lease, before the first cluster object. The download path is kept, intact and
checksum-pinned, behind an opt-in --fetch-tools.

Every floor asserted here was MEASURED against real binaries (see the comment
block above GSJ_HELM_FLOOR in runtime.sh); these tests hold the refusals, not
the measurements.

No cluster, no network, no real helm/kubectl/jq: the tools are shell scripts
that print a chosen version, put on PATH through the fixture's env override.
"""
import json
import os
import shutil
import subprocess

import pytest

from tests.test_installer import INSTALLER, runtime  # noqa: F401

# A HERMETIC PATH. It cannot simply append /usr/bin: macOS ships a real
# /usr/bin/jq, so a "jq is missing" case would silently find one and the test
# would assert nothing. The bin directory below therefore holds the fake tools
# plus symlinks to exactly the utilities bootstrap() and client_version() need,
# and nothing else is reachable.
_UTILITIES = ("bash", "curl", "tar", "gzip", "base64", "awk", "cut",
              "uname", "mktemp", "date", "sync", "sed", "head", "tr", "cat",
              "sha256sum", "shasum", "chmod", "mkdir", "cp", "mv", "rm")
# openssl is a floor of its own (GSJ_OPENSSL_FLOOR): the fake answers
# `openssl version` with the banner a test chooses -- OpenSSL 3 unless told
# otherwise, so no test here depends on the host's flavour (macOS ships
# LibreSSL as /usr/bin/openssl) -- and hands every other invocation to the
# real binary.
OPENSSL_3 = "OpenSSL 3.0.13 30 Jan 2024"


def _tools(directory, **versions):
    """A PATH holding only the named tools, each reporting the given version.

    A tool mapped to None is ABSENT — the directory simply has no such file.
    Each fake answers the exact invocation client_version() makes, in that
    tool's own spelling, because parsing those three spellings is half of what
    is under test.
    """
    directory.mkdir(exist_ok=True)
    for utility in _UTILITIES:
        found = shutil.which(utility, path="/usr/bin:/bin:/usr/sbin:/sbin")
        link = directory / utility
        if found and not link.exists():
            link.symlink_to(found)
    versions.setdefault("openssl", OPENSSL_3)
    real_openssl = shutil.which("openssl", path="/usr/bin:/bin:/usr/sbin:/sbin") or "/usr/bin/openssl"
    spelling = {
        # openssl version         -> OpenSSL 3.0.13 30 Jan 2024
        "openssl": 'if [ "${1:-}" = version ]; then printf "%s\\n" "$V"; else exec ' + real_openssl + ' "$@"; fi',
        # jq --version           -> jq-1.8.2
        "jq": 'printf "jq-%s\\n" "$V"',
        # helm version --short   -> v4.2.2+gb05881c
        "helm": 'printf "v%s+gdeadbee\\n" "$V"',
        # kubectl version --client -o json -> pretty JSON with gitVersion
        "kubectl": 'printf \'{\\n  "clientVersion": {\\n    "gitVersion": "v%s"\\n  }\\n}\\n\' "$V"',
    }
    for tool, version in versions.items():
        target = directory / tool
        if version is None:
            if target.exists():
                target.unlink()
            continue
        target.write_text(f"#!/bin/sh\nV='{version}'\n{spelling[tool]}\n")
        target.chmod(0o755)
    return str(directory)


def _floors():
    """The floors as the shipped runtime declares them.

    An undeclared floor becomes "0" rather than an import error, so that an
    installer without a client preflight fails each test below on its own
    terms instead of collapsing collection.
    """
    source = (INSTALLER / "runtime.sh").read_text()
    found = {}
    for name, tool in (("GSJ_HELM_FLOOR", "helm"), ("GSJ_KUBECTL_FLOOR", "kubectl"),
                       ("GSJ_JQ_FLOOR", "jq")):
        line = next((l for l in source.splitlines() if l.startswith(name + "=")), None)
        found[tool] = line.split("=", 1)[1].strip() if line else "0"
    return found


FLOORS = _floors()


def test_the_floors_are_declared_once_and_are_versions():
    assert set(FLOORS) == {"helm", "kubectl", "jq"}
    for tool, floor in FLOORS.items():
        assert floor != "0", f"{tool} has no declared floor in runtime.sh"
        assert floor.replace(".", "").isdigit(), (tool, floor)


def test_at_the_floor_exactly_the_preflight_admits(runtime, tmp_path):
    """The floor is inclusive: the lowest supported version is supported."""
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", **FLOORS)
    result = run("FETCH_TOOLS=false; client_preflight; echo ADMITTED", PATH=path)
    assert result.returncode == 0, result.stderr
    assert "ADMITTED" in result.stdout


def test_above_the_floor_the_preflight_admits(runtime, tmp_path):
    """The two real measured consumer boxes, exactly as they are."""
    run, _, _ = runtime
    for box in ({"helm": "3.19.2", "kubectl": "1.33.6", "jq": "1.7"},      # one cluster
                {"helm": "3.22.0", "kubectl": "1.36.4", "jq": "1.7"}):     # a second one
        path = _tools(tmp_path / "tools", **box)
        result = run("FETCH_TOOLS=false; client_preflight; echo ADMITTED", PATH=path)
        assert result.returncode == 0, f"{box}: {result.stderr}"
        assert "ADMITTED" in result.stdout


@pytest.mark.parametrize("tool,version", [
    ("helm", "3.11.3"),     # helm 3.11 defaults to kube 1.26; the chart needs 1.27
    ("helm", "2.17.0"),
    ("kubectl", "1.23.17"),  # kubectl 1.23 has no `patch --subresource`
    ("jq", "1.5"),
])
def test_a_too_old_client_is_refused_by_name_floor_and_finding(runtime, tmp_path, tool, version):
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", **{**FLOORS, tool: version})
    result = run("FETCH_TOOLS=false; client_preflight; echo ADMITTED", PATH=path)
    assert result.returncode != 0
    assert "ADMITTED" not in result.stdout
    # "requires Helm >= X, found 3.19.2" -- the tool, the floor, and what is here
    assert f"requires {tool} >= {FLOORS[tool]}, found {version}" in result.stderr, result.stderr
    assert "--fetch-tools" in result.stderr


@pytest.mark.parametrize("missing", ["helm", "kubectl", "jq"])
def test_a_missing_client_is_refused_and_names_the_escape_hatch(runtime, tmp_path, missing):
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", **{**FLOORS, missing: None})
    result = run("FETCH_TOOLS=false; client_preflight; echo ADMITTED", PATH=path)
    assert result.returncode != 0
    assert "ADMITTED" not in result.stdout
    assert f"requires {missing} >= {FLOORS[missing]}, found none on PATH" in result.stderr
    assert "--fetch-tools" in result.stderr


def test_the_refusal_precedes_the_payload_and_touches_no_cluster(runtime, tmp_path):
    """The refusal lands in the first seconds.

    bootstrap() unpacks the embedded payload only AFTER the client preflight.
    Under the fixture $0 is `bash`, which carries no payload marker, so an
    installer that checked its tools too late would say 'installer payload
    missing' instead. Getting the client message proves the ordering.
    """
    run, state, _ = runtime
    path = _tools(tmp_path / "tools", **{**FLOORS, "helm": "3.11.3"})
    result = run("FETCH_TOOLS=false; bootstrap; echo REACHED", PATH=path)
    assert result.returncode != 0
    assert "REACHED" not in result.stdout
    assert f"requires helm >= {FLOORS['helm']}" in result.stderr
    assert "installer payload missing" not in result.stderr
    assert json.loads(state.read_text())["calls"] == [], "the preflight contacted the cluster"


def test_fetch_tools_keeps_the_download_path_and_skips_the_preflight(runtime, tmp_path):
    """An air-gapped or under-provisioned box can still bring its own.

    With --fetch-tools, a box with NO helm/kubectl/jq at all must not be
    refused for that reason; bootstrap proceeds to the payload step.
    """
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", helm=None, kubectl=None, jq=None)
    refused = run("FETCH_TOOLS=false; bootstrap", PATH=path)
    fetched = run("FETCH_TOOLS=true; bootstrap", PATH=path)
    # Same box, same empty toolchain: only the default path refuses for it.
    assert "requires jq >=" in refused.stderr   # jq is checked first
    for tool in ("helm", "kubectl", "jq"):
        assert f"requires {tool} >=" not in fetched.stderr, fetched.stderr


def test_fetch_tools_is_an_accepted_argument_on_every_command():
    source = (INSTALLER / "runtime.sh").read_text()
    assert "--fetch-tools) FETCH_TOOLS=true; shift;;" in source
    assert "FETCH_TOOLS=false" in source, "the flag must default to using the consumer's tools"
    assert "--fetch-tools" in source.split("gsj-install.sh inspect")[1][:2000], \
        "the help output must name the escape hatch"


@pytest.mark.parametrize("version,ownership", [
    ("4.2.2", "--force-conflicts"),
    ("3.19.2", ""),
    ("3.12.0", ""),
])
def test_helm_dialect_spells_field_ownership_per_major(runtime, tmp_path, version, ownership):
    """Helm 3 rejects every Helm 4 spelling outright:
      --wait=hookOnly   -> invalid argument ... strconv.ParseBool
      --wait=watcher    -> invalid argument ... strconv.ParseBool
      --force-conflicts -> unknown flag
    Only the LAST of those still needs a dialect: Helm 4 applies server-side and
    must be told to take a field another manager owns, while Helm 3 applies
    client-side and has no such conflict. The wait flags need no dialect --
    `--wait --wait-for-jobs` is understood by both majors and means the same
    thing on both (measured on a live cluster).
    """
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", **{**FLOORS, "helm": version})
    body = ('helm_dialect\n'
            'own="${HELM_APPLY_OWNERSHIP[*]+${HELM_APPLY_OWNERSHIP[*]}}"\n'
            'printf "major=%s ownership=[%s]\\n" "$HELM_MAJOR" "$own"')
    result = run(body, PATH=path)
    assert result.returncode == 0, result.stderr
    assert f"major={version.split('.')[0]}" in result.stdout
    assert f"ownership=[{ownership}]" in result.stdout, result.stdout


def test_helm_major_is_set_before_any_arithmetic_on_it(runtime, tmp_path):
    """`(( UNSET >= 4 ))` is an unbound-variable ABORT under `set -u` (verified
    on bash 3.2), which would replace require_offline_render's precise refusal
    with a bash error on any path that has not run bootstrap."""
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", **FLOORS)
    # no helm_dialect call: this is the not-yet-bootstrapped state
    result = run('printf "major=[%s]\\n" "$HELM_MAJOR"; require_offline_render || true', PATH=path)
    assert "major=[0]" in result.stdout, result.stdout
    assert "unbound variable" not in result.stderr, result.stderr


def test_the_wait_flags_need_no_dialect():
    """Both add-on sites use the one spelling both majors understand."""
    source = (INSTALLER / "runtime.sh").read_text()
    assert "HELM_WAIT_FULL" not in source, "the wait dialect is unnecessary; both majors take --wait --wait-for-jobs"
    waits = [l for l in source.splitlines()
             if "--wait" in l and not l.strip().startswith("#") and "helm" in l]
    assert waits, "expected the add-on helm invocations"
    for line in waits:
        assert "--wait --wait-for-jobs" in line, line.strip()[:140]


def test_no_helm4_only_spelling_survives_unconditionally():
    """The four known Helm-4-only sites, held closed.

    --wait=hookOnly was a no-op restatement of Helm 4's own default AND a fatal
    ParseBool on Helm 3, so it is spelled by omission on both majors and must
    not come back.
    """
    for name in ("runtime.sh", "startup-recovery.sh", "verification-cleanup.sh"):
        source = (INSTALLER / name).read_text()
        for spelling in ("--wait=hookOnly", "--wait=watcher", "--force-conflicts"):
            for line in source.splitlines():
                if line.strip().startswith(("#", "HELM_WAIT_FULL=", "HELM_APPLY_OWNERSHIP=")):
                    continue
                if "HELM_MAJOR >= 4" in line:   # the dialect switch itself
                    continue
                if spelling in line:
                    pytest.fail(f"{name}: unconditional Helm 4 spelling {spelling}: {line.strip()[:120]}")


def test_the_pinned_clients_satisfy_the_floors_they_are_the_fallback_for():
    """--fetch-tools downloads these; they must clear the bar the preflight sets."""
    pinned = json.loads((INSTALLER / "clients.json").read_text())
    for tool, floor in FLOORS.items():
        urls = [target["url"] for target in pinned[tool].values()]
        assert urls, tool
        for url in urls:
            got = [part for part in url.replace("-", "/").replace("_", "/").split("/")
                   if part and part[0] in "v0123456789" and any(c.isdigit() for c in part)]
            assert got, url
        # the version appears in every pinned URL; compare the first numeric run
        version = next(p.lstrip("v") for p in urls[0].replace("/", " ").replace("-", " ").split()
                       if p.lstrip("v")[:1].isdigit() and "." in p)
        assert _at_least(version, floor), f"pinned {tool} {version} is below the floor {floor}"


def _at_least(have, want):
    mine = [int(p) for p in have.split(".") if p.isdigit()]
    theirs = [int(p) for p in want.split(".") if p.isdigit()]
    while len(mine) < len(theirs):
        mine.append(0)
    while len(theirs) < len(mine):
        theirs.append(0)
    return mine >= theirs


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")
def test_empty_dialect_arrays_expand_under_set_u_on_bash_3_2():
    """macOS still ships bash 3.2, where "${empty[@]}" is an unbound variable
    under `set -u` — and HELM_APPLY_OWNERSHIP is empty on exactly the Helm 3
    path the dialect switch opened. The call sites use the ${a[@]+"${a[@]}"}
    form."""
    probe = 'set -u; a=(); b=(x y); printf "[%s]" ${a[@]+"${a[@]}"} ${b[@]+"${b[@]}"}; echo'
    out = subprocess.run(["bash", "-c", probe], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[x][y]"
    source = (INSTALLER / "runtime.sh").read_text()
    for name in ("HELM_APPLY_OWNERSHIP",):
        bare = f'"${{{name}[@]}}"'
        guarded = f'${{{name}[@]+{bare}}}'
        # every bare expansion must be the inside of a guarded one
        assert source.count(bare) == source.count(guarded) > 0, \
            f"{name} is expanded without the bash 3.2 guard"


@pytest.mark.parametrize("version,admitted", [("4.2.2", True), ("3.22.0", False), ("3.19.2", False)])
def test_cluster_free_serialization_is_refused_precisely_on_helm_3(runtime, tmp_path, version, admitted):
    """The ONE real Helm 4 requirement, named where it bites.

    Four call sites run `KUBECONFIG=/dev/null helm install --dry-run=client` to
    serialize a release with no cluster at all. Measured: every Helm 3 answers
    "Kubernetes cluster unreachable" (3.12 does not even accept the flag
    value), and Helm 3 has no --kube-version on `install` to suppress the
    discovery. A Helm 3 operator must meet a precise refusal at that step, not
    a confusing transport error midway through a recovery.
    """
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", **{**FLOORS, "helm": version})
    result = run("helm_dialect; require_offline_render; echo ADMITTED", PATH=path)
    assert (result.returncode == 0) is admitted, result.stderr
    if admitted:
        assert "ADMITTED" in result.stdout
    else:
        assert "only Helm 4 can do" in result.stderr, result.stderr
        assert "--fetch-tools" in result.stderr


def test_every_cluster_free_render_site_is_guarded():
    """All four sites, in both files, or the guard proves nothing."""
    sites = 0
    for name in ("runtime.sh", "startup-recovery.sh"):
        for line in (INSTALLER / name).read_text().splitlines():
            if line.strip().startswith("#"):
                continue
            if "KUBECONFIG=/dev/null" in line and "--dry-run=client" in line:
                sites += 1
                assert "require_offline_render" in line, f"{name}: unguarded cluster-free render: {line.strip()[:100]}"
    assert sites == 4, f"expected the four known cluster-free render sites, found {sites}"


@pytest.mark.parametrize("have,want,expected", [
    ("3.19.2", "3.12", True),    # one cluster
    ("3.22.0", "3.12", True),    # a second one
    ("3.11.3", "3.12", False),   # helm whose default kube version is 1.26
    ("3.12", "3.12", True),      # the floor is inclusive
    ("3.12.0", "3.12", True),    # trailing components are zero
    ("2.17.0", "3.12", False),
    ("1.10", "1.9", True),       # a naive STRING compare gets this backwards
    ("1.9", "1.10", False),      # ...and this one too
    ("10.0", "9.99", True),      # ...and this one
    ("1.08", "1.8", True),       # leading zero must not be read as octal
    ("1.7", "1.6", True),
    ("1.5", "1.6", False),
    ("1.23.17", "1.24", False),
    ("1.33.6", "1.24", True),
    ("4", "3.12", True),         # fewer components than the floor
    ("3", "3.12", False),
])
def test_version_at_least_compares_numerically_not_lexically(runtime, tmp_path, have, want, expected):
    run, _, _ = runtime
    result = run(f'if version_at_least "{have}" "{want}"; then echo YES; else echo no; fi')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ("YES" if expected else "no"), \
        f"{have} >= {want} gave {result.stdout.strip()}"


@pytest.mark.parametrize("tool,raw,expected", [
    ("jq", "1.8.2", "1.8.2"),
    ("jq", "1.7", "1.7"),
    ("helm", "4.2.2", "4.2.2"),      # printed as v4.2.2+gdeadbee
    ("helm", "3.19.2", "3.19.2"),
    ("kubectl", "1.33.6", "1.33.6"),  # dug out of pretty-printed JSON
])
def test_client_version_parses_each_tools_own_spelling(runtime, tmp_path, tool, raw, expected):
    """None of these may go through jq: jq is itself one of the tools under test."""
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", **{**FLOORS, tool: raw})
    result = run(f'client_version {tool}', PATH=path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected, result.stdout


def test_the_helm_floor_admits_only_a_helm_that_can_label_an_addon():
    """The add-on path fences on `--labels gsj.io/addon-owner=...`, which does
    not exist before Helm 3.13. A floor that admitted 3.12 would let the run
    die inside managed_dependencies, after the Lease and the add-on CRDs."""
    assert _at_least(FLOORS["helm"], "3.13"), \
        f"helm floor {FLOORS['helm']} admits a helm without `--labels`"
    source = (INSTALLER / "runtime.sh").read_text()
    assert "--labels" in source, "the add-on path is expected to pass --labels"


def test_the_server_floor_is_asserted_not_merely_documented():
    """The chart needs Kubernetes >= 1.27 (the Job controller
    stamps batch.kubernetes.io/job-name only from there). Leaving that to Helm
    means the refusal lands after the Lease, the Secrets and the add-ons."""
    source = (INSTALLER / "runtime.sh").read_text()
    assert "GSJ_SERVER_FLOOR=1.27" in source
    preflight = source.split("\npreflight() {", 1)[1].split("\n}\n", 1)[0]
    assert "GSJ_SERVER_FLOOR" in preflight, \
        "preflight() must assert the server floor, not just declare it"
    assert "serverVersion" in preflight


def test_an_unreachable_egress_endpoint_is_not_reported_as_reachable(runtime, tmp_path):
    """curl writes 000 via --write-out AND exits nonzero on a transport
    failure, so a `|| printf 000` fallback appended a SECOND 000 and "000000"
    != "000" read as reachable — inverted on exactly the air-gapped box the
    field exists to characterise."""
    source = (INSTALLER / "runtime.sh").read_text()
    egress = [l for l in source.splitlines() if "%{http_code}" in l and not l.strip().startswith("#")]
    assert egress, "expected the egress probe"
    for line in egress:
        assert "printf 000" not in line, f"printing fallback doubles curl's own 000: {line.strip()[:120]}"

    run, _, work = runtime
    fake = tmp_path / "tools"
    fake.mkdir(exist_ok=True)
    (fake / "curl").write_text("#!/bin/sh\nprintf '000'\nexit 6\n")   # curl's real failure shape
    (fake / "curl").chmod(0o755)
    result = run(
        'out=$(curl --silent --output /dev/null --write-out "%{http_code}" https://x 2>/dev/null || true)\n'
        'printf "[%s]\\n" "$out"',
        PATH=str(fake) + os.pathsep + os.environ["PATH"])
    assert result.stdout.strip() == "[000]", result.stdout


def test_per_node_fields_bind_the_node_name(runtime):
    """`.spec.nodeName==(.spec.nodeName)` compares a pod with itself, so every
    node carried the whole cluster's evictions. Invisible on a single node."""
    source = (INSTALLER / "runtime.sh").read_text()
    assert ".spec.nodeName==(.spec.nodeName)" not in source, "tautological node filter"
    assert "evicted_pods:[($pods[0].items? // [])[]|select(.spec.nodeName==$node)" in source


def test_the_rehearsal_refuses_a_distribution_it_cannot_build():
    """Only a genuine k3s gitVersion maps onto a rancher/k3s tag. k3d discovers
    a bad tag on the image PULL, after it has built the network, volumes and
    server container."""
    script = (INSTALLER / "rehearsal.sh").read_text()
    assert 'distribution != k3s' in script, "a non-k3s profile must be refused before k3d runs"
    guard = script.index("distribution != k3s")
    create = script.index("k3d cluster create")
    assert guard < create, "the distribution guard must precede cluster creation"


def test_client_version_never_aborts_its_caller_when_a_tool_is_missing(runtime, tmp_path):
    """The installer runs under `set -Eeuo pipefail`. A MISSING tool makes the
    probe pipeline nonzero, and `major=$(client_version helm)` then kills the
    script instead of yielding an empty string — silently, wherever the caller
    happens to sit. That cost 43 test regressions in two recovery modules
    before it was found. Reporting "no version" is this function's job;
    deciding what that means belongs to client_preflight.
    """
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", helm=None, kubectl=None, jq=None)
    for tool in ("helm", "kubectl", "jq"):
        result = run(f'v=$(client_version {tool}); printf "[%s] rc=%s\\n" "$v" "$?"; echo SURVIVED',
                     PATH=path)
        assert result.returncode == 0, f"{tool}: {result.stderr}"
        assert "SURVIVED" in result.stdout, f"{tool}: client_version aborted the caller"
        assert "[] rc=0" in result.stdout, result.stdout


@pytest.mark.parametrize("spelling,expected", [
    ("v4.2.2+gb05881c", "4.2.2"),
    ("v3.19.2+g8766e71", "3.19.2"),
    ('{"name":"gsj","version":1,"info":{}}', ""),   # a harness JSON, not a version
    ("not a version at all", ""),
])
def test_client_version_is_anchored_and_does_not_scrape_digits_from_anywhere(
        runtime, tmp_path, spelling, expected):
    """Scraping the first digit run out of arbitrary output turned a test
    harness's release JSON into the confident, wrong answer "helm 1"."""
    run, _, _ = runtime
    directory = tmp_path / "tools"
    _tools(directory, **FLOORS)
    (directory / "helm").write_text("#!/bin/sh\ncat <<'EOF'\n" + spelling + "\nEOF\n")
    (directory / "helm").chmod(0o755)
    result = run('client_version helm', PATH=str(directory))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected, result.stdout


def test_the_offline_render_guard_refuses_only_a_known_helm_3(runtime, tmp_path):
    """Fail-open on an UNKNOWN version is deliberate and is only sound because
    client_preflight is fail-CLOSED on exactly that case, at startup, where an
    operator can still act on it."""
    run, _, _ = runtime
    directory = tmp_path / "tools"
    _tools(directory, **{**FLOORS, "helm": "3.19.2"})
    assert run('helm_dialect; require_offline_render', PATH=str(directory)).returncode != 0
    _tools(directory, **{**FLOORS, "helm": "4.2.2"})
    assert run('helm_dialect; require_offline_render', PATH=str(directory)).returncode == 0
    # no helm at all: the preflight owns that refusal, not this guard
    no_helm = _tools(tmp_path / "bare", helm=None, kubectl=None, jq=None)
    passed = run('require_offline_render && echo THROUGH', PATH=no_helm)
    assert passed.returncode == 0, passed.stderr
    assert "THROUGH" in passed.stdout


@pytest.mark.parametrize("server,admitted", [
    ("v1.26.15", False),   # the chart's NetworkPolicy label does not exist here
    ("v1.27.0", True),
    ("v1.33.6+k3s1", True),
    (None, True),          # unreadable: skip the check, never abort the run
])
def test_preflight_asserts_the_server_floor_and_tolerates_an_unreadable_one(runtime, tmp_path, server, admitted):
    """The server floor is asserted in preflight so a too-old cluster is
    refused BEFORE the Lease, the Secrets and the add-ons — not by Helm at
    apply time. And an unreadable version must skip the check rather than kill
    the run: `server=$(k version ... | jq ...)` under `set -Eeuo pipefail`
    aborts on a kubectl that cannot answer, which is the same trap that cost
    43 regressions in client_version.
    """
    run, _, work = runtime
    version = "return 1" if server is None else (
        "printf '%s' '{\"serverVersion\":{\"gitVersion\":\"" + server + "\"}}'")
    (work / "release.json").write_text(json.dumps({"platforms": ["linux/amd64"]}))
    (work / "preflight-site.json").write_text(json.dumps({
        "storage": {"profile": "managed", "class": "", "node": "n"},
        "ingress": {"profile": "managed", "class": ""},
        "registry": {"pull_secret": "", "config_file": ""}}))
    body = f'''GSJ_PAYLOAD="$TEST_WORK"; SITE="$TEST_WORK/preflight-site.json"; COMMAND=install
k() {{ case "$*" in
  *cluster-info*) return 0;;
  *version*) {version};;
  *"auth can-i"*) printf 'yes\\n';;
  *"get nodes"*) printf '%s' '{{"items":[{{"metadata":{{"name":"n"}},"status":{{"nodeInfo":{{"architecture":"amd64"}}}}}}]}}';;
  *) printf '{{}}';; esac; }}
preflight && echo ADMITTED'''
    result = run(body)
    if admitted:
        assert "ADMITTED" in result.stdout, result.stderr
    else:
        assert "ADMITTED" not in result.stdout
        assert "requires Kubernetes >= 1.27" in result.stderr, result.stderr
        assert "batch.kubernetes.io/job-name" in result.stderr


# --- OpenSSL: a floor of its own, named in the first seconds ------------------
#
# The three certificate-hostname refusals read the verdict `openssl x509
# -checkhost` prints. LibreSSL -- what macOS ships as /usr/bin/openssl -- has
# no -checkhost, so under it every certificate was refused late, as unreadable,
# with a message about the certificate. The floor is OpenSSL 3.0 (measured on
# 3.0.13, 3.5.7 and 3.6.4); the refusal names the tool, the floor and what was
# found, and it fires in bootstrap() before the client preflight, with and
# without --fetch-tools, because OpenSSL is never downloaded.

def _openssl_floor():
    source = (INSTALLER / "runtime.sh").read_text()
    line = next((l for l in source.splitlines() if l.startswith("GSJ_OPENSSL_FLOOR=")), None)
    return line.split("=", 1)[1].strip() if line else "0"


OPENSSL_FLOOR = _openssl_floor()


def test_the_openssl_floor_is_declared_once_and_is_a_version():
    assert OPENSSL_FLOOR != "0", "runtime.sh declares no GSJ_OPENSSL_FLOOR"
    assert OPENSSL_FLOOR.replace(".", "").isdigit(), OPENSSL_FLOOR
    assert (INSTALLER / "runtime.sh").read_text().count("GSJ_OPENSSL_FLOOR=") == 1


@pytest.mark.parametrize("banner,admitted", [
    ("OpenSSL 3.0.13 30 Jan 2024", True),                                          # Ubuntu 24.04
    ("OpenSSL 3.5.7 1 Oct 2025 (Library: OpenSSL 3.5.7 1 Oct 2025)", True),        # Debian trixie
    ("OpenSSL 3.6.4 25 Aug 2026 (Library: OpenSSL 3.6.4 25 Aug 2026)", True),      # Homebrew
    ("LibreSSL 3.3.6", False),                                                     # macOS /usr/bin/openssl
    ("OpenSSL 1.1.1w  11 Sep 2023", False),
])
def test_openssl_is_admitted_or_refused_by_name_floor_and_finding(runtime, tmp_path, banner, admitted):
    run, _, _ = runtime
    path = _tools(tmp_path / "tools", **FLOORS, openssl=banner)
    result = run("openssl_preflight; echo ADMITTED", PATH=path)
    if admitted:
        assert result.returncode == 0, result.stderr
        assert "ADMITTED" in result.stdout
    else:
        assert result.returncode != 0
        assert "ADMITTED" not in result.stdout
        assert f"requires OpenSSL >= {OPENSSL_FLOOR}, found {banner}" in result.stderr, result.stderr
        assert "--fetch-tools does not supply OpenSSL" in result.stderr


@pytest.mark.parametrize("fetch_tools", ["false", "true"])
def test_the_openssl_refusal_is_in_bootstrap_before_the_clients_and_survives_fetch_tools(runtime, tmp_path, fetch_tools):
    """LibreSSL and a too-old helm together: the OpenSSL refusal is the one
    reported, so it precedes the client preflight; and --fetch-tools, which
    skips that preflight, does not skip this one."""
    run, state, _ = runtime
    path = _tools(tmp_path / "tools", **{**FLOORS, "helm": "3.11.3"}, openssl="LibreSSL 3.3.6")
    result = run(f"FETCH_TOOLS={fetch_tools}; bootstrap; echo REACHED", PATH=path)
    assert result.returncode != 0
    assert "REACHED" not in result.stdout
    assert f"requires OpenSSL >= {OPENSSL_FLOOR}, found LibreSSL 3.3.6" in result.stderr, result.stderr
    assert "macOS ships LibreSSL" in result.stderr
    assert "requires helm" not in result.stderr
    assert "installer payload missing" not in result.stderr
    assert json.loads(state.read_text())["calls"] == [], "the preflight contacted the cluster"
