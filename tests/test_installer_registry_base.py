"""test_installer_registry_base — `registry.base`.

A customer on Nexus, ECR, Artifactory or Harbor keeps images under a PATH
PREFIX — `registry.company.com/team/project/gsj-web` — and until this field the
product had no answer: the release names where each image was PUBLISHED, a pull
Secret supplies credentials and cannot redirect a pull, and a container-runtime
mirror preserves the repository path, so it cannot add a prefix either.

The whole constraint, pinned here: THE LOCATION MAY MOVE, THE CONTENT MAY NOT.
`registry.base` rewrites every image reference this installer composes to
`<base>/<last path segment>`, and the digest is always the signed release's.
"""
import json
import re
import subprocess

import pytest

from tests.test_installer import INSTALLER, _release, _site, _validate, runtime  # noqa: F401  (fixture)

BASE = "registry.company.com/team/project"
ROLES = ("web", "runner", "mcp", "forgejo", "chroma", "decisionsData")


def _public_release():
    """Repositories shaped like a published release: several hosts, several
    depths — the last path segment is the only part that survives relocation."""
    release = _release()
    repositories = {"web": "ghcr.io/tumlegaltech/gsj-web", "runner": "ghcr.io/tumlegaltech/gsj-agent-runner",
                    "mcp": "ghcr.io/tumlegaltech/gsj-next-mcp", "forgejo": "codeberg.org/forgejo/forgejo",
                    "chroma": "docker.io/chromadb/chroma", "decisionsData": "ghcr.io/tumlegaltech/gsj-decisions-data"}
    for number, role in enumerate(ROLES):
        release["images"][role] = {"repository": repositories[role], "digest": "sha256:" + f"{number:x}" * 64}
    return release


def _compile(site, release, tmp_path):
    path = tmp_path / "release.json"
    path.write_text(json.dumps(release))
    result = subprocess.run(["jq", "--slurpfile", "release", str(path), "-f", str(INSTALLER / "compile.jq")],
                            input=json.dumps(site), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


# --- the site value ----------------------------------------------------------

@pytest.mark.parametrize("base", ["", "registry.company.com", "registry.company.com/team/project",
                                  "127.0.0.1:5002/team/project", "harbor.corp:8443/gsj", "nexus.corp/docker-hosted/legal_tech/gsj.v1"])
def test_a_registry_host_with_an_optional_path_prefix_is_accepted(base):
    site = _site()
    site["registry"]["base"] = base
    result = _validate(site)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("base", [
    "https://registry.company.com/team",      # a URL, not a registry reference
    "registry.company.com/team/",             # trailing slash: would render //name
    "registry.company.com/Team",              # OCI repository paths are lowercase
    "registry.company.com/team:latest",       # a tag is not a location
    "registry.company.com/team@sha256:" + "a" * 64,   # the digest is NEVER site input
    " registry.company.com",                  # whitespace
    "registry.company.com/team\n",            # a trailing newline a text editor leaves
    "registry.company.com//team",             # an empty path segment
    "/team/project",                          # no host
    "registry.company.com/team/../other",     # no traversal
])
def test_a_malformed_base_is_a_named_refusal_not_a_confusing_failure(base):
    site = _site()
    site["registry"]["base"] = base
    result = _validate(site)
    assert result.returncode != 0
    assert "site.registry.base: invalid format" in result.stderr
    # the refusal says what the value SHOULD look like; a bare "invalid format"
    # on the field that decides whether any Pod can start is the confusing failure
    assert "registry.example.org/team/project" in result.stderr


def test_the_format_hint_changes_no_other_field_s_message():
    site = _site()
    site["public_url"] = "not-a-url"
    result = _validate(site)
    assert result.returncode != 0
    assert result.stderr.strip().endswith("site.public_url: invalid format")


# --- the compiled values: location moves, content does not ---------------------

def test_every_one_of_the_six_images_moves_under_the_prefix_and_keeps_its_digest(tmp_path):
    release = _public_release()
    site = _site()
    site["registry"]["base"] = BASE
    image = _compile(site, release, tmp_path)["image"]
    compiled = {"web": image["web"], "runner": image["runner"], "mcp": image["mcp"],
                "forgejo": image["forgejo"], "chroma": image["chroma"], "decisionsData": image["corpus"]}
    for role in ROLES:
        source = release["images"][role]
        assert compiled[role]["repository"] == BASE + "/" + source["repository"].rsplit("/", 1)[1]
        assert compiled[role]["digest"] == source["digest"], "the digest is the signed release's, never the site's"
        assert compiled[role]["tag"] == "", "a tag would let the registry choose the content"
    assert len({value["repository"] for value in compiled.values()}) == 6


def test_the_field_is_optional_and_has_no_default_so_an_old_site_merges_to_the_bytes_it_always_did():
    """retained_site_matches compares a retained site byte-for-byte across installer
    versions. A new key in defaults.json would make every operation begun by the
    previous installer 'configuration changed' the moment this one continued it."""
    defaults = json.loads((INSTALLER / "defaults.json").read_text())
    assert "base" not in defaults["registry"]
    schema = json.loads((INSTALLER / "site.schema.json").read_text())["properties"]["registry"]
    assert "base" in schema["properties"] and "base" not in schema["required"]
    assert "default" not in schema["properties"]["base"]
    assert _validate(_site()).returncode == 0, "a site that never mentions registry.base is valid"


def test_an_absent_and_an_empty_base_both_compile_to_the_release_s_own_repositories(tmp_path):
    release = _public_release()
    absent = _site()
    empty = _site()
    empty["registry"]["base"] = ""
    assert "base" not in absent["registry"]
    assert _compile(absent, release, tmp_path) == _compile(empty, release, tmp_path)
    assert _compile(absent, release, tmp_path)["image"]["web"]["repository"] == "ghcr.io/tumlegaltech/gsj-web"


@pytest.mark.parametrize("base", ["myregistry", "myregistry/team/project", "harbor/gsj"])
def test_a_first_component_that_is_not_a_host_is_refused_because_a_runtime_reads_it_as_docker_hub(base):
    """`myregistry/gsj-web` is docker.io/myregistry/gsj-web to a container runtime.
    By-digest pulls could not fetch wrong CONTENT from there, but an air-gapped site
    would be sending its pulls to Docker Hub and the refusal would name a registry
    that was never contacted."""
    site = _site()
    site["registry"]["base"] = base
    result = _validate(site)
    assert result.returncode != 0
    assert "registry HOST" in result.stderr and "docker.io" in result.stderr


@pytest.mark.parametrize("base", ["localhost/team", "localhost:5000/team", "registry:5000/team", "reg.corp/team"])
def test_a_host_with_a_dot_a_port_or_localhost_is_a_host(base):
    site = _site()
    site["registry"]["base"] = base
    assert _validate(site).returncode == 0


# --- the runtime's own image references -----------------------------------------

def _payload(tmp_path, release):
    payload = tmp_path / "payload"
    payload.mkdir(exist_ok=True)
    (payload / "release.json").write_text(json.dumps(release))
    return payload


def test_maintenance_pods_are_relocated_too_not_only_the_chart(runtime, tmp_path):
    """The installer creates its own Pods from the web image — storage probe,
    vector staging, restore, credential repair. A consumer that skipped
    image_ref would name the registry the site just said its nodes cannot reach."""
    run, _, work = runtime
    release = _public_release()
    payload = _payload(tmp_path, release)
    site = _site()
    site["registry"]["base"] = BASE
    (work / "site.json").write_text(json.dumps(site))
    result = run(f'GSJ_PAYLOAD="{payload}"; payload_image web; payload_image decisionsData')
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [BASE + "/gsj-web@" + release["images"]["web"]["digest"],
                                     BASE + "/gsj-decisions-data@" + release["images"]["decisionsData"]["digest"]]


def test_a_recorded_installation_is_compared_under_the_base_it_was_installed_with(runtime, tmp_path):
    run, _, work = runtime
    release = _public_release()
    recorded_without = {"manifest": release, "site": {"registry": {"config_file": "", "pull_secret": ""}}}
    recorded_with = {"manifest": release, "site": {"registry": {"base": BASE, "config_file": "", "pull_secret": ""}}}
    (work / "old.json").write_text(json.dumps(recorded_without))
    (work / "new.json").write_text(json.dumps(recorded_with))
    result = run('installed_image web "$TEST_WORK/old.json"; installed_image web "$TEST_WORK/new.json"')
    assert result.returncode == 0, result.stderr
    digest = release["images"]["web"]["digest"]
    # an installation recorded BEFORE the field existed has no .site.registry.base
    assert result.stdout.split() == ["ghcr.io/tumlegaltech/gsj-web@" + digest, BASE + "/gsj-web@" + digest]


def test_the_three_copies_of_the_relocation_rule_agree(runtime, tmp_path):
    """There are three copies, not one: compile.jq (a payload file), JQ_IMAGE in
    runtime.sh, and an inlined def in startup-recovery.sh, which is also sourced
    without runtime.sh. Duplication is accepted; DISAGREEMENT is the defect, because
    the chart would deploy one reference and the installer compare against another."""
    run, _, work = runtime
    release = _public_release()
    payload = _payload(tmp_path, release)
    inline = re.search(r"def image_ref\(\$base\): .*?\.digest;", (INSTALLER / "startup-recovery.sh").read_text()).group(0)
    for base in ("", BASE, "127.0.0.1:5001/a/b/c"):
        site = _site()
        site["registry"]["base"] = base
        (work / "site.json").write_text(json.dumps(site))
        chart = _compile(site, release, tmp_path)["image"]
        from_chart = {role: chart["corpus" if role == "decisionsData" else role] for role in ROLES}
        from_chart = {role: value["repository"] + "@" + value["digest"] for role, value in from_chart.items()}
        result = run(f'GSJ_PAYLOAD="{payload}"; for r in {" ".join(ROLES)}; do payload_image $r; done')
        assert result.returncode == 0, result.stderr
        assert dict(zip(ROLES, result.stdout.split())) == from_chart, base
        recovery = subprocess.run(["jq", "-r", "--arg", "base", base, inline + " .images[] | image_ref($base)"],
                                  input=json.dumps(release), capture_output=True, text=True)
        assert sorted(recovery.stdout.split()) == sorted(from_chart.values()), base


def test_no_image_reference_in_the_installer_is_composed_outside_image_ref():
    """The audit of the fix, pinned: one definition composes every reference.
    A new `.repository+"@"+.digest` written anywhere else reintroduces the hole
    for exactly that consumer, silently."""
    for name in ("runtime.sh", "startup-recovery.sh"):
        source = (INSTALLER / name).read_text()
        compositions = [line for line in source.splitlines()
                        if '.repository+"@"+.digest' in line.replace(" ", "") and "def image_ref" not in line]
        assert compositions == [], f"{name} composes an image reference outside image_ref: {compositions}"


# --- preflight: what registry.base cannot do, said before the first write ---------

def test_two_images_sharing_a_final_segment_are_refused_rather_than_relocated_wrongly(runtime, tmp_path):
    run, _, work = runtime
    release = _public_release()
    release["images"]["mcp"]["repository"] = "quay.io/someone-else/gsj-web"     # collides with web
    payload = _payload(tmp_path, release)
    site = _site()
    site["registry"]["base"] = BASE
    (work / "site.json").write_text(json.dumps(site))
    result = run(f'GSJ_PAYLOAD="{payload}"; registry_base_preflight')
    assert result.returncode != 0
    assert "share a final path segment" in result.stderr
    # ...and the same release is NOT refused when the site relocates nothing
    site["registry"]["base"] = ""
    (work / "site.json").write_text(json.dumps(site))
    assert run(f'GSJ_PAYLOAD="{payload}"; registry_base_preflight').returncode == 0


def test_managed_addon_images_are_named_as_unmoved_not_silently_left_behind(runtime, tmp_path):
    run, _, work = runtime
    release = _public_release()
    release["addons"] = {"traefik": {"images": {"traefik": "docker.io/traefik@sha256:" + "7" * 64}},
                         "certManager": {"images": {"controller": "quay.io/jetstack/cert-manager-controller@sha256:" + "8" * 64}},
                         "localPath": {"images": {"helper": "docker.io/library/busybox@sha256:" + "9" * 64}}}
    payload = _payload(tmp_path, release)
    site = _site()
    site["registry"]["base"] = BASE
    site["ingress"]["profile"] = "managed-traefik"
    (work / "site.json").write_text(json.dumps(site))
    result = run(f'GSJ_PAYLOAD="{payload}"; registry_base_preflight')
    assert result.returncode == 0, "a mirror for the add-on registries is a legitimate site; this is a notice, not a refusal"
    assert "docker.io/traefik@sha256:" in result.stderr
    assert "cert-manager" not in result.stderr and "busybox" not in result.stderr, "only the add-ons this site SELECTS"


# --- the pull probe: the node's own runtime answers, by name ------------------------

PROBE_PRELUDE = '''
GSJ_PAYLOAD="{payload}"; OPERATION=aaaaaaaaaaaabbbbbbbbbbbb; CONFIG="$TEST_WORK/site.json"
trap 'echo "HINT=${{RECOVERY_HINT:-}}" >&2' EXIT      # what cleanup_exit would print as the next step
sleep() {{ :; }}
k() {{
  case "$1" in
    create) cat > "$TEST_WORK/probe-pod.json";;
    get) n=$(cat "$TEST_WORK/polls" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$TEST_WORK/polls"
         if [ -f "$TEST_WORK/status-after-$n.json" ]; then cp "$TEST_WORK/status-after-$n.json" "$TEST_WORK/status.json"; fi
         # each container's status reports the image its own container in the Pod asked for, as the kubelet
         # does for a pull it has not finished: a refusal can only name the reference the probe composed
         jq --slurpfile pod "$TEST_WORK/probe-pod.json" '($pod[0].spec.containers|map({{key:.name,value:.image}})|from_entries) as $asked
           | if .status.containerStatuses then .status.containerStatuses[] |= (.image = $asked[.name]) else . end' "$TEST_WORK/status.json";;
    delete) echo deleted >> "$TEST_WORK/deletes";;
  esac
}}
'''


def _statuses(states):
    return json.dumps({"status": {"containerStatuses": [
        {"name": "pull-" + role.lower(), "state": state}
        for role, state in zip(ROLES, states)]}})


PULLED = {"terminated": {"reason": "StartError", "exitCode": 128}}
BACKOFF = {"waiting": {"reason": "ImagePullBackOff", "message": "Back-off pulling image: manifest unknown"}}


def _probe(run, work, tmp_path, base=BASE):
    release = _public_release()
    payload = _payload(tmp_path, release)
    site = _site()
    site["registry"].update(base=base, pull_secret="corp-pull")
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
    return release, run(PROBE_PRELUDE.format(payload=payload) + "relocated_images_probe")


def test_without_a_base_the_probe_proves_the_release_s_own_repositories_by_digest(runtime, tmp_path):
    """A first install without registry.base pulled only the web image before
    the Helm apply (the storage check's), so a pull credential that cannot read
    the other five stalled the provisioning hook for its whole timeout or waited
    out the initialization deadline, hours in. The probe asks the node first,
    for every site."""
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED] * 6))
    release, result = _probe(run, work, tmp_path, base="")
    assert result.returncode == 0, result.stderr
    pod = json.loads((work / "probe-pod.json").read_text())
    assert sorted(c["image"] for c in pod["spec"]["containers"]) == sorted(
        v["repository"] + "@" + v["digest"] for v in release["images"].values()), "the six release repositories, by digest"
    assert pod["spec"]["imagePullSecrets"] == [{"name": "corp-pull"}]
    assert pod["spec"]["nodeSelector"] == {"kubernetes.io/hostname": "synthetic-node"}
    assert "Proving node synthetic-node can pull all 6 images from the release's own repositories" in result.stderr
    assert "All 6 images pulled from the release's own repositories" in result.stderr
    assert "registry.base" not in result.stderr, "a site that never set it is not told about it"


def test_the_probe_names_all_six_relocated_digests_on_the_storage_node_with_the_pull_secret(runtime, tmp_path):
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED] * 6))
    release, result = _probe(run, work, tmp_path)
    assert result.returncode == 0, result.stderr
    pod = json.loads((work / "probe-pod.json").read_text())
    images = sorted(container["image"] for container in pod["spec"]["containers"])
    assert images == sorted(BASE + "/" + release["images"][role]["repository"].rsplit("/", 1)[1] + "@" + release["images"][role]["digest"]
                            for role in ROLES)
    assert pod["spec"]["nodeSelector"] == {"kubernetes.io/hostname": "synthetic-node"}, "another node's cache proves nothing"
    assert pod["spec"]["imagePullSecrets"] == [{"name": "corp-pull"}]
    assert pod["spec"]["restartPolicy"] == "Never"
    labels = pod["metadata"]["labels"]
    assert labels == {"gsj.io/pull-probe": "synthetic-release"}, (
        "restore refuses a target holding Pods labelled gsj.io/owner or app.kubernetes.io/instance; "
        "the probe Pod is not part of the deployment and must not look like it")
    assert pod["spec"]["activeDeadlineSeconds"] == 900 + 300
    assert (work / "deletes").exists(), "the probe Pod is removed on success"
    assert "All 6 images pulled" in result.stderr


def test_a_registry_that_does_not_hold_the_digest_is_refused_by_the_condition_the_kubelet_reported(runtime, tmp_path):
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED] * 5 + [BACKOFF]))
    _, result = _probe(run, work, tmp_path)
    assert result.returncode != 0
    assert "registry.base (" + BASE + ")" in result.stderr
    assert "1 of 6 images" in result.stderr
    assert "does not hold" in result.stderr and "manifest unknown" not in result.stderr, \
        "the cause is the CONDITION the runtime's message establishes, never its words (a review finding)"
    assert "Helm has applied nothing in this run" in result.stderr, (
        "true on every chain; 'nothing was applied' was false on a repair of a quiesced deployment")
    assert (work / "deletes").exists(), "the probe Pod is removed on refusal too"
    # The cure is a CHANGED site file. `resume` refuses a changed site by design, so
    # naming it first (the default hint) would send the operator into a second refusal;
    # and on a FIRST install a repair would complete it without the storage check, so the
    # route is abandon and install again from the corrected file.
    hint = result.stderr.rsplit("HINT=", 1)[1]
    assert hint.startswith("abandon --operation aaaaaaaaaaaabbbbbbbbbbbb")
    assert "180 s" in hint, "measured on the pilot host: a repair 110 s after the stop was refused as 'still live'"


def test_six_failures_are_one_fact_said_once_not_six_times(runtime, tmp_path):
    """Measured on a proof deployment: a wrong prefix fails all six, and
    containerd's message repeats the reference three times -- 2.5 KB of one fact.
    Every image is named; the condition the runtime reported is named once
    (its words never: a review finding, they are kept in the state directory)."""
    run, _, work = runtime
    words = "rpc error: code = NotFound desc = failed to pull and unpack image: not found " * 3
    (work / "status.json").write_text(_statuses([{"waiting": {"reason": "ImagePullBackOff", "message": words}}] * 6))
    _, result = _probe(run, work, tmp_path)
    assert result.returncode != 0
    refusal = next(line for line in result.stderr.splitlines() if line.startswith("GSJ: "))
    assert "6 of 6 images" in refusal
    assert refusal.count("rpc error") == 0 and refusal.count("does not hold") == 1, "the condition once; the runtime's words never"
    assert words in (work / "pull-probe-status.json").read_text()
    assert len(refusal) < 1800


@pytest.mark.parametrize("base", ["", BASE], ids=["release-repositories", "relocated"])
def test_a_pull_failure_names_the_failing_container_s_own_reference(runtime, tmp_path, base):
    """Each container's status reports the image its own container asked for,
    so the refusal names the reference the probe composed for the one image
    that failed -- relocated under registry.base or the release's own -- and
    none of the five that pulled."""
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED, BACKOFF] + [PULLED] * 4))      # the runner's pull fails
    release, result = _probe(run, work, tmp_path, base=base)
    assert result.returncode != 0
    refusal = next(line for line in result.stderr.splitlines() if line.startswith("GSJ: "))
    runner = release["images"]["runner"]
    own = (BASE + "/gsj-agent-runner" if base else runner["repository"]) + "@" + runner["digest"]
    assert "1 of 6 images: " + own + ". " in refusal, refusal
    for role in ROLES:
        if role != "runner":
            assert release["images"][role]["digest"] not in refusal, role


def test_a_registry_that_stumbles_once_is_not_refused(runtime, tmp_path):
    """The kubelet retries with backoff. A refusal on the first ErrImagePull
    would be a false refusal of a healthy site."""
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED] * 5 + [BACKOFF]))
    (work / "status-after-6.json").write_text(_statuses([PULLED] * 6))      # recovers on a retry, 30 s in
    _, result = _probe(run, work, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "All 6 images pulled" in result.stderr


# --- the audit of the fix: each finding, pinned -------------------------------

def _installed(work, base):
    site = {"registry": {"config_file": "", "pull_secret": ""}}
    if base is not None:
        site["registry"]["base"] = base
    (work / "installed.json").write_text(json.dumps({"manifest": _public_release(), "site": site}))


def test_a_base_that_is_REMOVED_on_upgrade_is_probed_not_waved_through(runtime, tmp_path):
    """The audit's sharpest finding. The probe was gated on the NEW base being set,
    so a stale site.json -- the edit most likely to be made by accident -- rendered
    the release's original repositories with no proof at all, after quiesce had
    already scaled the application to zero."""
    run, _, work = runtime
    _installed(work, BASE)                                   # installed WITH a base
    (work / "status.json").write_text(_statuses([BACKOFF] * 6))
    release, result = _probe(run, work, tmp_path, base="")   # upgraded WITHOUT one
    assert result.returncode != 0, "a changed image location must be proven, whichever way it changed"
    pod = json.loads((work / "probe-pod.json").read_text())
    assert sorted(c["image"] for c in pod["spec"]["containers"]) == sorted(
        v["repository"] + "@" + v["digest"] for v in release["images"].values()), "it probes the UN-relocated references"
    assert "no longer sets registry.base" in result.stderr and BASE in result.stderr


def test_an_unchanged_empty_base_is_probed_and_a_failure_names_the_release_s_own_repositories(runtime, tmp_path):
    run, _, work = runtime
    _installed(work, None)                                   # recorded before the field existed
    (work / "status.json").write_text(_statuses([PULLED] * 5 + [BACKOFF]))
    release, result = _probe(run, work, tmp_path, base="")
    assert result.returncode != 0, "an upgrade of a plain site proves its pulls before the backup quiesces it"
    pod = json.loads((work / "probe-pod.json").read_text())
    assert sorted(c["image"] for c in pod["spec"]["containers"]) == sorted(
        v["repository"] + "@" + v["digest"] for v in release["images"].values())
    assert pod["spec"]["imagePullSecrets"] == [{"name": "corp-pull"}]
    refusal = next(line for line in result.stderr.splitlines() if line.startswith("GSJ: "))
    assert "cannot pull this release from the release's own repositories: 1 of 6 images" in refusal
    assert "no longer sets registry.base" not in refusal, "the base did not change"
    # nothing was relocated: the advice is the credential and the node, not a prefix or a copy
    assert "prefix" not in refusal and "copied there" not in refusal
    assert "registry.pull_secret" in refusal and "node's side" in refusal
    assert "Helm has applied nothing in this run" in refusal


def test_a_short_dependency_deadline_still_gets_the_named_refusal(runtime, tmp_path):
    """deadlines.dependencies_seconds may legally be 60. The 90 s retry rule then
    never fires, and the deadline check used to win with a nameless timeout."""
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([BACKOFF] * 6))
    release = _public_release()
    payload = _payload(tmp_path, release)
    site = _site()
    site["registry"]["base"] = BASE
    site["deadlines"]["dependencies_seconds"] = 60
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": []}}))
    result = run(PROBE_PRELUDE.format(payload=payload) + "relocated_images_probe")
    assert result.returncode != 0
    assert "cannot pull this release from registry.base" in result.stderr and "does not hold" in result.stderr and "manifest unknown" not in result.stderr
    assert "did not finish pulling" not in result.stderr


def test_the_first_failure_s_words_survive_the_back_off_that_replaces_them(runtime, tmp_path):
    """ErrImagePull carries the cause; ImagePullBackOff overwrites it with
    'Back-off pulling image'. 90 s later only the second is on the Pod."""
    run, _, work = runtime
    cause = {"waiting": {"reason": "ErrImagePull", "message": "failed to resolve reference: pull access denied, unauthorized"}}
    generic = {"waiting": {"reason": "ImagePullBackOff", "message": "Back-off pulling image \"x\""}}
    (work / "status.json").write_text(_statuses([PULLED] * 5 + [cause]))
    (work / "status-after-3.json").write_text(_statuses([PULLED] * 5 + [generic]))
    _, result = _probe(run, work, tmp_path)
    assert result.returncode != 0
    assert "unauthorized" in result.stderr, "the informative message is the one classified (a review finding: never quoted)"


def test_a_pod_evicted_before_its_pull_is_not_proof_of_a_pull(runtime, tmp_path):
    run, _, work = runtime
    unknown = {"terminated": {"reason": "ContainerStatusUnknown", "exitCode": 137}}
    (work / "status.json").write_text(_statuses([unknown] * 6))
    _, result = _probe(run, work, tmp_path)
    assert result.returncode != 0, "terminated/ContainerStatusUnknown with no imageID pulled nothing"
    assert "All 6 images pulled" not in result.stderr


def test_a_reported_image_id_is_proof_whatever_the_state(runtime, tmp_path):
    run, _, work = runtime
    status = json.loads(_statuses([{"waiting": {"reason": "ContainerCreating"}}] * 6))
    for entry in status["status"]["containerStatuses"]:
        entry["imageID"] = "registry.company.com/team/project/x@sha256:" + "a" * 64
    (work / "status.json").write_text(json.dumps(status))
    _, result = _probe(run, work, tmp_path)
    assert result.returncode == 0, result.stderr


def test_a_namespace_that_refuses_the_probe_pod_says_so_by_name(runtime, tmp_path):
    run, _, work = runtime
    release = _public_release()
    payload = _payload(tmp_path, release)
    site = _site()
    site["registry"]["base"] = BASE
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": []}}))
    prelude = PROBE_PRELUDE.format(payload=payload).replace(
        'create) cat > "$TEST_WORK/probe-pod.json";;',
        'create) cat >/dev/null; echo "pods \"gsj-pull\" is forbidden: violates PodSecurity restricted" >&2; return 1;;')
    result = run(prelude + "relocated_images_probe")
    assert result.returncode != 0
    # a review finding: the refusal names the class of the admission verdict, never kubectl's words (an
    # admission webhook's message is whatever its author wrote); the words are kept in the state directory
    assert "could not be created" in result.stderr and "an admission policy refused it" in result.stderr
    assert "violates PodSecurity" not in result.stderr and "pull-probe-create.err" in result.stderr
    assert "violates PodSecurity" in (work / "pull-probe-create.err").read_text()
    assert "HINT=\n" in result.stderr or result.stderr.rstrip().endswith("HINT="), "no repair hint: re-running would meet the same admission"


def test_sweep_removes_a_probe_pod_a_killed_installer_left_and_no_other_pod():
    """cleanup_exit removes the probe Pod on every ordinary exit; SIGKILL leaves
    it. It was labelled gsj.io/owner 'so sweep can find it' -- and sweep never
    listed Pods. Pinned on the text, because the sweep harness owns the behaviour:"""
    source = (INSTALLER / "runtime.sh").read_text()
    assert '.metadata.labels["gsj.io/pull-probe"]==$r' in source, "sweep inventories the probe Pod by ITS label alone"
    assert 'Pod) path="/api/v1/namespaces/$NAMESPACE/pods/$name";;' in source
    assert 'if [[ -n ${PROBE_POD:-} ]]; then k delete pod "$PROBE_POD"' in source, "cleanup_exit removes it on any exit"
    inventory = source[source.index("inventory=$(k get jobs,configmaps,secrets -o json"):]
    assert "k get jobs,configmaps,secrets -o json" in inventory and "k get pods,jobs" not in source, (
        "the general inventory must never start listing Pods: maintenance and application Pods carry the instance label")


def test_the_probe_runs_before_backup_quiesces_a_running_deployment():
    source = (INSTALLER / "runtime.sh").read_text()
    main = source[source.rindex(" compatibility; acquire\n"):]
    assert main.index("relocated_images_probe") < main.index("then backup; fi"), (
        "an upgrade refused by the probe must leave what was running, running")
    assert source.count("relocated_images_probe") >= 10, "defined once, called in every apply chain including restore"
    for chain in re.findall(r"^.*helm_apply;.*$", source, flags=re.M):
        if "helm_apply()" in chain:
            continue
        index = source.index(chain)
        function_start = source.rfind("\n}\n", 0, index)
        assert "relocated_images_probe" in source[function_start:index + len(chain)], chain.strip()[:90]


def test_a_sustained_pull_failure_names_the_node_side_causes_too(runtime, tmp_path):
    """Measured: the refusal listed only site values
    to check -- digests, prefix, pull secret -- and a repair after changing
    them. A registry CA the node's runtime does not trust, node DNS or proxy,
    a full node disk, a rate limit or a registry outage end in the same
    ImagePullBackOff; an operator who follows the list changes site values
    that were right."""
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED] * 5 + [BACKOFF]))
    _, result = _probe(run, work, tmp_path)
    assert result.returncode != 0
    assert "node's side" in result.stderr
    assert "trust" in result.stderr and "DNS" in result.stderr and "rate limit" in result.stderr
    assert "resume --operation" in result.stderr
    # the closing hint (what cleanup_exit prints) named repair alone -- a site change --
    # for a failure the probe cannot tell from a node-side one; it now names both routes
    hint = result.stderr.rsplit("HINT=", 1)[1]
    # a FIRST install (no installed record): a repair would complete it without the storage check, so a changed
    # site value means abandon and install again; a node that cannot pull means resume
    assert "abandon --operation" in hint and "install again" in hint and "resume --operation" in hint and "node" in hint
    assert "repair --operation" not in hint and "correct the node" not in hint


@pytest.mark.parametrize("status, installed, kind", [("backup-verified", False, "upgrade"), ("owned", True, "upgrade"), ("owned", True, "install")])
def test_a_sustained_pull_failure_over_an_installed_source_names_repair_and_resume_never_a_first_install(runtime, tmp_path, status, installed, kind):
    """Two states reach this probe over an installed source: main and resume's
    owned phase run it BEFORE the backup (status still "owned", the installed
    record read), and resume's backup-verified phase runs it after (status
    backup-verified, the record not read). Neither is a first install: the
    hint names repair for a changed site, and, before the backup, abandon and
    the operation's OWN verb again (install, or upgrade --to) -- never the
    other one."""
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED] * 5 + [BACKOFF]))
    (work / "operation.json").write_text(json.dumps({"operation": "aaaaaaaaaaaabbbbbbbbbbbb", "kind": kind, "status": status}))
    if installed:
        (work / "installed.json").write_text(json.dumps({"status": "complete"}))
    release = _public_release(); payload = _payload(tmp_path, release)
    site = _site(); site["registry"].update(base=BASE, pull_secret="corp-pull")
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
    result = run(PROBE_PRELUDE.format(payload=payload) + 'STATE_DIR="$TEST_WORK"; relocated_images_probe')
    assert result.returncode != 0
    hint = result.stderr.rsplit("HINT=", 1)[1]
    assert "repair --operation" in hint and "resume --operation" in hint
    assert "first install" not in hint and "a repair would complete" not in hint
    if status == "owned":
        # resume's owned phase follows an interrupted backup too, where abandon refuses: the hint names the
        # route without claiming nothing is quiesced, and the verb is the operation's OWN ("the same command"
        # would read as resume there; an interrupted upgrade is not told to install)
        own = "run install again" if kind == "install" else "run upgrade --to VERSION again"
        other = "run upgrade --to" if kind == "install" else "run install again"
        assert own in hint and other not in hint and "run the same command again" not in hint, hint
        assert "nothing is quiesced" not in hint and "abandon refuses while" in hint
    else:
        assert "abandon" not in hint and "install again" not in hint


@pytest.mark.parametrize("status, verb, absent", [
    ("restoring-resources", "restore-repair --operation", ("resume --operation", " repair --operation")),     # resume refuses this phase
    ("restore-files-verified", "resume --operation", ("resume refuses", "corrected installer")),                # resume accepts it under the source installer
    ("applying", "repair --operation", ("restore-repair", "resume --operation")),                             # the repair path
])
def test_a_sustained_pull_failure_during_a_restore_names_the_verb_its_state_accepts(runtime, tmp_path, status, verb, absent):
    """resume refuses a restore stopped in restoring-resources ("use
    restore-repair"), accepts restore-files-verified, and the repair path
    (applying) is repair's; a restore keeps its site byte for byte, so a
    changed registry.base or registry.pull_secret cannot continue it."""
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED] * 5 + [BACKOFF]))
    (work / "operation.json").write_text(json.dumps({"operation": "aaaaaaaaaaaabbbbbbbbbbbb", "kind": "restore", "status": status}))
    release = _public_release()
    payload = _payload(tmp_path, release)
    site = _site(); site["registry"].update(base=BASE, pull_secret="corp-pull")
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
    result = run(PROBE_PRELUDE.format(payload=payload) + 'STATE_DIR="$TEST_WORK"; relocated_images_probe')
    assert result.returncode != 0
    hint = result.stderr.rsplit("HINT=", 1)[1]
    assert hint.startswith(verb + " aaaaaaaaaaaabbbbbbbbbbbb"), hint
    for w in absent: assert w not in hint, (w, hint)
    if status == "restore-files-verified":
        assert "exact source installer" in hint and "restore-repair" not in hint
    assert "cannot continue this restore" in hint and "registry.base" in hint


@pytest.mark.parametrize("status", ["restore-files-verified", "applying"])
def test_a_restore_continued_under_a_corrected_program_names_that_installer(runtime, tmp_path, status):
    """After a restore-program transition neither resume nor the source
    installer continues the restore: only the corrected installer does --
    restore-repair before the application starts (restore-files-verified),
    repair at applying -- in every phase the probe runs in."""
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED] * 5 + [BACKOFF]))
    (work / "operation.json").write_text(json.dumps({"operation": "aaaaaaaaaaaabbbbbbbbbbbb", "kind": "restore", "status": status}))
    release = _public_release(); payload = _payload(tmp_path, release)
    site = _site(); site["registry"].update(base=BASE, pull_secret="corp-pull")
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
    result = run(PROBE_PRELUDE.format(payload=payload) + 'STATE_DIR="$TEST_WORK"; RESTORE_PROGRAM_ACTIVE=true; relocated_images_probe')
    assert result.returncode != 0
    hint = result.stderr.rsplit("HINT=", 1)[1]
    # the phase decides the verb under the corrected program too: applying is the repair path's
    verb = "repair" if status == "applying" else "restore-repair"
    assert hint.startswith(verb + " --operation aaaaaaaaaaaabbbbbbbbbbbb with this corrected installer"), hint
    if status == "applying":
        assert "restore-repair" not in hint
    assert "resume --operation" not in hint and "exact saved target" not in hint and "exact source installer" not in hint
    assert "after correcting registry.base" not in hint


def test_the_runtime_s_words_are_classified_and_never_repeated_bearer_included(runtime, tmp_path):
    """A review finding (the review's canary `registry-canary`): the refusal quoted
    up to 600 characters of the kubelet's message -- untrusted text a
    registry or a proxy composes, which carried a synthetic Authorization
    bearer into the output. The refusal now names the CONDITION the message
    establishes (not found, refused, unreachable, an untrusted certificate,
    a rate limit, a full disk, or unclassified) and where the Pod's own
    status was kept; the words themselves are never printed."""
    run, _, work = runtime
    marker = "ZZSECRET-CANARY"
    cases = {
        "registry replied Authorization: Bearer " + marker + " unauthorized: authentication required": ("refused the pull", "credential"),
        "rpc error: code = NotFound desc = failed to pull and unpack image " + marker + ": not found": ("does not hold", "digest"),
        "dial tcp: lookup registry.company.com " + marker + ": no such host": ("could not connect", "DNS"),
        "x509: certificate signed by unknown authority " + marker: ("does not trust", "certificate"),
        "toomanyrequests: rate limit exceeded " + marker: ("rate", "limit"),
        "no space left on device " + marker: ("disk", "full"),
        "something entirely new " + marker: ("does not classify", "pull-probe-status.json"),
    }
    for message, (word, other) in cases.items():
        waiting = {"waiting": {"reason": "ImagePullBackOff", "message": message}}
        (work / "status.json").write_text(_statuses([PULLED] * 5 + [waiting]))
        _, result = _probe(run, work, tmp_path)
        assert result.returncode != 0
        line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
        assert marker not in result.stderr and marker not in result.stdout, message
        assert word in line and other in line, (message, line)
        assert "pull-probe-status.json" in line                         # where the Pod's status was kept, for the operator
        kept = json.loads((work / "pull-probe-status.json").read_text())
        assert marker in json.dumps(kept)                                  # the words are kept there, 0600
        assert (work / "pull-probe-status.json").stat().st_mode & 0o077 == 0


def test_a_probe_pod_kubectl_could_not_create_is_named_without_kubectl_s_words(runtime, tmp_path):
    """The same rule for the creation failure: kubectl's stderr (an
    admission webhook's message, a forbidden verdict) is classified and kept
    in the state directory, never printed."""
    run, _, work = runtime
    marker = "ZZSECRET-CANARY"
    for words, expected in (("Error from server (Forbidden): pods is forbidden: User " + marker + " cannot create", "forbidden"),
                            ("Error from server: admission webhook denied the request: " + marker, "admission"),
                            ("the server could not find " + marker, "does not classify")):
        release = _public_release(); payload = _payload(tmp_path, release); site = _site()
        site["registry"].update(base=BASE, pull_secret="corp-pull")
        (work / "site.json").write_text(json.dumps(site))
        (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
        result = run(PROBE_PRELUDE.format(payload=payload) + "k() { if [[ $1 == create ]]; then echo " + json.dumps(words) + " >&2; return 1; fi; command kubectl \"$@\"; }\nrelocated_images_probe")
        assert result.returncode != 0
        line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
        assert marker not in line and expected in line and "pull-probe-create.err" in line, line
        assert marker in (work / "pull-probe-create.err").read_text()


def test_the_pull_deadline_names_the_conditions_reasons_never_their_messages(runtime, tmp_path):
    """The deadline refusal joined every False condition's MESSAGE -- free
    text the kubelet and the scheduler compose (a container's name, a taint's
    key and value, a node's name). It names the conditions' reasons (the
    API's enum words) and keeps the Pod's status in the state directory. The
    Pod here is placed and pulling; one the scheduler cannot place has its
    own refusal, pinned below."""
    run, _, work = runtime
    marker = "ZZSECRET-CANARY"
    waiting = {"waiting": {"reason": "ContainerCreating"}}
    status = json.loads(_statuses([waiting] * 6))
    status["status"]["conditions"] = [{"type": "PodScheduled", "status": "True"},
                                      {"type": "ContainersReady", "status": "False", "reason": "ContainersNotReady",
                                       "message": "containers with unready status: [pull-web] " + marker}]
    (work / "status.json").write_text(json.dumps(status))
    release = _public_release(); payload = _payload(tmp_path, release); site = _site()
    site["registry"].update(base=BASE, pull_secret="corp-pull"); site.setdefault("deadlines", {})["dependencies_seconds"] = 10
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
    result = run(PROBE_PRELUDE.format(payload=payload) + "relocated_images_probe")
    assert result.returncode != 0
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "did not finish pulling" in line and "ContainersReady: ContainersNotReady" in line and "pull-probe-status.json" in line
    assert "PodScheduled" not in line, "a condition that is True is not a reason the pull did not finish"
    assert marker not in result.stdout + result.stderr
    assert marker in (work / "pull-probe-status.json").read_text()


def test_the_pull_deadline_maps_a_crafted_condition_to_the_word_other(runtime, tmp_path):
    """The API does not constrain a reason string: one this installer does
    not know is named by the word "other", and its message is kept, never
    repeated."""
    run, _, work = runtime
    marker = "ZZSECRET-CANARY"
    waiting = {"waiting": {"reason": "ContainerCreating"}}
    status = json.loads(_statuses([waiting] * 6))
    status["status"]["conditions"] = [{"type": "PodScheduled", "status": "True"},
                                      {"type": "ContainersReady", "status": "False", "reason": "ContainersNotReady" + "ZZSECRETCANARY",
                                       "message": "containers with unready status: [pull-web] " + marker}]
    (work / "status.json").write_text(json.dumps(status))
    release = _public_release(); payload = _payload(tmp_path, release); site = _site()
    site["registry"].update(base=BASE, pull_secret="corp-pull"); site.setdefault("deadlines", {})["dependencies_seconds"] = 10
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
    result = run(PROBE_PRELUDE.format(payload=payload) + "relocated_images_probe")
    assert result.returncode != 0
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "did not finish pulling" in line and "ContainersReady: other" in line and "ZZSECRETCANARY" not in result.stderr and "pull-probe-status.json" in line
    assert marker not in result.stdout + result.stderr
    assert marker in (work / "pull-probe-status.json").read_text()


# --- how long a pull in progress may take, and what the deadline names -------------

CREATING = {"waiting": {"reason": "ContainerCreating"}}


def _slow(run, work, tmp_path, base, pulled_at=None, recorded=None, dependencies=10, initialization=20, operation=None, prefix="", states=None, status=None):
    """The probe over containers that are still pulling (no failure reported,
    unless states says otherwise; status: the Pod's whole status instead):
    each poll is 5 s, so poll n sees spent = 5*(n-1). pulled_at: the poll
    whose status has all six pulled; None: they never finish. recorded: the
    base the installed deployment was recorded with (None: no installed
    record)."""
    (work / "status.json").write_text(status or _statuses(states or [CREATING] * 6))
    if pulled_at:
        (work / f"status-after-{pulled_at}.json").write_text(_statuses([PULLED] * 6))
    if recorded is not None:
        _installed(work, recorded)
    if operation:
        (work / "operation.json").write_text(json.dumps({"operation": "aaaaaaaaaaaabbbbbbbbbbbb", **operation}))
    release = _public_release(); payload = _payload(tmp_path, release)
    site = _site(); site["registry"].update(base=base, pull_secret="corp-pull")
    site["deadlines"].update(dependencies_seconds=dependencies, initialization_seconds=initialization)
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
    return run(PROBE_PRELUDE.format(payload=payload) + prefix + "relocated_images_probe")


def test_a_plain_site_still_pulling_at_the_dependency_deadline_is_not_refused_and_the_log_says_why(runtime, tmp_path):
    """A plain site the previous release installed pulled four of its six images
    under the initialization deadline (24 h by default); the probe bounded all
    six by deadlines.dependencies_seconds and refused a slow link that had
    installed before. With the location unchanged, a pull still in progress
    goes on past that deadline, once said, up to the initialization deadline
    beyond it."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base="", pulled_at=6)          # spent 25 s: past the 10 s deadline
    assert result.returncode == 0, result.stderr
    assert "did not finish pulling" not in result.stderr
    assert result.stderr.count("still pulling") == 1, "said once, at deadlines.dependencies_seconds"
    line = next(l for l in result.stderr.splitlines() if "still pulling" in l)
    assert "deadlines.dependencies_seconds (10 s)" in line and "slow link" in line and "wait goes on" in line, line
    assert "All 6 images pulled" in result.stderr
    pod = json.loads((work / "probe-pod.json").read_text())
    assert pod["spec"]["activeDeadlineSeconds"] == 10 + 20 + 300, "the Pod outlives the wait it serves"


def test_a_plain_site_still_pulling_is_refused_at_both_deadlines_together(runtime, tmp_path):
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base="")
    assert result.returncode != 0
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "did not finish pulling" in line
    assert "deadlines.dependencies_seconds plus deadlines.initialization_seconds (30 s)" in line, line
    assert json.loads((work / "probe-pod.json").read_text())["spec"]["activeDeadlineSeconds"] == 30 + 300


@pytest.mark.parametrize("base, recorded", [(BASE, None), ("", BASE)], ids=["set", "removed"])
def test_a_set_or_changed_base_still_pulling_is_refused_at_the_dependency_deadline(runtime, tmp_path, base, recorded):
    """A relocated site, or one whose base changed, keeps the dependency
    deadline: its images were proven under it before."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base=base, pulled_at=6, recorded=recorded)
    assert result.returncode != 0
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "did not finish pulling" in line and "within deadlines.dependencies_seconds (10 s)" in line, line
    assert "still pulling" not in result.stderr
    assert json.loads((work / "probe-pod.json").read_text())["spec"]["activeDeadlineSeconds"] == 10 + 300


# --- a pull failure: refused after 90 s only when a retry cannot change it ------

TIMEOUT = {"waiting": {"reason": "ErrImagePull", "message": "failed to pull and unpack image: failed to copy: read tcp: i/o timeout"}}
UNAUTHORIZED = {"waiting": {"reason": "ErrImagePull", "message": "failed to authorize: failed to fetch anonymous token: 401 Unauthorized"}}


def _polls(work):
    return int((work / "polls").read_text())


def test_a_pull_failure_a_retry_can_clear_is_waited_out_on_a_plain_site_and_said_once(runtime, tmp_path):
    """The 90 s window ran from the first failing sighting and never reset while
    the kubelet retried, so on a slow link one timed-out pull of a large image
    was refused while its retry was still pulling. A connection, a rate limit
    or words this installer does not classify can clear on a retry: said once,
    and waited out for deadlines.dependencies_seconds from its first report."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base="", states=[PULLED] * 5 + [TIMEOUT], pulled_at=31,       # 150 s in
                   dependencies=200, initialization=200)
    assert result.returncode == 0, result.stderr
    assert "All 6 images pulled" in result.stderr
    retried = [l for l in result.stderr.splitlines() if "is failing and being retried" in l]
    assert len(retried) == 1, result.stderr
    assert "could not connect to the registry" in retried[0] and "a retry can clear" in retried[0], retried[0]
    assert "up to deadlines.dependencies_seconds (200 s) after it was first reported" in retried[0], retried[0]
    assert "initialization_seconds" not in retried[0], "a failure is never given the long bound of a pull in progress"
    assert "i/o timeout" not in result.stderr, "the runtime's words are classified, never repeated"


@pytest.mark.parametrize("waiting, condition", [
    (UNAUTHORIZED, "the registry refused the pull (unauthorized or forbidden"),
    ({"waiting": {"reason": "ErrImagePull", "message": "rpc error: code = NotFound desc = failed to resolve reference: not found"}},
     "the registry does not hold that name and digest (not found)"),
    ({"waiting": {"reason": "InvalidImageName", "message": "Failed to apply default image tag: couldn't parse image reference: invalid reference format"}},
     "the reference is not a valid image name (an invalid name)"),
], ids=["unauthorized", "not-found", "invalid-name"])
def test_a_definitive_pull_failure_is_still_refused_after_90_s_on_a_plain_site(runtime, tmp_path, waiting, condition):
    """The registry's answer about the credential or the name, and a name that
    is not one, are the same on every retry: refused once they have outlived
    90 s, as before, and never waited out to a bound of hours."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base="", states=[PULLED] * 5 + [waiting], dependencies=100, initialization=200)
    assert result.returncode != 0
    assert _polls(work) == 19, "refused at 90 s, not at the 300 s bound"
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "cannot pull this release" in line and condition in line, line
    assert "(300 s)" not in line and "being retried" not in result.stderr


def test_a_definitive_failure_of_one_image_is_not_masked_by_a_retried_failure_of_another(runtime, tmp_path):
    """The first failing container's words decided the class: an image whose
    pull times out ahead of one the registry refuses would have waited the
    refusal out to the bound."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base="", states=[PULLED] * 4 + [TIMEOUT, UNAUTHORIZED], dependencies=100, initialization=200)
    assert result.returncode != 0
    assert _polls(work) == 19, "refused at 90 s"
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "2 of 6 images" in line and "the registry refused the pull (unauthorized" in line, line
    assert "could not connect" not in line


@pytest.mark.parametrize("base, still", [
    ("", "still failing deadlines.dependencies_seconds (100 s) after it was first reported"),
    (BASE, "still failing at the end of deadlines.dependencies_seconds (100 s)"),
], ids=["plain", "relocated"])
def test_a_retried_pull_failure_still_failing_at_the_dependency_deadline_is_refused_by_its_class(runtime, tmp_path, base, still):
    """A failure the kubelet kept retrying for deadlines.dependencies_seconds
    is refused there as a failure, named by its class and by the deadline it
    outlived -- never as a pull that did not finish, and on a plain site
    never waited out to the long bound, which is a pull in progress's
    alone."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base=base, states=[PULLED] * 5 + [TIMEOUT], dependencies=100, initialization=200)
    assert result.returncode != 0
    assert _polls(work) == 21, "refused at deadlines.dependencies_seconds (100 s), not at 90 s nor at the 300 s bound"
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "cannot pull this release" in line and "1 of 6 images" in line, line
    assert "the node could not connect to the registry" in line and still in line, line
    assert "did not finish pulling" not in line and "i/o timeout" not in result.stderr
    assert result.stderr.count("is failing and being retried") == 1


DNS = {"waiting": {"reason": "ErrImagePull", "message": "dial tcp: lookup registry.company.com: no such host"}}
UNTRUSTED = {"waiting": {"reason": "ErrImagePull", "message": "tls: failed to verify certificate: x509: certificate signed by unknown authority"}}
RATE_LIMITED = {"waiting": {"reason": "ErrImagePull", "message": "429 Too Many Requests: toomanyrequests: rate limit exceeded"}}
DISK_FULL = {"waiting": {"reason": "ErrImagePull", "message": "failed to extract layer: write /var/lib/containerd/x: no space left on device"}}
UNCLASSIFIED = {"waiting": {"reason": "ErrImagePull", "message": "something this installer has never seen"}}


@pytest.mark.parametrize("waiting, condition", [
    (TIMEOUT, "the node could not connect to the registry"),
    (DNS, "the node could not connect to the registry"),
    (UNTRUSTED, "the node does not trust the registry's certificate"),
    (RATE_LIMITED, "the registry rate-limited the pull"),
    (DISK_FULL, "the node's disk is full"),
    (UNCLASSIFIED, "a condition this installer does not classify"),
], ids=["timeout", "dns", "x509", "rate-limit", "disk", "unclassified"])
def test_a_failure_a_retry_could_clear_that_persists_to_the_dependency_deadline_is_refused_there_by_class_and_image(runtime, tmp_path, waiting, condition):
    """On a site without registry.base a failure of any class but the
    definitive three was waited out to deadlines.dependencies_seconds plus
    deadlines.initialization_seconds, 24 hours and a quarter by default. The
    previous release gave its Forgejo image deadlines.dependencies_seconds,
    the provisioning hook's timeout. A failure reported that long is refused
    there, by its class and the failing image's reference: not at 90 s, the
    definitive classes' bound, and not at the long bound, which is a pull
    in progress's alone."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base="", states=[PULLED] * 5 + [waiting], dependencies=100, initialization=200)
    assert result.returncode != 0
    assert _polls(work) == 21, "refused at 100 s: not at 90 s (poll 19), not at the 300 s bound (poll 61)"
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    corpus = _public_release()["images"]["decisionsData"]
    assert "cannot pull this release from the release's own repositories: 1 of 6 images: " + corpus["repository"] + "@" + corpus["digest"] + ". " in line, line
    assert condition in line and "still failing deadlines.dependencies_seconds (100 s) after it was first reported" in line, line
    assert waiting["waiting"]["message"] not in result.stderr, "the runtime's words are classified, never repeated"
    assert result.stderr.count("is failing and being retried") == 1


def test_a_failure_first_reported_past_the_dependency_deadline_is_given_that_deadline_from_its_report(runtime, tmp_path):
    """A slow link's pull can time out long after deadlines.dependencies_seconds
    and pull on the kubelet's next attempt. The bound is how long the failure
    has been reported, not how long the pull has taken: refused
    deadlines.dependencies_seconds after its first report, and the slow link
    said once, at the deadline, while the containers were still pulling."""
    run, _, work = runtime
    (work / "status-after-31.json").write_text(_statuses([PULLED] * 5 + [TIMEOUT]))     # first reported 150 s in
    result = _slow(run, work, tmp_path, base="", states=[PULLED] * 5 + [CREATING], dependencies=100, initialization=400)
    assert result.returncode != 0
    assert _polls(work) == 51, "150 s + 100 s; not on the first sighting past the deadline, not at the 500 s bound"
    assert result.stderr.count("still pulling") == 1
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "could not connect to the registry" in line and "still failing deadlines.dependencies_seconds (100 s) after it was first reported" in line, line


@pytest.mark.parametrize("status, verb, absent", [
    ("restoring-resources", "restore-repair --operation", ("resume --operation", " repair --operation")),
    ("restore-files-verified", "resume --operation", ("restore-repair",)),
    ("applying", "repair --operation", ("restore-repair", "resume --operation")),
])
def test_the_pull_deadline_during_a_restore_names_the_verb_its_state_accepts(runtime, tmp_path, status, verb, absent):
    """The deadline named one hint for every kind and phase -- resume, or repair
    after raising the deadline -- and both refuse a restore stopped in
    restoring-*; a restore's site is retained byte for byte, so no raised
    deadline continues it."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base=BASE, operation={"kind": "restore", "status": status}, prefix='STATE_DIR="$TEST_WORK"; ')
    assert result.returncode != 0 and "did not finish pulling" in result.stderr
    hint = result.stderr.rsplit("HINT=", 1)[1]
    assert hint.startswith(verb + " aaaaaaaaaaaabbbbbbbbbbbb"), hint
    for word in absent:
        assert word not in hint, (word, hint)
    assert "a raised deadlines.dependencies_seconds cannot continue this restore" in hint, hint
    assert "after raising" not in hint


def test_the_pull_deadline_on_a_first_install_names_abandon_and_install_again_never_repair(runtime, tmp_path):
    """A repair of an owned first install completes it without the storage check."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base=BASE, operation={"kind": "install", "status": "owned"}, prefix='STATE_DIR="$TEST_WORK"; ')
    assert result.returncode != 0 and "did not finish pulling" in result.stderr
    hint = result.stderr.rsplit("HINT=", 1)[1]
    assert hint.startswith("abandon --operation aaaaaaaaaaaabbbbbbbbbbbb"), hint
    assert "install again from the corrected file after raising deadlines.dependencies_seconds" in hint, hint
    assert "resume --operation aaaaaaaaaaaabbbbbbbbbbbb" in hint and "repair --operation" not in hint


@pytest.mark.parametrize("status, kind, abandon", [("backup-verified", "upgrade", False), ("owned", "upgrade", True)])
def test_the_pull_deadline_over_an_installed_source_names_repair_after_raising_it_and_resume(runtime, tmp_path, status, kind, abandon):
    run, _, work = runtime
    (work / "installed.json").write_text(json.dumps({"status": "complete"}))
    result = _slow(run, work, tmp_path, base=BASE, operation={"kind": kind, "status": status}, prefix='STATE_DIR="$TEST_WORK"; ')
    assert result.returncode != 0 and "did not finish pulling" in result.stderr
    hint = result.stderr.rsplit("HINT=", 1)[1]
    assert hint.startswith("repair --operation aaaaaaaaaaaabbbbbbbbbbbb --config") and "after raising deadlines.dependencies_seconds" in hint, hint
    assert "resume --operation aaaaaaaaaaaabbbbbbbbbbbb" in hint and "first install" not in hint
    assert ("run upgrade --to VERSION again" in hint) == abandon and "install again" not in hint


# --- the probe Pod's resources, and a LimitRange or ResourceQuota that refuses it ---

def test_every_probe_container_asks_50m_and_64Mi_with_both_limits_equal_so_six_fit_beside_a_running_deployment(runtime, tmp_path):
    """10m CPU and 16Mi memory under a memory limit alone: a LimitRange minimum
    of 32Mi refused the probe, and the CPU limit a LimitRange injects where
    none is set made a limit-to-request ratio of 100. The storage check's
    100m and 128Mi then made six 600m and 768Mi, asked before the backup,
    beside the running deployment's reservations: on a node sized to the
    guide's figures -- 9 GiB, the deployment reserving 8.25 GiB -- that is
    the whole remainder, before the kubelet's own reservation and the system
    Pods, and the scheduler could not place it. 50m and 64Mi, both limits
    equal (ratio 1, nothing injected): six are 300m and 384Mi, half that
    remainder, and still above the LimitRange minimum."""
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED] * 6))
    _, result = _probe(run, work, tmp_path)
    assert result.returncode == 0, result.stderr
    pod = json.loads((work / "probe-pod.json").read_text())
    assert [c["resources"] for c in pod["spec"]["containers"]] == [
        {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"cpu": "50m", "memory": "64Mi"}}] * 6
    memory = sum(int(c["resources"]["requests"]["memory"][:-2]) for c in pod["spec"]["containers"])
    cpu = sum(int(c["resources"]["requests"]["cpu"][:-1]) for c in pod["spec"]["containers"])
    assert (cpu, memory) == (300, 384)
    assert memory <= (9 * 1024 - 8.25 * 1024) / 2, "at most half of what the guide's node leaves beside the deployment"


# A namespace LimitRange that admits every Pod the previous release created: a
# 32Mi minimum per container, a CPU limit of 1 injected where none is set, and a
# limit at most 10 times the request. The fake applies it to what the manifest
# asks and answers as the API server does.
LIMIT_RANGE_CREATE = r"""create) doc=$(cat)
           refused=$(jq -r 'def mi: if endswith("Gi") then (.[:-2]|tonumber)*1024 else .[:-2]|tonumber end;
             def milli: if endswith("m") then .[:-1]|tonumber else (tonumber*1000) end;
             [.spec.containers[].resources |
               (if (.requests.memory|mi) < 32 then "minimum memory usage per Container is 32Mi, but request is \(.requests.memory)" else empty end),
               ((((.limits.cpu // "1")|milli) / (.requests.cpu|milli)) as $ratio | if $ratio > 10 then "cpu max limit to request ratio per Container is 10, but provided ratio is \($ratio)" else empty end)]
             | unique | join(", ")' <<< "$doc")
           if [ -n "$refused" ]; then echo "Error from server (Forbidden): error when creating \"STDIN\": pods \"gsj-pull-aaaaaaaaaaaa\" is forbidden: [$refused]" >&2; return 1; fi
           printf '%s' "$doc" > "$TEST_WORK/probe-pod.json";;"""


def test_a_limit_range_that_admits_the_previous_release_s_pods_admits_the_probe(runtime, tmp_path):
    """The probe's 16Mi fell below that 32Mi minimum and its 10m under the
    injected CPU limit of 1 made a ratio of 100: the namespace admitted a whole
    deployment and refused the Pod meant to prove its pulls. What the manifest
    asks now passes both rules; the old request does not, so the fake bites."""
    run, _, work = runtime
    (work / "status.json").write_text(_statuses([PULLED] * 6))
    release = _public_release(); payload = _payload(tmp_path, release); site = _site()
    site["registry"].update(base=BASE, pull_secret="corp-pull")
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
    prelude = PROBE_PRELUDE.format(payload=payload).replace('create) cat > "$TEST_WORK/probe-pod.json";;', LIMIT_RANGE_CREATE)
    result = run(prelude + "relocated_images_probe")
    assert result.returncode == 0, result.stderr
    assert "All 6 images pulled" in result.stderr and "could not be created" not in result.stderr
    old = json.dumps({"spec": {"containers": [{"resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"memory": "16Mi"}}}]}})
    refused = run(prelude + "k create -f - <<< " + json.dumps(old))
    assert refused.returncode != 0
    assert "minimum memory usage per Container is 32Mi, but request is 16Mi" in refused.stderr
    assert "ratio per Container is 10, but provided ratio is 100" in refused.stderr


@pytest.mark.parametrize("words", [
    'Error from server (Forbidden): error when creating "STDIN": pods "gsj-pull-aaaaaaaaaaaa" is forbidden: minimum memory usage per Container is 32Mi, but request is 16Mi',
    'Error from server (Forbidden): error when creating "STDIN": pods "gsj-pull-aaaaaaaaaaaa" is forbidden: [maximum cpu usage per Container is 5m, but limit is 10m]',
    'Error from server (Forbidden): error when creating "STDIN": pods "gsj-pull-aaaaaaaaaaaa" is forbidden: exceeded quota: compute, requested: requests.memory=96Mi, used: requests.memory=4Gi, limited: requests.memory=4Gi',
], ids=["limitrange-minimum", "limitrange-maximum", "resourcequota"])
def test_a_limit_range_or_quota_that_refuses_the_probe_is_not_blamed_on_permissions(runtime, tmp_path, words):
    """Their verdict reads 'forbidden', and the refusal called it the
    kubeconfig's permissions: the operator was sent to RBAC."""
    run, _, work = runtime
    release = _public_release(); payload = _payload(tmp_path, release); site = _site()
    site["registry"].update(base=BASE, pull_secret="corp-pull")
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
    result = run(PROBE_PRELUDE.format(payload=payload) + "k() { if [[ $1 == create ]]; then echo " + json.dumps(words) + " >&2; return 1; fi; command kubectl \"$@\"; }\nrelocated_images_probe")
    assert result.returncode != 0
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "an admission policy (LimitRange or ResourceQuota) refused the Pod" in line, line
    assert "permissions" not in line and "32Mi" not in line and "exceeded" not in line
    assert "cpu 50m and memory 64Mi, with limits equal to those requests" in line and "LimitRange" in line and "ResourceQuota" in line


# --- a probe Pod the scheduler cannot place --------------------------------------

UNPLACED_WORDS = "0/1 nodes are available: 1 Insufficient memory, taint team=ZZSECRET-CANARY"


def _unscheduled(reason="Unschedulable"):
    """What the API reports for a Pod the scheduler cannot place: no container
    statuses at all, and PodScheduled False with the scheduler's own words."""
    return json.dumps({"status": {"phase": "Pending", "conditions": [
        {"type": "PodScheduled", "status": "False", "reason": reason, "message": UNPLACED_WORDS}]}})


@pytest.mark.parametrize("base", ["", BASE], ids=["plain", "relocated"])
def test_a_probe_pod_the_scheduler_cannot_place_is_refused_after_300_s_by_name(runtime, tmp_path, base):
    """The probe runs before the backup, beside the running deployment's
    reservations. A Pod the scheduler could not place reported no container
    status, was logged as a slow link at deadlines.dependencies_seconds and,
    on a site without registry.base, refused a day later as a pull that did
    not finish. Unscheduled for 300 s -- the storage check's bound and the
    capacity reader's -- it is refused by what it is: storage.node, what the
    Pod asks for in all, and the condition's reason; the scheduler's words
    are kept, never repeated."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base=base, status=_unscheduled(), dependencies=600, initialization=1200)
    assert result.returncode != 0
    assert _polls(work) == 61, "refused at 300 s, not at deadlines.dependencies_seconds nor at the long bound"
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "the image pull probe's Pod was not scheduled (PodScheduled: Unschedulable) within 300 s" in line, line
    assert "storage.node (synthetic-node) has no room for" in line and "cpu 300m and memory 384Mi" in line, line
    assert "pull-probe-status.json" in line and "Helm has applied nothing in this run" in line, line
    assert "did not finish pulling" not in line and "cannot pull" not in line, "the registry is not blamed"
    assert "still pulling" not in result.stderr, "a Pod the scheduler has not placed is not pulling on a slow link"
    assert "ZZSECRET-CANARY" not in result.stdout + result.stderr
    assert UNPLACED_WORDS in (work / "pull-probe-status.json").read_text()


@pytest.mark.parametrize("reason, word", [("SchedulerError", "SchedulerError"), ("Unschedulable" + "ZZSECRETCANARY", "other")],
                         ids=["scheduler-error", "crafted"])
def test_a_dependency_deadline_shorter_than_300_s_refuses_an_unplaced_pod_by_name_at_its_end(runtime, tmp_path, reason, word):
    """deadlines.dependencies_seconds may be 60 on a site with registry.base:
    its end arrives first, and the refusal still names the scheduler, not a
    pull that did not finish. A reason this installer does not know is the
    word "other"."""
    run, _, work = runtime
    result = _slow(run, work, tmp_path, base=BASE, status=_unscheduled(reason), dependencies=60)
    assert result.returncode != 0
    assert _polls(work) == 13
    line = [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]
    assert "was not scheduled (PodScheduled: " + word + ") within deadlines.dependencies_seconds (60 s)" in line, line
    assert "ZZSECRETCANARY" not in result.stderr and "did not finish pulling" not in line


def test_a_probe_pod_placed_within_300_s_is_not_refused(runtime, tmp_path):
    """Room freed beside it -- a Pod finishing, a node added -- places the Pod
    within minutes; the grace is not held against it once placed."""
    run, _, work = runtime
    (work / "status-after-60.json").write_text(_statuses([CREATING] * 6))       # placed and pulling 295 s in
    result = _slow(run, work, tmp_path, base="", status=_unscheduled(), pulled_at=70, dependencies=600, initialization=1200)
    assert result.returncode == 0, result.stderr
    assert "All 6 images pulled" in result.stderr and "was not scheduled" not in result.stderr


def test_the_slow_link_line_is_said_only_while_the_containers_report_a_pull(runtime, tmp_path):
    """A Pod placed on a node whose kubelet reports no container status is
    not a pull on a slow link: the line waits for a pull to be reported."""
    run, _, work = runtime
    placed = json.dumps({"status": {"phase": "Pending", "conditions": [{"type": "PodScheduled", "status": "True"}]}})
    result = _slow(run, work, tmp_path, base="", status=placed, dependencies=100, initialization=200)
    assert result.returncode != 0 and _polls(work) == 61
    assert "still pulling" not in result.stderr
    assert "did not finish pulling" in [l for l in result.stderr.splitlines() if l.startswith("GSJ:")][-1]


@pytest.mark.parametrize("operation, installed, starts, present, absent", [
    ({"kind": "install", "status": "owned"}, False, "abandon --operation aaaaaaaaaaaabbbbbbbbbbbb",
     ("install again from the corrected file with another storage.node", "(a repair would complete this first install without the storage check)",
      "resume --operation aaaaaaaaaaaabbbbbbbbbbbb once room is freed on node synthetic-node for the probe Pod's cpu 300m and memory 384Mi"),
     (" repair --operation", "after raising")),
    ({"kind": "upgrade", "status": "owned"}, True, "resume --operation aaaaaaaaaaaabbbbbbbbbbbb once room is freed on node synthetic-node",
     ("a changed storage.node is refused for an installed release, whose claims stay where they are",),
     ("repair --operation", "abandon", "install again", "after raising")),
    ({"kind": "upgrade", "status": "backup-verified"}, True, "resume --operation aaaaaaaaaaaabbbbbbbbbbbb once room is freed on node synthetic-node",
     ("a changed storage.node is refused for an installed release",), ("repair --operation", "abandon")),
    ({"kind": "restore", "status": "restoring-resources"}, False, "restore-repair --operation aaaaaaaaaaaabbbbbbbbbbbb with the exact saved target once room is freed",
     ("a changed storage.node cannot continue this restore",), ("resume --operation", " repair --operation")),
    ({"kind": "restore", "status": "restore-files-verified"}, False, "resume --operation aaaaaaaaaaaabbbbbbbbbbbb with the exact source installer once room is freed",
     ("a changed storage.node cannot continue this restore",), ("restore-repair",)),
    ({"kind": "restore", "status": "applying"}, False, "repair --operation aaaaaaaaaaaabbbbbbbbbbbb with the exact saved target once room is freed",
     ("a changed storage.node cannot continue this restore",), ("restore-repair", "resume --operation")),
], ids=["first-install", "upgrade-before-backup", "upgrade-after-backup", "restoring-resources", "restore-files-verified", "restore-applying"])
def test_an_unplaced_probe_pod_names_the_verb_the_operation_s_state_accepts(runtime, tmp_path, operation, installed, starts, present, absent):
    """Room freed on the node continues every operation with its own site: a
    first install may also start again from a file naming another node, an
    installed release's claims stay where they are, and a restore keeps its
    site byte for byte and is continued by the verb its phase accepts."""
    run, _, work = runtime
    if installed:
        (work / "installed.json").write_text(json.dumps({"status": "complete"}))
    result = _slow(run, work, tmp_path, base=BASE, status=_unscheduled(), dependencies=400, operation=operation, prefix='STATE_DIR="$TEST_WORK"; ')
    assert result.returncode != 0 and "was not scheduled" in result.stderr
    hint = result.stderr.rsplit("HINT=", 1)[1]
    assert hint.startswith(starts), hint
    for words in present:
        assert words in hint, (words, hint)
    for words in absent:
        assert words not in hint, (words, hint)


# --- a probe Pod that could not be created, during a restore ----------------------

@pytest.mark.parametrize("status, program, verb", [
    ("restoring-resources", False, "restore-repair --operation aaaaaaaaaaaabbbbbbbbbbbb with the exact saved target"),
    ("restore-files-verified", False, "resume --operation aaaaaaaaaaaabbbbbbbbbbbb with the exact source installer"),
    ("applying", False, "repair --operation aaaaaaaaaaaabbbbbbbbbbbb with the exact saved target"),
    ("restore-files-verified", True, "restore-repair --operation aaaaaaaaaaaabbbbbbbbbbbb with this corrected installer"),
], ids=["restoring-resources", "restore-files-verified", "applying", "corrected-program"])
def test_a_probe_pod_a_restore_could_not_create_names_the_verb_its_state_accepts(runtime, tmp_path, status, program, verb):
    """The closing line fell back to resume, which refuses a restore stopped in
    restoring-resources and one a corrected program continues: the verb is
    the one the restore's phase accepts, once the namespace admits the Pod."""
    run, _, work = runtime
    (work / "operation.json").write_text(json.dumps({"operation": "aaaaaaaaaaaabbbbbbbbbbbb", "kind": "restore", "status": status}))
    release = _public_release(); payload = _payload(tmp_path, release); site = _site()
    site["registry"].update(base=BASE, pull_secret="corp-pull")
    (work / "site.json").write_text(json.dumps(site))
    (work / "values.pending.json").write_text(json.dumps({"image": {"pullSecrets": ["corp-pull"]}}))
    words = 'Error from server (Forbidden): error when creating "STDIN": pods "gsj-pull-aaaaaaaaaaaa" is forbidden: exceeded quota: compute'
    result = run(PROBE_PRELUDE.format(payload=payload) + ("RESTORE_PROGRAM_ACTIVE=true; " if program else "")
                 + "k() { if [[ $1 == create ]]; then echo " + json.dumps(words) + " >&2; return 1; fi; command kubectl \"$@\"; }\nrelocated_images_probe")
    assert result.returncode != 0 and "could not be created" in result.stderr
    hint = result.stderr.rsplit("HINT=", 1)[1]
    assert hint.startswith(verb), hint
    assert "once the namespace admits the probe Pod (wait 180 s first" in hint, hint
    if status == "restoring-resources" or program:
        assert "resume --operation" not in hint
