"""test_web_pin — the product pin's integrity, the installer's counterpart of
the product's own library pin test.

web-pin.json names ONE gsj-next-web commit and records what the installer
takes from it. These tests hold the record to the Git objects (the chart's
tree and its normalized package, gsj_deploy's tree, the chart version, the
core tag the product ships), hold every other pin site in this repository to
the same commit (requirements-local.txt, the installed distributions), and
hold the contract document to the copy the product carries.

Skip-guarded on the pinned Git objects, like the product's sibling check: a
public CI runner has no access to the private product, so those legs skip
there and run wherever a maintainer stages the commit.
"""
import copy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import shutil

import pytest

from tests.pinned_web import PIN, ROOT, chart, needs_web, show, tree, webpin

needs_helm = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")


def test_the_pin_file_is_well_formed():
    assert PIN["schema"] == "gsj.web-pin/1"
    assert PIN["repository"] == "TUMLegalTech/gsj-next-web"
    assert re.fullmatch(r"[0-9a-f]{40}", PIN["commit"])


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(commit="abc"),
    lambda p: p.update(release="v0.10.0"),                       # a release with no images
    lambda p: p.update(images={"web": {"repository": "r", "digest": "sha256:" + "a" * 64}}),  # images with no release
    lambda p: p["chart"].update(sha256="short"),
    lambda p: p.pop("gsj_deploy"),
    lambda p: p["core"].update(tag="4.12.1"),
])
def test_a_malformed_pin_is_refused_before_anything_reads_it(tmp_path, mutation):
    value = copy.deepcopy(PIN)
    mutation(value)
    path = tmp_path / "web-pin.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="web-pin.json"):
        webpin.load(path)


def test_release_and_images_are_set_together_at_promotion(tmp_path):
    """The form promotion bumps in ONE reviewed change: the commit becomes the
    release tag's commit, `release` names the tag and `images` carries the
    four product image digests the product release published."""
    value = copy.deepcopy(PIN)
    value["release"] = "v0.10.0"
    value["images"] = {role: {"repository": "ghcr.io/tumlegaltech/" + role.lower(), "digest": "sha256:" + "a" * 64}
                       for role in webpin.IMAGE_ROLES}
    path = tmp_path / "web-pin.json"
    path.write_text(json.dumps(value))
    assert webpin.load(path)["release"] == "v0.10.0"


def test_requirements_pin_the_same_product_commit_and_core_tag():
    """requirements-local.txt is the second pin site; it must never drift."""
    text = (ROOT / "requirements-local.txt").read_text()
    product = re.findall(r"(?m)^gsj-web\[dev\] @ git\+file://[^\n]+@([^\s]+)$", text)
    core = re.findall(r"(?m)^gsj\[cli\] @ git\+file://[^\n]+@([^\s]+)$", text)
    assert product == [PIN["commit"]], f"requirements-local.txt installs the product at {product}, the pin is {PIN['commit']}"
    assert core == [PIN["core"]["tag"]], f"requirements-local.txt installs the library at {core}, the pin is {PIN['core']['tag']}"


def _direct_url(name):
    try:
        raw = importlib.metadata.distribution(name).read_text("direct_url.json")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip(f"{name} is not installed in this environment")
    return json.loads(raw) if raw else None


def test_the_installed_product_distribution_is_at_the_pin():
    info = _direct_url("gsj-web")
    assert info is not None, "gsj-web is not a direct (git) install"
    vcs = info.get("vcs_info") or {}
    assert vcs.get("commit_id") == PIN["commit"], \
        f"installed gsj-web is at {vcs.get('commit_id', '?')[:12]}, the pin is {PIN['commit'][:12]}"


def test_the_installed_library_is_at_the_core_tag_the_product_ships():
    info = _direct_url("gsj")
    assert info is not None, "gsj is not a direct (git) install"
    vcs = info.get("vcs_info") or {}
    assert vcs.get("requested_revision") == PIN["core"]["tag"], \
        f"installed gsj was requested at {vcs.get('requested_revision')!r}, not {PIN['core']['tag']!r}"


@needs_web
def test_the_pinned_git_objects_match_the_record():
    assert tree("chart") == PIN["chart"]["tree"], "the chart tree at the pinned commit differs from web-pin.json"
    assert tree("gsj_deploy") == PIN["gsj_deploy"]["tree"], "the gsj_deploy tree at the pinned commit differs from web-pin.json"
    assert webpin.chart_version(PIN) == PIN["chart"]["version"]
    assert webpin.core_tag(PIN) == PIN["core"]["tag"], "the product's own requirements-local.txt names another library tag"


@needs_web
@needs_helm
def test_the_pinned_chart_packages_to_the_recorded_digest():
    """build.py embeds the chart as a normalized package; the digest it
    refuses to build without is the one recorded here. FALSIFY: change any
    chart file at the pin -> the tree AND this digest move."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("gsj_installer_builder", ROOT / "ops/installer/build.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    data = builder.normalized_chart(chart(), PIN["chart"]["version"])
    assert hashlib.sha256(data).hexdigest() == PIN["chart"]["sha256"]


@needs_web
def test_the_contract_document_is_identical_in_both_repositories():
    """The installer and the chart share a wide contract, documented once and
    carried in both repositories byte for byte: ops/installer/CONTRACT.md here,
    chart/INSTALLER-CONTRACT.md in the product. A change to either without
    the other is visible here."""
    ours = (ROOT / "ops/installer/CONTRACT.md").read_bytes()
    theirs = show("chart/INSTALLER-CONTRACT.md")
    assert hashlib.sha256(ours).hexdigest() == hashlib.sha256(theirs).hexdigest(), \
        "ops/installer/CONTRACT.md and the pinned chart/INSTALLER-CONTRACT.md differ"
