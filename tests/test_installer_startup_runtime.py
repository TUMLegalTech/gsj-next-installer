"""Refuse to stop the original application while its importer is still working."""
import fcntl
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest
from gsj_deploy import corpus
from tests.test_installer_startup_source import ready_source

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT/'ops/installer/startup-runtime-preflight.py'
spec = importlib.util.spec_from_file_location('startup_preflight', PATH)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def test_actual_source_runtime_is_qualified_without_model_or_network():
    assert all(preflight.runtime_checks(corpus.installed_core_commit()).values())
    result = subprocess.run([sys.executable, '-B', str(PATH), corpus.installed_core_commit()], text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)['startup_complete'] is False


def test_complete_receipts_are_advisory_and_unchanged(ready_source):
    settings, _, _, checkpoint, *_ = ready_source
    current = checkpoint.parent/'current.json'; lock=checkpoint.parent/'writer.lock'
    before = {p:p.read_bytes() for p in (checkpoint,current,lock)}
    assert preflight.completed(settings)
    assert {p:p.read_bytes() for p in before} == before


@pytest.mark.parametrize('damage', ['incomplete','terminal','shard','current','missing_lock','symlink','wrong_core','different_generation'])
def test_incomplete_source_refused_before_any_scale_or_full_model_proof(ready_source,damage):
    settings, _, _, checkpoint, *_ = ready_source
    if damage in {'incomplete','terminal','shard'}:
        value=json.loads(checkpoint.read_text())
        if damage=='incomplete':value['phase']='indexing'
        elif damage=='terminal':value['terminal']=True
        else:next(iter(value['shards'].values()))['complete']=False
        checkpoint.write_text(json.dumps(value))
    elif damage=='current':(checkpoint.parent/'current.json').write_text('{}')
    elif damage=='missing_lock':(checkpoint.parent/'writer.lock').unlink()
    elif damage=='symlink':
        target=checkpoint.with_suffix('.other');checkpoint.rename(target);checkpoint.symlink_to(target)
    elif damage=='wrong_core':settings['core_commit']='0'*40
    else:settings['initializer']['repair_generation']+=1
    with pytest.raises((ValueError,FileNotFoundError)):
        preflight.completed(settings)


def test_active_initializer_lock_refuses_early_stop(ready_source):
    settings, _, _, checkpoint, *_ = ready_source
    with (checkpoint.parent/'writer.lock').open('rb') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):preflight.completed(settings)
