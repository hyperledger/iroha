"""Real file/tree custody with inert original archives; no native qualification.

Synthetic ABI/checksum JSON is only a request relation. No checker process,
addon, SDK assertions, npm installation or release success receipt is produced.
"""
from __future__ import annotations
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sorafs_javascript_parent_input as parent
import sorafs_javascript_input_files as files
import sorafs_javascript_installed as installed
import sorafs_javascript_qualification_source as qualification
from sorafs_javascript_archive import ArchiveError
from sorafs_javascript_package_fixtures import INSTALLED_MEMBERS, source_inputs, expected_files, archive_bytes, ROOT
from sorafs_javascript_dependencies_test import _originals
from sorafs_javascript_installed_test import hidden_lock

COMMIT, WORKSPACE, NATIVE_SOURCE = '1'*40, '2'*64, '3'*64
NATIVE = b'inert request relation only; never loaded as an addon'
CHECKSUM = json.dumps({'entries': {'darwin-arm64': {'source_git_revision': COMMIT,
    'source_tree_clean': True, 'source_tree_sha256': NATIVE_SOURCE,
    'sha256': hashlib.sha256(NATIVE).hexdigest(), 'build_execution_policy':'trusted-local-cargo-v1',
    'build_provenance_version':3, 'cargo_profile':'release'}}}).encode()


def _write(path, raw, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


@pytest.fixture(scope='module')
def originals():
    sources, _ = source_inputs()
    lock, dependencies = _originals()
    sources['package-lock.json'] = lock.raw
    package = archive_bytes(expected_files(sources, CHECKSUM))
    catalog = (ROOT/'scripts/fixtures/sorafs_javascript_qualification_sources_v1.json').read_bytes()
    names = json.loads(catalog)
    core = qualification.qualification_projection({name:(ROOT/name).read_bytes()
        for name in [r['path'] for r in names['source_files']]+names['fixture_files']},catalog=catalog)
    return package, sources, lock, dependencies, core


@pytest.fixture
def setup(tmp_path, originals):
    environment = tmp_path/'environment';environment.mkdir(mode=0o700)
    temporary = tmp_path/'temporary';temporary.mkdir(mode=0o700)
    native_root = tmp_path/'native';native_root.mkdir(mode=0o700)
    package, sources, lock, deps, core = originals
    projected = installed.installed_projection(package,sources=sources,checksum_manifest=CHECKSUM,
        lock=lock,dependency_originals=deps,npm_hidden_lock=hidden_lock(originals[:4]),
        environment_label=str(environment),sdk_archive_label=str(tmp_path/'originals/sdk.tgz'))
    for row in projected.members:_write(environment/'node_modules'/row.path,row.content,row.mode)
    for row in core.members:_write(environment/'qualification/core'/row.path,row.content)
    tool_originals = tmp_path/'tool-originals'
    for name,_ in parent.CHILD_TOOL_SHA256:
        raw = (ROOT/'scripts'/name).read_bytes()
        _write(tool_originals/name,raw)
        _write(environment/'qualification/tools'/name,raw)
    manifest = {'artifact_sha256':hashlib.sha256(NATIVE).hexdigest(),'artifact_size':len(NATIVE),
        'bridge_abi_version':31,'privacy_c_exports':[],'privacy_c_exports_inspected':False,
        'required_symbols':list(parent.native.REQUIRED_SYMBOLS['node']),
        'schema':parent.native.SCHEMA,'sdk':'node','source_commit':COMMIT,'source_tree_clean':True,
        'target':'darwin-arm64-node24','workspace_source_manifest_sha256':WORKSPACE}
    _write(native_root/'iroha_js_host.node',NATIVE)
    _write(native_root/'iroha_js_host.checksums.json',CHECKSUM)
    _write(native_root/'abi.json',parent.native.canonical_manifest_bytes(manifest),0o600)
    return dict(environment_root=environment, temporary_root=temporary,input_path=environment/'child-input.json',
        installed=projected,qualification=core,tools_source_root=tool_originals,
        native_path=native_root/'iroha_js_host.node',checksum_path=native_root/'iroha_js_host.checksums.json',
        abi_manifest_path=native_root/'abi.json',expected_source_commit=COMMIT,
        expected_workspace_sha256=WORKSPACE,expected_native_source_sha256=NATIVE_SOURCE,target='darwin-arm64-node24')


def test_original_relation_derives_canonical_child_bytes_and_retains_real_descriptors(setup):
    owner = parent.OriginalJavascriptChildInput(**setup)
    with pytest.raises(ArchiveError):owner.descriptor
    with owner:
        fd=owner.descriptor;raw=os.pread(fd,parent.MAX_INPUT_BYTES,0)
        assert raw == setup['input_path'].read_bytes()
        assert hashlib.sha256(raw).hexdigest()==owner.sha256
        value=json.loads(raw)
        assert raw==(json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'))+'\n').encode('ascii')
        assert len(value['source'])==191 and len(value['tools'])==8 and len(value['installed'])==INSTALLED_MEMBERS
        assert value['native']['sha256']==hashlib.sha256(NATIVE).hexdigest()
        assert value['native']['workspaceSourceTreeSha256']==WORKSPACE
        assert value['native']['nativeSourceTreeSha256']==NATIVE_SOURCE
        assert os.fstat(fd).st_mode&0o7777==0o600
        owner.recheck();assert owner.descriptor==fd
    with pytest.raises(OSError):os.fstat(fd)
    with pytest.raises(ArchiveError):owner.descriptor
    with pytest.raises(ArchiveError):owner.sha256
    with pytest.raises(ArchiveError):owner.recheck()
    with pytest.raises(ArchiveError):owner.__enter__()
    owner.close()
    assert setup['input_path'].read_bytes()==raw



@pytest.mark.parametrize('kind',('native','checksum','abi','source','installed','tools','tool_original','extra_core','extra_tools'))
def test_changed_original_or_copied_member_is_terminal(setup,kind):
    with pytest.raises(ArchiveError):
        with parent.OriginalJavascriptChildInput(**setup) as owner:
            paths={'native':setup['native_path'],'checksum':setup['checksum_path'],'abi':setup['abi_manifest_path'],
                'source':setup['environment_root']/'qualification/core/fixtures/sorafs_orchestrator/multi_peer_parity_v1/plan.json',
                'installed':setup['environment_root']/'node_modules/@noble/hashes/index.js',
                'tools':setup['environment_root']/'qualification/tools/sorafs_javascript_child.mjs',
                'tool_original':setup['tools_source_root']/'sorafs_javascript_child.mjs',
                'extra_core':setup['environment_root']/'qualification/core/selector.js',
                'extra_tools':setup['environment_root']/'qualification/tools/selector.mjs'}
            _write(paths[kind],b'substituted')
            with pytest.raises(ArchiveError):owner.recheck()
            with pytest.raises(ArchiveError):owner.descriptor
            owner.recheck()


@pytest.mark.parametrize('field,value',(('expected_source_commit','4'*40),('expected_workspace_sha256','4'*64),
    ('expected_native_source_sha256','4'*64),('target','darwin-arm64-node20'),('expected_workspace_sha256','0'*64)))
def test_independent_selection_cannot_be_relabelled(setup,field,value):
    setup[field]=value
    with pytest.raises(ArchiveError):
        with parent.OriginalJavascriptChildInput(**setup):pass
    assert not setup['input_path'].exists()


@pytest.mark.parametrize('kind',('existing_output','output_link','temporary_overlap','original_overlap','label','forged_projection','world_environment'))
def test_closed_physical_layout_and_real_projection_refuse_substitutes(setup,kind):
    if kind=='existing_output':_write(setup['input_path'],b'foreign',0o600)
    if kind=='output_link':setup['input_path'].symlink_to(setup['native_path'])
    if kind=='temporary_overlap':setup['temporary_root']=setup['environment_root']/'node_modules'
    if kind=='original_overlap':setup['abi_manifest_path']=setup['environment_root']/'qualification/core/abi.json'
    if kind=='label':setup['installed']=replace(setup['installed'],environment_label='/other/environment')
    if kind=='forged_projection':setup['installed']=replace(setup['installed'],members=setup['installed'].members[:-1])
    if kind=='world_environment':setup['environment_root'].chmod(0o755)
    with pytest.raises((ArchiveError,OSError)):
        with parent.OriginalJavascriptChildInput(**setup):pass
    if kind=='existing_output':assert setup['input_path'].read_bytes()==b'foreign'
    if kind=='output_link':assert setup['input_path'].is_symlink() and setup['native_path'].read_bytes()==NATIVE


def test_canonical_input_exact_bound_and_no_partial_output(setup,monkeypatch):
    document={'x':'\U0001f600'};raw=parent._canonical_input(document)
    monkeypatch.setattr(parent,'MAX_INPUT_BYTES',len(raw));assert parent._canonical_input(document)==raw
    monkeypatch.setattr(parent,'MAX_INPUT_BYTES',len(raw)-1)
    with pytest.raises(ArchiveError):parent._canonical_input(document)
    with pytest.raises(ArchiveError):
        with parent.OriginalJavascriptChildInput(**setup):pass
    assert not setup['input_path'].exists()


def test_constructor_never_runs_a_checker_or_native_process(setup,monkeypatch):
    def forbidden(*a,**k):raise AssertionError('input owner attempted qualification execution')
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    monkeypatch.setattr(parent.native,'verify_manifest',forbidden)
    monkeypatch.setattr(parent.native,'probe_artifact',forbidden)
    with parent.OriginalJavascriptChildInput(**setup) as owner:owner.recheck()


@pytest.mark.parametrize('mode',('close','swallowed_reentry','swallowed_property'))
def test_parent_cannot_complete_after_reentrant_or_closed_aggregate(setup,monkeypatch,mode):
    instance=parent.OriginalJavascriptChildInput(**setup);instance.__enter__()
    real=files.HeldInputFile.recheck;armed=True
    def checking(member):
        nonlocal armed
        real(member)
        if armed:
            armed=False
            if mode=='close':instance.close()
            elif mode=='swallowed_property':
                with pytest.raises(ArchiveError):instance.descriptor
            else:
                with pytest.raises(ArchiveError):instance.recheck()
    monkeypatch.setattr(files.HeldInputFile,'recheck',checking)
    try:
        with pytest.raises(ArchiveError):instance.recheck()
        with pytest.raises(ArchiveError):instance.descriptor
        with pytest.raises(ArchiveError):instance.recheck()
    finally:instance.close()


def test_aggregate_cleanup_drains_every_owner_and_never_retries_reused_output_fd(setup,monkeypatch):
    instance=parent.OriginalJavascriptChildInput(**setup);instance.__enter__()
    target=instance.descriptor;retained=[]
    for member in instance._owners:
        if isinstance(member,files.HeldInputFile):retained.extend((*member._parent[2],member.descriptor))
        elif isinstance(member,parent.OriginalTree):retained.extend(member._parent[2])
        else:retained.extend(member._parent[2])
    assert len(retained)==len(set(retained))
    foreign=setup['environment_root']/'foreign';foreign.write_bytes(b'foreign retained bytes')
    real=os.close;seen=[];reused=[];original=OSError('output was closed before failure')
    def closing(fd):
        seen.append(fd);real(fd)
        if fd==target:
            replacement=os.open(foreign,os.O_RDONLY);assert replacement==target;reused.append(replacement);raise original
    monkeypatch.setattr(os,'close',closing)
    with pytest.raises(ArchiveError) as caught:instance.close()
    assert caught.value.cleanup_errors[0].cleanup_errors==(original,)
    assert all(seen.count(fd)==1 for fd in retained)
    instance.close();assert all(seen.count(fd)==1 for fd in retained)
    assert os.pread(reused[0],64,0)==b'foreign retained bytes'
    real(reused[0])


def test_failed_output_write_retains_partial_file_and_original_error(setup,monkeypatch):
    real=os.write;original=KeyboardInterrupt('request construction interrupted');observed=[]
    def writing(fd,raw):
        if not observed:
            observed.append(fd);assert real(fd,raw[:7])==7;raise original
        return real(fd,raw)
    monkeypatch.setattr(os,'write',writing)
    with pytest.raises(KeyboardInterrupt) as caught:
        with parent.OriginalJavascriptChildInput(**setup):pass
    assert caught.value is original and setup['input_path'].read_bytes()==b'{"catal'
    with pytest.raises(OSError):os.fstat(observed[0])


def test_named_output_replacement_is_refused_and_never_unlinked(setup):
    instance=parent.OriginalJavascriptChildInput(**setup);instance.__enter__()
    saved=setup['input_path'].with_name('saved-input');setup['input_path'].rename(saved)
    setup['input_path'].write_bytes(b'foreign inode')
    try:
        with pytest.raises(ArchiveError):instance.recheck()
    finally:instance.close()
    assert setup['input_path'].read_bytes()==b'foreign inode' and saved.read_bytes().startswith(b'{"catalog"')


def test_tool_selection_is_fixed_reviewed_bytes_not_a_caller_hash(setup):
    tool=setup['tools_source_root']/'sorafs_javascript_child.mjs'
    tool.write_bytes(tool.read_bytes()+b'// foreign original\n')
    with pytest.raises(ArchiveError,match='fixed reviewed'):
        with parent.OriginalJavascriptChildInput(**setup):pass
    assert not setup['input_path'].exists()


def test_constituent_native_manifest_uses_the_sole_schema_without_execution(setup):
    value=json.loads(setup['abi_manifest_path'].read_bytes());value['required_symbols']=[]
    setup['abi_manifest_path'].write_text(json.dumps(value))
    with pytest.raises(parent.native.ArtifactContractError,match='required-symbol'):
        with parent.OriginalJavascriptChildInput(**setup):pass
    assert not setup['input_path'].exists()


def test_private_directory_policy_change_at_last_lineage_observation_is_refused(tmp_path,monkeypatch):
    directory=tmp_path/'private';directory.mkdir(mode=0o700)
    instance=parent._PrivateDirectory(directory);fd=instance._parent[0]
    real=os.fstat;count=0
    def observing(number):
        nonlocal count
        value=real(number)
        if number==fd:
            count+=1
            # First is root policy, next two are held lineage dev/ino reads.
            if count==3:directory.chmod(0o755)
        return value
    monkeypatch.setattr(os,'fstat',observing)
    try:
        with pytest.raises(ArchiveError,match='policy changed'):instance.recheck()
        assert count==4
        with pytest.raises(ArchiveError):instance.recheck()
    finally:instance.close()


@pytest.mark.parametrize("tool_name", (
    "sorafs_javascript_child.mjs", "sorafs_javascript_child_entry.mjs",
    "sorafs_javascript_child_files.mjs", "sorafs_javascript_child_input.mjs",
    "sorafs_javascript_child_loads.mjs", "sorafs_javascript_child_session.mjs",
    "sorafs_javascript_native_cache.mjs", "sorafs_javascript_test_events.mjs",
))
def test_every_fixed_child_original_refuses_resealed_copy_substitution(setup, tool_name):
    """Matching forged originals and copies cannot replace any selected tool."""
    original = setup["tools_source_root"] / tool_name
    copied = setup["environment_root"] / "qualification/tools" / tool_name
    assert original.read_bytes() == copied.read_bytes()
    changed = original.read_bytes() + b"\n// unreviewed matched tool substitution\n"
    original.write_bytes(changed)
    copied.write_bytes(changed)
    assert original.read_bytes() == copied.read_bytes() == changed
    with pytest.raises(ArchiveError, match="fixed reviewed"):
        with parent.OriginalJavascriptChildInput(**setup):
            raise AssertionError("unreviewed matched child tools were admitted")
    assert not setup["input_path"].exists()
