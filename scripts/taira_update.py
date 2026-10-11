#!/usr/bin/env python3
"""Install completed Taira artifacts while preserving the current ledger and custody.

Requires completed maintained preparation and an owner-public deployment record.
--plan-only contacts no host. The default command
requires previously prepared same-release daemon, CLI and Kagami and executes
the reviewed guest controller. --prepare-artifacts creates those exact binaries
via native cat/SSH before the reviewed update. No secret files are read. Failed attempts are never overwritten.
An explicit --failed-start-chain authenticates every failed startup since the
completed deployment. Unchanged binaries can be retried in a fresh operation.
Both pinned guest and Mac backing routes are required. Storage admission runs
before transfers and again before apply; no cleanup or alternate route is inferred.
--bind-backing-storage authors a fresh local deployment record from an explicit
pinned Mac SSH route and VM backing directory; it contacts no host.
--observe-installation captures a v2 initial cohort without stopping validators.
--installed-observation binds that actual capture for the first preserved-state
update; it makes no claim that an earlier update or checkpoint receipt exists.
--retained-renderer selects an explicit public renderer source whose exact digest
must equal the unchanged deployment and predecessor pins, independently of this
controller checkout. The new plan retains that source path and rechecks it at apply.
"""
import argparse
import contextlib
import fcntl
from urllib.parse import urlsplit
import taira_retry as retry
from taira_update_guest import (COHORT_MAX_TIMEOUT_SECONDS, MAX_FAILED_START_ATTEMPTS,
                                reject_retired_worker_plan, validate_update_plan_shape)
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
GUEST_OPERATION_TIMEOUT_SECONDS = COHORT_MAX_TIMEOUT_SECONDS + 60 * 60 + MAX_FAILED_START_ATTEMPTS * 4 * 20
GUEST_PROGRESS_SECONDS = 30


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def guest_progress(output, started, status, **fields):
    """Report only phase, elapsed time and the owner-private evidence path."""
    value = {'phase':'guest-apply', 'status':status,
             'elapsed_seconds':round(time.monotonic() - started, 3),
             'private_log':str(output), **fields}
    try:
        print(json.dumps(value, sort_keys=True), file=sys.stderr, flush=True)
    except (BrokenPipeError, OSError):
        # A disconnected observer must not stop an already submitted update.
        pass


@contextlib.contextmanager
def guest_update_heartbeat(output, started):
    stopped = threading.Event()
    guest_progress(output, started, 'started')

    def heartbeat():
        while not stopped.wait(GUEST_PROGRESS_SECONDS):
            guest_progress(output, started, 'running')

    watcher = threading.Thread(target=heartbeat, daemon=True)
    watcher.start()
    try:
        yield
    finally:
        stopped.set()
        watcher.join(timeout=1)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_public(path):
    return retry.public_record(path)


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def validate_deployment(value):
    """Admit one explicit owner-public first-release Taira installation."""
    modern = value.get('schema') == 'taira.runtime-deployment.v2'
    need(set(value) == {'schema', 'guest_ssh', 'backing_ssh', 'backing_path',
         'runtime_root', 'state_root', 'config_root',
         'config_release', 'genesis_manifest', 'network_id', 'public_origin', 'roles',
         'ports', 'replay_floor', 'renderer_sha256', 'current'}
         | ({'config_filename', 'kura_hash_journal'} if modern else set()), 'deployment fields differ')
    need(modern or value['schema'] == 'taira.runtime-deployment.v1', 'deployment schema differs')
    if modern:
        need(value['config_filename'] in ('config.toml', 'beacon.toml'), 'unsupported retained config name')
        need(value['kura_hash_journal'] in ('storage/blocks/canonical/blocks.hashes',
                                           'storage/kura/blocks/canonical/blocks.hashes'),
             'explicit canonical Kura hash journal required')
    for key in ('runtime_root', 'state_root', 'config_root', 'genesis_manifest', 'backing_path'):
        raw = value[key]
        need(isinstance(raw, str) and raw.startswith('/') and str(Path(os.path.normpath(raw))) == raw
             and not re.search(r'[\x00-\x1f\x7f]', raw), 'invalid public runtime path')
    need(re.fullmatch('[0-9a-f]{40}', value['config_release']) is not None,
         'exact retained config release required')
    need(isinstance(value['network_id'], str) and value['network_id'].startswith('hash:'),
         'exact retained NetworkId required')
    origin = urlsplit(value['public_origin'])
    need(origin.scheme == 'https' and origin.hostname and not origin.username and not origin.password
         and not origin.query and not origin.fragment and not origin.path,
         'canonical public HTTPS origin required')
    need(value['roles'] == [f'taira-validator-{i}' for i in range(1,5)]
         and len(value['ports']) == 4 and len(set(value['ports'])) == 4
         and all(type(port) is int and 1 <= port <= 65535 for port in value['ports']),
         'exact four-validator Taira layout required')
    need(type(value['replay_floor']) is int and value['replay_floor'] > 0,
         'explicit retained replay floor required')
    current = value['current']
    if modern and current.get('kind') == 'observed-installation':
        need(set(current) == {'kind', 'commit', 'daemons'}
             and re.fullmatch('[0-9a-f]{40}', current['commit'])
             and set(current['daemons']) == set(value['roles']), 'observed installation fields differ')
        for role, row in current['daemons'].items():
            need(set(row) == {'command', 'resolved', 'sha256', 'size'}
                 and row['command'] == str(Path(value['config_root']) / role / 'current/bin/iroha3d_taira')
                 and row['resolved'] == str(Path(value['config_root']) / role / 'releases'
                                           / value['config_release'] / 'bin/iroha3d_taira')
                 and re.fullmatch('[0-9a-f]{64}', row['sha256'])
                 and type(row['size']) is int and 1_000_000 < row['size'] < 1024**3,
                 'observed per-role daemon identity differs')
        need(re.fullmatch('[0-9a-f]{64}', value['renderer_sha256']), 'renderer digest missing')
        retry.validate_ssh(value['guest_ssh']); retry.validate_ssh(value['backing_ssh'])
        return value
    if modern:
        need(current.get('kind') == 'completed-update', 'v2 requires an explicit predecessor kind')
    need(set(current) == {'commit', 'daemon', 'attempt_name', 'plan_schema', 'result_schema',
                         'local_plan', 'local_plan_sha256'} | ({'kind'} if modern else set()),
         'current installation fields differ')
    need(re.fullmatch('[0-9a-f]{40}', current['commit']) is not None
         and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}', current['attempt_name']) is not None,
         'exact current installation required')
    daemon = Path(current['daemon'])
    need(daemon.is_absolute() and daemon.is_relative_to(Path(value['runtime_root']))
         and '..' not in daemon.parts, 'current daemon escapes approved runtime root')
    for key in ('plan_schema', 'result_schema'):
        need(isinstance(current[key], str) and re.fullmatch(r'taira\.[a-z0-9.-]+\.v[12]', current[key])
             and (modern or current[key].endswith('.v1')),
             'explicit retained receipt schema required')
    for digest in (value['renderer_sha256'], current['local_plan_sha256']):
        need(re.fullmatch('[0-9a-f]{64}', digest) is not None, 'public evidence digest missing')
    retry.validate_ssh(value['guest_ssh'])
    retry.validate_ssh(value['backing_ssh'])
    return value



def bind_backing_storage(args):
    """Author the required backing binding locally without altering its source record."""
    raw = read_public(args.deployment)
    value = retry.decode(raw)
    need(isinstance(value, dict) and 'backing_ssh' not in value and 'backing_path' not in value,
         'backing authoring requires an unbound source; partial or existing bindings are refused')
    value.update(backing_ssh=retry.decode(read_public(args.backing_route)),
                 backing_path=args.backing_path)
    validate_deployment(value)
    parent = args.output.parent
    info = parent.lstat()
    need(args.output.is_absolute() and parent.resolve() == parent and stat.S_ISDIR(info.st_mode)
         and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
         'fresh output below owner-private directory required')
    # Exclusive publication also refuses the source path and existing/symlink outputs.
    write_new(args.output, (json.dumps(value, sort_keys=True) + '\n').encode())
    print(json.dumps({'deployment': str(args.output), 'source_sha256': sha(raw),
                      'host_contacted': False, 'runtime_mutated': False}))


def validate_build(build, commit):
    need(re.fullmatch('[0-9a-f]{40}', commit) is not None and commit != '0' * 40,
         'exact approved source commit required')
    need(build.get('commit') == commit and build.get('target') == 'aarch64-unknown-linux-gnu'
         and build.get('profile') == 'release' and build.get('jobs') == 6
         and build.get('source_unchanged') is True and build.get('toolchain_unchanged') is True
         and build.get('deployed') is False and build.get('release_qualified') is False
         and build.get('native_check_scope') in ('build-only', 'basic', 'full') and 'exit_code' not in build,
         'completed maintained preparation required')
    rows = build.get('artifacts', [])
    need(len(rows) == 4 and {row.get('name') for row in rows}
         == {'iroha3d_taira', 'iroha', 'kagami', 'sorafs-node'}, 'maintained four-artifact result required')
    selected = []
    for name, package in [('iroha3d_taira', 'irohad'), ('iroha', 'iroha_cli'),
                          ('kagami', 'iroha_kagami')]:
        artifact = next(row for row in rows if row['name'] == name)
        need(artifact.get('package') == package and re.fullmatch('[0-9a-f]{64}', artifact.get('sha256', ''))
             and type(artifact.get('size')) is int and 1_000_000 < artifact['size'] < 1024 ** 3,
             'invalid candidate artifact identity: ' + name)
        selected.append(artifact)
    return selected


def failed_start_inputs(reference, deployment, prior, guest, operation, candidate):
    """Resolve a complete ancestry of digest-bound public failed-attempt records."""
    budget = guest.FailedStartRecordBudget()

    def read_ref(ref):
        raw = retry.public_record(ref['path'], ref['sha256'])
        budget.consume(raw)
        return retry.decode(raw)

    def load_attempt(ref):
        failed = read_ref(ref['plan'])
        records = {name: read_ref(value) for name, value in ref['records'].items()}
        return failed, records

    installed, entries = guest.validate_failed_start_chain(
        reference, deployment, prior, operation, load_attempt, candidate=candidate)
    return dict(reference, installed=installed), entries[-1][0]


def make_plan(build, deployment, prior, guest, operation, failed_start=None, *, retained_renderer=None):
    reject_retired_worker_plan(prior)
    commit = build['commit']
    artifacts = validate_build(build, commit)
    current = deployment['current']
    initial = current.get('kind') == 'observed-installation'
    modern = deployment['schema'] == 'taira.runtime-deployment.v2'
    need(not (modern and failed_start is not None),
         'v2 failed starts require explicit reconciliation; v1 lineage is not reused')
    need(commit != current['commit'], 'candidate is already the current runtime')
    need(re.fullmatch('update-[0-9a-f]{32}', operation), 'invalid operation directory')
    need(operation != current.get('attempt_name'), 'fresh operation directory required')
    if initial:
        need(failed_start is None, 'first adoption does not reinterpret a failed startup as an observation')
        guest.validate_installation_observation(prior, deployment)
    else:
        need(prior.get('schema') == current['plan_schema'] and prior.get('commit') == current['commit']
             and prior.get('network_id') == deployment['network_id'], 'installed predecessor plan differs')
    renderer = Path(retained_renderer) if retained_renderer is not None else ROOT / 'scripts/taira_validator_unit.py'
    need(renderer.is_absolute() and str(renderer) == os.path.normpath(str(renderer)),
         'retained renderer requires an absolute canonical source path')
    need(sha(read_public(renderer)) == deployment['renderer_sha256']
         == prior['renderer_sha256'], 'reviewed custody renderer changed')
    need([row['role'] for row in prior['units']] == deployment['roles'], 'predecessor cohort differs')
    value = {'schema':'taira.daemon-update.plan.v2' if modern else 'taira.daemon-update.plan.v1', 'commit':commit,
             'network_id':deployment['network_id'], 'artifacts':artifacts,
             'operation':operation, 'deployment':deployment}
    if retained_renderer is not None:
        value['retained_renderer_path'] = str(renderer)
    installed_plan = prior
    if failed_start is not None:
        value['failed_start'], installed_plan = failed_start_inputs(
            failed_start, deployment, prior, guest, operation, value)
    guest.validate_candidate_transition(commit, artifacts, current['commit'], installed_plan)
    guest.configure(value)
    units = []
    for row in installed_plan['units']:
        installed = row['installed' if initial else 'after']
        raw = base64.b64decode(installed, validate=True)
        need(sha(raw) == row['installed_sha256' if initial else 'after_sha256'],
             'installed predecessor unit digest differs')
        after = guest.replace_daemon(raw, row['role'])
        units.append({'role':row['role'], 'before':installed, 'after':base64.b64encode(after).decode(),
                      'before_sha256':sha(raw), 'after_sha256':sha(after)})
    predecessor = ({'schema':'taira.observed-installation-predecessor.v1', 'observation':prior,
                    'observation_sha256':sha(json.dumps(prior, sort_keys=True, separators=(',', ':')).encode())}
                   if initial else {'attempt_name':current['attempt_name'],
                    'intent_sha256':sha(json.dumps(prior, sort_keys=True, separators=(',', ':')).encode())})
    value.update(units=units, retained_predecessor=predecessor,
        guest_sha256=sha(read_public(HERE / 'taira_update_guest.py')),
        capacity_sha256=sha(read_public(HERE / 'taira_disk_capacity.py')),
        runner_sha256=sha(read_public(HERE / 'taira_update.py')),
        renderer_sha256=deployment['renderer_sha256'], secret_contents_read=False,
        transaction_submission=False,
        python_transaction_submission=False)
    validate_update_plan_shape(value)
    return value


def release_name(plan):
    """Keep every operation's staging independent, including the same candidate."""
    return 'release-' + plan['commit'] + '-' + plan['operation']


def successor_deployment(plan, raw, output):
    """Publish the exact installed operation as the next update's predecessor."""
    successor = json.loads(json.dumps(plan['deployment']))
    successor['current'] = {'commit':plan['commit'],
        'daemon':str(Path(successor['runtime_root']) / release_name(plan) / 'bin/iroha3d_taira'),
        'attempt_name':plan['operation'], 'plan_schema':'taira.daemon-update.plan.v1',
        'result_schema':'taira.daemon-update.result.v1',
        'local_plan':str(output / 'plan.json'), 'local_plan_sha256':sha(raw)}
    if successor['schema'] == 'taira.runtime-deployment.v2':
        successor['current'].update(kind='completed-update', plan_schema='taira.daemon-update.plan.v2',
                                    result_schema='taira.daemon-update.result.v2')
    return successor


def transfer_code(name, create_release, plan, admission):
    need(name in ('iroha3d_taira', 'iroha', 'kagami'), 'unexpected transfer artifact')
    source = capacity_source(plan)
    need(admission['operation'] == plan['operation'] and admission['commit'] == plan['commit']
         and admission['phase'] == 'prepare' and admission['capacity_sha256'] == plan['capacity_sha256'],
         'artifact storage admission differs')
    # Earlier successful transfers already consume their allocation. Keep every
    # remaining artifact and all evidence/reserve charges until its own write.
    earlier = ('iroha3d_taira', 'iroha', 'kagami')[:('iroha3d_taira', 'iroha', 'kagami').index(name)]
    guest_plan = dict(admission['guest_plan'], allocations=[row for row in admission['guest_plan']['allocations']
                      if row['label'] not in {'candidate artifact ' + item for item in earlier}])
    # stdin is inherited directly from the local artifact descriptor. Python
    # controls descriptors/paths only; /bin/cat owns the binary stream.
    return f'''
import os,stat,fcntl,base64,hashlib
from pathlib import Path
base=Path({plan['deployment']['runtime_root']!r})
assert os.geteuid()==0 and base.resolve()==base
for ancestor in [base,*base.parents]:
 s=ancestor.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
state=Path('/var/lib/taira-deployment')
for ancestor in state.parents:
 s=ancestor.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
s=state.lstat();assert state.resolve()==state and stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
lock_path=state/'.deployment.lock'
lock=os.open(lock_path,os.O_RDWR|os.O_NOFOLLOW)
s=os.fstat(lock);assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
t=lock_path.lstat();assert (s.st_dev,s.st_ino)==(t.st_dev,t.st_ino)
assert not os.path.lexists(state/'.reset-owner.json')
assert not os.path.lexists('/var/lib/taira-epoch-supervisor'),'retired epoch worker state must be reconciled before update'
assert not os.path.lexists('/etc/systemd/system/iroha-taira-epoch-supervisor.service'),'retired epoch worker service must be reconciled before update'
capacity_source=base64.b64decode({base64.b64encode(source).decode()!r},validate=True)
assert hashlib.sha256(capacity_source).hexdigest()=={plan['capacity_sha256']!r}
capacity={{'__name__':'taira_update_capacity'}}
exec(compile(capacity_source,'<maintained-taira-capacity>','exec'),capacity)
for path,expected in {admission['guest_filesystems']!r}.items():
 observed=capacity['inspect_filesystem'](Path(path))
 assert observed['device']==expected['device'] and observed['fragment_bytes']==expected['fragment_bytes'],'guest storage filesystem changed'
observed=capacity['evaluate']({guest_plan!r})
assert observed['passed'],'insufficient guest capacity before artifact transfer: '+'; '.join(observed['errors'])
os.set_inheritable(lock,True)
release=base/{release_name(plan)!r}
bins=release/'bin'
if {create_release!r}:
 release.mkdir(mode=0o700);bins.mkdir(mode=0o700)
else:
 for p in (release,bins):
  s=p.lstat();assert p.resolve()==p and stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
fd=os.open(bins/{name!r},os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)
os.fchmod(fd,0o755)
os.dup2(fd,1);os.close(fd)
os.execv('/bin/cat',['/bin/cat'])
'''


def artifact_transfer_argv(approved, remote_transfer):
    need(approved[0] == '/usr/bin/ssh', 'qualified SSH executable differs')
    return [approved[0], '-C', *approved[1:-1], remote_transfer]


def retained_artifacts(artifacts):
    """Admit local immutable producer outputs without reading binary bodies."""
    retained = []
    for artifact in artifacts:
        path = Path(artifact['path'])
        info = path.lstat()
        need(path.resolve() == path and stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
             and info.st_nlink == 1 and not info.st_mode & 0o222 and info.st_size == artifact['size'],
             'candidate must be the retained read-only build artifact')
        digest = subprocess.check_output(['/usr/bin/shasum', '-a', '256', str(path)], text=True).split()[0]
        need(digest == artifact['sha256'], 'retained candidate artifact differs')
        retained.append((artifact, path))
    return retained


def verify_prepared_remote(plan, argv, output):
    source = read_public(HERE / 'taira_update_guest.py')
    payload = source + b'\nverify_prepared_artifacts(' + repr(plan).encode() + b')\n'
    with (output / 'prepared-artifacts.stdout.json').open('xb') as out, \
         (output / 'prepared-artifacts.stderr').open('xb') as err:
        result = subprocess.run(argv, input=payload, stdout=out, stderr=err, timeout=300)
    need(result.returncode == 0, 'preprovisioned candidate verification failed; no missing-file fallback')
    report = retry.decode(read_public(output / 'prepared-artifacts.stdout.json'))
    need(report == {'schema': 'taira.prepared-update-artifacts.v1',
        'operation': plan['operation'], 'commit': plan['commit'],
        'artifacts': plan['artifacts'], 'runtime_mutated': False},
        'native prepared artifact verification receipt differs')
    return report


def capacity_source(plan):
    source = read_public(HERE / 'taira_disk_capacity.py')
    need(sha(source) == plan['capacity_sha256'], 'reviewed capacity checker changed')
    return source


def storage_remote(route, payload, output, name):
    """Retain bounded, metadata-only capacity observations on the exact pinned route."""
    argv = retry.validate_ssh(route)
    with (output / (name + '.stdout.json')).open('xb') as out, \
         (output / (name + '.stderr')).open('xb') as err:
        result = subprocess.run(argv, input=payload, stdout=out, stderr=err, timeout=60)
    need(result.returncode == 0, name + ' failed; no transfer or runtime mutation admitted')
    return retry.decode(read_public(output / (name + '.stdout.json')))


def admit_storage(plan, phase, output):
    """Check the Mac first, then charge the guest's actual filesystem allocation plan."""
    source = capacity_source(plan)
    deployment = plan['deployment']
    guest = module(HERE / 'taira_update_guest.py', 'update_storage_admission')
    sizes = sum(row[3] for row in guest.artifact_identity(plan['artifacts'])) if phase == 'prepare' else 0
    def backing(required, name):
        allocation = {'schema': 'taira.disk-capacity.plan.v1', 'allocations': [
            {'path': deployment['backing_path'], 'label': 'guest allocation including reserve',
             'bytes': required, 'inodes': 1},
            {'path': deployment['backing_path'], 'label': 'Mac physical backing headroom',
             'bytes': 2 * 1024**3, 'inodes': 1024}]}
        payload = retry.remote_payload(source, 'evaluate', allocation, print_result=True)
        payload = (b'import sys,os,stat\nassert sys.platform == "darwin", "backing capacity requires the approved Mac host"\n'
                   + ('assert stat.S_ISDIR(os.lstat(' + repr(deployment['backing_path'])
                      + ').st_mode), "explicit Mac backing directory is absent or not a directory"\n').encode()
                   + payload)
        result = storage_remote(deployment['backing_ssh'], payload, output, name)
        need(result.get('schema') == 'taira.disk-capacity.result.v1'
             and result.get('passed') is True and result.get('errors') == [],
             'insufficient Mac physical backing capacity before ' + phase)
    # This preliminary floor is deliberately not the full admission. It reports
    # a full Mac even when its sparse guest can no longer complete an SSH handshake.
    backing(sizes + 64 * 1024**2 + 2 * 1024**3, 'backing-capacity-before-' + phase)
    guest_source = read_public(HERE / 'taira_update_guest.py')
    need(sha(guest_source) == plan['guest_sha256'], 'reviewed guest controller changed')
    request = dict(plan=plan, phase=phase, capacity_source=base64.b64encode(source).decode())
    payload = guest_source + b'\nstorage_capacity_locked(' + repr(request).encode() + b')\n'
    admission = storage_remote(deployment['guest_ssh'], payload, output, 'guest-capacity-' + phase)
    need(admission.get('schema') == 'taira.update-storage-admission.v1'
         and admission.get('operation') == plan['operation'] and admission.get('commit') == plan['commit']
         and admission.get('phase') == phase and admission.get('capacity_sha256') == plan['capacity_sha256']
         and admission.get('guest_capacity', {}).get('passed') is True,
         'guest storage admission differs from the exact update')
    # The checker owns grouping by actual filesystem, including one reserve per
    # device. Existing files are already charged; only new allocation is added.
    required = sum(row['bytes'] for row in admission['guest_plan']['allocations'])
    need(type(required) is int and required >= sizes + 64 * 1024**2 + 2 * 1024**3,
         'guest storage admission omitted required allocation')
    backing(required, 'backing-capacity-' + phase)
    return admission


def prepare_artifacts(args, deployment, build_raw):
    """Explicit create-new artifact phase before the reviewed runtime update."""
    build = retry.decode(build_raw)
    artifacts = validate_build(build, build['commit'])
    need(re.fullmatch('update-[0-9a-f]{32}', args.operation)
         and args.operation != deployment['current'].get('attempt_name')
         and build['commit'] != deployment['current']['commit'], 'fresh candidate operation required')
    need(not args.output.exists(), 'fresh artifact preparation output required')
    plan = {'schema': 'taira.update-artifact-preparation.v1', 'operation': args.operation,
        'commit': build['commit'], 'deployment': deployment, 'artifacts': artifacts,
        'build_result_path': str(args.prepared_result), 'build_result_sha256': sha(build_raw),
        'runner_sha256': sha(read_public(HERE / 'taira_update.py')),
        'capacity_sha256': sha(read_public(HERE / 'taira_disk_capacity.py')),
        'guest_sha256': sha(read_public(HERE / 'taira_update_guest.py'))}
    retained = retained_artifacts(artifacts)
    argv = retry.validate_ssh(deployment['guest_ssh'])
    args.output.mkdir(mode=0o700)
    write_new(args.output / 'artifact-preparation.json', (json.dumps(plan, sort_keys=True) + '\n').encode())
    admission = admit_storage(plan, 'prepare', args.output)
    for index, (artifact, path) in enumerate(retained):
        remote = shlex.join(['/usr/bin/python3', '-I', '-c', transfer_code(artifact['name'], index == 0, plan, admission)])
        with path.open('rb') as source, (args.output / (artifact['name'] + '-transfer.stderr')).open('xb') as error:
            result = subprocess.run(artifact_transfer_argv(argv, remote), stdin=source,
                stdout=subprocess.DEVNULL, stderr=error, timeout=300)
        need(result.returncode == 0, 'native artifact preparation failed; retain partial release for inspection')
        write_new(args.output / (artifact['name'] + '-transfer.json'),
            json.dumps({'exit_code': 0, 'name': artifact['name'], 'size': artifact['size']}).encode())
    report = verify_prepared_remote(plan, argv, args.output)
    print(json.dumps(report | {'next_action': 'review the update plan for the prepared candidate artifacts'}))


def apply_plan(args):
    raw = read_public(args.plan)
    need(sha(raw) == args.plan_sha256, 'reviewed plan digest differs')
    plan = json.loads(raw)
    reject_retired_worker_plan(plan)
    validate_update_plan_shape(plan)
    validate_deployment(plan['deployment'])
    build_raw = read_public(Path(plan['build_result_path']))
    need(sha(build_raw) == plan['build_result_sha256'], 'bound preparation result changed')
    need(validate_build(json.loads(build_raw), plan['commit']) == plan['artifacts'],
         'plan artifacts differ from the bound completed preparation')
    for name, field in [('taira_update_guest.py', 'guest_sha256'), ('taira_update.py', 'runner_sha256'),
                        ('taira_disk_capacity.py', 'capacity_sha256')]:
        need(sha(read_public(HERE / name)) == plan[field], 'reviewed coordinator source changed')
    renderer = Path(plan.get('retained_renderer_path', ROOT / 'scripts/taira_validator_unit.py'))
    need(sha(read_public(renderer)) == plan['renderer_sha256'],
         'reviewed custody renderer changed')
    if 'failed_start' in plan:
        current = plan['deployment']['current']
        prior = retry.decode(retry.public_record(current['local_plan'], current['local_plan_sha256']))
        guest = module(HERE / 'taira_update_guest.py', 'runtime_update_recovery_validation')
        reference = {key: value for key, value in plan['failed_start'].items() if key != 'installed'}
        rebound = make_plan(json.loads(build_raw), plan['deployment'], prior, guest,
                            plan['operation'], reference,
                            retained_renderer=plan.get('retained_renderer_path'))
        need(rebound['failed_start'] == plan['failed_start'] and rebound['units'] == plan['units']
             and rebound['retained_predecessor'] == plan['retained_predecessor'],
             'failed-start recovery plan differs from its public inputs')
    need(args.output.is_absolute() and args.output.parent.resolve() == args.output.parent
         and not args.output.exists(), 'fresh absolute local output required')
    argv = retry.validate_ssh(plan['deployment']['guest_ssh'])
    artifacts = plan['artifacts']
    need([row['name'] for row in artifacts] == ['iroha3d_taira', 'iroha', 'kagami'],
         'exact same-release daemon, CLI and Kagami required')
    retained_artifacts(artifacts)
    args.output.mkdir(mode=0o700)
    write_new(args.output / 'plan.json', raw)
    admit_storage(plan, 'apply', args.output)
    verify_prepared_remote(plan, argv, args.output)
    guest_source = read_public(HERE / 'taira_update_guest.py')
    payload = guest_source + b'\napply_locked(' + repr(plan).encode() + b',' + repr(capacity_source(plan)).encode() + b')\n'
    started = time.monotonic()
    with (args.output / 'stdout.json').open('xb') as out, (args.output / 'stderr.log').open('xb') as err:
        os.fchmod(out.fileno(), 0o600)
        os.fchmod(err.fileno(), 0o600)
        # Bound the complete guest operation beyond its individual preflight,
        # stop/start and progress-bounded catch-up/final observation budgets.
        try:
            with guest_update_heartbeat(args.output, started):
                process = subprocess.run(argv, input=payload, stdout=out, stderr=err,
                                         timeout=GUEST_OPERATION_TIMEOUT_SECONDS)
        except Exception as error:
            guest_progress(args.output, started, 'failed', error_type=type(error).__name__)
            raise
    write_new(args.output / 'exit.json', json.dumps({'exit_code': process.returncode}).encode())
    if process.returncode != 0:
        guest_progress(args.output, started, 'failed', exit_code=process.returncode)
    need(process.returncode == 0, 'guest update failed; inspect owner-private attempt '
         + str(args.output) + ', never blindly reapply')
    result = json.loads(read_public(args.output / 'stdout.json'))
    need(result.get('runtime_update_complete') is True and result.get('commit') == plan['commit']
         and result.get('network_id') == plan['network_id']
         and result.get('canary_applied_verified') is False, 'guest result differs')
    successor = successor_deployment(plan, raw, args.output)
    retry.write_public(args.output / 'next-deployment.json', successor)
    print(json.dumps(result | {'next_deployment':str(args.output / 'next-deployment.json')}))


def observe_installation(args, deployment):
    """Capture the existing cohort through the pinned guest route, without a stop."""
    need(deployment['schema'] == 'taira.runtime-deployment.v2'
         and deployment['current']['kind'] == 'observed-installation',
         'initial observation requires an observed-installation deployment')
    need(not args.output.exists(), 'fresh observation output directory required')
    args.output.mkdir(mode=0o700)
    source = read_public(HERE / 'taira_update_guest.py')
    request = {'deployment':deployment, 'commit':deployment['current']['commit'],
               'operation':'observation-' + os.urandom(16).hex()}
    payload = source + b'\ncapture_installation(' + repr(request).encode() + b')\n'
    value = storage_remote(deployment['guest_ssh'], payload, args.output, 'installed-cohort')
    guest = module(HERE / 'taira_update_guest.py', 'runtime_update_observation_validation')
    guest.validate_installation_observation(value, deployment)
    retry.write_public(args.output / 'observation.json', value)
    print(json.dumps({'observation':str(args.output / 'observation.json'),
                      'runtime_mutated':False, 'secret_contents_read':False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment', type=Path, required=True)
    parser.add_argument('--prepared-result', type=Path)
    parser.add_argument('--retained-renderer', type=Path,
                        help='explicit public renderer source matching the unchanged deployment and predecessor digest pins')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--operation',
                        help='explicit fresh update-<32hex> operation identity')
    parser.add_argument('--prepare-artifacts', action='store_true',
                        help='create and verify the exact three candidate binaries before the reviewed runtime update')
    parser.add_argument('--plan-only', action='store_true', help='write the exact local plan without SSH')
    parser.add_argument('--observe-installation', action='store_true',
                        help='capture actual public units, native identity and private metadata for first adoption; no stop')
    parser.add_argument('--installed-observation', type=Path,
                        help='actual maintained first-adoption observation; never a prior update receipt')
    parser.add_argument('--failed-start-chain', type=Path,
                        help='ordered digest-bound failed attempts since the last completed deployment')
    parser.add_argument('--bind-backing-storage', action='store_true',
                        help='author a fresh local deployment record with the explicit Mac binding; no SSH')
    parser.add_argument('--backing-route', type=Path,
                        help='owner-public JSON containing the approved Mac SSH argv and exact host-key pins')
    parser.add_argument('--backing-path', help='canonical absolute Mac VM backing directory')
    args = parser.parse_args()
    if args.bind_backing_storage:
        need(args.backing_route is not None and args.backing_path is not None
             and args.prepared_result is None and args.operation is None
             and not args.prepare_artifacts
             and not args.observe_installation and args.installed_observation is None
             and not args.plan_only and args.failed_start_chain is None and args.retained_renderer is None,
             'backing authoring requires only deployment, backing-route, backing-path and fresh output')
    elif args.observe_installation:
        need(args.prepared_result is None and args.operation is None and not args.prepare_artifacts
             and not args.plan_only and args.failed_start_chain is None
             and args.installed_observation is None and args.backing_route is None and args.backing_path is None
             and args.retained_renderer is None,
             'initial observation is a separate read-only command')
    else:
        need(args.backing_route is None and args.backing_path is None
             and args.prepared_result is not None and args.operation is not None,
             'update requires prepared-result and operation; backing authoring is a separate local command')
    need(not args.prepare_artifacts or (not args.plan_only and args.failed_start_chain is None
                                       and args.retained_renderer is None),
         'prepare-artifacts is separate from plan-only and failed-start recovery')
    os.umask(0o077)
    need(subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip()
         == 'optimizations', 'only optimizations is allowed')
    if args.bind_backing_storage:
        bind_backing_storage(args)
        return
    deployment = validate_deployment(retry.decode(read_public(args.deployment)))
    parent = args.output.parent
    info = parent.lstat()
    need(args.output.is_absolute() and parent.resolve() == parent and stat.S_ISDIR(info.st_mode)
         and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
         'fresh output below owner-private directory required')
    if args.observe_installation:
        observe_installation(args, deployment)
        return
    lock = os.open(args.deployment.parent / '.taira-update.lock',
                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600, 'invalid local deployment lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        build_raw = read_public(args.prepared_result)
        if args.prepare_artifacts:
            prepare_artifacts(args, deployment, build_raw)
            return
        if deployment['current'].get('kind') == 'observed-installation':
            need(args.installed_observation is not None, 'first adoption requires an actual maintained observation')
            prior_raw = read_public(args.installed_observation)
        else:
            need(args.installed_observation is None, 'completed updates use their retained completion')
            prior_raw = retry.public_record(deployment['current']['local_plan'],
                                            deployment['current']['local_plan_sha256'])
        guest = module(HERE / 'taira_update_guest.py', 'runtime_update_guest')
        value = make_plan(retry.decode(build_raw), deployment, retry.decode(prior_raw), guest,
                          args.operation,
                          retry.decode(read_public(args.failed_start_chain))
                          if args.failed_start_chain is not None else None,
                          retained_renderer=args.retained_renderer)
        value.update(build_result_path=str(args.prepared_result), build_result_sha256=sha(build_raw))
        raw = (json.dumps(value, sort_keys=True)+'\n').encode()
        if args.plan_only:
            write_new(args.output, raw)
            print(json.dumps({'plan':str(args.output), 'host_contacted':False}))
        else:
            path = parent / (value['operation']+'.plan.json')
            write_new(path, raw)
            args.plan, args.plan_sha256 = path, sha(raw)
            apply_plan(args)
    finally:
        os.close(lock)


if __name__ == '__main__':
    main()
