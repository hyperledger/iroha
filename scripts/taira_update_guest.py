#!/usr/bin/env python3
"""State-preserving Taira guest worker; invoked by taira_update.py only.

Python reads public units/status and metadata only. Retained file metadata binds
private configuration; the native daemon alone consumes config/key contents.
Native alone retires the exact obsolete zk.halo2 table; Python never reads or
rewrites config/key contents. No ledger removal, reset, or Python signing. Retired epoch
worker services and state are rejected without process or journal mutation.
Startup replay may expose a lower prefix; success still requires each retained
checkpoint and a fresh anchored quorum. Heights within one process never regress.
A prestart Native restore leaves validators paused and publishes actual restored
config metadata. It is not a healthy completion: a later update must reconcile
that receipt because atomic restoration can change the original config inode.
"""
import ast
import base64
import contextlib
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import time

# One isolated remote process serves one explicit deployment and operation.
SNAPSHOT_ARTIFACTS = {'snapshot.data', 'snapshot.sha256', 'snapshot.sig',
                      'snapshot.fast.norito', 'snapshot.merkle.json'}
FAILED_START_CHAIN_SCHEMA = 'taira.failed-start-chain.v1'
MAX_FAILED_START_ATTEMPTS = 16
MAX_FAILED_START_RECORD_BYTES = 8 * 1024 * 1024
MAX_FAILED_START_CHAIN_BYTES = 32 * 1024 * 1024
COHORT_STALL_TIMEOUT_SECONDS = 600
COHORT_MAX_TIMEOUT_SECONDS = 90 * 60
COHORT_OBSERVATION_SCHEMA = 'taira.cohort-observation-intent.v1'
COHORT_REMAINING_ACTIONS = ('observe_cohort', 'verify_strict_restore',
                          'observe_final_cohort', 'publish_completion_receipts')
FAILED_START_RECORDS = ('intent.json', 'before.json', 'checkpoint-stopped.json',
                      'start-intent.json', 'failure.json')
BOUND = False
DEPLOYMENT_LOCK_FD = None
CONFIG_RETIREMENT = None
RETIRED_WORKER_STATE = Path('/var/lib/taira-epoch-supervisor')
RETIRED_WORKER_UNIT = Path('/etc/systemd/system/iroha-taira-epoch-supervisor.service')


def reject_retired_worker_plan(plan):
    """Reject retired worker inputs instead of decoding or silently discarding them."""
    need(not any(key.startswith('epoch_supervisor') for key in plan),
         'retired epoch worker plan fields are not accepted')


def reject_retired_epoch_worker():
    """Fail closed on any old worker service or state, including dangling links."""
    need(not os.path.lexists(RETIRED_WORKER_STATE)
         and not os.path.lexists(RETIRED_WORKER_UNIT),
         'retired epoch worker service or state must be reconciled before update')


def configure(plan):
    """Bind deployment-owned public paths once, before any guest observation."""
    global BOUND, BASE, OLD, CANDIDATE_COMMIT, CONFIG_RELEASE, PREVIOUS_DAEMON, DAEMON, CLI, KAGAMI
    global ATTEMPT, NETWORK, ROLES, UNITS, REPLAY_BARRIER, PUBLIC_ORIGIN, CONFIG_RETIREMENT
    global STATE_ROOT, CONFIG_ROOT, GENESIS_MANIFEST, PORTS, PREDECESSOR, CONFIG_FILENAME, INITIAL_DAEMONS, KURA_HASH_JOURNAL
    need(not BOUND, 'one deployment per guest process')
    reject_retired_worker_plan(plan)
    deployment = plan['deployment']
    BASE = Path(deployment['runtime_root'])
    STATE_ROOT = Path(deployment['state_root'])
    CONFIG_ROOT = Path(deployment['config_root'])
    GENESIS_MANIFEST = Path(deployment['genesis_manifest'])
    CONFIG_RELEASE = deployment['config_release']
    CONFIG_FILENAME = deployment.get('config_filename', 'config.toml')
    KURA_HASH_JOURNAL = deployment.get('kura_hash_journal', 'storage/kura/blocks/canonical/blocks.hashes')
    need(KURA_HASH_JOURNAL in ('storage/blocks/canonical/blocks.hashes',
                              'storage/kura/blocks/canonical/blocks.hashes'),
         'explicit canonical Kura hash journal required')
    PREDECESSOR = deployment['current']
    installed = plan.get('failed_start', {}).get('installed', PREDECESSOR)
    OLD = installed['commit']
    CANDIDATE_COMMIT = plan['commit']
    INITIAL_DAEMONS = installed.get('daemons', {})
    PREVIOUS_DAEMON = Path(installed['daemon']) if not INITIAL_DAEMONS else None
    DAEMON = BASE / ('release-' + plan['commit'] + '-' + plan['operation']) / 'bin/iroha3d_taira'
    CLI = DAEMON.with_name('iroha')
    KAGAMI = DAEMON.with_name('kagami')
    ATTEMPT = BASE / plan['operation']
    NETWORK = deployment['network_id']
    ROLES = tuple(deployment['roles'])
    UNITS = tuple(f'iroha3d-{role}.service' for role in ROLES)
    PORTS = tuple(deployment['ports'])
    REPLAY_BARRIER = deployment['replay_floor']
    PUBLIC_ORIGIN = deployment['public_origin']
    CONFIG_RETIREMENT = None
    BOUND = True


ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/root', 'LC_ALL': 'C'}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def validate_update_plan_shape(plan):
    """Admit the sole update contract before dispatch or failed-start recovery."""
    required = {'schema', 'commit', 'network_id', 'artifacts', 'operation', 'deployment',
                'units', 'retained_predecessor', 'guest_sha256', 'capacity_sha256',
                'runner_sha256', 'renderer_sha256', 'secret_contents_read',
                'transaction_submission', 'python_transaction_submission'}
    optional = {'failed_start', 'build_result_path', 'build_result_sha256', 'retained_renderer_path'}
    need(isinstance(plan, dict) and required <= set(plan) <= required | optional,
         'update plan fields differ from the canonical contract')
    need(plan['schema'] in ('taira.daemon-update.plan.v1', 'taira.daemon-update.plan.v2')
         and ('build_result_path' in plan) == ('build_result_sha256' in plan)
         and all(plan[field] is False for field in
                 ('secret_contents_read', 'transaction_submission', 'python_transaction_submission')),
         'update plan schema or read-only custody claims differ')
    need((plan['schema'].endswith('.v2')) == (plan['deployment']['schema'] == 'taira.runtime-deployment.v2'),
         'update and deployment versions differ')
    need(not (plan['schema'].endswith('.v2') and 'failed_start' in plan),
         'v2 failed starts require explicit reconciliation; v1 lineage is not reused')
    if 'retained_renderer_path' in plan:
        value = plan['retained_renderer_path']
        need(isinstance(value, str) and value.startswith('/')
             and os.path.normpath(value) == value and not re.search(r'[\x00-\x1f\x7f]', value),
             'retained renderer requires an absolute canonical source path')


def load_capacity(plan, capacity_source):
    """Load only the source-bound maintained allocation evaluator."""
    need(hashlib.sha256(capacity_source).hexdigest() == plan['capacity_sha256'],
         'reviewed capacity checker changed')
    capacity = {'__name__': 'taira_update_capacity'}
    exec(compile(capacity_source, '<maintained-taira-capacity>', 'exec'), capacity)
    return capacity


def storage_capacity(plan, capacity_source, phase):
    """Observe every allocating guest filesystem through the maintained checker."""
    need(phase in ('prepare', 'apply'), 'unknown update storage phase')
    capacity = load_capacity(plan, capacity_source)
    identity = artifact_identity(plan['artifacts'])
    runtime = plan['deployment']['runtime_root']
    # Evidence allowances are explicit working budgets, not a promise that an
    # arbitrary service can run forever without consuming its filesystem reserve.
    requirements = [(runtime, 'update evidence and publication', 64 * 1024**2, 1024, 8)]
    if phase == 'prepare':
        requirements += [(runtime, 'candidate artifact ' + name, size, 1, 1)
                         for name, _, _, size in identity]
    else:
        units = sum(len(base64.b64decode(row['after'], validate=True)) for row in plan['units'])
        requirements += [
            ('/etc/systemd/system', 'unit publication and rollback', 2 * units, 10, 0),
            (plan['deployment']['state_root'], 'retained validator state', 0, 0, 0),
        ]
        if plan['schema'].endswith('.v2'):
            # Native bounds each of four configs at 1 MiB, with original, staged
            # and restore publications. No private contents are read for sizing.
            requirements.append((plan['deployment']['config_root'],
                                 'native config retirement and rollback', 12 * 1024**2, 12, 0))
    allocations, observations = [], {}
    for path, label, size, files, directories in requirements:
        if path not in observations:
            observations[path] = capacity['inspect_filesystem'](Path(path))
        observed = observations[path]
        bound = capacity['allocation_bound'](size, files, directories, observed['fragment_bytes'])
        allocations.append(dict(path=path, label=label, **bound))
    devices = set()
    for path, observed in observations.items():
        if observed['device'] not in devices:
            allocations.append(dict(path=path, label='guest filesystem headroom',
                                    bytes=2 * 1024**3, inodes=1024))
            devices.add(observed['device'])
    guest_plan = dict(schema=capacity['PLAN_SCHEMA'], allocations=allocations)
    result = capacity['evaluate'](guest_plan, inspect=capacity['inspect_filesystem'])
    need(result['passed'], 'insufficient guest capacity before ' + phase + ': ' + '; '.join(result['errors']))
    need({row['device'] for row in result['filesystems']} == devices,
         'guest allocation filesystems changed during admission')
    guest_filesystems = {}
    for path, observed in observations.items():
        current = capacity['inspect_filesystem'](Path(path))
        expected = {key: observed[key] for key in ('device', 'fragment_bytes')}
        need({key: current[key] for key in expected} == expected,
             'guest allocation path changed filesystem during admission')
        guest_filesystems[path] = expected
    return dict(schema='taira.update-storage-admission.v1', operation=plan['operation'],
                commit=plan['commit'], phase=phase, capacity_sha256=plan['capacity_sha256'],
                guest_plan=guest_plan, guest_capacity=result, guest_filesystems=guest_filesystems)


def storage_capacity_locked(request):
    """Return a metadata-only allocation observation under the existing update locks."""
    plan = request['plan']
    reject_retired_worker_plan(plan)
    with deployment_locks(plan):
        result = storage_capacity(plan, base64.b64decode(request['capacity_source'], validate=True),
                                  request['phase'])
    print(json.dumps(result), flush=True)


def validate_failed_start_inputs(deployment, baseline, failed, records, operation,
                                previous_plan, previous_installed):
    """Authenticate public failed-start lineage without inventing a completed runtime."""
    reject_retired_worker_plan(failed)
    reject_retired_worker_plan(baseline)
    validate_update_plan_shape(failed)
    current = deployment['current']
    roles = deployment['roles']
    units = [f'iroha3d-{role}.service' for role in roles]
    need(failed.get('schema') == 'taira.daemon-update.plan.v1'
         and failed.get('deployment') == deployment
         and failed.get('network_id') == deployment['network_id']
         and failed.get('renderer_sha256') == deployment['renderer_sha256'],
         'failed-start baseline or plan differs')
    commit, attempt = failed.get('commit', ''), failed.get('operation', '')
    need(re.fullmatch('[0-9a-f]{40}', commit) and commit != current['commit']
         and re.fullmatch('update-[0-9a-f]{32}', attempt) and attempt != operation
         and attempt != current['attempt_name'], 'failed-start source or operation differs')
    need(failed.get('retained_predecessor') == {
        'attempt_name': current['attempt_name'],
        'intent_sha256': hashlib.sha256(json.dumps(baseline, sort_keys=True,
                                                   separators=(',', ':')).encode()).hexdigest()},
        'failed-start completed predecessor proof differs')
    artifacts = failed.get('artifacts', [])
    need([row.get('name') for row in artifacts] == ['iroha3d_taira', 'iroha', 'kagami']
         and all(row.get('package') == package
                 and re.fullmatch('[0-9a-f]{64}', row.get('sha256', ''))
                 and type(row.get('size')) is int and 1_000_000 < row['size'] < 1024 ** 3
                 for row, package in zip(artifacts, ('irohad', 'iroha_cli', 'iroha_kagami'), strict=True)),
         'failed-start artifact identities differ')
    installed = {'commit': commit, 'attempt_name': attempt,
                 'daemon': str(Path(deployment['runtime_root']) /
                               ('release-' + commit + '-' + attempt) / 'bin/iroha3d_taira')}
    need([row.get('role') for row in failed.get('units', [])] == roles
         and [row.get('role') for row in baseline.get('units', [])] == roles,
         'failed-start unit cohort differs')
    for previous, row in zip(previous_plan['units'], failed['units'], strict=True):
        before = base64.b64decode(row['before'], validate=True)
        after = base64.b64decode(row['after'], validate=True)
        old = previous_installed['daemon'].encode()
        need(row['before'] == previous['after']
             and row['before_sha256'] == previous['after_sha256']
             and hashlib.sha256(before).hexdigest() == row['before_sha256']
             and hashlib.sha256(after).hexdigest() == row['after_sha256']
             and before.count(old) == 1
             and before.replace(old, installed['daemon'].encode(), 1) == after
             and unit_command(before) == [previous_installed['daemon'], '--config',
                 str(Path(deployment['config_root']) / row['role'] / 'current/config/config.toml'), '--sora']
             and unit_command(after)[0] == installed['daemon'],
             'failed-start unit lineage differs')
    need(set(records) == set(FAILED_START_RECORDS) and records['intent.json'] == failed,
         'failed-start intent record differs')
    need(records['start-intent.json'] == {
        'units': units, 'automatic_old_binary_rollback_after_start': False},
        'failed-start startup marker differs')
    failure = records['failure.json']
    need(set(failure) == {'error', 'new_start_attempted', 'installed_units',
                         'validator_stop_attempted', 'validator_stop_confirmed'}
         and isinstance(failure['error'], str) and failure['new_start_attempted'] is True
         and failure['validator_stop_attempted'] is True
         and failure['validator_stop_confirmed'] is True
         and failure['installed_units'] == roles, 'failed-start failure marker differs')
    before, checkpoints = records['before.json'], records['checkpoint-stopped.json']
    need([row.get('role') for row in before] == roles
         and [row.get('role') for row in checkpoints] == roles,
         'failed-start retained evidence lacks exact cohort')
    for row, checkpoint in zip(before, checkpoints, strict=True):
        need(row['public']['commit'] == current['commit']
             and row['public']['network_id'] == deployment['network_id']
             and type(row['public']['height']) is int and row['public']['height'] > 0
             and checkpoint.get('cohort_stopped') is True
             and checkpoint.get('invocation_id') == row['systemd']['InvocationID']
             and re.fullmatch('[0-9a-f]{32}', checkpoint['invocation_id'])
             and type(checkpoint.get('checkpoint_height')) is int
             and checkpoint['checkpoint_height'] >= deployment['replay_floor']
             and type(checkpoint['kura_tip']['height']) is int
             and checkpoint['kura_tip']['height'] >= max(checkpoint['checkpoint_height'], row['public']['height'])
             and re.fullmatch('[0-9a-f]{64}', checkpoint['kura_tip']['hash']),
             'failed-start checkpoint or historical observation differs')
    return installed


class FailedStartRecordBudget:
    """Bound public evidence before JSON decoding, including duplicate reference reads."""
    def __init__(self):
        self.consumed = 0

    def consume(self, raw):
        need(len(raw) <= MAX_FAILED_START_RECORD_BYTES,
             'failed-start public record exceeds byte bound')
        self.consumed += len(raw)
        need(self.consumed <= MAX_FAILED_START_CHAIN_BYTES,
             'failed-start chain exceeds aggregate byte bound')


def artifact_identity(artifacts):
    """Canonical identity ignores storage paths, never binary bytes or package identity."""
    need(isinstance(artifacts, list) and len(artifacts) == 3,
         'exact daemon, CLI and Kagami artifacts required')
    identity = []
    for row, (name, package) in zip(artifacts,
            (('iroha3d_taira', 'irohad'), ('iroha', 'iroha_cli'),
             ('kagami', 'iroha_kagami')), strict=True):
        need(row.get('name') == name and row.get('package') == package
             and isinstance(row.get('sha256'), str)
             and re.fullmatch('[0-9a-f]{64}', row['sha256'])
             and type(row.get('size')) is int and 1_000_000 < row['size'] < 1024 ** 3,
             'invalid ordered daemon, CLI or Kagami artifact identity')
        identity.append((name, package, row['sha256'], row['size']))
    return tuple(identity)


def validate_candidate_transition(commit, artifacts, completed_commit, installed_plan):
    """A new operation may reuse the installed source only with identical artifacts."""
    need(re.fullmatch('[0-9a-f]{40}', commit) and commit != completed_commit,
         'candidate cannot repeat the completed runtime')
    candidate = artifact_identity(artifacts)
    if commit == installed_plan['commit']:
        need(candidate == artifact_identity(installed_plan['artifacts']),
             'same source commit has different prepared daemon, CLI or Kagami bytes')


def failed_attempt_reference_identity(reference):
    """Validate reference shape and compare immutable bytes independently of capture paths."""
    need(set(reference) == {'operation', 'plan', 'records'}
         and re.fullmatch('update-[0-9a-f]{32}', reference['operation'])
         and set(reference['records']) == set(FAILED_START_RECORDS),
         'failed-start attempt reference fields differ')
    for ref in (reference['plan'], *reference['records'].values()):
        need(set(ref) == {'path', 'sha256'} and isinstance(ref['path'], str)
             and Path(ref['path']).is_absolute()
             and isinstance(ref['sha256'], str)
             and re.fullmatch('[0-9a-f]{64}', ref['sha256']),
             'failed-start public record reference differs')
    need(reference['plan']['sha256'] == reference['records']['intent.json']['sha256'],
         'failed-start plan and installed intent bytes differ')
    return (reference['operation'], reference['plan']['sha256'],
            tuple((name, reference['records'][name]['sha256']) for name in FAILED_START_RECORDS))


def validate_failed_start_prefix(failed, prefix, installed):
    """Historical intents must authenticate exactly the earlier chain, without following paths."""
    ancestry = failed.get('failed_start')
    if not prefix:
        need('failed_start' not in failed, 'first failed attempt has an unbound ancestor')
        return
    need(isinstance(ancestry, dict) and ancestry.get('installed') == installed,
         'failed-start ancestor installed identity differs')
    if ancestry.get('schema') == 'taira.failed-start-reference.v1':
        # This is immutable incident evidence, not an accepted operator input.
        need(len(prefix) == 1 and set(ancestry) == {'schema', 'plan', 'records', 'installed'},
             'historical failed-start reference does not bind the complete prefix')
        actual = [{'operation': installed['attempt_name'], 'plan': ancestry['plan'],
                   'records': ancestry['records']}]
    else:
        need(set(ancestry) == {'schema', 'attempts', 'installed'}
             and ancestry['schema'] == FAILED_START_CHAIN_SCHEMA
             and isinstance(ancestry['attempts'], list)
             and len(ancestry['attempts']) == len(prefix),
             'failed-start ancestry does not bind the complete prefix')
        actual = ancestry['attempts']
    need([failed_attempt_reference_identity(ref) for ref in actual]
         == [failed_attempt_reference_identity(ref) for ref in prefix],
         'failed-start ancestor record identities differ')


def validate_failed_start_chain(reference, deployment, baseline, operation, load_attempt,
                                baseline_observations=None, candidate=None):
    """Authenticate a bounded oldest-to-newest chain while keeping completed health separate."""
    need(set(reference) == {'schema', 'attempts'}
         and reference['schema'] == FAILED_START_CHAIN_SCHEMA
         and isinstance(reference['attempts'], list)
         and 1 <= len(reference['attempts']) <= MAX_FAILED_START_ATTEMPTS,
         'bounded failed-start chain required')
    current = deployment['current']
    seen = {operation, current['attempt_name']}
    installed, previous_plan = current, baseline
    entries = []
    source_artifacts = {}
    previous_checkpoints = None
    historical_health = baseline_observations
    for index, ref in enumerate(reference['attempts']):
        failed_attempt_reference_identity(ref)
        need(ref['operation'] not in seen, 'failed-start chain repeats an operation')
        seen.add(ref['operation'])
        failed, records = load_attempt(ref)
        need(failed.get('operation') == ref['operation'], 'failed-start operation differs')
        validate_failed_start_prefix(failed, reference['attempts'][:index], installed)
        next_installed = validate_failed_start_inputs(
            deployment, baseline, failed, records, operation, previous_plan, installed)
        validate_candidate_transition(failed['commit'], failed['artifacts'],
                                      current['commit'], previous_plan)
        identity = artifact_identity(failed['artifacts'])
        need(source_artifacts.setdefault(failed['commit'], identity) == identity,
             'failed-start ancestry reused a source with different binary bytes')
        before, checkpoints = records['before.json'], records['checkpoint-stopped.json']
        if historical_health is None:
            historical_health = before
        for original, observed in zip(historical_health, before, strict=True):
            compare_retained_identity(original, observed)
            need(original['public'] == observed['public'],
                 'failed-start historical health differs from completed predecessor')
        if previous_checkpoints is not None:
            for previous, checkpoint in zip(previous_checkpoints, checkpoints, strict=True):
                old, new = previous['kura_tip'], checkpoint['kura_tip']
                need(new['height'] >= old['height']
                     and checkpoint['checkpoint_height'] >= previous['checkpoint_height']
                     and (new['height'] != old['height'] or new['hash'] == old['hash']),
                     'failed-start checkpoint ancestry regressed')
        installed, previous_plan, previous_checkpoints = next_installed, failed, checkpoints
        entries.append((failed, records))
    if candidate is not None:
        validate_candidate_transition(candidate['commit'], candidate['artifacts'],
                                      current['commit'], previous_plan)
        if candidate['commit'] in source_artifacts:
            need(artifact_identity(candidate['artifacts']) == source_artifacts[candidate['commit']],
                 'candidate source differs from its retained ancestry artifacts')
    return installed, entries


def stamp(path, directory=False):
    path = Path(path)
    info = path.lstat()
    need(path.resolve() == path and info.st_uid == 0 and not info.st_mode & 0o022,
         'unsafe owner path: ' + str(path))
    need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
         'wrong path kind: ' + str(path))
    if not directory:
        need(info.st_nlink == 1, 'unexpected hard link: ' + str(path))
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def write_new(path, raw, mode=0o600):
    path = Path(path)
    stamp(path.parent, True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    sync(path.parent)


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def record(name, value):
    write_new(ATTEMPT / name, (json.dumps(value, sort_keys=True) + '\n').encode())


class NativeCommandFailure(RuntimeError):
    """Expose a native exit code without copying stdout, stderr or argv."""
    def __init__(self, label, exit_code):
        self.exit_code = exit_code
        super().__init__(f'native command failed: {label} (exit {exit_code})')


def command(argv, *, timeout=60, name=None, pass_fds=(), allowed_exit_codes=(0,)):
    # Output may contain native configuration diagnostics; retain it privately,
    # never include arbitrary stderr/config-related output in the public report.
    result = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=timeout, env=ENV,
                            pass_fds=pass_fds)
    if name:
        write_new(ATTEMPT / (name + '.stdout'), result.stdout)
        write_new(ATTEMPT / (name + '.stderr'), result.stderr)
        record(name + '.result.json', {'exit_code': result.returncode})
    if result.returncode not in allowed_exit_codes:
        raise NativeCommandFailure(name or Path(argv[0]).name, result.returncode)
    return result.stdout


def native_digest(path):
    before = stamp(path)
    value = command(['/usr/bin/sha256sum', path]).split()[0].decode('ascii')
    need(before == stamp(path), 'file changed during native digest: ' + str(path))
    return value


def native_private_command(argv, *, timeout, name):
    # Config validation bypasses runtime custody (taira_runtime_signer.rs:657).
    # Keep every diagnostic byte native-to-file; Python observes exit only.
    out_fd = os.open(ATTEMPT / (name + '.stdout'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    err_fd = os.open(ATTEMPT / (name + '.stderr'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        result = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL,
                                stdout=out_fd, stderr=err_fd, timeout=timeout, env=ENV)
        os.fsync(out_fd)
        os.fsync(err_fd)
    finally:
        os.close(out_fd)
        os.close(err_fd)
    record(name + '.result.json', {'exit_code': result.returncode})
    need(result.returncode == 0, 'native configuration validation failed: ' + name)


def unit_command(raw):
    prefix = 'ExecStart=/usr/bin/python3 -c '
    lines = [line for line in raw.decode().splitlines() if line.startswith('ExecStart=')]
    need(len(lines) == 1 and lines[0].startswith(prefix), 'unexpected unit launcher')
    code = json.loads(lines[0][len(prefix):]).replace('%%', '%').replace('$$', '$')
    values = [ast.literal_eval(node.value) for node in ast.parse(code).body
              if isinstance(node, ast.Assign) and len(node.targets) == 1
              and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'cmd']
    need(len(values) == 1, 'unit must have one literal cmd')
    return values[0]


def previous_daemon(role, *, resolved=False):
    if INITIAL_DAEMONS:
        return Path(INITIAL_DAEMONS[role]['resolved' if resolved else 'command'])
    return PREVIOUS_DAEMON


def retained_config(role):
    return CONFIG_ROOT / role / 'releases' / CONFIG_RELEASE / 'config' / CONFIG_FILENAME


def replace_daemon(raw, role):
    old = str(previous_daemon(role))
    cmd = [old, '--config', str(CONFIG_ROOT / role / 'current/config' / CONFIG_FILENAME), '--sora']
    need(unit_command(raw) == cmd and raw.count(old.encode()) == 1, 'old unit command differs')
    changed = raw.replace(old.encode(), str(DAEMON).encode(), 1)
    need(unit_command(changed) == [str(DAEMON), *cmd[1:]], 'new unit command differs')
    need(changed.replace(str(DAEMON).encode(), old.encode(), 1) == raw,
         'unit change exceeds daemon path')
    return changed


def systemd(unit):
    names = ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlPID',
             'FragmentPath', 'DropInPaths', 'NeedDaemonReload', 'InvocationID', 'Job',
             'Result', 'ExecMainCode', 'ExecMainStatus', 'NRestarts')
    raw = command(['/usr/bin/systemctl', 'show', '--all',
                   *['--property=' + name for name in names], unit], timeout=15)
    result = dict(line.split('=', 1) for line in raw.decode().splitlines())
    need(set(result) == set(names), 'systemd fields differ')
    need(result['LoadState'] == 'loaded' and result['DropInPaths'] == ''
         and result['NeedDaemonReload'] == 'no' and result['Job'] == ''
         and result['FragmentPath'] == '/etc/systemd/system/' + unit,
         'systemd fragment/job differs: ' + unit)
    return result


class StartupProbeUnavailable(RuntimeError):
    """Only declared local transport failures or HTTP 503 may be polled."""


def public_probe(index, route, *, name=None):
    need(route in ('/status', '/v1/accounts/faucet/puzzle', '/readyz'),
         'unexpected public probe route')
    label = f'role={ROLES[index]} endpoint={route}'
    accept = 'text/plain' if route == '/readyz' else 'application/json'
    try:
        raw = command(['/usr/bin/curl', '--fail', '--silent', '--show-error', '--max-time', '8',
                       '--write-out', '\n%{http_code}', '-H', 'Accept: ' + accept,
                       f'http://127.0.0.1:{PORTS[index]}{route}'],
                      timeout=10, name=name, allowed_exit_codes=(0, 22))
    except NativeCommandFailure as error:
        # Connection refused, timeout, empty reply, and connection reset can
        # occur during native startup. DNS/configuration/HTTP errors cannot.
        kind = StartupProbeUnavailable if error.exit_code in (7, 28, 52, 56) else RuntimeError
        raise kind(f'public probe failed: {label} curl_exit={error.exit_code}') from None
    except subprocess.TimeoutExpired:
        raise StartupProbeUnavailable(f'public probe failed: {label} timeout') from None
    except (RuntimeError, OSError):
        raise RuntimeError(f'public probe failed: {label} native_probe_unavailable') from None
    body, separator, code = raw.rpartition(b'\n')
    need(separator and re.fullmatch(b'[0-9]{3}', code),
         'public probe HTTP status is malformed: ' + label)
    if code == b'503':
        raise StartupProbeUnavailable('public probe not ready: ' + label + ' http_status=503')
    need(code == b'200', 'public probe HTTP status rejected: ' + label + ' http_status=' + code.decode())
    if route == '/readyz':
        need(body == b'Ready', 'public readiness body differs: ' + label)
    return body


def public_get(index, route):
    raw = public_probe(index, route)
    label = f'role={ROLES[index]} endpoint={route}'
    need(len(raw) <= 2 * 1024 * 1024, 'public response exceeds bound: ' + label)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise RuntimeError('public identity is not valid JSON: ' + label) from None
    need(isinstance(value, dict), 'public identity is not an object: ' + label)
    return value


def public_identity(index, *, expected_commit, minimum_height=0):
    status = public_get(index, '/status')
    build = status.get('build', {})
    height = status.get('blocks')
    need(isinstance(build, dict) and type(height) is int and height > 0,
         f'public build identity or positive retained height missing: role={ROLES[index]} endpoint=/status')
    # Validate each response before issuing another probe that may be transient.
    # An invalid fresh status must never disappear behind a later puzzle 503.
    need(build.get('git_commit_sha') == expected_commit,
         'candidate revision differs: ' + ROLES[index])
    need(height >= minimum_height, 'committed catch-up height regressed: ' + ROLES[index])
    puzzle = public_get(index, '/v1/accounts/faucet/puzzle')
    need(puzzle.get('network_id') == NETWORK and puzzle.get('chain_discriminant') == 369,
         f'live NetworkId or Taira prefix changed: role={ROLES[index]} endpoint=/v1/accounts/faucet/puzzle')
    return {'network_id': puzzle['network_id'], 'height': height,
            'commit': build['git_commit_sha']}


def retained_identity(row, *, after=False):
    role = row['role']
    unit = f'iroha3d-{role}.service'
    fragment = Path('/etc/systemd/system') / unit
    stamp(fragment)
    raw = fragment.read_bytes()  # Public generated unit only.
    expected = base64.b64decode(row['after' if after else 'before'], validate=True)
    need(raw == expected, 'unit bytes differ: ' + role)
    cmd = unit_command(raw)
    release = CONFIG_ROOT / role / 'releases' / CONFIG_RELEASE
    selector = CONFIG_ROOT / role / 'current'
    need(os.readlink(selector) == str(release), 'current selector changed: ' + role)
    expected_exe = str(DAEMON if after else previous_daemon(role, resolved=True))
    config = retained_config(role)
    need(Path(cmd[2]).resolve() == config, 'config resolution changed: ' + role)
    return {'role': role, 'unit_stamp': stamp(fragment),
            'config_stamp': stamp(config),
            'state_root_identity': stamp(STATE_ROOT / role, True)[:2],
            'current_target': os.readlink(selector), 'executable': expected_exe}


def process_summary(props):
    """Render only bounded systemd state fields, never native diagnostic text."""
    fields = ('ActiveState', 'SubState', 'MainPID', 'InvocationID', 'NRestarts',
              'Result', 'ExecMainStatus')
    values = []
    for key in fields:
        value = props.get(key, 'unavailable')
        safe = value if isinstance(value, str) and re.fullmatch('[A-Za-z0-9_-]{1,64}', value) else 'invalid'
        values.append(key + '=' + safe)
    return ','.join(values)


def observe(row, *, after=False, allow_unavailable=False, expected_commit=None, minimum_height=0):
    props = systemd(f'iroha3d-{row["role"]}.service')
    need(props['ActiveState'] == 'active' and props['SubState'] == 'running'
         and props['ControlPID'] == '0',
         'validator not running: ' + row['role'] + ' ' + process_summary(props))
    pid = int(props['MainPID'])
    need(pid > 0, 'validator PID missing')
    identity = retained_identity(row, after=after)
    cmd = unit_command(base64.b64decode(row['after' if after else 'before'], validate=True))
    actual = Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    need(actual == cmd, 'daemon argv differs: ' + row['role'])
    need(os.readlink(f'/proc/{pid}/exe') == identity['executable'],
         'daemon executable differs: ' + row['role'])
    public = None
    unavailable = None
    try:
        public = public_identity(ROLES.index(row['role']),
                                 expected_commit=expected_commit or (CANDIDATE_COMMIT if after else OLD),
                                 minimum_height=minimum_height)
    except StartupProbeUnavailable as error:
        unavailable = error
    identity.update(systemd=props, public=public)
    current = systemd(f'iroha3d-{row["role"]}.service')
    need(current == props,
         'validator changed during observation: ' + row['role']
         + (('; ' + str(unavailable)) if unavailable else '')
         + ' observed=' + process_summary(props) + '; current=' + process_summary(current))
    if unavailable is not None:
        if not allow_unavailable:
            raise unavailable
        identity['public_unavailable'] = str(unavailable)
    return identity


def snapshot_selection(role):
    """Read only the public digest selector; payload/manifest remain native-owned."""
    root = STATE_ROOT / role / 'snapshots'
    root_identity = stamp(root, True)[:2]
    pointer = root / 'current'
    pointer_stamp = stamp(pointer)
    need(pointer_stamp[6] == 65, 'snapshot selector must be one canonical digest')
    fd = os.open(pointer, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 66)
    finally:
        os.close(fd)
    need(re.fullmatch(b'[0-9a-f]{64}\n', raw) is not None,
         'snapshot selector is not canonical')
    selected = raw[:64].decode('ascii')
    generations = root / 'generations'
    stamp(generations, True)
    generation = generations / selected
    generation_identity = stamp(generation, True)[:2]
    need({p.name for p in generation.iterdir()} == SNAPSHOT_ARTIFACTS,
         'snapshot selected generation inventory differs')
    artifacts = {name: stamp(generation / name) for name in sorted(SNAPSHOT_ARTIFACTS)}
    need(pointer_stamp == stamp(pointer) and root_identity == stamp(root, True)[:2]
         and generation_identity == stamp(generation, True)[:2]
         and artifacts == {name: stamp(generation / name) for name in sorted(SNAPSHOT_ARTIFACTS)},
         'snapshot generation changed during metadata capture')
    return {'root_identity': root_identity, 'selector': selected, 'pointer_stamp': pointer_stamp,
            'generation_identity': generation_identity, 'artifacts': artifacts}


def snapshot_events(role, invocation):
    need(re.fullmatch('[0-9a-f]{32}', invocation) is not None, 'exact daemon InvocationID required')
    # Native journal filtering returns only fixed public checkpoint/startup events.
    pattern = ('Successfully created a snapshot of state|Saving latest snapshot and shutting down|'
               'Failed to create a snapshot of state|Deferring snapshot until commit evidence is complete|'
               'Successfully loaded the state from a snapshot|Validated snapshot block hashes against Kura|'
               'Failed to load state snapshot|creating an empty state|Snapshot restore is disabled|'
               'emergency Fast|Replaying authenticated complete Kura prefix|'
               'Kura retains the configured-primary replay floor; rebuilding state from blocks|'
               'Sumeragi rebuilt the state from genesis and Kura')
    query = subprocess.run(['/usr/bin/journalctl', '--no-pager', '-o', 'json', '-n', '64',
                            '-u', f'iroha3d-{role}.service', '_SYSTEMD_INVOCATION_ID=' + invocation,
                            '--grep=' + pattern], stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=15, env=ENV)
    # journalctl --grep returns 1 when no record matched. That is absence of
    # evidence in this invocation, never permission to ignore query failures.
    if query.returncode == 1 and query.stdout == query.stderr == b'':
        return []
    need(query.returncode == 0, 'native snapshot journal query failed')
    raw = query.stdout
    need(len(raw) <= 1024 * 1024, 'snapshot journal projection exceeds bound')
    result = []
    for line in raw.splitlines():
        event = json.loads(line)
        need(event.get('_SYSTEMD_INVOCATION_ID') == invocation, 'snapshot journal invocation differs')
        result.append({'time_us': int(event['__REALTIME_TIMESTAMP']),
                       'message': event['MESSAGE']})
    # journalctl --grep with a line limit can return newest-first. Select
    # checkpoint events by native timestamp, never incidental output order.
    return sorted(result, key=lambda event: event['time_us'])


def native_kura_tip(role):
    # Exact observed chain-scoped hash journal; native tail/od project only the
    # final public 32-byte block hash. No ledger/state payload enters Python.
    path = STATE_ROOT / role / KURA_HASH_JOURNAL
    before = stamp(path)
    need(before[6] >= 32 and before[6] % 32 == 0, 'canonical Kura hash journal size differs')
    tail = subprocess.Popen(['/usr/bin/tail', '-c', '32', str(path)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=ENV)
    try:
        projected = subprocess.run(['/usr/bin/od', '-An', '-tx1', '-v'], stdin=tail.stdout,
                                   capture_output=True, timeout=10, env=ENV)
        tail.stdout.close()
        need(tail.wait(timeout=10) == 0 and projected.returncode == 0,
             'native Kura public tip projection failed')
    finally:
        if tail.poll() is None:
            tail.kill()
            tail.wait()
    tip = ''.join(projected.stdout.decode('ascii').split())
    need(re.fullmatch('[0-9a-f]{64}', tip) is not None and before == stamp(path),
         'Kura public tip changed during projection')
    return {'height': before[6] // 32, 'hash': tip}


def native_kura_hash(role, height):
    """Project one retained public hash; native tools alone read the journal."""
    need(role in ROLES and type(height) is int and height > 0, 'invalid retained Kura height')
    path = STATE_ROOT / role / KURA_HASH_JOURNAL
    before = stamp(path)
    need(before[6] >= height * 32, 'retained Kura height is missing')
    reader = subprocess.Popen(['/usr/bin/dd', 'if=' + str(path), 'bs=32',
                               'skip=' + str(height - 1), 'count=1', 'status=none'],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, env=ENV)
    try:
        result = subprocess.run(['/usr/bin/od', '-An', '-tx1', '-v'], stdin=reader.stdout,
                                capture_output=True, timeout=10, env=ENV)
        reader.stdout.close()
        need(reader.wait(timeout=10) == 0 and result.returncode == 0,
             'native retained Kura hash projection failed')
    finally:
        if reader.poll() is None:
            reader.kill()
            reader.wait()
    value = ''.join(result.stdout.decode('ascii').split())
    after = stamp(path)
    need(re.fullmatch('[0-9a-f]{64}', value) is not None
         and before[:6] == after[:6] and after[6] >= before[6],
         'retained Kura journal identity or hash changed during projection')
    return value


def require_retained_tip(role, tip):
    need(native_kura_hash(role, tip['height']) == tip['hash'],
         'retained Kura prefix hash changed: ' + role)


def strict_snapshot_height(events):
    forbidden = ('Failed to load state snapshot', 'creating an empty state',
                 'Snapshot restore is disabled', 'emergency Fast')
    need(not any(any(text in e['message'] for text in forbidden) for e in events),
         'runtime did not use an authenticated Strict snapshot')
    loaded = [e for e in events if 'Successfully loaded the state from a snapshot' in e['message']]
    verified = [e for e in events if 'Validated snapshot block hashes against Kura' in e['message']]
    need(loaded and verified, 'native Strict snapshot/Kura checkpoint authentication missing')
    height = re.search(r'\bat_height=(\d+)\b', loaded[-1]['message'])
    authenticated = re.search(r'\bsnapshot_height=(\d+)\b', verified[-1]['message'])
    need(height and authenticated and int(height[1]) == int(authenticated[1]),
         'native Strict snapshot/Kura checkpoint authentication differs')
    return int(height[1]), loaded[-1]


def checkpoint_native_proof(events):
    publications = [e for e in events if 'Successfully created a snapshot of state' in e['message']]
    if publications:
        latest = publications[-1]
        height = re.search(r'\bat_height=(\d+)\b', latest['message'])
        need(height, 'native publication height missing')
        return int(height[1]), latest['time_us'], 'native_publication'
    if any('Successfully loaded the state from a snapshot' in e['message'] for e in events):
        height, loaded = strict_snapshot_height(events)
        return height, loaded['time_us'], 'native_strict_restore'
    return None


def checkpoint_barrier(observation, *, stopped=False, prior=None):
    role = observation['role']
    selected = snapshot_selection(role)
    tip = native_kura_tip(role)
    events = snapshot_events(role, observation['systemd']['InvocationID'])
    need(selected == snapshot_selection(role), 'snapshot changed during native evidence capture')
    proof = checkpoint_native_proof(events)
    provenance = observation['systemd']['InvocationID']
    evidence = events
    reused = False
    if proof is None and prior is not None:
        need(prior['role'] == role and selected == prior['selection'],
             'retained native checkpoint selection changed')
        evidence = prior['native_events']
        proof = checkpoint_native_proof(evidence)
        provenance = prior.get('proof_invocation_id', prior.get('publication_invocation_id', prior['invocation_id']))
        reused = True
    need(proof is not None, 'no native authenticated snapshot evidence')
    height, proof_time_us, kind = proof
    need(height >= REPLAY_BARRIER, 'native checkpoint precedes affected history')
    need(selected['pointer_stamp'][7] <= proof_time_us * 1000,
         'selected snapshot was replaced after native checkpoint evidence')
    need(height <= tip['height'], 'native checkpoint exceeds retained Kura tip')
    if prior is not None:
        require_retained_tip(role, prior['kura_tip'])
    if stopped:
        need(tip['height'] >= observation['public']['height'],
             'stopped Kura tip lost previously observed height')
    shutdown = [e for e in events if 'Saving latest snapshot and shutting down' in e['message']]
    return {'role': role, 'invocation_id': observation['systemd']['InvocationID'],
            'proof_invocation_id': provenance, 'reused_checkpoint_proof': reused,
            'checkpoint_height': height, 'proof_kind': kind, 'selection': selected, 'kura_tip': tip,
            'native_events': evidence, 'current_invocation_events': events,
            'graceful_stop_observed': bool(shutdown), 'cohort_stopped': stopped,
            'standalone_native_manifest_verification': False}


def native_log_words(message):
    """Match Rust str::split_whitespace (Unicode White_Space), not Python's C0 extras."""
    return re.findall(r'[^\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+', message)


def native_replay_required_error(message):
    return native_log_words(message)[-1:] == ['error=NativeExecutionReplayRequired']


def authenticated_kura_replay_height(events):
    """Recognize only the native policy-required, completed certified replay path.

    irohad admits this fallback only outside emergency Fast, after the complete
    configured-primary prefix preflight. Sumeragi node::prepare then executes
    stored signed genesis and every block against its commit QC and World roots
    before emitting the completion event or installing Ready runtime services.
    """
    failed = [e for e in events if 'Failed to load state snapshot' in e['message']]
    begun = [e for e in events if 'Kura retains the configured-primary replay floor; rebuilding state from blocks' in e['message']]
    completed = [e for e in events if 'Sumeragi rebuilt the state from genesis and Kura' in e['message']]
    need(len(failed) == len(begun) == len(completed) == 1
         and native_replay_required_error(failed[0]['message'])
         and all(type(e.get('time_us')) is int and e['time_us'] > 0 for e in (failed[0], begun[0], completed[0]))
         and failed[0]['time_us'] <= begun[0]['time_us'] <= completed[0]['time_us'],
         'native authenticated Kura replay sequence is missing or differs')
    forbidden = ('creating an empty state', 'Snapshot restore is disabled', 'emergency Fast',
                 'Successfully loaded the state from a snapshot', 'Validated snapshot block hashes against Kura')
    need(not any(any(text in e['message'] for text in forbidden) for e in events),
         'native replay has a foreign or mixed startup mode')
    heights = [word.removeprefix('height=') for word in native_log_words(completed[0]['message'])
               if word.startswith('height=')]
    need(len(heights) == 1 and heights[0] and all('0' <= digit <= '9' for digit in heights[0])
         and int(heights[0]) > 0, 'native replay completion height is absent or malformed')
    return int(heights[0])


def verify_restored_checkpoint(observation, checkpoint, *, allow_authenticated_replay=False):
    events = snapshot_events(observation['role'], observation['systemd']['InvocationID'])
    replay = allow_authenticated_replay and any(native_replay_required_error(e['message']) for e in events)
    if replay:
        height = authenticated_kura_replay_height(events)
    else:
        height, _loaded = strict_snapshot_height(events)
    need(height >= max(REPLAY_BARRIER, checkpoint['checkpoint_height']),
         'new runtime snapshot restoration height is below the retained barrier')
    need(observation['public']['height'] >= checkpoint['kura_tip']['height'],
         'new runtime has not restored the retained Kura tip')
    require_retained_tip(observation['role'], checkpoint['kura_tip'])
    for event in events:
        if 'Replaying authenticated complete Kura prefix' in event['message']:
            start = re.search(r'\bstart_height=(\d+)\b', event['message'])
            need(start and int(start[1]) > height,
                 'historical replay crosses the authenticated retained checkpoint')
    result = {'role': observation['role'], 'restored_height': height,
              'native_strict_checkpoint_verified': not replay, 'events': events}
    if replay:
        need(height >= checkpoint['kura_tip']['height']
             and height <= observation['public']['height']
             and observation['public']['network_id'] == NETWORK
             and observation['cohort_observation']['ready'] is True
             and observation['cohort_observation']['public_fresh'] is True,
             'native replay does not join the exact Ready retained runtime')
        result.update(proof_kind='native_authenticated_kura_replay',
                      native_authenticated_kura_replay_verified=True,
                      retained_kura_tip=checkpoint['kura_tip'],
                      source_commit=observation['public']['commit'], network_id=NETWORK)
    return result


def require_retained_restore_proof(restored, stopped, *, source, network, allow_authenticated_replay=False):
    if restored.get('native_strict_checkpoint_verified') is True:
        need(not {'proof_kind', 'native_authenticated_kura_replay_verified', 'retained_kura_tip',
                  'source_commit', 'network_id'}.intersection(restored),
             'Strict restore receipt cannot claim native replay')
        return True
    need(allow_authenticated_replay
         and restored.get('native_strict_checkpoint_verified') is False
         and restored.get('native_authenticated_kura_replay_verified') is True
         and restored.get('proof_kind') == 'native_authenticated_kura_replay'
         and restored.get('source_commit') == source and restored.get('network_id') == network
         and restored.get('role') == stopped['role']
         and restored.get('retained_kura_tip') == stopped['kura_tip'],
         'predecessor Strict restoration is not verified and no exact native replay proof exists')
    height = authenticated_kura_replay_height(restored.get('events', []))
    need(type(restored.get('restored_height')) is int and restored['restored_height'] == height
         and height >= max(stopped['checkpoint_height'], stopped['kura_tip']['height']),
         'retained native replay height differs')
    return False


def require_completed_restore_modes(completed, strict_modes, *, modern):
    need(len(strict_modes) == 4 and all(type(mode) is bool for mode in strict_modes),
         'completed restore cohort is not exact')
    all_strict = all(strict_modes)
    need(completed.get('retained_native_snapshot_verified') is all_strict,
         'completed snapshot verification contradicts native proofs')
    if modern:
        expected = ['native_strict_restore' if strict else 'native_authenticated_kura_replay'
                    for strict in strict_modes]
        need(completed.get('retained_native_state_verified') is True
             and completed.get('native_recovery_modes') == expected
             and completed.get('historical_genesis_replay_supported') is (not all_strict),
             'completed native state or recovery modes contradict native proofs')
    else:
        need(all_strict, 'legacy predecessor requires Strict restore')


def install_unit(path, raw, expected, mode):
    need(path.read_bytes() == expected, 'installed unit changed before replacement')
    temporary = path.with_name(path.name + '.taira-update-next')
    write_new(temporary, raw, mode)
    os.replace(temporary, path)
    sync(path.parent)


def stop_all():
    command(['/usr/bin/systemctl', 'stop', *UNITS], timeout=150, name='stop')
    states = []
    for unit in UNITS:
        state = systemd(unit)
        need((state['ActiveState'], state['SubState']) in (('inactive', 'dead'), ('failed', 'failed'))
             and state['MainPID'] == state['ControlPID'] == '0' and state['Job'] == '',
             'cohort stop incomplete: ' + unit)
        states.append({'unit': unit, 'systemd': state,
                       'clean_exit': state['Result'] == 'success' and state['ExecMainStatus'] == '0'})
    record('stop-observations.json', states)
    return states


def compare_retained_identity(old, new, *, allow_config_retirement=False):
    for key in ('state_root_identity', 'current_target'):
        need(old[key] == new[key], 'retained identity changed: ' + key)
    if allow_config_retirement and CONFIG_RETIREMENT is not None:
        rows = CONFIG_RETIREMENT['rows']
        matches = [row for row in rows if row['role'] == old['role'] == new['role']]
        need(len(matches) == 1 and old['config_stamp'] == matches[0]['before_stamp']
             and new['config_stamp'] == matches[0]['installed_stamp'],
             'retained config_stamp differs from native retirement receipt')
    else:
        need(old['config_stamp'] == new['config_stamp'], 'retained identity changed: config_stamp')


def cohort_retained_tip(checkpoints):
    """Freeze the existing cohort's highest committed prefix before startup."""
    need(tuple(row['role'] for row in checkpoints) == ROLES,
         'retained Kura checkpoint cohort differs')
    tips = [row['kura_tip'] for row in checkpoints]
    need(all(type(tip['height']) is int and tip['height'] >= REPLAY_BARRIER
             and re.fullmatch('[0-9a-f]{64}', tip['hash']) for tip in tips),
         'retained cohort Kura tip is invalid')
    height = max(tip['height'] for tip in tips)
    hashes = {tip['hash'] for tip in tips if tip['height'] == height}
    need(len(hashes) == 1, 'highest retained Kura tips disagree')
    return {'height': height, 'hash': hashes.pop()}


def verify_stopped_cohort_prefixes(checkpoints):
    """Check every stopped tip against every peer retaining that height."""
    tip = cohort_retained_tip(checkpoints)
    for checkpoint in checkpoints:
        for peer in checkpoints:
            if peer['kura_tip']['height'] >= checkpoint['kura_tip']['height']:
                require_retained_tip(peer['role'], checkpoint['kura_tip'])
    return tip


def verify_cohort_processes(observations, expected=None):
    """Reject exits/restarts during the complete cohort observation window."""
    for observed, original in zip(observations, expected or observations, strict=True):
        role = observed['role']
        props = observed['systemd']
        need(role == original['role']
             and props['ActiveState'] == 'active' and props['SubState'] == 'running'
             and props['ControlPID'] == '0' and int(props['MainPID']) > 0
             and re.fullmatch('[0-9a-f]{32}', props['InvocationID'])
             and props.get('NRestarts', '0') == '0'
             and all(props[key] == original['systemd'][key]
                     for key in ('MainPID', 'InvocationID')),
             'validator process changed across cohort verification: ' + role
             + ' expected=' + process_summary(original['systemd'])
             + '; observed=' + process_summary(props))
        current = systemd(f'iroha3d-{role}.service')
        need(current == props, 'validator process changed across cohort verification: ' + role
             + ' observed=' + process_summary(props) + '; current=' + process_summary(current))


def observe_healthy_cohort(rows, before, *, after, commit, retained_tip,
                           expected_processes=None, verified=None, minimum_heights=None):
    """Attempt all four peers; only fresh Ready peers can contribute to quorum.

    A prior candidate observation can retain an unavailable peer's identity,
    but is explicitly marked stale and never counted as a fresh quorum vote.
    """
    need(tuple(row['role'] for row in rows) == ROLES
         and tuple(row['role'] for row in before) == ROLES, 'observation cohort differs')
    verified = verified or [None] * len(rows)
    minimum_heights = minimum_heights or [row['public']['height'] for row in before]
    observations = []
    for index, (row, old, prior, minimum) in enumerate(zip(
            rows, before, verified, minimum_heights, strict=True)):
        # The stopped process's height is a completion target, not a lower
        # bound for the new process's intermediate replay observations.
        last_height = prior['public']['height'] if prior is not None and prior['public'] else 0
        new = observe(row, after=after, allow_unavailable=True,
                      expected_commit=commit, minimum_height=last_height)
        compare_retained_identity(old, new, allow_config_retirement=after)
        public = new['public']
        fresh = public is not None
        if fresh:
            need(public['commit'] == commit, 'candidate revision differs: ' + row['role'])
            if prior is not None and prior['public'] is not None:
                need(public['height'] >= prior['public']['height'],
                     'committed catch-up height regressed: ' + row['role'])
            if public['height'] >= retained_tip['height']:
                require_retained_tip(row['role'], retained_tip)
        elif prior is not None:
            new['public'] = prior['public']
        ready = True
        try:
            public_probe(index, '/readyz')
        except StartupProbeUnavailable as error:
            ready = False
            new['ready_unavailable'] = str(error)
        public = new['public']
        restored = public is not None and public['height'] >= minimum
        new['cohort_observation'] = {
            'public_fresh': fresh, 'ready': ready,
            'own_retained_tip_restored': restored,
            'anchored_quorum_member': fresh and ready and restored
                and public['height'] >= retained_tip['height']}
        observations.append(new)
    verify_cohort_processes(observations, expected_processes)
    return observations


def cohort_sample_summary(observations, retained_tip):
    return {'retained_tip': retained_tip, 'required': 3,
            'quorum_roles': [row['role'] for row in observations
                             if row['cohort_observation']['anchored_quorum_member']],
            'missing_roles': [row['role'] for row in observations
                              if not row['cohort_observation']['public_fresh']],
            'unready_roles': [row['role'] for row in observations
                              if not row['cohort_observation']['ready']],
            'lagging_roles': [row['role'] for row in observations
                              if row['public'] is not None
                              and row['public']['height'] < retained_tip['height']],
            'unverified_roles': [row['role'] for row in observations
                                 if not row['cohort_observation']['own_retained_tip_restored']]}


def observe_cohort(rows, before, *, after, commit, retained_tip, expected_processes=None,
                   verified=None, minimum_heights=None):
    observations = observe_healthy_cohort(
        rows, before, after=after, commit=commit, retained_tip=retained_tip,
        expected_processes=expected_processes, verified=verified, minimum_heights=minimum_heights)
    summary = cohort_sample_summary(observations, retained_tip)
    need(not summary['unverified_roles'] and len(summary['quorum_roles']) >= 3,
         'anchored retained quorum is not ready: ' + json.dumps(summary, sort_keys=True))
    return observations


def wait_for_cohort(rows, before, *, after, commit, retained_tip, startup_processes=None,
                    verified=None, minimum_heights=None, sample_receipts=None,
                    timeout=COHORT_STALL_TIMEOUT_SECONDS,
                    max_timeout=COHORT_MAX_TIMEOUT_SECONDS):
    """Require two fresh anchored quorum samples and all four own restorations.

    Only progressing Ready peers extend their own catch-up budget. A fourth
    stalled peer cannot block a coherent quorum or conceal a permanent failure.
    """
    need(0 < timeout <= max_timeout <= COHORT_MAX_TIMEOUT_SECONDS,
         'cohort observation time bounds are invalid')
    started = time.monotonic()
    hard_deadline = started + max_timeout
    progress_deadlines = [started + timeout for _ in rows]
    previous_heights = [None] * len(rows)
    expected_processes = startup_processes
    deadline = min(hard_deadline, started + timeout)
    confirmations = []
    latest = None
    while time.monotonic() < deadline:
        if expected_processes is not None:
            verify_cohort_processes(expected_processes)
        # Permanent identity, process, hash, protocol and filesystem failures
        # escape immediately. The observer alone classifies unavailable HTTP.
        observations = observe_healthy_cohort(
            rows, before, after=after, commit=commit, retained_tip=retained_tip,
            expected_processes=expected_processes, verified=verified, minimum_heights=minimum_heights)
        now = time.monotonic()
        if now >= deadline:
            break
        if expected_processes is None:
            expected_processes = [{'role': row['role'], 'systemd': dict(row['systemd'])}
                                  for row in observations]
        for index, row in enumerate(observations):
            sample = row['cohort_observation']
            if sample['public_fresh']:
                height = row['public']['height']
                previous = previous_heights[index]
                if sample['ready'] and previous is not None and height > previous:
                    progress_deadlines[index] = now + timeout
                previous_heights[index] = height
        verified = observations
        summary = cohort_sample_summary(observations, retained_tip)
        latest = json.dumps(summary, sort_keys=True)
        if not summary['unverified_roles'] and len(summary['quorum_roles']) >= 3:
            confirmations.append(summary)
            if len(confirmations) == 2:
                if sample_receipts is not None:
                    sample_receipts.extend(confirmations)
                return observations
        else:
            confirmations.clear()
        # Three peers must have time remaining to reach the anchor. All four
        # additionally retain an individual deadline until their own tip is seen.
        budgets = [hard_deadline if row['cohort_observation']['anchored_quorum_member']
                   else progress_deadlines[index] for index, row in enumerate(observations)]
        required_restores = [progress_deadlines[index] for index, row in enumerate(observations)
                             if not row['cohort_observation']['own_retained_tip_restored']]
        deadline = min(hard_deadline, sorted(budgets, reverse=True)[2], *required_restores)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    raise RuntimeError('cohort observation deadline: ' + str(latest))


def read_bounded_proc(path, limit):
    """Read only an explicitly selected public procfs projection."""
    with path.open('rb') as source:
        raw = source.read(limit + 1)
    need(len(raw) <= limit, 'public updater process projection exceeds bound')
    return raw


def cohort_process_start_time(pid):
    """Read a live process's public start-time field without its environment."""
    need(type(pid) is int and pid > 0, 'invalid updater process PID')
    raw = read_bounded_proc(Path('/proc') / str(pid) / 'stat', 4096)
    parts = raw.rsplit(b') ', 1)
    need(len(parts) == 2, 'updater process stat is malformed')
    prefix, fields = parts
    fields = fields.split()
    need(prefix.split(b' ', 1)[0] == str(pid).encode() and len(fields) >= 20
         and fields[0] not in (b'Z', b'X') and fields[19].isdigit(),
         'updater process identity is not live')
    return int(fields[19])


def cohort_observation_owner(pid=None):
    """Identify a live guest Python process holding the exact update flock."""
    pid = os.getpid() if pid is None else pid
    start_time = cohort_process_start_time(pid)
    process = Path('/proc') / str(pid)
    argv = read_bounded_proc(process / 'cmdline', 4096).split(b'\0')
    need(argv == [b'/usr/bin/python3', b'-I', b'-', b''], 'updater process argv differs')
    lock_path = BASE / '.routine-update.lock'
    lock = stamp(lock_path)
    need(stat.S_ISREG(lock[2]) and lock[3] == 0 and lock[5] == 1
         and stat.S_IMODE(lock[2]) == 0o600, 'invalid guest update lock')
    device, inode = lock[:2]
    matches = []
    for line in read_bounded_proc(Path('/proc/locks'), 1024 * 1024).splitlines():
        row = line.split()
        if len(row) != 8 or row[1:5] != [b'FLOCK', b'ADVISORY', b'WRITE', str(pid).encode()]:
            continue
        identity = row[5].split(b':')
        if len(identity) == 3 and row[6:] == [b'0', b'EOF']:
            major, minor, number = int(identity[0], 16), int(identity[1], 16), int(identity[2])
            if (major, minor, number) == (os.major(device), os.minor(device), inode):
                matches.append(row)
    need(len(matches) == 1, 'updater no longer holds the exact update flock')
    need(stamp(lock_path) == lock and cohort_process_start_time(pid) == start_time
         and read_bounded_proc(process / 'cmdline', 4096).split(b'\0') == argv,
         'updater process or lock changed during observation')
    return {'pid': pid, 'start_time_ticks': start_time,
            'argv': ['/usr/bin/python3', '-I', '-'], 'lock': {'device': device, 'inode': inode}}



DEPLOYMENT_STATE_ROOT = Path('/var/lib/taira-deployment')


def stopped_owner_maintenance(operation):
    """Let the native custody owner retire only the proven stopped cohort."""
    request_name = 'stopped-owner-maintenance-request.json'
    record(request_name, {
        'schema': 'taira.stopped-owner-maintenance.request.v1',
        'operation_directory': str(ATTEMPT), 'owner': cohort_observation_owner()})
    # The candidate verifies its direct parent, the held update flock, all four
    # stopped units and retained roots before taking the existing slot locks.
    # Only public process/plan identities cross this descriptor; Python never
    # opens custody files or performs native owner cleanup itself.
    request_fd = os.open(ATTEMPT / request_name, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = command([CLI, 'taira', 'stopped-owner-maintenance',
                       '--request-fd', str(request_fd)], timeout=150,
                      name='stopped-owner-maintenance-command', pass_fds=(request_fd,))
    finally:
        os.close(request_fd)
    need(len(raw) <= 16_384, 'native stopped-owner maintenance report exceeds bound')
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeError):
        raise RuntimeError('native stopped-owner maintenance report is not valid JSON') from None
    need(isinstance(report, dict)
         and set(report) == {'schema', 'operation', 'all_four_stopped_owners_clean'}
         and report['schema'] == 'taira.stopped-owner-maintenance.result.v1'
         and report['operation'] == operation
         and report['all_four_stopped_owners_clean'] is True,
         'native stopped-owner maintenance did not prove the exact stopped cohort')


CONFIG_RETIREMENT_FIELDS = {'role', 'source_path', 'staged_path', 'original_path', 'changed',
                            'source_sha256', 'output_sha256', 'before_stamp', 'staged_stamp'}


def valid_config_stamp(value):
    """Validate only public filesystem metadata; configuration bytes stay native-owned."""
    return (isinstance(value, list) and len(value) == 9
            and all(type(part) is int and part >= 0 for part in value)
            and stat.S_ISREG(value[2]) and not value[2] & 0o022
            and value[3] == 0 and value[5] == 1)


def validate_config_retirement(report, operation, action, before, prepared=None):
    """Bind native evidence to the unchanged cohort and exact metadata transition."""
    stage = {'prepare': 'prepared', 'install': 'installed', 'restore': 'restored'}[action]
    need(isinstance(report, dict)
         and set(report) == {'schema', 'operation', 'source_commit', 'network_id', 'rows'}
         and report['schema'] == 'taira.validator-config-retirement.' + stage + '.v1'
         and report['operation'] == operation and report['source_commit'] == CANDIDATE_COMMIT
         and report['network_id'] == NETWORK and isinstance(report['rows'], list)
         and len(report['rows']) == len(before) == len(ROLES) == 4,
         'native config retirement receipt identity differs')
    need(action == 'prepare' or prepared is not None, 'native preparation receipt required')
    extra = set() if action == 'prepare' else {stage + '_stamp'}
    for index, (role, row, original) in enumerate(zip(ROLES, report['rows'], before, strict=True)):
        source = retained_config(role)
        staged = source.with_name('.' + source.name + '.' + operation + '.retirement-next')
        backup = source.with_name('.' + source.name + '.' + operation + '.retirement-original')
        need(isinstance(row, dict) and set(row) == CONFIG_RETIREMENT_FIELDS | extra
             and row['role'] == original['role'] == role
             and row['source_path'] == str(source) and row['staged_path'] == str(staged)
             and row['original_path'] == str(backup) and type(row['changed']) is bool
             and all(isinstance(row[key], str) and re.fullmatch('[0-9a-f]{64}', row[key])
                     for key in ('source_sha256', 'output_sha256'))
             and row['changed'] == (row['source_sha256'] != row['output_sha256'])
             and valid_config_stamp(row['before_stamp']) and valid_config_stamp(row['staged_stamp'])
             and row['before_stamp'] == original['config_stamp'],
             'native config retirement row differs from retained original')
        if prepared is not None:
            need({key: row[key] for key in CONFIG_RETIREMENT_FIELDS} == prepared['rows'][index],
                 'native config retirement changed its preparation')
        if action == 'prepare':
            need(stamp(source) == row['before_stamp'] and stamp(staged) == row['staged_stamp'],
                 'native staged configuration metadata changed')
        else:
            final = row[stage + '_stamp']
            need(valid_config_stamp(final) and stamp(source) == final,
                 'native installed/restored configuration metadata changed')
            if action == 'install':
                need(final != row['before_stamp'] if row['changed'] else final == row['before_stamp'],
                     'native no-op or changed config transition differs')
    return report


def retire_validator_configs(operation, action, before, prepared=None):
    """Dispatch the native adapter once; consume only its bounded public receipt."""
    need(action in ('prepare', 'install', 'restore'), 'unknown config retirement action')
    stage = {'prepare': 'prepared', 'install': 'installed', 'restore': 'restored'}[action]
    request_name = 'config-retirement-' + action + '-request.json'
    record(request_name, {'schema': 'taira.validator-config-retirement.request.v1',
                         'operation_directory': str(ATTEMPT), 'owner': cohort_observation_owner()})
    request_fd = os.open(ATTEMPT / request_name, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = command([CLI, 'taira', 'retire-validator-config', '--action', action,
                       '--request-fd', str(request_fd)], timeout=150,
                      name='config-retirement-' + action + '-command', pass_fds=(request_fd,))
    finally:
        os.close(request_fd)
    need(len(raw) <= 65_536, 'native config retirement report exceeds bound')
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeError):
        raise RuntimeError('native config retirement report is not valid JSON') from None
    validate_config_retirement(report, operation, action, before, prepared)
    # Native owns durable receipt publication. Python cannot invent a config transition
    # from stdout alone or overwrite the evidence used by later runtime verification.
    need(retained_public_record(ATTEMPT, 'config-retirement-' + stage + '.json') == report,
         'native config retirement report differs from its published receipt')
    return report


def verify_cohort_observation_owner(intent):
    """Read-only proof of an active observation owner; never acquire its lock."""
    need(intent.get('schema') == COHORT_OBSERVATION_SCHEMA
         and intent.get('operation') == ATTEMPT.name and intent.get('phase') == 'cohort_observation'
         and re.fullmatch('[0-9a-f]{40}', intent.get('commit', ''))
         and DAEMON == BASE / ('release-' + intent['commit'] + '-' + ATTEMPT.name) / 'bin/iroha3d_taira'
         and intent.get('automatic_restart_or_rollback_after_start') is False
         and intent.get('remaining_actions') == list(COHORT_REMAINING_ACTIONS),
         'cohort observation intent differs')
    terminal = [ATTEMPT / name for name in ('result.json', 'failure.json', 'rollback.json')]
    need(not any(os.path.lexists(path) for path in terminal), 'cohort observation already terminated')
    expected = intent['owner']
    owner = cohort_observation_owner(expected['pid'])
    need(owner == expected and not any(os.path.lexists(path) for path in terminal),
         'cohort observation owner changed or terminated')
    return owner


def retained_public_record(directory, name, digest=None, budget=None):
    """Read a bounded root-owned public receipt, optionally pinned by captured bytes."""
    path = directory / name
    before = stamp(path)
    need(before[6] <= 8 * 1024 * 1024, 'retained public record exceeds bound')
    raw = path.read_bytes()
    need(before == stamp(path), 'retained public record changed during read')
    if digest is not None:
        need(re.fullmatch('[0-9a-f]{64}', digest)
             and hashlib.sha256(raw).hexdigest() == digest, 'failed-start public record digest differs')
    if budget is not None:
        budget.consume(raw)
    return json.loads(raw)


def validate_installation_observation(value, deployment):
    """A first observation has no previous upgrade or checkpoint claim."""
    need(set(value) == {'schema', 'commit', 'network_id', 'renderer_sha256', 'units',
                       'observations', 'secret_contents_read', 'runtime_mutated'}
         and value['schema'] == 'taira.installed-cohort-observation.v1'
         and value['commit'] == deployment['current']['commit']
         and value['network_id'] == deployment['network_id']
         and value['renderer_sha256'] == deployment['renderer_sha256']
         and value['secret_contents_read'] is False and value['runtime_mutated'] is False,
         'first-adoption observation contract differs')
    roles = deployment['roles']
    need([row['role'] for row in value['units']] == roles
         and [row['role'] for row in value['observations']] == roles,
         'first-adoption observation lacks exact cohort')
    for row, observed in zip(value['units'], value['observations'], strict=True):
        need(set(row) == {'role', 'installed', 'installed_sha256'}, 'observed unit fields differ')
        raw = base64.b64decode(row['installed'], validate=True)
        need(len(raw) <= 128 * 1024 and hashlib.sha256(raw).hexdigest() == row['installed_sha256'],
             'observed unit digest differs')
        expected = deployment['current']['daemons'][row['role']]
        need(unit_command(raw) == [expected['command'], '--config',
             str(Path(deployment['config_root']) / row['role'] / 'current/config' / deployment['config_filename']),
             '--sora'], 'observed unit command differs')
        need(set(observed) == {'role', 'unit_stamp', 'config_stamp', 'state_root_identity',
                              'current_target', 'executable', 'systemd', 'public', 'daemon_stamp'}
             and observed['executable'] == expected['resolved']
             and observed['public']['commit'] == value['commit']
             and observed['public']['network_id'] == value['network_id']
             and type(observed['public']['height']) is int
             and observed['public']['height'] >= deployment['replay_floor']
             and len(observed['config_stamp']) == len(observed['daemon_stamp']) == 9,
             'observed process, public identity or custody differs')


def verify_initial_daemon(role):
    expected = INITIAL_DAEMONS[role]
    path = Path(expected['resolved'])
    need(Path(expected['command']).resolve() == path, 'observed daemon selector changed')
    identity = stamp(path)
    need(identity[6] == expected['size'] and native_digest(path) == expected['sha256']
         and stamp(path) == identity, 'observed installed daemon identity differs')
    return identity


def capture_installation(request):
    """Read public units/native status and private metadata under the lifecycle lock."""
    deployment = request['deployment']
    need(deployment['schema'] == 'taira.runtime-deployment.v2'
         and deployment['current']['kind'] == 'observed-installation',
         'capture requires the explicit initial deployment schema')
    with deployment_locks(request):
        configure(request)
        rows, observations = [], []
        for role in ROLES:
            fragment = Path('/etc/systemd/system') / f'iroha3d-{role}.service'
            before = stamp(fragment)
            need(before[6] <= 128 * 1024, 'public unit exceeds bound')
            raw = fragment.read_bytes()
            need(stamp(fragment) == before, 'public unit changed during capture')
            replace_daemon(raw, role)  # Validate the exact existing command, without writing.
            encoded = base64.b64encode(raw).decode()
            row = {'role':role, 'before':encoded}
            observed = observe(row, expected_commit=OLD, minimum_height=REPLAY_BARRIER)
            observed['daemon_stamp'] = verify_initial_daemon(role)
            need(observed['unit_stamp'] == before, 'public unit changed during observation')
            rows.append({'role':role, 'installed':encoded, 'installed_sha256':hashlib.sha256(raw).hexdigest()})
            observations.append(observed)
        result = {'schema':'taira.installed-cohort-observation.v1', 'commit':OLD,
                  'network_id':NETWORK, 'renderer_sha256':deployment['renderer_sha256'],
                  'units':rows, 'observations':observations,
                  'secret_contents_read':False, 'runtime_mutated':False}
        validate_installation_observation(result, deployment)
        print(json.dumps(result), flush=True)


def retained_attempt(plan):
    """Verify completion separately from an explicitly authenticated failed installation."""
    prior = plan['retained_predecessor']
    if PREDECESSOR.get('kind') == 'observed-installation':
        need(plan['schema'] == 'taira.daemon-update.plan.v2' and 'failed_start' not in plan
             and set(prior) == {'schema', 'observation', 'observation_sha256'}
             and prior['schema'] == 'taira.observed-installation-predecessor.v1',
             'first adoption requires its explicit observed predecessor')
        observation = prior['observation']
        need(hashlib.sha256(json.dumps(observation, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
             == prior['observation_sha256'], 'installed observation digest differs')
        validate_installation_observation(observation, plan['deployment'])
        before, checkpoints = [], []
        for original, row, captured in zip(observation['units'], plan['units'], observation['observations'], strict=True):
            need(original['installed'] == row['before'] and original['installed_sha256'] == row['before_sha256'],
                 'adoption changed the observed unit')
            fresh = observe(row, expected_commit=OLD, minimum_height=captured['public']['height'])
            compare_retained_identity(captured, fresh)
            need(captured['unit_stamp'] == fresh['unit_stamp']
                 and captured['systemd']['InvocationID'] == fresh['systemd']['InvocationID']
                 and captured['systemd']['MainPID'] == fresh['systemd']['MainPID'],
                 'observed validator process or unit changed before adoption')
            need(verify_initial_daemon(row['role']) == captured['daemon_stamp'],
                 'observed daemon custody changed before adoption')
            before.append(fresh)
            # This is genuine current native evidence, never a claimed previous
            # update checkpoint. The stopped barrier is captured again below.
            checkpoints.append(checkpoint_barrier(fresh))
        return before, checkpoints
    need(prior['attempt_name'] == PREDECESSOR['attempt_name'], 'installed predecessor required')
    directory = BASE / prior['attempt_name']
    stamp(directory, True)

    def public_record(name):
        return retained_public_record(directory, name)

    intent = public_record('intent.json')
    reject_retired_worker_plan(intent)
    digest = hashlib.sha256(json.dumps(intent, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    need(digest == prior['intent_sha256'], 'predecessor intent differs')
    need(intent.get('schema') == PREDECESSOR['plan_schema']
         and intent['network_id'] == plan['network_id'] and intent['commit'] == PREDECESSOR['commit']
         and plan['commit'] != PREDECESSOR['commit'],
         'installed predecessor source or candidate differs')
    need(tuple(row['role'] for row in intent['units']) == ROLES, 'predecessor plan lacks exact cohort')
    before = public_record('after.json')
    checkpoints = public_record('checkpoint-stopped.json')
    restored = public_record('checkpoint-restored.json')
    need(tuple(row['role'] for row in before) == ROLES
         and tuple(row['role'] for row in checkpoints) == ROLES
         and tuple(row['role'] for row in restored) == ROLES, 'predecessor evidence lacks exact cohort')
    need(all(row['public']['commit'] == PREDECESSOR['commit']
             and row['public']['network_id'] == NETWORK for row in before),
         'installed predecessor runtime differs')
    strict_modes = [require_retained_restore_proof(recovered, checkpoint, source=PREDECESSOR['commit'],
        network=NETWORK, allow_authenticated_replay=plan['schema'].endswith('.v2'))
        for recovered, checkpoint in zip(restored, checkpoints, strict=True)]
    completed = public_record('result.json')
    require_completed_restore_modes(completed, strict_modes, modern=plan['schema'].endswith('.v2'))
    need(completed.get('schema') == PREDECESSOR['result_schema']
         and completed.get('runtime_update_complete') is True
         and completed.get('state_preserved') is True
         and completed.get('commit') == PREDECESSOR['commit'] and completed.get('network_id') == NETWORK,
         'installed predecessor completion receipt differs')
    installed_plan = intent
    if 'failed_start' in plan:
        reference = plan['failed_start']
        need(set(reference) == {'schema', 'attempts', 'installed'}
             and set(reference['installed']) == {'commit', 'attempt_name', 'daemon'},
             'failed-start chain plan fields differ')
        budget = FailedStartRecordBudget()

        def load_attempt(ref):
            directory = BASE / ref['operation']
            stamp(directory, True)
            # Partial observations never substitute for a terminal outcome.
            for name in ('result.json', 'rollback.json'):
                need(not os.path.lexists(directory / name),
                     'failed-start attempt has a success or rollback marker: ' + name)
            records = {name: retained_public_record(directory, name, value['sha256'], budget)
                       for name, value in ref['records'].items()}
            return records['intent.json'], records

        public_reference = {key: value for key, value in reference.items() if key != 'installed'}
        installed, entries = validate_failed_start_chain(
            public_reference, plan['deployment'], intent, plan['operation'], load_attempt,
            baseline_observations=before, candidate=plan)
        need(installed == reference['installed'] and installed['commit'] == OLD
             and installed['daemon'] == str(PREVIOUS_DAEMON), 'failed-start installed identity differs')
        # Verify every retained ancestor prefix in the live journal. The final
        # stop barrier independently freezes and verifies the newest prefix.
        for failed, records in entries:
            for checkpoint in records['checkpoint-stopped.json']:
                require_retained_tip(checkpoint['role'], checkpoint['kura_tip'])
        installed_plan, records = entries[-1]
        for artifact, path in zip(installed_plan['artifacts'],
                                  (PREVIOUS_DAEMON, PREVIOUS_DAEMON.with_name('iroha'),
                                   PREVIOUS_DAEMON.with_name('kagami')), strict=True):
            need(native_digest(path) == artifact['sha256'] and stamp(path)[6] == artifact['size'],
                 'failed-start installed artifact differs')
        before, checkpoints = records['before.json'], records['checkpoint-stopped.json']
    validate_candidate_transition(plan['commit'], plan['artifacts'], PREDECESSOR['commit'],
                                  installed_plan)
    for original, current in zip(installed_plan['units'], plan['units'], strict=True):
        need(original['after'] == current['before'] and original['after_sha256'] == current['before_sha256'],
             'successor changed installed predecessor unit')
    return before, checkpoints


def apply(plan, capacity_source):
    global CONFIG_RETIREMENT
    validate_update_plan_shape(plan)
    configure(plan)
    need(os.geteuid() == 0 and plan['network_id'] == NETWORK, 'guest or network differs')
    need(plan['commit'] != PREDECESSOR['commit'], 'candidate cannot repeat the completed runtime')
    need(tuple(row['role'] for row in plan['units']) == ROLES, 'four ordered roles required')
    need([row['name'] for row in plan['artifacts']] == ['iroha3d_taira', 'iroha', 'kagami'],
         'exact same-release daemon, CLI and Kagami required')
    capacity_before = storage_capacity(plan, capacity_source, 'apply')
    retained = retained_attempt(plan)
    # Installed unit bytes and retained config/state metadata bind the old cohort.
    # A crash-looping peer need not answer HTTP before the cohort is stopped.
    for artifact, path in zip(plan['artifacts'], (DAEMON, CLI, KAGAMI), strict=True):
        need(native_digest(path) == artifact['sha256'], 'candidate digest differs')
        need(stamp(path)[6] == artifact['size'], 'candidate size differs')
        candidate_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(candidate_fd)
        finally:
            os.close(candidate_fd)
    for directory in (DAEMON.parent, DAEMON.parent.parent, BASE):
        sync(directory)
    need(not os.path.lexists(ATTEMPT), 'attempt exists; inspect it instead of repeating mutations')
    ATTEMPT.mkdir(mode=0o700)
    sync(BASE)
    record('intent.json', plan)
    record('capacity-before-apply.json', capacity_before)
    # --version reports package semver, not a source commit. The candidate digest
    # binds the approved build here; /status verifies actual source after start.
    version = command([DAEMON, '--version'], name='candidate-version').decode()
    need(version.startswith('iroha3d '), 'candidate is not the native Iroha daemon')
    before = []
    for index, row in enumerate(plan['units']):
        raw = base64.b64decode(row['before'], validate=True)
        after = base64.b64decode(row['after'], validate=True)
        need(replace_daemon(raw, row['role']) == after, 'unit changes exceed approved cmd[0]')
        snapshot = dict(retained[0][index])
        identity = retained_identity(row)
        compare_retained_identity(snapshot, identity)
        # Health stays the last completed observation. Unit metadata and the
        # executable describe the installed release, which may have failed.
        snapshot['unit_stamp'] = identity['unit_stamp']
        if 'executable' in identity:
            snapshot['executable'] = identity['executable']
        snapshot.pop('config_sha256', None)  # The exact retained metadata is checked; no private rehash.
        need(snapshot['public']['commit'] == PREDECESSOR['commit'], 'predecessor runtime differs')
        before.append(snapshot)
        write_new(ATTEMPT / (row['role'] + '.before.service'), raw)
        write_new(ATTEMPT / (f'iroha3d-{row["role"]}.service'), after, snapshot['unit_stamp'][2] & 0o7777)
    record('retained-entry.json', before)
    # Native retirement owns the v2 retained installation. The v1 recovery corridor
    # keeps its existing config validation and never invokes the v2-only adapter.
    prepared_configs = (retire_validator_configs(plan['operation'], 'prepare', before)
                        if plan['schema'].endswith('.v2') else None)
    check_paths = ([Path(row['staged_path']) for row in prepared_configs['rows']]
                   if prepared_configs is not None else [retained_config(role) for role in ROLES])
    for index, config in enumerate(check_paths):
        native_private_command([DAEMON, '--config', config, '--genesis-manifest-json',
                 GENESIS_MANIFEST, '--sora', '--check-config'],
                timeout=90, name=f'check-config-{index+1}')
    command(['/usr/bin/systemd-analyze', 'verify',
             *[ATTEMPT / (f'iroha3d-{row["role"]}.service') for row in plan['units']]],
            name='verify-units')
    record('capacity-before-stop.json', storage_capacity(plan, capacity_source, 'apply'))
    installed = []
    new_start_attempted = False
    validator_stop_attempted = False
    validator_stop_confirmed = False
    config_install_attempted = False
    try:
        record('stop-intent.json', {'units': UNITS, 'configuration_or_ledger_mutation': False})
        validator_stop_attempted = True
        stopped = stop_all()
        validator_stop_confirmed = True
        record('stopped.json', {'all_four_stopped': True, 'observations': stopped})
        for row, state in zip(before, stopped, strict=True):
            row['systemd'] = state['systemd']
        record('before.json', before)
        checkpoints = [checkpoint_barrier(row, stopped=True, prior=prior)
                       for row, prior in zip(before, retained[1], strict=True)]
        record('checkpoint-stopped.json', checkpoints)
        retained_tip = verify_stopped_cohort_prefixes(checkpoints)
        record('cohort-retained-tip.json', retained_tip)
        stopped_owner_maintenance(plan['operation'])
        if prepared_configs is not None:
            config_install_attempted = True
            CONFIG_RETIREMENT = retire_validator_configs(plan['operation'], 'install', before, prepared_configs)
        for row, original in zip(plan['units'], before, strict=True):
            path = Path('/etc/systemd/system') / f'iroha3d-{row["role"]}.service'
            install_unit(path, base64.b64decode(row['after']), base64.b64decode(row['before']),
                         original['unit_stamp'][2] & 0o7777)
            installed.append(row)
        command(['/usr/bin/systemctl', 'daemon-reload'], name='daemon-reload')
        for checkpoint in checkpoints:
            need(snapshot_selection(checkpoint['role']) == checkpoint['selection'],
                 'retained checkpoint changed before new runtime startup')
            need(native_kura_tip(checkpoint['role']) == checkpoint['kura_tip'],
                 'stopped Kura tip changed before new runtime startup')
        # An uncertain start-intent publication closes the rollback boundary too.
        # Native restoration refuses any retained intent even when start was not reached.
        new_start_attempted = True
        record('start-intent.json', {'units': UNITS, 'automatic_old_binary_rollback_after_start': False})
        command(['/usr/bin/systemctl', 'start', *UNITS], timeout=150, name='start')
        startup_processes = [{'role': role, 'systemd': systemd(unit)}
                             for role, unit in zip(ROLES, UNITS, strict=True)]
        need(all(row['systemd']['NRestarts'] == '0' for row in startup_processes),
             'validator restarted before startup process capture')
        verify_cohort_processes(startup_processes)
        record('startup-processes.json', startup_processes)
        record('cohort-observation-intent.json', {
            'schema': COHORT_OBSERVATION_SCHEMA, 'operation': plan['operation'],
            'commit': plan['commit'], 'phase': 'cohort_observation',
            'owner': cohort_observation_owner(),
            'automatic_restart_or_rollback_after_start': False,
            'remaining_actions': list(COHORT_REMAINING_ACTIONS)})
        minimum_heights = [row['kura_tip']['height'] for row in checkpoints]
        initial_samples = []
        after = wait_for_cohort(plan['units'], before, after=True, commit=plan['commit'],
                                retained_tip=retained_tip, startup_processes=startup_processes,
                                minimum_heights=minimum_heights, sample_receipts=initial_samples)
        record('after.json', after)
        record('cohort-initial-quorum.json', {'samples': initial_samples})
        restored = [verify_restored_checkpoint(row, checkpoint,
                    **({'allow_authenticated_replay': True} if plan['schema'].endswith('.v2') else {}))
                    for row, checkpoint in zip(after, checkpoints, strict=True)]
        record('checkpoint-restored.json', restored)
        # Public doctor is an independently invoked diagnostic. Deployment
        # completion depends on the actual cohort, retained state and readiness.
        final_samples = []
        final = wait_for_cohort(plan['units'], before, after=True, commit=plan['commit'],
                                retained_tip=retained_tip, startup_processes=startup_processes,
                                verified=after, minimum_heights=minimum_heights,
                                sample_receipts=final_samples)
        if any(row.get('native_authenticated_kura_replay_verified') is True for row in restored):
            need(all(row['cohort_observation']['ready'] is True
                     and row['cohort_observation']['public_fresh'] is True for row in final),
                 'all four replayed runtime peers must remain freshly Ready')
        for observed, checkpoint in zip(final, checkpoints, strict=True):
            require_retained_tip(observed['role'], checkpoint['kura_tip'])
        record('cohort-ready.json', {'retained_tip': retained_tip, 'observations': final,
                                     'quorum_confirmations': final_samples,
                                     'startup_processes_unchanged': True})
        verify_cohort_processes(final, startup_processes)
        result = {'schema': ('taira.daemon-update.result.v2' if plan['schema'].endswith('.v2')
                             else 'taira.daemon-update.result.v1'), 'runtime_update_complete': True,
                  'commit': plan['commit'], 'network_id': NETWORK, 'state_preserved': True,
                  'canary_applied_verified': False, 'application_ready': False,
                  'retained_native_snapshot_verified': all(row['native_strict_checkpoint_verified'] for row in restored),
                  'cohort_retained_tip_verified': retained_tip,
                  'cohort_quorum': final_samples[-1],
                  'cohort_fresh_quorum_confirmations': len(final_samples),
                  'cohort_processes_verified_after_final_observation': True,
                  'all_own_retained_tips_verified_after_final_observation': True,
                  'historical_genesis_replay_supported': False,
                  'historical_replay_limitation': 'Preserve the authenticated current snapshot at or after the deployment replay floor. No historical blocks were rewritten.',
                  'next_action': 'prove a fresh signed transaction Applied under the new runtime'}
        if plan['schema'].endswith('.v2'):
            result['retained_native_state_verified'] = True
            result['native_recovery_modes'] = [row.get('proof_kind', 'native_strict_restore') for row in restored]
            if not result['retained_native_snapshot_verified']:
                result['historical_genesis_replay_supported'] = True
                result['historical_replay_limitation'] = ('Native policy required reexecution of original signed genesis and every certified Kura block; the retained canonical prefix is unchanged. Snapshot cache bytes were not used as executed World authority.')
        record('result.json', result)
        print(json.dumps(result), flush=True)
    except BaseException as error:
        try:
            record('failure.json', {'error': str(error), 'new_start_attempted': new_start_attempted,
                'validator_stop_attempted': validator_stop_attempted,
                'validator_stop_confirmed': validator_stop_confirmed,
                'installed_units': [row['role'] for row in installed]})
        finally:
            # Failure-record I/O must not suppress candidate containment.
            if new_start_attempted:
                # Keep the failed candidate and its retained state for diagnosis,
                # while preventing the service supervisor from repeating failures.
                # The caller still owns the deployment lock throughout containment.
                command(['/usr/bin/systemctl', 'stop', *UNITS], timeout=150,
                        name='failed-start-stop')
                stopped = [{'unit': unit, 'systemd': systemd(unit)} for unit in UNITS]
                need(all(row['systemd']['MainPID'] == row['systemd']['ControlPID'] == '0'
                         and row['systemd']['ActiveState'] in ('inactive', 'failed')
                         for row in stopped), 'failed candidate cohort stop incomplete')
                record('failed-start-stopped.json', {'all_four_stopped': True,
                                                   'observations': stopped})
            elif validator_stop_confirmed:
                # No new daemon was allowed to execute retained state. Restore all
                # old units, including any replacement completed before an I/O error.
                for row, original in zip(plan['units'], before, strict=True):
                    path = Path('/etc/systemd/system') / f'iroha3d-{row["role"]}.service'
                    current = path.read_bytes()
                    old = base64.b64decode(row['before'])
                    new = base64.b64decode(row['after'])
                    need(current in (old, new), 'unit has an unknown rollback successor')
                    if current != old:
                        install_unit(path, old, new, original['unit_stamp'][2] & 0o7777)
                config_restored = None
                if config_install_attempted:
                    config_restored = retire_validator_configs(plan['operation'], 'restore', before, prepared_configs)
                    CONFIG_RETIREMENT = None
                command(['/usr/bin/systemctl', 'daemon-reload'], name='rollback-reload')
                restored = []
                for unit in UNITS:
                    state = systemd(unit)
                    need((state['ActiveState'], state['SubState']) in (('inactive', 'dead'), ('failed', 'failed'))
                         and state['MainPID'] == state['ControlPID'] == '0' and state['Job'] == '',
                         'rollback did not retain the paused cohort: ' + unit)
                    restored.append({'unit': unit, 'systemd': state})
                rollback = {'restored_previous_stopped_cohort': True,
                            'old_daemons_restarted': False, 'observations': restored}
                if config_restored is not None:
                    rollback.update(config_retirement_restored_receipt='config-retirement-restored.json',
                                    restored_config_stamps=[{'role': row['role'], 'config_stamp': row['restored_stamp']}
                                                           for row in config_restored['rows']],
                                    config_identity_reconciliation_required=any(
                                        row['restored_stamp'] != row['before_stamp']
                                        for row in config_restored['rows']))
                record('rollback.json', rollback)
            else:
                # An ambiguous stop is never retried. Before-stop failures leave
                # validators untouched; partial-stop failures require read-only
                # manager reconciliation and admit no unit or state mutation.
                record('reconciliation-required.json', {
                    'validator_stop_attempted': validator_stop_attempted,
                    'validator_stop_confirmed': False, 'recovery_only': True,
                    'automatic_manager_retry': False})
        raise


def verify_prepared_artifacts(plan):
    """Observe all three preprovisioned binaries; never create or replace one."""
    import fcntl
    need(os.geteuid() == 0, 'artifact verification requires root')
    reject_retired_worker_plan(plan)
    identity = artifact_identity(plan['artifacts'])
    need(re.fullmatch('[0-9a-f]{40}', plan['commit'])
         and re.fullmatch('update-[0-9a-f]{32}', plan['operation']), 'invalid prepared operation')
    root = stamp(DEPLOYMENT_STATE_ROOT, True)
    need(stat.S_IMODE(root[2]) == 0o700 and root[4] == 0, 'deployment state root custody differs')
    path = DEPLOYMENT_STATE_ROOT / '.deployment.lock'
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
             and before.st_nlink == 1 and before.st_size == 0 and stat.S_IMODE(before.st_mode) == 0o600,
             'invalid prepared artifact deployment lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need((before.st_dev, before.st_ino) == tuple(stamp(path)[:2]), 'artifact deployment lock changed')
        reject_retired_epoch_worker()
        need(not os.path.lexists(DEPLOYMENT_STATE_ROOT / '.reset-owner.json'),
             'retained reset owner blocks artifact admission')
        base = Path(plan['deployment']['runtime_root'])
        release = base / ('release-' + plan['commit'] + '-' + plan['operation'])
        for directory in (base, release, release / 'bin'):
            metadata = stamp(directory, True)
            need(metadata[4] == 0 and stat.S_IMODE(metadata[2]) == 0o700,
                 'prepared artifact root custody differs')
        for name, package, digest, size in identity:
            binary = release / 'bin' / name
            metadata = stamp(binary)
            need(metadata[4] == 0 and stat.S_IMODE(metadata[2]) == 0o755
                 and metadata[6] == size and native_digest(binary) == digest
                 and stamp(binary) == metadata, 'preprovisioned candidate bytes or custody differ')
        print(json.dumps({'schema': 'taira.prepared-update-artifacts.v1',
            'operation': plan['operation'], 'commit': plan['commit'], 'artifacts': plan['artifacts'],
            'runtime_mutated': False}), flush=True)
    finally:
        os.close(fd)


@contextlib.contextmanager
def deployment_locks(plan):
    """Hold the same two exact owner locks for storage admission and mutation."""
    import fcntl
    global DEPLOYMENT_LOCK_FD
    held = []
    try:
        for root, name in ((Path(plan['deployment']['runtime_root']), '.routine-update.lock'),
                           (DEPLOYMENT_STATE_ROOT, '.deployment.lock')):
            metadata = stamp(root, True)
            if root == DEPLOYMENT_STATE_ROOT:
                need(stat.S_IMODE(metadata[2]) == 0o700 and metadata[4] == 0,
                     'deployment state root custody differs')
            path = root / name
            flags = os.O_RDWR | os.O_NOFOLLOW
            if name == '.routine-update.lock':
                flags |= os.O_CREAT
            fd = os.open(path, flags, 0o600)
            held.append(fd)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                 and before.st_nlink == 1 and before.st_size == 0 and stat.S_IMODE(before.st_mode) == 0o600,
                 'invalid guest deployment lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            need((before.st_dev, before.st_ino) == tuple(stamp(path)[:2]),
                 'guest deployment lock changed')
        DEPLOYMENT_LOCK_FD = held[-1]
        reject_retired_epoch_worker()
        need(not os.path.lexists(DEPLOYMENT_STATE_ROOT / '.reset-owner.json'),
             'retained reset owner blocks updater; never reclaim or clear it')
        yield
    finally:
        DEPLOYMENT_LOCK_FD = None
        for fd in reversed(held):
            os.close(fd)


def apply_locked(plan, capacity_source):
    """Hold both update flocks across stop, publication, restart and containment."""
    with deployment_locks(plan):
        apply(plan, capacity_source)
