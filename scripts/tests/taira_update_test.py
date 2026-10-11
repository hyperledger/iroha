"""Offline routine-update contracts; no Cargo, SSH or runtime signing inputs.

Run from a normal checkout with python3 scripts/tests/taira_update_test.py.
"""
import argparse
import ast
import base64
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import copy
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import taira_update as runner
import taira_validator_unit as renderer

# In a normal checkout these resolve to the same scripts directory. Keeping
# dependencies module-owned also permits an isolated source overlay in review.
ROOT = Path(renderer.__file__).resolve().parents[1]
runner.ROOT = ROOT
GUEST_FILE = SCRIPTS / 'taira_update_guest.py'
OPERATION = 'update-' + '1' * 32
CAPACITY_SOURCE = (SCRIPTS / 'taira_disk_capacity.py').read_bytes()


def fresh_guest():
    spec = importlib.util.spec_from_file_location('taira_update_guest_test', GUEST_FILE)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def deployment():
    return {'schema':'taira.runtime-deployment.v1', 'guest_ssh':{'argv':[], 'pins':[]},
        'backing_ssh':{'argv':[], 'pins':[]}, 'backing_path':'/approved/mac/guest',
        'runtime_root':'/private/runtime/taira', 'state_root':'/var/lib/taira',
        'config_root':'/srv/taira', 'config_release':'a'*40,
        'genesis_manifest':'/private/runtime/taira/genesis/genesis.json',
        'network_id':'hash:fixture', 'public_origin':'https://test.example',
        'roles':[f'taira-validator-{i}' for i in range(1,5)], 'ports':[8080,8081,8082,8083],
        'replay_floor':146, 'renderer_sha256':runner.sha((ROOT/'scripts/taira_validator_unit.py').read_bytes()),
        'current':{'commit':'b'*40, 'daemon':'/private/runtime/taira/selected/bin/iroha3d_taira',
          'attempt_name':'retained', 'plan_schema':'taira.daemon-update.plan.v1',
          'result_schema':'taira.daemon-update.result.v1', 'local_plan':'/owner/prior.json',
          'local_plan_sha256':'c'*64}}


def installed_unit(role):
    raw=renderer.render(role, '/fixture/retained/key', '/fixture/retained/seed').encode()
    old=f'/srv/taira/{role}/current/bin/iroha3d_taira'.encode()
    return raw.replace(old, deployment()['current']['daemon'].encode(), 1)


def fixture():
    value=deployment()
    build={'commit':'a'*40, 'target':'aarch64-unknown-linux-gnu', 'profile':'release',
        'environment_sha256':'e'*64,
        'jobs':6, 'source_unchanged':True, 'toolchain_unchanged':True,
        'deployed':False, 'release_qualified':False, 'native_check_scope':'basic',
        'artifacts':[{'name':name,'package':package,'path':'/public/'+name,
                      'sha256':'b'*64,'size':2_000_000}
            for name,package in [('iroha3d_taira','irohad'),('iroha','iroha_cli'),
                                 ('kagami','iroha_kagami'),('sorafs-node','sorafs_node')]]}
    prior={'schema':value['current']['plan_schema'], 'commit':value['current']['commit'],
        'network_id':value['network_id'], 'renderer_sha256':value['renderer_sha256'],
        'units':[{'role':role, 'after':base64.b64encode(installed_unit(role)).decode(),
                  'after_sha256':runner.sha(installed_unit(role))} for role in value['roles']]}
    return build,prior


def plan_for(build=None, prior=None, value=None, failed_start=None):
    global guest
    if build is None or prior is None:
        default_build,default_prior=fixture()
        build=default_build if build is None else build
        prior=default_prior if prior is None else prior
    guest=fresh_guest()
    return runner.make_plan(build, deployment() if value is None else value, prior, guest,
                            OPERATION, failed_start)


def admission_for(plan, phase='prepare', *, inspect=None):
    observer = fresh_guest()
    capacity = observer.load_capacity(plan, CAPACITY_SOURCE)
    capacity['inspect_filesystem'] = inspect or (lambda path: {
        'device': 1, 'anchor': str(path), 'fragment_bytes': 4096,
        'available_bytes': 32 * 1024**3, 'available_inodes': 100000})
    with patch.object(observer, 'load_capacity', return_value=capacity):
        return observer.storage_capacity(plan, CAPACITY_SOURCE, phase)


def failed_fixture(value=None, prior=None):
    build, default_prior = fixture()
    value = deployment() if value is None else value
    prior = default_prior if prior is None else prior
    failed = runner.make_plan(build, value, prior, fresh_guest(), 'update-' + '2' * 32)
    before = [{'role': role, 'unit_stamp': [1, 2, 0o100600, 0, 0, 1, 3, 4, 5],
               'config_stamp': [1, 4], 'state_root_identity': [1, 8], 'current_target': 'unchanged',
               'public': {'commit': value['current']['commit'], 'network_id': value['network_id'],
                          'height': 199}, 'systemd': {'InvocationID': 'e' * 32}}
              for role in value['roles']]
    checkpoints = [{'role': role, 'cohort_stopped': True, 'invocation_id': 'e' * 32,
                    'checkpoint_height': 199, 'kura_tip': {'height': 200, 'hash': 'c' * 64},
                    'selection': {'selector': 'b' * 64, 'pointer_stamp': [0] * 7 + [90_000]},
                    'native_events': [{'time_us': 100,
                                       'message': 'Successfully created a snapshot of state at_height=199'}],
                    'proof_invocation_id': 'e' * 32}
                   for role in value['roles']]
    records = {'intent.json': failed, 'before.json': before, 'checkpoint-stopped.json': checkpoints,
               'start-intent.json': {'units': [f'iroha3d-{role}.service' for role in value['roles']],
                                    'automatic_old_binary_rollback_after_start': False},
               'failure.json': {'error': 'native startup failure', 'new_start_attempted': True,
                   'validator_stop_attempted': True, 'validator_stop_confirmed': True,
                   'installed_units': value['roles']}}
    return failed, records


def write_failed_reference(directory, records):
    directory = Path(directory).resolve()
    directory.mkdir(exist_ok=True)
    refs = {}
    for name, value in records.items():
        path = directory / name
        raw = (json.dumps(value, sort_keys=True) + '\n').encode()
        path.write_bytes(raw)
        refs[name] = {'path': str(path), 'sha256': runner.sha(raw)}
    return {'schema': 'taira.failed-start-chain.v1', 'attempts': [
        {'operation': records['intent.json']['operation'],
         'plan': refs['intent.json'], 'records': refs}]}


def failed_chain_fixture(directory, commits=('a', 'c'), historical_second=False):
    """Create actual sequential failed plans, retaining completed baseline health."""
    build, prior = fixture()
    _, template = failed_fixture()
    chain = {'schema': 'taira.failed-start-chain.v1', 'attempts': []}
    entries = []
    for index, source in enumerate(commits):
        build['commit'] = source * 40
        failed = runner.make_plan(copy.deepcopy(build), deployment(), prior, fresh_guest(),
            'update-' + f'{index + 2:032x}', copy.deepcopy(chain) if index else None)
        if historical_second and index == 1:
            first = chain['attempts'][0]
            failed['failed_start'] = {'schema': 'taira.failed-start-reference.v1',
                'plan': first['plan'], 'records': first['records'],
                'installed': failed['failed_start']['installed']}
        records = copy.deepcopy(template)
        records['intent.json'] = failed
        for before, checkpoint in zip(records['before.json'], records['checkpoint-stopped.json']):
            before['systemd']['InvocationID'] = f'{index + 10:032x}'
            checkpoint['invocation_id'] = before['systemd']['InvocationID']
            # A failed startup may reuse the same authenticated checkpoint.
            checkpoint['proof_invocation_id'] = 'e' * 32
        ref = write_failed_reference(Path(directory) / failed['operation'], records)['attempts'][0]
        chain['attempts'].append(ref)
        entries.append((failed, records))
    return build, prior, chain, entries


def local_inputs(directory):
    build,prior=fixture();value=deployment()
    root=Path(directory).resolve()
    prior_path=root/'prior.json';prior_raw=json.dumps(prior).encode();prior_path.write_bytes(prior_raw)
    value['current'].update(local_plan=str(prior_path),local_plan_sha256=runner.sha(prior_raw))
    deployment_path=root/'deployment.json';deployment_path.write_text(json.dumps(value))
    build_path=root/'result.json';build_path.write_text(json.dumps(build))
    return value,build,deployment_path,build_path


def cli_argv(deployment_path,build_path,output):
    return ['taira_update.py','--deployment',str(deployment_path),'--prepared-result',str(build_path),
            '--output',str(output),'--operation',OPERATION,
            '--plan-only']


class CanonicalUpdateContractTests(unittest.TestCase):
    def test_preparation_scope_is_evidence_without_a_regression_deployment_gate(self):
        build, _ = fixture()
        for scope in ('build-only', 'basic', 'full'):
            with self.subTest(scope=scope):
                selected = runner.validate_build(dict(build, native_check_scope=scope), build['commit'])
                self.assertEqual([row['name'] for row in selected], ['iroha3d_taira', 'iroha', 'kagami'])
        for scope in ('unknown', None, False):
            with self.subTest(scope=scope), self.assertRaisesRegex(RuntimeError, 'maintained preparation'):
                runner.validate_build(dict(build, native_check_scope=scope), build['commit'])

    def test_unqualified_preparation_still_requires_release_provenance_and_artifact_identity(self):
        build, _ = fixture()
        build['native_check_scope'] = 'build-only'
        for key, value in (('profile', 'dev'), ('source_unchanged', False),
                           ('toolchain_unchanged', False), ('release_qualified', True),
                           ('target', 'x86_64-unknown-linux-gnu')):
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'maintained preparation'):
                runner.validate_build(dict(build, **{key: value}), build['commit'])
        changed = copy.deepcopy(build)
        changed['artifacts'][0]['sha256'] = 'invalid'
        with self.assertRaisesRegex(RuntimeError, 'artifact identity'):
            runner.validate_build(changed, build['commit'])

    def test_retired_supervisor_option_is_rejected_before_observation_or_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, descriptor, result = local_inputs(directory)
            with patch.object(sys, 'argv', cli_argv(descriptor, result, descriptor.parent/'out')
                              + ['--supervisor-plan', '/retired.json']), \
                 patch.object(runner.subprocess, 'check_output') as observation, \
                 patch.object(runner.subprocess, 'run') as dispatch, \
                 patch.object(runner, 'read_public') as read, \
                 __import__('contextlib').redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    runner.main()
                self.assertEqual(error.exception.code, 2)
                observation.assert_not_called(); dispatch.assert_not_called(); read.assert_not_called()

    def test_update_contract_rejects_retired_and_unknown_fields_before_guest_action(self):
        plan = plan_for()
        for field in ('epoch_supervisor', 'epoch_supervisor_installed',
                      'epoch_supervisor_renderer_sha256', 'maintenance_admin_identity', 'unknown'):
            value = dict(plan, **{field: {}})
            observer = fresh_guest()
            with self.subTest(field=field), patch.object(observer, 'configure') as configure, \
                 patch.object(observer, 'storage_capacity') as capacity:
                with self.assertRaisesRegex(RuntimeError, 'canonical contract'):
                    observer.apply(value, CAPACITY_SOURCE)
                configure.assert_not_called(); capacity.assert_not_called()
        for field in ('secret_contents_read', 'transaction_submission', 'python_transaction_submission'):
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'custody claims'):
                runner.validate_update_plan_shape(dict(plan, **{field: True}))
        self.assertFalse(plan['transaction_submission'])
        self.assertEqual(set(plan) & {'epoch_supervisor', 'epoch_supervisor_installed'}, set())


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        plan_for()

    def test_cli_failed_start_uses_installed_units_without_promoting_failed_health(self):
        with tempfile.TemporaryDirectory() as temporary:
            value, build, descriptor, result = local_inputs(temporary)
            prior = json.loads(Path(value['current']['local_plan']).read_bytes())
            failed, records = failed_fixture(value, prior)
            reference = write_failed_reference(descriptor.parent / 'failed', records)
            reference_path = descriptor.parent / 'failed-reference.json'
            reference_path.write_text(json.dumps(reference))
            build['commit'] = 'c' * 40
            result.write_text(json.dumps(build))
            output = descriptor.parent / 'corrective.json'
            with patch.object(sys, 'argv', cli_argv(descriptor, result, output) +
                              ['--failed-start-chain', str(reference_path)]), \
                 patch.object(runner.subprocess, 'check_output', return_value='optimizations\n'), \
                 patch.object(runner.retry, 'validate_ssh', return_value=['approved']), \
                 patch.object(runner.subprocess, 'run') as remote, \
                 patch.object(runner, 'apply_plan') as apply, redirect_stdout(io.StringIO()):
                runner.main()
            remote.assert_not_called(); apply.assert_not_called()
            plan = json.loads(output.read_bytes())
            self.assertEqual(plan['deployment'], value)
            self.assertEqual(plan['retained_predecessor'], failed['retained_predecessor'])
            self.assertEqual(plan['failed_start']['installed']['commit'], failed['commit'])
            self.assertEqual(plan['failed_start']['attempts'][-1]['records'], reference['attempts'][-1]['records'])
            for previous, current in zip(failed['units'], plan['units'], strict=True):
                self.assertEqual(current['before'], previous['after'])
                self.assertEqual(current['before_sha256'], previous['after_sha256'])
            self.assertNotIn('accepted_health', plan['failed_start'])
            self.assertNotEqual(runner.release_name(plan), runner.release_name(failed))
            with patch.object(sys, 'argv', cli_argv(descriptor, result, output) +
                              ['--failed-start-chain', str(reference_path)]), \
                 patch.object(runner.subprocess, 'check_output', return_value='optimizations\n'), \
                 patch.object(runner.retry, 'validate_ssh', return_value=['approved']), \
                 patch.object(runner.subprocess, 'run') as remote:
                with self.assertRaises(FileExistsError): runner.main()
            remote.assert_not_called()
            self.assertEqual(plan, json.loads(output.read_bytes()))

    def test_failed_start_planning_rejects_unproven_or_inconsistent_failure_lineage(self):
        for failure in ('missing', 'digest', 'predecessor', 'unit', 'artifact', 'not_started',
                        'partial_install', 'checkpoint', 'invocation', 'intent', 'same_operation', 'nested'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                build, prior = fixture()
                build['commit'] = 'c' * 40
                failed, records = failed_fixture()
                if failure == 'predecessor': failed['retained_predecessor']['intent_sha256'] = 'd' * 64
                if failure == 'unit': failed['units'][0]['before_sha256'] = 'd' * 64
                if failure == 'artifact': failed['artifacts'][0]['package'] = 'wrong'
                if failure == 'not_started': records['failure.json']['new_start_attempted'] = False
                if failure == 'partial_install': records['failure.json']['installed_units'] = []
                if failure == 'checkpoint': records['checkpoint-stopped.json'][0]['kura_tip']['height'] = 198
                if failure == 'invocation': records['checkpoint-stopped.json'][0]['invocation_id'] = 'd' * 32
                if failure == 'same_operation': failed['operation'] = OPERATION
                if failure == 'nested': failed['failed_start'] = {}
                reference = write_failed_reference(temporary, records)
                if failure == 'missing': Path(reference['attempts'][-1]['records']['failure.json']['path']).unlink()
                if failure == 'digest': reference['attempts'][-1]['records']['failure.json']['sha256'] = 'd' * 64
                if failure == 'intent': reference['attempts'][-1]['plan'] = dict(reference['attempts'][-1]['plan'], sha256='d' * 64)
                with patch.object(runner.subprocess, 'run') as remote:
                    with self.assertRaises((RuntimeError, FileNotFoundError)):
                        plan_for(build, prior, failed_start=reference)
                remote.assert_not_called()

    def test_cli_plan_only_binds_the_completed_build_and_exact_predecessor_without_ssh(self):
        with tempfile.TemporaryDirectory() as temporary:
            value,build,descriptor,result=local_inputs(temporary)
            output=descriptor.parent/'plan.json'
            with patch.object(sys,'argv',cli_argv(descriptor,result,output)), \
                 patch.object(runner.subprocess,'check_output',return_value='optimizations\n'), \
                 patch.object(runner.retry,'validate_ssh',return_value=['approved']), \
                 patch.object(runner.subprocess,'run') as remote, \
                 patch.object(runner,'apply_plan') as apply, redirect_stdout(io.StringIO()) as printed:
                runner.main()
            remote.assert_not_called();apply.assert_not_called()
            self.assertFalse(json.loads(printed.getvalue())['host_contacted'])
            plan=json.loads(output.read_bytes())
            self.assertEqual(plan['commit'],build['commit'])
            self.assertEqual(plan['build_result_path'],str(result))
            self.assertEqual(plan['build_result_sha256'],runner.sha(result.read_bytes()))
            self.assertEqual(plan['deployment'],value)
            self.assertEqual([row['name'] for row in plan['artifacts']],['iroha3d_taira','iroha','kagami'])
            self.assertEqual([row['role'] for row in plan['units']],value['roles'])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
            prior=json.loads(Path(value['current']['local_plan']).read_bytes())
            self.assertEqual(plan['retained_predecessor']['intent_sha256'],
                runner.sha(json.dumps(prior,sort_keys=True,separators=(',',':')).encode()))
            self.assertFalse(plan['transaction_submission'])

    def test_cli_rejects_missing_failed_or_incomplete_preparation_without_transfer(self):
        for failure in ('missing','failed','source_changed','artifact_missing'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                _,build,descriptor,result=local_inputs(temporary)
                if failure=='missing':result.unlink()
                else:
                    if failure=='failed':build['exit_code']=1
                    elif failure=='source_changed':build['source_unchanged']=False
                    else:build['artifacts'].pop()
                    result.write_text(json.dumps(build))
                output=descriptor.parent/'plan.json'
                with patch.object(sys,'argv',cli_argv(descriptor,result,output)), \
                     patch.object(runner.subprocess,'check_output',return_value='optimizations\n'), \
                     patch.object(runner.retry,'validate_ssh',return_value=['approved']), \
                     patch.object(runner.subprocess,'run') as remote, \
                     patch.object(runner,'apply_plan') as apply:
                    with self.assertRaises((RuntimeError,FileNotFoundError)):runner.main()
                remote.assert_not_called();apply.assert_not_called()
                self.assertFalse(output.exists())

    def test_cli_rejects_stale_predecessor_or_changed_custody_before_plan_publication(self):
        for failure in ('digest','commit','custody'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                value,_,descriptor,result=local_inputs(temporary)
                prior_path=Path(value['current']['local_plan'])
                prior=json.loads(prior_path.read_bytes())
                if failure=='commit':prior['commit']='e'*40
                elif failure=='custody':
                    raw=base64.b64decode(prior['units'][0]['after']).replace(b'--sora',b'--wrong')
                    prior['units'][0].update(after=base64.b64encode(raw).decode(),after_sha256=runner.sha(raw))
                else:prior['unknown']='changed after binding'
                prior_path.write_text(json.dumps(prior))
                if failure!='digest':
                    value['current']['local_plan_sha256']=runner.sha(prior_path.read_bytes())
                    descriptor.write_text(json.dumps(value))
                output=descriptor.parent/'plan.json'
                with patch.object(sys,'argv',cli_argv(descriptor,result,output)), \
                     patch.object(runner.subprocess,'check_output',return_value='optimizations\n'), \
                     patch.object(runner.retry,'validate_ssh',return_value=['approved']), \
                     patch.object(runner.subprocess,'run') as remote, \
                     patch.object(runner,'apply_plan') as apply:
                    with self.assertRaises(RuntimeError):runner.main()
                remote.assert_not_called();apply.assert_not_called()
                self.assertFalse(output.exists())

    def test_local_lock_contention_prevents_plan_or_transfer(self):
        with tempfile.TemporaryDirectory() as temporary:
            _,_,descriptor,result=local_inputs(temporary)
            output=descriptor.parent/'plan.json'
            lock=os.open(descriptor.parent/'.taira-update.lock',os.O_RDWR|os.O_CREAT,0o600)
            try:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with patch.object(sys,'argv',cli_argv(descriptor,result,output)), \
                     patch.object(runner.subprocess,'check_output',return_value='optimizations\n'), \
                     patch.object(runner.retry,'validate_ssh',return_value=['approved']), \
                     patch.object(runner.subprocess,'run') as remote, \
                     patch.object(runner,'apply_plan') as apply:
                    with self.assertRaises(BlockingIOError):runner.main()
                remote.assert_not_called();apply.assert_not_called()
                self.assertFalse(output.exists())
            finally:os.close(lock)

    def test_indirect_or_shared_public_inputs_and_output_paths_are_rejected(self):
        for failure in ('descriptor_symlink','descriptor_hardlink','output_parent_symlink'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                _,_,descriptor,result=local_inputs(temporary)
                output=descriptor.parent/'plan.json'
                if failure=='output_parent_symlink':
                    alias=descriptor.parent/'alias';alias.symlink_to(descriptor.parent,target_is_directory=True)
                    output=alias/'plan.json'
                else:
                    alias=descriptor.with_name('alias.json')
                    if failure=='descriptor_symlink':alias.symlink_to(descriptor)
                    else:os.link(descriptor,alias)
                    descriptor=alias
                with patch.object(sys,'argv',cli_argv(descriptor,result,output)), \
                     patch.object(runner.subprocess,'check_output',return_value='optimizations\n'), \
                     patch.object(runner.retry,'validate_ssh',return_value=['approved']), \
                     patch.object(runner.subprocess,'run') as remote:
                    with self.assertRaises(RuntimeError):runner.main()
                remote.assert_not_called()
                self.assertFalse(output.exists())

    def test_guest_lock_denies_contention_and_linked_lock_before_any_state_operation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();plan={'deployment':{'runtime_root':str(root)}}
            path=root/'.routine-update.lock'
            actual_fstat=os.fstat
            def root_stat(fd):
                value=actual_fstat(fd)
                return SimpleNamespace(st_mode=value.st_mode,st_uid=0,st_gid=0,st_nlink=value.st_nlink,
                                       st_dev=value.st_dev,st_ino=value.st_ino,st_size=value.st_size)
            def root_stamp(path,directory=False):
                value=Path(path).lstat()
                return [value.st_dev,value.st_ino,value.st_mode,0,0,value.st_nlink]
            guest.DEPLOYMENT_STATE_ROOT=root/'deployment'
            guest.DEPLOYMENT_STATE_ROOT.mkdir(mode=0o700)
            (guest.DEPLOYMENT_STATE_ROOT/'.deployment.lock').touch(mode=0o600)
            held=os.open(path,os.O_RDWR|os.O_CREAT,0o600)
            try:
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with patch.object(guest,'stamp',side_effect=root_stamp), \
                     patch.object(guest.os,'fstat',side_effect=root_stat),patch.object(guest,'apply') as apply:
                    with self.assertRaises(BlockingIOError):guest.apply_locked(plan, CAPACITY_SOURCE)
                    apply.assert_not_called()
            finally:os.close(held)
            alias=root/'shared-lock';os.link(path,alias)
            with patch.object(guest,'stamp',side_effect=root_stamp), \
                 patch.object(guest.os,'fstat',side_effect=root_stat),patch.object(guest,'apply') as apply:
                with self.assertRaisesRegex(RuntimeError,'invalid guest deployment lock'):guest.apply_locked(plan, CAPACITY_SOURCE)
                apply.assert_not_called()
                alias.unlink()
                guest.apply_locked(plan, CAPACITY_SOURCE)
                apply.assert_called_once_with(plan, CAPACITY_SOURCE)
    def test_unit_update_preserves_complete_custody_and_changes_only_daemon_path(self):
        for role in guest.ROLES:
            before = installed_unit(role)
            after = guest.replace_daemon(before, role)
            old = str(guest.PREVIOUS_DAEMON).encode()
            self.assertEqual(after.replace(str(guest.DAEMON).encode(), old), before)
            self.assertEqual(guest.unit_command(after)[1:], guest.unit_command(before)[1:])
            self.assertIn(renderer.CUSTODY.splitlines()[0].encode(), before)

    def test_unexpected_executable_or_extra_occurrence_is_rejected(self):
        raw = installed_unit(guest.ROLES[0])
        with self.assertRaisesRegex(RuntimeError, 'old unit command differs'):
            guest.replace_daemon(raw.replace(b'--sora', b'--other'), guest.ROLES[0])
        with self.assertRaisesRegex(RuntimeError, 'old unit command differs'):
            guest.replace_daemon(raw + b'\n# ' + str(guest.PREVIOUS_DAEMON).encode() + b'\n', guest.ROLES[0])

    def test_plan_selects_daemon_and_same_revision_cli_from_completed_build_and_exact_four_units(self):
        build, metadata = fixture()
        plan = plan_for(build, metadata)
        self.assertEqual([a['name'] for a in plan['artifacts']], ['iroha3d_taira', 'iroha', 'kagami'])
        self.assertEqual(len(plan['units']), 4)
        for row in plan['units']:
            self.assertEqual(guest.replace_daemon(base64.b64decode(row['before']), row['role']),
                             base64.b64decode(row['after']))
        for field, value in [('commit', deployment()['current']['commit']), ('source_unchanged', False), ('target', 'x86_64-unknown-linux-gnu')]:
            invalid = copy.deepcopy(build)
            invalid[field] = value
            with self.assertRaises(RuntimeError):
                plan_for(invalid, metadata)
        metadata['units'][0]['after_sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'predecessor unit digest differs'):
            plan_for(build, metadata)

    def test_config_diagnostics_are_native_file_descriptors_only(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(guest, 'ATTEMPT', Path(directory)), \
                patch.object(guest, 'record'), patch.object(guest.subprocess, 'run') as run:
            run.return_value = subprocess.CompletedProcess([], 0)
            guest.native_private_command(['/native/daemon', '--config', '/private/config'], timeout=3, name='config')
            kwargs = run.call_args.kwargs
            self.assertIs(type(kwargs['stdout']), int)
            self.assertIs(type(kwargs['stderr']), int)
            self.assertNotIn('capture_output', kwargs)

    def test_transfer_creates_release_once_then_adds_same_revision_cli(self):
        plan = plan_for()
        admission = admission_for(plan)
        first = runner.transfer_code('iroha3d_taira', True, plan, admission)
        second = runner.transfer_code('iroha', False, plan, admission)
        self.assertIn('if True:', first)
        self.assertIn('if False:', second)
        self.assertIn("bins/'iroha'", second)
        compile(first, '<native-transfer-daemon>', 'exec')
        compile(second, '<native-transfer-cli>', 'exec')
        with self.assertRaises(RuntimeError):
            runner.transfer_code('../config', False, plan, admission)
        self.assertIn("release=base/" + repr(runner.release_name(plan_for())), first)


    def test_artifact_transfer_compression_preserves_the_approved_ssh_route(self):
        approved = ['/usr/bin/ssh', '-F', '/dev/null', '-o', 'UserKnownHostsFile=/approved/hosts',
                    '-o', 'ProxyCommand=/approved/proxy', 'root@192.168.64.3', '/usr/bin/python3 -I -']
        transfer = runner.artifact_transfer_argv(approved, '/reviewed/transfer')
        self.assertEqual(transfer, [approved[0], '-C', *approved[1:-1], '/reviewed/transfer'])
        self.assertNotIn('-C', approved)
        self.assertEqual(approved[-1], '/usr/bin/python3 -I -')

    def test_snapshot_journal_is_ordered_by_timestamp_before_selecting_latest(self):
        invocation = "a" * 32
        records = [
            {"_SYSTEMD_INVOCATION_ID": invocation, "__REALTIME_TIMESTAMP": str(t),
             "MESSAGE": f"Successfully created a snapshot of state at_height={h}"}
            for t, h in [(300, 217), (100, 17), (200, 180)]
        ]
        raw = "\n".join(json.dumps(row) for row in records).encode()
        with patch.object(guest.subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, stdout=raw, stderr=b'')):
            events = guest.snapshot_events("taira-validator-1", invocation)
        self.assertEqual([row["time_us"] for row in events], [100, 200, 300])
        self.assertIn("at_height=217", events[-1]["message"])

    def test_empty_snapshot_journal_accepts_only_clean_no_match(self):
        with patch.object(guest.subprocess, 'run') as query:
            query.return_value = subprocess.CompletedProcess([], 1, stdout=b'', stderr=b'')
            self.assertEqual(guest.snapshot_events(guest.ROLES[0], 'a' * 32), [])
            self.assertIn('_SYSTEMD_INVOCATION_ID=' + 'a' * 32, query.call_args.args[0])
            for status, out, err in [(2, b'', b''), (1, b'partial', b''),
                                     (1, b'', b'journal failure'), (1, b'', b'\n')]:
                query.return_value = subprocess.CompletedProcess([], status, stdout=out, stderr=err)
                with self.assertRaisesRegex(RuntimeError, 'snapshot journal query failed'):
                    guest.snapshot_events(guest.ROLES[0], 'a' * 32)

    def test_checkpoint_retains_authenticated_pre_boundary_proof_and_later_kura_tip(self):
        obs = {'role': guest.ROLES[0], 'systemd': {'InvocationID': 'a' * 32}, 'public': {'height': 221}}
        selected = {'pointer_stamp': [0] * 7 + [90_000], 'selector': 'b' * 64}
        published = {'time_us': 100, 'message': 'Successfully created a snapshot of state at_height=215'}
        tip = {'height': 221, 'hash': 'c' * 64}
        with patch.object(guest, 'snapshot_selection', return_value=selected) as selection, \
             patch.object(guest, 'native_kura_tip', return_value=tip), \
             patch.object(guest, 'native_kura_hash', return_value=tip['hash']) as retained_hash, \
             patch.object(guest, 'snapshot_events', return_value=[published]) as logs:
            prior = guest.checkpoint_barrier(obs)
            self.assertEqual(prior['checkpoint_height'], 215)
            self.assertFalse(prior['standalone_native_manifest_verification'])
            # Failed shutdown publication does not invalidate an intact authenticated generation.
            logs.return_value = [published, {'time_us': 120, 'message': 'Failed to create a snapshot of state'}]
            stopped = guest.checkpoint_barrier(obs, stopped=True, prior=prior)
            self.assertTrue(stopped['cohort_stopped'])
            self.assertFalse(stopped['graceful_stop_observed'])
            self.assertEqual(stopped['kura_tip'], tip)
            # An invocation with no publication uses the retained proof, never invents one.
            obs['systemd']['InvocationID'] = 'd' * 32
            logs.return_value = []
            reused = guest.checkpoint_barrier(obs, stopped=True, prior=prior)
            self.assertTrue(reused['reused_checkpoint_proof'])
            self.assertEqual(reused['proof_invocation_id'], 'a' * 32)
            self.assertEqual(reused['native_events'], [published])
            # Proof remains usable across another attempt, with its original provenance.
            again = guest.checkpoint_barrier(obs, stopped=True, prior=reused)
            self.assertEqual(again['proof_invocation_id'], 'a' * 32)
            retained_hash.return_value = 'e' * 64
            with self.assertRaisesRegex(RuntimeError, 'prefix hash changed'):
                guest.checkpoint_barrier(obs, stopped=True, prior=prior)
            retained_hash.return_value = tip['hash']
            selection.return_value = dict(selected, selector='f' * 64)
            with self.assertRaisesRegex(RuntimeError, 'selection changed'):
                guest.checkpoint_barrier(obs, prior=prior)
            selection.return_value = selected
            logs.return_value = [{'time_us': 100, 'message': 'Successfully created a snapshot of state at_height=145'}]
            with self.assertRaisesRegex(RuntimeError, 'precedes affected history'):
                guest.checkpoint_barrier(obs)
            logs.return_value = []
            with self.assertRaisesRegex(RuntimeError, 'no native authenticated'):
                guest.checkpoint_barrier(obs)

    def test_new_invocation_must_restore_authenticated_checkpoint_without_historical_replay(self):
        obs = {'role': guest.ROLES[0], 'systemd': {'InvocationID': 'd' * 32}, 'public': {'height': 201}}
        cp = {'checkpoint_height': 200, 'kura_tip': {'height': 201, 'hash': 'a' * 64}}
        events = [{'message': 'Validated snapshot block hashes against Kura snapshot_height=200 kura_height=201'},
                  {'message': 'Successfully loaded the state from a snapshot at_height=200'},
                  {'message': 'Replaying authenticated complete Kura prefix start_height=201 generic_replay_height=201'}]
        with patch.object(guest, 'snapshot_events', return_value=events) as logs, \
             patch.object(guest, 'native_kura_hash', return_value='a' * 64) as native_hash:
            result = guest.verify_restored_checkpoint(obs, cp)
            self.assertEqual(result['restored_height'], 200)
            logs.assert_called_with(obs['role'], 'd' * 32)
            native_hash.assert_called_with(obs['role'], 201)
            native_hash.return_value = 'b' * 64
            with self.assertRaisesRegex(RuntimeError, 'prefix hash changed'):
                guest.verify_restored_checkpoint(obs, cp)
            native_hash.return_value = 'a' * 64
            for bad in [[], events[:1], events + [{'message': 'Failed to load state snapshot'}],
                        events[:2] + [{'message': 'Replaying authenticated complete Kura prefix start_height=146'}],
                        [{'message': 'Validated snapshot block hashes against Kura snapshot_height=145'},
                         {'message': 'Successfully loaded the state from a snapshot at_height=145'}]]:
                logs.return_value = bad
                with self.assertRaises(RuntimeError):
                    guest.verify_restored_checkpoint(obs, cp)

    def test_current_invocation_strict_restore_authenticates_a_newer_selected_generation(self):
        observation = {'role': guest.ROLES[0], 'systemd': {'InvocationID': 'f' * 32},
                       'public': {'height': 221}}
        selected = {'pointer_stamp': [0] * 7 + [200_000], 'selector': 'b' * 64}
        prior = {'role': guest.ROLES[0], 'selection': {'selector': 'older-generation'},
                 'kura_tip': {'height': 219, 'hash': 'c' * 64}}
        events = [{'time_us': 300, 'message': 'Validated snapshot block hashes against Kura snapshot_height=221'},
                  {'time_us': 301, 'message': 'Successfully loaded the state from a snapshot at_height=221'}]
        with patch.object(guest, 'snapshot_selection', return_value=selected), \
             patch.object(guest, 'native_kura_tip', return_value={'height': 221, 'hash': 'd' * 64}), \
             patch.object(guest, 'native_kura_hash', return_value='c' * 64), \
             patch.object(guest, 'snapshot_events', return_value=events) as logs:
            result = guest.checkpoint_barrier(observation, stopped=True, prior=prior)
            self.assertEqual(result['proof_kind'], 'native_strict_restore')
            self.assertEqual(result['checkpoint_height'], 221)
            self.assertEqual(result['proof_invocation_id'], 'f' * 32)
            self.assertFalse(result['reused_checkpoint_proof'])
            self.assertNotIn('native_publication_height', result)
            logs.assert_called_with(guest.ROLES[0], 'f' * 32)
            logs.return_value = events[1:]
            with self.assertRaisesRegex(RuntimeError, 'authentication missing'):
                guest.checkpoint_barrier(observation, stopped=True, prior=prior)
            logs.return_value = events
            selected['pointer_stamp'][7] = 302_000
            with self.assertRaisesRegex(RuntimeError, 'replaced after native'):
                guest.checkpoint_barrier(observation, stopped=True, prior=prior)

    def test_stop_accepts_terminated_failed_services_and_records_their_failure(self):
        clean = {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0',
                 'ControlPID': '0', 'Job': '', 'Result': 'success', 'ExecMainCode': '1', 'ExecMainStatus': '0'}
        failed = dict(clean, ActiveState='failed', SubState='failed', Result='exit-code', ExecMainStatus='1')
        with patch.object(guest, 'command') as command, \
             patch.object(guest, 'systemd', side_effect=[clean, failed, clean, failed]) as states, \
             patch.object(guest, 'record') as record:
            observed = guest.stop_all()
            self.assertEqual([row['clean_exit'] for row in observed], [True, False, True, False])
            self.assertEqual(observed[1]['systemd']['ExecMainStatus'], '1')
            record.assert_called_once_with('stop-observations.json', observed)
            self.assertEqual(command.call_args.args[0], ['/usr/bin/systemctl', 'stop', *guest.UNITS])
            for bad in [dict(failed, MainPID='42'), dict(failed, ControlPID='43'),
                        dict(failed, Job='123'), dict(clean, SubState='stop-sigterm')]:
                states.side_effect = [bad]
                with self.assertRaisesRegex(RuntimeError, 'cohort stop incomplete'):
                    guest.stop_all()

    def test_public_probe_errors_identify_role_endpoint_and_exit_without_native_content(self):
        private = b'never expose this response, stderr or argv'
        for route, code in (('/status', 7), ('/readyz', 56),
                            ('/v1/accounts/faucet/puzzle', 28)):
            with self.subTest(route=route, code=code), \
                 patch.object(guest.subprocess, 'run', return_value=SimpleNamespace(
                     returncode=code, stdout=private, stderr=private)):
                with self.assertRaises(RuntimeError) as failure:
                    guest.public_probe(2, route)
                self.assertEqual(str(failure.exception),
                                 f'public probe failed: role={guest.ROLES[2]} endpoint={route} curl_exit={code}')
                self.assertNotIn(private.decode(), str(failure.exception))
        with patch.object(guest.subprocess, 'run', side_effect=subprocess.TimeoutExpired(
                ['curl', private.decode()], 10, output=private, stderr=private)):
            with self.assertRaises(RuntimeError) as failure:
                guest.public_probe(1, '/readyz')
            self.assertEqual(str(failure.exception),
                             f'public probe failed: role={guest.ROLES[1]} endpoint=/readyz timeout')
        for response in (private, b'["never expose this response"]', b'\xffprivate'):
            with self.subTest(response=response), \
                 patch.object(guest, 'public_probe', return_value=response):
                with self.assertRaises(RuntimeError) as failure:
                    guest.public_get(0, '/status')
                self.assertIn(f'role={guest.ROLES[0]} endpoint=/status', str(failure.exception))
                self.assertNotIn('never expose', str(failure.exception))
                self.assertNotIn('private', str(failure.exception))

    def test_public_probe_classifies_only_transport_and_exact_503_as_transient(self):
        for status in (200, 400, 401, 403, 404, 429, 500, 502, 503, 504):
            raw = b'public body\n' + str(status).encode()
            with self.subTest(status=status), patch.object(guest.subprocess, 'run',
                    return_value=SimpleNamespace(returncode=0 if status == 200 else 22,
                                                 stdout=raw, stderr=b'private diagnostic')):
                if status == 200:
                    self.assertEqual(guest.public_probe(0, '/status'), b'public body')
                else:
                    with self.assertRaises(RuntimeError) as failed:
                        guest.public_probe(0, '/status')
                    self.assertEqual(isinstance(failed.exception, guest.StartupProbeUnavailable), status == 503)
                    self.assertIn('http_status=' + str(status), str(failed.exception))
                    self.assertNotIn('body', str(failed.exception))
                    self.assertNotIn('private', str(failed.exception))
        for code in (6, 7, 23, 28, 35, 52, 56, 60):
            with self.subTest(exit_code=code), patch.object(guest.subprocess, 'run',
                    return_value=SimpleNamespace(returncode=code, stdout=b'', stderr=b'')):
                with self.assertRaises(RuntimeError) as failed:
                    guest.public_probe(0, '/readyz')
                self.assertEqual(isinstance(failed.exception, guest.StartupProbeUnavailable),
                                 code in (7, 28, 52, 56))

    def test_malformed_http_status_and_native_tool_failures_are_permanent(self):
        for raw in (b'', b'200', b'private body\nxyz', b'body\n200\n'):
            with self.subTest(raw=raw), patch.object(guest.subprocess, 'run',
                    return_value=SimpleNamespace(returncode=0, stdout=raw, stderr=b'')):
                with self.assertRaises(RuntimeError) as failed:
                    guest.public_probe(0, '/status')
                self.assertNotIsInstance(failed.exception, guest.StartupProbeUnavailable)
                self.assertIn('HTTP status is malformed', str(failed.exception))
        with patch.object(guest.subprocess, 'run', side_effect=OSError('private diagnostics')):
            with self.assertRaises(RuntimeError) as failed:
                guest.public_probe(0, '/status')
            self.assertNotIsInstance(failed.exception, guest.StartupProbeUnavailable)
            self.assertNotIn('private diagnostics', str(failed.exception))

    def test_http200_ready_body_is_exact_native_contract(self):
        for body in (b'Ready', b'', b'NotReady', b'Ready\n', b'{"ready":true}'):
            with self.subTest(body=body), patch.object(guest.subprocess, 'run',
                    return_value=SimpleNamespace(returncode=0, stdout=body + b'\n200', stderr=b'')):
                if body == b'Ready':
                    self.assertEqual(guest.public_probe(0, '/readyz'), body)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'readiness body differs') as failed:
                        guest.public_probe(0, '/readyz')
                    self.assertNotIsInstance(failed.exception, guest.StartupProbeUnavailable)

    def test_invalid_status_fails_before_transient_puzzle_can_hide_it(self):
        good = {'blocks': 220, 'build': {'git_commit_sha': guest.CANDIDATE_COMMIT}}
        bad_statuses = [dict(good, build={'git_commit_sha': 'f' * 40}),
                        dict(good, build=[]), dict(good, blocks=True),
                        dict(good, blocks=0), dict(good, blocks=199)]
        for status in bad_statuses:
            with self.subTest(status=status), patch.object(guest, 'public_get',
                    side_effect=[status, guest.StartupProbeUnavailable('puzzle 503')]) as read:
                with self.assertRaises(RuntimeError) as failed:
                    guest.public_identity(3, expected_commit=guest.CANDIDATE_COMMIT, minimum_height=200)
                self.assertNotIsInstance(failed.exception, guest.StartupProbeUnavailable)
                self.assertEqual(read.call_args_list, [unittest.mock.call(3, '/status')])
        with patch.object(guest, 'public_get',
                side_effect=[good, guest.StartupProbeUnavailable('puzzle 503')]):
            with self.assertRaises(guest.StartupProbeUnavailable):
                guest.public_identity(3, expected_commit=guest.CANDIDATE_COMMIT, minimum_height=200)

    def test_failed_http_observation_reports_process_restart_without_config_or_body(self):
        old = {'ActiveState': 'active', 'SubState': 'running', 'ControlPID': '0',
               'MainPID': '42', 'InvocationID': 'a' * 32, 'NRestarts': '0',
               'Result': 'success', 'ExecMainStatus': '0'}
        new = dict(old, MainPID='43', InvocationID='b' * 32, NRestarts='1',
                   Result='exit-code', ExecMainStatus='1')
        row = {'role': guest.ROLES[2], 'after': base64.b64encode(b'public unit').decode()}
        argv = ['/fixed/daemon', '--config', '/owner-private/config.toml', '--sora']
        private = b'never expose this diagnostic'
        with patch.object(guest, 'systemd', side_effect=[old, new]), \
             patch.object(guest, 'retained_identity', return_value={
                 'role': row['role'], 'executable': argv[0]}), \
             patch.object(guest, 'unit_command', return_value=argv), \
             patch.object(Path, 'read_bytes', return_value='\0'.join(argv).encode()), \
             patch.object(guest.os, 'readlink', return_value=argv[0]), \
             patch.object(guest.subprocess, 'run', return_value=SimpleNamespace(
                 returncode=7, stdout=private, stderr=private)):
            with self.assertRaises(RuntimeError) as failure:
                guest.observe(row, after=True)
            message = str(failure.exception)
            self.assertIn(f'role={row["role"]} endpoint=/status curl_exit=7', message)
            self.assertIn('observed=ActiveState=active,SubState=running,MainPID=42', message)
            self.assertIn('current=ActiveState=active,SubState=running,MainPID=43', message)
            self.assertIn('NRestarts=1,Result=exit-code,ExecMainStatus=1', message)
            self.assertNotIn(private.decode(), message)
            self.assertNotIn(argv[2], message)
        with patch.object(guest, 'systemd', return_value=dict(new, ActiveState='failed', SubState='failed')):
            with self.assertRaisesRegex(RuntimeError, 'validator not running: taira-validator-3.*NRestarts=1'):
                guest.observe(row, after=True)
        summary = guest.process_summary(dict(new, Result='arbitrary diagnostic\nprivate token',
                                             UnrequestedField=private.decode()))
        self.assertIn('Result=invalid', summary)
        self.assertNotIn('private', summary)
        self.assertNotIn('UnrequestedField', summary)

    def test_cohort_target_is_highest_stopped_tip_and_rejects_conflicting_maximum(self):
        checkpoints = [{'role': role, 'kura_tip': {'height': height, 'hash': digest * 64}}
                       for role, height, digest in zip(guest.ROLES,
                           [1260, 1260, 1023, 1260], ['c', 'c', 'b', 'c'], strict=True)]
        self.assertEqual(guest.cohort_retained_tip(checkpoints),
                         {'height': 1260, 'hash': 'c' * 64})
        checkpoints[1]['kura_tip']['hash'] = 'd' * 64
        with self.assertRaisesRegex(RuntimeError, 'highest retained Kura tips disagree'):
            guest.cohort_retained_tip(checkpoints)
        checkpoints[1]['kura_tip']['hash'] = 'c' * 64
        checkpoints[2]['kura_tip']['height'] = guest.REPLAY_BARRIER - 1
        with self.assertRaisesRegex(RuntimeError, 'retained cohort Kura tip is invalid'):
            guest.cohort_retained_tip(checkpoints)
        with self.assertRaisesRegex(RuntimeError, 'checkpoint cohort differs'):
            guest.cohort_retained_tip(checkpoints[::-1])

    def test_stopped_cohort_checks_every_overlapping_prefix_before_startup(self):
        checkpoints = [{'role': role, 'kura_tip': {'height': height, 'hash': digest * 64}}
                       for role, height, digest in zip(guest.ROLES,
                           [1260, 1260, 1023, 1260], ['c', 'c', 'b', 'c'], strict=True)]
        with patch.object(guest, 'native_kura_hash',
                          side_effect=lambda role, height: ('b' if height == 1023 else 'c') * 64) as hashes:
            self.assertEqual(guest.verify_stopped_cohort_prefixes(checkpoints),
                             {'height': 1260, 'hash': 'c' * 64})
            self.assertEqual(hashes.call_count, 13)
            hashes.side_effect = lambda role, height: ('a' if role == guest.ROLES[0]
                                                       and height == 1023 else
                                                       'b' if height == 1023 else 'c') * 64
            with self.assertRaisesRegex(RuntimeError, 'retained Kura prefix hash changed'):
                guest.verify_stopped_cohort_prefixes(checkpoints)

    def test_cohort_final_process_sweep_rejects_restart_after_individual_observation(self):
        props = {'ActiveState': 'active', 'SubState': 'running', 'ControlPID': '0',
                 'MainPID': '42', 'InvocationID': 'a' * 32}
        observations = [{'role': role, 'systemd': dict(props)} for role in guest.ROLES]
        for changes in ({'MainPID': '43'}, {'InvocationID': 'b' * 32},
                        {'ActiveState': 'failed', 'SubState': 'failed', 'MainPID': '0'}):
            with self.subTest(changes=changes), \
                 patch.object(guest, 'systemd', return_value=dict(props, **changes)):
                with self.assertRaisesRegex(RuntimeError, 'process changed across cohort verification'):
                    guest.verify_cohort_processes(observations)
        restarted = copy.deepcopy(observations)
        restarted[2]['systemd']['InvocationID'] = 'b' * 32
        with patch.object(guest, 'systemd', return_value=props):
            with self.assertRaisesRegex(RuntimeError, 'process changed across cohort verification'):
                guest.verify_cohort_processes(restarted, observations)

    def test_observation_intent_is_published_after_start_before_completion(self):
        _, records, _, plan = self.simulate()
        intent = records['cohort-observation-intent.json']
        self.assertEqual(intent, {
            'schema': 'taira.cohort-observation-intent.v1',
            'operation': plan['operation'], 'commit': plan['commit'],
            'phase': 'cohort_observation',
            'owner': {'pid': 991, 'start_time_ticks': 1234,
                      'argv': ['/usr/bin/python3', '-I', '-'],
                      'lock': {'device': 1, 'inode': 9}},
            'automatic_restart_or_rollback_after_start': False,
            'remaining_actions': ['observe_cohort', 'verify_strict_restore',
                                  'observe_final_cohort', 'publish_completion_receipts']})
        names = list(records)
        self.assertLess(names.index('start-intent.json'), names.index('cohort-observation-intent.json'))
        self.assertLess(names.index('cohort-observation-intent.json'), names.index('after.json'))
        _, failed, _, _ = self.simulate('start')
        self.assertNotIn('cohort-observation-intent.json', failed)
        self.assertIn('failure.json', failed)

    def test_retained_attempt_binds_exact_completed_predecessor(self):
        build, old_plan = fixture()
        plan = plan_for(build, old_plan)
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(guest, 'BASE', Path(temporary)), \
             patch.object(guest, 'stamp', return_value=[0] * 6 + [100]):
            prior = Path(temporary) / deployment()['current']['attempt_name']
            prior.mkdir()
            records = {'intent.json': old_plan,
                       'result.json': {'schema': 'taira.daemon-update.result.v1',
                                       'runtime_update_complete': True, 'state_preserved': True,
                                       'retained_native_snapshot_verified': True,
                                       'commit': guest.OLD, 'network_id': guest.NETWORK},
                       'after.json': [{'role': role, 'public': {'commit': guest.OLD, 'network_id': guest.NETWORK}} for role in guest.ROLES],
                       'checkpoint-stopped.json': [{'role': role} for role in guest.ROLES],
                       'checkpoint-restored.json': [{'role': role, 'native_strict_checkpoint_verified': True} for role in guest.ROLES]}
            for name, value in records.items():
                (prior / name).write_text(json.dumps(value))
            before_bytes = {p.name: p.read_bytes() for p in prior.iterdir()}
            result = guest.retained_attempt(plan)
            self.assertEqual(result, (records['after.json'], records['checkpoint-stopped.json']))
            self.assertEqual(before_bytes, {p.name: p.read_bytes() for p in prior.iterdir()})
            changed = copy.deepcopy(plan)
            changed['units'][0]['before_sha256'] = 'd' * 64
            with self.assertRaisesRegex(RuntimeError, 'changed installed predecessor unit'):
                guest.retained_attempt(changed)
            changed = dict(plan, commit=old_plan['commit'])
            with self.assertRaisesRegex(RuntimeError, 'installed predecessor source or candidate differs'):
                guest.retained_attempt(changed)
            records['result.json']['runtime_update_complete'] = False
            (prior / 'result.json').write_text(json.dumps(records['result.json']))
            with self.assertRaisesRegex(RuntimeError, 'completion receipt differs'):
                guest.retained_attempt(plan)
            records['result.json']['runtime_update_complete'] = True
            (prior / 'result.json').write_text(json.dumps(records['result.json']))
            records['checkpoint-restored.json'][0]['native_strict_checkpoint_verified'] = False
            (prior / 'checkpoint-restored.json').write_text(json.dumps(records['checkpoint-restored.json']))
            with self.assertRaisesRegex(RuntimeError, 'Strict restoration is not verified'):
                guest.retained_attempt(plan)

    def test_guest_recovery_authenticates_failed_records_and_completed_baseline_independently(self):
        for failure in (None, 'missing', 'digest', 'after.json', 'checkpoint-restored.json',
                        'result.json', 'rollback.json', 'unit', 'artifact', 'health',
                        'completion', 'strict', 'identity'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                build, prior = fixture()
                build['commit'] = 'c' * 40
                failed, records = failed_fixture()
                root = Path(temporary).resolve()
                reference = write_failed_reference(root / failed['operation'], records)
                plan = plan_for(build, prior, failed_start=reference)
                baseline = root / deployment()['current']['attempt_name']
                baseline.mkdir()
                baseline_records = {
                    'intent.json': prior, 'after.json': records['before.json'],
                    'checkpoint-stopped.json': [{'role': role} for role in guest.ROLES],
                    'checkpoint-restored.json': [{'role': role, 'native_strict_checkpoint_verified': True}
                                                 for role in guest.ROLES],
                    'result.json': {'schema': 'taira.daemon-update.result.v1',
                                    'runtime_update_complete': True, 'state_preserved': True,
                                    'retained_native_snapshot_verified': True,
                                    'commit': guest.PREDECESSOR['commit'], 'network_id': guest.NETWORK}}
                if failure == 'completion': baseline_records['result.json']['runtime_update_complete'] = False
                if failure == 'strict': baseline_records['checkpoint-restored.json'][0]['native_strict_checkpoint_verified'] = False
                for name, row in baseline_records.items():
                    (baseline / name).write_text(json.dumps(row))
                failed_directory = root / failed['operation']
                if failure in ('after.json', 'checkpoint-restored.json', 'result.json', 'rollback.json'):
                    (failed_directory / failure).write_text('{}')
                if failure == 'missing': (failed_directory / 'start-intent.json').unlink()
                if failure == 'digest': (failed_directory / 'failure.json').write_text('{}')
                if failure == 'unit': plan['units'][0]['before_sha256'] = 'd' * 64
                if failure in ('health', 'identity'):
                    if failure == 'health': records['before.json'][0]['public']['height'] = 198
                    else: records['before.json'][0]['state_root_identity'] = [8, 8]
                    rebound = write_failed_reference(failed_directory, records)
                    plan['failed_start']['attempts'][-1]['records'] = rebound['attempts'][-1]['records']
                contents = {str(path): path.read_bytes() for path in root.rglob('*.json')}
                with patch.object(guest, 'BASE', root), \
                     patch.object(guest, 'native_kura_hash', return_value='c' * 64), \
                     patch.object(guest, 'stamp', return_value=[0] * 6 + [2_000_000]), \
                     patch.object(guest, 'native_digest', return_value=('d' if failure == 'artifact' else 'b') * 64), \
                     patch.object(guest, 'record') as record, \
                     patch.object(guest, 'stop_all') as stop:
                    if failure not in (None, 'after.json', 'checkpoint-restored.json'):
                        with self.assertRaises((RuntimeError, FileNotFoundError)):
                            guest.retained_attempt(plan)
                    else:
                        retained = guest.retained_attempt(plan)
                        self.assertEqual(retained, (records['before.json'], records['checkpoint-stopped.json']))
                        self.assertEqual(guest.OLD, failed['commit'])
                        self.assertEqual(retained[0][0]['public']['commit'], guest.PREDECESSOR['commit'])
                        observation = copy.deepcopy(retained[0][0])
                        observation['systemd']['InvocationID'] = 'f' * 32
                        checkpoint = retained[1][0]
                        with patch.object(guest, 'snapshot_selection', return_value=checkpoint['selection']) as selection, \
                             patch.object(guest, 'snapshot_events', return_value=[]) as logs, \
                             patch.object(guest, 'native_kura_tip', return_value={'height': 201, 'hash': 'd' * 64}), \
                             patch.object(guest, 'native_kura_hash', return_value='c' * 64) as prefix:
                            recovered = guest.checkpoint_barrier(observation, stopped=True, prior=checkpoint)
                            self.assertTrue(recovered['reused_checkpoint_proof'])
                            self.assertEqual(recovered['proof_invocation_id'], 'e' * 32)
                            self.assertEqual(recovered['invocation_id'], 'f' * 32)
                            self.assertEqual(recovered['kura_tip']['height'], 201)
                            logs.assert_called_with(observation['role'], 'f' * 32)
                            prefix.assert_called_with(observation['role'], 200)
                            prefix.return_value = 'd' * 64
                            with self.assertRaisesRegex(RuntimeError, 'prefix hash changed'):
                                guest.checkpoint_barrier(observation, stopped=True, prior=checkpoint)
                            prefix.return_value = 'c' * 64
                            selection.return_value = dict(checkpoint['selection'], selector='d' * 64)
                            with self.assertRaisesRegex(RuntimeError, 'selection changed'):
                                guest.checkpoint_barrier(observation, stopped=True, prior=checkpoint)
                    record.assert_not_called(); stop.assert_not_called()
                self.assertEqual(contents, {str(path): path.read_bytes() for path in root.rglob('*.json')})

    def simulate(self, failure=None, *, recovery=False, same_artifacts=False, failed_chain_depth=1,
                 retirement_changed=True, modern=True):
        build, metadata = fixture()
        if recovery:
            with tempfile.TemporaryDirectory() as temporary:
                build, metadata, reference, entries = failed_chain_fixture(
                    temporary, commits=('a',) + ('c',) * (failed_chain_depth - 1))
                failed_records = entries[-1][1]
                if not same_artifacts:
                    build['commit'] = ('c' if failed_chain_depth == 1 else 'd') * 40
                plan = plan_for(build, metadata, failed_start=reference)
        else:
            plan = plan_for(build, metadata)
        if modern and not recovery:
            plan['schema'] = 'taira.daemon-update.plan.v2'
            plan['deployment'].update(schema='taira.runtime-deployment.v2', config_filename='config.toml',
                                      kura_hash_journal='storage/kura/blocks/canonical/blocks.hashes')
            plan['deployment']['current']['kind'] = 'completed-update'
        events = []
        records = {}
        units = {row['role']: base64.b64decode(row['before']) for row in plan['units']}
        original_config = [1, 4, 0o100600, 0, 0, 1, 100, 90, 90]
        configs = {role: list(original_config) for role in guest.ROLES}

        def running(role):
            index = guest.ROLES.index(role) + 1
            props = {'ActiveState': 'active', 'SubState': 'running', 'ControlPID': '0',
                     'MainPID': str(100 + index), 'InvocationID': str(index) * 32,
                     'NRestarts': '0', 'Job': ''}
            if 'checkpoint-restored' in events and role == guest.ROLES[2]:
                if failure == 'final-observation-invocation':
                    props['InvocationID'] = 'b' * 32
                if failure == 'final-observation-pid':
                    props['MainPID'] = '203'
            return props

        def native(argv, *, timeout=60, name=None):
            events.append(name or str(argv[0]))
            self.assertNotIn('doctor', argv, 'public doctor is not an update prerequisite')
            if failure is not None and name == failure:
                raise RuntimeError('injected ' + str(name))
            if name == 'candidate-version':
                return b'iroha3d 3.0.0\n'  # Real --version has no commit.
            return b''

        def identity(row, *, after=False):
            need_raw = base64.b64decode(row['after' if after else 'before'])
            self.assertEqual(units[row['role']], need_raw)
            return {'role': row['role'], 'unit_stamp': [1, 2, 0o100600, 0, 0, 1, 3, 4, 5],
                    'config_stamp': list(configs[row['role']]), 'config_sha256': 'same', 'state_root_identity': [1, 8],
                    'current_target': 'unchanged',
                    'systemd': running(row['role']),
                    'executable': str(guest.DAEMON if after else guest.PREVIOUS_DAEMON),
                    'public': {'commit': plan['commit'] if after else guest.PREDECESSOR['commit'],
                               'network_id': guest.NETWORK,
                               'height': 200 if after else 199}}

        def observe(row, *, after=False, allow_unavailable=False, **kwargs):
            if not after:
                raise AssertionError('stopped predecessor has no live Torii observation')
            events.append('observe-' + row['role'])
            if (failure in ('final-observation-http', 'failure-record')
                    and 'checkpoint-restored' in events
                    and row['role'] == guest.ROLES[2]):
                raise RuntimeError('validator no longer answers HTTP')
            return identity(row, after=after)

        def install(path, raw, expected, mode):
            role = path.name.removeprefix('iroha3d-').removesuffix('.service')
            events.append('install-' + role)
            self.assertEqual(units[role], expected)
            units[role] = raw
            if failure == 'partial-install' and role == guest.ROLES[1] and raw != base64.b64decode(plan['units'][1]['before']):
                raise RuntimeError('injected installation error after atomic rename')

        original_read = Path.read_bytes

        def read(path):
            if str(path).startswith('/etc/systemd/system/'):
                return units[path.name.removeprefix('iroha3d-').removesuffix('.service')]
            return original_read(path)

        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            stack.enter_context(patch.object(guest, 'configure', side_effect=lambda value: self.assertEqual(value, plan)))
            stack.enter_context(patch.object(guest, 'BASE', Path(directory)))
            stack.enter_context(patch.object(guest, 'ATTEMPT', Path(directory) / 'attempt'))
            if failure == 'attempt-exists':
                guest.ATTEMPT.mkdir()
            stack.enter_context(patch.object(guest.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(guest, 'native_digest', return_value='b' * 64))
            stack.enter_context(patch.object(guest, 'stamp', return_value=[1, 2, 0o100755, 0, 0, 1, 2_000_000]))
            # A real, empty test file stands in for the already transferred
            # public daemon solely for its fsync; no subprocess executes it.
            fake = Path(directory) / 'daemon'
            fake.touch()
            original_open = guest.os.open
            stack.enter_context(patch.object(guest.os, 'open', side_effect=lambda path, flags, *a:
                                            original_open(fake if path in (guest.DAEMON, guest.CLI, guest.KAGAMI) else path, flags, *a)))
            stack.enter_context(patch.object(guest, 'sync'))
            capacity_calls = [0]
            def capacity(*args):
                capacity_calls[0] += 1
                if failure == 'capacity-before-stop' and capacity_calls[0] == 2:
                    raise RuntimeError('guest capacity exhausted before stopping services')
                return {'passed': True}
            stack.enter_context(patch.object(guest, 'storage_capacity', side_effect=capacity))
            stack.enter_context(patch.object(guest, 'write_new'))
            def record(name, value):
                if failure == 'failure-record' and name == 'failure.json':
                    raise OSError(28, 'No space left on device')
                records[name] = value
                if name == 'checkpoint-restored.json':
                    events.append('checkpoint-restored')
            stack.enter_context(patch.object(guest, 'record', side_effect=record))
            stack.enter_context(patch.object(guest, 'command', side_effect=native))
            stack.enter_context(patch.object(guest, 'public_probe', return_value=b'Ready'))
            now = [0.0]
            stack.enter_context(patch.object(guest.time, 'monotonic', side_effect=lambda: now[0]))
            stack.enter_context(patch.object(guest.time, 'sleep',
                side_effect=lambda seconds: now.__setitem__(0, now[0] + seconds)))
            def check_config(argv, **kwargs):
                events.append(kwargs['name'])
                if plan['schema'].endswith('.v2'):
                    self.assertIn('config-retirement-prepared.json', records)
                    self.assertIn(str(argv[2]), [row['staged_path'] for row in records['config-retirement-prepared.json']['rows']])
                else:
                    self.assertNotIn('config-retirement-prepared.json', records)
                    self.assertIn(argv[2], [guest.retained_config(role) for role in guest.ROLES])
                if failure == 'config-check':
                    raise RuntimeError('candidate configuration validation failed')
            stack.enter_context(patch.object(guest, 'native_private_command', side_effect=check_config))
            def retire_configs(operation, action, before, prepared=None):
                events.append('config-retirement-' + action)
                self.assertEqual(operation, plan['operation'])
                if action == 'prepare':
                    self.assertIn('retained-entry.json', records)
                    self.assertNotIn('stop-all', events)
                    if failure == 'config-prepare':
                        raise RuntimeError('native configuration retirement preparation failed')
                    rows = [{'role': row['role'], 'before_stamp': list(row['config_stamp']),
                             'staged_path': '/fixture/staged/' + row['role'],
                             'changed': retirement_changed} for row in before]
                    report = {'rows': rows}
                else:
                    self.assertIn('stopped-owner-maintenance', events)
                    self.assertNotIn('start-intent.json', records)
                    rows = copy.deepcopy(prepared['rows'])
                    for index, row in enumerate(rows):
                        value = list(row['before_stamp'])
                        if retirement_changed:
                            value[1] += (100 if action == 'install' else 200) + index
                        configs[row['role']] = value
                        row['installed_stamp' if action == 'install' else 'restored_stamp'] = value
                        if failure == 'config-install' and action == 'install' and index == 1:
                            raise RuntimeError('native configuration installation failed after partial rename')
                    if action == 'restore':
                        for unit in plan['units']:
                            self.assertEqual(units[unit['role']], base64.b64decode(unit['before']))
                    report = {'rows': rows}
                stage = {'prepare': 'prepared', 'install': 'installed', 'restore': 'restored'}[action]
                records['config-retirement-' + stage + '.json'] = report
                return report
            stack.enter_context(patch.object(guest, 'retire_validator_configs', side_effect=retire_configs))
            stack.enter_context(patch.object(guest, 'observe', side_effect=observe))
            def observing_owner():
                self.assertIn('start', events)
                self.assertNotIn('after.json', records)
                return {'pid': 991, 'start_time_ticks': 1234,
                        'argv': ['/usr/bin/python3', '-I', '-'],
                        'lock': {'device': 1, 'inode': 9}}
            stack.enter_context(patch.object(guest, 'cohort_observation_owner', side_effect=observing_owner))
            def maintain_owners(operation):
                events.append('stopped-owner-maintenance')
                self.assertEqual(operation, plan['operation'])
                self.assertEqual([row['role'] for row in records['checkpoint-stopped.json']],
                                 list(guest.ROLES))
                self.assertIn('cohort-retained-tip.json', records)
                self.assertFalse(any(event.startswith('install-') for event in events))
                self.assertNotIn('start', events)
                if failure == 'stopped-owner-maintenance':
                    raise RuntimeError('native stopped-owner maintenance failed')
            stack.enter_context(patch.object(guest, 'stopped_owner_maintenance', side_effect=maintain_owners))
            prior = ([identity(row) for row in plan['units']],
                     failed_records['checkpoint-stopped.json'] if recovery else [{} for _ in guest.ROLES])
            stack.enter_context(patch.object(guest, 'retained_attempt', return_value=prior))
            stack.enter_context(patch.object(guest, 'retained_identity', side_effect=identity))
            paused = {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0',
                      'ControlPID': '0', 'Job': '', 'InvocationID': 'f' * 32}
            def systemd(unit):
                events.append('systemd-' + unit)
                return (running(unit.removeprefix('iroha3d-').removesuffix('.service'))
                        if 'start' in events and 'failed-start-stop' not in events else paused)
            stack.enter_context(patch.object(guest, 'systemd', side_effect=systemd))
            def stop_cohort():
                events.append('stop-all')
                if failure == 'partial-stop': raise RuntimeError('injected partial validator stop')
                return [{'unit': unit, 'systemd': paused} for unit in guest.UNITS]
            stack.enter_context(patch.object(guest, 'stop_all', side_effect=stop_cohort))
            def checkpoint(row, *, stopped, prior):
                self.assertTrue(stopped)
                self.assertEqual(row['systemd']['InvocationID'], 'f' * 32)
                if recovery:
                    self.assertEqual(prior, failed_records['checkpoint-stopped.json'][guest.ROLES.index(row['role'])])
                return {'role': row['role'], 'selection': 'selected', 'checkpoint_height': 199,
                        'cohort_stopped': True, 'invocation_id': row['systemd']['InvocationID'],
                        'kura_tip': {'height': 200, 'hash': 'c' * 64}}
            stack.enter_context(patch.object(guest, 'checkpoint_barrier', side_effect=checkpoint))
            stack.enter_context(patch.object(guest, 'snapshot_selection', return_value='selected'))
            stack.enter_context(patch.object(guest, 'native_kura_tip', return_value={'height': 200, 'hash': 'c' * 64}))
            def kura_hash(role, height):
                events.append('hash-' + role)
                self.assertEqual(height, 200)
                return ('d' if failure == 'final-observation-hash' and 'checkpoint-restored' in events
                        and role == guest.ROLES[2] else 'c') * 64
            stack.enter_context(patch.object(guest, 'native_kura_hash', side_effect=kura_hash))
            stack.enter_context(patch.object(guest, 'verify_restored_checkpoint', side_effect=lambda row, cp, **kwargs:
                {'role': row['role'], 'restored_height': 199, 'native_strict_checkpoint_verified': True}))
            stack.enter_context(patch.object(guest, 'install_unit', side_effect=install))
            stack.enter_context(patch.object(Path, 'read_bytes', read))
            with redirect_stdout(io.StringIO()):
                if failure:
                    with self.assertRaises(OSError if failure == 'failure-record' else RuntimeError):
                        guest.apply(plan, CAPACITY_SOURCE)
                else:
                    guest.apply(plan, CAPACITY_SOURCE)
        return events, records, units, plan

    def test_native_config_retirement_order_and_noop_complete_without_renderer_changes(self):
        for changed in (False, True):
            with self.subTest(changed=changed):
                events, records, units, plan = self.simulate(retirement_changed=changed)
                self.assertLess(events.index('config-retirement-prepare'), events.index('check-config-1'))
                self.assertLess(events.index('check-config-4'), events.index('stop-all'))
                self.assertLess(events.index('stopped-owner-maintenance'), events.index('config-retirement-install'))
                self.assertLess(events.index('config-retirement-install'), events.index('install-' + guest.ROLES[0]))
                self.assertLess(events.index('install-' + guest.ROLES[-1]), events.index('start'))
                self.assertNotIn('config-retirement-restore', events)
                for original, row, final in zip(records['retained-entry.json'],
                        records['config-retirement-installed.json']['rows'], records['after.json']):
                    self.assertEqual(original['config_stamp'], row['before_stamp'])
                    self.assertEqual(final['config_stamp'], row['installed_stamp'])
                    self.assertEqual(row['before_stamp'] != row['installed_stamp'], changed)

    def test_v1_corridor_keeps_original_configuration_and_never_calls_v2_native_adapter(self):
        events, records, _, _ = self.simulate(modern=False)
        self.assertFalse(any(event.startswith('config-retirement-') for event in events))
        self.assertNotIn('config-retirement-prepared.json', records)
        self.assertEqual([row['config_stamp'] for row in records['retained-entry.json']],
                         [row['config_stamp'] for row in records['after.json']])

    def test_config_preparation_or_validation_failure_never_stops_or_mutates_live_cohort(self):
        for failure in ('config-prepare', 'config-check'):
            with self.subTest(failure=failure):
                events, records, units, plan = self.simulate(failure)
                for event in ('stop-all', 'config-retirement-install', 'config-retirement-restore', 'start'):
                    self.assertNotIn(event, events)
                for row in plan['units']:
                    self.assertEqual(units[row['role']], base64.b64decode(row['before']))

    def test_partial_config_install_or_unit_failure_restores_configs_after_old_units(self):
        for failure in ('config-install', 'partial-install', 'daemon-reload'):
            with self.subTest(failure=failure):
                events, records, units, plan = self.simulate(failure)
                self.assertIn('config-retirement-restore', events)
                self.assertLess(events.index('config-retirement-restore'), events.index('rollback-reload'))
                self.assertNotIn('start-intent.json', records)
                self.assertNotIn('start', events)
                self.assertTrue(records['rollback.json']['restored_previous_stopped_cohort'])
                self.assertTrue(records['rollback.json']['config_identity_reconciliation_required'])
                self.assertFalse(records['rollback.json']['old_daemons_restarted'])
                self.assertEqual(records['rollback.json']['config_retirement_restored_receipt'],
                                 'config-retirement-restored.json')
                for row in plan['units']:
                    self.assertEqual(units[row['role']], base64.b64decode(row['before']))

    def test_failed_start_retains_candidate_configs_and_never_restores_old_configuration(self):
        events, records, _, _ = self.simulate('start')
        self.assertIn('start-intent.json', records)
        self.assertIn('failed-start-stop', events)
        self.assertNotIn('config-retirement-restore', events)

    def test_capacity_is_rechecked_before_any_validator_stop(self):
        events, records, _, _ = self.simulate('capacity-before-stop')
        self.assertIn('capacity-before-apply.json', records)
        self.assertNotIn('capacity-before-stop.json', records)
        for event in ('stop-all', 'start'):
            self.assertNotIn(event, events)
        self.assertFalse(any(event.startswith('install-') for event in events))

    def test_healthy_update_completes_without_public_doctor_or_fabricated_diagnostic_claims(self):
        # The command mock rejects every doctor invocation, even a renamed one.
        events, records, _, _ = self.simulate()
        self.assertNotIn('public-doctor', events)
        self.assertNotIn('public_basic_doctor',
                         records['cohort-observation-intent.json']['remaining_actions'])
        result = records['result.json']
        self.assertTrue(result['runtime_update_complete'])
        self.assertTrue(result['cohort_processes_verified_after_final_observation'])
        self.assertTrue(result['all_own_retained_tips_verified_after_final_observation'])
        self.assertNotIn('cohort_processes_verified_after_public_doctor', result)
        self.assertNotIn('all_own_retained_tips_verified_after_public_doctor', result)

    def test_full_cohort_is_stopped_before_any_unit_replacement_and_readbacks_precede_success(self):
        events, records, _, _ = self.simulate()
        self.assertLess(events.index('verify-units'), events.index('stop-all'))
        self.assertEqual(events.count('stopped-owner-maintenance'), 1)
        self.assertLess(events.index('stop-all'), events.index('stopped-owner-maintenance'))
        self.assertLess(events.index('stopped-owner-maintenance'), events.index('install-taira-validator-1'))
        self.assertLess(events.index('install-taira-validator-4'), events.index('start'))
        self.assertIn('after.json', records)
        self.assertIn('retained-entry.json', records)
        self.assertIn('checkpoint-stopped.json', records)
        self.assertIn('checkpoint-restored.json', records)
        self.assertEqual(records['cohort-retained-tip.json'], {'height': 200, 'hash': 'c' * 64})
        self.assertEqual(records['cohort-ready.json']['retained_tip'], records['cohort-retained-tip.json'])
        self.assertTrue(records['cohort-ready.json']['startup_processes_unchanged'])
        self.assertTrue(records['result.json']['cohort_processes_verified_after_final_observation'])
        self.assertTrue(records['result.json']['all_own_retained_tips_verified_after_final_observation'])
        self.assertEqual(records['result.json']['cohort_fresh_quorum_confirmations'], 2)
        self.assertEqual(len(records['cohort-initial-quorum.json']['samples']), 2)
        self.assertEqual(len(records['cohort-ready.json']['quorum_confirmations']), 2)
        restored = events.index('checkpoint-restored')
        for role in guest.ROLES:
            for event in ('observe-' + role, 'hash-' + role, 'systemd-iroha3d-' + role + '.service'):
                self.assertIn(event, events[restored + 1:])
        self.assertFalse(records['result.json']['canary_applied_verified'])
        self.assertFalse(records['result.json']['application_ready'])
        self.assertNotIn('rollback-start', events)

    def test_stopped_owner_maintenance_failure_keeps_all_units_stopped_and_unchanged(self):
        events, records, units, plan = self.simulate('stopped-owner-maintenance')
        self.assertEqual(events.count('stopped-owner-maintenance'), 1)
        self.assertFalse(any(event.startswith('install-') for event in events))
        self.assertNotIn('start', events)
        self.assertNotIn('start-intent.json', records)
        self.assertNotIn('result.json', records)
        self.assertFalse(records['failure.json']['new_start_attempted'])
        self.assertTrue(records['rollback.json']['restored_previous_stopped_cohort'])
        self.assertFalse(records['rollback.json']['old_daemons_restarted'])
        for row in plan['units']:
            self.assertEqual(units[row['role']], base64.b64decode(row['before']))

    def test_partial_install_restores_every_old_unit_before_any_new_daemon_start(self):
        events, records, units, plan = self.simulate('partial-install')
        self.assertNotIn('start', events)
        self.assertNotIn('rollback-start', events)
        self.assertTrue(records['rollback.json']['restored_previous_stopped_cohort'])
        self.assertFalse(records['rollback.json']['old_daemons_restarted'])
        for row in plan['units']:
            self.assertEqual(units[row['role']], base64.b64decode(row['before']))

    def test_update_stops_the_installed_cohort_without_requiring_old_http(self):
        events, records, _, _ = self.simulate()
        self.assertIn('stop-all', events)
        self.assertIn('start', events)
        self.assertTrue(records['result.json']['state_preserved'])
        self.assertEqual(records['intent.json']['schema'], 'taira.daemon-update.plan.v1')
        self.assertEqual(records['before.json'][0]['systemd']['InvocationID'], 'f' * 32)
        self.assertEqual(len(records['stopped.json']['observations']), 4)

    def test_failure_after_start_never_blindly_rolls_back_execution_rules(self):
        events, records, _, _ = self.simulate('final-observation-http')
        self.assertIn('start', events)
        self.assertNotIn('rollback-start', events)
        self.assertTrue(records['failure.json']['new_start_attempted'])
        self.assertNotIn('result.json', records)
        self.assertIn('failed-start-stop', events)
        self.assertTrue(records['failed-start-stopped.json']['all_four_stopped'])

    def test_failure_record_enospc_does_not_prevent_stopping_failed_candidate(self):
        events, records, _, _ = self.simulate('failure-record')
        self.assertIn('failed-start-stop', events)
        self.assertTrue(records['failed-start-stopped.json']['all_four_stopped'])
        self.assertNotIn('failure.json', records)
        self.assertNotIn('result.json', records)
        self.assertNotIn('rollback-start', events)

    def test_final_cohort_failures_cannot_report_success_or_restart_old_daemons(self):
        for failure in ('final-observation-invocation', 'final-observation-pid',
                        'final-observation-http', 'final-observation-hash'):
            with self.subTest(failure=failure):
                events, records, _, _ = self.simulate(failure)
                self.assertIn('checkpoint-restored', events)
                self.assertIn('after.json', records, 'retain the earlier startup observations')
                self.assertIn('checkpoint-restored.json', records)
                self.assertTrue(records['failure.json']['new_start_attempted'])
                self.assertNotIn('cohort-ready.json', records)
                self.assertNotIn('result.json', records)
                self.assertNotIn('rollback.json', records)
                self.assertNotIn('rollback-start', events)

    def test_actual_late_failure_records_can_recover_without_promoting_partial_observations(self):
        for failure in ('final-observation-invocation', 'final-observation-pid',
                        'final-observation-http', 'final-observation-hash'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                _, records, _, failed = self.simulate(failure)
                root = Path(temporary).resolve()
                failed_directory = root / failed['operation']
                required = {name: records[name] for name in guest.FAILED_START_RECORDS}
                reference = write_failed_reference(failed_directory, required)
                for name, value in records.items():
                    if name not in required:
                        (failed_directory / name).write_text(json.dumps(value))
                self.assertTrue((failed_directory / 'after.json').exists())
                self.assertTrue((failed_directory / 'checkpoint-restored.json').exists())
                build, prior = fixture()
                build['commit'] = 'c' * 40
                recovery_guest = fresh_guest()
                plan = runner.make_plan(build, deployment(), prior, recovery_guest,
                                        'update-' + '3' * 32, reference)
                baseline = root / deployment()['current']['attempt_name']
                baseline.mkdir()
                baseline_records = {
                    'intent.json': prior, 'after.json': records['before.json'],
                    'checkpoint-stopped.json': records['checkpoint-stopped.json'],
                    'checkpoint-restored.json': records['checkpoint-restored.json'],
                    'result.json': {'schema': 'taira.daemon-update.result.v1',
                                    'runtime_update_complete': True, 'state_preserved': True,
                                    'retained_native_snapshot_verified': True,
                                    'commit': recovery_guest.PREDECESSOR['commit'],
                                    'network_id': recovery_guest.NETWORK}}
                for name, value in baseline_records.items():
                    (baseline / name).write_text(json.dumps(value))
                with patch.object(recovery_guest, 'BASE', root), \
                     patch.object(recovery_guest, 'native_kura_hash', return_value='c' * 64), \
                     patch.object(recovery_guest, 'stamp', return_value=[0] * 6 + [2_000_000]), \
                     patch.object(recovery_guest, 'native_digest', return_value='b' * 64), \
                     patch.object(recovery_guest, 'stop_all') as stop:
                    retained = recovery_guest.retained_attempt(plan)
                    self.assertEqual(retained, (records['before.json'], records['checkpoint-stopped.json']))
                    self.assertEqual(retained[0][0]['public']['commit'], recovery_guest.PREDECESSOR['commit'])
                    self.assertNotEqual(retained[0][0]['public']['commit'], records['after.json'][0]['public']['commit'])
                    for name in ('result.json', 'rollback.json'):
                        marker = failed_directory / name
                        marker.write_text('{}')
                        with self.assertRaisesRegex(RuntimeError, 'success or rollback marker'):
                            recovery_guest.retained_attempt(plan)
                        marker.unlink()
                    stop.assert_not_called()

    def test_failed_start_recovery_keeps_historical_health_and_exact_rollback_boundary(self):
        for failure in (None, 'partial-install', 'start', 'final-observation-http'):
            with self.subTest(failure=failure):
                events, records, units, plan = self.simulate(failure, recovery=True)
                for row in records['before.json']:
                    self.assertEqual(row['public']['commit'], deployment()['current']['commit'])
                    self.assertEqual(row['executable'], plan['failed_start']['installed']['daemon'])
                    self.assertEqual(row['systemd']['InvocationID'], 'f' * 32)
                if failure == 'partial-install':
                    self.assertNotIn('start', events)
                    self.assertFalse(records['rollback.json']['old_daemons_restarted'])
                    self.assertFalse(records['failure.json']['new_start_attempted'])
                    for row in plan['units']:
                        self.assertEqual(units[row['role']], base64.b64decode(row['before']))
                        self.assertEqual(guest.unit_command(units[row['role']])[0],
                                         plan['failed_start']['installed']['daemon'])
                else:
                    self.assertIn('start', events)
                    self.assertNotIn('rollback.json', records)
                    for row in plan['units']:
                        self.assertEqual(units[row['role']], base64.b64decode(row['after']))
                if failure:
                    self.assertNotIn('result.json', records)
                else:
                    self.assertTrue(records['result.json']['runtime_update_complete'])

    def test_failed_start_recovery_cannot_repeat_an_existing_attempt(self):
        events, records, units, plan = self.simulate('attempt-exists', recovery=True)
        self.assertEqual(events, [])
        self.assertEqual(records, {})
        for row in plan['units']:
            self.assertEqual(units[row['role']], base64.b64decode(row['before']))

    def test_deployment_metadata_and_route_are_explicit_and_closed(self):
        value=deployment()
        with patch.object(runner.retry,'validate_ssh',return_value=['fixed']) as ssh:
            self.assertIs(runner.validate_deployment(value),value)
            self.assertEqual([call.args[0] for call in ssh.call_args_list],
                             [value['guest_ssh'], value['backing_ssh']])
            for key,bad in [('replay_floor',0),('public_origin','https://test.example/'),
                            ('roles',['one']),('ports',[8080]*4),('private_key','forbidden')]:
                changed=copy.deepcopy(value);changed[key]=bad
                with self.assertRaises(RuntimeError):runner.validate_deployment(changed)

    def test_two_operations_can_stage_the_same_candidate_without_overwriting_and_bind_successors(self):
        paths=[]
        commit='d'*40
        for operation in ['update-'+'1'*32,'update-'+'2'*32]:
            value=deployment()
            original=copy.deepcopy(value)
            plan=dict(plan_for(value=value), commit=commit, operation=operation)
            local_guest=fresh_guest();local_guest.configure(plan)
            expected=value['runtime_root']+'/release-'+commit+'-'+operation+'/bin/iroha3d_taira'
            paths.append(expected)
            self.assertEqual(str(local_guest.DAEMON),expected)
            self.assertEqual(str(local_guest.CLI),str(Path(expected).with_name('iroha')))
            transfer=runner.transfer_code('iroha3d_taira',True,plan,admission_for(plan))
            self.assertIn('release=base/'+repr(Path(expected).parents[1].name),transfer)
            self.assertIn('release.mkdir(mode=0o700)',transfer)
            self.assertIn('os.O_EXCL|os.O_NOFOLLOW',transfer)
            raw=b'exact retained operation plan'
            output=Path('/owner-private')/operation
            successor=runner.successor_deployment(plan,raw,output)
            self.assertEqual(successor['current']['daemon'],expected)
            self.assertEqual(successor['current']['attempt_name'],operation)
            self.assertEqual(successor['current']['commit'],commit)
            self.assertEqual(successor['current']['local_plan'],str(output/'plan.json'))
            self.assertEqual(successor['current']['local_plan_sha256'],runner.sha(raw))
            self.assertEqual(value,original)
            self.assertEqual(str(local_guest.ATTEMPT),value['runtime_root']+'/'+operation)
            self.assertEqual(local_guest.PUBLIC_ORIGIN,value['public_origin'])
            self.assertEqual(local_guest.PORTS,tuple(value['ports']))
            with self.assertRaisesRegex(RuntimeError,'one deployment'):
                local_guest.configure({'deployment':value,'commit':commit,'operation':operation})
        self.assertEqual(len(set(paths)),2)


    def test_partial_validator_stop_requires_read_only_reconciliation(self):
        for failure in ('partial-stop',):
            with self.subTest(failure=failure):
                events, records, units, plan = self.simulate(failure)
                self.assertNotIn('start', events)
                self.assertNotIn('rollback-reload', events)
                self.assertFalse(any(name.startswith('install-') for name in events))
                self.assertEqual('stop-all' in events, failure == 'partial-stop')
                self.assertTrue(records['reconciliation-required.json']['recovery_only'])
                self.assertFalse(records['reconciliation-required.json']['automatic_manager_retry'])
                for row in plan['units']:
                    self.assertEqual(units[row['role']], base64.b64decode(row['before']))

    def test_failure_record_io_never_suppresses_failed_cohort_containment(self):
        events, records, _, _ = self.simulate('failure-record')
        self.assertIn('failed-start-stop', events)
        self.assertNotIn('rollback-start', events)
        self.assertNotIn('result.json', records)


class CohortProgressTests(unittest.TestCase):
    def setUp(self):
        plan_for()
        self.now = 0.0
        self.rows = [{'role': role} for role in guest.ROLES]
        self.props = [{'ActiveState': 'active', 'SubState': 'running', 'ControlPID': '0',
                       'MainPID': str(42 + index), 'InvocationID': str(index + 1) * 32}
                      for index in range(4)]
        self.before = [{'role': role, 'config_stamp': [1], 'state_root_identity': [2],
                        'current_target': 'same', 'systemd': self.props[index],
                        'public': {'height': 200, 'commit': guest.OLD}}
                       for index, role in enumerate(guest.ROLES)]

    def run_catchup(self, sample, *, target=220, timeout=6, max_timeout=30, ready=None, systemd=None,
                    minimum_heights=None, receipts=None, digest=None):
        def observation(row, **kwargs):
            index = guest.ROLES.index(row['role'])
            result = copy.deepcopy(self.before[index])
            try:
                height = sample(index, self.now, result)
                # Exercise the real HTTP identity/floor checks with public
                # fixture responses, without procfs or a live service.
                with patch.object(guest, 'public_get', side_effect=[
                        {'blocks': height, 'build': {'git_commit_sha': result['public']['commit']}},
                        {'network_id': guest.NETWORK, 'chain_discriminant': 369}]):
                    result['public'] = guest.public_identity(
                        index, expected_commit=kwargs['expected_commit'],
                        minimum_height=kwargs['minimum_height'])
            except guest.StartupProbeUnavailable as error:
                result['public'] = None
                result['public_unavailable'] = str(error)
            return result

        def sleep(seconds):
            self.now += seconds

        with patch.object(guest.time, 'monotonic', side_effect=lambda: self.now), \
             patch.object(guest.time, 'sleep', side_effect=sleep), \
             patch.object(guest, 'observe', side_effect=observation), \
             patch.object(guest, 'systemd', side_effect=systemd or (lambda unit: self.props[guest.UNITS.index(unit)])), \
             patch.object(guest, 'native_kura_hash', side_effect=digest, return_value='c' * 64), \
             patch.object(guest, 'public_probe', side_effect=ready, return_value=b'Ready'), \
             patch.object(guest, 'stop_all') as stop:
            try:
                return guest.wait_for_cohort(
                    self.rows, self.before, after=True, commit=guest.OLD,
                    retained_tip={'height': target, 'hash': 'c' * 64},
                    timeout=timeout, max_timeout=max_timeout,
                    minimum_heights=minimum_heights, sample_receipts=receipts)
            finally:
                stop.assert_not_called()

    def test_observe_cohort_accepts_three_anchored_peers_and_rejects_two(self):
        current = copy.deepcopy(self.before)
        for row in current[:3]:
            row['public']['height'] = 220
        with patch.object(guest, 'observe', side_effect=lambda row, **kwargs:
                          copy.deepcopy(current[guest.ROLES.index(row['role'])])), \
             patch.object(guest, 'systemd', side_effect=lambda unit: self.props[guest.UNITS.index(unit)]), \
             patch.object(guest, 'native_kura_hash', return_value='c' * 64), \
             patch.object(guest, 'public_probe', return_value=b'Ready'):
            result = guest.observe_cohort(self.rows, self.before, after=True, commit=guest.OLD,
                                          retained_tip={'height': 220, 'hash': 'c' * 64})
            self.assertEqual(sum(row['cohort_observation']['anchored_quorum_member'] for row in result), 3)
            self.assertEqual(result[3]['public']['height'], 200)
            current[2]['public']['height'] = 200
            with self.assertRaisesRegex(RuntimeError, 'anchored retained quorum is not ready'):
                guest.observe_cohort(self.rows, self.before, after=True, commit=guest.OLD,
                                      retained_tip={'height': 220, 'hash': 'c' * 64})

    def test_startup_replay_prefix_waits_for_all_own_tips_and_fresh_anchor(self):
        receipts = []
        result = self.run_catchup(
            lambda index, now, row: (198 if now == 0 else 199) if now < 4 else 220,
            minimum_heights=[220] * 4, receipts=receipts)
        self.assertEqual(self.now, 6, 'two complete samples follow replay, not listener startup')
        self.assertEqual(len(receipts), 2)
        self.assertTrue(all(sample['quorum_roles'] == list(guest.ROLES) for sample in receipts))
        self.assertTrue(all(sample['unverified_roles'] == [] for sample in receipts))
        self.assertEqual([row['public']['height'] for row in result], [220] * 4)

    def test_startup_replay_prefix_stall_retains_original_deadline(self):
        with self.assertRaisesRegex(RuntimeError, 'cohort observation deadline.*unverified_roles'):
            self.run_catchup(lambda index, now, row: 199)
        self.assertEqual(self.now, 6)

    def test_regression_between_replay_prefixes_is_permanent(self):
        with self.assertRaisesRegex(RuntimeError, 'committed catch-up height regressed'):
            self.run_catchup(lambda index, now, row: 199 if now == 0 else 198)
        self.assertEqual(self.now, 2)

    def test_wrong_revision_in_lower_replay_prefix_is_immediately_fatal(self):
        def sample(index, now, row):
            row['public']['commit'] = 'f' * 40
            return 199
        with self.assertRaisesRegex(RuntimeError, 'candidate revision differs'):
            self.run_catchup(sample)
        self.assertEqual(self.now, 0)

    def test_two_fresh_samples_record_each_peer_without_synthetic_height_advance(self):
        receipts = []
        result = self.run_catchup(lambda index, now, row: 220, receipts=receipts)
        self.assertEqual(self.now, 2)
        self.assertEqual(len(receipts), 2)
        for sample in receipts:
            self.assertEqual(sample['quorum_roles'], list(guest.ROLES))
            self.assertEqual(sample['missing_roles'], [])
            self.assertEqual(sample['unverified_roles'], [])
        self.assertEqual([row['public']['height'] for row in result], [220] * 4)

    def test_temporarily_missing_verified_fourth_is_reported_and_never_counted(self):
        receipts = []
        def sample(index, now, row):
            if index == 3 and now >= 2:
                raise guest.StartupProbeUnavailable('listener unavailable')
            return 220
        result = self.run_catchup(sample, receipts=receipts)
        self.assertEqual(self.now, 2)
        self.assertEqual(receipts[-1]['quorum_roles'], list(guest.ROLES[:3]))
        self.assertEqual(receipts[-1]['missing_roles'], [guest.ROLES[3]])
        self.assertEqual(result[3]['public']['height'], 220)
        self.assertFalse(result[3]['cohort_observation']['public_fresh'])
        self.assertFalse(result[3]['cohort_observation']['anchored_quorum_member'])

    def test_never_observed_fourth_cannot_borrow_predecessor_source_identity(self):
        def sample(index, now, row):
            if index == 3:
                raise guest.StartupProbeUnavailable('listener unavailable')
            return 220
        with self.assertRaisesRegex(RuntimeError, 'cohort observation deadline.*unverified_roles'):
            self.run_catchup(sample)
        self.assertEqual(self.now, 6)

    def test_own_stopped_tip_must_be_restored_even_with_three_ready_peers(self):
        with self.assertRaisesRegex(RuntimeError, 'cohort observation deadline.*unverified_roles'):
            self.run_catchup(lambda index, now, row: 200 if index == 3 else 220,
                             minimum_heights=[200, 200, 200, 205])
        self.assertEqual(self.now, 6)

    def test_known_fourth_may_be_unready_without_blocking_three_ready_peers(self):
        receipts = []
        def ready(index, route, **kwargs):
            if index == 3:
                raise guest.StartupProbeUnavailable('HTTP 503')
            return b''
        result = self.run_catchup(lambda index, now, row: 220, ready=ready, receipts=receipts)
        self.assertEqual(self.now, 2)
        self.assertEqual(receipts[-1]['unready_roles'], [guest.ROLES[3]])
        self.assertFalse(result[3]['cohort_observation']['anchored_quorum_member'])

    def test_missing_samples_break_confirmation_sequence_and_stale_peers_cannot_vote(self):
        receipts = []
        def sample(index, now, row):
            if now == 2 and index >= 2:
                raise guest.StartupProbeUnavailable('listener unavailable')
            return 220
        self.run_catchup(sample, receipts=receipts)
        self.assertEqual(self.now, 6, 'the failed second sample requires two new samples')
        self.assertEqual(len(receipts), 2)
        self.assertTrue(all(sample['missing_roles'] == [] for sample in receipts))

    def test_two_ready_peers_and_two_stalled_peers_cannot_form_quorum(self):
        with self.assertRaisesRegex(RuntimeError, 'cohort observation deadline'):
            self.run_catchup(lambda index, now, row: 220 if index < 2 else 200)
        self.assertEqual(self.now, 6)

    def test_wrong_revision_or_malformed_response_on_fourth_is_immediately_fatal(self):
        for failure in ('revision', 'json'):
            with self.subTest(failure=failure):
                self.now = 0
                def sample(index, now, row):
                    if index == 3:
                        if failure == 'json':
                            raise RuntimeError('public identity is not valid JSON')
                        row['public']['commit'] = 'f' * 40
                    return 220
                with self.assertRaisesRegex(RuntimeError, 'revision differs|not valid JSON'):
                    self.run_catchup(sample)
                self.assertEqual(self.now, 0)

    def test_verified_minority_wrong_status_cannot_be_hidden_by_puzzle_503(self):
        def sample(index, now, row):
            if index == 3 and now >= 2:
                status = guest.public_identity(index, expected_commit=guest.OLD, minimum_height=220)
                row['public'].update(status)
            return 220
        with patch.object(guest, 'public_get', side_effect=[
                {'blocks': 220, 'build': {'git_commit_sha': 'f' * 40}},
                guest.StartupProbeUnavailable('puzzle 503')]) as read:
            with self.assertRaisesRegex(RuntimeError, 'candidate revision differs'):
                self.run_catchup(sample)
        self.assertEqual(self.now, 2, 'a completed first sample must not mask the new mismatch')
        self.assertEqual(read.call_args_list, [unittest.mock.call(3, '/status')])

    def test_conflicting_anchor_on_fourth_is_immediately_fatal_even_with_quorum(self):
        with self.assertRaisesRegex(RuntimeError, 'retained Kura prefix hash changed'):
            self.run_catchup(lambda index, now, row: 220,
                digest=lambda role, height: ('d' if role == guest.ROLES[3] else 'c') * 64)
        self.assertEqual(self.now, 0)

    def test_restart_count_on_fourth_is_fatal_even_if_pid_is_unchanged(self):
        def systemd(unit):
            props = dict(self.props[guest.UNITS.index(unit)])
            if unit == guest.UNITS[3]:
                props['NRestarts'] = '1'
            return props
        with self.assertRaisesRegex(RuntimeError, 'validator process changed'):
            self.run_catchup(lambda index, now, row: 220, systemd=systemd)
        self.assertEqual(self.now, 0)

    def test_three_ready_peers_do_not_wait_for_fourth_or_empty_blocks(self):
        result = self.run_catchup(lambda index, now, row: 200 + int(now) if index == 2 else 220)
        self.assertEqual(self.now, 2)
        self.assertEqual([row['public']['height'] for row in result], [220, 220, 202, 220])
        self.assertFalse(result[2]['cohort_observation']['anchored_quorum_member'])

    def test_needed_third_advancing_peer_can_finish_without_stalled_fourth(self):
        def sample(index, now, row):
            return 200 + int(now) if index == 0 else (200 if index == 2 else 220)
        result = self.run_catchup(sample)
        self.assertEqual(self.now, 22)
        self.assertEqual(sum(row['cohort_observation']['anchored_quorum_member'] for row in result), 3)

    def test_dead_listener_cannot_borrow_another_peers_progress_budget(self):
        def sample(index, now, row):
            if index == 2 and now >= 2:
                raise RuntimeError('validator not running')
            return 200 + int(now)
        with self.assertRaisesRegex(RuntimeError, 'not running'):
            self.run_catchup(sample)
        self.assertEqual(self.now, 2)

    def test_restart_or_wrong_candidate_never_earns_more_observation_time(self):
        for change in ('restart', 'commit'):
            with self.subTest(change=change):
                self.now = 0
                def sample(index, now, row):
                    if index == 2 and now >= 2:
                        if change == 'restart':
                            row['systemd']['InvocationID'] = 'f' * 32
                        else:
                            row['public']['commit'] = 'f' * 40
                    return 200 + int(now)
                def systemd(unit):
                    index = guest.UNITS.index(unit)
                    props = dict(self.props[index])
                    if change == 'restart' and index == 2 and self.now >= 2:
                        props['InvocationID'] = 'f' * 32
                    return props
                expected_error = ('validator process changed' if change == 'restart'
                                  else 'candidate revision differs')
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    self.run_catchup(sample, systemd=systemd)
                self.assertEqual(self.now, 2)

    def test_startup_restart_fails_before_any_healthy_http_observation(self):
        startup = [{'role': role, 'systemd': dict(props)}
                   for role, props in zip(guest.ROLES, self.props, strict=True)]
        def systemd(unit):
            props = dict(self.props[guest.UNITS.index(unit)])
            if self.now >= 2:
                props['MainPID'] = '999'
            return props
        def sleep(seconds):
            self.now += seconds
        def unavailable(row, **kwargs):
            result = copy.deepcopy(self.before[guest.ROLES.index(row['role'])])
            result['public'] = None
            result['public_unavailable'] = 'listener warming'
            return result
        with patch.object(guest.time, 'monotonic', side_effect=lambda: self.now), \
             patch.object(guest.time, 'sleep', side_effect=sleep), \
             patch.object(guest, 'systemd', side_effect=systemd), \
             patch.object(guest, 'public_probe', side_effect=guest.StartupProbeUnavailable('listener warming')), \
             patch.object(guest, 'observe', side_effect=unavailable) as read:
            with self.assertRaisesRegex(RuntimeError, 'validator process changed'):
                guest.wait_for_cohort(self.rows, self.before, after=True, commit=guest.OLD,
                    retained_tip={'height': 220, 'hash': 'c' * 64}, startup_processes=startup,
                    timeout=600, max_timeout=600)
        self.assertEqual(self.now, 2)
        self.assertEqual(read.call_count, 4)

    def test_advancing_but_unready_peer_does_not_extend_the_deadline(self):
        def ready(index, route, **kwargs):
            if self.now >= 2:
                raise guest.StartupProbeUnavailable('readyz 503')
            return b''
        with self.assertRaisesRegex(RuntimeError, 'cohort observation deadline.*unready_roles'):
            self.run_catchup(lambda index, now, row: 200 + int(now), ready=ready)
        self.assertEqual(self.now, 6)

    def test_first_healthy_late_sample_alone_does_not_extend_the_deadline(self):
        def sample(index, now, row):
            if now < 4:
                raise guest.StartupProbeUnavailable('warming')
            return 219
        with self.assertRaisesRegex(RuntimeError, 'cohort observation deadline'):
            self.run_catchup(sample)
        self.assertEqual(self.now, 6)

    def test_converged_observation_finishing_after_deadline_is_not_accepted(self):
        for deadline_kind in ('stall', 'absolute'):
            with self.subTest(deadline_kind=deadline_kind):
                self.now = 0
                def sample(index, now, row):
                    late_at = 4 if deadline_kind == 'stall' else 8
                    if now >= late_at and index == 3:
                        self.now = 7 if deadline_kind == 'stall' else 11
                    return 220 if now >= late_at else 200 + int(now)
                with self.assertRaisesRegex(RuntimeError, 'cohort observation deadline'):
                    self.run_catchup(sample, timeout=4 if deadline_kind == 'stall' else 6,
                                     max_timeout=10)

    def test_height_regression_is_rejected_before_a_later_recovery_can_hide_it(self):
        def sample(index, now, row):
            return (202 if now == 0 else 201) if index == 2 else 220
        with self.assertRaisesRegex(RuntimeError, 'committed catch-up height regressed'):
            self.run_catchup(sample)
        self.assertEqual(self.now, 2)

    def test_continuous_progress_has_an_absolute_deadline(self):
        with self.assertRaisesRegex(RuntimeError, 'cohort observation deadline'):
            self.run_catchup(lambda index, now, row: 200 + int(now),
                             target=1000, max_timeout=10)
        self.assertEqual(self.now, 10)

    def test_deadlines_reject_unbounded_inputs_and_host_covers_guest_maximum(self):
        for timeout, maximum in ((0, 30), (6, 5), (6, guest.COHORT_MAX_TIMEOUT_SECONDS + 1)):
            with self.subTest(timeout=timeout, maximum=maximum), \
                 self.assertRaisesRegex(RuntimeError, 'time bounds are invalid'):
                self.run_catchup(lambda index, now, row: 220, timeout=timeout, max_timeout=maximum)
        self.assertEqual(guest.COHORT_STALL_TIMEOUT_SECONDS, 600)
        self.assertEqual(guest.COHORT_MAX_TIMEOUT_SECONDS, 90 * 60)
        self.assertEqual(runner.GUEST_OPERATION_TIMEOUT_SECONDS,
                         guest.COHORT_MAX_TIMEOUT_SECONDS + 60 * 60 + guest.MAX_FAILED_START_ATTEMPTS * 4 * 20)
        tree = ast.parse(Path(runner.__file__).read_text())
        apply = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'apply_plan')
        remote = [node for node in ast.walk(apply) if isinstance(node, ast.Call)
                  and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                  and node.func.value.id == 'subprocess' and node.func.attr == 'run']
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                             and isinstance(node.func.value, ast.Name)
                             and node.func.value.id == 'subprocess' and node.func.attr == 'Popen'
                             for node in ast.walk(apply)))
        self.assertEqual(len(remote), 1)
        payload = next(keyword.value for keyword in remote[0].keywords if keyword.arg == 'input')
        self.assertIsInstance(payload, ast.Name)
        self.assertEqual(payload.id, 'payload')
        deadline = next(keyword.value for keyword in remote[0].keywords if keyword.arg == 'timeout')
        self.assertIsInstance(deadline, ast.Name)
        self.assertEqual(deadline.id, 'GUEST_OPERATION_TIMEOUT_SECONDS')


class ConfigRetirementReceiptTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_for()
        self.before = [{'role': role, 'config_stamp': [1, 10 + index, 0o100600, 0, 0, 1, 100, 90, 90],
                        'state_root_identity': [1, 200 + index], 'current_target': 'unchanged'}
                       for index, role in enumerate(guest.ROLES)]
        self.prepared = {'schema': 'taira.validator-config-retirement.prepared.v1',
                         'operation': self.plan['operation'], 'source_commit': self.plan['commit'],
                         'network_id': self.plan['network_id'], 'rows': []}
        for index, original in enumerate(self.before):
            source = guest.retained_config(original['role'])
            self.prepared['rows'].append({'role': original['role'], 'source_path': str(source),
                'staged_path': str(source.with_name('.' + source.name + '.' + OPERATION + '.retirement-next')),
                'original_path': str(source.with_name('.' + source.name + '.' + OPERATION + '.retirement-original')),
                'changed': True, 'source_sha256': 'a' * 64, 'output_sha256': 'b' * 64,
                'before_stamp': list(original['config_stamp']),
                'staged_stamp': [1, 30 + index, 0o100600, 0, 0, 1, 70, 95, 95]})

    def report(self, action, *, changed=True):
        value = copy.deepcopy(self.prepared)
        stage = {'prepare': 'prepared', 'install': 'installed', 'restore': 'restored'}[action]
        value['schema'] = 'taira.validator-config-retirement.' + stage + '.v1'
        for row in value['rows']:
            if not changed:
                row['changed'] = False
                row['output_sha256'] = row['source_sha256']
            if action != 'prepare':
                row[stage + '_stamp'] = list(row['staged_stamp'] if action == 'install' and changed
                                            else row['before_stamp'])
                if action == 'restore' and changed:
                    row['restored_stamp'][1] += 100
        return value

    def invoke_validation(self, report, action, prepared=None):
        metadata = {}
        for row in report['rows']:
            metadata[row['source_path']] = row[{'prepare': 'before', 'install': 'installed', 'restore': 'restored'}[action] + '_stamp']
            metadata[row['staged_path']] = row['staged_stamp']
        with patch.object(guest, 'stamp', side_effect=lambda path: metadata[str(path)]):
            return guest.validate_config_retirement(report, OPERATION, action, self.before, prepared)

    def test_config_allocation_is_explicit_for_v2_and_does_not_change_v1(self):
        plan = copy.deepcopy(self.plan)
        original = admission_for(plan, 'apply')['guest_plan']['allocations']
        self.assertFalse(any(row['label'] == 'native config retirement and rollback' for row in original))
        plan['schema'] = 'taira.daemon-update.plan.v2'
        plan['deployment'].update(schema='taira.runtime-deployment.v2', config_filename='config.toml',
                                  kura_hash_journal='storage/kura/blocks/canonical/blocks.hashes')
        plan['deployment']['current']['kind'] = 'completed-update'
        guest.validate_update_plan_shape(plan)
        rows = admission_for(plan, 'apply')['guest_plan']['allocations']
        config = next(row for row in rows if row['label'] == 'native config retirement and rollback')
        self.assertEqual(config['path'], plan['deployment']['config_root'])
        self.assertGreaterEqual(config['bytes'], 12 * 1024**2)
        self.assertGreaterEqual(config['inodes'], 12)

    def test_exact_prepared_installed_restored_and_noop_receipts_bind_native_stamps(self):
        for changed in (False, True):
            prepared = self.report('prepare', changed=changed)
            self.invoke_validation(prepared, 'prepare')
            for action in ('install', 'restore'):
                self.invoke_validation(self.report(action, changed=changed), action, prepared)
        self.assertFalse(guest.valid_config_stamp([1, 2]))
        self.assertFalse(guest.valid_config_stamp([1, 2, 0o100622, 0, 0, 1, 1, 1, 1]))

    def test_foreign_receipt_and_row_or_stamp_tamper_are_not_config_transition_authority(self):
        for kind in ('operation', 'source_commit', 'network_id', 'schema', 'extra', 'role', 'path',
                     'before', 'digest', 'changed', 'staged', 'installed', 'noop'):
            with self.subTest(kind=kind):
                report = self.report('install')
                row = report['rows'][0]
                if kind in ('operation', 'source_commit', 'network_id', 'schema'):
                    report[kind] += 'foreign'
                elif kind == 'extra': report['extra'] = True
                elif kind == 'role': row['role'] = guest.ROLES[1]
                elif kind == 'path': row['source_path'] += '.foreign'
                elif kind == 'before': row['before_stamp'][1] += 1
                elif kind == 'digest': row['output_sha256'] = 'c' * 64
                elif kind == 'changed': row['changed'] = False
                elif kind == 'staged': row['staged_stamp'][1] += 1
                elif kind == 'installed': row['installed_stamp'][2] |= 0o022
                elif kind == 'noop': row['installed_stamp'] = list(row['before_stamp'])
                with self.assertRaises(RuntimeError):
                    self.invoke_validation(report, 'install', self.prepared)
        report = self.report('install')
        with patch.object(guest, 'stamp', return_value=report['rows'][0]['before_stamp']):
            with self.assertRaisesRegex(RuntimeError, 'metadata changed'):
                guest.validate_config_retirement(report, OPERATION, 'install', self.before, self.prepared)

    def test_only_bound_transition_changes_config_identity_and_never_state_or_selector(self):
        report = self.report('install')
        old = self.before[0]
        new = dict(old, config_stamp=report['rows'][0]['installed_stamp'])
        with patch.object(guest, 'CONFIG_RETIREMENT', report):
            guest.compare_retained_identity(old, new, allow_config_retirement=True)
            with self.assertRaises(RuntimeError): guest.compare_retained_identity(old, new)
            for key, value in (('config_stamp', old['config_stamp']),
                               ('state_root_identity', [9, 9]), ('current_target', 'foreign')):
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    guest.compare_retained_identity(old, dict(new, **{key: value}), allow_config_retirement=True)

    def test_adapter_uses_public_readonly_fd_closes_it_and_requires_native_published_receipt(self):
        owner = {'pid': 991, 'start_time_ticks': 1234,
                 'argv': ['/usr/bin/python3', '-I', '-'], 'lock': {'device': 1, 'inode': 9}}
        for malformed, mismatch in ((False, False), (True, False), (False, True)):
            with self.subTest(malformed=malformed, mismatch=mismatch), tempfile.TemporaryDirectory() as directory,                  patch.object(guest, 'ATTEMPT', Path(directory)), patch.object(guest, 'stamp'),                  patch.object(guest, 'cohort_observation_owner', return_value=owner),                  patch.object(guest, 'validate_config_retirement') as validate,                  patch.object(guest, 'retained_public_record', return_value={} if mismatch else self.prepared):
                descriptors = []
                def command(argv, **kwargs):
                    fd, = kwargs['pass_fds']; descriptors.append(fd)
                    self.assertEqual(argv, [guest.CLI, 'taira', 'retire-validator-config', '--action', 'prepare',
                                           '--request-fd', str(fd)])
                    self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
                    request = json.loads(os.read(fd, 16384))
                    self.assertEqual(request, {'schema': 'taira.validator-config-retirement.request.v1',
                                              'operation_directory': directory, 'owner': owner})
                    return b'private-malformed-body' if malformed else json.dumps(self.prepared).encode()
                with patch.object(guest, 'command', side_effect=command) as native:
                    if malformed or mismatch:
                        with self.assertRaises(RuntimeError) as error:
                            guest.retire_validator_configs(OPERATION, 'prepare', self.before)
                        self.assertNotIn('private-malformed-body', str(error.exception))
                    else:
                        self.assertEqual(guest.retire_validator_configs(OPERATION, 'prepare', self.before), self.prepared)
                    native.assert_called_once()
                if malformed: validate.assert_not_called()
                else: validate.assert_called_once_with(self.prepared, OPERATION, 'prepare', self.before, None)
                with self.assertRaises(OSError): os.fstat(descriptors[0])


class RetainedRendererSourceTests(unittest.TestCase):
    def test_explicit_predecessor_renderer_is_digest_bound_without_source_or_deployment_rewrite(self):
        build, prior = fixture()
        value = deployment()
        before = copy.deepcopy(value)
        with tempfile.TemporaryDirectory() as directory:
            retained = Path(directory).resolve() / 'retained-renderer.py'
            retained.write_bytes((ROOT / 'scripts/taira_validator_unit.py').read_bytes())
            retained.chmod(0o600)
            with patch.object(runner, 'ROOT', Path(directory) / 'different-controller'):
                plan = runner.make_plan(build, value, prior, fresh_guest(), OPERATION,
                                        retained_renderer=retained)
            self.assertEqual(plan['retained_renderer_path'], str(retained))
            self.assertEqual(plan['renderer_sha256'], value['renderer_sha256'])
            self.assertEqual(value, before)
            retained.write_bytes(b'changed source')
            with self.assertRaisesRegex(RuntimeError, 'renderer changed'):
                runner.make_plan(build, value, prior, fresh_guest(), OPERATION,
                                 retained_renderer=retained)
            retained.unlink(); retained.symlink_to(ROOT / 'scripts/taira_validator_unit.py')
            with self.assertRaises((RuntimeError, runner.retry.RetryError)):
                runner.make_plan(build, value, prior, fresh_guest(), OPERATION,
                                 retained_renderer=retained)
        for path in ('relative.py', '/a/../renderer.py', '/a/renderer.py\n'):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                guest.validate_update_plan_shape(dict(plan, retained_renderer_path=path))


class StoppedOwnerMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_for()
        self.owner = {'pid': 991, 'start_time_ticks': 1234,
                      'argv': ['/usr/bin/python3', '-I', '-'],
                      'lock': {'device': 1, 'inode': 9}}
        self.report = {'schema': 'taira.stopped-owner-maintenance.result.v1',
                       'operation': self.plan['operation'], 'all_four_stopped_owners_clean': True}

    def invoke(self, raw=None, *, exit_code=0, timeout=False, error_type=None):
        raw = json.dumps(self.report).encode() if raw is None else raw
        descriptors = []
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(guest, 'ATTEMPT', Path(directory)), \
             patch.object(guest, 'stamp'), \
             patch.object(guest, 'cohort_observation_owner', return_value=self.owner) as owner:
            native_result = Path(directory) / 'stopped-owner-maintenance-result.json'
            def native(argv, **kwargs):
                fd, = kwargs['pass_fds']
                descriptors.append(fd)
                self.assertEqual(argv, [str(guest.CLI), 'taira', 'stopped-owner-maintenance',
                                        '--request-fd', str(fd)])
                self.assertEqual(kwargs['timeout'], 150)
                self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
                self.assertTrue(kwargs['capture_output'])
                self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
                info = os.fstat(fd)
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                self.assertEqual(info.st_nlink, 1)
                self.assertEqual(json.loads(os.read(fd, 16_385)), {
                    'schema': 'taira.stopped-owner-maintenance.request.v1',
                    'operation_directory': directory, 'owner': self.owner})
                if timeout:
                    raise subprocess.TimeoutExpired(argv, 150)
                # The real native command owns this receipt. Python's command
                # capture must use a distinct name and must not rewrite it.
                native_result.write_bytes(b'native-owned-receipt\n')
                return subprocess.CompletedProcess(argv, exit_code, raw, b'private-native-diagnostic')
            with patch.object(guest.subprocess, 'run', side_effect=native) as run:
                if error_type:
                    with self.assertRaises(error_type) as caught:
                        guest.stopped_owner_maintenance(self.plan['operation'])
                    self.assertNotIn('private-native-diagnostic', str(caught.exception))
                    self.assertNotIn('untrusted-body', str(caught.exception))
                else:
                    guest.stopped_owner_maintenance(self.plan['operation'])
                run.assert_called_once()
            owner.assert_called_once_with()
            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError):
                os.fstat(descriptors[0])
            if not timeout:
                self.assertEqual(native_result.read_bytes(), b'native-owned-receipt\n')
                self.assertEqual(json.loads((Path(directory) /
                    'stopped-owner-maintenance-command.result.json').read_bytes()),
                    {'exit_code': exit_code})

    def test_candidate_cli_receives_only_readonly_public_request_and_preserves_native_receipt(self):
        self.invoke()

    def test_incomplete_foreign_or_malformed_native_report_cannot_authorize_installation(self):
        reports = [b'untrusted-body', b'[]', b' ' * 16_385]
        for field, value in (('schema', 'unknown'), ('operation', 'update-' + 'f' * 32),
                             ('all_four_stopped_owners_clean', False),
                             ('all_four_stopped_owners_clean', 1)):
            reports.append(json.dumps(dict(self.report, **{field: value})).encode())
        reports.extend((json.dumps({'schema': self.report['schema']}).encode(),
                        json.dumps(dict(self.report, extra='untrusted-body')).encode()))
        for raw in reports:
            with self.subTest(raw=raw[:120]):
                self.invoke(raw, error_type=RuntimeError)

    def test_native_failure_or_timeout_closes_request_without_retry_or_diagnostic_disclosure(self):
        self.invoke(exit_code=1, error_type=guest.NativeCommandFailure)
        self.invoke(timeout=True, error_type=subprocess.TimeoutExpired)


class CohortObservationOwnerTests(unittest.TestCase):
    def setUp(self):
        plan = plan_for()
        self.device = os.makedev(8, 1)
        self.lock = [self.device, 9, 0o100600, 0, 0, 1, 0, 0, 0]
        self.proc = {
            '/proc/991/stat': b'991 (python3) S ' + b'0 ' * 18 + b'1234',
            '/proc/991/cmdline': b'/usr/bin/python3\0-I\0-\0',
            '/proc/locks': b'77: FLOCK ADVISORY WRITE 991 08:01:9 0 EOF\n'}
        self.owner = {'pid': 991, 'start_time_ticks': 1234,
                      'argv': ['/usr/bin/python3', '-I', '-'],
                      'lock': {'device': self.device, 'inode': 9}}
        self.intent = {'schema': guest.COHORT_OBSERVATION_SCHEMA, 'operation': plan['operation'],
                       'commit': plan['commit'], 'phase': 'cohort_observation', 'owner': self.owner,
                       'automatic_restart_or_rollback_after_start': False,
                       'remaining_actions': list(guest.COHORT_REMAINING_ACTIONS)}

    def verify(self, *, terminal=None):
        def read(path, limit):
            raw = self.proc[str(path)]
            if isinstance(raw, list):
                raw = raw.pop(0)
            self.assertLessEqual(len(raw), limit)
            return raw
        with patch.object(guest, 'read_bounded_proc', side_effect=read), \
             patch.object(guest, 'stamp', return_value=self.lock), \
             patch.object(guest.os.path, 'lexists', side_effect=terminal or (lambda path: False)), \
             patch.object(fcntl, 'flock') as flock:
            try:
                return guest.verify_cohort_observation_owner(self.intent)
            finally:
                flock.assert_not_called()

    def test_live_process_and_exact_flock_are_verified_without_lock_acquisition(self):
        self.assertEqual(self.verify(), self.owner)

    def test_changed_pid_start_time_argv_and_lock_cannot_be_reused(self):
        original = dict(self.proc)
        for path, raw in (
            ('/proc/991/stat', b'991 (python3) S ' + b'0 ' * 18 + b'9999'),
            ('/proc/991/stat', b'991 (python3) Z ' + b'0 ' * 18 + b'1234'),
            ('/proc/991/cmdline', b'/usr/bin/python3\0-c\0different\0'),
            ('/proc/locks', b'77: FLOCK ADVISORY WRITE 992 08:01:9 0 EOF\n'),
            ('/proc/locks', b'77: FLOCK ADVISORY WRITE 991 08:01:10 0 EOF\n'),
            ('/proc/locks', b'77: -> FLOCK ADVISORY WRITE 991 08:01:9 0 EOF\n'),
        ):
            with self.subTest(path=path, raw=raw):
                self.proc = dict(original, **{path: raw})
                with self.assertRaises(RuntimeError):
                    self.verify()

    def test_terminal_markers_are_checked_before_and_after_owner_projection(self):
        for name in ('result.json', 'failure.json', 'rollback.json'):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'already terminated'):
                self.verify(terminal=lambda path: path.name == name)
        calls = [0]
        def terminal(path):
            calls[0] += 1
            return calls[0] > 3 and path.name == 'result.json'
        with self.assertRaisesRegex(RuntimeError, 'owner changed or terminated'):
            self.verify(terminal=terminal)

    def test_final_process_sample_must_still_be_live_and_well_formed(self):
        original = self.proc['/proc/991/stat']
        for final in (b'991 (python3) Z ' + b'0 ' * 18 + b'1234',
                      b'991 (python3) S 0', b'malformed'):
            with self.subTest(final=final):
                self.proc['/proc/991/stat'] = [original, final]
                with self.assertRaises(RuntimeError):
                    self.verify()

    def test_lock_device_inode_and_custody_are_exact(self):
        original = self.lock[:]
        for index, value in ((0, os.makedev(8, 2)), (1, 10), (2, 0o100644), (3, 1000), (5, 2)):
            with self.subTest(index=index):
                self.lock = original[:]
                self.lock[index] = value
                with self.assertRaises(RuntimeError):
                    self.verify()

    def test_wrong_operation_phase_or_candidate_cannot_claim_the_observation(self):
        for field, value in (('operation', 'update-' + 'f' * 32), ('phase', 'install'),
                             ('commit', 'f' * 40), ('automatic_restart_or_rollback_after_start', True)):
            with self.subTest(field=field):
                original = self.intent[field]
                self.intent[field] = value
                with self.assertRaisesRegex(RuntimeError, 'intent differs'):
                    self.verify()
                self.intent[field] = original

    def test_proc_projection_reads_are_bounded(self):
        with patch.object(Path, 'open', return_value=io.BytesIO(b'a' * 5)):
            with self.assertRaisesRegex(RuntimeError, 'exceeds bound'):
                guest.read_bounded_proc(Path('/proc/locks'), 4)


class FailedStartChainTests(unittest.TestCase):
    def rebind(self, directory, chain, entries):
        """Re-pin deliberately changed public evidence without hiding structural tampering."""
        result = copy.deepcopy(chain)
        for index, (failed, records) in enumerate(entries):
            records['intent.json'] = failed
            result['attempts'][index] = write_failed_reference(
                Path(directory) / failed['operation'], records)['attempts'][0]
        return result

    def completed_guest_records(self, directory, prior, first):
        baseline = Path(directory) / deployment()['current']['attempt_name']
        baseline.mkdir()
        records = {'intent.json': prior, 'after.json': first['before.json'],
            'checkpoint-stopped.json': first['checkpoint-stopped.json'],
            'checkpoint-restored.json': [{'role': role, 'native_strict_checkpoint_verified': True}
                for role in deployment()['roles']],
            'result.json': {'schema': 'taira.daemon-update.result.v1',
                'runtime_update_complete': True, 'state_preserved': True,
                'retained_native_snapshot_verified': True,
                'commit': deployment()['current']['commit'], 'network_id': deployment()['network_id']}}
        for name, value in records.items():
            (baseline / name).write_text(json.dumps(value))

    def test_unchanged_artifacts_retry_a_failed_corrective_rollout(self):
        for depth in (1, 2, 3):
            with self.subTest(depth=depth):
                events, records, units, plan = CoordinatorTests.simulate(
                    self, recovery=True, same_artifacts=True, failed_chain_depth=depth)
                self.assertEqual(plan['commit'], plan['failed_start']['installed']['commit'])
                self.assertEqual(len(plan['failed_start']['attempts']), depth)
                self.assertTrue(records['result.json']['runtime_update_complete'])
                self.assertEqual(records['before.json'][0]['public']['commit'], deployment()['current']['commit'])
                self.assertNotEqual(guest.DAEMON, guest.PREVIOUS_DAEMON)
                for row in plan['units']:
                    self.assertEqual(units[row['role']], base64.b64decode(row['after']))
                self.assertLess(events.index('stop-all'), events.index('start'))
                self.assertNotIn('rollback-start', events)

    def test_chain_accepts_historical_reference_evidence_and_relocated_capture_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            build, prior, chain, entries = failed_chain_fixture(temporary, historical_second=True)
            # Embedded historical paths are not instructions or operational inputs.
            historical = entries[1][0]['failed_start']
            for ref in (historical['plan'], *historical['records'].values()):
                ref['path'] = '/inert/historical/capture/' + Path(ref['path']).name
            chain = self.rebind(temporary, chain, entries)
            plan = plan_for(build, prior, failed_start=chain)
            self.assertEqual(plan['failed_start']['installed']['attempt_name'], entries[-1][0]['operation'])
            self.assertNotEqual(entries[-1][1]['checkpoint-stopped.json'][0]['invocation_id'],
                                entries[-1][1]['checkpoint-stopped.json'][0]['proof_invocation_id'])

    def test_same_commit_binary_identity_is_enforced_for_all_three_artifacts(self):
        for index in (0, 1, 2):
            for field, value in (('sha256', 'd' * 64), ('size', 2_000_001), ('package', 'foreign')):
                with self.subTest(index=index, field=field), tempfile.TemporaryDirectory() as temporary:
                    build, prior, chain, _ = failed_chain_fixture(temporary)
                    build['artifacts'][index][field] = value
                    with patch.object(runner.subprocess, 'run') as remote:
                        with self.assertRaises(RuntimeError): plan_for(build, prior, failed_start=chain)
                    remote.assert_not_called()

    def test_nonadjacent_source_reuse_cannot_change_binary_identity(self):
        for artifact in (0, 1, 2):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as temporary:
                build, prior, chain, _ = failed_chain_fixture(temporary)
                build['commit'] = 'a' * 40
                build['artifacts'][artifact]['sha256'] = 'd' * 64
                with self.assertRaisesRegex(RuntimeError, 'ancestry artifacts'):
                    plan_for(build, prior, failed_start=chain)

    def test_historical_nonadjacent_source_reuse_is_revalidated(self):
        for artifact in (0, 1, 2):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as temporary:
                build, prior, chain, entries = failed_chain_fixture(temporary, commits=('a', 'c', 'a'))
                entries[-1][0]['artifacts'][artifact]['sha256'] = 'd' * 64
                chain = self.rebind(temporary, chain, entries)
                build['commit'] = 'd' * 40
                with self.assertRaisesRegex(RuntimeError, 'ancestry reused a source'):
                    plan_for(build, prior, failed_start=chain)

    def test_artifact_order_and_each_intermediate_unit_are_authenticated(self):
        for failure in ('artifact_order', 'unit_before', 'unit_after', 'baseline'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                build, prior, chain, entries = failed_chain_fixture(temporary)
                failed = entries[-1][0]
                if failure == 'artifact_order': failed['artifacts'].reverse()
                if failure == 'unit_before': failed['units'][1]['before'] = failed['units'][0]['before']
                if failure == 'unit_after': failed['units'][1]['after_sha256'] = 'd' * 64
                if failure == 'baseline': failed['retained_predecessor']['intent_sha256'] = 'd' * 64
                chain = self.rebind(temporary, chain, entries)
                with self.assertRaises(RuntimeError): plan_for(build, prior, failed_start=chain)

    def test_maximum_chain_is_bounded_and_remains_reusable(self):
        with tempfile.TemporaryDirectory() as temporary:
            build, prior, chain, _ = failed_chain_fixture(temporary, commits=('a',) * 16)
            plan = plan_for(build, prior, failed_start=chain)
            self.assertEqual(len(plan['failed_start']['attempts']), 16)

    def test_same_artifact_cli_plans_a_fresh_operation_without_building_or_contacting_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            value, build, descriptor, result = local_inputs(temporary)
            prior = json.loads(Path(value['current']['local_plan']).read_bytes())
            failed, records = failed_fixture(value, prior)
            reference = write_failed_reference(Path(temporary) / failed['operation'], records)
            reference_path = Path(temporary).resolve() / 'failed-chain.json'
            reference_path.write_text(json.dumps(reference))
            output = Path(temporary).resolve() / 'retry-plan.json'
            with patch.object(sys, 'argv', cli_argv(descriptor, result, output) +
                              ['--failed-start-chain', str(reference_path)]), \
                 patch.object(runner.subprocess, 'check_output', return_value='optimizations\n'), \
                 patch.object(runner.retry, 'validate_ssh', return_value=['approved']), \
                 patch.object(runner.subprocess, 'run') as remote, \
                 patch.object(runner, 'apply_plan') as apply, redirect_stdout(io.StringIO()):
                runner.main()
            plan = json.loads(output.read_bytes())
            self.assertEqual(plan['commit'], failed['commit'])
            self.assertNotEqual(plan['operation'], failed['operation'])
            self.assertEqual(plan['build_result_path'], str(result))
            self.assertEqual(plan['build_result_sha256'], runner.sha(result.read_bytes()))
            self.assertEqual(plan['artifacts'], failed['artifacts'])
            remote.assert_not_called(); apply.assert_not_called()

    def test_relocated_identical_prepared_binaries_are_not_a_new_source_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            build, prior, chain, _ = failed_chain_fixture(temporary)
            for row in build['artifacts']: row['path'] = '/new/retained/' + row['name']
            plan = plan_for(build, prior, failed_start=chain)
            self.assertEqual(plan['commit'], 'c' * 40)

    def test_public_evidence_byte_budgets_precede_decode_and_host_mutation(self):
        local_guest = fresh_guest()
        with patch.object(local_guest, 'MAX_FAILED_START_RECORD_BYTES', 4), \
             patch.object(local_guest, 'MAX_FAILED_START_CHAIN_BYTES', 6):
            budget = local_guest.FailedStartRecordBudget()
            budget.consume(b'1234')
            budget.consume(b'56')
            with self.assertRaisesRegex(RuntimeError, 'aggregate byte bound'):
                budget.consume(b'7')
            with self.assertRaisesRegex(RuntimeError, 'record exceeds byte bound'):
                local_guest.FailedStartRecordBudget().consume(b'12345')
        with tempfile.TemporaryDirectory() as temporary:
            build, prior, chain, _ = failed_chain_fixture(temporary)
            local_guest = fresh_guest()
            with patch.object(local_guest, 'MAX_FAILED_START_CHAIN_BYTES', 1), \
                 patch.object(runner.subprocess, 'run') as remote:
                with self.assertRaisesRegex(RuntimeError, 'aggregate byte bound'):
                    runner.make_plan(build, deployment(), prior, local_guest, OPERATION, chain)
            remote.assert_not_called()

    def test_completed_baseline_source_and_old_operational_reference_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            build, prior, chain, _ = failed_chain_fixture(temporary)
            build['commit'] = deployment()['current']['commit']
            with self.assertRaises(RuntimeError): plan_for(build, prior, failed_start=chain)
            build['commit'] = 'c' * 40
            old = dict(chain['attempts'][0], schema='taira.failed-start-reference.v1')
            old.pop('operation')
            with self.assertRaisesRegex(RuntimeError, 'bounded failed-start chain'):
                plan_for(build, prior, failed_start=old)

    def test_chain_rejects_missing_reordered_repeated_or_foreign_ancestry(self):
        for failure in ('empty', 'overlong', 'drop', 'reorder', 'duplicate', 'operation',
                        'current_operation', 'prefix', 'health', 'config', 'invocation',
                        'tip_regression', 'tip_conflict', 'checkpoint_regression'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                build, prior, chain, entries = failed_chain_fixture(temporary, commits=('a', 'c', 'd'))
                if failure == 'empty': chain['attempts'] = []
                elif failure == 'overlong': chain['attempts'] *= 6
                elif failure == 'drop': chain['attempts'].pop(1)
                elif failure == 'reorder': chain['attempts'].reverse()
                elif failure == 'duplicate': chain['attempts'][1] = chain['attempts'][0]
                elif failure == 'operation': chain['attempts'][1]['operation'] = 'update-' + '9' * 32
                elif failure == 'current_operation': chain['attempts'][1]['operation'] = OPERATION
                else:
                    failed, records = entries[1]
                    if failure == 'prefix':
                        failed['failed_start']['attempts'][0]['records']['failure.json']['sha256'] = 'd' * 64
                    if failure == 'health': records['before.json'][0]['public']['height'] = 198
                    if failure == 'config': records['before.json'][0]['config_stamp'] = [9, 9]
                    if failure == 'invocation': records['before.json'][0]['systemd']['InvocationID'] = 'f' * 32
                    if failure == 'tip_regression': records['checkpoint-stopped.json'][0]['kura_tip']['height'] = 199
                    if failure == 'tip_conflict': records['checkpoint-stopped.json'][0]['kura_tip']['hash'] = 'd' * 64
                    if failure == 'checkpoint_regression': records['checkpoint-stopped.json'][0]['checkpoint_height'] = 198
                    chain = self.rebind(temporary, chain, entries)
                with patch.object(runner.subprocess, 'run') as remote:
                    with self.assertRaises(RuntimeError): plan_for(build, prior, failed_start=chain)
                remote.assert_not_called()

    def test_guest_rechecks_every_ancestor_before_mutation(self):
        for failure in (None, 'ancestor_result', 'ancestor_rollback', 'ancestor_missing',
                        'ancestor_digest', 'ancestor_kura', 'candidate_daemon', 'candidate_cli',
                        'aggregate_bytes'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                build, prior, chain, entries = failed_chain_fixture(temporary)
                plan = plan_for(build, prior, failed_start=chain)
                self.completed_guest_records(temporary, prior, entries[0][1])
                ancestor = Path(temporary) / entries[0][0]['operation']
                if failure == 'ancestor_result': (ancestor / 'result.json').write_text('{}')
                if failure == 'ancestor_rollback': (ancestor / 'rollback.json').write_text('{}')
                if failure == 'ancestor_missing': (ancestor / 'failure.json').unlink()
                if failure == 'ancestor_digest': (ancestor / 'failure.json').write_text('{}')
                if failure == 'candidate_daemon': plan['artifacts'][0]['sha256'] = 'd' * 64
                if failure == 'candidate_cli': plan['artifacts'][1]['sha256'] = 'd' * 64
                with patch.object(guest, 'BASE', Path(temporary)), \
                     patch.object(guest, 'stamp', return_value=[0] * 6 + [2_000_000]), \
                     patch.object(guest, 'native_digest', return_value='b' * 64), \
                     patch.object(guest, 'MAX_FAILED_START_CHAIN_BYTES',
                                  1 if failure == 'aggregate_bytes' else 32 * 1024 * 1024), \
                     patch.object(guest, 'native_kura_hash', return_value=('d' if failure == 'ancestor_kura' else 'c') * 64) as kura, \
                     patch.object(guest, 'record') as record, patch.object(guest, 'stop_all') as stop:
                    if failure is None:
                        before, checkpoints = guest.retained_attempt(plan)
                        self.assertEqual(before, entries[-1][1]['before.json'])
                        self.assertEqual(checkpoints, entries[-1][1]['checkpoint-stopped.json'])
                        self.assertEqual(kura.call_count, 8)
                    else:
                        with self.assertRaises((RuntimeError, FileNotFoundError)):
                            guest.retained_attempt(plan)
                    record.assert_not_called(); stop.assert_not_called()


class KagamiArtifactAdmissionTests(unittest.TestCase):
    def test_kagami_identity_is_mandatory_before_any_plan_or_host_action(self):
        for mutation in ('missing', 'duplicate', 'package', 'digest', 'size', 'boolean_size'):
            with self.subTest(mutation=mutation):
                build, prior = fixture()
                row = build['artifacts'][2]
                if mutation == 'missing': build['artifacts'].pop(2)
                elif mutation == 'duplicate': build['artifacts'][3] = dict(row)
                elif mutation == 'package': row['package'] = 'iroha_cli'
                elif mutation == 'digest': row['sha256'] = 'invalid'
                elif mutation == 'size': row['size'] = 0
                else: row['size'] = True
                with patch.object(runner.subprocess, 'run') as remote:
                    with self.assertRaises(RuntimeError): plan_for(build, prior)
                remote.assert_not_called()

    def test_ordered_three_artifact_guest_identity_rejects_omission_reorder_and_substitution(self):
        plan = plan_for()
        value = fresh_guest()
        identity = value.artifact_identity(plan['artifacts'])
        self.assertEqual(tuple(row[0] for row in identity), ('iroha3d_taira', 'iroha', 'kagami'))
        for rows in (plan['artifacts'][:2], list(reversed(plan['artifacts'])),
                     [*plan['artifacts'][:2], dict(plan['artifacts'][1])]):
            with self.subTest(rows=rows):
                with self.assertRaises(RuntimeError): value.artifact_identity(rows)

    def test_kagami_transfer_is_exact_release_path_and_native_stream(self):
        plan = plan_for()
        tree = ast.parse(runner.transfer_code('kagami', False, plan, admission_for(plan)))
        code = ast.unparse(tree)
        self.assertIn("bins / 'kagami'", code)
        self.assertIn('os.O_EXCL | os.O_NOFOLLOW', code)
        self.assertIn("os.execv('/bin/cat', ['/bin/cat'])", code)
        self.assertNotIn('read_bytes', code)
        self.assertEqual(str(guest.KAGAMI), str(guest.DAEMON.with_name('kagami')))
        with self.assertRaises(RuntimeError): runner.transfer_code('../kagami', False, plan, admission_for(plan))


class DeploymentLockTests(unittest.TestCase):
    def test_missing_lifecycle_lock_is_not_created_and_existing_lock_spans_apply(self):
        observer = fresh_guest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            runtime = root/'runtime'; runtime.mkdir(mode=0o700)
            state = root/'deployment'; state.mkdir(mode=0o700)
            observer.DEPLOYMENT_STATE_ROOT = state
            plan = {'deployment': {'runtime_root': str(runtime)}}
            real_fstat = os.fstat
            def owned(fd):
                value = real_fstat(fd)
                return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0,
                    st_nlink=value.st_nlink, st_dev=value.st_dev, st_ino=value.st_ino,
                    st_size=value.st_size)
            def stamped(path, directory=False):
                value = Path(path).lstat()
                return [value.st_dev, value.st_ino, value.st_mode, 0, 0, value.st_nlink]
            lock = state/'.deployment.lock'
            with patch.object(observer.os, 'fstat', side_effect=owned), \
                 patch.object(observer, 'stamp', side_effect=stamped), \
                 patch.object(observer, 'apply') as apply:
                with self.assertRaises(FileNotFoundError):
                    observer.apply_locked(plan, CAPACITY_SOURCE)
                self.assertFalse(lock.exists()); apply.assert_not_called()
                self.assertIsNone(observer.DEPLOYMENT_LOCK_FD)
                lock.touch(mode=0o600)
                def check_held(*args):
                    descriptor = os.open(lock, os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        self.assertIsNotNone(observer.DEPLOYMENT_LOCK_FD)
                    finally:
                        os.close(descriptor)
                apply.side_effect = check_held
                observer.apply_locked(plan, CAPACITY_SOURCE)
                apply.assert_called_once_with(plan, CAPACITY_SOURCE)
                self.assertIsNone(observer.DEPLOYMENT_LOCK_FD)
                descriptor = os.open(lock, os.O_RDWR)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(descriptor)

    def test_native_transfer_requires_existing_lock_and_refuses_any_reset_marker(self):
        plan = plan_for()
        tree = ast.parse(runner.transfer_code('iroha', False, plan, admission_for(plan)))
        begin = next(index for index, item in enumerate(tree.body)
                     if isinstance(item, ast.Assign) and ast.unparse(item.targets[0]) == 'lock_path')
        end = next(index for index, item in enumerate(tree.body)
                   if isinstance(item, ast.Assign) and ast.unparse(item.targets[0]) == 'capacity_source')
        probe = compile(ast.Module(body=tree.body[begin:end], type_ignores=[]), '<transfer-lock>', 'exec')
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            scope = dict(os=os, stat=stat, fcntl=fcntl, state=state)
            lock = state/'.deployment.lock'
            with self.assertRaises(FileNotFoundError):
                exec(probe, scope)
            self.assertFalse(lock.exists())
            lock.touch(mode=0o600)
            (state/'.reset-owner.json').symlink_to(state/'missing')
            real_fstat = os.fstat
            def owned(fd):
                value = real_fstat(fd)
                return SimpleNamespace(st_mode=value.st_mode, st_uid=0, st_gid=0,
                    st_nlink=value.st_nlink, st_dev=value.st_dev, st_ino=value.st_ino)
            with patch.object(os, 'fstat', side_effect=owned):
                try:
                    with self.assertRaises(AssertionError):
                        exec(probe, scope)
                finally:
                    os.close(scope['lock'])
            self.assertTrue((state/'.reset-owner.json').is_symlink())

    def test_shared_deployment_lock_and_any_reset_marker_block_before_apply(self):
        guest = fresh_guest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root/'runtime'; runtime.mkdir()
            deployment_state = root/'deployment'; deployment_state.mkdir(mode=0o700)
            guest.DEPLOYMENT_STATE_ROOT = deployment_state
            plan = {'deployment': {'runtime_root': str(runtime)}}
            real_fstat = os.fstat
            def owned(fd):
                info = real_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0,
                    st_nlink=info.st_nlink, st_dev=info.st_dev, st_ino=info.st_ino, st_size=info.st_size)
            def stamped(path, directory=False):
                info = Path(path).lstat()
                return [info.st_dev, info.st_ino, info.st_mode, 0, 0, info.st_nlink]
            with patch.object(guest.os, 'fstat', side_effect=owned), \
                 patch.object(guest, 'stamp', side_effect=stamped), patch.object(guest, 'apply') as apply:
                fd = os.open(deployment_state/'.deployment.lock', os.O_RDWR|os.O_CREAT, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
                    with self.assertRaises(BlockingIOError): guest.apply_locked(plan, CAPACITY_SOURCE)
                finally:
                    os.close(fd)
                marker = deployment_state/'.reset-owner.json'
                marker.symlink_to(deployment_state/'missing')
                with self.assertRaisesRegex(RuntimeError, 'retained reset owner'):
                    guest.apply_locked(plan, CAPACITY_SOURCE)
                self.assertTrue(marker.is_symlink())
                apply.assert_not_called()
                self.assertIsNone(guest.DEPLOYMENT_LOCK_FD)


    def test_retired_worker_paths_reject_every_existing_kind_without_mutation(self):
        value = fresh_guest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, unit = root/'retired-state', root/'retired.service'
            with patch.object(value, 'RETIRED_WORKER_STATE', state), \
                 patch.object(value, 'RETIRED_WORKER_UNIT', unit), \
                 patch.object(value.subprocess, 'run') as process:
                value.reject_retired_epoch_worker()
                for path in (state, unit):
                    for kind in ('file', 'directory', 'dangling-link'):
                        with self.subTest(path=path, kind=kind):
                            if kind == 'file': path.write_bytes(b'opaque retained evidence')
                            elif kind == 'directory': path.mkdir()
                            else: path.symlink_to(root/'missing')
                            before = path.lstat()
                            with self.assertRaisesRegex(RuntimeError, 'retired epoch worker'):
                                value.reject_retired_epoch_worker()
                            self.assertEqual(path.lstat(), before)
                            if kind == 'directory': path.rmdir()
                            else: path.unlink()
                process.assert_not_called()

    def test_deployment_lock_must_exist_empty_and_retired_state_is_rejected_under_lock(self):
        value = fresh_guest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, state = root/'runtime', root/'state'
            runtime.mkdir(); state.mkdir()
            lock, retired = state/'.deployment.lock', root/'retired'
            plan = {'deployment': {'runtime_root': str(runtime)}}
            actual_fstat = os.fstat
            def owned(fd):
                info = actual_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0,
                    st_nlink=info.st_nlink, st_dev=info.st_dev, st_ino=info.st_ino, st_size=info.st_size)
            def stamped(path, directory=False):
                info = Path(path).lstat()
                return [info.st_dev, info.st_ino, info.st_mode, 0, 0, info.st_nlink]
            original_reject = value.reject_retired_epoch_worker
            def reject_while_held():
                contender = os.open(lock, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(contender)
                original_reject()
            with patch.object(value, 'DEPLOYMENT_STATE_ROOT', state), \
                 patch.object(value, 'RETIRED_WORKER_STATE', retired), \
                 patch.object(value, 'RETIRED_WORKER_UNIT', root/'retired.service'), \
                 patch.object(value, 'reject_retired_epoch_worker', side_effect=reject_while_held), \
                 patch.object(value.os, 'fstat', side_effect=owned), \
                 patch.object(value, 'stamp', side_effect=stamped), patch.object(value, 'apply') as apply:
                with self.assertRaises(FileNotFoundError): value.apply_locked(plan, CAPACITY_SOURCE)
                self.assertFalse(lock.exists())
                lock.write_bytes(b'not empty'); lock.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, 'invalid guest deployment lock'):
                    value.apply_locked(plan, CAPACITY_SOURCE)
                lock.write_bytes(b'')
                retired.symlink_to(root/'missing')
                with self.assertRaisesRegex(RuntimeError, 'retired epoch worker'):
                    value.apply_locked(plan, CAPACITY_SOURCE)
                apply.assert_not_called()
                self.assertTrue(retired.is_symlink())
                self.assertIsNone(value.DEPLOYMENT_LOCK_FD)
                retired.unlink()
                value.apply_locked(plan, CAPACITY_SOURCE)
                apply.assert_called_once_with(plan, CAPACITY_SOURCE)

    def test_retired_worker_plans_and_receipts_are_rejected_without_host_actions(self):
        for field in ('epoch_supervisor', 'epoch_supervisor_installed',
                      'epoch_supervisor_renderer_sha256'):
            with self.subTest(field=field), patch.object(runner.subprocess, 'run') as remote:
                build, prior = fixture()
                prior[field] = {'opaque': 'not decoded'}
                with self.assertRaisesRegex(RuntimeError, 'retired epoch worker plan'):
                    plan_for(build, prior)
                plan = plan_for()
                plan[field] = None
                with self.assertRaisesRegex(RuntimeError, 'retired epoch worker plan'):
                    fresh_guest().configure(plan)
                remote.assert_not_called()
        plan, records = failed_fixture()
        records['epoch-supervisor-paused.json'] = {}
        with tempfile.TemporaryDirectory() as directory:
            reference = write_failed_reference(directory, records)
            with self.assertRaisesRegex(RuntimeError, 'reference fields differ'):
                plan_for(failed_start=reference)

    def test_retired_worker_runner_and_schema_cannot_reappear(self):
        self.assertFalse((SCRIPTS/'taira_epoch_supervisor_unit.py').exists())
        self.assertFalse((SCRIPTS/'tests/taira_epoch_supervisor_unit_test.py').exists())
        source = GUEST_FILE.read_text()
        functions = {node.name for node in ast.walk(ast.parse(source))
                     if isinstance(node, ast.FunctionDef)}
        self.assertFalse(any(name.startswith('supervisor_') for name in functions))
        for path in (GUEST_FILE, SCRIPTS/'taira_update.py'):
            text = path.read_text()
            for retired in ('epoch-maintenance', 'epoch-supervisor-host',
                            'taira.epoch-supervisor-update.v1'):
                self.assertNotIn(retired, text)
        plan = plan_for()
        source = runner.transfer_code('iroha', False, plan, admission_for(plan))
        self.assertIn("state=Path('/var/lib/taira-deployment')", source)
        self.assertIn('lock=os.open(lock_path,os.O_RDWR|os.O_NOFOLLOW)', source)
        self.assertLess(source.index('fcntl.flock('), source.index("state/'.reset-owner.json'"))
        self.assertLess(source.index('retired epoch worker service'), source.index('release=base/'))
        self.assertNotIn('state.mkdir', source)
        self.assertFalse(plan['transaction_submission'])
        self.assertFalse(plan['python_transaction_submission'])


class ArtifactPreparationPhaseTests(unittest.TestCase):
    def test_preparation_is_explicit_and_separate_from_apply_or_plan_only(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, descriptor, result = local_inputs(directory)
            args = cli_argv(descriptor, result, descriptor.parent/'output')
            for invalid in (args + ['--prepare-artifacts'],
                            [value for value in args if value != '--plan-only'] + ['--prepare-artifacts', '--failed-start-chain', '/unused']):
                with patch.object(sys, 'argv', invalid), patch.object(runner.subprocess, 'run') as remote, \
                     patch.object(runner.subprocess, 'check_output') as observation:
                    with self.assertRaisesRegex(RuntimeError, 'prepare-artifacts is separate'):
                        runner.main()
                    remote.assert_not_called(); observation.assert_not_called()
            clean = ['taira_update.py', '--prepare-artifacts', '--deployment', str(descriptor),
                '--prepared-result', str(result), '--operation', OPERATION,
                '--output', str(descriptor.parent/'prepared-output')]
            with patch.object(sys, 'argv', clean), \
                 patch.object(runner.subprocess, 'check_output', return_value='optimizations'), \
                 patch.object(runner.retry, 'validate_ssh', return_value=['approved']), \
                 patch.object(runner, 'prepare_artifacts') as prepare, \
                 patch.object(runner, 'make_plan') as plan, patch.object(runner, 'apply_plan') as apply:
                runner.main()
                prepare.assert_called_once(); plan.assert_not_called(); apply.assert_not_called()

    def test_verification_requires_all_exact_preprovisioned_artifacts_and_never_creates_missing_file(self):
        guest = fresh_guest()
        plan = plan_for()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root/'deployment'; state.mkdir(mode=0o700)
            (state/'.deployment.lock').touch(mode=0o600)
            runtime = root/'runtime'; runtime.mkdir(mode=0o700)
            plan['deployment']['runtime_root'] = str(runtime)
            release = runtime/runner.release_name(plan); release.mkdir(mode=0o700)
            bins = release/'bin'; bins.mkdir(mode=0o700)
            for item in plan['artifacts']:
                with (bins/item['name']).open('wb') as out: out.truncate(item['size'])
                (bins/item['name']).chmod(0o755)
            guest.DEPLOYMENT_STATE_ROOT = state
            real_fstat = os.fstat
            def owned(fd):
                info=real_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode,st_uid=0,st_gid=0,
                    st_nlink=info.st_nlink,st_dev=info.st_dev,st_ino=info.st_ino,st_size=info.st_size)
            def stamp(path,directory=False):
                path=Path(path); info=path.lstat()
                if path.resolve()!=path or (not directory and info.st_nlink!=1):
                    raise RuntimeError('fixture public path custody differs')
                return [info.st_dev,info.st_ino,info.st_mode,0,0,info.st_nlink,
                        info.st_size,info.st_mtime_ns,info.st_ctime_ns]
            with patch.object(guest.os, 'geteuid', return_value=0), \
                 patch.object(guest.os, 'fstat', side_effect=owned), \
                 patch.object(guest, 'stamp', side_effect=stamp), \
                 patch.object(guest, 'native_digest', return_value='b'*64) as digest, \
                 redirect_stdout(io.StringIO()) as output:
                guest.verify_prepared_artifacts(plan)
                report=json.loads(output.getvalue())
                self.assertFalse(report['runtime_mutated'])
                self.assertEqual(digest.call_count,3)
                kagami=bins/'kagami'
                kagami.chmod(0o775)
                with self.assertRaisesRegex(RuntimeError,'custody differ'):
                    guest.verify_prepared_artifacts(plan)
                kagami.chmod(0o755)
                digest.return_value='f'*64
                with self.assertRaisesRegex(RuntimeError,'bytes or custody differ'):
                    guest.verify_prepared_artifacts(plan)
                digest.return_value='b'*64
                kagami.unlink()
                with self.assertRaises(FileNotFoundError): guest.verify_prepared_artifacts(plan)
                self.assertFalse(kagami.exists())


class StorageAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.plan = plan_for()

    @staticmethod
    def filesystem(path, *, device=1, free=32 * 1024**3):
        return dict(device=device, anchor=str(path), fragment_bytes=4096,
                    available_bytes=free, available_inodes=100000)

    def test_backing_owner_and_path_are_required_and_both_routes_are_pinned(self):
        for key in ('backing_ssh', 'backing_path'):
            value = deployment()
            del value[key]
            with self.subTest(missing=key), patch.object(runner.retry, 'validate_ssh') as ssh:
                with self.assertRaisesRegex(RuntimeError, 'deployment fields differ'):
                    runner.validate_deployment(value)
                ssh.assert_not_called()
        for path in ('relative', '/approved/../other', '/approved/guest\n'):
            value = dict(deployment(), backing_path=path)
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, 'runtime path'):
                runner.validate_deployment(value)
        value = deployment()
        with patch.object(runner.retry, 'validate_ssh', side_effect=[['guest'], RuntimeError('backing pin changed')]) as ssh:
            with self.assertRaisesRegex(RuntimeError, 'backing pin changed'):
                runner.validate_deployment(value)
        self.assertEqual(ssh.call_args.args, (value['backing_ssh'],))

    def test_actual_artifacts_and_each_guest_filesystem_are_charged_once(self):
        prepared = admission_for(self.plan)
        rows = prepared['guest_plan']['allocations']
        self.assertEqual(sum(row['label'] == 'guest filesystem headroom' for row in rows), 1)
        for artifact in self.plan['artifacts']:
            row = next(row for row in rows if row['label'] == 'candidate artifact ' + artifact['name'])
            self.assertEqual(row['bytes'], artifact['size'] + 4095 + 4096)
        shared = admission_for(self.plan, 'apply')
        self.assertEqual(sum(row['label'] == 'guest filesystem headroom'
                             for row in shared['guest_plan']['allocations']), 1)
        self.assertFalse(any(row['label'].startswith('candidate artifact')
                             for row in shared['guest_plan']['allocations']))
        paths = (self.plan['deployment']['runtime_root'],
                 '/etc/systemd/system', self.plan['deployment']['state_root'])
        separate = admission_for(self.plan, 'apply', inspect=lambda path:
                                 self.filesystem(path, device=paths.index(str(path)) + 1))
        self.assertEqual(len(separate['guest_capacity']['filesystems']), len(paths))
        self.assertEqual(sum(row['label'] == 'guest filesystem headroom'
                             for row in separate['guest_plan']['allocations']), len(paths))

    def test_full_state_filesystem_and_inode_exhaustion_refuse_despite_free_runtime(self):
        def inspect(path):
            state = str(path) == self.plan['deployment']['state_root']
            return self.filesystem(path, device=2 if state else 1, free=113 * 1024**2 if state else 32 * 1024**3)
        with self.assertRaisesRegex(RuntimeError, 'insufficient guest capacity before apply'):
            admission_for(self.plan, 'apply', inspect=inspect)
        with self.assertRaisesRegex(RuntimeError, 'inodes'):
            admission_for(self.plan, inspect=lambda path:
                          dict(self.filesystem(path), available_inodes=0))

    def test_changed_capacity_source_and_filesystem_are_rejected(self):
        observer = fresh_guest()
        with self.assertRaisesRegex(RuntimeError, 'capacity checker changed'):
            observer.storage_capacity(self.plan, CAPACITY_SOURCE + b'\n', 'prepare')
        calls = [0]
        def inspect(path):
            calls[0] += 1
            return self.filesystem(path, device=1 if calls[0] == 1 else 2)
        with self.assertRaisesRegex(RuntimeError, 'filesystems changed'):
            admission_for(self.plan, inspect=inspect)

    def test_mac_admission_precedes_guest_and_uses_its_full_measured_allocation(self):
        admission = admission_for(self.plan)
        calls = []
        def remote(route, payload, output, name):
            calls.append((route, payload, name))
            if name.startswith('guest'):
                return admission
            self.assertIn(b'sys.platform == "darwin"', payload)
            return {'schema': 'taira.disk-capacity.result.v1', 'passed': True, 'errors': []}
        with patch.object(runner, 'storage_remote', side_effect=remote):
            self.assertEqual(runner.admit_storage(self.plan, 'prepare', Path('/unused')), admission)
        self.assertEqual([row[2] for row in calls],
                         ['backing-capacity-before-prepare', 'guest-capacity-prepare', 'backing-capacity-prepare'])
        self.assertIs(calls[0][0], self.plan['deployment']['backing_ssh'])
        self.assertIs(calls[1][0], self.plan['deployment']['guest_ssh'])
        required = sum(row['bytes'] for row in admission['guest_plan']['allocations'])
        self.assertIn(str(required).encode(), calls[-1][1])

    def test_full_mac_or_guest_stops_before_next_storage_phase(self):
        for failed_phase in ('backing-capacity-before-prepare', 'guest-capacity-prepare', 'backing-capacity-prepare'):
            calls = []
            def remote(route, payload, output, name):
                calls.append(name)
                if name == failed_phase:
                    if name.startswith('guest'):
                        raise RuntimeError('insufficient guest capacity')
                    return {'schema': 'taira.disk-capacity.result.v1', 'passed': False,
                            'errors': ['113 MiB available']}
                return (admission_for(self.plan) if name.startswith('guest') else
                        {'schema': 'taira.disk-capacity.result.v1', 'passed': True, 'errors': []})
            with self.subTest(phase=failed_phase), patch.object(runner, 'storage_remote', side_effect=remote):
                with self.assertRaisesRegex(RuntimeError, 'capacity'):
                    runner.admit_storage(self.plan, 'prepare', Path('/unused'))
            self.assertEqual(calls[-1], failed_phase)
            if failed_phase.startswith('backing-capacity-before'):
                self.assertEqual(len(calls), 1)

    def test_preparation_uses_existing_coordination_root_under_locked_probe(self):
        observer = fresh_guest()
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve() / 'deployment'
            state.mkdir(mode=0o700)
            events = []
            @__import__('contextlib').contextmanager
            def held(plan):
                self.assertEqual(plan, self.plan)
                self.assertTrue(state.is_dir())
                self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
                events.append('locked')
                yield
                events.append('unlocked')
            def probe(*args):
                self.assertEqual(events, ['locked'])
                return {'fixture': True}
            with patch.object(observer, 'DEPLOYMENT_STATE_ROOT', state), \
                 patch.object(observer, 'stamp') as stamp, \
                 patch.object(observer, 'deployment_locks', held), \
                 patch.object(observer, 'storage_capacity', side_effect=probe), redirect_stdout(io.StringIO()):
                observer.storage_capacity_locked(dict(plan=self.plan, phase='prepare',
                    capacity_source=base64.b64encode(CAPACITY_SOURCE).decode()))
            self.assertEqual(events, ['locked', 'unlocked'])
            stamp.assert_not_called()
            self.assertEqual(list(state.iterdir()), [])

    def test_storage_refusal_prevents_apply_guest_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            build, _ = fixture()
            raw_build = json.dumps(build).encode()
            build_path = root / 'build.json'
            build_path.write_bytes(raw_build)
            plan = dict(self.plan, build_result_path=str(build_path),
                        build_result_sha256=runner.sha(raw_build))
            plan_path = root / 'plan.json'
            raw_plan = json.dumps(plan).encode()
            plan_path.write_bytes(raw_plan)
            args = SimpleNamespace(plan=plan_path, plan_sha256=runner.sha(raw_plan),
                                   output=root / 'attempt')
            with patch.object(runner, 'retained_artifacts'), \
                 patch.object(runner.retry, 'validate_ssh', return_value=['pinned']), \
                 patch.object(runner, 'admit_storage', side_effect=RuntimeError('full Mac')) as admit, \
                 patch.object(runner.subprocess, 'run') as dispatch, \
                 patch.object(runner, 'verify_prepared_remote') as verify:
                with self.assertRaisesRegex(RuntimeError, 'full Mac'):
                    runner.apply_plan(args)
            self.assertEqual(admit.call_args.args[1], 'apply')
            dispatch.assert_not_called(); verify.assert_not_called()

    def test_guest_apply_heartbeat_keeps_one_timeout_bound_submission_and_private_output(self):
        for timeout in (False, True):
            with self.subTest(timeout=timeout), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                build, _ = fixture()
                raw_build = json.dumps(build).encode()
                build_path = root / 'build.json'
                build_path.write_bytes(raw_build)
                plan = dict(self.plan, build_result_path=str(build_path),
                            build_result_sha256=runner.sha(raw_build))
                plan_path = root / 'plan.json'
                raw_plan = json.dumps(plan).encode()
                plan_path.write_bytes(raw_plan)
                args = SimpleNamespace(plan=plan_path, plan_sha256=runner.sha(raw_plan),
                                       output=root / 'attempt')
                heartbeat_seen = threading.Event()
                private = io.StringIO()
                original_progress = runner.guest_progress

                def progress(*values, **fields):
                    original_progress(*values, **fields)
                    if values[2] == 'running':
                        heartbeat_seen.set()

                def child(argv, **kwargs):
                    self.assertEqual(argv, ['pinned'])
                    self.assertEqual(kwargs['timeout'], runner.GUEST_OPERATION_TIMEOUT_SECONDS)
                    self.assertEqual(kwargs['input'][:len(GUEST_FILE.read_bytes())],
                                     GUEST_FILE.read_bytes())
                    kwargs['stderr'].write(b'private-secret\n')
                    self.assertTrue(heartbeat_seen.wait(2), 'heartbeat did not fire while guest was running')
                    if timeout:
                        raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
                    return subprocess.CompletedProcess(argv, 17)

                with patch.object(runner, 'retained_artifacts'), \
                     patch.object(runner.retry, 'validate_ssh', return_value=['pinned']), \
                     patch.object(runner, 'admit_storage'), \
                     patch.object(runner, 'verify_prepared_remote'), \
                     patch.object(runner, 'GUEST_PROGRESS_SECONDS', 0.01), \
                     patch.object(runner, 'guest_progress', side_effect=progress), \
                     patch.object(runner.subprocess, 'run', side_effect=child) as dispatch, \
                     redirect_stderr(private):
                    with self.assertRaises(subprocess.TimeoutExpired if timeout else RuntimeError):
                        runner.apply_plan(args)
                self.assertEqual(dispatch.call_count, 1)
                events = [json.loads(line) for line in private.getvalue().splitlines()]
                self.assertEqual(events[0]['status'], 'started')
                self.assertTrue(any(row['status'] == 'running' for row in events))
                self.assertEqual(events[-1]['status'], 'failed')
                self.assertEqual(events[-1]['private_log'], str(args.output))
                self.assertEqual(events[-1].get('error_type') if timeout else events[-1].get('exit_code'),
                                 'TimeoutExpired' if timeout else 17)
                self.assertNotIn('private-secret', private.getvalue())
                self.assertEqual((args.output / 'stderr.log').read_bytes(), b'private-secret\n')
                self.assertEqual(stat.S_IMODE((args.output / 'stderr.log').stat().st_mode), 0o600)
                if timeout:
                    self.assertFalse((args.output / 'exit.json').exists())
                else:
                    self.assertEqual(json.loads((args.output / 'exit.json').read_bytes()),
                                     {'exit_code': 17})

    def test_storage_refusal_prevents_artifact_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            build, _ = fixture()
            args = SimpleNamespace(operation=OPERATION, output=Path(directory) / 'attempt',
                                   prepared_result=Path(directory) / 'build.json')
            with patch.object(runner, 'retained_artifacts', return_value=[]), \
                 patch.object(runner.retry, 'validate_ssh', return_value=['pinned']), \
                 patch.object(runner, 'admit_storage', side_effect=RuntimeError('full Mac')) as admit, \
                 patch.object(runner.subprocess, 'run') as transfer, \
                 patch.object(runner, 'verify_prepared_remote') as verify:
                with self.assertRaisesRegex(RuntimeError, 'full Mac'):
                    runner.prepare_artifacts(args, deployment(), json.dumps(build).encode())
            self.assertEqual(admit.call_args.args[1], 'prepare')
            transfer.assert_not_called(); verify.assert_not_called()

    def test_apply_capacity_refusal_precedes_attempt_and_runtime_mutations(self):
        observer = fresh_guest()
        with patch.object(observer.os, 'geteuid', return_value=0), \
             patch.object(observer, 'storage_capacity', side_effect=RuntimeError('full guest')), \
             patch.object(observer, 'retained_attempt') as retained, \
             patch.object(observer, 'write_new') as write, \
             patch.object(observer, 'command') as native:
            with self.assertRaisesRegex(RuntimeError, 'full guest'):
                observer.apply(self.plan, CAPACITY_SOURCE)
        retained.assert_not_called(); write.assert_not_called(); native.assert_not_called()

    def test_transfer_rechecks_capacity_under_lock_before_any_artifact_write(self):
        admission = admission_for(self.plan)
        tree = ast.parse(runner.transfer_code('iroha', False, self.plan, admission))
        source = ast.unparse(tree)
        self.assertLess(source.index('fcntl.flock('), source.index("capacity['evaluate']("))
        self.assertLess(source.index("capacity['evaluate']("), source.index('release = base'))
        # Execute the real generated capacity statements with the actual checker,
        # forcing statvfs to report exhaustion before any transfer statements run.
        begin = next(index for index, item in enumerate(tree.body)
                     if isinstance(item, ast.Assign) and isinstance(item.targets[0], ast.Name)
                     and item.targets[0].id == 'capacity_source')
        end = next(index for index, item in enumerate(tree.body)
                   if isinstance(item, ast.Expr) and isinstance(item.value, ast.Call)
                   and ast.unparse(item.value.func) == 'os.set_inheritable')
        probe = ast.Module(body=tree.body[begin:end], type_ignores=[])
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory).resolve()
            local_plan = copy.deepcopy(self.plan)
            local_plan['deployment']['runtime_root'] = str(local)
            local_admission = admission_for(local_plan, inspect=lambda path:
                dict(self.filesystem(path), device=local.stat().st_dev))
            local_tree = ast.parse(runner.transfer_code('iroha', False, local_plan, local_admission))
            probe.body = local_tree.body[begin:end]
            exhausted = SimpleNamespace(f_frsize=4096, f_bsize=4096, f_bavail=0, f_favail=100000)
            with patch.object(os, 'fstatvfs', return_value=exhausted):
                with self.assertRaisesRegex(AssertionError, 'insufficient guest capacity before artifact transfer'):
                    exec(compile(probe, '<actual-transfer-capacity>', 'exec'),
                         {'base64': base64, 'hashlib': __import__('hashlib'), 'Path': Path})
        # Only the completed daemon allocation is removed on the second transfer.
        self.assertNotIn("'candidate artifact iroha3d_taira'", source)
        self.assertIn("'candidate artifact iroha'", source)
        self.assertIn("'candidate artifact kagami'", source)


class BackingRecordAuthoringTests(unittest.TestCase):
    def authoring_inputs(self, directory):
        root = Path(directory).resolve()
        value = deployment()
        route = value.pop('backing_ssh')
        backing = value.pop('backing_path')
        source = root / 'source.json'
        # Preserve original whitespace too, not just decoded semantic identity.
        raw = (json.dumps(value, indent=2) + '\n').encode()
        source.write_bytes(raw)
        route_path = root / 'route.json'
        route_path.write_text(json.dumps(route))
        return SimpleNamespace(deployment=source, backing_route=route_path,
                               backing_path=backing, output=root / 'bound.json'), raw, value, route

    def test_local_authoring_preserves_source_and_publishes_only_validated_current_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            args, raw, value, route = self.authoring_inputs(directory)
            output = io.StringIO()
            with patch.object(runner.retry, 'validate_ssh') as pins, \
                 patch.object(runner.subprocess, 'run') as remote, redirect_stdout(output):
                runner.bind_backing_storage(args)
            self.assertEqual(pins.call_args_list, [unittest.mock.call(value['guest_ssh']),
                                                   unittest.mock.call(route)])
            remote.assert_not_called()
            self.assertEqual(args.deployment.read_bytes(), raw)
            self.assertEqual(json.loads(args.output.read_bytes()), dict(value, backing_ssh=route,
                                                                        backing_path=args.backing_path))
            self.assertEqual(stat.S_IMODE(args.output.stat().st_mode), 0o600)
            self.assertEqual(json.loads(output.getvalue()), {'deployment': str(args.output),
                'source_sha256': runner.sha(raw), 'host_contacted': False, 'runtime_mutated': False})

    def test_pin_failure_partial_binding_unknown_fields_and_overwrites_are_refused(self):
        for mutation in ('pin', 'partial', 'bound', 'unknown', 'existing', 'source', 'symlink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                args, raw, value, route = self.authoring_inputs(directory)
                if mutation == 'partial': value['backing_path'] = args.backing_path
                if mutation == 'bound': value.update(backing_path=args.backing_path, backing_ssh=route)
                if mutation == 'unknown': value['surprise'] = True
                if mutation in ('partial', 'bound', 'unknown'):
                    raw = json.dumps(value).encode(); args.deployment.write_bytes(raw)
                if mutation == 'existing': args.output.write_bytes(b'retained')
                if mutation == 'source': args.output = args.deployment
                if mutation == 'symlink': args.output.symlink_to(args.deployment)
                before = args.output.read_bytes() if args.output.exists() else None
                with patch.object(runner.retry, 'validate_ssh',
                                  side_effect=RuntimeError('pin changed') if mutation == 'pin' else None), \
                     patch.object(runner.subprocess, 'run') as remote:
                    with self.assertRaises((RuntimeError, FileExistsError)):
                        runner.bind_backing_storage(args)
                remote.assert_not_called()
                self.assertEqual(args.deployment.read_bytes(), raw)
                if before is not None: self.assertEqual(args.output.read_bytes(), before)
                else: self.assertFalse(args.output.exists())

    def test_cli_dispatch_is_explicit_local_and_disallows_update_options(self):
        with tempfile.TemporaryDirectory() as directory:
            args, _, _, _ = self.authoring_inputs(directory)
            argv = ['taira_update.py', '--bind-backing-storage', '--deployment', str(args.deployment),
                    '--backing-route', str(args.backing_route), '--backing-path', args.backing_path,
                    '--output', str(args.output)]
            with patch.object(sys, 'argv', argv), \
                 patch.object(runner.subprocess, 'check_output', return_value='optimizations\n'), \
                 patch.object(runner, 'bind_backing_storage') as author, \
                 patch.object(runner.subprocess, 'run') as remote:
                runner.main()
            author.assert_called_once(); remote.assert_not_called()
            for extra in (['--operation', OPERATION], ['--plan-only'], ['--prepare-artifacts'],
                          ['--prepared-result', '/unused/build.json']):
                with self.subTest(extra=extra), patch.object(sys, 'argv', argv + extra), \
                     patch.object(runner, 'bind_backing_storage') as author:
                    with self.assertRaisesRegex(RuntimeError, 'backing authoring requires only'):
                        runner.main()
                author.assert_not_called()


class NativeReplayTokenBoundaryTests(unittest.TestCase):
    @staticmethod
    def events(error='error=NativeExecutionReplayRequired', separator=' ', suffix='', height_separator=' '):
        return [
            {'time_us': 1, 'message': 'Failed to load state snapshot' + separator + error + suffix},
            {'time_us': 2, 'message': 'Kura retains the configured-primary replay floor; rebuilding state from blocks'},
            {'time_us': 3, 'message': 'Sumeragi rebuilt the state from genesis and Kura' + height_separator + 'height=146'},
        ]

    def test_every_rust_unicode_whitespace_boundary_and_suffix_is_accepted(self):
        guest = fresh_guest()
        spaces = ' \t\n\r\v\f\u0085\u00a0\u1680' + ''.join(chr(n) for n in range(0x2000, 0x200b)) + '\u2028\u2029\u202f\u205f\u3000'
        for value in spaces:
            with self.subTest(codepoint=ord(value)):
                self.assertEqual(guest.authenticated_kura_replay_height(self.events(separator=value, suffix=value, height_separator=value)), 146)

    def test_prefixed_quoted_extended_or_nonfinal_error_tokens_are_rejected(self):
        guest = fresh_guest()
        for error in ['other:error=NativeExecutionReplayRequired', 'xerror=NativeExecutionReplayRequired',
                      '"error=NativeExecutionReplayRequired"', 'error=NativeExecutionReplayRequired.extra',
                      'error=NativeExecutionReplayRequired trailing=1']:
            with self.subTest(error=error), self.assertRaises(RuntimeError):
                guest.authenticated_kura_replay_height(self.events(error=error))

    def test_python_only_c0_spaces_and_bom_are_not_rust_boundaries(self):
        guest = fresh_guest()
        for value in ['\x1c', '\x1d', '\x1e', '\x1f', '\ufeff', '\u200b']:
            for selection in ['separator', 'suffix', 'height_separator']:
                with self.subTest(codepoint=ord(value), selection=selection), self.assertRaises(RuntimeError):
                    guest.authenticated_kura_replay_height(self.events(**{selection: value}))

    def test_exact_token_and_existing_order_and_positive_height_guards_remain(self):
        guest = fresh_guest()
        self.assertTrue(guest.native_replay_required_error('error=NativeExecutionReplayRequired'))
        self.assertFalse(guest.native_replay_required_error(''))
        for mutation in ['order', 'zero-height', 'duplicate-height']:
            events = self.events()
            if mutation == 'order': events[1]['time_us'] = 4
            if mutation == 'zero-height': events[2]['message'] = events[2]['message'].replace('height=146', 'height=0')
            if mutation == 'duplicate-height': events[2]['message'] += ' height=146'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                guest.authenticated_kura_replay_height(events)


if __name__ == '__main__':
    unittest.main()
