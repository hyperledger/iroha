"""Native custody, proof-fence and interrupted owner completion regressions.

Effects are confined to the sibling nginx fixture's owner-controlled directory;
only its mocked master signal is used. Admission tests use the actual pytest
parent, inherited descriptors and an independently opened competing lock.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

from taira_native_nginx_apply_test import MODULE as OWNER
from taira_native_nginx_apply_test import _identity, _inspection, _prior, native_apply

MODULE_PATH = Path(__file__).resolve().parents[1] / "taira_native_edge_completion.py"
SPEC = importlib.util.spec_from_file_location("taira_native_edge_completion", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_retained_private_file_accepts_inherited_group_and_pins_it(tmp_path, monkeypatch):
    path = tmp_path.resolve() / "published.conf"
    path.write_bytes(b"owner-private public include\n")
    path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        observed = MODULE.identity(os.fstat(fd))
        monkeypatch.setattr(MODULE.os, "getegid", lambda: observed["gid"] + 1)
        reference = dict(file=dict(path=str(path), identity=observed),
            sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        assert MODULE.retained_public(dict(fd=fd, reference=reference)) == path.read_bytes()
        changed = copy.deepcopy(reference)
        changed["file"]["identity"]["gid"] += 1
        with pytest.raises(RuntimeError, match="retained_identity_changed"):
            MODULE.retained_public(dict(fd=fd, reference=changed))
    finally:
        os.close(fd)


@pytest.mark.parametrize("field,value", [("uid", "foreign"), ("mode", 0o640), ("links", 2)])
def test_inherited_group_retains_private_file_custody_checks(tmp_path, field, value):
    path = tmp_path.resolve() / "published.conf"
    path.write_bytes(b"owner-private public include\n")
    path.chmod(0o600)
    observed = MODULE.identity(path.stat())
    observed["gid"] = os.getegid() + 1
    observed[field] = os.geteuid() + 1 if value == "foreign" else value
    with pytest.raises(RuntimeError, match="unsafe_retained_owner"):
        MODULE.validate_observed(dict(path=str(path), identity=observed))


def test_retained_directory_still_requires_process_group(tmp_path):
    path = tmp_path.resolve()
    observed = MODULE.identity(path.stat())
    observed.update(mode=0o700, gid=os.getegid() + 1)
    with pytest.raises(RuntimeError, match="unsafe_retained_owner"):
        MODULE.validate_observed(dict(path=str(path), identity=observed), directory=True)


def _write_public(path, value):
    body = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(body)
    path.chmod(0o600)
    return body


def _plan(request, root):
    candidate = root / "candidate-public.conf"
    import base64
    _write_public(candidate, base64.b64decode(request["candidate_base64"]))
    renderer = root / "renderer-public.py"
    _write_public(renderer, b"# maintained renderer fixture\n")
    reference = dict(path=str(renderer), sha256=hashlib.sha256(renderer.read_bytes()).hexdigest())
    # The prior native publisher, rather than this fixture renderer, determines
    # the renderer source identity retained by completion.
    reference["sha256"] = request["renderer_source_sha256"]
    return dict(schema=OWNER.PLAN_SCHEMA, provider="macstadium-dublin", host_kind=request["host_kind"],
        deployment_reference=reference, native=request["native"], master=request["master"],
        renderer_source=reference, candidate=dict(path=str(candidate), sha256=request["candidate_sha256"],
        owner_uid=os.geteuid()), destination=request["destination"], operation_id=request["operation_id"],
        publication=request["publication"])


class EffectAdmission:
    """Supply admission bindings while exercising the real maintained owner."""

    def __init__(self, request, root, action="rollback"):
        self.path = root / "completion"
        self.path.mkdir(mode=0o700)
        self.directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.directory_identity = MODULE.identity(os.fstat(self.directory))
        self.bindings = dict(operation_id="c" * 32, inventory_sha256="d" * 64,
            authorization_sha256="e" * 64, authorization_nonce="f" * 32, host_pair_sha256="1" * 64,
            host_identity_sha256="2" * 64, custody_root=str(root))
        self.plan = dict(schema="iroha.taira.public-reset.native-nginx-completion-plan.v1",
            nginx=_plan(request, root), completion_journal_basename="native-completion.ndjson",
            publication_effect=dict(kind="owned", value=None))
        self.packet = dict(action=action, plan=dict(reference=dict(sha256="3" * 64)),
            progress=dict(reference=dict(sha256="4" * 64)), fence=dict(kind="absent", value={}))
        self.refuse = None
        if action != "rollback":
            self.packet["fence"] = dict(kind="present", value=dict(reference=dict(reference=dict(sha256="5" * 64))))

    def verify(self):
        if self.refuse is not None:
            raise RuntimeError(self.refuse)
        if self.packet["action"] == "rollback" and (self.path / "global-proof.json").exists():
            raise RuntimeError("rollback_after_global_proof")
        return OWNER

    def refresh_directory(self):
        self.directory_identity = MODULE.identity(os.fstat(self.directory))

    def close(self):
        os.close(self.directory)


@pytest.fixture
def effect_admission(native_apply):
    request, root = _inspection(native_apply)
    admission = EffectAdmission(request, root)
    try:
        yield admission, root
    finally:
        admission.close()


def _complete(admission):
    journal = MODULE.CompletionJournal(admission)
    try:
        return MODULE.complete_owned(admission, journal), copy.deepcopy(journal.records)
    finally:
        journal.close()


def test_real_owner_rollback_restores_exact_previous_publication_and_closed_receipt(effect_admission):
    admission, root = effect_admission
    before_reload = int((root / "reload-count").read_text())
    result, records = _complete(admission)
    assert result["status"] == "rolled_back" and result["error_code"] is None, result
    assert result["action"] == "rollback" and result["global_proof_sha256"] is None
    assert set(result) == MODULE.BINDING_KEYS | {"schema", "action", "progress_before_sha256",
        "global_proof_sha256", "publication_operation_id", "completion_journal", "status", "error_code",
        "restored_owned_publication"}
    assert result["schema"] == MODULE.RECEIPT_SCHEMA
    assert (root / "conf.d/new-scoped.conf").read_bytes() == b"upstream selected { server 127.0.0.1:10080; }\n"
    assert int((root / "reload-count").read_text()) == before_reload + 1
    assert [row["phase"] for row in records] == ["admitted", "rollback_requested", "source_restored",
        "reload_requested", "publisher_terminal_requested", "publisher_terminal_requested",
        "publisher_terminal_requested", "publisher_terminal", "rolled_back"]
    witnesses = [row["publisher_write_intent"] for row in records if row["publisher_write_intent"] is not None]
    assert len(witnesses) == 2
    assert {witness["record"]["operation_id"] for witness in witnesses} == {"a"*32, "b"*32}
    assert not list((root / "conf.d").glob(".taira-nginx-backup-*"))
    assert "private-native" not in json.dumps(result) and "private-existing" not in json.dumps(result)
    observed = json.loads(json.dumps(result))["completion_journal"]["file"]["identity"]
    assert type(observed["mtime_ns"]) is int and observed["mtime_ns"] > 2**53
    restored = result["restored_owned_publication"]
    assert set(restored) == {"operation_id", "journal", "publication"}
    assert restored["operation_id"] == "a" * 32
    assert restored["publication"]["file"]["identity"] == MODULE.identity((root / "conf.d/new-scoped.conf").stat())
    assert restored["publication"]["sha256"] == hashlib.sha256((root / "conf.d/new-scoped.conf").read_bytes()).hexdigest()
    journal = Path(restored["journal"]["file"]["path"])
    assert restored["journal"]["file"]["identity"] == MODULE.identity(journal.stat())
    assert restored["journal"]["sha256"] == hashlib.sha256(journal.read_bytes()).hexdigest()
    assert json.loads(journal.read_text().splitlines()[-1])["publication_identity"] == _identity(root / "conf.d/new-scoped.conf")


def _configuration_exchange(admission, callback):
    """Permit atomic journal publication while guarding configuration effects."""
    exchange = OWNER.native_exchange
    expected = os.fstat(admission.directory)
    def guarded(directory, *names):
        actual = os.fstat(directory)
        if (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino) or any(
                name.endswith('.receipt.ndjson') for name in names):
            return exchange(directory, *names)
        return callback(directory, *names)
    return guarded


@pytest.mark.parametrize('forge_successor', [False, True])
def test_durable_external_writer_witness_reuses_stage_or_refuses_restamped_chain(effect_admission, monkeypatch, forge_successor):
    admission, root = effect_admission
    publisher = Path(admission.plan['nginx']['publication']['prior']['journal']['path'])
    exchange = OWNER.native_exchange
    interrupted = False
    foreign_intent = None
    def at_owner_publication(directory, first, second):
        nonlocal interrupted, foreign_intent
        if publisher.name not in {first,second} or interrupted:
            return exchange(directory,first,second)
        interrupted = True
        completion = [json.loads(line) for line in (admission.path/'native-completion.ndjson').read_bytes().splitlines()]
        proof = completion[-1]['publisher_write_intent']
        assert proof is not None and proof['record']['operation_id'] == admission.plan['nginx']['operation_id']
        assert proof['intent']['identity'] == _identity(Path(proof['intent']['path']))
        if forge_successor:
            exchange(directory,first,second)
            body = publisher.read_bytes()
            lines = body.splitlines(keepends=True)
            row = json.loads(lines[-1])
            foreign = root/'foreign-restamped-public-journal'
            foreign.write_bytes(body); foreign.chmod(0o600)
            binding = {key:_identity(foreign)[key] for key in ('device','inode','uid','gid','mode')}
            original_intent = json.loads(Path(row['journal_write_intent']['path']).read_bytes())
            original_intent['created_identity'] = binding
            foreign_intent = root/('.taira-native-nginx-write-'+row['operation_id']+'-'+str(row['sequence'])+'-'+('9'*32)+'.intent.json')
            foreign_intent.write_bytes((json.dumps(original_intent,sort_keys=True)+'\n').encode()); foreign_intent.chmod(0o600)
            row['journal_publication_identity'] = binding
            row['journal_write_intent'] = dict(path=str(foreign_intent),identity=_identity(foreign_intent),
                sha256=hashlib.sha256(foreign_intent.read_bytes()).hexdigest())
            foreign.write_bytes(b''.join(lines[:-1])+(json.dumps(row,sort_keys=True)+'\n').encode())
            os.replace(foreign,publisher)
        raise KeyboardInterrupt('external witness durable before lost owner publication acknowledgment')
    monkeypatch.setattr(OWNER,'native_exchange',at_owner_publication)
    with pytest.raises(KeyboardInterrupt): _complete(admission)
    assert interrupted
    reloads = (root/'reload-count').read_bytes()
    before = publisher.read_bytes(),_identity(publisher)
    monkeypatch.setattr(OWNER,'native_exchange',exchange)
    result, records = _complete(admission)
    if forge_successor:
        assert result['status'] == 'recovery_pending' and result['error_code'] == 'publisher_terminal_not_recorded', result
        assert (publisher.read_bytes(),_identity(publisher)) == before
        assert foreign_intent is not None and foreign_intent.exists()
    else:
        assert result['status'] == 'rolled_back' and result['error_code'] is None, result
        assert records[-1]['phase'] == 'rolled_back'
        assert sum(row['phase'] == 'rolled_back_unqualified' for row in
            [json.loads(line) for line in publisher.read_bytes().splitlines()]) == 1
    assert (root/'reload-count').read_bytes() == reloads


def test_seal_and_cleanup_require_proof_and_never_signal_or_restore(effect_admission, monkeypatch):
    admission, root = effect_admission
    admission.packet["action"] = "seal"
    admission.packet["fence"] = dict(kind="present", value=dict(reference=dict(reference=dict(sha256="5" * 64))))
    destination = root / "conf.d/new-scoped.conf"
    expected = destination.read_bytes()
    monkeypatch.setattr(OWNER, "signal_master", lambda *args: pytest.fail("seal or cleanup signaled a master"))
    monkeypatch.setattr(OWNER, "native_exchange", _configuration_exchange(admission,
        lambda *args: pytest.fail("proof-fenced source was restored")))
    sealed, records = _complete(admission)
    assert sealed["status"] == "sealed", sealed
    assert sealed["restored_owned_publication"] is None
    assert [row["phase"] for row in records] == ["admitted", "seal_requested", "sealed"]
    assert list((root / "conf.d").glob(".taira-nginx-backup-*"))
    admission.packet["action"] = "cleanup"
    cleaned, records = _complete(admission)
    assert cleaned["status"] == "cleaned", cleaned
    assert cleaned["restored_owned_publication"] is None
    assert [row["phase"] for row in records][-2:] == ["cleanup_requested", "cleaned"]
    assert destination.read_bytes() == expected
    assert not list((root / "conf.d").glob(".taira-nginx-backup-*"))
    again, records_again = _complete(admission)
    assert again["status"] == "cleaned" and records_again == records


def test_cleanup_before_durable_seal_preserves_both_owned_sources(effect_admission):
    admission, root = effect_admission
    admission.packet["action"] = "cleanup"
    admission.packet["fence"] = dict(kind="present", value=dict(reference=dict(reference=dict(sha256="5" * 64))))
    before = (root / "conf.d/new-scoped.conf").read_bytes()
    result, records = _complete(admission)
    assert result["status"] == "recovery_pending" and result["error_code"] == "cleanup_before_seal"
    assert result["restored_owned_publication"] is None
    assert records[-1]["phase"] == "recovery_pending"
    assert (root / "conf.d/new-scoped.conf").read_bytes() == before
    assert len(list((root / "conf.d").glob(".taira-nginx-backup-*"))) == 1


def test_pre_effect_rollback_proves_incumbent_without_touching_it(effect_admission, monkeypatch):
    admission, root = effect_admission
    incumbent = MODULE.numeric_owned_publication(admission.plan["nginx"])
    intended = "d" * 32
    admission.plan["publication_effect"] = dict(kind="not_requested",
        value=dict(intended_operation_id=intended, incumbent=incumbent))
    destination = root / "conf.d/new-scoped.conf"
    publication_before = destination.read_bytes(), _identity(destination)
    journal = Path(incumbent["journal"]["file"]["path"])
    journal_before = journal.read_bytes(), _identity(journal)
    reloads = (root / "reload-count").read_bytes()
    monkeypatch.setattr(OWNER, "signal_master", lambda *args: pytest.fail("pre-effect rollback signaled nginx"))
    monkeypatch.setattr(OWNER, "native_exchange", _configuration_exchange(admission,
        lambda *args: pytest.fail("pre-effect rollback exchanged incumbent")))
    result, records = _complete(admission)
    assert result["status"] == "rolled_back" and result["error_code"] is None, result
    assert result["publication_operation_id"] == intended
    assert result["restored_owned_publication"] == incumbent
    assert [row["phase"] for row in records] == ["admitted", "rollback_requested", "rolled_back"]
    assert (destination.read_bytes(), _identity(destination)) == publication_before
    assert (journal.read_bytes(), _identity(journal)) == journal_before
    assert (root / "reload-count").read_bytes() == reloads
    assert _complete(admission)[1] == records


@pytest.mark.parametrize("fault", ["after_exchange", "after_signal", "after_publisher_append"])
def test_interrupted_rollback_resumes_exact_owned_intent_without_double_exchange(effect_admission, monkeypatch, fault):
    admission, root = effect_admission
    exchange, signal, append = OWNER.native_exchange, OWNER.signal_master, MODULE.CompletionJournal.append
    calls = dict(exchange=0, signal=0)
    crashed = False
    def exchange_once(*args):
        nonlocal crashed
        calls["exchange"] += 1
        exchange(*args)
        if fault == "after_exchange" and not crashed:
            crashed = True
            raise KeyboardInterrupt("owned child crash after exchange")
    def signal_once(*args):
        nonlocal crashed
        calls["signal"] += 1
        result = signal(*args)
        if fault == "after_signal" and not crashed:
            crashed = True
            raise KeyboardInterrupt("owned child crash after HUP")
        return result
    def append_once(self, phase, **kwargs):
        nonlocal crashed
        if fault == "after_publisher_append" and phase == "publisher_terminal" and not crashed:
            crashed = True
            raise KeyboardInterrupt("owned child crash after exact publisher suffix")
        return append(self, phase, **kwargs)
    monkeypatch.setattr(OWNER, "native_exchange", _configuration_exchange(admission, exchange_once))
    monkeypatch.setattr(OWNER, "signal_master", signal_once)
    monkeypatch.setattr(MODULE.CompletionJournal, "append", append_once)
    with pytest.raises(KeyboardInterrupt):
        _complete(admission)
    result, records = _complete(admission)
    assert result["error_code"] is None
    assert result["status"] == "rolled_back"
    assert calls["exchange"] == 1
    assert calls["signal"] == (2 if fault == "after_signal" else 1)
    publisher = Path(admission.plan["nginx"]["publication"]["prior"]["journal"]["path"])
    rows = [json.loads(line) for line in publisher.read_text().splitlines()]
    assert sum(row["phase"] == "rolled_back_unqualified" for row in rows) == 1
    assert records[-1]["phase"] == "rolled_back"


def test_foreign_substitution_after_exchange_preserves_both_names_and_requests_recovery(effect_admission, monkeypatch):
    admission, root = effect_admission
    exchange = OWNER.native_exchange
    foreign_body = b"foreign publication must remain\n"
    def substitute(*args):
        exchange(*args)
        foreign = root / "foreign.conf"
        _write_public(foreign, foreign_body)
        os.replace(foreign, root / "conf.d/new-scoped.conf")
    monkeypatch.setattr(OWNER, "native_exchange", _configuration_exchange(admission, substitute))
    before_reload = (root / "reload-count").read_bytes()
    result, _ = _complete(admission)
    assert result["status"] == "recovery_pending", result
    assert (root / "conf.d/new-scoped.conf").read_bytes() == foreign_body
    assert len(list((root / "conf.d").glob(".taira-nginx-backup-*"))) == 1
    assert (root / "reload-count").read_bytes() == before_reload


def test_publisher_suffix_refuses_unrelated_append_and_preserves_it(effect_admission, monkeypatch):
    admission, root = effect_admission
    append = MODULE.CompletionJournal.append
    publisher = Path(admission.plan["nginx"]["publication"]["prior"]["journal"]["path"])
    def append_foreign(self, phase, **kwargs):
        result = append(self, phase, **kwargs)
        if phase == "publisher_terminal_requested":
            with publisher.open("ab") as fd:
                fd.write(b'{"foreign":"public appendix"}\n')
        return result
    monkeypatch.setattr(MODULE.CompletionJournal, "append", append_foreign)
    result, _ = _complete(admission)
    assert result["status"] == "recovery_pending", result
    assert result["error_code"] in {"publisher_journal_suffix_changed", "native_identity_changed"}
    assert publisher.read_bytes().endswith(b'{"foreign":"public appendix"}\n')


def test_completion_journal_retains_immutable_intent_and_refuses_path_substitution(effect_admission):
    admission, root = effect_admission
    journal = MODULE.CompletionJournal(admission)
    try:
        mutable = {"nested": {"value": "admitted"}}
        journal.append("admitted", publication_identity=mutable, backup_identity=None,
                       publisher_journal=None)
        mutable["nested"]["value"] = "changed"
        assert journal.records[0]["publication_identity"]["nested"]["value"] == "admitted"
        foreign = root / "foreign-journal"
        _write_public(foreign, (admission.path / journal.name).read_bytes())
        os.replace(foreign, admission.path / journal.name)
        with pytest.raises(RuntimeError, match="completion_journal_changed"):
            journal.check()
    finally:
        journal.close()


def test_native_completion_never_python_reads_private_main(effect_admission, monkeypatch):
    admission, root = effect_admission
    private = (root / "nginx.conf").stat()
    native_pread = os.pread
    def public_only(fd, count, offset):
        observed = os.fstat(fd)
        assert (observed.st_dev, observed.st_ino) != (private.st_dev, private.st_ino), "private main reached Python"
        return native_pread(fd, count, offset)
    monkeypatch.setattr(MODULE.os, "pread", public_only)
    result, _ = _complete(admission)
    assert result["status"] == "rolled_back", result


def test_global_proof_arriving_after_rollback_intent_refuses_any_source_effect(effect_admission, monkeypatch):
    admission, root = effect_admission
    append = MODULE.CompletionJournal.append
    def publish_fence(self, phase, **kwargs):
        result = append(self, phase, **kwargs)
        if phase == "rollback_requested":
            _write_public(admission.path / "global-proof.json", b"owned proof fence\n")
        return result
    monkeypatch.setattr(MODULE.CompletionJournal, "append", publish_fence)
    monkeypatch.setattr(OWNER, "signal_master", lambda *args: pytest.fail("HUP after global fence"))
    monkeypatch.setattr(OWNER, "native_exchange", _configuration_exchange(admission,
        lambda *args: pytest.fail("exchange after global fence")))
    expected = (root / "conf.d/new-scoped.conf").read_bytes()
    result, records = _complete(admission)
    assert result["status"] == "recovery_pending" and result["error_code"] == "rollback_after_global_proof"
    assert records[-1]["phase"] == "rollback_requested"
    assert (root / "conf.d/new-scoped.conf").read_bytes() == expected


def test_interrupted_cleanup_resumes_missing_backup_only_after_durable_owned_intent(effect_admission, monkeypatch):
    admission, root = effect_admission
    admission.packet["action"] = "seal"
    admission.packet["fence"] = dict(kind="present", value=dict(reference=dict(reference=dict(sha256="5" * 64))))
    assert _complete(admission)[0]["status"] == "sealed"
    admission.packet["action"] = "cleanup"
    native_unlink = os.unlink
    interrupted = False
    def unlink_then_interrupt(path, *args, **kwargs):
        nonlocal interrupted
        native_unlink(path, *args, **kwargs)
        if str(path).startswith(".taira-nginx-backup-") and not interrupted:
            interrupted = True
            raise KeyboardInterrupt("owned child crash after cleanup unlink")
    monkeypatch.setattr(MODULE.os, "unlink", unlink_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        _complete(admission)
    assert not list((root / "conf.d").glob(".taira-nginx-backup-*"))
    result, records = _complete(admission)
    assert result["status"] == "cleaned", result
    assert [row["phase"] for row in records][-2:] == ["cleanup_requested", "cleaned"]


@pytest.mark.parametrize("fault", ["changed_plan", "hardlink", "partial_append"])
def test_completion_journal_refuses_changed_intent_and_unowned_storage(effect_admission, fault):
    admission, root = effect_admission
    journal = MODULE.CompletionJournal(admission)
    journal.append("admitted", publication_identity=None, backup_identity=None, publisher_journal=None)
    journal.close()
    if fault == "changed_plan":
        admission.packet["plan"]["reference"]["sha256"] = "6" * 64
    elif fault == "hardlink":
        os.link(admission.path / "native-completion.ndjson", root / "extra-journal-link")
    else:
        with (admission.path / "native-completion.ndjson").open("ab") as target:
            target.write(b'{"partial":')
    with pytest.raises(RuntimeError, match={"changed_plan":"completion_journal_binding",
        "hardlink":"completion_journal_changed", "partial_append":"completion_journal_bound"}[fault]):
        MODULE.CompletionJournal(admission)


def test_actual_isolated_cli_help_and_closed_malformed_request(native_apply):
    _, root, _ = native_apply
    help_result = subprocess.run([sys.executable, "-I", str(MODULE_PATH), "--help"],
                                 capture_output=True, timeout=10)
    assert help_result.returncode == 0, help_result.stderr.decode()
    assert b"--admission-fd" in help_result.stdout and b"--inspect-request-fd" in help_result.stdout
    malformed = root / "malformed-public.json"
    _write_public(malformed, b'{"private":"never-export","private":"duplicate"}')
    fd = os.open(malformed, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        result = subprocess.run([sys.executable, "-I", str(MODULE_PATH), "--admission-fd", str(fd)],
                                pass_fds=[fd], capture_output=True, timeout=10)
    finally:
        os.close(fd)
    assert result.returncode == 1 and result.stderr == b""
    assert json.loads(result.stdout) == {"error_code":"duplicate_json_member"}
    assert "never-export" not in result.stdout.decode()


@pytest.fixture
def native_admission(native_apply):
    """Project custody under an explicit authority stub, never fake Rust auth.

    Unstubbed calls must reject this arbitrary C parent/custody root. The stub
    admits only authority derivation so real parent executable/FD/lock/fence
    checks can be fault-tested independently of the Rust signature gate.
    """
    if sys.platform != "darwin":
        pytest.skip("the maintained completion corridor admits native Darwin only")
    request, root, _ = native_apply
    result = OWNER.remote_apply(request)
    assert result["exit_code"] == 0, result
    request["publication"] = dict(kind="reconcile", prior=_prior(root, request["operation_id"], request["candidate_sha256"]))
    custody = root / "custody"
    operation = custody / "taira-edge/operations" / ("a" * 64)
    for directory in (custody, custody / "taira-edge", custody / "taira-edge/operations", operation):
        directory.mkdir(mode=0o700)
    descriptors = []
    def retained(path, value=None, executable=False):
        if value is not None:
            _write_public(path, value)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(fd)
        return dict(fd=fd, reference=dict(file=dict(path=str(path), identity=MODULE.identity(os.fstat(fd))),
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    # A tiny ordinary native fixture remains the child's real parent while
    # Python runs Admission. No native dispatcher/signature gate is simulated
    # by changing getppid or the maintained native process observer.
    executable = root / "native-parent"
    parent_source = root / "native-parent.c"
    _write_public(parent_source, b'''#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
    if (argc < 2 || getchar() == EOF) return 80;
    pid_t child = fork();
    if (child < 0) return 81;
    if (child == 0) { execv(argv[1], argv + 1); _exit(82); }
    int status;
    if (waitpid(child, &status, 0) != child) return 83;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 84;
}
''')
    compiler = shutil.which("cc")
    assert compiler is not None, "native Darwin admission fixture requires the installed C compiler"
    subprocess.run([compiler, str(parent_source), "-o", str(executable)],
                   capture_output=True, check=True, timeout=30)
    executable.chmod(0o700)
    parent = dict(pid=0, uid=os.geteuid(), started="Sun Oct 4 01:02:03 2026",
                  executable=retained(executable, executable=True))
    guard = dict(schema="iroha.taira.public-reset.host-guard.v1", host_slug="native-edge",
        service_root=str(root / "service"), state_root=str(custody), trusted_key_sha256="b" * 64,
        dispatcher_path=str(executable), dispatcher_sha256=parent["executable"]["reference"]["sha256"],
        upload_parent=str(root / "upload"))
    guard_reference = retained(root / "guard.json", guard)
    bindings = dict(operation_id="c" * 32, authorization_sha256="a" * 64, authorization_nonce="d" * 32,
        host_pair_sha256="e" * 64, host_identity_sha256="f" * 64, custody_root=str(custody))
    inventory = dict(deployment_id="fixture", authorization_nonce=bindings["authorization_nonce"],
        revision=dict(commit="1" * 40), next_genesis_hash="hash:fixture", hosts=dict(provider="macstadium-dublin",
        native_edge=dict(owner_uid=os.geteuid(), owner_gid=os.getegid(), custody_root=str(custody),
            endpoint=dict(host_identity_sha256=bindings["host_identity_sha256"]),
            guard_sha256=guard_reference["reference"]["sha256"], dispatcher_path=str(executable),
            dispatcher_sha256=guard["dispatcher_sha256"]),
        validator_guest=dict(endpoint=dict(host_identity_sha256="2" * 64), custody_root="/private/guest")))
    inventory_reference = retained(operation / "inventory.json", inventory)
    bindings["inventory_sha256"] = inventory_reference["reference"]["sha256"]
    claims = dict(inventory_sha256=bindings["inventory_sha256"], authorization_nonce=bindings["authorization_nonce"],
        deployment_id=inventory["deployment_id"], execution_expires_at_unix_ms=9999999999999)
    authorization = retained(operation / "authorization.json", dict(claims=claims, signature_hex="0" * 128))
    progress = dict(bindings, schema=MODULE.PROGRESS_SCHEMA, sequence=1, predecessor_sha256=None,
        request_sha256="3" * 64, publication_operation_id=request["operation_id"], status="awaiting_readiness",
        checkpoint_sha256=None, completion_receipt_sha256=None)
    plan = dict(schema="iroha.taira.public-reset.native-nginx-completion-plan.v1",
        nginx=_plan(request, root), completion_journal_basename="native-completion.ndjson",
        publication_effect=dict(kind="owned", value=None))
    packet = dict(bindings, schema=MODULE.ADMISSION_SCHEMA, action="rollback",
        helper_source_closure_sha256=MODULE.source_closure()[0], parent=parent, guard=guard_reference,
        inventory=inventory_reference, authorization=authorization, progress=retained(operation / "progress.json", progress),
        plan=retained(operation / "completion-plan.json", plan), checkpoints=[])
    lock_fd = os.open(operation / "operation.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    descriptors.append(lock_fd)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    packet["lock"] = dict(fd=lock_fd, file=dict(path=str(operation / "operation.lock"), identity=MODULE.identity(os.fstat(lock_fd))))
    host_lock_path = custody / "taira-edge/host-operation.lock"
    host_lock_fd = os.open(host_lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    descriptors.append(host_lock_fd)
    fcntl.flock(host_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    packet["host_lock"] = dict(fd=host_lock_fd,
        file=dict(path=str(host_lock_path), identity=MODULE.identity(os.fstat(host_lock_fd))))
    directory_fd = os.open(operation, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors.append(directory_fd)
    packet["fence"] = dict(kind="absent", value=dict(directory_fd=directory_fd,
        directory=dict(path=str(operation), identity=MODULE.identity(os.fstat(directory_fd))), basename="global-proof.json"))
    child = '''import importlib.util, json, pathlib, sys
spec=importlib.util.spec_from_file_location("completion",sys.argv[1]); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
if sys.argv[3]=="stub_authority":
    def projection_authority(packet):
        guard=module.public_json(module.retained_public(packet["guard"]))
        reference=packet["guard"]["reference"]
        retained=module.open_anchored(reference["file"]["path"])
        return dict(custody_root=packet["custody_root"],dispatcher_path=packet["parent"]["executable"]["reference"]["file"]["path"],
            guard=guard,retained=dict(fd=retained,reference=reference))
    module.native_custodian_anchor=projection_authority
else:
    def reject_packet_file(*args,**kwargs):
        raise AssertionError("arbitrary caller-selected input opened before independent anchor refusal")
    module.open_anchored=reject_packet_file
try:
    admission=module.Admission(json.loads(pathlib.Path(sys.argv[2]).read_bytes()))
    try: admission.verify(); result={"accepted":True}
    finally: admission.close()
except Exception as error:
    code=error.args[0] if type(error) is RuntimeError and error.args else "native_admission_refused"
    result={"accepted":False,"error_code":code}
print(json.dumps(result))
'''
    def run(*, stub_authority=True):
        packet_path = root / "child-admission.json"
        # The native fixture stays the actual parent; it waits while pytest
        # records its live PID/start identity, then launches exactly one child.
        # The command is fixed text and receives only public fixture argv.
        process = subprocess.Popen([str(executable), sys.executable, "-I", "-c", child,
            str(MODULE_PATH), str(packet_path), "stub_authority" if stub_authority else "independent_authority"],
            pass_fds=descriptors, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            admitted = copy.deepcopy(packet)
            if admitted["parent"]["pid"] == 0:
                admitted["parent"]["pid"] = process.pid
            started = subprocess.run(["/bin/ps", "-p", str(process.pid), "-o", "lstart="],
                capture_output=True, check=True, timeout=10).stdout.decode()
            admitted["parent"]["started"] = " ".join(started.split())
            _write_public(packet_path, admitted)
            stdout, stderr = process.communicate(b"ready\n", timeout=30)
            assert process.returncode == 0, stderr.decode()
            return json.loads(stdout)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
    def rewrite(key, value):
        packet[key] = retained(operation / {"progress":"progress.json", "plan":"completion-plan.json"}[key], value)
    def absent_refresh():
        packet["fence"]["value"]["directory"]["identity"] = MODULE.identity(os.fstat(directory_fd))
    def checkpoint(count=2):
        references = []
        for index in range(count):
            claim = dict(schema="iroha.taira.public-reset.host-phase-checkpoint.v1",
                phase=dict(kind=("candidate_frontier", "native_edge_ready", "deployment_proven")[index], value=None),
                deployment_id=inventory["deployment_id"], inventory_sha256=bindings["inventory_sha256"],
                authorization_sha256=bindings["authorization_sha256"], authorization_nonce=bindings["authorization_nonce"],
                host_pair_sha256=bindings["host_pair_sha256"], guest_host_identity_sha256="2" * 64,
                native_edge_host_identity_sha256=bindings["host_identity_sha256"], guest_custody_root="/private/guest",
                native_edge_custody_root=str(custody), source_commit=inventory["revision"]["commit"],
                next_genesis_hash=inventory["next_genesis_hash"], evidence_sha256="4" * 64,
                predecessor_sha256=references[-1]["reference"]["sha256"] if references else None,
                execution_expires_at_unix_ms=claims["execution_expires_at_unix_ms"])
            references.append(retained(operation / f"checkpoint-{index+1}.json", dict(claims=claim, signature_hex="0" * 128)))
        packet["checkpoints"] = references
        absent_refresh()
    def proof(action="seal"):
        checkpoint(3)
        ready = dict(progress, status="edge_ready_unqualified", checkpoint_sha256=packet["checkpoints"][1]["reference"]["sha256"])
        rewrite("progress", ready)
        retained(operation / "global-proof-predecessor.json", ready)
        fence = dict(bindings, schema=MODULE.FENCE_SCHEMA,
            checkpoint_sha256=[item["reference"]["sha256"] for item in packet["checkpoints"]],
            final_checkpoint_sha256=packet["checkpoints"][-1]["reference"]["sha256"],
            progress_predecessor_sha256=packet["progress"]["reference"]["sha256"],
            publication_operation_id=request["operation_id"])
        packet["fence"] = dict(kind="present", value=dict(reference=retained(operation / "global-proof.json", fence)))
        packet["action"] = action
        if action == "cleanup":
            rewrite("progress", dict(ready, status="sealed"))
    try:
        yield dict(packet=packet, run=run, rewrite=rewrite, root=root, operation=operation,
                   progress=progress, retained=retained, absent_refresh=absent_refresh, checkpoint=checkpoint, proof=proof)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def test_actual_parent_inherited_fd_lock_and_absent_fence_projection_with_authority_stub(native_admission):
    fixture = native_admission
    assert fixture["run"]() == {"accepted": True}
    fixture["checkpoint"](2)
    assert fixture["run"]() == {"accepted": True}


@pytest.mark.parametrize("action", ["seal", "cleanup"])
def test_custody_projection_accepts_exact_fence_and_native_unit_enum_wire(native_admission, action):
    native_admission["proof"](action)
    assert native_admission["run"]() == {"accepted": True}


def test_unmodified_anchor_refuses_self_rooted_c_parent_before_any_selected_file_read(native_admission):
    result = native_admission["run"](stub_authority=False)
    assert result == {"accepted":False, "error_code":"independent_native_anchor_required"}
    assert not (native_admission["operation"] / "native-completion.ndjson").exists()


@pytest.mark.parametrize("fault", ["unheld_lock", "wrong_parent", "changed_closure", "unknown_fence_field",
    "omitted_fence_value", "proof_exists", "third_checkpoint", "unit_enum_without_null", "foreign_lock", "unheld_host_lock", "foreign_host_lock",
    "changed_host_lock", "host_lock_wrong_path"])
def test_actual_admission_refuses_owner_and_proof_faults_before_effects(native_admission, fault):
    fixture, packet = native_admission, native_admission["packet"]
    if fault == "unheld_lock":
        fcntl.flock(packet["lock"]["fd"], fcntl.LOCK_UN)
    elif fault == "unheld_host_lock":
        fcntl.flock(packet["host_lock"]["fd"], fcntl.LOCK_UN)
    elif fault == "foreign_host_lock":
        replacement = fixture["root"] / "foreign-host-lock"
        _write_public(replacement, b"")
        os.replace(replacement, Path(packet["host_lock"]["file"]["path"]))
    elif fault == "changed_host_lock":
        os.fchmod(packet["host_lock"]["fd"], 0o640)
    elif fault == "host_lock_wrong_path":
        packet["host_lock"]["file"]["path"] = str(fixture["root"] / "wrong-host-operation.lock")
    elif fault == "wrong_parent":
        packet["parent"]["pid"] += 1
    elif fault == "changed_closure":
        packet["helper_source_closure_sha256"] = "0" * 64
    elif fault == "unknown_fence_field":
        packet["fence"]["private"] = "never export"
    elif fault == "omitted_fence_value":
        del packet["fence"]["value"]
    elif fault == "proof_exists":
        _write_public(fixture["operation"] / "global-proof.json", b"public proof fence\n")
        fixture["absent_refresh"]()
    elif fault == "third_checkpoint":
        fixture["checkpoint"](3)
    elif fault == "unit_enum_without_null":
        fixture["checkpoint"](1)
        path = fixture["operation"] / "checkpoint-1.json"
        value = json.loads(path.read_bytes())
        del value["claims"]["phase"]["value"]
        packet["checkpoints"][0] = fixture["retained"](path, value)
        fixture["absent_refresh"]()
    elif fault == "foreign_lock":
        replacement = fixture["root"] / "foreign-lock"
        _write_public(replacement, b"")
        os.replace(replacement, Path(packet["lock"]["file"]["path"]))
        fixture["absent_refresh"]()
    result = fixture["run"]()
    expected = dict(unheld_lock="native_lock_not_held", wrong_parent="native_parent_changed",
        changed_closure="helper_closure_changed", unknown_fence_field="proof_fence_fields",
        omitted_fence_value="proof_fence_fields", proof_exists="rollback_after_global_proof",
        third_checkpoint="rollback_after_global_proof", unit_enum_without_null="checkpoint_binding",
        foreign_lock="retained_identity_changed", unheld_host_lock="native_lock_not_held",
        foreign_host_lock="retained_identity_changed", changed_host_lock="retained_identity_changed",
        host_lock_wrong_path="native_lock_path")
    assert result == {"accepted":False, "error_code":expected[fault]}, (fault, result)
    assert "never export" not in json.dumps(result)
    assert not (fixture["operation"] / "native-completion.ndjson").exists()


def test_present_fence_cannot_be_relabelled_for_rollback(native_admission):
    fixture = native_admission
    fixture["proof"]()
    fixture["packet"]["action"] = "rollback"
    fixture["rewrite"]("progress", dict(fixture["progress"], status="awaiting_readiness"))
    result = fixture["run"]()
    assert result == {"accepted": False, "error_code": "rollback_after_global_proof"}


@pytest.mark.parametrize("status", ["cleaned", "sealed", "arbitrary", 7])
def test_progress_phase_must_admit_the_requested_terminal_action(native_admission, status):
    fixture = native_admission
    fixture["rewrite"]("progress", dict(fixture["progress"], status=status))
    fixture["absent_refresh"]()
    result = fixture["run"]()
    assert result == {"accepted": False, "error_code": "completion_progress_phase"}


@pytest.mark.parametrize("fault", ["wrong_fd", "changed_digest", "unsafe_mode", "path_substitution"])
def test_actual_public_input_descriptor_path_and_body_binding(native_admission, fault):
    fixture, packet = native_admission, native_admission["packet"]
    path = fixture["operation"] / "progress.json"
    if fault == "wrong_fd":
        packet["progress"]["fd"] = packet["plan"]["fd"]
    elif fault == "changed_digest":
        packet["progress"]["reference"]["sha256"] = "0" * 64
    elif fault == "unsafe_mode":
        path.chmod(0o644)
        packet["progress"]["reference"]["file"]["identity"] = MODULE.identity(path.stat())
    else:
        foreign = fixture["root"] / "foreign-progress"
        _write_public(foreign, path.read_bytes())
        os.replace(foreign, path)
        fixture["absent_refresh"]()
    result = fixture["run"]()
    assert result["accepted"] is False
    assert result["error_code"] == {"wrong_fd":"retained_identity_changed",
        "changed_digest":"retained_public_digest_changed", "unsafe_mode":"unsafe_retained_owner",
        "path_substitution":"retained_identity_changed"}[fault]


@pytest.mark.parametrize("effect", [{"kind":"owned"}, {"kind":"owned","value":{}},
    {"kind":"legacy","value":None}, {"kind":"owned","value":None,"unknown":True}])
def test_publication_effect_is_exact_first_release_unit_wire(native_admission, effect):
    fixture = native_admission
    plan = json.loads((fixture["operation"] / "completion-plan.json").read_bytes())
    plan["publication_effect"] = effect
    fixture["rewrite"]("plan", plan)
    fixture["absent_refresh"]()
    result = fixture["run"]()
    assert result["accepted"] is False
    expected = ("publication_effect_kind" if effect.get("kind") == "legacy"
                else "publication_effect_fields" if set(effect) != {"kind", "value"}
                else "owned_publication_effect")
    assert result["error_code"] == expected


@pytest.mark.parametrize('fault', ['same_operation', 'journal_before_intent', 'journal_after_intent'])
def test_stage_only_rollback_refuses_requested_successor_and_preserves_incumbent(effect_admission, monkeypatch, fault):
    admission, root = effect_admission
    intended = admission.plan['nginx']['operation_id'] if fault == 'same_operation' else 'd'*32
    incumbent = MODULE.numeric_owned_publication(admission.plan['nginx'])
    admission.plan['publication_effect'] = dict(kind='not_requested',
        value=dict(intended_operation_id=intended, incumbent=incumbent))
    intended_journal = root/('.taira-native-nginx-apply-'+intended+'.receipt.ndjson')
    publication = root/'conf.d/new-scoped.conf'
    before = publication.read_bytes(), _identity(publication)
    append = MODULE.CompletionJournal.append
    if fault == 'journal_before_intent':
        _write_public(intended_journal, b'owned successor intent\n')
    elif fault == 'journal_after_intent':
        def requested(self, phase, **details):
            result = append(self, phase, **details)
            if phase == 'rollback_requested':
                _write_public(intended_journal, b'owned successor intent\n')
            return result
        monkeypatch.setattr(MODULE.CompletionJournal, 'append', requested)
    monkeypatch.setattr(OWNER, 'signal_master', lambda *args: pytest.fail('stage-only refusal signaled master'))
    monkeypatch.setattr(OWNER, 'native_exchange', _configuration_exchange(admission,
        lambda *args: pytest.fail('stage-only refusal exchanged incumbent')))
    result, records = _complete(admission)
    assert result['status'] == 'recovery_pending', result
    assert result['error_code'] == ('intended_operation_is_incumbent' if fault == 'same_operation'
                                  else 'publication_effect_already_requested')
    assert result['restored_owned_publication'] is None
    assert (publication.read_bytes(), _identity(publication)) == before
    assert not any(row['phase'] == 'rolled_back' for row in records)


@pytest.mark.parametrize('fault,expected', [
    ('missing_journal','publisher_rollback_fields'),
    ('missing_restored','publisher_rollback_fields'),
    ('string_identity','native_identity_numbers'),
    ('create_with_predecessor','publisher_rollback_predecessor'),
    ('replace_without_predecessor','publisher_rollback_predecessor'),
    ('wrong_operation','publisher_rollback_operation'),
    ('private_journal_path','prior_journal_reference'),
    ('seal_action','publisher_rollback_effect'),
    ('wrong_progress','publisher_rollback_effect'),
])
def test_publisher_rolled_back_constructor_refuses_untyped_or_unjoined_wire(native_admission, fault, expected):
    fixture = native_admission
    plan = json.loads((fixture['operation']/'completion-plan.json').read_bytes())
    prior = plan['nginx']['publication']['prior']
    journal = dict(file=dict(path=prior['journal']['path'],
        identity={key:int(value) for key,value in prior['journal']['identity'].items()}),
        sha256=prior['journal']['sha256'])
    plan['nginx']['publication'] = dict(kind='create')
    plan['publication_effect'] = dict(kind='publisher_rolled_back',
        value=dict(journal=journal, restored_owned_publication=None))
    progress = json.loads((fixture['operation']/'progress.json').read_bytes())
    progress['status'] = 'rollback_requested'
    if fault == 'missing_journal':
        del plan['publication_effect']['value']['journal']
    elif fault == 'missing_restored':
        del plan['publication_effect']['value']['restored_owned_publication']
    elif fault == 'string_identity':
        journal['file']['identity']['mtime_ns'] = str(journal['file']['identity']['mtime_ns'])
    elif fault == 'create_with_predecessor':
        plan['publication_effect']['value']['restored_owned_publication'] = MODULE.numeric_owned_publication(
            dict(plan['nginx'], publication=dict(kind='reconcile', prior=prior)))
    elif fault == 'replace_without_predecessor':
        prior = copy.deepcopy(prior)
        prior['operation_id'] = 'b'*32
        prior['journal']['path'] = str(Path(prior['journal']['path']).parent/('.taira-native-nginx-apply-'+('b'*32)+'.receipt.ndjson'))
        plan['nginx']['publication'] = dict(kind='replace', prior=prior)
    elif fault == 'wrong_operation':
        journal['file']['path'] = str(Path(prior['journal']['path']).parent/('.taira-native-nginx-apply-'+('b'*32)+'.receipt.ndjson'))
    elif fault == 'private_journal_path':
        journal['file']['path'] = plan['nginx']['native']['main']['path']
    elif fault == 'seal_action':
        fixture['packet']['action'] = 'seal'
        progress['status'] = 'sealing'
    else:
        progress['status'] = 'awaiting_readiness'
    fixture['rewrite']('progress', progress)
    fixture['rewrite']('plan', plan)
    fixture['absent_refresh']()
    result = fixture['run']()
    assert result == {'accepted':False, 'error_code':expected}, (fault, result)
    assert not (fixture['operation']/'native-completion.ndjson').exists()
