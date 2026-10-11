#!/usr/bin/env python3
"""Native retry identity, custody and failure-handling tests without SSH or live secrets."""

import copy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "taira_retry.py"
SPEC = importlib.util.spec_from_file_location("taira_retry", SCRIPT)
retry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retry)
CAPACITY = SCRIPT.with_name("taira_disk_capacity.py")
SPEC_CAPACITY = importlib.util.spec_from_file_location("retry_capacity_test", CAPACITY)
capacity = importlib.util.module_from_spec(SPEC_CAPACITY)
SPEC_CAPACITY.loader.exec_module(capacity)
UNIT_RENDERER_PATH = SCRIPT.with_name("taira_validator_unit.py")
UNIT_RENDERER = {"__name__": "reviewed_unit_fixture", "__file__": str(UNIT_RENDERER_PATH)}
exec(compile(UNIT_RENDERER_PATH.read_bytes(), str(UNIT_RENDERER_PATH), "exec"), UNIT_RENDERER)
OPERATOR_PUBLIC_KEY = "ed0120D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"


class ContinuityTopologyTests(unittest.TestCase):
    def test_exact_four_native_topology_peers(self):
        peers = [f"peer-{index}" for index in range(4)]
        manifest = {"transactions": [
            {"topology": [{"peer": peer} for peer in peers[:2]]},
            {"instructions": []},
            {"topology": [{"peer": peer} for peer in peers[2:]]},
        ]}
        self.assertEqual(retry._continuity_topology_peers(manifest), peers)
        for altered in (
            {}, {"transactions": None}, {"transactions": [None]},
            {"transactions": [{"topology": None}]},
            {"transactions": [{"topology": [{"peer": peer} for peer in peers[:3]]}]},
            {"transactions": [{"topology": [{"peer": "peer-0"}] * 4}]},
            {"transactions": [{"topology": [{"validator": peer} for peer in peers]}]},
            {"transactions": [{"topology": [{"peer": ""}] * 4}]},
        ):
            with self.subTest(altered=altered), self.assertRaises(RuntimeError):
                retry._continuity_topology_peers(altered)


class ContinuitySignerCustodyTests(unittest.TestCase):
    def test_initial_unit_has_exact_runtime_signer_and_no_beacon_credential(self):
        role = "taira-validator-1"
        raw = UNIT_RENDERER["render"](role, "/private/runtime.key").encode()
        fields = retry._continuity_unit_sources(raw, role, UNIT_RENDERER)
        self.assertEqual(fields["runtime_key"], "/private/runtime.key")
        self.assertIsNone(fields["global_beacon_credential"])
        self.assertEqual(fields["cmd"][2], f"/srv/taira/{role}/current/config/config.toml")
        for altered in (
            UNIT_RENDERER["render"](role, "/private/runtime.key", "/private/beacon.norito").encode(),
            UNIT_RENDERER["render"](role, "/private/runtime.key", config_file="beacon.toml").encode(),
            raw.replace(b"Type=exec", b"Type=simple"),
        ):
            with self.subTest(altered=altered), self.assertRaises(RuntimeError):
                retry._continuity_unit_sources(altered, role, UNIT_RENDERER)

    def test_retained_runtime_signer_metadata_never_reads_key_bytes(self):
        info = SimpleNamespace(st_dev=1, st_ino=2, st_size=71, st_mtime_ns=3,
                               st_ctime_ns=4, st_uid=0, st_mode=stat.S_IFREG | 0o600,
                               st_nlink=1)
        with mock.patch.object(retry, "_continuity_open_direct", return_value=123) as opened, \
             mock.patch.object(retry.os, "fstat", return_value=info), \
             mock.patch.object(retry.os, "close") as closed, \
             mock.patch.object(retry.os, "read", side_effect=AssertionError("private key read")):
            result = retry._continuity_signer_metadata("/private/runtime.key")
            self.assertEqual(result, retry._continuity_stamp(info))
            opened.assert_called_once_with("/private/runtime.key", metadata_only=True)
            closed.assert_called_once_with(123)
            for field, value in (("st_size", 32), ("st_mode", stat.S_IFREG | 0o644),
                                 ("st_uid", 1000), ("st_nlink", 2)):
                original = getattr(info, field)
                setattr(info, field, value)
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    retry._continuity_signer_metadata("/private/runtime.key")
                setattr(info, field, original)


def beacon_input_fixture(draft):
    return {
        "schema": "iroha.taira.public-reset.beacon-inputs.v1",
        "authorization_nonce": draft["authorization_nonce"],
        "request": {"native_public_request": "opaque to Python"},
        "final_units": [{
            "validator": row["slug"], "signer_index": seat,
            "credential_path": f"/var/lib/taira/.public-reset-control-v1/beacon/{draft['authorization_nonce']}/ceremony/seat-{seat}/iroha-global-beacon-partial-signer-v1.norito",
            "config_file": "beacon.toml",
        } for row, seat in zip(draft["validators"], [3, 1, 4, 2])],
    }




def complete_previous_fixture(value=None):
    """Public synthetic retained inventory with real-shaped intent and stale computed fields."""
    value=copy.deepcopy(value or {})
    value.setdefault("schema","iroha.taira.public-reset.inventory.v1")
    value.setdefault("qualification_scope","core_testnet")
    value.setdefault("deployment_id","retained")
    value.setdefault("authorization_nonce","0"*32)
    value.setdefault("previous_genesis_hash","8"*64)
    value.setdefault("next_genesis_hash","c"*64)
    value.setdefault("chain_id","fc56984b-2be7-431d-840e-21514d1883f0")
    value.setdefault("chain_discriminant",369)
    value.setdefault("operator_public_key",OPERATOR_PUBLIC_KEY)
    value.setdefault("inrou_canary",None)
    value.setdefault("inrou_stage_tree_sha256",None)
    revision=value.setdefault("revision",{})
    revision.setdefault("commit","a"*40)
    revision.setdefault("source_root","/source")
    revision.setdefault("source_manifest_path","/source/source-manifest.json")
    revision.update(tree="c"*40,cargo_lock_sha256="d"*64,source_manifest_sha256="e"*64,source_closure_sha256="f"*64)
    value.setdefault("validators",[{"slug":f"taira-validator-{i}"} for i in range(1,5)])
    for i,row in enumerate(value["validators"],1):
        role=f"taira-validator-{i}"
        row.setdefault("slug",role)
        row.setdefault("endpoint",{"hostname":role+".example","host_identity_sha256":"a"*64,"known_host_line_sha256":"b"*64})
        row.setdefault("platform",{"os":"linux","architecture":"aarch64"})
        row.setdefault("service_root","/srv/taira/"+role)
        row.setdefault("state_root","/var/lib/taira/"+role)
        row.setdefault("reset_guard","/var/lib/taira/"+role+"/.reset-guard")
        row.setdefault("systemd_unit","iroha3d-"+role+".service")
        row.setdefault("systemd_unit_sha256","d"*64)
        row.setdefault("initial_state",{"kind":"vacant"})
        row.update(node_fingerprint="node-stale",build_fingerprint="build-stale",config_fingerprint="config-stale")
        row.setdefault("artifacts",[{"role":"iroha_cli","local_path":"/runtime/artifacts/bin/iroha","sha256":"b"*64}])
        for a in row["artifacts"]:
            a.setdefault("remote_path",row["service_root"]+"/releases/"+revision["commit"]+"/bin/iroha")
            a.update(size=10,mode=493,source_commit=revision["commit"],target="aarch64-unknown-linux-gnu")
    value.setdefault("validator_clients",[{"slug":f"taira-validator-{i}","probe_origin":f"http://127.0.0.1:{18080+i}/"} for i in range(1,5)])
    edge=value.setdefault("edge",{})
    edge.setdefault("slug","taira-edge");edge.setdefault("endpoint",{"hostname":"edge.example"});edge.setdefault("platform",{"os":"linux","architecture":"aarch64"})
    edge.setdefault("service_root","/srv/taira/edge");edge.setdefault("state_root","/var/lib/taira/edge");edge.setdefault("reset_guard","/var/lib/taira/edge/.guard");edge.setdefault("nginx_config","/etc/nginx/taira.conf");edge.setdefault("initial_state",{"kind":"vacant"});edge.setdefault("artifacts",copy.deepcopy(value["validators"][0]["artifacts"]))
    for a in edge["artifacts"]:a.setdefault("remote_path","/srv/taira/edge/releases/"+revision["commit"]+"/bin/iroha")
    for key in ("faucet_policy","fee_intent","canary_onboarding_request","cleanup","timeouts"):value.setdefault(key,{"synthetic_selected_intent":True})
    value.setdefault("beacon_bootstrap",{"old_signed_session":"must not enter topology"})
    for key in ("runtime_client_config_sha256","onboarding_token_sha256","validator_client_configs_sha256","artifact_closure_sha256"):value.setdefault(key,"9"*64)
    return value


def expected_topology(previous,attempt,nonce):
    # Independent field-list oracle: a predecessor computed pin must never leak through.
    top=("qualification_scope","previous_genesis_hash","validator_clients","faucet_policy","fee_intent","canary_onboarding_request","cleanup","timeouts")
    out={k:copy.deepcopy(previous[k]) for k in top}
    out.update(schema="iroha.taira.public-reset.topology-intent.v1",deployment_id="taira-"+attempt,authorization_nonce=nonce,revision={k:previous["revision"][k] for k in ("source_root","source_manifest_path")})
    fields=("slug","endpoint","platform","service_root","state_root","reset_guard","initial_state")
    def node(v,extra):
        r={k:copy.deepcopy(v[k]) for k in (*fields,extra)}
        r["artifacts"]=[{k:a[k] for k in ("role","local_path","remote_path")} for a in v["artifacts"]]
        return r
    out["validators"]=[node(v,"systemd_unit") for v in previous["validators"]]
    out["edge"]=node(previous["edge"],"nginx_config")
    return out


def artifact_receipts():
    artifacts = [
        {"name": name, "size": 10, "sha256": "b" * 64}
        for name in ("iroha", "iroha3d_taira", "sorafs-node", "kagami")
    ]
    build = {
        "commit": "a" * 40,
        "environment_sha256": "e" * 64,
        "tree": "c" * 40,
        "source_unchanged": True,
        "toolchain_unchanged": True,
        "target": "aarch64-unknown-linux-gnu",
        "profile": "release",
        "jobs": 6,
        "deployed": False,
        "release_qualified": False,
        "artifacts": copy.deepcopy(artifacts),
    }
    binary = {
        "commit": build["commit"],
        "destination": "/runtime/artifacts/bin",
        "all_hashes_verified": True,
        "activated": False,
        "artifacts": artifacts,
    }
    source = {
        "commit": build["commit"],
        "tree": build["tree"],
        "clean": True,
        "signature_verified": True,
        "object_inventory_verified": True,
        "activated": False,
        "runtime_files_transferred": False,
        "history_included": False,
        "source_root": "/source",
    }
    return build, binary, source


def full_plan():
    footprint = {"bytes": 10, "inodes": 1}
    return capacity.cohost_peak_plan(
        coordinator_path="/runtime",
        upload_path="/srv/taira",
        service_path="/srv/taira",
        store_paths=[f"/var/lib/taira/validator-{i}/store" for i in range(4)],
        runtime_paths=[f"/var/lib/taira/validator-{i}/runtime" for i in range(4)],
        artifacts=footprint,
        stage=footprint,
        per_store=footprint,
        per_replica_runtime=footprint,
        headroom=[
            {
                "path": "/runtime",
                "label": "filesystem headroom",
                "bytes": 2 * 1024**3,
                "inodes": 1024,
            }
        ],
    )


def core_plan():
    return {"schema": capacity.PLAN_SCHEMA, "allocations": [
        {"path": "/runtime", "label": label, "bytes": 10, "inodes": 1}
        for label in ("coordinator artifact snapshot", "per-role artifact uploads", "per-role installed artifacts")
    ] + [{"path": "/runtime", "label": "guest filesystem headroom", "bytes": 2 * 1024**3, "inodes": 16384}]}


def measured_inputs():
    stage = "/private/runtime/retained/inrou-stage"
    names = {
        "receipt.json": 2896,
        "container.json": 1398,
        "service.json": 2891,
        "manifests/aarch64.to": 502,
        "manifests/discovery.to": 502,
        "manifests/bundle.to": 502,
        "payloads/bundle.bin": 4082,
        "payloads/guest/aarch64/initrd.img": 13923072,
        "payloads/guest/aarch64/vmlinux": 27236288,
        "payloads/guest/aarch64/rootfs.ext4": 1610612736,
        "payloads/discovery/index.json": 729,
    }
    roles = [
        {"slug": f"taira-validator-{index}", "role": role, "bytes": 128}
        for index in range(1, 5)
        for role in (
            "iroha3d",
            "iroha_cli",
            "kagami",
            "sorafs_node",
            "config",
            "genesis",
            "genesis_hash",
            "validator_unit",
        )
    ]
    roles += [
        {"slug": "taira-edge", "role": role, "bytes": 128}
        for role in ("iroha_cli", "edge_config")
    ]
    inputs = {
        "schema": "taira.public-capacity-inputs.v1",
        "qualification_scope": "full_inrou",
        "secret_contents_read": False,
        "filesystem": {"fragment_bytes": 4096},
        "artifacts": roles,
        "stage_files": [
            {"path": stage + "/" + name, "bytes": size} for name, size in names.items()
        ],
        "inventory_inrou_stage_bytes": sum(names.values()),
        "native_sf1_manifest_bindings": {
            name: "f" * 64 for name in ("bundle", "guest", "discovery")
        },
    }
    runtime = {
        "schema": "taira.public-runtime-capacity-inputs.v1",
        "secret_contents_read": False,
        "source_stage": stage,
        "service_artifacts": [],
        "bundle_compressed_bytes": 4082,
        "bundle_archive_decoded_bytes": 16384,
        "bundle_members": [{"path": "app/server.py", "kind": "file", "bytes": 14608}],
        "lease_volumes": [
            {"volume_name": "root_disk", "max_total_bytes": 1610612736},
            {"volume_name": "app_data", "max_total_bytes": 67108864},
        ],
        "container_resources": {"ephemeral_storage_bytes": 16777216},
    }
    return inputs, runtime


def derived_capacity(inputs=None, runtime=None, build=None):
    original_inputs, original_runtime = measured_inputs()
    return capacity.derive_capacity(
        inputs or original_inputs,
        runtime or original_runtime,
        build or artifact_receipts()[0],
        expected_commit="a" * 40,
        coordinator_path="/private/runtime/journal-v1",
        upload_path="/srv/taira",
        service_path="/srv/taira",
        store_paths=[
            f"/var/lib/taira/taira-validator-{i}/sorafs-data" for i in range(1, 5)
        ],
        runtime_paths=[
            f"/var/lib/taira/taira-validator-{i}/inrou-data" for i in range(1, 5)
        ],
        guest_headroom_path="/private/runtime",
        backing_path="/approved/vm",
    )



class RetryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def record(self, name, value):
        path = self.root / name
        retry.write_public(path, value)
        return path

    def ssh_route(self, host, known_hosts, *, proxy=None, forwarding=None):
        argv = ["/usr/bin/ssh", "-T", "-F", "/dev/null", "-i", "/private/ssh-identity"]
        for value in (
            "BatchMode=yes",
            "NumberOfPasswordPrompts=0",
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "StrictHostKeyChecking=yes",
            "ForwardAgent=no",
            "ClearAllForwardings=yes",
            "GlobalKnownHostsFile=/dev/null",
            "UpdateHostKeys=no",
            "VerifyHostKeyDNS=no",
            "UserKnownHostsFile=" + str(known_hosts),
        ):
            argv += ["-o", value]
        if proxy is not None:
            argv += ["-o", "ProxyCommand=" + retry.shlex.join(proxy)]
        if forwarding is not None:
            argv += ["-W", forwarding, host]
        else:
            argv += [host, "/usr/bin/python3 -I -"]
        return argv

    def test_ssh_pins_exact_host_key_files_for_both_fixed_hops(self):
        guest_keys = self.record("guest_known_hosts", {"public": "guest"})
        mac_keys = self.record("mac_known_hosts", {"public": "backing"})
        proxy = self.ssh_route(
            "administrator@208.83.1.62", mac_keys, forwarding="192.168.64.3:22"
        )
        argv = self.ssh_route("root@192.168.64.3", guest_keys, proxy=proxy)
        pins = [
            {
                "path": str(path),
                "sha256": retry.hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in (guest_keys, mac_keys)
        ]
        self.assertEqual(retry.validate_ssh({"argv": argv, "pins": pins}), argv)
        # The established jump route predates IdentityAgent=none; IdentitiesOnly
        # and its explicit identity still constrain it to that admitted key.
        proxy.remove("IdentityAgent=none")
        proxy.pop(proxy.index("IdentitiesOnly=yes") + 1)
        argv = self.ssh_route("root@192.168.64.3", guest_keys, proxy=proxy)
        self.assertEqual(retry.validate_ssh({"argv": argv, "pins": pins}), argv)

    def test_ssh_compression_preserves_direct_and_nested_host_key_pins(self):
        guest_keys, mac_keys = "/public/guest_hosts", "/public/mac_hosts"
        for host, keys in (("root@192.168.64.3", guest_keys),
                           ("administrator@208.83.1.62", mac_keys)):
            argv = self.ssh_route(host, keys)
            argv[-2:-2] = ["-o", "Compression=yes"]
            with self.subTest(host=host):
                self.assertEqual(retry.ssh_host_key_paths(argv), {keys})
        proxy = self.ssh_route("administrator@208.83.1.62", mac_keys,
                               forwarding="192.168.64.3:22")
        argv = self.ssh_route("root@192.168.64.3", guest_keys, proxy=proxy)
        # The outer guest connection compresses plaintext. Its fixed Mac hop
        # transports ciphertext and does not need a second compression layer.
        argv[-2:-2] = ["-o", "Compression=yes"]
        self.assertEqual(retry.ssh_host_key_paths(argv), {guest_keys, mac_keys})
        self.assertNotIn("Compression=yes", proxy)
        proxy[-1:-1] = ["-o", "Compression=yes"]
        argv = self.ssh_route("root@192.168.64.3", guest_keys, proxy=proxy)
        self.assertEqual(retry.ssh_host_key_paths(argv), {guest_keys, mac_keys})

    def test_ssh_compression_accepts_only_explicit_yes_and_preserves_route_guards(self):
        good = self.ssh_route("root@192.168.64.3", "/public/guest_hosts")
        good[-2:-2] = ["-o", "Compression=yes"]
        for option in ("Compression=no", "Compression=adaptive", "Compression=1",
                       "StrictHostKeyChecking=no", "ProxyCommand=ssh arbitrary"):
            changed = good[:-2] + ["-o", option] + good[-2:]
            with self.subTest(option=option), self.assertRaises(retry.RetryError):
                retry.ssh_host_key_paths(changed)
        for value in ("no", "adaptive", "1", "YES"):
            changed = ["Compression=" + value if item == "Compression=yes" else item
                       for item in good]
            with self.subTest(value=value), self.assertRaises(retry.RetryError):
                retry.ssh_host_key_paths(changed)
        for extra in (["-C"], ["-o", "Compression=yes"]):
            with self.subTest(extra=extra), self.assertRaises(retry.RetryError):
                retry.ssh_host_key_paths(good[:-2] + extra + good[-2:])
        banned = good[:-2] + ["root@denylist.vultr.example", good[-1]]
        with self.assertRaises(retry.RetryError):
            retry.ssh_host_key_paths(banned)

    def test_ssh_rejects_unrelated_or_missing_pins_before_reading_any_bytes(self):
        argv = self.ssh_route("root@192.168.64.3", "/public/known_hosts")
        valid = {"path": "/public/known_hosts", "sha256": "a" * 64}
        secret = {"path": "/private/ssh-identity", "sha256": "b" * 64}
        for pins in ([secret], [valid, secret], [], [valid, valid]):
            with (
                self.subTest(pins=[pin["path"] for pin in pins]),
                mock.patch.object(retry, "public_record") as read,
            ):
                with self.assertRaises(retry.RetryError):
                    retry.validate_ssh({"argv": argv, "pins": pins})
                read.assert_not_called()

    def test_ssh_rejects_shell_proxy_wrong_forwarding_and_option_override(self):
        proxy = self.ssh_route(
            "administrator@208.83.1.62",
            "/public/mac_hosts",
            forwarding="192.168.64.3:22",
        )
        good = self.ssh_route("root@192.168.64.3", "/public/guest_hosts", proxy=proxy)
        wrong_target = copy.deepcopy(good)
        wrong_target[
            wrong_target.index(
                next(arg for arg in wrong_target if arg.startswith("ProxyCommand="))
            )
        ] = "ProxyCommand=" + retry.shlex.join(proxy).replace(
            "192.168.64.3:22", "192.168.64.4:22"
        )
        shell = copy.deepcopy(good)
        shell[
            shell.index(next(arg for arg in shell if arg.startswith("ProxyCommand=")))
        ] += "; touch /bad"
        override = good[:-2] + ["-o", "stricthostkeychecking=no"] + good[-2:]
        local_command = good[:-2] + ["-o", "LocalCommand=touch /bad"] + good[-2:]
        for argv in (wrong_target, shell, override, local_command):
            with self.assertRaises(retry.RetryError):
                retry.ssh_host_key_paths(argv)

    def test_duplicate_json_and_record_replacement_reject(self):
        with self.assertRaises(retry.RetryError):
            retry.decode(b'{"field":1,"field":2}')
        path = self.record("record.json", {"public": True})
        with self.assertRaises(FileExistsError):
            retry.write_public(path, {"public": False})
        self.assertEqual(retry.decode(retry.public_record(path)), {"public": True})

    def test_public_record_digest_mode_symlink_and_fifo_reject(self):
        path = self.record("record.json", {"public": True})
        with self.assertRaises(retry.RetryError):
            retry.public_record(path, "0" * 64)
        path.chmod(0o644)
        with self.assertRaises(retry.RetryError):
            retry.public_record(path, private=True)
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(retry.RetryError):
            retry.public_record(link)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(retry.RetryError):
            retry.public_record(fifo)

    def test_fresh_inventory_projects_intent_without_computed_pins_or_old_plans(self):
        previous=complete_previous_fixture()
        before=copy.deepcopy(previous)
        attempt="retry-1788850000000000000-1234abcd"
        actual=retry.fresh_inventory(previous,attempt,"1"*32)
        self.assertEqual(actual,expected_topology(previous,attempt,"1"*32))
        self.assertEqual(previous,before)
        actual["validators"][0]["artifacts"][0]["local_path"]="changed"
        self.assertEqual(previous,before)
        with self.assertRaises(retry.RetryError):retry.fresh_inventory(previous,attempt,"0"*32)


    def test_candidate_probe_inventory_rejects_obsolete_or_ambiguous_drafts(self):
        valid = {"qualification_scope": "core_testnet",
                 "inrou_canary": None, "inrou_stage_tree_sha256": None,
                 "operator_public_key": OPERATOR_PUBLIC_KEY, "validator_clients": [
            {"slug": f"taira-validator-{index}",
             "probe_origin": f"http://127.0.0.1:{18080 + index}/"}
            for index in range(1, 5)
        ]}
        retry.require_candidate_probe_inventory(valid)
        full = dict(valid, qualification_scope="full_inrou", inrou_canary={"stage_tree_sha256": "a" * 64}, inrou_stage_tree_sha256="a" * 64)
        retry.require_candidate_probe_inventory(full)
        for value in (dict(valid, inrou_canary={}), dict(valid, inrou_stage_tree_sha256="a" * 64),
                      dict(full, inrou_canary=None), dict(full, inrou_stage_tree_sha256="b" * 64)):
            with self.assertRaises(retry.RetryError):
                retry.require_candidate_probe_inventory(value)
        for field in ("inrou_canary", "inrou_stage_tree_sha256"):
            value = dict(valid)
            del value[field]
            with self.assertRaises(retry.RetryError):
                retry.require_candidate_probe_inventory(value)
        for scope in (None, "", "inrou", "all", "CORE_TESTNET", True, []):
            value = copy.deepcopy(valid)
            value["qualification_scope"] = scope
            with self.subTest(scope=scope), self.assertRaises(retry.RetryError):
                retry.require_candidate_probe_inventory(value)
        for public_key in (None, "", OPERATOR_PUBLIC_KEY.lower(),
                           OPERATOR_PUBLIC_KEY.upper(), OPERATOR_PUBLIC_KEY + "\n",
                           OPERATOR_PUBLIC_KEY[:-1], "802620" + "A" * 64, 1):
            value = copy.deepcopy(valid)
            value["operator_public_key"] = public_key
            with self.subTest(public_key=public_key), self.assertRaises(retry.RetryError):
                retry.require_candidate_probe_inventory(value)
        for origin in (None, "https://taira.sora.org/", "http://localhost:8080/",
                       "http://127.0.0.1/", "http://127.0.0.1:0/",
                       "http://127.0.0.1:80/", 8080,
                       "http://127.0.0.1:65536/", "http://127.0.0.1:08080/",
                       "http://127.0.0.1:18082/", "http://127.0.0.1:8080/path"):
            value = copy.deepcopy(valid)
            value["validator_clients"][0]["probe_origin"] = origin
            with self.subTest(origin=origin), self.assertRaises(retry.RetryError):
                retry.require_candidate_probe_inventory(value)
        for value in ({}, {"validator_clients": []},
                      {"validator_clients": list(reversed(valid["validator_clients"]))}):
            with self.assertRaises(retry.RetryError):
                retry.require_candidate_probe_inventory(value)

    def test_actual_artifact_identity_is_separate_from_attempt(self):
        build, binary, source = artifact_receipts()
        self.assertEqual(
            retry.validate_artifact_receipts(build, binary, source), build["commit"]
        )
        for change in ("binary", "source", "build"):
            b, a, s = copy.deepcopy((build, binary, source))
            if change == "binary":
                a["artifacts"][0]["sha256"] = "d" * 64
            elif change == "source":
                s["commit"] = "e" * 40
            else:
                b["exit_code"] = 0
            with self.assertRaises(retry.RetryError):
                retry.validate_artifact_receipts(b, a, s)

    def test_kagami_transfer_is_required_and_bound_to_preparation(self):
        for receipt_index in (0, 1):
            receipts = list(copy.deepcopy(artifact_receipts()))
            receipts[receipt_index]["artifacts"] = [
                row for row in receipts[receipt_index]["artifacts"]
                if row["name"] != "kagami"
            ]
            with self.subTest(receipt=receipt_index), self.assertRaises(retry.RetryError):
                retry.validate_artifact_receipts(*receipts)
        build, binary, source = artifact_receipts()
        next(row for row in binary["artifacts"] if row["name"] == "kagami")["sha256"] = "c" * 64
        with self.assertRaisesRegex(retry.RetryError, "transfer differs"):
            retry.validate_artifact_receipts(build, binary, source)

    def test_kagami_inventory_path_and_digest_cannot_be_substituted(self):
        build, binary, source = artifact_receipts()
        artifact = {"role": "kagami", "sha256": "b" * 64,
                    "local_path": "/runtime/artifacts/bin/kagami"}
        inventory = {"revision": {"commit": build["commit"], "source_root": "/source"},
                     "validators": [{"artifacts": [artifact]}], "edge": {"artifacts": []}}
        retry.require_same_inventory_artifacts(inventory, binary, source)
        for field, wrong in (("sha256", "c" * 64), ("local_path", "/unadmitted/bin/kagami")):
            changed = copy.deepcopy(inventory)
            changed["validators"][0]["artifacts"][0][field] = wrong
            with self.subTest(field=field), self.assertRaises(retry.RetryError):
                retry.require_same_inventory_artifacts(changed, binary, source)

    def test_config_paths_remain_exact_for_same_artifact_retry(self):
        build, binary, source = artifact_receipts()
        row = {
            "role": "iroha_cli",
            "sha256": "b" * 64,
            "local_path": "/runtime/artifacts/bin/iroha",
        }
        inventory = {
            "revision": {"commit": build["commit"], "source_root": "/source"},
            "validators": [{"artifacts": [row]}],
            "edge": {"artifacts": [row]},
        }
        retry.require_same_inventory_artifacts(inventory, binary, source)
        row["local_path"] = "/runtime/new/bin/iroha"
        with self.assertRaises(retry.RetryError):
            retry.require_same_inventory_artifacts(inventory, binary, source)

    def test_complete_edge_rollback_is_supported_and_incomplete_edge_rejects(self):
        inventory = {"qualification_scope": "full_inrou", "revision": {"commit": "a" * 40}, "deployment_id": "actual75"}
        value = {
            "deployment_id": "actual75",
            "qualification_scope": "full_inrou",
            "status": "rolled_back",
            "phase": "rolled_back",
            "next_step": 9,
            "touched_validators": list(retry.RETIRE_SLUGS[:-1]),
            "edge_touched": True,
            "edge_rollback_complete": True,
            "rollback_next_validator": 4,
            "rollback_failures": [],
            "recovery_intent": None,
        }
        with (
            mock.patch.object(retry, "RETIRE_COMMIT", "a" * 40),
            mock.patch.object(retry, "RETIRE_RETAINED_DEPLOYMENT", "actual75"),
        ):
            retry._retire_validate_terminal(inventory, value)
            recovered = dict(value, rollback_failures=[
                "phase=rollback;target=taira-validator-3;class=operation_failed;sha256=" + "b" * 64
            ])
            retry._retire_validate_terminal(inventory, recovered)
            for field, changed in (("rollback_next_validator", 3),
                                   ("status", "rolling_back"),
                                   ("edge_rollback_complete", False)):
                with self.subTest(recovered=field), self.assertRaises(retry._retire_RebindError):
                    retry._retire_validate_terminal(inventory, dict(recovered, **{field: changed}))
            for field, changed in (
                ("edge_rollback_complete", False),
                ("rollback_next_validator", 3),
                ("recovery_intent", {}),
                ("rollback_failures", ["failed"]),
                ("rollback_failures", recovered["rollback_failures"] * 6),
                ("rollback_failures", ["phase=rollback;target=other;class=operation_failed;sha256=" + "b" * 64]),
                ("phase", "rolling_back"),
            ):
                with (
                    self.subTest(field=field),
                    self.assertRaises(retry._retire_RebindError),
                ):
                    retry._retire_validate_terminal(
                        inventory, dict(value, **{field: changed})
                    )

    def test_host_progress_must_include_completed_edge(self):
        context = {
            "inventory_sha256": "a",
            "authorization_sha256": "b",
            "nonce": "c",
            "edge_touched": True,
        }
        progress = {
            "schema": "iroha.taira.public-reset.host-progress.v1",
            "inventory_sha256": "a",
            "authorization_sha256": "b",
            "authorization_nonce": "c",
            "prepared_action": None,
            "rolling_back": True,
            "sealed": False,
            "touched_hosts": list(retry.RETIRE_SLUGS),
            "rolled_back_hosts": list(retry.RETIRE_SLUGS),
        }
        retry._retire_validate_progress(progress, context)
        progress["rolled_back_hosts"] = list(retry.RETIRE_SLUGS[:-1])
        with self.assertRaises(retry._retire_RebindError):
            retry._retire_validate_progress(progress, context)

    def test_same_cli_retirement_accepts_exact_manifest(self):
        _, manifest, _ = artifact_receipts()
        fake = SimpleNamespace(fd=123, close=lambda: None)
        args = SimpleNamespace(expected_commit="a" * 40, new_cli_sha256="b" * 64)
        with (
            mock.patch.object(
                retry, "RETIRE_BINARY_MANIFEST", Path("/runtime/manifest.json")
            ),
            mock.patch.object(retry, "RETIRE_BINS", Path(manifest["destination"])),
            mock.patch.object(retry, "RETIRE_COMMIT", args.expected_commit),
            mock.patch.object(retry, "RETIRE_CLI_SHA", args.new_cli_sha256),
            mock.patch.object(
                retry, "_retire_read_public", return_value=json.dumps(manifest).encode()
            ),
            mock.patch.object(retry, "_retire_binary", return_value=fake),
            mock.patch.object(
                retry.os, "fstat", return_value=SimpleNamespace(st_size=10)
            ),
            mock.patch.object(retry, "_retire_retained_context", return_value={}),
        ):
            value = retry._retire_context_from_retained({}, args)
        self.assertEqual(value["expected_commit"], "a" * 40)
        self.assertEqual(value["new_dispatcher_sha256"], "b" * 64)

    def test_capacity_observation_reads_only_public_stage_content_not_configs(self):
        stage = self.root / "stage"
        (stage / "payloads").mkdir(parents=True)
        config = self.root / "peer.toml"
        config.write_bytes(b"private_config_fixture_must_never_be_read")
        config.chmod(0o600)
        (stage / "container.json").write_text(
            json.dumps({"resources": {"ephemeral_storage_bytes": 16}})
        )
        (stage / "service.json").write_text(
            json.dumps({"lease_volumes": [], "artifacts": []})
        )
        archive = io.BytesIO()
        with retry.tarfile.open(fileobj=archive, mode="w:") as tar:
            info = retry.tarfile.TarInfo("app/main.py")
            info.size = 4
            tar.addfile(info, io.BytesIO(b"pass"))
        (stage / "payloads/bundle.bin").write_bytes(
            retry.gzip.compress(archive.getvalue())
        )
        (stage / "manifests").mkdir()
        bindings = {}
        for role, name in (
            ("bundle", "bundle.to"),
            ("guest", "aarch64.to"),
            ("discovery", "discovery.to"),
        ):
            path = stage / "manifests" / name
            path.write_bytes(("public manifest fixture " + role).encode())
            bindings[role + "_manifest_sha256"] = retry.hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
        inventory = {
            "qualification_scope": "full_inrou",
            "revision": {"commit": "a" * 40},
            "validators": [
                {
                    "slug": "taira-validator-1",
                    "artifacts": [
                        {
                            "role": "config",
                            "local_path": str(config),
                            "size": config.stat().st_size,
                        }
                    ],
                }
            ],
            "edge": {"slug": "taira-edge", "artifacts": []},
            "inrou_canary": {
                **bindings,
                "stage_bytes": sum(
                    path.stat().st_size for path in stage.rglob("*") if path.is_file()
                ),
            },
        }
        actual_lstat = Path.lstat

        def root_metadata(path):
            info = actual_lstat(path)
            result = {
                name: getattr(info, name)
                for name in dir(info)
                if name.startswith("st_")
            }
            result["st_uid"] = 0
            return SimpleNamespace(**result)

        allowed = {
            stage / "container.json",
            stage / "service.json",
            stage / "payloads/bundle.bin",
        }
        allowed.update((stage / "manifests").iterdir())
        reads = []

        def read_public(path, *args, **kwargs):
            path = Path(path)
            self.assertIn(path, allowed)
            reads.append(path)
            return path.read_bytes()

        with (
            mock.patch.object(Path, "lstat", root_metadata),
            mock.patch.object(retry, "public_record", side_effect=read_public),
        ):
            inputs, runtime = retry.measured_capacity_inputs(inventory, stage)
        self.assertEqual(set(reads), allowed)
        self.assertEqual(inputs["artifacts"][0]["bytes"], config.stat().st_size)
        self.assertEqual(
            runtime["bundle_members"],
            [{"path": "app/main.py", "kind": "file", "bytes": 4}],
        )
        self.assertNotIn("private_config_fixture", json.dumps((inputs, runtime)))

    def test_measured_capacity_includes_four_runtimes_and_physical_reserve(self):
        result = derived_capacity()
        self.assertEqual(
            result["derivation"]["per_replica_runtime"],
            {"bytes": 3347934329, "inodes": 139},
        )
        rows = result["guest_plan"]["allocations"]
        self.assertEqual(
            sum(
                row["bytes"]
                for row in rows
                if row["label"].startswith("runtime replica ")
            ),
            13391737316,
        )
        self.assertEqual(
            sum(row["bytes"] for row in result["backing_plan"]["allocations"]),
            sum(row["bytes"] for row in rows) + 2 * 1024**3,
        )
        inputs, runtime = measured_inputs()
        runtime["lease_volumes"][1]["max_total_bytes"] += 1024**2
        self.assertEqual(
            derived_capacity(inputs, runtime)["derivation"]["required_bytes"]
            - result["derivation"]["required_bytes"],
            4 * 1024**2,
        )

    def test_measured_capacity_uses_actual_binary_role_weights_and_config_bound(self):
        old = derived_capacity()
        build = artifact_receipts()[0]
        next(row for row in build["artifacts"] if row["name"] == "iroha3d_taira")[
            "size"
        ] += 1024
        next(row for row in build["artifacts"] if row["name"] == "iroha")["size"] += (
            2048
        )
        next(row for row in build["artifacts"] if row["name"] == "kagami")["size"] += 4096
        new = derived_capacity(build=build)
        self.assertEqual(
            new["derivation"]["required_bytes"] - old["derivation"]["required_bytes"],
            3 * (4 * 1024 + 5 * 2048 + 4 * 4096),
        )
        configs = [
            row
            for row in new["derivation"]["artifact_role_sizes"]
            if row["role"] == "config"
        ]
        self.assertEqual([row["bytes"] for row in configs], [1024**2] * 4)

    def test_measured_capacity_rejects_unknown_stage_service_and_missing_role(self):
        for variant in ("stage", "service", "role", "profile"):
            inputs, runtime = measured_inputs()
            if variant == "stage":
                inputs["stage_files"].pop()
            if variant == "service":
                runtime["service_artifacts"] = [{"unmodeled": True}]
            if variant == "role":
                inputs["artifacts"].pop()
            if variant == "profile":
                inputs.pop("native_sf1_manifest_bindings")
            with (
                self.subTest(variant=variant),
                self.assertRaises(capacity.CapacityError),
            ):
                derived_capacity(inputs, runtime)

    def test_runtime_paths_come_from_native_assembly_not_new_attempt_names(self):
        prep = "/private/runtime/prep"
        arguments = {
            "--public-inputs": [prep + "/public-inputs"],
            "--runtime-client-config": [prep + "/runtime-client.toml"],
            "--validator-client-config": [
                prep + f"/validator-{i}-client.toml" for i in range(1, 5)
            ],
            "--validator-operator-key": ["/private/runtime/operator.key"],
            "--inrou-stage-dir": [prep + "/inrou-stage"],
            "--onboarding-token": [prep + "/network/runtime/onboarding.token"],
            "--known-hosts": ["/private/runtime/known-hosts"],
        }
        plan = {
            "runtime_root": "/private/runtime",
            "previous_inventory": "/private/runtime/assembly/inventory.json",
        }
        _, binary, _ = artifact_receipts()
        result = retry.derive_runtime_paths(
            plan, binary, {"qualification_scope": "full_inrou", "revision": {"commit": "a" * 40}}, arguments
        )
        self.assertEqual(result["attempts_root"], "/private/runtime/retry-v1")
        self.assertEqual(result["prep_root"], prep)
        self.assertEqual(
            result["binary_manifest"], "/runtime/artifacts/verified-manifest.json"
        )
        self.assertEqual(
            result["local_args_path"],
            "/private/runtime/assembly/native-local-args.json",
        )
        arguments["--onboarding-token"] = ["/private/unrelated/token"]
        with self.assertRaises(retry.RetryError):
            retry.derive_runtime_paths(
                plan, binary, {"qualification_scope": "full_inrou", "revision": {"commit": "a" * 40}}, arguments
            )

    def test_full_capacity_requires_all_four_runtime_footprints(self):
        module = {"validate_plan": capacity.validate_plan}
        plan = full_plan()
        retry.validate_full_capacity(module, plan, "full_inrou")
        plan["allocations"] = [
            row for row in plan["allocations"] if row["label"] != "runtime replica 4"
        ]
        with self.assertRaises(retry.RetryError):
            retry.validate_full_capacity(module, plan, "full_inrou")

    def test_capacity_false_and_missing_headroom_fail_before_mutation(self):
        with self.assertRaises(retry.RetryError):
            retry.check_capacity(
                {"evaluate": lambda _: {"passed": False, "errors": ["ENOSPC"]}},
                {},
                "apply",
            )
        plan = full_plan()
        plan["allocations"][-1]["bytes"] = 1
        with self.assertRaises(retry.RetryError):
            retry.validate_full_capacity(
                {"validate_plan": capacity.validate_plan}, plan, "full_inrou"
            )

    def test_errno_projection_keeps_operation_and_never_key_or_header_values(self):
        raw = (
            b"phase=preseed failed to write staged chunk4596: No space left on device (os error 28)\n"
            b"private_key=NOT-A-REAL-KEY authorization: bearer NOT-A-REAL-TOKEN"
        )
        result = retry.safe_native_error(raw)
        self.assertEqual(result["errno_name"], "ENOSPC")
        self.assertEqual(result["native_phase"], "preseed")
        self.assertEqual(result["operation"], "write staged chunk")
        self.assertNotIn("NOT-A-REAL", json.dumps(result))

    def test_native_heartbeat_projects_only_phase_and_counts(self):
        path = self.record(
            "journal.json",
            {
                "schema": "iroha.taira.public-reset.journal.v1",
                "phase": "preseed",
                "qualification_scope": "full_inrou",
                "next_step": 5,
                "touched_validators": ["one", "two", "three", "four"],
                "edge_touched": False,
                "authorization_nonce": "MUST_NOT_LEAK",
                "failure_summary": "SECRET_TEST_VALUE",
            },
        )
        with mock.patch.object(
            retry,
            "public_record",
            side_effect=lambda path, **kwargs: Path(path).read_bytes(),
        ):
            result = retry.native_journal_progress(path)
        self.assertEqual(
            result,
            {
                "native_phase": "preseed",
                "next_step": 5,
                "touched_validator_count": 4,
                "edge_touched": False,
            },
        )
        self.assertNotIn("MUST_NOT_LEAK", json.dumps(result))
        self.assertNotIn("SECRET_TEST_VALUE", json.dumps(result))

    def test_public_validation_requires_ready_source_network_and_mcp_without_doctor(self):
        _, binary, _ = artifact_receipts()
        signer = self.root / "signer"
        signer.mkdir()
        retry.write_public(
            signer / "signer-authority-receipt.json", {"network_id": "native-network"}
        )
        for variant in ("valid", "full", "not-ready", "wrong-source", "wrong-target",
                        "empty-tip", "wrong-network", "mcp-error"):
            output = self.root / variant
            calls = []
            inventory = {"qualification_scope": "full_inrou" if variant == "full" else "core_testnet"}

            def native(argv, directory, *, phase, env, **kwargs):
                self.assertEqual(env, {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                self.assertNotIn("--config", argv)
                self.assertEqual(argv[0], "/usr/bin/curl")
                directory.mkdir(mode=0o700)
                calls.append(argv)
                self.assertNotIn("doctor", argv)
                if directory.name == "readiness":
                    self.assertEqual(argv[-1], "https://taira.sora.org/readyz")
                    self.assertIn("Accept: text/plain", argv)
                    (directory / "stdout").write_bytes(
                        b"503" if variant == "not-ready" else b"200")
                    (directory / "body.json").write_bytes(b"Ready")
                    return
                self.assertIn("--noproxy", argv)
                response = {
                    "status": {
                        "build": {
                            "git_commit_sha": "0" * 40
                            if variant == "wrong-source"
                            else binary["commit"],
                            "target_triple": "x86_64-unknown-linux-gnu"
                            if variant == "wrong-target" else "aarch64-unknown-linux-gnu",
                        }
                    },
                    "tip": 0 if variant == "empty-tip" else 12,
                    "network": {
                        "network_id": "other"
                        if variant == "wrong-network"
                        else "native-network",
                        "chain_discriminant": 369,
                    },
                    "mcp": {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "result": {
                            "isError": variant == "mcp-error",
                            "structuredContent": {"status": 200},
                        },
                    },
                }[directory.name]
                (directory / "stdout").write_bytes(b"200")
                retry.write_public(directory / "body.json", response)
                if directory.name == "mcp":
                    body = json.loads(argv[argv.index("--data-binary") + 1])
                    self.assertEqual(body["params"]["name"], "iroha.health")
                    self.assertEqual(body["params"]["arguments"], {})

            with (
                mock.patch.object(retry, "CONTINUITY_OUT", signer),
                mock.patch.object(retry, "run_native", side_effect=native),
                mock.patch.object(
                    retry,
                    "public_record",
                    side_effect=lambda path, **kwargs: Path(path).read_bytes(),
                ),
            ):
                if variant in ("valid", "full"):
                    result = retry.public_validation(binary, inventory, output)
                    self.assertTrue(result["public_readiness_passed"])
                    self.assertTrue(result["public_mcp_health_passed"])
                    self.assertNotIn("same_revision_doctor_passed", result)
                    self.assertFalse(result["application_validation_completed"])
                else:
                    with self.assertRaises(retry.RetryError):
                        retry.public_validation(binary, inventory, output)
            self.assertEqual(len(calls), 1 if variant == "not-ready" else 5)
        with mock.patch.object(retry, "run_native") as native:
            for scope in (None, "", "unknown"):
                with self.assertRaises(retry.RetryError):
                    retry.public_validation(binary, {"qualification_scope": scope}, self.root / "invalid")
            native.assert_not_called()

    def test_native_error_tail_is_bounded_and_public_only(self):
        path = self.root / "stderr"
        path.write_bytes(b"x" * 100000 + b" write staged chunk 4596 (os error 28)")
        path.chmod(0o600)
        self.assertEqual(retry.native_error(path)["chunk"], 4596)

    def test_native_command_is_submitted_once_across_progress_waits(self):
        process = mock.Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired("native", 30), 0]
        with (
            mock.patch.object(retry.subprocess, "Popen", return_value=process) as popen,
            mock.patch.object(retry, "emit"),
        ):
            result = retry.run_native(
                ["/native", "apply"], self.root / "native", phase="apply"
            )
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(process.wait.call_count, 2)

    def test_native_failure_preserves_errno_receipt_and_never_resubmits(self):
        def create(*args, **kwargs):
            kwargs["stderr"].write(b"write staged chunk 4596 (os error 28)")
            return SimpleNamespace(wait=lambda timeout: 1)

        with (
            mock.patch.object(retry.subprocess, "Popen", side_effect=create) as popen,
            mock.patch.object(retry, "emit"),
            self.assertRaises(retry.RetryError),
        ):
            retry.run_native(["/native", "apply"], self.root / "native", phase="apply")
        value = json.loads((self.root / "native/result.json").read_bytes())
        self.assertEqual(value["errno_name"], "ENOSPC")
        self.assertFalse(value["automatic_replay"])
        self.assertEqual(popen.call_count, 1)

    def test_remote_ssh_failure_reports_phase_exit_and_private_path_once(self):
        output = self.root / "remote"
        child = [sys.executable, "-c",
                 "import sys; sys.stderr.write('private-secret\\n'); sys.exit(255)"]
        printed = io.StringIO()
        with mock.patch.object(retry.subprocess, "Popen", wraps=subprocess.Popen) as popen, \
             contextlib.redirect_stdout(printed):
            with self.assertRaises(retry.RetryError):
                retry.remote_command(child, b"", output, "native-retry")
        events = [json.loads(line) for line in printed.getvalue().splitlines()]
        self.assertEqual(popen.call_count, 1)
        self.assertEqual([(event["phase"], event["status"]) for event in events],
                         [("native-retry", "started"), ("native-retry", "failed")])
        self.assertEqual(events[-1]["exit_code"], 255)
        self.assertEqual(events[-1]["private_log"], str(output))
        self.assertFalse(events[-1]["automatic_replay"])
        self.assertNotIn("private-secret", printed.getvalue())
        self.assertEqual((output / "stderr").read_bytes(), b"private-secret\n")
        self.assertEqual(stat.S_IMODE((output / "stderr").stat().st_mode), 0o600)
        self.assertEqual(json.loads((output / "result.json").read_bytes())["exit_code"], 255)

    def test_future_import_module_payload_does_not_run_cli_main(self):
        source = b'from __future__ import annotations\ndef evaluate(value): return value\nif __name__ == "__main__": raise AssertionError("CLI main")\n'
        payload = retry.remote_payload(
            source, "evaluate", {"passed": True}, print_result=True
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(compile(payload, "<test>", "exec"), {})
        self.assertEqual(json.loads(output.getvalue()), {"passed": True})

    def test_signer_is_an_inherited_read_only_fd_without_python_read(self):
        path = self.root / "signer"
        path.write_bytes(b"PUBLIC-NONKEY-FIXTURE")
        path.chmod(0o600)
        real_fstat = os.fstat

        def info(fd):
            original = real_fstat(fd)
            return SimpleNamespace(st_mode=original.st_mode, st_uid=0, st_nlink=1)

        captured = []

        def native(argv, output, *, phase, pass_fds):
            fd = pass_fds[0]
            self.assertEqual(
                retry.fcntl.fcntl(fd, retry.fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY
            )
            self.assertEqual(argv[argv.index("--signing-key-fd") + 1], fd)
            captured.append(fd)
            return {"passed": True}

        with (
            mock.patch.object(retry.os, "fstat", side_effect=info),
            mock.patch.object(retry, "run_native", side_effect=native),
            mock.patch.object(
                retry.os, "read", side_effect=AssertionError("Python secret read")
            ),
            mock.patch.object(
                retry.os, "pread", side_effect=AssertionError("Python secret pread")
            ),
        ):
            retry.authorize_native(
                ["/native"],
                self.root,
                [],
                {"signing_key": str(path), "trusted_public_key": "/trust"},
                self.root / "native",
            )
        with self.assertRaises(OSError):
            os.fstat(captured[0])

    def test_progress_relay_drops_unstructured_secret_output(self):
        path = self.root / "stdout"
        path.write_bytes(
            b"authorization: NOT-A-REAL-TOKEN\n"
            + json.dumps(
                {
                    "schema": retry.PROGRESS_SCHEMA,
                    "phase": "apply",
                    "status": "failed",
                    "errno_name": "ENOSPC",
                    "unexpected_secret": "NOT-A-REAL-TOKEN",
                }
            ).encode()
            + b"\n"
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cursor, pending, phase = retry.relay_progress(path, 0, b"", "start")
        self.assertEqual(phase, "apply")
        self.assertEqual(cursor, path.stat().st_size)
        self.assertEqual(pending, b"")
        self.assertNotIn("NOT-A-REAL-TOKEN", output.getvalue())
        self.assertIn("ENOSPC", output.getvalue())

    def test_pending_mutation_is_not_inferred_as_rolled_back(self):
        root = self.root / "journal"
        (root / "rolled-back").mkdir(parents=True)
        with self.assertRaisesRegex(retry.RetryError, "pending mutation"):
            retry.find_terminal(root, "pending")

    def test_local_arguments_are_exact_ordered_paths(self):
        flags = (
            ("--public-inputs", 1),
            ("--runtime-client-config", 1),
            ("--validator-client-config", 4),
            ("--validator-operator-key", 1),
            ("--onboarding-token", 1),
            ("--inrou-stage-dir", 1),
            ("--validator-unit", 4),
            ("--native-edge-capability", 1),
            ("--known-hosts", 1),
        )
        args = []
        for flag, count in flags:
            args += [flag, *["/runtime/input-" + str(index) for index in range(count)]]
        actual, grouped = retry.local_arguments(json.dumps(args).encode(), "full_inrou")
        self.assertEqual(actual, args)
        self.assertEqual(len(grouped["--validator-client-config"]), 4)
        self.assertEqual(len(grouped["--validator-operator-key"]), 1)
        self.assertEqual(len(grouped["--native-edge-capability"]), 1)
        retired_edge = list(args)
        retired_edge[retired_edge.index("--native-edge-capability")] = "--edge-unit"
        with self.assertRaisesRegex(retry.RetryError, "order differs"):
            retry.local_arguments(json.dumps(retired_edge).encode(), "full_inrou")
        missing_capability = list(args)
        offset = missing_capability.index("--native-edge-capability")
        del missing_capability[offset:offset + 2]
        with self.assertRaisesRegex(retry.RetryError, "closure required"):
            retry.local_arguments(json.dumps(missing_capability).encode(), "full_inrou")
        apply_arguments = actual[:actual.index("--validator-unit")]
        self.assertIn("--validator-operator-key", apply_arguments)
        missing_key = list(args)
        offset = missing_key.index("--validator-operator-key")
        del missing_key[offset:offset + 2]
        with self.assertRaises(retry.RetryError):
            retry.local_arguments(json.dumps(missing_key).encode(), "full_inrou")
        for flag,count in (("--maintenance-admin-config",1),("--epoch-seed-sources",4),("--epoch-supervisor-plan",1)):
            incomplete=[*args, flag, *["/retired/input" for _ in range(count)]]
            with self.subTest(flag=flag),self.assertRaises(retry.RetryError):retry.local_arguments(json.dumps(incomplete).encode(),"full_inrou")
        bad=list(args);bad.insert(0,"--http-operator-key-sha256");bad.insert(1,"a"*64)
        with self.assertRaises(retry.RetryError):retry.local_arguments(json.dumps(bad).encode(),"full_inrou")
        args[0] = "--private-key"
        with self.assertRaises(retry.RetryError):
            retry.local_arguments(json.dumps(args).encode(), "full_inrou")

    def test_phase_timing_and_failure_record_are_exclusive(self):
        with mock.patch.object(retry, "emit"):
            self.assertEqual(retry.call_phase("retire", lambda: 7, self.root), 7)
            with self.assertRaises(ZeroDivisionError):
                retry.call_phase("signer-post", lambda: 1 / 0, self.root)
        self.assertTrue(
            json.loads((self.root / "retire-phase.json").read_bytes())["passed"]
        )
        self.assertFalse(
            json.loads((self.root / "signer-post-phase.json").read_bytes())["passed"]
        )


class DeploymentRetirementLockTests(unittest.TestCase):
    """Real file descriptors/flocks; only Linux-root metadata is modeled on macOS."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=SCRIPT.parent)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.state = self.base / "deployment-state"
        self.state.mkdir(mode=0o700)
        self.lock = self.state / ".deployment.lock"
        self.lock.write_bytes(b"")
        self.lock.chmod(0o600)
        self.real_lstat, self.real_fstat = Path.lstat, os.fstat
        self.real_open, self.real_close = os.open, os.close
        self.real_flock = retry.fcntl.flock
        self.overrides = {}
        self.opened, self.closed = [], []
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(retry, "RETIRE_DEPLOYMENT_STATE", self.state))

        def metadata(info):
            values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            values.update(st_uid=0, st_gid=0)
            values.update(self.overrides.get((info.st_dev, info.st_ino), {}))
            return SimpleNamespace(**values)

        def lstat(path, *args, **kwargs):
            return metadata(self.real_lstat(path, *args, **kwargs))

        def opened(path, flags, *args, **kwargs):
            fd = self.real_open(path, flags, *args, **kwargs)
            self.opened.append((Path(path), fd, flags))
            return fd

        def closed(fd):
            self.closed.append(fd)
            return self.real_close(fd)

        self.stack.enter_context(mock.patch.object(Path, "lstat", lstat))
        self.stack.enter_context(mock.patch.object(retry.os, "fstat", side_effect=lambda fd: metadata(self.real_fstat(fd))))
        self.stack.enter_context(mock.patch.object(retry.os, "open", side_effect=opened))
        self.stack.enter_context(mock.patch.object(retry.os, "close", side_effect=closed))

    def override(self, path, **fields):
        info = self.real_lstat(path)
        self.overrides[(info.st_dev, info.st_ino)] = fields

    def assert_all_closed(self):
        for _, fd, _ in self.opened:
            with self.assertRaises(OSError):
                self.real_fstat(fd)

    def test_existing_lock_is_held_exclusively_without_creation_or_private_reads(self):
        with mock.patch.object(retry.os, "read", side_effect=AssertionError("unexpected body read")):
            fd = retry._retire_deployment_lock()
        try:
            flags = self.opened[-1][2]
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertFalse(flags & os.O_CREAT)
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_CLOEXEC)
            self.assertTrue(flags & os.O_NONBLOCK)
            competing = self.real_open(self.lock, os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    self.real_flock(competing, retry.fcntl.LOCK_EX | retry.fcntl.LOCK_NB)
            finally:
                self.real_close(competing)
        finally:
            retry.os.close(fd)
        self.assert_all_closed()

    def test_contended_existing_lock_fails_without_wait_or_descriptor_leak(self):
        held = self.real_open(self.lock, os.O_RDONLY)
        self.real_flock(held, retry.fcntl.LOCK_EX | retry.fcntl.LOCK_NB)
        try:
            with self.assertRaises(BlockingIOError):
                retry._retire_deployment_lock()
            self.assert_all_closed()
        finally:
            self.real_close(held)

    def test_missing_or_symlinked_lock_is_never_recreated_or_followed(self):
        self.lock.unlink()
        with self.assertRaises(FileNotFoundError):
            retry._retire_deployment_lock()
        self.assertFalse(self.lock.exists())
        target = self.state / "unadmitted-lock"
        target.write_bytes(b"")
        target.chmod(0o600)
        self.lock.symlink_to(target)
        with self.assertRaises(OSError):
            retry._retire_deployment_lock()
        self.assertTrue(self.lock.is_symlink())
        self.assert_all_closed()

    def test_root_and_lock_custody_and_active_owner_reject(self):
        for path, field, wrong in (
            (self.state, "st_uid", 1), (self.state, "st_gid", 1),
            (self.state, "st_mode", retry.stat.S_IFDIR | 0o777),
            (self.lock, "st_uid", 1), (self.lock, "st_gid", 1),
            (self.lock, "st_nlink", 2), (self.lock, "st_size", 1),
            (self.lock, "st_mode", retry.stat.S_IFREG | 0o644),
        ):
            with self.subTest(path=path.name, field=field):
                self.override(path, **{field: wrong})
                with self.assertRaises(retry._retire_RebindError):
                    retry._retire_deployment_lock()
                self.assert_all_closed()
                self.overrides.clear()
        owner = self.state / ".reset-owner.json"
        owner.write_bytes(b"PUBLIC-OWNER-MARKER-FIXTURE")
        with self.assertRaisesRegex(retry._retire_RebindError, "active reset owner"):
            retry._retire_deployment_lock()
        self.assert_all_closed()

    def test_retired_worker_state_service_or_broken_symlink_reject_without_mutation(self):
        state = self.base / "retired-worker"
        unit = self.base / "retired-worker.service"
        with mock.patch.object(retry, "RETIRE_WORKER_STATE", state), mock.patch.object(retry, "RETIRE_WORKER_UNIT", unit):
            for path in (state, unit):
                path.write_bytes(b"retired public fixture")
                with self.assertRaisesRegex(retry._retire_RebindError, "retired epoch worker"):
                    retry._retire_deployment_lock()
                self.assertEqual(path.read_bytes(), b"retired public fixture")
                path.unlink()
            unit.symlink_to(self.base / "absent")
            with self.assertRaisesRegex(retry._retire_RebindError, "retired epoch worker"):
                retry._retire_deployment_lock()
            self.assertTrue(unit.is_symlink())
        self.assert_all_closed()

    def test_named_lock_replacement_during_acquisition_rejects(self):
        def changed(fd, flags):
            self.real_flock(fd, flags)
            self.lock.rename(self.state / "retained-lock")
            self.lock.write_bytes(b"")
            self.lock.chmod(0o600)
        with mock.patch.object(retry.fcntl, "flock", side_effect=changed):
            with self.assertRaisesRegex(retry._retire_RebindError, "changed during acquisition"):
                retry._retire_deployment_lock()
        self.assert_all_closed()

    def prepare_retirement_locks(self):
        runtime, control, work = self.base / "runtime", self.base / "control", self.base / "work"
        paths = [runtime / "journal-v1/public-reset.lock", control / "hosts/fixture/action.lock", self.lock]
        for path in paths[:2]:
            path.parent.mkdir(parents=True, mode=0o700)
            path.write_bytes(b"")
            path.chmod(0o600)
        for name, value in (("RETIRE_RUNTIME", runtime), ("RETIRE_CONTROL", control), ("RETIRE_WORK", work)):
            self.stack.enter_context(mock.patch.object(retry, name, value))
        return paths

    def test_retirement_holds_native_lock_order_and_releases_in_reverse(self):
        paths = self.prepare_retirement_locks()
        guard = {"inspect_file": lambda info, **kwargs: self.assertEqual(info.st_size, 0)}
        with retry._retire_locks(guard, {"coordination_relative": "hosts/fixture"}):
            self.assertEqual([path for path, _, _ in self.opened], paths)
            for path in paths:
                competing = self.real_open(path, os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):
                        self.real_flock(competing, retry.fcntl.LOCK_EX | retry.fcntl.LOCK_NB)
                finally:
                    self.real_close(competing)
        self.assertEqual(self.closed, [fd for _, fd, _ in reversed(self.opened)])
        self.assert_all_closed()

    def test_deployment_failure_releases_preceding_retirement_locks(self):
        paths = self.prepare_retirement_locks()
        (self.state / ".reset-owner.json").write_bytes(b"PUBLIC-OWNER-MARKER-FIXTURE")
        with self.assertRaisesRegex(retry._retire_RebindError, "active reset owner"):
            with retry._retire_locks({"inspect_file": lambda *_args, **_kwargs: None},
                                     {"coordination_relative": "hosts/fixture"}):
                self.fail("retirement entered while reset owns the lifecycle")
        self.assertEqual([path for path, _, _ in self.opened], paths)
        self.assertEqual(self.closed, [fd for _, fd, _ in reversed(self.opened)])
        self.assert_all_closed()




class BeaconArgumentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.reads = []
        self.counter = 0
        self.renderer = self.root / "renderer.py"
        self.renderer.write_bytes(UNIT_RENDERER_PATH.read_bytes())
        self.renderer.chmod(0o644)
        self.plan = {"unit_renderer": {"path": str(self.renderer), "sha256": retry.hashlib.sha256(self.renderer.read_bytes()).hexdigest()}}
        self.draft = {"authorization_nonce": "1" * 32, "validators": []}
        self.arguments = {"--validator-unit": []}
        for index in range(1, 5):
            role = f"taira-validator-{index}"
            path = self.root / ("iroha3d-" + role + ".service")
            raw = UNIT_RENDERER["render"](role, f"/unread/{index}.key").encode()
            path.write_bytes(raw)
            path.chmod(0o644)
            self.arguments["--validator-unit"].append(str(path))
            self.draft["validators"].append({"slug": role, "systemd_unit": path.name, "systemd_unit_sha256": retry.hashlib.sha256(raw).hexdigest()})
        self.static = ["--public-inputs", "/retained/public-inputs", "--validator-unit", *self.arguments["--validator-unit"]]
        real_read = retry.public_record
        def public_read(path, expected=None, **kwargs):
            self.reads.append(Path(path))
            kwargs.pop("owner", None)  # Fixture files belong to the local test runner.
            return real_read(path, expected, **kwargs)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(retry, "public_record", side_effect=public_read))
        self.stack.enter_context(mock.patch.object(retry, "_continuity_read", side_effect=lambda path, limit=1024*1024, expected=None: public_read(path, expected, limit=limit)))

    def prepare(self, change=None):
        self.counter += 1
        assembly = self.root / str(self.counter)
        assembly.mkdir(mode=0o700)
        value = beacon_input_fixture(self.draft)
        if change:
            change(value)
        def native(argv, directory, *, phase):
            self.assertEqual(phase, "prepare-beacon-inputs")
            self.assertEqual(argv[3], "prepare-beacon-inputs")
            self.assertEqual(argv[argv.index("--public-inputs") + 1], assembly / "public-inputs")
            retry.write_public(Path(argv[argv.index("--output") + 1]), value)
        with mock.patch.object(retry, "run_native", side_effect=native):
            derived = retry.prepare_beacon_arguments(["/native/iroha", "taira", "public-reset"], assembly, self.plan, self.static, self.arguments, self.draft, self.draft, assembly / "native")
        return assembly, derived, value

    def test_native_nonce_seat_map_renders_exact_four_units_without_private_reads(self):
        original = list(self.static)
        assembly, derived, value = self.prepare()
        self.assertEqual(self.static, original)
        self.assertEqual(derived[1], str(assembly / "public-inputs"))
        self.assertEqual(json.loads((assembly / "native-assembly-args.json").read_bytes()), derived)
        self.assertEqual(json.loads((assembly / "native-local-args.json").read_bytes()), original)
        paths = derived[derived.index("--beacon-validator-unit") + 1:]
        self.assertEqual(len(paths), 4)
        for index, (path, row) in enumerate(zip(paths, value["final_units"]), 1):
            expected = UNIT_RENDERER["render"](row["validator"], f"/unread/{index}.key", row["credential_path"], config_file="beacon.toml")
            self.assertEqual(Path(path).read_text(), expected)
            self.assertEqual(Path(path).stat().st_mode & 0o777, 0o644)
        self.assertEqual(set(self.reads), {self.renderer, assembly / "beacon-inputs.json", *(Path(p) for p in self.arguments["--validator-unit"])})
        self.assertFalse(any(str(path).startswith("/unread/") for path in self.reads))

    def test_native_output_rejects_wrong_nonce_duplicate_seat_role_path_and_config(self):
        mutations = [
            lambda v: v.update(authorization_nonce="2" * 32),
            lambda v: v.update(schema="old"),
            lambda v: v.update(extra="ambiguous"),
            lambda v: v["final_units"].pop(),
            lambda v: v["final_units"][0].update(signer_index=True),
            lambda v: v["final_units"][0].update(signer_index=v["final_units"][1]["signer_index"]),
            lambda v: v["final_units"][0].update(validator="taira-validator-2"),
            lambda v: v["final_units"][0].update(credential_path="/foreign/credential"),
            lambda v: v["final_units"][0].update(config_file="../config.toml"),
        ]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(retry.RetryError):
                self.prepare(change)
            self.assertFalse((self.root / str(self.counter) / "beacon-units").exists())

    def test_initial_unit_and_renderer_bytes_must_match_pins(self):
        self.plan["unit_renderer"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(retry.RetryError, "digest"):
            self.prepare()
        self.plan["unit_renderer"]["sha256"] = retry.hashlib.sha256(self.renderer.read_bytes()).hexdigest()
        initial = Path(self.arguments["--validator-unit"][0])
        initial.write_bytes(initial.read_bytes() + b"# unexpected edit\n")
        with self.assertRaisesRegex(retry.RetryError, "digest"):
            self.prepare()
        self.draft["validators"][0]["systemd_unit_sha256"] = retry.hashlib.sha256(initial.read_bytes()).hexdigest()
        with self.assertRaisesRegex(RuntimeError, "exact reviewed"):
            self.prepare()

    def test_apply_arguments_exclude_all_assembly_only_inputs_in_both_scopes(self):
        inputs = {flag: ["/path/" + flag[2:]] for flag in (
            "--runtime-client-config", "--validator-client-config", "--validator-operator-key",
            "--onboarding-token", "--inrou-stage-dir", "--public-inputs", "--validator-unit",
            "--native-edge-capability", "--beacon-inputs", "--beacon-validator-unit")}
        for scope in ("core_testnet", "full_inrou"):
            result = retry.apply_arguments(inputs, scope)
            self.assertNotIn("--maintenance-admin-config",result)
            self.assertNotIn("--epoch-seed-sources",result)
            self.assertNotIn("--epoch-supervisor-plan",result)
            self.assertNotIn("--epoch-seed-source",result)
            self.assertEqual("--inrou-stage-dir" in result, scope == "full_inrou")
            for flag in ("--public-inputs", "--validator-unit", "--native-edge-capability", "--beacon-inputs", "--beacon-validator-unit"):
                self.assertNotIn(flag, result)


class BeaconCompletionTests(unittest.TestCase):
    def setUp(self):
        self.assembly = Path("/runtime/retry-v1/attempt/assembly")
        self.before = {"inventory_sha256": "a" * 64, "nodes": []}
        self.frontier = {"inventory_sha256": "a" * 64, "authorization_sha256": "b" * 64}
        self.inventory = {"authorization_nonce": "1" * 32, "validators": [], "validator_clients": [],
                          "beacon_bootstrap": {"request": {"dkg_session": {"session_id": [7] * 32}}, "final_units": []}}
        self.markers = {}
        for index in range(1, 5):
            role = f"taira-validator-{index}"
            unit = f"iroha3d-{role}.service"
            original = f"/srv/taira/{role}/releases/commit/config/config.toml"
            argv = [f"/srv/taira/{role}/current/bin/iroha3d_taira", "--config", f"/srv/taira/{role}/current/config/config.toml", "--sora"]
            self.inventory["validators"].append({"slug": role, "systemd_unit": unit,
                "artifacts": [{"role": "config", "remote_path": original, "sha256": "c" * 64}]})
            self.inventory["validator_clients"].append({"slug": role, "peer_id": f"peer-{index}"})
            self.inventory["beacon_bootstrap"]["final_units"].append({"validator": role, "sha256": "d" * 64})
            self.before["nodes"].append({"peer_id": f"peer-{index}", "systemd_unit": unit,
                "unit_sha256": "e" * 64, "config_sha256": "c" * 64, "signer_file": {"inode": index},
                "signer_fd": 198, "node_fingerprint": f"node-{index}",
                "binding": {"config_path": original, "config_sha256": "c" * 64,
                            "config_files": [{"path": original, "sha256": "c" * 64}], "argv": argv}})
            self.markers[role] = {"schema": "iroha.taira.public-reset.beacon-provider-active.v1",
                "authorization_sha256": "b" * 64, "bundle_sha256": "f" * 64,
                "validator": role, "session_id": [7] * 32, "config_sha256": "9" * 64, "unit_sha256": "d" * 64}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.completed = self.stack.enter_context(mock.patch.object(retry, "completed_attempt", return_value={"inventory": self.inventory}))
        self.reads = []
        def public_read(path, *args, **kwargs):
            self.reads.append(str(path))
            if Path(path).name == "apply-started.json":
                return json.dumps(self.frontier).encode()
            self.assertEqual(Path(path).parent, Path("/var/lib/taira/.public-reset-control-v1/beacon") / ("1" * 32))
            role = Path(path).name.removesuffix(".active.json")
            return json.dumps(self.markers[role]).encode()
        self.stack.enter_context(mock.patch.object(retry, "public_record", side_effect=public_read))

    def test_completed_native_activation_changes_only_authenticated_process_binding(self):
        original = copy.deepcopy(self.before)
        rows = retry.beacon_completed_rows(Path("/runtime"), self.assembly, self.before)
        self.completed.assert_called_once_with({"runtime_root": "/runtime"}, self.assembly.parent, required=True)
        self.assertEqual(self.before, original)
        for old, row in zip(original["nodes"], rows):
            self.assertEqual(row["signer_file"], old["signer_file"])
            self.assertEqual(row["signer_fd"], 198)
            self.assertEqual(row["node_fingerprint"], old["node_fingerprint"])
            self.assertEqual(row["unit_sha256"], "d" * 64)
            self.assertEqual(row["config_sha256"], "9" * 64)
            self.assertTrue(row["binding"]["config_path"].endswith("/beacon.toml"))
            self.assertTrue(row["binding"]["argv"][2].endswith("/beacon.toml"))
        self.assertFalse(any(path.endswith(".toml") for path in self.reads))

    def test_marker_cannot_authorize_without_exact_native_completion(self):
        self.completed.side_effect = retry.RetryError("exact native completed receipt is missing")
        with self.assertRaisesRegex(retry.RetryError, "completed receipt"):
            retry.beacon_completed_rows(Path("/runtime"), self.assembly, self.before)
        self.assertEqual(self.reads, [])

    def test_projection_rejects_foreign_authorization_session_unit_bundle_and_inventory(self):
        for field, value in (("authorization_sha256", "0" * 64), ("session_id", [8] * 32),
                             ("unit_sha256", "0" * 64), ("bundle_sha256", "0" * 64),
                             ("validator", "foreign"), ("config_sha256", "invalid")):
            with self.subTest(field=field):
                saved = copy.deepcopy(self.markers)
                self.markers["taira-validator-2"][field] = value
                with self.assertRaises(retry.RetryError):
                    retry.beacon_completed_rows(Path("/runtime"), self.assembly, self.before)
                self.markers = saved
        self.frontier["inventory_sha256"] = "0" * 64
        with self.assertRaisesRegex(retry.RetryError, "pre-start inventory"):
            retry.beacon_completed_rows(Path("/runtime"), self.assembly, self.before)


class CoreScopeTests(unittest.TestCase):
    def test_scope_steps_match_native_preseed_and_seal_boundaries(self):
        core = retry.qualification_steps("core_testnet")
        full = retry.qualification_steps("full_inrou")
        self.assertEqual((len(core), len(full)), (13, 14))
        self.assertEqual(core, tuple(step for step in full if step != "preseed"))
        self.assertEqual((core[2], full[2]), ("stop", "stop"))
        self.assertEqual((core[5], full[5], full[6]), ("start", "preseed", "start"))
        self.assertEqual((core[11], full[12]), ("seal", "seal"))
        self.assertEqual(core[6:9], ("canary", "convergence", "edge_stage"))
        self.assertEqual(full[7:10], core[6:9])
        self.assertNotIn("restart_proof", core)
        self.assertNotIn("restart_proof", full)
        for scope in (None, "inrou", "basic", "full", ""):
            with self.subTest(scope=scope), self.assertRaises(retry.RetryError):
                retry.qualification_steps(scope)

    def test_journal_order_matches_native_execution_arrays_and_serialized_labels(self):
        # This is a cross-language journal cursor contract: consume the native
        # arrays and label mapping, so changing either producer fails here.
        source = (SCRIPT.parents[1] / "crates/iroha_cli/src/taira_public_reset.rs").read_text()
        label_start = source.index("impl ExecutionStep {")
        label_end = source.index("\n    }", label_start)
        labels = dict(retry.re.findall(r'Self::(\w+)\s*=>\s*"([a-z_]+)"', source[label_start:label_end]))
        for scope, name in (("core_testnet", "CORE_TESTNET_EXECUTION_STEPS"), ("full_inrou", "FULL_INROU_EXECUTION_STEPS")):
            match = retry.re.search(r"const " + name + r": \[ExecutionStep; (\d+)\] = \[(.*?)\];", source, retry.re.S)
            self.assertIsNotNone(match, name)
            variants = retry.re.findall(r"ExecutionStep::(\w+)", match.group(2))
            self.assertEqual(len(variants), int(match.group(1)))
            self.assertEqual(len(set(variants)), len(variants))
            self.assertEqual(retry.qualification_steps(scope), tuple(labels[variant] for variant in variants))

    def test_local_arguments_require_public_bundle_and_forbid_core_stage(self):
        args = []
        for flag, count in (("--public-inputs", 1), ("--runtime-client-config", 1),
                            ("--validator-client-config", 4), ("--validator-operator-key", 1),
                            ("--onboarding-token", 1), ("--validator-unit", 4),
                            ("--native-edge-capability", 1), ("--known-hosts", 1)):
            args += [flag, *[f"/public/{flag[2:]}-{index}" for index in range(count)]]
        actual, grouped = retry.local_arguments(json.dumps(args).encode(), "core_testnet")
        self.assertEqual(actual, args)
        self.assertNotIn("--inrou-stage-dir", grouped)
        retired_edge = list(args)
        retired_edge[retired_edge.index("--native-edge-capability")] = "--edge-unit"
        with self.assertRaisesRegex(retry.RetryError, "order differs"):
            retry.local_arguments(json.dumps(retired_edge).encode(), "core_testnet")
        apply_args = actual[actual.index("--runtime-client-config"):actual.index("--validator-unit")]
        self.assertNotIn("--public-inputs", apply_args)
        full = list(args)
        at = full.index("--validator-unit")
        full[at:at] = ["--inrou-stage-dir", "/public/inrou-stage"]
        self.assertEqual(retry.local_arguments(json.dumps(full).encode(), "full_inrou")[0], full)
        for wrong, scope in ((full, "core_testnet"), (args, "full_inrou"), (args[2:], "core_testnet")):
            with self.subTest(scope=scope), self.assertRaises(retry.RetryError):
                retry.local_arguments(json.dumps(wrong).encode(), scope)

    def test_core_capacity_reads_only_artifact_metadata(self):
        inventory = {"qualification_scope": "core_testnet", "revision": {"commit": "a" * 40},
                     "inrou_canary": None, "inrou_stage_tree_sha256": None,
                     "validators": [{"slug": "taira-validator-1", "artifacts": [
                         {"role": "config", "local_path": "/private/config.toml", "size": 101}]}],
                     "edge": {"slug": "taira-edge", "artifacts": []}}
        with mock.patch.object(retry, "public_file_metadata", return_value={"path": "/private/config.toml", "bytes": 101}) as metadata, \
             mock.patch.object(retry.os, "statvfs", return_value=SimpleNamespace(f_frsize=4096, f_bsize=4096)), \
             mock.patch.object(retry, "public_record", side_effect=AssertionError("must not read any contents")), \
             mock.patch.object(retry.os, "walk", side_effect=AssertionError("must not walk Inrou stage")), \
             mock.patch.object(retry, "direct", side_effect=AssertionError("no stage path admission")):
            inputs, runtime = retry.measured_capacity_inputs(inventory, None)
            self.assertIsNone(runtime)
            self.assertEqual(inputs["stage_files"], [])
            self.assertIsNone(inputs["native_sf1_manifest_bindings"])
            metadata.assert_called_once_with("/private/config.toml")
            for stage in ("/unrelated/inrou-stage", ""):
                with self.assertRaises(retry.RetryError):
                    retry.measured_capacity_inputs(inventory, stage)
            for field in ("inrou_canary", "inrou_stage_tree_sha256"):
                wrong = dict(inventory, **{field: {}})
                with self.assertRaises(retry.RetryError):
                    retry.measured_capacity_inputs(wrong, None)

    def test_scope_capacity_cannot_substitute_inrou_or_omit_core_copies(self):
        module = {"validate_plan": capacity.validate_plan}
        retry.validate_full_capacity(module, core_plan(), "core_testnet")
        for plan, scope in ((full_plan(), "core_testnet"), (core_plan(), "full_inrou")):
            with self.subTest(scope=scope), self.assertRaises(retry.RetryError):
                retry.validate_full_capacity(module, plan, scope)
        for index in range(4):
            plan = core_plan()
            plan["allocations"].pop(index)
            with self.subTest(missing=index), self.assertRaises(retry.RetryError):
                retry.validate_full_capacity(module, plan, "core_testnet")
        plan = core_plan()
        plan["allocations"][-1]["bytes"] -= 1
        with self.assertRaises(retry.RetryError):
            retry.validate_full_capacity(module, plan, "core_testnet")

    def test_core_rollback_cursor_cannot_cross_seal_or_change_scope(self):
        inventory = {"qualification_scope": "core_testnet", "revision": {"commit": "a" * 40}, "deployment_id": "core"}
        value = {"qualification_scope": "core_testnet", "deployment_id": "core", "status": "rolled_back", "phase": "rolled_back",
                 "next_step": 10, "touched_validators": list(retry.RETIRE_SLUGS[:-1]), "edge_touched": True,
                 "edge_rollback_complete": True, "rollback_next_validator": 4, "rollback_failures": [], "recovery_intent": None}
        retry._retire_validate_terminal(inventory, value, expected_commit="a" * 40, expected_deployment="core")
        for field, wrong in (("next_step", 11), ("qualification_scope", "full_inrou"), ("qualification_scope", "inrou")):
            with self.subTest(field=field, wrong=wrong), self.assertRaises(retry._retire_RebindError):
                retry._retire_validate_terminal(inventory, dict(value, **{field: wrong}), expected_commit="a" * 40, expected_deployment="core")


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.attempts = self.root / "attempts"
        self.attempts.mkdir(mode=0o700)
        build, self.binary, self.source = artifact_receipts()
        self.inventory = {
            "revision": {"commit": build["commit"], "source_root": "/source"},
            "qualification_scope": "core_testnet",
            "inrou_canary": None, "inrou_stage_tree_sha256": None,
            "operator_public_key": OPERATOR_PUBLIC_KEY,
            "deployment_id": "retained",
            "authorization_nonce": "0" * 32,
            "next_genesis_hash": "c" * 64,
            "validators": [],
            "validator_clients": [
                {"slug": f"taira-validator-{index}",
                 "probe_origin": f"http://127.0.0.1:{18080 + index}/"}
                for index in range(1, 5)
            ],
        }
        for index in range(1, 5):
            self.inventory["validators"].append(
                {
                    "slug": f"taira-validator-{index}",
                    "systemd_unit": f"iroha3d-taira-validator-{index}.service",
                    "systemd_unit_sha256": "d" * 64,
                    "artifacts": [
                        {
                            "role": "iroha_cli",
                            "local_path": "/runtime/artifacts/bin/iroha",
                            "sha256": "b" * 64,
                        }
                    ],
                }
            )
        self.inventory["edge"] = {
            "systemd_unit_sha256": "e" * 64,
            "artifacts": [dict(self.inventory["validators"][0]["artifacts"][0])],
        }

        self.inventory=complete_previous_fixture(self.inventory)

        def record(name, value):
            path = self.root / name
            path.write_text(json.dumps(value))
            return str(path)

        args = []
        for flag, count in (
            ("--public-inputs", 1),
            ("--runtime-client-config", 1),
            ("--validator-client-config", 4),
            ("--validator-operator-key", 1),
            ("--onboarding-token", 1),
            ("--validator-unit", 4),
            ("--native-edge-capability", 1),
            ("--known-hosts", 1),
        ):
            paths = [
                f"/public-fixture/{flag.removeprefix('--')}-{i}" for i in range(count)
            ]
            if flag == "--validator-unit":
                unit_root = self.root / "initial-units"
                unit_root.mkdir(mode=0o700)
                paths = []
                for row in self.inventory["validators"]:
                    path = unit_root / row["systemd_unit"]
                    unit = UNIT_RENDERER["render"](row["slug"], "/private-fixture/" + row["slug"] + ".key").encode()
                    path.write_bytes(unit)
                    row["systemd_unit_sha256"] = retry.hashlib.sha256(unit).hexdigest()
                    paths.append(str(path))
            if flag == "--known-hosts":
                paths = ["/public-fixture/known_hosts"]
            args.extend([flag, *paths])
        reference = {"path": "/public-fixture/helper.py", "sha256": "f" * 64}
        self.plan = {
            "qualification_scope": "core_testnet",
            "runtime_root": str(self.root),
            "retired_public_imports": [],
            "attempts_root": str(self.attempts),
            "previous_inventory": record("inventory.json", self.inventory),
            "previous_terminal": str(
                self.root / "journal-v1/rolled-back" / ("a" * 64 + ".json")
            ),
            "local_args_path": record("args.json", args),
            "binary_manifest": record("binary.json", self.binary),
            "source_manifest": record("source.json", self.source),
            "trusted_public_key": record("trust.json", {"public_test_fixture": True}),
            "signing_key": "/public-fixture/signer",
            "ssh_identity": "/public-fixture/ssh_identity",
            "known_hosts": "/public-fixture/known_hosts",
            "prep_root": "/public-fixture/prep",
            "guard_support": reference,
            "unit_renderer": reference,
            "local_node": reference,
            "expected_mac": "00:00:00:00:00:00",
            "capacity_plan": core_plan(),
        }
        Path(self.plan["previous_inventory"]).write_text(json.dumps(self.inventory))
        self.request = {
            "intent": "deployment",
            "plan": self.plan,
            "binary": self.binary,
            "source": self.source,
            "binary_sha256": "1" * 64,
            "source_sha256": "2" * 64,
        }
        self.calls = []
        self.fail_phase = None
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(
            mock.patch.object(
                retry,
                "public_record",
                side_effect=lambda path, *a, **k: Path(path).read_bytes(),
            )
        )
        self.stack.enter_context(
            mock.patch.object(retry, "_retire_load_support", return_value={})
        )
        self.stack.enter_context(
            mock.patch.object(retry, "_retire_context_from_retained", return_value={})
        )
        self.stack.enter_context(
            mock.patch.object(
                retry, "_retire_locks", side_effect=lambda *a: contextlib.nullcontext()
            )
        )
        self.stack.enter_context(mock.patch.object(retry, "_retire_retained_state"))
        self.stack.enter_context(
            mock.patch.object(retry, "_retire_root_identity", return_value={})
        )
        self.stack.enter_context(
            mock.patch.object(
                retry, "_retire_apply", return_value={"guard_bytes_unchanged": True}
            )
        )
        self.stack.enter_context(mock.patch.object(retry, "emit"))
        self.stack.enter_context(mock.patch.object(retry, "_continuity_load_public_module", return_value=UNIT_RENDERER))
        self.stack.enter_context(
            mock.patch.object(retry, "run_native", side_effect=self.native)
        )
        self.stack.enter_context(
            mock.patch.object(retry, "authorize_native", side_effect=self.authorize)
        )
        self.stack.enter_context(
            mock.patch.object(retry, "_continuity_capture", side_effect=self.signer_pre)
        )
        self.stack.enter_context(
            mock.patch.object(
                retry, "_continuity_reconcile", side_effect=self.signer_post
            )
        )
        self.stack.enter_context(
            mock.patch.object(
                retry,
                "completed_execution_lock",
                side_effect=lambda *a: contextlib.nullcontext(),
            )
        )
        self.stack.enter_context(
            mock.patch.object(retry, "public_validation", return_value={"passed": True})
        )
        self.stack.enter_context(mock.patch.object(retry, "_boot_main"))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.capacity = {"evaluate": lambda _: {"passed": True, "errors": []}}

    def tearDown(self):
        self.temporary.cleanup()

    def native(
        self, argv, directory, *, phase, pass_fds=(), env=None, journal_path=None
    ):
        self.calls.append(phase)
        if phase == "apply":
            for forbidden in ("--beacon-inputs", "--beacon-validator-unit", "--beacon-genesis-manifest", "--public-inputs", "--validator-unit", "--native-edge-capability"):
                self.assertNotIn(forbidden, argv)
        self.assertNotIn("--inventory-draft",argv)
        self.assertNotIn("--http-operator-key-sha256",argv)
        self.assertNotIn("--observation-trust",argv)
        if phase in ("assemble", "apply"):
            for retired in ("--maintenance-admin-config", "--epoch-supervisor-plan", "--epoch-seed-sources", "--epoch-seed-source"):
                self.assertNotIn(retired, argv)
            self.assertEqual("--public-inputs" in argv, phase == "assemble")
            self.assertEqual("--inrou-stage-dir" in argv, self.inventory["qualification_scope"] == "full_inrou")
            self.assertIn("--validator-operator-key", argv)
            self.assertEqual(
                argv[argv.index("--validator-operator-key") + 1],
                "/public-fixture/validator-operator-key-0",
            )
        directory.mkdir(mode=0o700)
        if phase == self.fail_phase:
            self.fail_phase = None
            raise retry.RetryError("public injected native failure")
        if phase == "prepare-public-inputs":
            self.assertEqual(argv[argv.index("--localnet-dir") + 1], Path("/public-fixture/prep/network"))
            self.assertNotIn("--canary-public-key", argv)
            draft_path = Path(argv[argv.index("--intent") + 1])
            self.assertEqual(draft_path.parent.name, "assembly")
            self.assertNotIn("beacon_bootstrap", json.loads(draft_path.read_bytes()))
            output = Path(argv[argv.index("--output-dir") + 1])
            self.assertEqual(output.parent.name, "assembly")
            self.assertFalse(output.exists())
            output.mkdir(mode=0o700)
        if phase == "prepare-beacon-inputs":
            draft = json.loads(Path(argv[argv.index("--intent") + 1]).read_bytes())
            self.assertNotIn("beacon_bootstrap", draft)
            retry.write_public(Path(argv[argv.index("--output") + 1]), beacon_input_fixture(draft))
        if phase == "assemble":
            self.assertIn("--beacon-inputs", argv)
            self.assertIn("--beacon-validator-unit", argv)
            draft = json.loads(
                Path(argv[argv.index("--intent") + 1]).read_bytes()
            )
            self.assertEqual(draft,expected_topology(self.inventory,directory.parent.parent.name,draft["authorization_nonce"]))
            assembled=copy.deepcopy(self.inventory)
            assembled["deployment_id"]=draft["deployment_id"]
            assembled["authorization_nonce"]=draft["authorization_nonce"]
            retry.write_public(Path(argv[argv.index("--output") + 1]),assembled)
        if phase == "preflight":
            inventory_path = Path(argv[argv.index("--inventory") + 1])
            inventory = json.loads(inventory_path.read_bytes())
            retry.write_public(
                directory / "stdout",
                {
                    "schema": "iroha.taira.public-reset.report.v1",
                    "command": "preflight",
                    "status": "ok",
                    "qualification_scope": inventory["qualification_scope"],
                    "deployment_id": inventory["deployment_id"],
                    "revision": inventory["revision"]["commit"],
                    "inventory_sha256": retry.hashlib.sha256(
                        inventory_path.read_bytes()
                    ).hexdigest(),
                    "authorization_sha256": "9" * 64,
                },
            )
        if phase == "apply":
            attempt = directory.parent.parent
            inventory = json.loads((attempt / "assembly/inventory.json").read_bytes())
            frontier = json.loads((attempt / "apply-started.json").read_bytes())
            completed = {
                "schema": "iroha.taira.public-reset.journal.v1",
                "deployment_id": inventory["deployment_id"],
                "qualification_scope": inventory["qualification_scope"],
                "inventory_sha256": frontier["inventory_sha256"],
                "authorization_sha256": frontier["authorization_sha256"],
                "authorization_nonce": inventory["authorization_nonce"],
                "status": "completed",
                "phase": "completed",
                "next_step": len(retry.qualification_steps(inventory["qualification_scope"])),
                "recovery_intent": None,
                "touched_validators": [row["slug"] for row in inventory["validators"]],
                "edge_touched": True,
                "edge_rollback_complete": False,
                "rollback_next_validator": 0,
                "failure_summary": "",
                "rollback_failures": [],
            }
            for kind, value in (
                ("completed", completed),
                (
                    "deployment-proven",
                    dict(completed, status="sealing", phase="seal", next_step=len(retry.qualification_steps(inventory["qualification_scope"])) - 2),
                ),
            ):
                target = self.root / "journal-v1" / kind
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                retry.write_public(target / ("9" * 64 + ".json"), value)
        return {"phase": phase, "exit_code": 0}

    def authorize(self, cli, assembly, args, plan, directory):
        self.calls.append("authorize")
        self.assertEqual(args, json.loads((assembly / "native-assembly-args.json").read_bytes()))
        self.assertNotIn("--beacon-inputs", json.loads((assembly / "native-local-args.json").read_bytes()))
        retry.write_public(
            assembly / "authorization.json", {"public_signature_fixture": True}
        )

    def signer_pre(self, args):
        retry.CONTINUITY_OUT.mkdir(mode=0o700)
        retry.write_public(
            retry.CONTINUITY_OUT / "prestart.json", {"public_fixture": True}
        )

    def signer_post(self, args):
        if self.fail_phase == "signer-post":
            self.fail_phase = None
            retry.write_public(
                retry.CONTINUITY_OUT / "startup-evidence.json",
                {"partial_public_observation": True},
            )
            raise retry.RetryError("injected postcondition failure")
        retry.write_public(
            retry.CONTINUITY_OUT / "signer-authority-receipt.json",
            {"public_fixture": True},
        )

    def test_missing_candidate_origin_stops_before_retirement_or_native_calls(self):
        del self.inventory["validator_clients"][0]["probe_origin"]
        Path(self.plan["previous_inventory"]).write_text(json.dumps(self.inventory))
        with self.assertRaisesRegex(retry.RetryError, "candidate probe origin"):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        retry._retire_retained_state.assert_not_called()
        retry._retire_apply.assert_not_called()
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.attempts.iterdir()), [])

    def test_missing_operator_identity_stops_before_retirement_or_native_calls(self):
        del self.inventory["operator_public_key"]
        Path(self.plan["previous_inventory"]).write_text(json.dumps(self.inventory))
        with self.assertRaisesRegex(retry.RetryError, "operator public key"):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        retry._retire_retained_state.assert_not_called()
        retry._retire_apply.assert_not_called()
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.attempts.iterdir()), [])

    def test_complete_workflow_submits_one_apply_after_durable_frontier(self):
        result = retry.guest_locked(self.request, self.capacity, self.attempts)
        attempt = Path(result["private_attempt"])
        self.assertTrue(result["passed"])
        self.assertTrue((attempt / "apply-started.json").exists())
        self.assertEqual(self.calls, ["prepare-public-inputs", "prepare-beacon-inputs", "assemble", "authorize", "preflight", "apply"])
        static=json.loads((attempt/"assembly/native-local-args.json").read_bytes())
        retained=json.loads((attempt/"assembly/native-retained-args.json").read_bytes())
        self.assertEqual(static, retained)
        derived = json.loads((attempt / "assembly/native-assembly-args.json").read_bytes())
        self.assertEqual(derived[derived.index("--public-inputs") + 1], str(attempt / "assembly/public-inputs"))
        self.assertEqual(result["completed"], list(retry.PHASES))
        self.assertEqual(result["qualification_scope"], "core_testnet")

    def test_beacon_preparation_failure_stops_before_authorization_and_keeps_same_nonce(self):
        self.fail_phase = "prepare-beacon-inputs"
        with self.assertRaises(retry.RetryError):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        pointer = json.loads((self.attempts / "latest.json").read_bytes())
        attempt = self.attempts / pointer["attempt_id"]
        operation = (attempt / "operation.json").read_bytes()
        self.assertEqual(json.loads((attempt / "failure.json").read_bytes())["phase"], "prepare-beacon-inputs")
        self.assertEqual(self.calls, ["prepare-public-inputs", "prepare-beacon-inputs"])
        self.assertFalse((attempt / "apply-started.json").exists())
        result = retry.guest_locked(self.request, self.capacity, self.attempts)
        self.assertEqual(result["attempt_id"], pointer["attempt_id"])
        self.assertEqual((attempt / "operation.json").read_bytes(), operation)
        self.assertEqual(self.calls.count("apply"), 1)
        self.assertEqual(len(list(attempt.glob("preapply-evidence-*"))), 1)








    def test_python_preparation_never_opens_private_runtime_inputs(self):
        retry.guest_locked(self.request, self.capacity, self.attempts)
        args = json.loads(Path(self.plan["local_args_path"]).read_bytes())
        _, grouped = retry.local_arguments(json.dumps(args).encode(), "core_testnet")
        private_paths = {path for flag in (
            "--runtime-client-config",
            "--validator-client-config", "--validator-operator-key", "--onboarding-token")
            for path in grouped[flag]}
        reads = {str(call.args[0]) for call in retry.public_record.call_args_list}
        self.assertTrue(reads)
        self.assertFalse(reads & private_paths)


    def test_retired_supervisor_intent_stops_before_retirement_and_native_calls(self):
        self.plan["epoch_supervisor"] = {"retired": True}
        with self.assertRaises(retry.RetryError):retry.guest_locked(self.request,self.capacity,self.attempts)
        retry._retire_retained_state.assert_not_called()
        retry._retire_apply.assert_not_called()
        self.assertEqual(self.calls,[])

    def test_fresh_native_public_bundle_failure_cannot_reuse_retained_bundle(self):
        self.fail_phase = "prepare-public-inputs"
        with self.assertRaises(retry.RetryError):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        self.assertEqual(self.calls, ["prepare-public-inputs"])
        pointer = json.loads((self.attempts / "latest.json").read_bytes())
        attempt = self.attempts / pointer["attempt_id"]
        self.assertFalse((attempt / "assembly/native-assembly-args.json").exists())
        self.assertFalse((attempt / "apply-started.json").exists())

    def test_missing_scope_stops_before_retirement_or_native_calls(self):
        del self.inventory["qualification_scope"]
        Path(self.plan["previous_inventory"]).write_text(json.dumps(self.inventory))
        with self.assertRaisesRegex(retry.RetryError, "qualification scope"):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        retry._retire_retained_state.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_inrou_workflow_preserves_its_explicit_scope(self):
        self.inventory["qualification_scope"] = "full_inrou"
        self.inventory["inrou_canary"] = {"stage_tree_sha256": "a" * 64}
        self.inventory["inrou_stage_tree_sha256"] = "a" * 64
        self.plan["qualification_scope"] = "full_inrou"
        self.plan["capacity_plan"] = full_plan()
        args_path = Path(self.plan["local_args_path"])
        args = json.loads(args_path.read_bytes())
        at = args.index("--validator-unit")
        args[at:at] = ["--inrou-stage-dir", "/public-fixture/inrou-stage"]
        args_path.write_text(json.dumps(args))
        Path(self.plan["previous_inventory"]).write_text(json.dumps(self.inventory))
        result = retry.guest_locked(self.request, self.capacity, self.attempts)
        self.assertEqual(result["qualification_scope"], "full_inrou")
        self.assertEqual(self.calls.count("apply"), 1)

    def test_completed_scope_cannot_be_upgraded_during_recovery(self):
        self.fail_phase = "signer-post"
        with self.assertRaises(retry.RetryError):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        target = self.root / "journal-v1/completed" / ("9" * 64 + ".json")
        value = json.loads(target.read_bytes())
        value["qualification_scope"] = "full_inrou"
        target.write_text(json.dumps(value))
        with self.assertRaisesRegex(retry.RetryError, "exact completed deployment"):
            retry.previous_attempt(self.plan)
        self.assertEqual(self.calls.count("apply"), 1)

    def test_preapply_failure_resumes_same_identity_and_preserves_evidence(self):
        self.fail_phase = "assemble"
        with self.assertRaises(retry.RetryError):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        pointer = json.loads((self.attempts / "latest.json").read_bytes())
        attempt = self.attempts / pointer["attempt_id"]
        operation = (attempt / "operation.json").read_bytes()
        self.assertFalse((attempt / "apply-started.json").exists())
        result = retry.guest_locked(self.request, self.capacity, self.attempts)
        self.assertEqual(result["attempt_id"], pointer["attempt_id"])
        self.assertEqual((attempt / "operation.json").read_bytes(), operation)
        self.assertEqual(len(list(attempt.glob("preapply-evidence-*"))), 1)
        self.assertEqual(self.calls.count("apply"), 1)

    def test_completed_apply_resumes_postconditions_without_new_nonce_or_native_calls(
        self,
    ):
        self.fail_phase = "signer-post"
        with self.assertRaises(retry.RetryError):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        pointer = json.loads((self.attempts / "latest.json").read_bytes())
        attempt = self.attempts / pointer["attempt_id"]
        operation = (attempt / "operation.json").read_bytes()
        native_calls = list(self.calls)
        self.plan["capacity_plan"] = retry.postcondition_capacity_plans(
            str(self.root), "/backing"
        )["guest_plan"]
        result = retry.guest_locked(self.request, self.capacity, self.attempts)
        self.assertTrue(result["postconditions_only"])
        self.assertEqual(result["attempt_id"], pointer["attempt_id"])
        self.assertEqual((attempt / "operation.json").read_bytes(), operation)
        self.assertEqual(self.calls, native_calls)
        self.assertEqual(retry._retire_apply.call_count, 1)
        self.assertEqual(len(list(attempt.glob("postcondition-evidence-*"))), 1)
        self.assertTrue((attempt / "signer-continuity/prestart.json").exists())

    def test_completed_receipt_mismatch_blocks_postcondition_capacity_exemption(self):
        self.fail_phase = "signer-post"
        with self.assertRaises(retry.RetryError):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        target = self.root / "journal-v1/completed" / ("9" * 64 + ".json")
        value = json.loads(target.read_bytes())
        value["inventory_sha256"] = "0" * 64
        target.write_text(json.dumps(value))
        with self.assertRaisesRegex(retry.RetryError, "exact completed deployment"):
            retry.previous_attempt(self.plan)
        self.assertEqual(self.calls.count("apply"), 1)

    def test_apply_frontier_blocks_resubmission_without_actual_terminal(self):
        self.fail_phase = "apply"
        with self.assertRaises(retry.RetryError):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        with self.assertRaisesRegex(retry.RetryError, "pending mutation"):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        self.assertEqual(self.calls.count("apply"), 1)


    def test_retirement_returns_without_native_apply_and_resumes_same_attempt(self):
        self.request["intent"] = "retirement"
        first = retry.guest_locked(self.request, self.capacity, self.attempts)
        attempt = self.attempts / first["attempt_id"]
        self.assertEqual(first["schema"], "taira.retry-retirement.v1")
        self.assertFalse(first["native_apply_started"])
        self.assertEqual(self.calls, [])
        self.assertFalse((attempt / "apply-started.json").exists())
        self.assertFalse((attempt / "result.json").exists())
        self.assertTrue((attempt / "retirement-ready.json").exists())
        second = retry.guest_locked(self.request, self.capacity, self.attempts)
        self.assertEqual(second, first)
        self.request.update(intent="deployment", retirement_attempt_id=first["attempt_id"])
        result = retry.guest_locked(self.request, self.capacity, self.attempts)
        self.assertEqual(result["attempt_id"], first["attempt_id"])
        self.assertEqual(self.calls.count("apply"), 1)

    def test_changed_retirement_attempt_stops_before_any_native_call(self):
        self.request["intent"] = "retirement"
        retry.guest_locked(self.request, self.capacity, self.attempts)
        self.request.update(intent="deployment", retirement_attempt_id="retry-1000000000000000-deadbeef")
        with self.assertRaisesRegex(retry.RetryError, "retired attempt changed"):
            retry.guest_locked(self.request, self.capacity, self.attempts)
        self.assertEqual(self.calls, [])

    def test_retirement_capacity_cannot_authorize_deployment(self):
        bounded = retry.retirement_capacity_plans(self.plan["runtime_root"], "/backing", self.binary)
        self.request.update(intent="retirement", backing_path="/backing")
        self.plan["capacity_plan"] = bounded["guest_plan"]
        retry.validate_execution_capacity(self.request, vars(capacity), False, None)
        self.request["intent"] = "deployment"
        with self.assertRaises(retry.RetryError):
            retry.validate_execution_capacity(self.request, vars(capacity), False, None)
        self.request["intent"] = "retirement"
        self.plan["capacity_plan"]["allocations"][0]["bytes"] -= 1
        with self.assertRaisesRegex(retry.RetryError, "exact bounded"):
            retry.validate_execution_capacity(self.request, vars(capacity), False, None)

    def test_execution_intent_and_completed_retirement_are_rejected(self):
        for invalid in (None, "", "apply", True):
            with self.assertRaisesRegex(retry.RetryError, "explicit retry"):
                retry.execution_intent({"intent": invalid})
        self.request.update(intent="retirement", backing_path="/backing")
        with self.assertRaisesRegex(retry.RetryError, "cannot be retired"):
            retry.validate_execution_capacity(self.request, vars(capacity), True, "completed")



class PublicProbePrerequisiteTests(unittest.TestCase):
    def test_missing_curl_is_rejected(self):
        with mock.patch.object(retry.Path, "is_file", return_value=False), \
             mock.patch.object(retry.os, "access") as access:
            with self.assertRaisesRegex(retry.RetryError, "/usr/bin/curl is unavailable"):
                retry.require_public_probe_curl()
        access.assert_not_called()

    def test_nonexecutable_curl_is_rejected(self):
        with mock.patch.object(retry.Path, "is_file", return_value=True), \
             mock.patch.object(retry.os, "access", return_value=False) as access:
            with self.assertRaisesRegex(retry.RetryError, "/usr/bin/curl is unavailable"):
                retry.require_public_probe_curl()
        access.assert_called_once_with("/usr/bin/curl", os.X_OK)

    def test_executable_curl_is_accepted(self):
        with mock.patch.object(retry.Path, "is_file", return_value=True), \
             mock.patch.object(retry.os, "access", return_value=True) as access:
            retry.require_public_probe_curl()
        access.assert_called_once_with("/usr/bin/curl", os.X_OK)

    def test_guest_entrypoints_check_curl_before_work_or_output_creation(self):
        mac = "aa:bb:cc:dd:ee:ff"
        request = {"intent": "retirement", "plan": {"expected_mac": mac}}
        for entry in (retry.guest_admit, retry.guest_run):
            with self.subTest(entry=entry.__name__), contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(retry.os, "geteuid", return_value=0))
                stack.enter_context(mock.patch.object(retry.sys, "platform", "linux"))
                stack.enter_context(mock.patch.object(retry.platform, "machine", return_value="aarch64"))
                stack.enter_context(mock.patch.object(retry.Path, "glob", return_value=[SimpleNamespace(read_text=lambda: mac)]))
                stack.enter_context(mock.patch.object(retry.Path, "is_file", return_value=False))
                untouched = [stack.enter_context(mock.patch.object(owner, name)) for owner, name in (
                    (retry, "direct"), (retry, "capacity_module"),
                    (retry.Path, "mkdir"), (retry.os, "umask"),
                )]
                with self.assertRaisesRegex(retry.RetryError, "/usr/bin/curl is unavailable"):
                    entry(request)
                for operation in untouched:
                    operation.assert_not_called()

    def test_guest_identity_is_checked_before_curl(self):
        request = {"intent": "retirement", "plan": {"expected_mac": "aa:bb:cc:dd:ee:ff"}}
        for entry in (retry.guest_admit, retry.guest_run):
            with self.subTest(entry=entry.__name__), contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(retry.os, "geteuid", return_value=0))
                stack.enter_context(mock.patch.object(retry.sys, "platform", "linux"))
                stack.enter_context(mock.patch.object(retry.platform, "machine", return_value="aarch64"))
                stack.enter_context(mock.patch.object(retry.Path, "glob", return_value=[]))
                guard = stack.enter_context(mock.patch.object(retry, "require_public_probe_curl"))
                with self.assertRaisesRegex(retry.RetryError, "guest identity differs"):
                    entry(request)
                guard.assert_not_called()


class BootPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.prior = {
            "path": "/etc/systemd/system/multi-user.target.wants/nginx.service",
            "target": "/usr/lib/systemd/system/nginx.service",
            "uid": 0,
            "metadata": {"inode": 123},
        }
        self.canonical = dict(self.prior, target="../nginx.service")
        self.before = {
            "MainPID": "42", "InvocationID": "same-invocation",
            "ActiveEnterTimestampMonotonic": "1234", "UnitFileState": "enabled",
            "FragmentPath": "/etc/systemd/system/nginx.service",
        }
        self.fragment = {"inode": 456}
        self.events = []
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.link = self.stack.enter_context(mock.patch.object(
            retry, "_boot_link", side_effect=[self.prior, self.canonical]
        ))
        self.state = self.stack.enter_context(mock.patch.object(
            retry, "_boot_state", side_effect=[self.before, self.before]
        ))
        self.fragment_read = self.stack.enter_context(mock.patch.object(
            retry, "_boot_fragment", return_value=self.fragment
        ))
        self.stack.enter_context(mock.patch.object(
            retry, "_boot_write", side_effect=lambda name, value: self.events.append((name, value))
        ))
        def run(argv, **kwargs):
            self.events.append(("command", argv))
            return subprocess.CompletedProcess(argv, 0)
        self.run = self.stack.enter_context(mock.patch.object(retry.subprocess, "run", side_effect=run))

    def repair(self):
        retry._boot_reenable_nginx(self.prior, self.before, "a" * 64, self.fragment)

    def test_vendor_nginx_repair_records_intent_then_reenables_exact_fragment(self):
        self.repair()
        self.assertEqual([name for name, _ in self.events], [
            "reenable-intent.json", "command", "reenable-result.json"
        ])
        self.assertEqual(self.events[0][1]["prior_link"], self.prior)
        self.assertEqual(self.events[0][1]["fragment_sha256"], "a" * 64)
        self.assertIs(self.events[0][1]["used_now"], False)
        self.assertEqual(self.events[1][1], [
            "/usr/bin/systemctl", "reenable", "/etc/systemd/system/nginx.service"
        ])
        self.assertEqual(self.run.call_args.kwargs["timeout"], 45)
        self.assertEqual(self.events[2][1], {"exit_code": 0, "units": ["nginx.service"], "used_now": False})

    def test_only_exact_observed_vendor_link_can_be_repaired(self):
        for target in ("/lib/systemd/system/nginx.service", "/tmp/nginx.service", "../nginx.service"):
            with self.subTest(target=target):
                self.prior["target"] = target
                with self.assertRaisesRegex(RuntimeError, "unexpected nginx boot link repair"):
                    self.repair()
        self.assertEqual(self.events, [])
        self.run.assert_not_called()

    def test_vendor_target_remains_invalid_as_final_link(self):
        self.link.side_effect = [self.prior, self.prior]
        with self.assertRaisesRegex(RuntimeError, "enabled unit link points elsewhere"):
            self.repair()
        self.assertEqual(self.events[-1][0], "reenable-result.json")

    def test_repair_rejects_identity_change_before_mutation(self):
        self.link.side_effect = [dict(self.prior, metadata={"inode": 999})]
        with self.assertRaisesRegex(RuntimeError, "nginx boot repair identity changed"):
            self.repair()
        self.run.assert_not_called()
        self.assertEqual([name for name, _ in self.events], ["reenable-intent.json"])

    def test_repair_rejects_process_or_fragment_change_after_mutation(self):
        for field in ("MainPID", "InvocationID", "ActiveEnterTimestampMonotonic", "FragmentPath"):
            with self.subTest(field=field):
                self.link.side_effect = [self.prior]
                self.state.side_effect = [self.before, dict(self.before, **{field: "changed"})]
                with self.assertRaisesRegex(RuntimeError, "live unit process or loaded fragment changed"):
                    self.repair()
        self.link.side_effect = [self.prior]
        self.state.side_effect = [self.before, self.before]
        self.fragment_read.side_effect = [self.fragment, {"inode": 999}]
        with self.assertRaisesRegex(RuntimeError, "signed fragment bytes or metadata changed"):
            self.repair()

    def test_failed_reenable_preserves_intent_and_result(self):
        self.run.side_effect = lambda argv, **kwargs: subprocess.CompletedProcess(argv, 1)
        with self.assertRaisesRegex(RuntimeError, "systemctl reenable failed; preserve private evidence"):
            self.repair()
        self.assertEqual([name for name, _ in self.events], ["reenable-intent.json", "reenable-result.json"])
        self.assertEqual(self.events[-1][1]["exit_code"], 1)


class MainOrderTests(unittest.TestCase):
    def run_main(self, *, completed=False, backing_pass=True, retirement_schema=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            build, binary, source = artifact_receipts()
            plan = {
                "guest": {"runtime_root": "/runtime", "expected_mac": "00:00:00:00:00:00", "retired_public_imports": []},
                "guest_ssh": {"argv": ["approved-guest"]},
                "backing_ssh": {"argv": ["approved-backing"]},
                "backing_path": "/backing",
                "binary_transfer": {"sha256": "1" * 64},
                "source_transfer": {"sha256": "2" * 64},
            }
            planpath = root / "plan.json"
            attempt_id = "retry-1000000000000000-deadbeef"
            state = {"retired": False}
            calls = []
            def payload(_source, function, argument, *, print_result=False):
                return {"function": function, "request": copy.deepcopy(argument)}
            def remote(_argv, wire, _output, phase):
                calls.append((phase, wire["function"]))
                request = wire["request"]
                if wire["function"] == "guest_admit":
                    derived = dict(request["plan"], attempts_root="/runtime/retry-v1", capacity_plan={"fixture": request["intent"]})
                    return {"schema": "taira.retry-admission.v1", "commit": build["commit"],
                            "intent": request["intent"], "plan": derived,
                            "backing_plan": {"fixture": request["intent"]},
                            "postconditions_only": completed,
                            "pending_attempt_id": attempt_id if state["retired"] or completed else None}
                if wire["function"] == "evaluate":
                    return {"passed": backing_pass if phase == "backing-capacity" else True}
                if request["intent"] == "retirement":
                    state["retired"] = True
                    return {"schema": retirement_schema or "taira.retry-retirement.v1",
                            "intent": "retirement", "passed": True, "commit": build["commit"],
                            "attempt_id": attempt_id, "native_apply_started": False,
                            "binary_manifest_sha256": request["binary_sha256"],
                            "source_manifest_sha256": request["source_sha256"],
                            "custody_plan_sha256": retry.custody_plan_digest(request["plan"])}
                self.assertEqual(request["intent"], "deployment")
                if not completed:
                    self.assertEqual(request["retirement_attempt_id"], attempt_id)
                return {"schema": retry.RESULT_SCHEMA, "passed": True, "commit": build["commit"]}
            argv = ["taira_retry.py", "--plan", str(planpath), "--output-root", str(root)]
            records = {"preparation": build, "binary_transfer": binary, "source_transfer": source}
            with mock.patch.object(retry.sys, "argv", argv), \
                 mock.patch.object(retry, "public_record", side_effect=lambda path, *a, **k: json.dumps(plan).encode() if Path(path) == planpath else b"# public source fixture"), \
                 mock.patch.object(retry, "validate_plan", return_value=(build["commit"], records)), \
                 mock.patch.object(retry, "remote_payload", side_effect=payload), \
                 mock.patch.object(retry, "remote_command", side_effect=remote), \
                 contextlib.redirect_stdout(io.StringIO()):
                try:
                    retry.main()
                except retry.RetryError:
                    return calls, False
            return calls, True

    def test_prune_precedes_fresh_guest_and_backing_admission(self):
        calls, passed = self.run_main()
        self.assertTrue(passed)
        self.assertEqual([phase for phase, _ in calls], [
            "retirement-admission", "retirement-backing-capacity", "retirement",
            "admission", "backing-capacity", "native-retry"])

    def test_failed_fresh_backing_admission_never_runs_native_deployment(self):
        calls, passed = self.run_main(backing_pass=False)
        self.assertFalse(passed)
        self.assertEqual(calls[-1][0], "backing-capacity")
        self.assertNotIn("native-retry", [phase for phase, _ in calls])

    def test_retirement_receipt_cannot_be_a_deployment_success_receipt(self):
        calls, passed = self.run_main(retirement_schema=retry.RESULT_SCHEMA)
        self.assertFalse(passed)
        self.assertEqual(calls[-1][0], "retirement")

    def test_completed_deployment_skips_retirement_and_keeps_capacity_checks(self):
        calls, passed = self.run_main(completed=True)
        self.assertTrue(passed)
        self.assertEqual([phase for phase, _ in calls], [
            "retirement-admission", "admission", "backing-capacity", "native-retry"])



class RetiredPublicPruneTests(unittest.TestCase):
    def setUp(self):
        # Parent custody is exercised by the real helper. Keep fixtures under
        # this owner-controlled checkout instead of world-writable /tmp.
        self.tmp = tempfile.TemporaryDirectory(dir=SCRIPT.parent)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.runtime = self.root / 'runtime'
        self.work = self.runtime / 'retry/retirement'
        self.work.mkdir(parents=True, mode=0o700)
        self.prep = self.runtime / 'prep'
        self.bins = self.runtime / 'original/bin'
        self.nonce = '1' * 32
        self.invpath = self.runtime / 'inventory.json'
        self.context = {'commit': 'a' * 40, 'inventory_sha256': 'b' * 64,
                        'terminal_sha256': 'c' * 64, 'authorization_sha256': 'd' * 64,
                        'nonce': self.nonce, 'uploads': [],
                        'coordination_relative': 'hosts/' + 'e' * 64}
        roles = [('iroha_cli', 'iroha'), ('iroha3d', 'iroha3d_taira'),
                 ('sorafs_node', 'sorafs-node'), ('kagami', 'kagami')]
        for _, name in roles:
            self.file(self.bins / name, b'public executable', 0o755)
        self.inventory = {'qualification_scope': 'full_inrou', 'validators': [], 'inrou_canary': {}}
        for index, role in enumerate(('bundle', 'guest', 'discovery'), 1):
            content = ('public ' + role + ' manifest').encode()
            self.inventory['inrou_canary'][role + '_manifest_digest_hex'] = str(index) * 64
            self.inventory['inrou_canary'][role + '_manifest_sha256'] = retry._retire_digest(content)
        self.targets = []
        for slug in retry.RETIRE_SLUGS:
            artifacts = [{'role': role, 'local_path': str(self.bins / name),
                          'size': len(b'public executable')} for role, name in
                         (roles[:1] if slug == 'taira-edge' else roles)]
            host = {'slug': slug, 'artifacts': artifacts,
                    'endpoint': {'host_identity_sha256': 'e' * 64}}
            if slug == 'taira-edge': self.inventory['edge'] = host
            else: self.inventory['validators'].append(host)
            upload = self.work / 'uploads' / slug
            self.context['uploads'].append({'slug': slug, 'archive': str(upload)})
            self.file(upload / 'artifact-config', b'PRIVATE CONFIG PRESERVE', 0o600)
            for role, name in (roles[:1] if slug == 'taira-edge' else roles):
                staged_name = 'iroha' if role == 'iroha_cli' else 'artifact-' + role
                for path, mode in [(upload / staged_name, 0o755),
                    (self.runtime / 'journal-v1/staged-artifacts-v1' / ('b' * 64) /
                     slug / self.nonce / staged_name, 0o500 if role in ('iroha_cli', 'iroha3d') else 0o400)]:
                    self.file(path, b'public executable', mode); self.targets.append(path)
                if slug != 'taira-edge':
                    release = self.work / 'retired-control' / slug / 'rollback' / self.nonce / 'first-release.after'
                    self.marker(release, slug, 'release')
                    path = release / 'bin' / name
                    self.file(path, b'public executable', 0o755); self.targets.append(path)
                    self.file(release / 'bin/private-config.toml', b'PRIVATE PRESERVE', 0o600)
            if slug != 'taira-edge':
                fresh = self.work / 'retired-control' / slug / 'rollback' / self.nonce / 'fresh-state.after'
                self.marker(fresh, slug, 'fresh_state')
                store = fresh / 'sorafs-data'; self.marker(store, slug, 'fresh_state_entry')
                self.file(store / '.storage.lock', b'', 0o600)
                for index, role in enumerate(('bundle', 'guest', 'discovery'), 1):
                    manifest = store / 'manifests' / (str(index) * 64)
                    self.file(manifest / 'manifest.to', ('public ' + role + ' manifest').encode(), 0o644)
                    self.file(manifest / 'metadata.to', b'PRIVATE METADATA PRESERVE', 0o600)
                    chunk = manifest / 'chunks/chunk_00000.bin'
                    self.file(chunk, b'public chunk', 0o600); self.targets.append(chunk)
                self.file(store / 'manifests' / ('f' * 64) / 'chunks/chunk_00000.bin', b'OTHER DATA PRESERVE', 0o600)
                self.file(store / '.ingest-staging/unknown/chunk_00000.bin', b'UNADMITTED PRESERVE', 0o600)
        for name in ('rootfs.ext4', 'vmlinux', 'initrd.img'):
            self.file(self.prep / 'inrou-stage/payloads/guest/aarch64' / name, b'public guest', 0o600)
            path = self.runtime / 'journal-v1/runtime-stage-v1' / ('d' * 64) / 'payloads/guest/aarch64' / name
            self.file(path, b'public guest', 0o400); self.targets.append(path)
        # The retained inventory digest is over its actual native bytes.
        self.file(self.invpath, json.dumps(self.inventory, indent=2).encode(), 0o600)
        prior_digest = self.context['inventory_sha256']
        self.context['inventory_sha256'] = retry._retire_digest(self.invpath.read_bytes())
        staged = self.runtime / 'journal-v1/staged-artifacts-v1'
        (staged / prior_digest).rename(staged / self.context['inventory_sha256'])
        self.targets = [Path(str(path).replace('/' + prior_digest + '/', '/' + self.context['inventory_sha256'] + '/')) for path in self.targets]
        # Update generated markers to the final actual inventory binding.
        for path in self.work.rglob('.public-reset-generated-v1.json'):
            value = json.loads(path.read_bytes()); value['inventory_sha256'] = self.context['inventory_sha256']
            path.write_text(json.dumps(value))
        self.result = {'published': True, 'control_archived': True, 'native_rollback_completed': True,
                       'inventory_sha256': self.context['inventory_sha256'],
                       'terminal_sha256': self.context['terminal_sha256'],
                       'retired_control_path': str(self.work / 'retired-control')}
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        for name, value in [('RETIRE_RUNTIME', self.runtime), ('RETIRE_WORK', self.work),
                            ('RETIRE_BINS', self.bins), ('CONTINUITY_PREP', self.prep),
                            ('RETIRE_INVENTORY_PATH', self.invpath)]:
            self.stack.enter_context(mock.patch.object(retry, name, value))
        def private_record(g, path, **kwargs):
            # Model the support helper's exact private-file mode, so this fixture
            # cannot silently admit public manifests through a private reader.
            self.assertEqual(Path(path).stat().st_mode & 0o7777, 0o600)
            return retry.public_record(path, owner=os.geteuid(), private=True, **kwargs)
        self.stack.enter_context(mock.patch.object(retry, '_retire_read_public', side_effect=private_record))
        self.stack.enter_context(mock.patch.object(retry, '_retire_retained_state'))
        self.stack.enter_context(mock.patch.object(retry, '_retire_live_references', return_value={'passed': True}))
        self.reclaim = self.stack.enter_context(mock.patch.object(retry.subprocess, 'run', return_value=SimpleNamespace(returncode=0)))
        self.guard = {'fresh_write': lambda path,data,mode: self.file(path,data,mode), 'sync_directory': lambda path: None}

    def file(self, path, data, mode):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data); path.chmod(mode)

    def marker(self, path, slug, kind):
        self.file(path / '.public-reset-generated-v1.json', json.dumps({
            'schema': 'iroha.taira.public-reset.generated-path.v1', 'kind': kind,
            'host_slug': slug, 'inventory_sha256': self.context['inventory_sha256'],
            'authorization_nonce': self.nonce, 'revision': self.context['commit']}).encode(), 0o600)

    def prune(self):
        return retry._retire_prune_public(self.guard, self.context, self.result)

    def archived_host_stage(self):
        root = (self.work / 'retired-control' / self.context['coordination_relative']
                / 'inrou-stage-v1' / self.nonce)
        self.marker(root, retry.RETIRE_SLUGS[0], 'inrou_stage')
        root.chmod(0o700)
        for name in ('rootfs.ext4', 'vmlinux', 'initrd.img'):
            self.file(root / 'payloads/guest/aarch64' / name, b'public guest', 0o400)
        self.file(root / 'payloads/guest/aarch64/private-config', b'PRIVATE PRESERVE', 0o600)
        self.file(root / 'manifests/aarch64.to', b'PUBLIC METADATA PRESERVE', 0o400)
        return root

    def test_core_prune_does_not_inspect_unrelated_stage_or_guest_store(self):
        inventory = dict(self.inventory, qualification_scope="core_testnet", inrou_canary=None, inrou_stage_tree_sha256=None)
        original_info = retry._retire_prune_info
        original_marker = retry._retire_prune_marker
        original_exists = Path.exists
        original_lexists = retry.os.path.lexists
        def admitted(path):
            value = str(path)
            self.assertFalse(any(part in value for part in ("inrou-stage", "runtime-stage", "fresh-state.after", "sorafs-data")), value)
        def info(path, **kwargs):
            admitted(path)
            return original_info(path, **kwargs)
        def marker(g, path, context, slug, kind):
            admitted(path)
            return original_marker(g, path, context, slug, kind)
        def exists(path):
            admitted(path)
            return original_exists(path)
        def lexists(path):
            admitted(path)
            return original_lexists(path)
        with mock.patch.object(retry, "_retire_prune_info", side_effect=info), \
             mock.patch.object(retry, "_retire_prune_marker", side_effect=marker), \
             mock.patch.object(Path, "exists", exists), \
             mock.patch.object(retry.os.path, "lexists", side_effect=lexists):
            exact, chunks, protected, stores = retry._retire_prune_scopes(self.guard, self.context, inventory)
        self.assertEqual((chunks, stores), (set(), []))
        self.assertEqual(len(exact), 50)
        for path in (*exact, *protected):
            admitted(path)

    def test_archived_host_stage_three_payloads_are_pruned_and_resume_preserves_siblings(self):
        root = self.archived_host_stage()
        expected = {root / 'payloads/guest/aarch64' / name
                    for name in ('rootfs.ext4', 'vmlinux', 'initrd.img')}
        keep = {path: path.read_bytes() for path in root.rglob('*')
                if path.is_file() and path not in expected}
        first = self.prune()
        self.assertEqual(first['file_count'], 68)
        self.assertEqual(first, self.prune())
        self.assertTrue(all(not path.exists() for path in expected))
        self.assertTrue(all(path.read_bytes() == raw for path, raw in keep.items()))
        self.assertTrue(all((self.prep / 'inrou-stage/payloads/guest/aarch64' / path.name).exists()
                            for path in expected))

    def test_archived_host_stage_requires_exact_carrier_and_nonce(self):
        root = self.archived_host_stage()
        marker = root / '.public-reset-generated-v1.json'
        original = json.loads(marker.read_bytes())
        for key, wrong in [('host_slug', retry.RETIRE_SLUGS[1]), ('authorization_nonce', '0' * 32),
                           ('kind', 'release')]:
            changed = {**original, key: wrong}
            marker.write_text(json.dumps(changed))
            with self.subTest(key=key), self.assertRaisesRegex(retry._retire_RebindError, 'closed attempt'):
                self.prune()
            self.assertFalse((self.work / 'public-prune-intent.json').exists())
        marker.write_text(json.dumps(original))
        self.context['coordination_relative'] = 'hosts/' + 'f' * 64
        with self.assertRaisesRegex(retry._retire_RebindError, 'coordination differs'):
            self.prune()

    def test_archived_host_stage_rejects_wrong_copy_mode_and_symlink(self):
        root = self.archived_host_stage()
        payload = root / 'payloads/guest/aarch64/rootfs.ext4'
        payload.chmod(0o600)
        with self.assertRaisesRegex(retry._retire_RebindError, 'size or mode differs'):
            self.prune()
        payload.unlink()
        payload.symlink_to(self.prep / 'inrou-stage/payloads/guest/aarch64/rootfs.ext4')
        with self.assertRaises(retry.RetryError):
            self.prune()
        self.assertFalse((self.work / 'public-prune-intent.json').exists())

    def test_archived_host_stage_resumes_partial_payload_unlink(self):
        root = self.archived_host_stage()
        real = Path.unlink
        def interrupted(path, *args, **kwargs):
            if path == root / 'payloads/guest/aarch64/rootfs.ext4':
                raise OSError('interrupted archived stage cleanup')
            return real(path, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', interrupted), self.assertRaises(OSError):
            self.prune()
        self.assertTrue((self.work / 'public-prune-intent.json').exists())
        self.assertFalse((root / 'payloads/guest/aarch64/initrd.img').exists())
        self.assertEqual(self.prune()['file_count'], 68)
        self.assertTrue((root / 'payloads/guest/aarch64/private-config').exists())

    def test_closed_public_prune_preserves_private_siblings_and_is_idempotent(self):
        preserved = {path: path.read_bytes() for path in self.root.rglob('*')
                     if path.is_file() and path not in self.targets}
        directory_ids = {path: path.stat().st_ino for path in self.root.rglob('*') if path.is_dir()}
        first = self.prune(); second = self.prune()
        self.assertEqual(first, second); self.assertEqual(first['file_count'], 65)
        self.assertTrue(all(not path.exists() for path in self.targets))
        self.assertTrue(all(path.read_bytes() == data for path,data in preserved.items()))
        self.assertTrue(all(path.stat().st_ino == inode for path,inode in directory_ids.items()))
        self.assertEqual(self.reclaim.call_count, 4)

    def test_closed_public_prune_flushes_freed_blocks_before_bounded_trim(self):
        def native_reclaim(argv, **kwargs):
            self.assertTrue(all(not path.exists() for path in self.targets))
            self.assertEqual(kwargs, {'capture_output': True, 'timeout': 60, 'check': False})
            return SimpleNamespace(returncode=0)
        self.reclaim.side_effect = native_reclaim
        with mock.patch.object(retry.os.path, 'ismount', side_effect=lambda path: path == self.runtime):
            self.prune()
            self.prune()
        self.assertEqual([call.args[0] for call in self.reclaim.call_args_list], [
            ['/usr/bin/sync', '-f', str(self.runtime)],
            ['/usr/sbin/fstrim', str(self.runtime)],
            ['/usr/bin/sync', '-f', str(self.runtime)],
            ['/usr/sbin/fstrim', str(self.runtime)],
        ])

    def test_closed_public_prune_flush_failure_stops_trim_and_resumes(self):
        self.reclaim.return_value = SimpleNamespace(returncode=1)
        with self.assertRaisesRegex(retry._retire_RebindError, 'filesystem flush failed'):
            self.prune()
        self.assertEqual(self.reclaim.call_count, 1)
        self.assertEqual(self.reclaim.call_args.args[0][:2], ['/usr/bin/sync', '-f'])
        self.assertTrue(all(not path.exists() for path in self.targets))
        self.reclaim.reset_mock()
        self.reclaim.return_value = SimpleNamespace(returncode=0)
        self.assertEqual(self.prune()['file_count'], 65)
        self.assertEqual([call.args[0][0] for call in self.reclaim.call_args_list],
                         ['/usr/bin/sync', '/usr/sbin/fstrim'])

    def test_closed_public_prune_flush_timeout_stops_trim(self):
        self.reclaim.side_effect = subprocess.TimeoutExpired(['/usr/bin/sync'], 60)
        with self.assertRaises(subprocess.TimeoutExpired):
            self.prune()
        self.assertEqual(self.reclaim.call_count, 1)
        self.assertEqual(self.reclaim.call_args.args[0][:2], ['/usr/bin/sync', '-f'])
        self.assertEqual(self.reclaim.call_args.kwargs['timeout'], 60)

    def test_closed_public_prune_resumes_an_interrupted_unlink_and_trim(self):
        original = Path.unlink; count = 0
        def interrupted(path, *args, **kwargs):
            nonlocal count
            count += 1
            if count == 4: raise OSError('simulated unlink interruption')
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', interrupted), self.assertRaises(OSError): self.prune()
        self.assertTrue((self.work / 'public-prune-intent.json').exists())
        self.assertFalse((self.work / 'public-prune-completed.json').exists())
        self.reclaim.side_effect = lambda argv, **kwargs: SimpleNamespace(
            returncode=1 if argv[0] == '/usr/sbin/fstrim' else 0)
        with self.assertRaisesRegex(retry._retire_RebindError, 'trim failed'): self.prune()
        self.reclaim.side_effect = None
        self.assertEqual(self.prune()['file_count'], 65)

    def test_closed_public_prune_rejects_forged_manifest_and_unpublished_retirement(self):
        self.result['published'] = False
        with self.assertRaises(retry._retire_RebindError): self.prune()
        self.result['published'] = True
        manifest = next(self.work.rglob('manifest.to')); manifest.write_bytes(b'forged public manifest')
        with self.assertRaisesRegex(retry.RetryError, 'public record digest differs'): self.prune()
        self.assertTrue(all(path.exists() for path in self.targets))

    def test_closed_public_prune_accepts_public_manifest_modes_without_chmod(self):
        manifests = list(self.work.rglob('manifest.to'))
        for index, path in enumerate(manifests):
            path.chmod(0o444 if index % 2 else 0o644)
        before = {path: retry.identity(path.stat()) for path in manifests}
        self.assertEqual(self.prune()['file_count'], 65)
        self.assertEqual(before, {path: retry.identity(path.stat()) for path in manifests})

    def test_closed_public_prune_rejects_public_manifest_write_permissions_and_links(self):
        manifest = next(self.work.rglob('manifest.to'))
        original = manifest.read_bytes()
        manifest.chmod(0o664)
        with self.assertRaisesRegex(retry._retire_RebindError, 'custody'): self.prune()
        manifest.chmod(0o644)
        link = manifest.with_name('manifest.extra')
        os.link(manifest, link)
        with self.assertRaisesRegex(retry._retire_RebindError, 'links'): self.prune()
        link.unlink(); manifest.unlink()
        self.file(link, original, 0o644); manifest.symlink_to(link)
        with self.assertRaisesRegex(retry.RetryError, 'direct'): self.prune()
        self.assertTrue(all(path.exists() for path in self.targets))

    def test_closed_public_prune_rejects_manifest_replacement_after_authenticated_read(self):
        public_record = retry.public_record
        def replace_after_read(path, *args, **kwargs):
            raw = public_record(path, *args, **kwargs)
            if Path(path).name == 'manifest.to':
                replacement = Path(path).with_name('manifest.replacement')
                self.file(replacement, b'unadmitted replacement', 0o644)
                replacement.replace(path)
            return raw
        with mock.patch.object(retry, 'public_record', side_effect=replace_after_read), \
             self.assertRaisesRegex(retry._retire_RebindError, 'changed during prune admission'):
            self.prune()
        self.assertTrue(all(path.exists() for path in self.targets))
        self.assertFalse((self.work / 'public-prune-intent.json').exists())

    def test_closed_public_prune_rejects_links_unknown_chunks_and_live_references(self):
        victim = self.targets[0]; original = victim.read_bytes(); victim.unlink()
        victim.symlink_to(self.bins / 'iroha')
        with self.assertRaises(retry.RetryError): self.prune()
        victim.unlink(); self.file(victim, original, 0o755)
        chunk = next(path for path in self.targets if path.name.startswith('chunk_'))
        foreign = chunk.parent / 'private-key'; self.file(foreign, b'PRESERVE', 0o600)
        with self.assertRaisesRegex(retry._retire_RebindError, 'unexpected entry'): self.prune()
        foreign.unlink()
        retry._retire_live_references.return_value = {'passed': False}
        with self.assertRaisesRegex(retry._retire_RebindError, 'live reference'): self.prune()
        self.assertTrue(all(path.exists() for path in self.targets))

    def test_published_retirement_apply_finishes_prune_on_both_reopens(self):
        self.context.update(old_dispatcher_sha256="e" * 64, new_dispatcher_sha256="e" * 64)
        self.file(self.work / "manifest.json", retry._retire_canonical(self.context), 0o600)
        self.file(self.work / "result.json", retry._retire_canonical(self.result), 0o600)
        with (self.bins / "iroha").open("rb") as source, \
             mock.patch.object(retry, "_retire_locks", side_effect=lambda *args: contextlib.nullcontext()), \
             mock.patch.object(retry, "_retire_binary", side_effect=lambda *args: SimpleNamespace(fd=source.fileno(), close=lambda: None)), \
             mock.patch.object(retry, "_retire_no_running_inode"), \
             mock.patch.object(retry, "_retire_check_guards"):
            first = retry._retire_apply(self.guard, self.context)
            second = retry._retire_apply(self.guard, self.context)
        self.assertEqual(first, self.result)
        self.assertEqual(second, self.result)
        self.assertTrue(all(not path.exists() for path in self.targets))
        self.assertEqual(self.reclaim.call_count, 4)

    def test_closed_public_prune_rejects_replacement_after_persisted_intent(self):
        self.reclaim.return_value = SimpleNamespace(returncode=1)
        with self.assertRaises(retry._retire_RebindError): self.prune()
        self.file(self.targets[0], b'public executable', 0o755)
        with self.assertRaisesRegex(retry._retire_RebindError, 'appeared or changed'): self.prune()
        self.assertTrue(self.targets[0].exists())


class SupersededImportTests(unittest.TestCase):
    """Actual native record joins and interrupted public deletion, without host I/O."""

    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o022))
        # Use native symlink metadata and owner-controlled ancestry. A shared
        # checkout projects macOS symlink modes; /tmp has writable ancestors.
        self.tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.runtime = self.root / 'runtime'
        self.work = self.runtime / 'retry-v1/attempt/retirement'
        self.work.mkdir(mode=0o700, parents=True)
        self.source_root = self.root / 'public-source'
        self.source_root.mkdir(mode=0o755)
        self.bins = self.runtime / 'old-release/bin'
        self.current_bins = self.runtime / 'current-release/bin'
        self.pack = self.runtime / 'old-source-import/source.pack'
        self.tracked = [
            {'path': 'src/lib.rs', 'mode': 0o644, 'size': 4, 'sha256': 'a' * 64},
            {'path': 'run', 'mode': 0o755, 'size': 4, 'sha256': 'a' * 64},
            {'path': 'leaf', 'mode': 0o120000, 'size': 10, 'sha256': 'b' * 64},
            {'path': 'iroha-docs', 'mode': 0o160000, 'size': 0, 'sha256': 'c' * 64},
        ]
        for relative, mode in [('src/lib.rs', 0o644), ('run', 0o755)]:
            self.file(self.source_root / relative, b'code', mode, directory_mode=0o755)
        (self.source_root / 'leaf').symlink_to('/no-follow')
        if hasattr(os, 'lchmod'): os.lchmod(self.source_root / 'leaf', 0o777)
        (self.source_root / 'iroha-docs').mkdir(mode=0o755)
        for name in ('HEAD', 'ORIG_HEAD', 'config', 'shallow', 'refs/heads/optimizations',
                     'logs/HEAD', 'logs/refs/heads/optimizations'):
            self.file(self.source_root / '.git' / name, b'public git', 0o644, directory_mode=0o755)
        self.file(self.source_root / '.git/index', b'public index', 0o600, directory_mode=0o755)
        for name in ('objects/info', 'refs/tags'):
            (self.source_root / '.git' / name).mkdir(mode=0o755, parents=True, exist_ok=True)
        for suffix in ('.pack', '.idx', '.rev'):
            self.file(self.source_root / ('.git/objects/pack/pack-' + 'd' * 40 + suffix),
                      b'public pack', 0o444, directory_mode=0o755)
        self.file(self.pack, b'public pack', 0o600)
        self.closure = {
            'schema': 'iroha.taira.public-reset.signed-source-closure.v1',
            'branch': 'optimizations', 'head_commit_sha1': 'a' * 40,
            'head_tree_sha1': 'b' * 40, 'closure_sha256': 'c' * 64,
            'cargo_lock_sha256': 'd' * 64, 'tracked_files': self.tracked, 'untracked_files': [],
        }
        closure_ref = self.record(self.runtime / 'old-inputs/source-manifest.json', self.closure, 0o644)
        self.old = {'qualification_scope': 'full_inrou', 'deployment_id': 'closed-attempt', 'authorization_nonce': 'e' * 32,
                    'revision': {'branch': 'optimizations', 'commit': 'a' * 40, 'tree': 'b' * 40,
                        'source_root': str(self.source_root), 'source_manifest_path': closure_ref['path'],
                        'source_manifest_sha256': closure_ref['sha256'], 'source_closure_sha256': 'c' * 64,
                        'cargo_lock_sha256': 'd' * 64}, 'validators': []}
        self.artifacts = []
        for name in ('iroha', 'iroha3d_taira', 'sorafs-node', 'kagami'):
            self.file(self.bins / name, b'public binary', 0o755)
            self.file(self.current_bins / name, b'current binary', 0o755)
            self.artifacts.append({'name': name, 'size': len(b'public binary'), 'sha256': 'f' * 64})
        roles = [('iroha_cli', 'iroha'), ('iroha3d', 'iroha3d_taira'), ('sorafs_node', 'sorafs-node'), ('kagami', 'kagami')]
        for index in range(5):
            host = {'slug': retry.RETIRE_SLUGS[index], 'artifacts': [
                {'role': role, 'local_path': str(self.bins / name), 'size': len(b'public binary'), 'sha256': 'f' * 64}
                for role, name in (roles if index < 4 else roles[:1])]}
            if index < 4: self.old['validators'].append(host)
            else: self.old['edge'] = host
        inventory_ref = self.record(self.runtime / 'old-inputs/inventory.json', self.old)
        self.terminal = {'deployment_id': self.old['deployment_id'], 'inventory_sha256': inventory_ref['sha256'],
            'authorization_sha256': 'a' * 64, 'authorization_nonce': 'e' * 32,
            'qualification_scope': 'full_inrou', 'status': 'rolled_back', 'phase': 'rolled_back', 'next_step': 7, 'recovery_intent': None,
            'touched_validators': list(retry.RETIRE_SLUGS[:-1]), 'edge_touched': False,
            'edge_rollback_complete': False, 'rollback_next_validator': 4, 'rollback_failures': []}
        terminal_ref = self.record(self.runtime / 'journal-v1/rolled-back' / ('a' * 64 + '.json'), self.terminal)
        self.retired = {'schema': 'taira.terminal-custody-retirement.v1', 'published': True,
            'control_archived': True, 'native_rollback_completed': True, 'inventory_sha256': inventory_ref['sha256'],
            'retained_commit': 'a' * 40, 'retained_deployment_id': self.old['deployment_id'],
            'terminal_path': terminal_ref['path'], 'terminal_sha256': terminal_ref['sha256']}
        retirement_ref = self.record(self.runtime / 'old-retirement/result.json', self.retired)
        self.binary = {'commit': 'a' * 40, 'all_hashes_verified': True, 'activated': False,
                       'destination': str(self.bins), 'artifacts': self.artifacts}
        self.source = {'commit': 'a' * 40, 'tree': 'b' * 40, 'source_root': str(self.source_root),
            'size': 11, 'sha256': 'b' * 64, 'clean': True, 'signature_verified': True,
            'object_inventory_verified': True, 'activated': False, 'runtime_files_transferred': False,
            'runtime_files_included': False, 'history_included': False}
        self.descriptor = {'inventory': inventory_ref, 'retirement': retirement_ref,
            'binary_manifest': self.record(self.bins.parent / 'verified-manifest.json', self.binary),
            'source_manifest': self.record(self.pack.parent / 'verified-manifest.json', self.source),
            'source_pack': str(self.pack)}
        self.current = copy.deepcopy(self.old)
        self.current['revision']['source_root'] = str(self.root / 'current-source')
        for host in self.current['validators'] + [self.current['edge']]:
            for artifact in host['artifacts']:
                artifact['local_path'] = str(self.current_bins / Path(artifact['local_path']).name)
        self.invpath = self.runtime / 'current-inputs/inventory.json'
        ref = self.record(self.invpath, self.current)
        self.context = {'inventory_sha256': ref['sha256'], 'terminal_sha256': '9' * 64}
        self.result = {'published': True, 'control_archived': True, 'native_rollback_completed': True, **self.context}
        self.preserved = {}
        for path in (self.bins / 'private-config', self.pack.parent / 'retained-receipt',
                     self.runtime / 'prep/private-key', self.root / 'current-source/Cargo.lock'):
            self.file(path, b'PRIVATE OR CURRENT PRESERVE', 0o600)
            self.preserved[path] = path.read_bytes()
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        for name, value in {'RETIRE_RUNTIME': self.runtime, 'RETIRE_WORK': self.work,
            'RETIRE_CONTROL': self.runtime / 'control', 'RETIRE_DISPATCHER': self.runtime / 'dispatcher',
            'CONTINUITY_PREP': self.runtime / 'prep', 'RETIRE_BINS': self.current_bins,
            'RETIRE_INVENTORY_PATH': self.invpath, 'RETIRE_PUBLIC_IMPORTS': [self.descriptor],
            'RETIRE_PROTECTED_INPUTS': ()}.items():
            self.stack.enter_context(mock.patch.object(retry, name, value))
        self.stack.enter_context(mock.patch.object(retry, '_retire_retained_state'))
        self.references = self.stack.enter_context(mock.patch.object(retry, '_retire_live_references', return_value={'passed': True}))
        self.stack.enter_context(mock.patch.object(retry, '_retire_read_public', side_effect=lambda g,p,expected=None,**kw:
            retry.public_record(p, expected, owner=os.geteuid(), private=True, **kw)))
        self.stack.enter_context(mock.patch.object(retry, '_retire_rename_atomic', side_effect=os.rename))
        self.native = self.stack.enter_context(mock.patch.object(retry.subprocess, 'run', return_value=SimpleNamespace(returncode=0)))
        self.stack.enter_context(mock.patch.object(retry.os.path, 'ismount', side_effect=lambda p: Path(p) == self.root))
        self.guard = {'fresh_write': self.fresh_write, 'sync_directory': retry.sync_directory}

    def file(self, path, raw, mode, directory_mode=0o700):
        path.parent.mkdir(mode=directory_mode, parents=True, exist_ok=True)
        path.write_bytes(raw); path.chmod(mode)

    def record(self, path, value, mode=0o600):
        raw = retry._retire_canonical(value); self.file(path, raw, mode)
        return {'path': str(path), 'sha256': retry._retire_digest(raw)}

    def fresh_write(self, path, raw, mode):
        with path.open('xb') as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        path.chmod(mode)

    def prune(self):
        return retry._retire_completed_public_imports(self.guard, self.context, self.result)

    def intent(self):
        return self.work / 'public-import-retirement' / (self.descriptor['inventory']['sha256'] + '.intent.json')

    def test_superseded_import_reclaims_exact_public_payloads_and_reopens(self):
        all_receipts = {p: p.read_bytes() for p in self.runtime.rglob('*.json')}
        first = self.prune(); self.assertEqual(first, self.prune())
        self.assertGreater(first[0]['allocated_bytes_removed'], 0)
        self.assertFalse(self.source_root.exists()); self.assertFalse(self.pack.exists())
        self.assertTrue(all(not (self.bins / row['name']).exists() for row in self.artifacts))
        self.assertTrue(all((self.current_bins / row['name']).exists() for row in self.artifacts))
        self.assertTrue(all(p.read_bytes() == raw for p,raw in {**all_receipts, **self.preserved}.items()))
        self.assertEqual([call.args[0][0] for call in self.native.call_args_list],
                         ['/usr/bin/sync', '/usr/sbin/fstrim'] * 2)

    def test_superseded_import_resumes_partial_quarantine_and_file_unlink(self):
        def interrupted(path):
            (Path(path) / 'src/lib.rs').unlink()
            raise OSError('interrupted source deletion')
        interrupted.avoids_symlink_attacks = True
        with mock.patch.object(retry.shutil, 'rmtree', interrupted), self.assertRaises(OSError): self.prune()
        self.assertTrue(self.intent().exists()); self.assertFalse(self.source_root.exists())
        real_unlink = Path.unlink
        def interrupt_binary(path, *args, **kwargs):
            if path == self.bins / 'iroha3d_taira': raise OSError('interrupted binary deletion')
            return real_unlink(path, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', interrupt_binary), self.assertRaises(OSError): self.prune()
        self.assertEqual(len(self.prune()), 1)
        self.assertFalse(self.pack.exists())

    def test_superseded_import_resumes_flush_failure_without_deleting_current_inputs(self):
        self.native.return_value = SimpleNamespace(returncode=1)
        with self.assertRaisesRegex(retry.RetryError, 'flush failed'): self.prune()
        self.assertEqual(self.native.call_count, 1)
        self.native.return_value = SimpleNamespace(returncode=0)
        self.assertEqual(len(self.prune()), 1)

    def test_superseded_import_protects_same_artifact_source_and_all_four_binaries(self):
        retry.RETIRE_BINS = self.bins
        self.current = copy.deepcopy(self.old)
        ref = self.record(self.invpath, self.current)
        self.context['inventory_sha256'] = self.result['inventory_sha256'] = ref['sha256']
        self.prune()
        self.assertTrue(self.source_root.exists())
        self.assertTrue(all((self.bins / row['name']).exists() for row in self.artifacts))
        self.assertFalse(self.pack.exists())

    def test_superseded_import_rejects_unpublished_receipt_and_foreign_live_journal(self):
        self.retired['published'] = False
        self.descriptor['retirement'] = self.record(Path(self.descriptor['retirement']['path']), self.retired)
        with self.assertRaisesRegex(retry.RetryError, 'completed custody retirement'): self.prune()
        self.retired['published'] = True
        self.descriptor['retirement'] = self.record(Path(self.descriptor['retirement']['path']), self.retired)
        self.file(self.runtime / 'journal-v1/closed-attempt.journal.json', b'PRESERVE', 0o600)
        with self.assertRaisesRegex(retry.RetryError, 'live native journal'): self.prune()
        self.assertFalse(self.intent().exists()); self.assertTrue(self.source_root.exists())

    def test_superseded_import_rejects_ignored_private_file_and_live_reference_before_mutation(self):
        extra = self.source_root / '.ignored-private-key'
        self.file(extra, b'NEVER DELETE', 0o600)
        with self.assertRaises(retry.RetryError): self.prune()
        self.assertTrue(extra.exists()); self.assertFalse(self.intent().exists())
        extra.unlink(); self.references.return_value = {'passed': False}
        with self.assertRaisesRegex(retry.RetryError, 'live process'): self.prune()
        self.assertTrue(self.source_root.exists()); self.assertTrue(self.pack.exists())

    def test_superseded_import_rejects_replaced_binary_and_escaped_resume_quarantine(self):
        self.native.return_value = SimpleNamespace(returncode=1)
        with self.assertRaises(retry.RetryError): self.prune()
        self.file(self.bins / 'iroha', b'public binary', 0o755)
        with self.assertRaisesRegex(retry.RetryError, 'appeared after intent'): self.prune()
        (self.bins / 'iroha').unlink()
        value = json.loads(self.intent().read_bytes()); value['quarantine'] = str(self.root / 'current-source')
        self.record(self.intent(), value)
        with self.assertRaisesRegex(retry.RetryError, 'quarantine escaped'): self.prune()
        self.assertTrue((self.root / 'current-source/Cargo.lock').exists())

    def test_superseded_import_read_only_admission_checks_real_receipts_without_mutation(self):
        admissions = retry._retire_import_admissions(None, self.current)
        self.assertEqual(len(admissions), 1)
        self.assertEqual(admissions[0]['source_root'], str(self.source_root))
        self.assertFalse(self.intent().parent.exists())
        self.native.assert_not_called(); self.references.assert_not_called()
        self.source['commit'] = '9' * 40
        self.descriptor['source_manifest'] = self.record(Path(self.descriptor['source_manifest']['path']), self.source)
        with self.assertRaisesRegex(retry.RetryError, 'provenance differs'):
            retry._retire_import_admissions(None, self.current)
        self.assertTrue(self.source_root.exists()); self.assertTrue(self.pack.exists())

    def test_superseded_import_shape_and_capacity_bounds_are_explicit(self):
        self.assertEqual(retry.validate_retired_public_imports([self.descriptor]), [self.descriptor])
        for descriptor in ({}, {**self.descriptor, 'source_pack': str(self.runtime / 'prep/private-key')}):
            with self.assertRaises(retry.RetryError): retry.validate_retired_public_imports([descriptor])
        with self.assertRaises(retry.RetryError): retry.validate_retired_public_imports([self.descriptor] * 2)
        base = retry.retirement_capacity_plans(str(self.runtime), '/backing', self.binary)
        extra = retry.retirement_capacity_plans(str(self.runtime), '/backing', self.binary, 2)
        self.assertEqual(extra['guest_plan']['allocations'][0]['bytes'] - base['guest_plan']['allocations'][0]['bytes'],
                         2 * (retry.RETIRE_IMPORT_MAX_INTENT_BYTES + 1024 * 1024))
        with self.assertRaises(retry.RetryError): retry.retirement_capacity_plans(str(self.runtime), '/backing', self.binary, 5)



if __name__ == "__main__":
    unittest.main()
