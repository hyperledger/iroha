#!/usr/bin/env python3
"""Render a Taira validator systemd unit without reading runtime signing inputs.

Requires Python 3.10+ and explicit absolute Linux paths to retained owner-private
signers. Output is a new public mode-0644 unit, ready for native inventory
assembly and never installed or overwritten here. Referenced signers stay private.
Validate it with systemd-analyze verify on the deployment host and bind its exact
bytes into the native public-reset inventory before installation.

Type=exec waits for systemd to execute the inline custody launcher. Native
process attestation and HTTP readiness still wait for the actual daemon.
The public beacon credential path is optional only during initial key setup;
configured beacon custody uses FD 200 and is required for beacon readiness.
Initial units use config.toml; --config-file beacon.toml selects the separately
authenticated provider-config transition without changing the initial artifacts.
--amend-unit with --rate-config-receipt instead creates a fresh public unit from
an installed unit and the native torii-rate-config-amend receipt. Only its sole
literal --config-blake3 value changes; config and signer bodies are never read.
Install the separately validated native config at its original path before
activating this unit. This helper never installs or restarts a validator.

First boot (Sumeragi record provenance, specs/sumeragi.md section 7.4): every
unit starts iroha3d_taira --config ... --sora and adds
--sumeragi-assert-fresh-key only when its launcher consumes the one-shot token
/var/lib/taira/ROLE/sumeragi-first-boot. Missing safety history never
authorizes the assertion: only --arm-first-boot creates the token, run as root
on the stopped validator host before the first start of its fresh state root,
and it refuses when the configured sumeragi-records directory or
sumeragi-installation.log exists. The launcher refuses to start while a token
sits beside existing history, and removes the token durably before it execs the
daemon, so no restart repeats the assertion and no lost record store renews it.
"""
import argparse
import ast
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

CUSTODY = '''reserved_fds = (198, 200)
for reserved_fd in reserved_fds:
    try:
        os.fstat(reserved_fd)
    except OSError as error:
        if error.errno != errno.EBADF: raise
    else:
        raise RuntimeError("Taira signer descriptor is already occupied")
staged = []

def armed_first_boot():
    # Only the explicit first-boot step creates this token. Missing safety
    # history alone never authorizes the fresh-key assertion.
    try:
        token = os.lstat(first_boot_token)
    except FileNotFoundError:
        return None
    root = os.lstat(state_root)
    if not stat.S_ISDIR(root.st_mode) or root.st_uid != os.geteuid() or root.st_mode & 0o022:
        raise RuntimeError("untrusted Taira validator state root")
    if not stat.S_ISREG(token.st_mode) or token.st_uid != os.geteuid() or token.st_mode & 0o7777 != 0o600 or token.st_nlink != 1 or token.st_size != 0:
        raise RuntimeError("untrusted Taira first-boot token")
    for history in sumeragi_history:
        try:
            os.lstat(history)
        except FileNotFoundError:
            continue
        raise RuntimeError("Taira first boot refused: Sumeragi safety history already exists")
    return (token.st_dev, token.st_ino)

def sync_state_root():
    root_fd = os.open(state_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try: os.fsync(root_fd)
    finally: os.close(root_fd)

# Refuse an unusable first boot before any signer copy exists.
first_boot = armed_first_boot()
first_boot_consumed = False

def stage_signer(source_path, target_fd, expected_size, label):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow)
    if source_fd in reserved_fds:
        os.close(source_fd)
        raise RuntimeError("source open reached a reserved Taira signer descriptor")
    launch_path = source_path + ".fd" + str(target_fd)
    launch_fd = None
    launch_created = False
    launch_ready = False
    secret = bytearray()
    secret_view = None
    try:
        source_before = os.fstat(source_fd)
        size = source_before.st_size
        if not stat.S_ISREG(source_before.st_mode) or source_before.st_uid != os.geteuid() or source_before.st_mode & 0o7777 != 0o600 or source_before.st_nlink != 1:
            raise RuntimeError("untrusted persistent Taira " + label + " file")
        if (expected_size is not None and size != expected_size) or (expected_size is None and not 0 < size <= 16 * 1024 * 1024):
            raise RuntimeError("invalid persistent Taira " + label + " length")
        secret = bytearray(size)
        secret_view = memoryview(secret)
        try:
            stale = os.lstat(launch_path)
        except FileNotFoundError:
            stale = None
        if stale is not None:
            if not stat.S_ISREG(stale.st_mode) or stale.st_uid != os.geteuid() or stale.st_mode & 0o7777 != 0o600 or stale.st_nlink != 1 or stale.st_size not in (0, size):
                raise RuntimeError("untrusted stale Taira FD" + str(target_fd) + " launch file")
            os.unlink(launch_path)
        launch_fd = os.open(launch_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | nofollow, 0o600)
        launch_created = True
        if launch_fd in reserved_fds:
            raise RuntimeError("launch open reached a reserved Taira signer descriptor")
        offset = 0
        while offset < len(secret):
            count = os.readv(source_fd, [secret_view[offset:]])
            if count == 0: raise RuntimeError("short Taira " + label + " source")
            offset += count
        source_after = os.fstat(source_fd)
        stable_fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(source_before, field) != getattr(source_after, field) for field in stable_fields):
            raise RuntimeError("Taira " + label + " source changed while staging")
        offset = 0
        while offset < len(secret):
            count = os.write(launch_fd, secret_view[offset:])
            if count == 0: raise RuntimeError("short Taira FD" + str(target_fd) + " launch write")
            offset += count
        os.fsync(launch_fd)
        os.lseek(launch_fd, 0, os.SEEK_SET)
        launch_stat = os.fstat(launch_fd)
        if not stat.S_ISREG(launch_stat.st_mode) or launch_stat.st_uid != os.geteuid() or launch_stat.st_mode & 0o7777 != 0o600 or launch_stat.st_nlink != 1 or launch_stat.st_size != size:
            raise RuntimeError("untrusted Taira FD" + str(target_fd) + " launch file")
        os.dup2(launch_fd, target_fd, inheritable=True)
        staged.append((target_fd, launch_path))
        launch_ready = True
    finally:
        for index in range(len(secret)): secret[index] = 0
        if secret_view is not None: secret_view.release()
        # A write/fsync/dup2 failure can leave a full copy before it joins
        # staged. Erase that owned copy while its descriptor is still open.
        if launch_created and not launch_ready and launch_fd is not None:
            try:
                os.ftruncate(launch_fd, 0)
                os.fsync(launch_fd)
            except OSError: pass
        try: os.close(source_fd)
        except OSError: pass
        if launch_fd is not None:
            try: os.close(launch_fd)
            except OSError: pass
        if launch_created and not launch_ready:
            try: os.unlink(launch_path)
            except OSError: pass

try:
    stage_signer(runtime_key, 198, 71, "runtime signer")
    if global_beacon_credential is not None:
        stage_signer(global_beacon_credential, 200, None, "global-beacon credential")
    launch_argv = cmd
    if first_boot is not None:
        if armed_first_boot() != first_boot:
            raise RuntimeError("Taira first-boot token changed while staging")
        # Consume the token durably before the daemon exists: no later start,
        # even one that finds no safety history, repeats the assertion.
        os.unlink(first_boot_token)
        first_boot_consumed = True
        sync_state_root()
        launch_argv = cmd + ['--sumeragi-assert-fresh-key']
    os.execv(cmd[0], launch_argv)
finally:
    # Successful foreground exec never returns. Failed staging/exec must not
    # leave an extra full seed copy or close an unrelated inherited descriptor.
    for staged_fd, staged_path in reversed(staged):
        try:
            os.ftruncate(staged_fd, 0)
            os.fsync(staged_fd)
        except OSError:
            pass
        try: os.close(staged_fd)
        except OSError: pass
        try: os.unlink(staged_path)
        except OSError: pass
    if first_boot_consumed:
        # The daemon never ran, so its unused first-boot token is restored.
        token_fd = os.open(first_boot_token, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(token_fd, 0o600)
            os.fsync(token_fd)
        finally:
            os.close(token_fd)
        sync_state_root()
'''

ROLES = tuple(f"taira-validator-{index}" for index in range(1, 5))
CONFIG_FILES = ("config.toml", "beacon.toml")
STATE_ROOT_PARENT = "/var/lib/taira"
FIRST_BOOT_TOKEN = "sumeragi-first-boot"
# `[sumeragi] records_dir` and `installation_log` of the native Taira validator
# config (`iroha taira public-reset materialize-validator-config`), inside the
# validator state root.
SUMERAGI_HISTORY = ("sumeragi-records", "sumeragi-installation.log")
RATE_BUDGETS = frozenset({
    "torii.query_rate_per_authority_per_sec", "torii.query_burst_per_authority",
    "torii.tx_rate_per_authority_per_sec", "torii.tx_burst_per_authority",
    "torii.deploy_rate_per_origin_per_sec", "torii.deploy_burst_per_origin",
    "torii.preauth_rate_per_ip_per_sec", "torii.preauth_burst_per_ip",
    "torii.soracloud_public_rate_per_ip_per_sec", "torii.soracloud_public_burst_per_ip",
    "torii.soracloud_mutation_rate_per_account_origin_per_sec",
    "torii.soracloud_mutation_burst_per_account_origin", "torii.proof_rate_per_minute",
    "torii.proof_burst", "torii.mcp.rate_per_minute", "torii.mcp.burst",
    "torii.push.rate_per_minute", "torii.push.burst", "content.max_requests_per_second",
    "content.request_burst", "torii.connect.ws_rate_per_ip_per_min",
    "sorafs.gateway.rate_limit.max_requests", "torii.operator_auth.rate_per_minute",
    "torii.operator_auth.burst", "torii.soranet_privacy_ingest.rate_per_sec",
    "torii.soranet_privacy_ingest.burst", "torii.recipient_lookup.requests_per_minute",
})
STABLE_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


def snapshot(info):
    return tuple(getattr(info, field) for field in STABLE_FIELDS)


def public_input(path, limit):
    """Retain a bounded, owner-controlled public input; never used for config bodies."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) not in (0o400, 0o444, 0o600, 0o644)
                or info.st_nlink != 1 or not 0 < info.st_size <= limit
                or snapshot(os.lstat(path)) != snapshot(info)):
            raise ValueError("untrusted public amendment input")
        content = bytearray()
        while len(content) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != info.st_size or snapshot(os.fstat(descriptor)) != snapshot(info):
            raise ValueError("public amendment input changed while reading")
        return descriptor, info, bytes(content)
    except BaseException:
        os.close(descriptor)
        raise


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate public receipt key")
        result[key] = value
    return result


def rate_config_receipt(content):
    receipt = json.loads(content, object_pairs_hook=unique_json)
    fields = {"schema", "source_path", "source_config_blake3", "output_path", "output_config_blake3",
              "request_budgets", "unchanged_optional_sections", "output_metadata"}
    if not isinstance(receipt, dict) or set(receipt) != fields or receipt["schema"] != "iroha.taira.torii-rate-config-amend.v1":
        raise ValueError("unsupported public rate-config receipt")
    for name in ("source_path", "output_path"):
        if not isinstance(receipt[name], str):
            raise ValueError("invalid public config path")
        checked_path(receipt[name], name)
    if (receipt["source_path"] == receipt["output_path"]
            or PurePosixPath(receipt["source_path"]).parent != PurePosixPath(receipt["output_path"]).parent):
        raise ValueError("native output must be fresh beside its source")
    for name in ("source_config_blake3", "output_config_blake3"):
        if not isinstance(receipt[name], str) or not re.fullmatch(r"[0-9a-f]{64}", receipt[name]):
            raise ValueError("invalid native config fingerprint")
    budgets = receipt["request_budgets"]
    if (not isinstance(budgets, dict) or not set(budgets) <= RATE_BUDGETS
            or any(type(value) is not int or not 0 < value <= 0xffffffff for value in budgets.values())):
        raise ValueError("invalid public request budgets")
    optional = receipt["unchanged_optional_sections"]
    if optional not in ([], ["recipient-lookup"]) or (optional and "torii.recipient_lookup.requests_per_minute" in budgets):
        raise ValueError("invalid optional section receipt")
    metadata = receipt["output_metadata"]
    if (not isinstance(metadata, dict) or set(metadata) != {"device", "inode", "uid", "mode", "links", "bytes"}
            or any(type(value) is not int or value < 0 for value in metadata.values())
            or metadata["uid"] != os.geteuid() or metadata["mode"] != 0o600
            or metadata["links"] != 1 or not 0 < metadata["bytes"] <= 1024 * 1024):
        raise ValueError("unsafe native config output metadata")
    return receipt


def unit_config_binding(content):
    lines = content.decode("utf-8").splitlines()
    starts = [line for line in lines if line.lstrip().startswith("ExecStart=")]
    prefix = "ExecStart=/usr/bin/python3 -c "
    if len(starts) != 1 or not starts[0].startswith(prefix):
        raise ValueError("unit must have one inline custody launcher")
    code = json.loads(starts[0][len(prefix):])
    if not isinstance(code, str):
        raise ValueError("invalid inline custody launcher")
    tree = ast.parse(code.replace("%%", "%").replace("$$", "$"))
    stores = [node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "cmd" and isinstance(node.ctx, ast.Store)]
    assignments = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                   and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "cmd"]
    if len(stores) != 1 or len(assignments) != 1:
        raise ValueError("unit must contain one literal daemon argv")
    cmd = ast.literal_eval(assignments[0].value)
    if (not isinstance(cmd, list) or len(cmd) != 6 or any(not isinstance(value, str) for value in cmd)
            or cmd[1:].count("--sora") != 1 or cmd[1:].count("--config") != 1
            or cmd[1:].count("--config-blake3") != 1):
        raise ValueError("unit argv must bind exactly one config fingerprint")
    config_index, hash_index = cmd.index("--config"), cmd.index("--config-blake3")
    if config_index == 5 or hash_index == 5 or set((1, 2, 3, 4, 5)) != {config_index, config_index + 1, hash_index, hash_index + 1, cmd.index("--sora")}:
        raise ValueError("invalid fingerprint-bound daemon argv")
    checked_path(cmd[0], "daemon executable")
    checked_path(cmd[config_index + 1], "unit config")
    if PurePosixPath(cmd[0]).name != "iroha3d_taira" or not re.fullmatch(r"[0-9a-f]{64}", cmd[hash_index + 1]):
        raise ValueError("invalid fingerprint-bound daemon argv")
    return cmd[config_index + 1], cmd[hash_index + 1]


def amend_unit(role, source, receipt_path, output):
    """Replace one public fingerprint; retain all custody bytes and read no config body."""
    for path in (source, receipt_path, output):
        checked_path(str(path), "public amendment path")
    if role not in ROLES or Path(source).name != f"iroha3d-{role}.service" or Path(output).name != f"iroha3d-{role}.service":
        raise ValueError("source and output filenames must match the canonical role unit name")
    held = []
    created = None
    output = Path(output)
    try:
        for path, limit in ((source, 256 * 1024), (receipt_path, 64 * 1024)):
            descriptor, info, content = public_input(path, limit)
            held.append((path, descriptor, info, content))
        receipt = rate_config_receipt(held[1][3])
        binding = unit_config_binding(held[0][3])
        if binding != (receipt["source_path"], receipt["source_config_blake3"]):
            raise ValueError("native receipt does not match the installed unit config binding")
        old, new = (receipt[name].encode("ascii") for name in ("source_config_blake3", "output_config_blake3"))
        if old == new or held[0][3].count(old) != 1:
            raise ValueError("unit must contain exactly one changed config fingerprint")
        config_stats = []
        for name in ("source_path", "output_path"):
            info = os.lstat(receipt[name])
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or info.st_nlink != 1
                    or not 0 < info.st_size <= 1024 * 1024):
                raise ValueError("untrusted native config metadata")
            config_stats.append((receipt[name], info))
        info = config_stats[1][1]
        actual = dict(zip(("device", "inode", "uid", "mode", "links", "bytes"),
                          (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size)))
        if actual != receipt["output_metadata"]:
            raise ValueError("native output metadata no longer matches its receipt")
        parent = os.lstat(output.parent)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise ValueError("untrusted public unit output directory")
        def unchanged():
            for path, descriptor, before, _ in held:
                if snapshot(os.fstat(descriptor)) != snapshot(before) or snapshot(os.lstat(path)) != snapshot(before):
                    raise ValueError("public amendment input changed")
            for path, before in config_stats:
                if snapshot(os.lstat(path)) != snapshot(before):
                    raise ValueError("native config metadata changed")
        unchanged()
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            created = os.fstat(file.fileno())
            file.write(held[0][3].replace(old, new, 1))
            file.flush()
            unchanged()
            os.fchmod(file.fileno(), 0o644)
            os.fsync(file.fileno())
        unchanged()
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return output
    except BaseException:
        if created is not None:
            try:
                current = os.lstat(output)
                if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(output)
            except FileNotFoundError:
                pass
        raise
    finally:
        for _, descriptor, _, _ in held:
            os.close(descriptor)


def checked_path(value, label):
    path = PurePosixPath(value)
    if (not value.startswith("/") or value.startswith("//") or str(path) != value
            or ".." in path.parts or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or path.name in ("", ".", "..")):
        raise ValueError(label + " must be an explicit canonical absolute Linux path")
    return value


def validator_state_root(role):
    if role not in ROLES:
        raise ValueError("unknown validator role")
    return STATE_ROOT_PARENT + "/" + role


def first_boot_paths(role, state_root=None):
    """Return the state root, the first-boot token and the Sumeragi history paths.

    Units always use /var/lib/taira/ROLE; tests pass a disposable canonical root.
    """
    root = validator_state_root(role)
    if state_root is not None:
        root = checked_path(state_root, "validator state root")
    return root, root + "/" + FIRST_BOOT_TOKEN, tuple(root + "/" + name for name in SUMERAGI_HISTORY)


def launcher(role, runtime_key, global_beacon_credential=None, *,
             config_file="config.toml", state_root=None):
    if role not in ROLES:
        raise ValueError("unknown validator role")
    if config_file not in CONFIG_FILES:
        raise ValueError("config file must be config.toml or beacon.toml")
    runtime_key = checked_path(runtime_key, "signer input")
    state_root, first_boot_token, sumeragi_history = first_boot_paths(role, state_root)
    paths = (runtime_key, runtime_key + ".fd198",
             first_boot_token, *sumeragi_history)
    if global_beacon_credential is not None:
        global_beacon_credential = checked_path(global_beacon_credential, "signer input")
        paths += (global_beacon_credential, global_beacon_credential + ".fd200")
    if len(set(paths)) != len(paths):
        raise ValueError("retained signer, launch-copy and first-boot paths must all be distinct")
    current = f"/srv/taira/{role}/current"
    cmd = [current + "/bin/iroha3d_taira", "--config", current + "/config/" + config_file, "--sora"]
    # Native consumers truncate only their independent owner-private, single-link
    # RW launch copies. Retained native sources remain intact for restart.
    return ("import errno\nimport os\nimport stat\n"
            + f"runtime_key = {runtime_key!r}\n"
            + f"global_beacon_credential = {global_beacon_credential!r}\n"
            + f"state_root = {state_root!r}\nfirst_boot_token = {first_boot_token!r}\n"
            + f"sumeragi_history = {sumeragi_history!r}\n"
            + f"cmd = {cmd!r}\n" + CUSTODY)


def systemd_argument(value):
    # systemd.syntax C escaping, then systemd.exec specifier/environment escaping.
    # This is one quoted argv element, without a shell or external launcher file.
    out = value.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    out = out.replace("%", "%%").replace("$", "$$")
    return '"' + out + '"'


def render(role, runtime_key, global_beacon_credential=None, *, config_file="config.toml"):
    code = launcher(role, runtime_key, global_beacon_credential, config_file=config_file)
    compile(code, "<signed-unit-inline-python>", "exec")
    return (f"[Unit]\nDescription=Taira {role}\nAfter=network.target\n\n"
            "[Service]\nType=exec\nUser=root\nGroup=root\nUMask=0077\n"
            f"WorkingDirectory={validator_state_root(role)}\n"
            "CPUQuota=100%\nMemoryMax=2147483648\nRestart=on-failure\nRestartSec=5s\n"
            f"ExecStart=/usr/bin/python3 -c {systemd_argument(code)}\n"
            "\n[Install]\nWantedBy=multi-user.target\n")


def arm_first_boot(role, *, state_root=None):
    """Create the one-shot token that makes the unit's next start assert the fresh key.

    Run as root on the validator host, with the validator stopped, before the
    first start of its fresh state root. Refuses unless the state root is a
    directory of this user that nobody else can write and neither Sumeragi
    history path exists; never replaces an existing token.
    """
    root, token, history = first_boot_paths(role, state_root)
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise RuntimeError("validator state root must be a directory of this user that nobody else can write")
    for path in history:
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        raise RuntimeError("Sumeragi safety history already exists at " + path + "; this is not a first boot")
    try:
        descriptor = os.open(token, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise RuntimeError("first-boot token " + token + " already exists") from None
    try:
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return token


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=ROLES, required=True)
    parser.add_argument("--arm-first-boot", action="store_true", help="Render nothing; as root on the stopped validator host, before the first start of its fresh state root, create the one-shot token that makes the next start pass --sumeragi-assert-fresh-key; refuses when Sumeragi safety history or a token exists")
    parser.add_argument("--runtime-key", help="Required to render. Actual retained owner-0600, single-link, 71-byte signer path on the approved guest; never read here")
    parser.add_argument("--global-beacon-credential", help="Retained owner-0600, single-link native beacon credential on the approved guest; consumed launch copy at FD 200; omit only for initial key setup; never read here")
    parser.add_argument("--config-file", choices=CONFIG_FILES, help="Exact retained initial config (config.toml, the default) or authenticated beacon provider transition")
    parser.add_argument("--amend-unit", type=Path, help="Installed public unit whose sole native config fingerprint is to be amended; config and custody bytes stay unchanged")
    parser.add_argument("--rate-config-receipt", type=Path, help="Public native torii-rate-config-amend receipt binding the installed config path and old/new fingerprints")
    parser.add_argument("--output", type=Path, help="Required to render or amend. Fresh iroha3d-ROLE.service file; never overwritten")
    args = parser.parse_args()
    rendering = {"--runtime-key": args.runtime_key,
                 "--global-beacon-credential": args.global_beacon_credential,
                 "--config-file": args.config_file, "--output": args.output}
    if args.arm_first_boot:
        given = [flag for flag, value in rendering.items() if value is not None]
        given += [flag for flag, value in (("--amend-unit", args.amend_unit), ("--rate-config-receipt", args.rate_config_receipt)) if value is not None]
        if given:
            parser.error("--arm-first-boot takes only --role, not " + ", ".join(given))
        try:
            token = arm_first_boot(args.role)
        except (OSError, RuntimeError) as error:
            parser.exit(1, f"{parser.prog}: first boot not armed: {error}\n")
        print(token)
        return
    if args.amend_unit is not None or args.rate_config_receipt is not None:
        missing = [flag for flag, value in (("--amend-unit", args.amend_unit), ("--rate-config-receipt", args.rate_config_receipt), ("--output", args.output)) if value is None]
        given = [flag for flag, value in rendering.items() if flag != "--output" and value is not None]
        if missing or given:
            parser.error("amendment requires --amend-unit, --rate-config-receipt and --output, with no rendering inputs")
        try:
            print(amend_unit(args.role, args.amend_unit, args.rate_config_receipt, args.output))
        except (OSError, ValueError, SyntaxError, RecursionError) as error:
            parser.exit(1, f"{parser.prog}: unit not amended: {error}\n")
        return
    missing = [flag for flag in ("--runtime-key", "--output") if rendering[flag] is None]
    if missing:
        parser.error("the following arguments are required to render: " + ", ".join(missing))
    if args.output.name != f"iroha3d-{args.role}.service":
        parser.error("output filename must match the canonical role unit name")
    try:
        content = render(args.role, args.runtime_key, args.global_beacon_credential,
                         config_file=args.config_file or "config.toml").encode()
    except ValueError as error:
        parser.error(str(error))
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(content)
        output.flush()
        # Match the native validator_unit artifact role even under UMask=0077.
        # Publish only the completed public unit; signer files are never opened.
        os.fchmod(output.fileno(), 0o644)
        os.fsync(output.fileno())
    print(args.output)


if __name__ == "__main__":
    main()
