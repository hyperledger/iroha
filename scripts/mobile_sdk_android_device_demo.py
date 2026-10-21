#!/usr/bin/env python3
"""Explicit ARM64 physical-device demo admission. Never a release/all-ABI artifact.

Capture only the first genuinely promoted ABI from an ongoing maintained producer.
No Rust/Gradle invocation, source edit, shared-output write, or app installation.
"""
from pathlib import Path
import argparse, hashlib, json, os, re, shutil, stat, struct, subprocess, tempfile

SCHEMA = 'iroha.android-device-demo-native.v1'
ABI = 'arm64-v8a'
TARGET = 'aarch64-linux-android'
EVIDENCE = {'source-seal.json', 'build-environment.json', 'producer-receipt.json',
            'compiler-command.json', 'cabi-receipt.json', 'jni-receipt.json'}
LIB = 'jni/arm64-v8a/libconnect_norito_bridge.so'
RAW = 'raw/arm64-v8a/libconnect_norito_bridge.so'

def require(value, message):
    if not value:
        raise ValueError(message)

def directory(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_dir(),
            f'Not a canonical directory: {path}')
    return path

def original(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, f'Not a canonical file: {path}')
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid(),
            f'Not an owned single-link regular original: {path}')
    require(0 < before.st_size <= 1024 ** 3, f'Invalid input size: {path}')
    data = path.read_bytes()
    after = path.stat()
    require((before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_ino, after.st_size, after.st_mtime_ns), f'Input changed while reading: {path}')
    return data

def digest(data):
    return hashlib.sha256(data).hexdigest()

def document(path):
    return json.loads(original(path))

def elf(data):
    require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01', 'Not ARM64 little-endian ELF64')
    h = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    kind, machine, version, _, off, _, _, ehsize, entsize, count, *_ = h
    require((kind, machine, version, ehsize, entsize) == (3, 183, 1, 64, 56), 'Wrong ELF identity')
    require(0 < count < 65535 and 64 <= off <= len(data) - count * entsize, 'Invalid ELF headers')
    loads = 0
    for i in range(count):
        kind, _, offset, address, _, size, memory, alignment = struct.unpack_from('<IIQQQQQQ', data, off + i * entsize)
        if kind != 1:
            continue
        loads += 1
        require(alignment >= 16384 and alignment & (alignment - 1) == 0 and
                (address - offset) % alignment == 0 and size <= memory and
                offset <= len(data) and size <= len(data) - offset, 'Invalid or non-16KB LOAD segment')
    require(loads > 0, 'No ELF LOAD segments')

def toolchain(ndk):
    ndk = directory(ndk)
    source = original(ndk / 'source.properties')
    require(b'28.0.12674087' in source, 'Wrong NDK source.properties')
    bins = list((ndk / 'toolchains/llvm/prebuilt').glob('*/bin/llvm-strip'))
    require(len(bins) == 1, 'Expected one pinned NDK llvm-strip')
    strip = bins[0].resolve(strict=True)
    nm = bins[0].with_name('llvm-nm').resolve(strict=True)
    require(strip.is_file() and nm.is_file() and strip.parent == bins[0].parent.resolve() and
            nm.parent == bins[0].parent.resolve(), 'Missing or redirected NDK strip/symbol tools')
    return strip, nm, digest(source)

def check_symbols(data_path, root, nm):
    src = root / 'kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/crypto/NativeSignerBridge.kt'
    methods = re.findall(r'external fun\s+(\w+)\s*\(', original(src).decode())
    require(methods and len(methods) == len(set(methods)), 'Invalid current signer JNI contract')
    required = {'Java_org_hyperledger_iroha_sdk_crypto_NativeSignerBridge_' + m for m in methods}
    required.add('connect_norito_detached_transaction_scaffold_inspect_v1')
    symbols = subprocess.check_output([str(nm), '-D', '--defined-only', str(data_path)], text=True)
    exports = {line.split()[-1] for line in symbols.splitlines() if line.split()}
    require(required <= exports, 'Missing current JNI/C exports: ' + ','.join(sorted(required - exports)))

def validate(artifact, root, ndk):
    artifact, root = directory(artifact), directory(root)
    require(artifact != root and root not in artifact.parents, 'Demo artifact must be outside source')
    require(artifact.stat().st_uid == os.getuid() and stat.S_IMODE(artifact.stat().st_mode) == 0o700, 'Demo artifact directory must be owned and mode 0700')
    files = {str(x.relative_to(artifact)) for x in artifact.rglob('*') if x.is_file()}
    require(files == {'receipt.json', LIB, RAW} | EVIDENCE, 'Unexpected or incomplete demo artifact inventory')
    require(not any(x.is_symlink() for x in artifact.rglob('*')), 'Symlink in demo artifact')
    m = document(artifact / 'receipt.json')
    require(m['schema'] == SCHEMA and m['artifact_scope'] == 'physical-device-demo' and
            m['status'] == 'qualified-arm64-device-demo', 'Wrong artifact type/status')
    require(m['abi'] == ABI and m['target'] == TARGET and m['native_bridge_abi_version'] == 31 and
            m['native_signer_contract_revision'] == 7, 'Wrong native ABI/signer contract')
    require(m['source_root'] == str(root), 'Different source checkout')
    commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    require(m['source_commit'] == commit, 'Device demo requires current selected source commit')
    require(m['producer_stage'] == 'arm64-promoted-full-producer-continues', 'Wrong producer boundary')
    require(set(m['evidence']) == EVIDENCE, 'Wrong evidence inventory')
    docs = {}
    for name in EVIDENCE:
        data = original(artifact / name)
        require(digest(data) == m['evidence'][name], f'Changed evidence: {name}')
        docs[name] = json.loads(data)
    seal, env, producer, cmd = (docs[n] for n in ('source-seal.json', 'build-environment.json', 'producer-receipt.json', 'compiler-command.json'))
    require(seal['schema'] == 'iroha.norito-bridge-source-seal.v1' and seal['platform'] == 'android' and
            seal['source_commit'] == commit and seal['source_fingerprint_sha256'] == m['source_fingerprint_sha256'], 'Source seal mismatch')
    require(producer['status'] in ('running', 'passed') and producer['sourceCommit'] == commit and
            producer['sourceRoot'] == str(root) and producer['artifactRoot'] == m['producer_artifact_root'], 'Producer origin mismatch')
    require(cmd['sourceCommit'] == commit and cmd['target'] == TARGET and
            '--crate-name' in cmd['argv'] and cmd['argv'][cmd['argv'].index('--crate-name') + 1] == 'connect_norito_bridge', 'Compiler origin mismatch')
    require(env['environment_profile'] == 'android-cargo' and env['cargo_build_jobs'] == 1 and
            env['rust_toolchain_channel'] == '1.93.1', 'Unexpected producer environment')
    for key, name in [('wallet_runtime_authority', 'MOBILE_SDK_WALLET_RUNTIME_AUTHORITY'),
                      ('wallet_runtime_trust_ed25519_hex', 'MOBILE_SDK_WALLET_RUNTIME_TRUST_ED25519_HEX')]:
        require(os.environ.get(name) and env[key] == os.environ[name], 'Runtime trust selection differs from compiled native original')
    strip, nm, ndk_sha = toolchain(ndk)
    require(env['android_ndk_source_properties_sha256'] == ndk_sha, 'NDK differs from producer')
    item = m['library']
    require(item['path'] == LIB and item['raw_path'] == RAW, 'Wrong library paths')
    raw, native = original(artifact / RAW), original(artifact / LIB)
    require(len(raw) == item['raw_bytes'] and digest(raw) == item['raw_sha256'] and
            len(native) == item['bytes'] and digest(native) == item['sha256'], 'Native library byte mismatch')
    producer_root = directory(m['producer_artifact_root'])
    promoted = producer_root / 'gradle-build/iroha_kotlin_sdk/client-android/native/cargo-ndk/production/arm64-v8a/libconnect_norito_bridge.so'
    require(digest(original(promoted)) == item['raw_sha256'], 'Demo raw bytes differ from genuine promoted original')
    elf(raw); elf(native); check_symbols(artifact / LIB, root, nm)
    with tempfile.TemporaryDirectory(prefix='iroha-device-demo-strip-') as temporary:
        check = Path(temporary) / 'libconnect_norito_bridge.so'; check.write_bytes(raw)
        subprocess.run([str(strip), '--strip-unneeded', str(check)], check=True,
                       env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
        require(digest(check.read_bytes()) == item['sha256'], 'Stripped bytes do not reproduce from raw original')
    for name in ('cabi-receipt.json', 'jni-receipt.json'):
        probe = docs[name]
        require(probe['status'] == 'passed' and probe.get('exitCode') == 0, f'Physical probe failed: {name}')
        require(any(Path(p).name == 'libconnect_norito_bridge.so' and value == item['raw_sha256']
                    for p, value in probe['inputs'].items()), f'Physical probe used different raw bytes: {name}')
    cabi, jni = docs['cabi-receipt.json'], docs['jni-receipt.json']
    require(cabi['currentDtoFieldCompatible'] and cabi['truncatedInputRejected'] and cabi['appleHostInspectionExactlyEqual'], 'C ABI contract probe failed')
    result = jni['result']
    require(result['nativeAvailable'] and result['malformedNativeInputRefused'] and result['oldNineFieldOutputRefused'], 'ART JNI/strict DTO probe failed')
    require(cabi['serial'] == jni['serial'], 'Physical probes must qualify the same attached device')
    return m

def capture(args):
    producer, root = directory(args.producer), directory(args.root)
    destination = Path(args.artifact_dir)
    require(destination.is_absolute() and not destination.exists() and directory(destination.parent) == destination.parent, 'Capture requires new canonical external directory')
    require(root not in destination.parents, 'Capture must be outside source')
    native = producer / 'gradle-build/iroha_kotlin_sdk/client-android/native'
    raw_path = native / 'cargo-ndk/production/arm64-v8a/libconnect_norito_bridge.so'
    raw = original(raw_path)
    producer_receipt = document(producer / 'receipt.json')
    require(producer_receipt['status'] in ('running', 'passed'), 'Producer failed or was stopped')
    # This line can only be emitted by the next cargo-ndk invocation after the
    # maintained producer's ARM64 immediate post-promotion source authentication.
    log = original(producer / 'producer.log').decode(errors='strict')
    require('Building armeabi-v7a (armv7-linux-androideabi)' in log or producer_receipt['status'] == 'passed', 'ARM64 post-promotion boundary has not completed')
    sources = {'source-seal.json': native / 'sourceSeal/production/source-seal-v1.json',
               'build-environment.json': native / 'buildEnvironment/production/build-environment-v1.json',
               'producer-receipt.json': producer / 'receipt.json',
               'compiler-command.json': producer / 'compiler-commands/aarch64-linux-android.json',
               'cabi-receipt.json': Path(args.cabi_receipt), 'jni-receipt.json': Path(args.jni_receipt)}
    evidence = {name: original(path) for name, path in sources.items()}
    seal = json.loads(evidence['source-seal.json'])
    # The public candidate path never exists until all byte/probe checks pass.
    published_destination = destination
    destination = Path(tempfile.mkdtemp(prefix=destination.name + '.pending-', dir=destination.parent)).resolve()
    for rel, data in [(RAW, raw), (LIB, raw), *evidence.items()]:
        output = destination / rel; output.parent.mkdir(parents=True, exist_ok=True); output.write_bytes(data)
    strip, _, _ = toolchain(args.ndk)
    subprocess.run([str(strip), '--strip-unneeded', str(destination / LIB)], check=True,
                   env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
    stripped = original(destination / LIB)
    m = {'schema': SCHEMA, 'artifact_scope': 'physical-device-demo', 'status': 'qualified-arm64-device-demo',
         'abi': ABI, 'target': TARGET, 'native_bridge_abi_version': 31, 'native_signer_contract_revision': 7,
         'source_root': str(root), 'source_commit': seal['source_commit'],
         'source_fingerprint_sha256': seal['source_fingerprint_sha256'], 'producer_artifact_root': str(producer),
         'producer_stage': 'arm64-promoted-full-producer-continues',
         'library': {'path': LIB, 'bytes': len(stripped), 'sha256': digest(stripped),
                     'raw_path': RAW, 'raw_bytes': len(raw), 'raw_sha256': digest(raw)},
         'evidence': {name: digest(data) for name, data in evidence.items()}}
    (destination / 'receipt.json').write_text(json.dumps(m, indent=2) + '\n')
    try:
        validate(destination, root, args.ndk)
    except Exception:
        (destination / 'receipt.json').unlink()
        raise
    require(not published_destination.exists(), 'Candidate destination appeared during validation')
    destination.rename(published_destination)
    return m

def main():
    p = argparse.ArgumentParser();p.add_argument('--root', required=True);p.add_argument('--ndk', required=True)
    p.add_argument('--artifact-dir', required=True);p.add_argument('--producer');p.add_argument('--cabi-receipt');p.add_argument('--jni-receipt');p.add_argument('--output-dir')
    args = p.parse_args()
    if args.producer:
        require(args.cabi_receipt and args.jni_receipt and not args.output_dir, 'Capture requires physical probe receipts')
        m = capture(args)
    else:
        require(not args.cabi_receipt and not args.jni_receipt, 'Unexpected capture arguments')
        m = validate(args.artifact_dir, args.root, args.ndk)
    if args.output_dir:
        target = Path(args.output_dir)
        build_root = directory(os.environ.get('MOBILE_SDK_ANDROID_ARTIFACT_DIR', ''))
        expected = build_root / 'gradle-build/iroha_kotlin_sdk/client-android/generated/deviceDemoNative'
        require(target == expected and target.resolve(strict=False) == target, 'Consumer output must be the dedicated external SDK generated directory')
        require(Path(args.root).resolve() not in target.parents and target not in Path(args.artifact_dir).parents, 'Consumer output overlaps source/artifact')
        if target.exists():shutil.rmtree(target)
        (target / 'jni/arm64-v8a').mkdir(parents=True)
        shutil.copyfile(Path(args.artifact_dir) / LIB, target / LIB)
        (target / 'assets/iroha').mkdir(parents=True)
        shutil.copyfile(Path(args.artifact_dir) / 'receipt.json', target / 'assets/iroha/android-device-demo-native-v1.json')
        require(digest(original(target / LIB)) == m['library']['sha256'], 'Consumer copy changed')
    print(json.dumps(m, sort_keys=True))
if __name__ == '__main__':
    main()
