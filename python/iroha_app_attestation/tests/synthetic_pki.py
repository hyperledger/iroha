"""Cryptographically signed synthetic X.509 and KeyMint builders for tests only.

Every root here is a throwaway test key. These fixtures qualify component code only; they are
never Google, Huawei or Apple roots, device evidence or production qualification.
"""
from __future__ import annotations

import hashlib
import subprocess
import time
from pathlib import Path

from iroha_app_attestation.attestation import (
    ANDROID_KEY_DESCRIPTION_OID, ANDROID_PROVISIONING_INFORMATION_OID, APPLE_NONCE_OID,
    children, der_one, primitive,
)

SIGNER = b"\x71" * 32
PACKAGE = "org.example.wallet"
DAY_MS = 86_400_000


def der(tag: bytes, value: bytes) -> bytes:
    length = len(value)
    encoded = (bytes([length]) if length < 128 else
               bytes([0x80 | ((length.bit_length() + 7) // 8)])
               + length.to_bytes((length.bit_length() + 7) // 8, "big"))
    return tag + encoded + value


def sequence(*parts: bytes) -> bytes:
    return der(b"\x30", b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    return der(b"\x31", b"".join(parts))


def integer(value: int, tag: bytes = b"\x02") -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] >= 128:
        raw = b"\0" + raw
    return der(tag, raw)


def octets(value: bytes) -> bytes:
    return der(b"\x04", value)


def null() -> bytes:
    return b"\x05\x00"


def boolean(value: bool) -> bytes:
    return der(b"\x01", b"\xff" if value else b"\x00")


def explicit(number: int, value: bytes) -> bytes:
    if number < 31:
        return der(bytes([0xa0 | number]), value)
    components = [number & 127]
    number >>= 7
    while number:
        components.insert(0, 0x80 | (number & 127))
        number >>= 7
    return der(b"\xbf" + bytes(components), value)


def cbor(value) -> bytes:
    if isinstance(value, int):
        major, length = (0, value) if value >= 0 else (1, -1 - value)
        payload = b""
    elif isinstance(value, bytes):
        major, length, payload = 2, len(value), value
    elif isinstance(value, str):
        payload = value.encode("utf-8")
        major, length = 3, len(payload)
    elif isinstance(value, list):
        payload = b"".join(map(cbor, value))
        major, length = 4, len(value)
    else:
        payload = b"".join(cbor(key) + cbor(item) for key, item in value.items())
        major, length = 5, len(value)
    if length < 24:
        return bytes([(major << 5) | length]) + payload
    if length < 256:
        return bytes([(major << 5) | 24, length]) + payload
    if length < 65536:
        return bytes([(major << 5) | 25]) + length.to_bytes(2, "big") + payload
    return bytes([(major << 5) | 26]) + length.to_bytes(4, "big") + payload


def app_identity(packages=((PACKAGE, 7),), signers=(SIGNER,)) -> bytes:
    return sequence(set_of(*(sequence(octets(name.encode()), integer(version))
                             for name, version in packages)),
                    set_of(*(octets(signer) for signer in signers)))


def key_description(challenge: bytes, *, attestation_version: int = 300,
                    keymint_version: int | None = None, level: int = 2,
                    keymint_level: int | None = None, packages=((PACKAGE, 7),),
                    signers=(SIGNER,), app_list: str | None = "software",
                    boot_key: bytes = b"\x51" * 32, locked: bool = True, state: int = 0,
                    boot_hash: bytes | None | str = "default", purpose=(2,), algorithm: int = 3,
                    key_size: int = 256, digest=(4,), curve: int = 1, origin: int = 0,
                    os_patch_level: int | None = None, vendor_patch_level: int | None = 20260805,
                    boot_patch_level: int | None = None, hardware_extra=None,
                    software_extra=None, hardware_fields=None, software_fields=None) -> bytes:
    """One KeyMint KeyDescription for the given exact challenge bytes."""
    keymint_version = attestation_version if keymint_version is None else keymint_version
    keymint_level = level if keymint_level is None else keymint_level
    if boot_hash == "default":
        boot_hash = None if attestation_version == 2 else b"\x52" * 32
    boot = sequence(octets(boot_key), boolean(locked), integer(state, b"\x0a"),
                    *([] if boot_hash is None else [octets(boot_hash)]))
    hardware = {1: set_of(*(integer(p) for p in purpose)), 2: integer(algorithm),
                3: integer(key_size), 5: set_of(*(integer(d) for d in digest)),
                10: integer(curve), 702: integer(origin), 704: boot}
    if os_patch_level is not None:
        hardware[706] = integer(os_patch_level)
    if vendor_patch_level is not None and attestation_version >= 3:
        hardware[718] = integer(vendor_patch_level)
    if boot_patch_level is not None and attestation_version >= 3:
        hardware[719] = integer(boot_patch_level)
    software: dict = {}
    identity = octets(app_identity(packages, signers))
    if app_list in ("software", "both"):
        software[709] = identity
    if app_list in ("hardware", "both"):
        hardware[709] = identity
    hardware.update(hardware_extra or {})
    software.update(software_extra or {})
    if hardware_fields is None:
        hardware_fields = [explicit(tag, hardware[tag]) for tag in sorted(hardware)]
    if software_fields is None:
        software_fields = [explicit(tag, software[tag]) for tag in sorted(software)]
    return sequence(integer(attestation_version), integer(level, b"\x0a"),
                    integer(keymint_version), integer(keymint_level, b"\x0a"),
                    octets(challenge), octets(b""), sequence(*software_fields),
                    sequence(*hardware_fields))


def extension_line(oid: str, value: bytes, critical: bool = False) -> str:
    return (oid + "=" + ("critical," if critical else "") + "DER:"
            + ":".join(f"{byte:02X}" for byte in value))


class SyntheticPki:
    """Throwaway X.509 hierarchy minted with the selected OpenSSL CLI."""

    def __init__(self, directory: Path, openssl: Path) -> None:
        self.directory, self.openssl = directory, openssl
        self.serial = 4096

    def run(self, *arguments: str) -> bytes:
        return subprocess.run([str(self.openssl), *arguments], cwd=self.directory,
                              capture_output=True, check=True).stdout

    def key(self, name: str, kind: str = "ec256") -> bytes:
        if kind == "rsa":
            self.run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                     "-out", name + ".key")
        else:
            curve = "P-384" if kind == "ec384" else "P-256"
            self.run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:" + curve,
                     "-out", name + ".key")
        self.run("pkey", "-in", name + ".key", "-pubout", "-outform", "DER", "-out", name + ".spki")
        return (self.directory / (name + ".spki")).read_bytes()

    def point(self, name: str) -> bytes:
        spki = children(der_one((self.directory / (name + ".spki")).read_bytes()))
        return primitive(spki[1], 3)[1:]

    def _next_serial(self, serial: int | None) -> str:
        if serial is None:
            self.serial += 1
            serial = self.serial
        return str(serial)

    def root(self, name: str, subject: str, kind: str = "ec256", *, days: int = 2,
             serial: int | None = None, extensions=()) -> bytes:
        self.key(name, kind)
        lines = ["basicConstraints=critical,CA:TRUE", "keyUsage=critical,keyCertSign,cRLSign",
                 *extensions]
        config = self.directory / (name + ".cnf")
        config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\n[ext]\n"
                          + "\n".join(lines) + "\n")
        self.run("req", "-x509", "-new", "-key", name + ".key", "-out", name + ".pem",
                 "-days", str(days), "-subj", subject, "-set_serial", self._next_serial(serial),
                 "-config", str(config), "-sha256")
        return self.der(name)

    def issue(self, name: str, issuer: str, subject: str, *, kind: str = "ec256",
              ca: bool = True, extensions=(), days: int = 2, serial: int | None = None,
              new_key: bool = True) -> bytes:
        if new_key:
            self.key(name, kind)
        self.run("req", "-new", "-key", name + ".key", "-subj", subject, "-out", name + ".csr")
        lines = (["basicConstraints=critical,CA:TRUE", "keyUsage=critical,keyCertSign"]
                 if ca else [])
        lines.extend(extensions)
        config = self.directory / (name + ".ext")
        config.write_text("\n".join(lines) + "\n")
        self.run("x509", "-req", "-in", name + ".csr", "-CA", issuer + ".pem",
                 "-CAkey", issuer + ".key", "-set_serial", self._next_serial(serial),
                 "-days", str(days), "-extfile", str(config), "-out", name + ".pem", "-sha256")
        return self.der(name)

    def der(self, name: str) -> bytes:
        self.run("x509", "-in", name + ".pem", "-outform", "DER", "-out", name + ".der")
        return (self.directory / (name + ".der")).read_bytes()

    def leaf(self, name: str, issuer: str, description: bytes, *, extensions=(),
             new_key: bool = True, serial: int | None = None) -> bytes:
        return self.issue(name, issuer, "/CN=Android Keystore Key", ca=False,
                          extensions=(extension_line(ANDROID_KEY_DESCRIPTION_OID, description),
                                      *extensions),
                          new_key=new_key, serial=serial)


PROVISIONING_INFORMATION = extension_line(ANDROID_PROVISIONING_INFORMATION_OID, cbor({1: 1}))


def factory_hierarchy(pki: SyntheticPki, root_kind: str = "rsa") -> None:
    """Synthetic shape of a documented factory-provisioned chain under an RSA-root family."""
    pki.root("root", "/serialNumber=f92009e853b6b045", root_kind)
    pki.issue("intermediate", "root", "/serialNumber=87f4514475ba0a2b")
    pki.issue("attestation", "intermediate", "/serialNumber=c6047571d8f0d17c/title=TEE")


def remote_hierarchy(pki: SyntheticPki, root_kind: str = "rsa", *, root_name: str = "root",
                     root_subject: str = "/serialNumber=f92009e853b6b045") -> None:
    """Synthetic shape of a remotely provisioned (RKP) chain with provisioning information."""
    pki.root(root_name, root_subject, root_kind)
    pki.issue("intermediate", root_name, "/CN=Droid CA2/O=Google LLC")
    pki.issue("attestation", "intermediate", "/CN=7d3a8e01/O=TEE",
              extensions=(PROVISIONING_INFORMATION,))


def now_ms() -> int:
    # Certificates are minted after this call; keep a minute of margin inside validity.
    return int(time.time() * 1000) + 60_000


class SignedEnvelope:
    """Synthetic EC root and leaf for Apple App Attest component tests."""

    def __init__(self, directory: Path, openssl: Path) -> None:
        self.directory = directory
        self.openssl = openssl
        self.run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                 "-nodes", "-keyout", "root.key", "-out", "root.pem", "-days", "2",
                 "-subj", "/CN=Synthetic Root", "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        self.run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                 "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=Synthetic Leaf")
        self.run("pkey", "-in", "leaf.key", "-pubout", "-outform", "DER", "-out", "leaf.spki")
        spki = children(der_one((directory / "leaf.spki").read_bytes()))
        self.point = primitive(spki[1], 3)[1:]

    def run(self, *arguments: str) -> None:
        subprocess.run([str(self.openssl), *arguments], cwd=self.directory,
                       capture_output=True, check=True)

    def sign(self, extension_oid: str, extension_der: bytes) -> tuple:
        extension = self.directory / "extension.cnf"
        extension.write_text(extension_line(extension_oid, extension_der) + "\n")
        self.run("x509", "-req", "-in", "leaf.csr", "-CA", "root.pem", "-CAkey", "root.key",
                 "-CAcreateserial", "-out", "leaf.pem", "-days", "2", "-extfile", "extension.cnf")
        self.run("x509", "-in", "root.pem", "-outform", "DER", "-out", "root.der")
        self.run("x509", "-in", "leaf.pem", "-outform", "DER", "-out", "leaf.der")
        return (self.directory / "leaf.der").read_bytes(), (self.directory / "root.der").read_bytes()

    def root_der(self) -> bytes:
        self.run("x509", "-in", "root.pem", "-outform", "DER", "-out", "root.der")
        return (self.directory / "root.der").read_bytes()


APP_ID = "TEAMID.example.app"


def apple_object(fixture: SignedEnvelope, challenge_digest: bytes, *, app_id: str = APP_ID,
                 aaguid: bytes = b"appattest" + b"\0" * 7):
    key_id = hashlib.sha256(fixture.point).digest()
    cose = cbor({1: 2, 3: -7, -1: 1, -2: fixture.point[1:33], -3: fixture.point[33:]})
    auth = (hashlib.sha256(app_id.encode()).digest() + b"\x40" + b"\0" * 4
            + aaguid + b"\0\x20" + key_id + cose)
    nonce = hashlib.sha256(auth + challenge_digest).digest()
    leaf, root = fixture.sign(APPLE_NONCE_OID, sequence(explicit(1, octets(nonce))))
    obj = cbor({"fmt": "apple-appattest",
                "attStmt": {"x5c": [leaf, root], "receipt": b"synthetic receipt"},
                "authData": auth})
    return obj, key_id, root


def apple_assertion(fixture: SignedEnvelope, client_data_hash: bytes, counter: int,
                    app_id: str = APP_ID) -> bytes:
    auth = hashlib.sha256(app_id.encode()).digest() + b"\x40" + counter.to_bytes(4, "big")
    (fixture.directory / "assertion-message.bin").write_bytes(
        hashlib.sha256(auth + client_data_hash).digest())
    fixture.run("dgst", "-sha256", "-sign", "leaf.key", "-out", "assertion-signature.bin",
                "assertion-message.bin")
    return cbor({"signature": (fixture.directory / "assertion-signature.bin").read_bytes(),
                 "authenticatorData": auth})
