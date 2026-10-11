"""Inert source/USTAR fixtures; no SDK imports, installation, or qualification."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import sorafs_javascript_dependencies as dependencies

CHECKSUM = b'{"component_control":"opaque original manifest; not native qualification"}'
# Reviewed census of the captured candidate, shared by every SoraFS JavaScript
# test so that adding or removing an SDK module changes it in one place.
SOURCE_FILES = 234
PROJECTED_MEMBERS = 231
PROJECTED_DIST_MEMBERS = 193
INSTALLED_MEMBERS = 250
REQUIRED_OUTPUTS = (
    "address.js", "atomicPrivateSettlement.js", "browser.js", "curveRegistry.js",
    "ivmArtifact.js", "native.js", "nativeArtifactHash.js", "numericV1.js",
    "strictLosslessJson.js", "boundedByteSnapshot.js", "validationFeeTrust.js", "sorafsOrderbookPreflight.js", "sorafsOrderbookSubmission.js", "sorafsOrderbookSubmission.d.ts",
    "smartContractDeploymentSubmit.js", "sumeragiTyped.js", "tairaTestnetProfile.js",
    "toriiBrowserClient.js", "toriiClient.js", "toriiOptional.js", "kotodamaCompiler/index.js",
    "kotodamaCompiler/browser.js", "kotodamaCompiler/client.js",
    "kotodamaCompiler/embeddedCallSchema.js", "kotodamaCompiler/embeddedNorito.js",
    "kotodamaCompiler/nativeBridge.js",
    "kotodamaCompiler/normalize.js",
)


def source_inputs():
    package = ROOT / "javascript/iroha_js"
    recipe = json.loads((package / "package.json").read_bytes())
    names = set(recipe["files"]) - {"dist", "native/iroha_js_host.checksums.json"}
    names |= {"recipes/README.md", "scripts/build-dist.mjs", "scripts/check-node-engine.mjs",
              "scripts/node-engine-contract.mjs", "package-lock.json"}
    names |= {str(path.relative_to(package)) for path in (package / "src").rglob("*") if path.is_file()}
    sources = {name: (package / name).read_bytes() for name in sorted(names)}
    raw = sources["package-lock.json"]
    lock = dependencies.parse_dependency_lock(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    return sources, lock


def expected_files(sources, checksum=CHECKSUM):
    recipe = json.loads(sources["package.json"])
    result = {name: sources[name] for name in set(recipe["files"]) - {"dist", "native/iroha_js_host.checksums.json"}}
    result["recipes/README.md"] = sources["recipes/README.md"]
    result.update({"dist/" + name.removeprefix("src/"): body for name, body in sources.items() if name.startswith("src/")})
    result["native/iroha_js_host.checksums.json"] = checksum
    return result


def archive_bytes(files, *, modes=None, extra_rows=(), reverse=False):
    """Use stdlib's independent writer; the production owner alone parses."""
    rows = sorted(files.items(), reverse=reverse) + list(extra_rows)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as target:
        for name, body in rows:
            entry = tarfile.TarInfo("package/" + name)
            entry.size, entry.mode, entry.mtime = len(body), (modes or {}).get(name, 0o644), 499162500
            target.addfile(entry, io.BytesIO(body))
    return gzip.compress(output.getvalue(), mtime=0)
