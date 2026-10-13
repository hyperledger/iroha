#!/usr/bin/env python3
"""Compare every CRT table word with the pinned, unmodified upstream C++ generator.

Explicit maintainer command (network and a C++17 compiler required); ordinary
tests remain offline. No Rust/Python generator is used to produce the C headers.
"""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import urllib.request

COMMIT = "4fb6b71143b37764546b7c7729440d9cd8898a5e"
SOURCES = {
    "tables/vole_mult_tables.cpp": "be86cf83d69aa0eb8be73837d5bb0497df522f94e88c00a8f0d57cbf2094e241",
    "meson.build": "70596e5c4dc8cdec882b6f1b2628bfc1c159a11738910b599a76f4eed3af5d28",
    "macros.h": "3618d70932217eb5160948fe5cb931605244719dd316858afb7c8a8a44ba3aa6",
    "faest_defines.h": "0cc8f1e4ec00b621300ed006da66ae5d792e39ff8992b50ade2700fa125ae091",
}
PRESETS = ("128s", "128f", "192s", "192f", "256s", "256f", "em_192s", "em_192f")
PARTS = ("TREE_MODULI", "M_TREE", "F", "G", "W_TREE", "W_GATE", "W_CRT")


def parameters(meson):
    """Extract numeric configuration exactly as Meson's parameter_data loop does."""
    names = dict(re.findall(r"(param_\w+)\.set\('PARAM', '([A-Z0-9_]+)'\)", meson))
    if len(names) != 12:
        raise ValueError("expected twelve upstream parameter configurations")
    values = {}
    for variable, key, value in re.findall(r"(param_\w+)\.set\('(\w+)', (\d+)\)", meson):
        values[f"FAEST_{names[variable]}_{key}"] = int(value)
    for key, value in re.findall(r"parameter_data\.set\('(FAEST_\d+_LAMBDA)', (\d+)\)", meson):
        values[key] = int(value)
    if len([key for key in values if re.fullmatch(r"FAEST_\d+_LAMBDA", key)]) != 3:
        raise ValueError("missing upstream security-level macros")
    return values


def array(text, pattern, literal):
    match = re.search(pattern, text, re.S)
    if match is None:
        raise ValueError(f"array missing: {pattern}")
    body = match[1]
    values = [int(value.replace("_", ""), 16) for value in re.findall(literal, body)]
    remainder = re.sub(literal, "", body)
    if re.sub(r"[\s{},]", "", remainder):
        raise ValueError("unexpected array syntax")
    return values


def compare(work, rust_dir, values, preset):
    header = work / f"tables_{preset}.h"
    subprocess.run([str(work / "generator"), "--preset", preset, "--emit-c", str(header)],
                   check=True, timeout=1200)
    upstream = header.read_text()
    rust = (rust_dir / f"faest_{preset}_tables.rs").read_text()
    prefix = f"FAEST_{preset.upper()}"
    macros = dict((key, int(value)) for key, value in
                  re.findall(r"#define (\w+) (\d+)\n", upstream))
    constants = dict((key, int(value)) for key, value in
                     re.findall(r"pub const (\w+): u32 = (\d+);", rust))
    scalar_values = {
        "LAMBDA": values[f"{prefix}_LAMBDA"],
        "TAU": values[f"{prefix}_TAU"],
        "W_GRIND": macros[f"{prefix}_WGRIND"],
        "N_MULT": macros[f"{prefix}_NGATES"],
    }
    scalar_values["N_DELTA"] = scalar_values["LAMBDA"] - scalar_values["W_GRIND"]
    if constants != scalar_values:
        raise ValueError(f"{preset}: scalar mismatch")
    words = [int.from_bytes(b"FAESTCRT", "little")]
    words.extend(scalar_values[key] for key in ("LAMBDA", "TAU", "W_GRIND", "N_MULT"))
    for part in PARTS:
        c_words = array(upstream, rf"static const uint(?:16|64)_t {prefix}_{part}\[[^=]+?= \{{(.*?)\}};",
                        r"UINT(?:16|64)_C\((0x[0-9a-f]+)\)")
        rust_words = array(rust, rf"pub static {part}: \[u(?:16|64); \d+\] = \[(.*?)\];",
                           r"(0x[0-9a-f_]+)")
        if c_words != rust_words:
            raise ValueError(f"{preset}: {part} differs")
        words.extend(c_words)
    encoded = b"".join(word.to_bytes(8, "little") for word in words)
    return (f"{preset} words={len(words)} canonical_sha3_256={hashlib.sha3_256(encoded).hexdigest()} "
            f"upstream_header_sha256={hashlib.sha256(header.read_bytes()).hexdigest()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--cxx", default="c++")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    for source, expected in SOURCES.items():
        destination = work / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            url = f"https://raw.githubusercontent.com/faest-sign/faest-ref/{COMMIT}/{source}"
            with urllib.request.urlopen(url, timeout=30) as response:
                destination.write_bytes(response.read())
        if hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
            raise ValueError(f"pinned source hash mismatch: {source}")
    values = parameters((work / "meson.build").read_text())
    (work / "parameters.h").write_text("".join(f"#define {key} {value}\n" for key, value in sorted(values.items())))
    subprocess.run([args.cxx, "-std=c++17", "-O2", str(work / "tables/vole_mult_tables.cpp"),
                    "-o", str(work / "generator")], check=True, timeout=1200)
    rust_dir = Path(__file__).resolve().parents[3] / "src/crt/generated"
    lines = [f"commit={COMMIT}"]
    for preset in PRESETS:
        line = compare(work, rust_dir, values, preset)
        lines.append(line)
        print(line, flush=True)
    result = "\n".join(lines) + "\n"
    (work / "comparison.txt").write_text(result)
    expected = Path(__file__).with_name("upstream_crt_comparison.txt").read_text()
    if result != expected:
        raise ValueError("comparison record differs from the pinned result")


if __name__ == "__main__":
    main()
