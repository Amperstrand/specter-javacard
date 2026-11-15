#!/usr/bin/env python3
"""Validate satochip-protocol.yaml against pinned Toporin SatochipApplet tags.

The sync mechanism of the contract pipeline: constants (INS/SW/CLA) and
handler names are extracted from the applet source at each pinned tag and
compared with the checked-in spec. Any upstream renumbering, addition, or
removal fails the check with a precise diff — semantic review happens on
the diff, not by archaeology.

Also emits Rust constants (--emit-rust) consumed by
../satochip-client/src/protocol.rs (checked in; regenerate + diff in CI).

Usage:
  ./extract_apdu_spec.py [--source-cache DIR] [--emit-rust FILE] [TAG ...]
      default: validate all tags in the spec
      --source-cache DIR: reuse a dir with <tag>/ holding the .java files
"""
import argparse
import os
import re
import sys
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "spec", "satochip-protocol.yaml")

RAW = "https://raw.githubusercontent.com/Toporin/SatochipApplet/{tag}/{prefix}/{file}"
# java files parsed per tag: the applet + files carrying SW constants
TAG_FILES = {
    "v0.14-0.2": ["CardEdge.java", "Bip32ObjectManager.java"],
    "v0.16-0.1": ["Satochip.java", "SecureChannel.java"],
}

INS_RE = re.compile(r"\bbyte\s+(INS_\w+)\s*=\s*\(byte\)\s*0x([0-9A-Fa-f]+)")
SW_RE = re.compile(r"\bshort\s+(SW_\w+)\s*=\s*\(short\)\s*0x([0-9A-Fa-f]+)")
SW_REF_RE = re.compile(r"\bshort\s+(SW_\w+)\s*=\s*(\w+)\.SW_\w+")
CLA_RE = re.compile(r"\bbyte\s+CardEdge_CLA\s*=\s*\(byte\)\s*0x([0-9A-Fa-f]+)")
METHOD_RE = re.compile(
    r"\b\w+\s+(\w+)\s*\(\s*(?:final\s+)?(?:APDU|byte)", re.MULTILINE)
# dispatch call targets ("sizeout= Handler(apdu, buffer)" / zero-arg calls)
CALL_RE = re.compile(r"sizeout=\s*(\w+)\(")


def load_tag(tag, source_prefix, cache):
    tagdir = os.path.join(cache, tag)
    os.makedirs(tagdir, exist_ok=True)
    texts = {}
    for f in TAG_FILES[tag]:
        path = os.path.join(tagdir, f)
        if not os.path.exists(path):
            url = RAW.format(tag=tag, prefix=source_prefix, file=f)
            with urllib.request.urlopen(url, timeout=30) as r:
                data = r.read().decode("utf-8", "replace")
            with open(path, "w") as fh:
                fh.write(data)
        with open(path) as fh:
            texts[f] = fh.read()
    return texts


def strip_comments_line(text):
    # constants live on single lines; commented-out ones start with //
    return [ln for ln in text.splitlines()
            if not ln.strip().startswith("//")]


def parse_constants(texts):
    ins, sw, methods, cla = {}, {}, set(), None
    refs = set()
    for text in texts.values():
        lines = strip_comments_line(text)
        for ln in lines:
            for m in INS_RE.finditer(ln):
                ins[m.group(1)] = int(m.group(2), 16)
            for m in SW_RE.finditer(ln):
                sw[m.group(1)] = int(m.group(2), 16)
            for m in SW_REF_RE.finditer(ln):
                # cross-file reference, e.g. SW_NO_MEMORY_LEFT =
                # Bip32ObjectManager.SW_NO_MEMORY_LEFT: resolve against the
                # literal set once every file is parsed
                refs.add(m.group(1))
            m = CLA_RE.search(ln)
            if m and cla is None:
                cla = int(m.group(1), 16)
        for m in METHOD_RE.finditer(text):
            methods.add(m.group(1))
        for m in CALL_RE.finditer(text):
            methods.add(m.group(1))
    for name in refs:
        if name not in sw:
            raise SystemExit(f"unresolved cross-file SW reference: {name}")
    return ins, sw, methods, cla


def check_tag(tag, spec_version, channel_cla, cache, errors):
    texts = load_tag(tag, spec_version["source_prefix"], cache)
    src_ins, src_sw, src_methods, src_cla = parse_constants(texts)
    label = tag

    # INS
    for name, entry in spec_version["ins"].items():
        code = entry["code"] if isinstance(entry, dict) else entry
        code = int(code, 16) if isinstance(code, str) else code
        const = "INS_" + name
        if const not in src_ins:
            errors.append(f"{label}: spec INS {name} not found in source")
        elif src_ins[const] != code:
            errors.append(f"{label}: spec INS {name}=0x{code:02X} "
                          f"but source has 0x{src_ins[const]:02X}")
        if isinstance(entry, dict) and "handler" in entry:
            h = entry["handler"]
            if h not in src_methods:
                errors.append(f"{label}: spec handler '{h}' (INS {name}) "
                              f"not a method in source")
    for const, code in src_ins.items():
        name = const[len("INS_"):]
        if name not in spec_version["ins"]:
            errors.append(f"{label}: source has INS {name}=0x{code:02X} "
                          f"missing from spec")
    # SW
    for name, entry in spec_version["sw"].items():
        if isinstance(entry, dict):
            if entry.get("source") == "observed":
                continue
            code = entry["code"]
        else:
            code = entry
        code = int(code, 16) if isinstance(code, str) else code
        const = "SW_" + name
        if const not in src_sw:
            errors.append(f"{label}: spec SW {name} not found in source")
        elif src_sw[const] != code:
            errors.append(f"{label}: spec SW {name}=0x{code:04X} "
                          f"but source has 0x{src_sw[const]:04X}")
    for const, code in src_sw.items():
        if code is None:
            continue
        name = const[len("SW_"):]
        entry = spec_version["sw"].get(name)
        if entry is None:
            errors.append(f"{label}: source has SW {name}=0x{code:04X} "
                          f"missing from spec")
        elif isinstance(entry, dict) and entry.get("source") == "observed":
            continue
    if src_cla is not None and src_cla != channel_cla:
        errors.append(f"{label}: source CLA=0x{src_cla:02X} "
                      f"but spec channel.cla=0x{channel_cla:02X}")
    print(f"{label}: {len(src_ins)} INS, {len(src_sw)} SW constants, "
          f"CLA=0x{src_cla:02X}" if src_cla is not None else
          f"{label}: {len(src_ins)} INS, {len(src_sw)} SW constants")
    return src_ins, src_sw


def emit_rust(spec, path, parsed):
    aid = bytes.fromhex(spec["meta"]["aid"])
    lines = [
        "//! GENERATED by extract_apdu_spec.py from satochip-protocol.yaml",
        "//! (validated against the pinned Toporin tags) — do not edit.",
        "",
        "pub const CLA: u8 = 0xB0;",
        "pub const AID: [u8; %d] = [%s];" % (
            len(aid), ", ".join("0x%02X" % b for b in aid)),
        "",
    ]
    mod_names = {"v0.14-0.2": "v014_02", "v0.16-0.1": "v016_01"}
    for tag, version in spec["versions"].items():
        mod = mod_names[tag]
        lines.append("pub mod %s {" % mod)
        for name, entry in sorted(version["ins"].items()):
            code = entry["code"] if isinstance(entry, dict) else entry
            code = int(code, 16) if isinstance(code, str) else code
            lines.append("    pub const INS_%s: u8 = 0x%02X;" % (name.upper(), code))
        for name, entry in sorted(version["sw"].items()):
            code = entry["code"] if isinstance(entry, dict) else entry
            code = int(code, 16) if isinstance(code, str) else code
            lines.append("    pub const SW_%s: u16 = 0x%04X;" % (name.upper(), code))
        lines.append("}")
        lines.append("")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))
    print("rust constants ->", path)


YAML = None


def main():
    global YAML
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-cache",
                    default="/tmp/opencode/satochip-spec-cache")
    ap.add_argument("--emit-rust")
    ap.add_argument("tags", nargs="*")
    args = ap.parse_args()

    YAML = yaml.safe_load(open(SPEC))
    channel_cla = YAML["channel"]["cla"]
    channel_cla = int(channel_cla, 16) if isinstance(channel_cla, str) \
        else channel_cla
    tags = args.tags or list(YAML["versions"].keys())
    errors = []
    parsed = {}
    for tag in tags:
        parsed[tag] = check_tag(tag, YAML["versions"][tag], channel_cla,
                                args.source_cache, errors)
    if errors:
        print("\nSPEC DRIFT (%d):" % len(errors))
        for e in errors:
            print("  -", e)
        return 1
    print("spec OK for: %s" % ", ".join(tags))
    if args.emit_rust:
        emit_rust(YAML, args.emit_rust, parsed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
