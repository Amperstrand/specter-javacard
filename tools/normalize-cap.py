#!/usr/bin/env python3
"""Normalize JavaCard CAP files for reproducible builds.

Strips the Java-Card-CAP-Creation-Time timestamp from META-INF/MANIFEST.MF
and zeros ZIP entry modification times so that two builds produce identical SHA-256.
"""
import zipfile, io, os, sys, hashlib, re, argparse

FIXED_TIME = "Thu Jan  1 00:00:00 UTC 1970"
ZIP_MTIME = (1980, 1, 1, 0, 0, 0)

def normalize_cap(cap_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(cap_path, 'r') as zin:
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                raw = zin.read(item.filename)
                if item.filename == 'META-INF/MANIFEST.MF':
                    text = raw.decode('utf-8')
                    text = re.sub(
                        r'Java-Card-CAP-Creation-Time:.*\r?\n',
                        f'Java-Card-CAP-Creation-Time: {FIXED_TIME}\r\n',
                        text,
                    )
                    raw = text.encode('utf-8')
                item.date_time = ZIP_MTIME
                item.external_attr = (item.external_attr & 0xffffffff) | (0o644 << 16)
                zout.writestr(item, raw)
    with open(cap_path, 'wb') as f:
        f.write(buf.getvalue())

def hash_load_file_data_block(cap_path):
    h = hashlib.sha256()
    with zipfile.ZipFile(cap_path, 'r') as z:
        for name in sorted(z.namelist()):
            if name.endswith('.cap'):
                h.update(z.read(name))
    return h.hexdigest()

def main():
    p = argparse.ArgumentParser(description='Normalize CAP files for reproducible builds')
    p.add_argument('caps', nargs='+', help='CAP files to normalize')
    p.add_argument('--hash-lfd', action='store_true', help='Also print Load File Data Block hash')
    args = p.parse_args()

    for cap in args.caps:
        normalize_cap(cap)
        full_hash = hashlib.sha256(open(cap, 'rb').read()).hexdigest()
        print(f"{full_hash}  {os.path.basename(cap)}")
        if args.hash_lfd:
            lfd_hash = hash_load_file_data_block(cap)
            print(f"  LFD: {lfd_hash}  {os.path.basename(cap)}")

if __name__ == '__main__':
    main()
