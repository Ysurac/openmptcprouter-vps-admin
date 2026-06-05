#!/usr/bin/env python3
"""
Build omr-admin as a standalone executable using Cython.
Usage: python3 cypthon.py [--keep-c]
"""
import argparse
import os
import subprocess
import sys
import sysconfig


def run(cmd):
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)


def build(keep_c: bool = False):
    source  = "omradmin.py"
    c_file  = "omr-admin.c"
    output  = "omr-admin"

    # 1. Cython -> C with --embed (adds main() entry point)
    print(f"\n[1/2] Cython: {source} -> {c_file}")
    run([
        sys.executable, "-m", "cython",
        "--embed",
        "-3",
        "--module-name", "omradmin",
        "--directive", "annotation_typing=False",
        "--output-file", c_file,
        source,
    ])

    # 2. C -> native executable
    print(f"\n[2/2] GCC: {c_file} -> {output}")
    py_include  = sysconfig.get_path("include")
    py_libdir   = sysconfig.get_config_var("LIBDIR") or ""
    py_ldver    = sysconfig.get_config_var("LDVERSION") or (
        f"{sys.version_info.major}.{sys.version_info.minor}"
    )
    extra = (sysconfig.get_config_var("LIBS") or "").split()
    extra += (sysconfig.get_config_var("SYSLIBS") or "").split()

    run([
        "gcc", "-O1", "-pipe",
        f"-I{py_include}",
        c_file,
        f"-L{py_libdir}",
        f"-lpython{py_ldver}",
        *extra,
        "-o", output,
    ])
    os.chmod(output, 0o755)

    if not keep_c:
        os.remove(c_file)
        print(f"Removed {c_file}")

    print(f"\nDone! Executable: ./{output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build omr-admin executable via Cython")
    parser.add_argument("--keep-c", action="store_true", help="Keep generated C file")
    args = parser.parse_args()
    build(keep_c=args.keep_c)
