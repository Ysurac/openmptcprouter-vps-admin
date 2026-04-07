#!/usr/bin/env python3
"""
Build omr-admin as a standalone executable using Cython + setuptools.
Usage: python3 cypthon.py build_exe
"""
import os
import subprocess
import sys
import sysconfig
from distutils.cmd import Command
from setuptools import setup


class BuildExecutable(Command):
    description = "Build standalone executable with Cython"
    user_options = []

    def initialize_options(self): pass
    def finalize_options(self): pass

    def run(self):
        source = "omradmin.py"
        c_file = "omradmin.c"
        output = "omr-admin"

        # Step 1: Cython -> C with --embed (adds main() entry point)
        print(f"[1/2] Cython: {source} -> {c_file}")
        subprocess.run(
            [
                sys.executable, "-m", "cython",
                "--embed",
                "-3",
                "--module-name", "omradmin",
                "--directive", "annotation_typing=False",
                "--output-file", c_file,
                source,
            ],
            check=True,
        )

        # Step 2: C -> native executable
        print(f"[2/2] GCC: {c_file} -> {output}")
        py_include = sysconfig.get_path("include")
        py_libdir = sysconfig.get_config_var("LIBDIR") or ""
        py_ldversion = sysconfig.get_config_var("LDVERSION") or (
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )
        extra_ldflags = (sysconfig.get_config_var("LIBS") or "").split()
        extra_ldflags += (sysconfig.get_config_var("SYSLIBS") or "").split()

        cmd = [
            "gcc", "-O1", "-pipe",
            f"-I{py_include}",
            c_file,
            f"-L{py_libdir}",
            f"-lpython{py_ldversion}",
        ] + extra_ldflags + ["-o", output]

        subprocess.run(cmd, check=True)
        os.chmod(output, 0o755)
        print(f"Done! Executable: ./{output}")


setup(
    name="omr-admin",
    py_modules=[],
    packages=[],
    cmdclass={"build_exe": BuildExecutable},
)
