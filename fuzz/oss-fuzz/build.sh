#!/bin/bash -eu
pip3 install .

# PyInstaller only bundles Python modules; add the package data files
# files explicitly or the packaged fuzzer fails at startup.
pkg_dir=$(python3 -c "import os, syslogcef; print(os.path.dirname(syslogcef.__file__))")

for fuzzer in fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer" \
    --add-data "$pkg_dir/mappings:syslogcef/mappings" \
    --add-data "$pkg_dir/dictionary.json:syslogcef"
done

for fuzzer in fuzz/fuzz_*.py; do
  name=$(basename "$fuzzer" .py)
  zip -q -j "$OUT/${name}_seed_corpus.zip" fuzz/corpus/*
done
