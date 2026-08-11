#!/bin/bash -eu
# ClusterFuzzLite build script: compile every fuzz/fuzz_*.py harness and
# package the seed corpus for each.
pip3 install .

# PyInstaller (inside compile_python_fuzzer) only bundles Python modules;
# package data files (mapping JSON, dictionary.json) must be added or the
# fuzzer dies on startup with FileNotFoundError: cisco_asa.json.
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
