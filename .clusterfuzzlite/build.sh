#!/bin/bash -eu
# ClusterFuzzLite build script: compile every fuzz/fuzz_*.py harness and
# package the seed corpus for each.
pip3 install .

# PyInstaller (inside compile_python_fuzzer) only bundles Python modules;
# the mapping JSON data files must be added explicitly or the packaged
# fuzzer dies on startup with FileNotFoundError: cisco_asa.json.
mappings_dir=$(python3 -c "import os, syslogcef.mappings as m; print(os.path.dirname(m.__file__))")

for fuzzer in fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer" --add-data "$mappings_dir:syslogcef/mappings"
done

for fuzzer in fuzz/fuzz_*.py; do
  name=$(basename "$fuzzer" .py)
  zip -q -j "$OUT/${name}_seed_corpus.zip" fuzz/corpus/*
done
