# Fuzzing syslogcef

Three layers, from fastest to deepest:

1. **Property tests** (`tests/test_fuzz_properties.py`, hypothesis) —
   run in normal CI on every change; 10k-example deep profile weekly
   via the *Deep fuzz* workflow.
2. **ClusterFuzzLite** (`.clusterfuzzlite/`, `.github/workflows/cflite_pr.yml`)
   — coverage-guided libFuzzer runs (via Atheris) against the code
   changed in a pull request that touches `syslogcef/` or `fuzz/`.
   Self-serve: no external enrollment required.
3. **Local / OSS-Fuzz Atheris harnesses** — for long manual sessions
   and future OSS-Fuzz enrollment:
   - `fuzz_convert.py` throws raw fuzzer bytes at `convert_line`;
   - `fuzz_structured.py` *builds* syslog-shaped lines (RFC3164,
     RFC5424, rsyslog JSON, kv, Cisco, adaptive-only shapes) with
     fuzzer-chosen hosts, IPs, timestamps, and payload lengths from
     empty to multi-KB, exploring the parser and mapping space far
     deeper than free-form text.

## Invariants

Any crash, hang, or assertion from a harness is by definition a bug:
`convert_line` must never raise, must emit structurally valid CEF
(`CEF:0` version slot, 7 header fields on unescaped-pipe split, numeric
severity, no CR/LF in the header), and must stay fast on adversarial
input.

## Running locally

With Docker (no toolchain needed on the host; from the repo root):

```bash
mkdir -p artifacts
docker run --rm -v "$PWD":/src:ro -v "$PWD/artifacts":/artifacts python:3.11-slim bash -c '
  cp -r /src /tmp/build && rm -rf /tmp/build/.git /tmp/build/*.egg-info
  pip install -q atheris /tmp/build
  cd /tmp/build
  python fuzz/fuzz_convert.py -max_total_time=300 -max_len=4096 \
      -artifact_prefix=/artifacts/ fuzz/corpus/'
```

Crash artifacts land in `./artifacts/` on the host (the container is
removed on exit, so never point `-artifact_prefix` inside it).

Reference run (2026-08-11, 3 minutes): **887,058 executions, zero
crashes or hangs**.

Crashing inputs are written to the `-artifact_prefix` directory as
`crash-*` files; reproduce with:

```bash
python fuzz/fuzz_convert.py crash-<hash>
```

## Corpus

`corpus/` holds one seed per parser family (RFC3164/ASA, RFC5424,
rsyslog JSON, kernel kv, Cisco seq, kv stream, ISO syslog, an
adaptive-only shape, a bare PRI, and a CEF-lookalike aimed at the
escaper). Add a minimized seed here whenever a new format or a fixed
crash warrants one.

## OSS-Fuzz enrollment (future)

`oss-fuzz/` contains a ready `project.yaml`, `Dockerfile`, and
`build.sh`. To apply: fork [google/oss-fuzz], copy those three files to
`projects/syslogcef/`, and open a PR. Note Google's [acceptance
criteria] favor widely-used projects — apply once syslogcef has
meaningful adoption (e.g. official distro packaging); until then
ClusterFuzzLite provides the same engine on our own runners.

[google/oss-fuzz]: https://github.com/google/oss-fuzz
[acceptance criteria]: https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/
