# Sentinel-CPP

[![Sentinel-CPP-CI](https://github.com/azizbekasadov/Sentinel-CPP/actions/workflows/ci.yml/badge.svg)](https://github.com/azizbekasadov/Sentinel-CPP/actions/workflows/ci.yml)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-brightgreen)](https://isocpp.org)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](./LICENSE)

**Sentinel-CPP** is a modern C++20 static scanning engine for detecting unsafe literals and suspicious patterns in large codebases. It is designed to showcase production-quality C++ fundamentals: clean interfaces, RAII, concurrent execution, deterministic reporting, and testable architecture.

## Main Goal of this project

- Concurrent file scanning with a reusable thread-pool abstraction.
- Extensible rule system with both fixed-string and regex-based strategies, each carrying a
  severity and remediation guidance.
- Config-driven rule packs loaded from JSON, with a bundled starter pack for common secrets.
- Streaming file scanner that handles chunk boundaries correctly for large files, for both
  literal and regex rules.
- Structured scan summaries with per-file findings, byte counts, and machine-readable JSON or
  SARIF 2.1.0 output for code-scanning integrations.
- Modern CMake layout with unit tests and warning flags enabled.

## Features

- Scan a single file or an entire directory tree recursively.
- Detect multiple signatures in the same run.
- Mix literal signatures with regex rules from the CLI, or load curated rule packs with
  `--rules`.
- Rank findings by severity and print remediation guidance for every rule that fired.
- Filter scans with include/exclude globs for more realistic repository workflows.
- Skip binary files by default while allowing explicit opt-in byte scanning.
- Produce human-readable text, JSON suitable for automation, or SARIF for GitHub code scanning.
- Limit findings per file to keep reports bounded and deterministic.
- Report unreadable files and matcher failures per file instead of aborting the scan, and
  reflect them in the exit status.

## Architecture

### Core Components

- `IRule`: rule strategy interface for all detection logic, including severity and remediation.
- `StringMatchRule`: exact-match rule for secrets, markers, and policy strings.
- `RegexRule`: regex-backed rule for richer pattern matching.
- `RulePack`: loader that turns a JSON document into a validated set of rules.
- `Scanner`: streaming engine that scans files, aggregates findings, and produces scan summaries.
- `ThreadPool`: reusable concurrency primitive for parallel directory scans.
- `Report`: text, JSON and SARIF renderers over a scan summary.
- `Cli`: argument parsing and rule assembly for the `sentinel` binary.
- `json`: a small dependency-free JSON parser and serializer used by rule packs and reports.

### Data Flow

1. CLI arguments and rule packs are converted into rule objects.
2. `Scanner` enumerates target files.
3. Files are distributed across the thread pool.
4. Each file is scanned in fixed-size chunks. Every rule declares the longest match it can
   produce, and that many bytes are carried over between chunks so a match straddling a
   boundary is reported exactly once.
5. Findings are merged into a deterministic summary and rendered as text, JSON or SARIF.

More implementation notes live in [docs/architecture.md](./docs/architecture.md).

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

### Build options

| Option | Default | Purpose |
|--------|---------|---------|
| `SENTINEL_BUILD_TESTS` | `ON` | Build the Catch2 unit tests. |
| `SENTINEL_BUILD_BENCHMARKS` | `ON` | Build the Catch2 benchmark binary (needs tests). |
| `SENTINEL_WARNINGS_AS_ERRORS` | `OFF` | Promote compiler warnings to errors (enabled in CI). |
| `SENTINEL_SANITIZER` | empty | `address` enables ASan + UBSan, `thread` enables TSan. |
| `SENTINEL_ENABLE_CLANG_TIDY` | `OFF` | Run clang-tidy on every translation unit during the build. |

```bash
# Sanitizer build
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSENTINEL_SANITIZER=address
cmake --build build-asan && ctest --test-dir build-asan

# Static analysis build
cmake -S . -B build-tidy -DSENTINEL_ENABLE_CLANG_TIDY=ON
cmake --build build-tidy
```

### Benchmarks

```bash
cmake --build build --target benchmarks
./build/benchmarks --benchmark-samples 20
```

The suite measures rule matching over a single 64 KiB window, single-file throughput for
literal, regex and mixed rule sets on an 8 MiB file, and directory scans of 64 files across 1, 2,
4 and 8 worker threads. Pass `--benchmark-no-analysis` for a quick smoke run.

Indicative Release numbers on an Apple M-series laptop:

| Case | Mean |
|------|------|
| 8 MiB file, 5 literal rules | 6 ms |
| 8 MiB file, 3 regex rules | 7 ms |
| 64 x 256 KiB files, mixed rules, 1 thread | 25 ms |
| 64 x 256 KiB files, mixed rules, 8 threads | 6 ms |

Regex rules stay close to literal speed because `RegexRule` only runs `std::regex` where the
pattern's literal prefix occurs; see [docs/architecture.md](./docs/architecture.md).

### Install

```bash
cmake --install build --prefix /usr/local
```

This installs the `sentinel` binary and the bundled rule packs under `share/sentinel/rules`.

### Code style

Formatting is enforced with `clang-format` using the checked-in `.clang-format`, and static
analysis rules live in `.clang-tidy`. Two helper targets are available when `clang-format` is
installed:

```bash
cmake --build build --target format        # rewrite sources in place
cmake --build build --target format-check  # fail if anything is misformatted
```

## Usage

### Scan with default signatures

```bash
./build/sentinel --path ./src
```

### Add custom literal rules

```bash
./build/sentinel --path ./src --signature API_KEY --signature password=
```

### Use a rule pack and produce SARIF for code scanning

```bash
./build/sentinel \
  --path . \
  --rules rules/secrets.json \
  --format sarif > results.sarif
```

The bundled `rules/secrets.json` covers AWS access keys, PEM private keys, GitHub, Slack, Google,
Stripe and JWT tokens, and plain-text password or API key assignments. Every rule has a severity
and remediation text that flows into the report. Rule packs and inline `--signature` / `--regex`
rules can be combined; ids must be unique across all sources.

### Add regex rules and emit JSON

```bash
./build/sentinel \
  --path ./src \
  --regex "AKIA[0-9A-Z]{16}" \
  --regex "-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----" \
  --format json
```

### Restrict scans to source files and ignore generated content

```bash
./build/sentinel \
  --path . \
  --include "*.cpp" \
  --include "*.hpp" \
  --exclude "build/**" \
  --exclude "out/**"
```

Globs follow gitignore conventions: a pattern without a `/` is matched against the file name at
any depth, a pattern containing `/` is matched against the path relative to the scan root, `*`
and `?` never cross a `/`, and `**` matches any number of path segments. Symbolic links are not
followed.

### Include clean files in the report

```bash
./build/sentinel --path ./src --include-clean-files
```

### Scan binary payloads explicitly

```bash
./build/sentinel --path ./artifacts --scan-binary-files --signature password=
```

## Rule Packs

A rule pack is a JSON document:

```json
{
  "name": "secrets",
  "version": "1.0.0",
  "rules": [
    {
      "id": "aws-access-key-id",
      "type": "regex",
      "pattern": "(AKIA|ASIA)[0-9A-Z]{16}",
      "description": "AWS access key id",
      "severity": "critical",
      "remediation": "Deactivate the key in IAM and load it from a secrets manager.",
      "maxMatchLength": 20
    },
    {
      "id": "password-literal",
      "type": "string",
      "pattern": "password=",
      "description": "Hardcoded password assignment",
      "severity": "high"
    }
  ]
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | Unique within the run; used in reports and SARIF `ruleId`. |
| `type` | yes | `string` or `regex`. |
| `pattern` | yes | Literal text or an ECMAScript regular expression. |
| `description` | no | Shown next to each finding. |
| `severity` | no | `info`, `low`, `medium` (default), `high` or `critical`. |
| `remediation` | no | Printed once per triggered rule; becomes SARIF `help.text`. |
| `maxMatchLength` | no | Regex only. Longest expected match in bytes (default 4096); sizes the chunk overlap. |
| `flags` | no | Regex only. Currently `["icase"]` for case-insensitive matching. |

Validation errors name the pack, the rule index and the rule id.

## Example Output

```text
Sentinel-CPP Scan Report
Root: "./src"
Files scanned: 42
Files with detections: 2
Files with errors: 0
Files skipped: 3
Bytes scanned: 194823
Threads: auto
Findings:
  "./src/auth/keys.txt"
    - [critical] [aws-access-key-id] offset=0 length=20 :: AWS access key id
  "./src/config/dev.env"
    - [high] [password-literal] offset=14 length=9 :: Literal password assignment
Remediation:
  aws-access-key-id: Deactivate the key in IAM, issue a new one, and load it from the environment or a secrets manager instead of source control.
  password-literal: Read passwords from configuration injected at deploy time and rotate the exposed value.
```

SARIF output maps `critical` and `high` to `error`, `medium` to `warning`, and `low` and `info`
to `note`, and reports every finding as a byte-offset region relative to the scan root.

## Exit Status

| Code | Meaning |
|------|---------|
| `0` | No findings, and every selected file was scanned. |
| `1` | At least one finding. |
| `2` | Invalid arguments, or the scan was incomplete because a file could not be read, a matcher failed, or directory traversal emitted a warning. |

Findings take precedence over errors, so a run that both detects a secret and fails to read a
file exits with `1` while still listing the failed file in the report.

## Testing

The test suite covers:

- rule behavior, severity metadata and invalid input handling
- the JSON parser and serializer, including escapes, surrogate pairs and error positions
- rule pack loading and every validation error it can report
- text, JSON and SARIF report structure
- CLI parsing, numeric validation and rule assembly from inline rules and packs
- chunk-boundary correctness for literal and regex rules, including files whose size is an
  exact multiple of the chunk size
- per-file error reporting for unreadable files and matcher failures
- summary aggregation across multiple files
- include/exclude filtering, `**` globs, symbolic-link handling and binary-file policy
- compatibility of the simple boolean scanning API

CI runs the suite on Linux and macOS, under AddressSanitizer + UndefinedBehaviorSanitizer and
ThreadSanitizer, and gates on `clang-format` and `clang-tidy`.

## Roadmap

- YAML rule packs, once a dependency-free parser is justified.
- Entropy-based detection for generic high-entropy secrets.
- Baseline files to suppress known, accepted findings.
- SIMD-accelerated literal matching for very large trees.

See [CHANGELOG.md](./CHANGELOG.md) for what has shipped.

## License

Sentinel-CPP is released under the MIT license. See [LICENSE](./LICENSE) for details.
