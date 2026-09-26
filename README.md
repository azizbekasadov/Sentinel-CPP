# Sentinel-CPP

[![Sentinel-CPP-CI](https://github.com/azizbekasadov/Sentinel-CPP/actions/workflows/ci.yml/badge.svg)](https://github.com/azizbekasadov/Sentinel-CPP/actions/workflows/ci.yml)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-brightgreen)](https://isocpp.org)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](./LICENSE)

**Sentinel-CPP** is a modern C++20 static scanning engine for detecting unsafe literals and suspicious patterns in large codebases. It is designed to showcase production-quality C++ fundamentals: clean interfaces, RAII, concurrent execution, deterministic reporting, and testable architecture.

## Main Goal of this project

- Concurrent file scanning with a reusable thread-pool abstraction.
- Extensible rule system with both fixed-string and regex-based strategies.
- Streaming file scanner that handles chunk boundaries correctly for large files, for both
  literal and regex rules.
- Structured scan summaries with per-file findings, byte counts, and machine-readable JSON output.
- Modern CMake layout with unit tests and warning flags enabled.

## Features

- Scan a single file or an entire directory tree recursively.
- Detect multiple signatures in the same run.
- Mix literal signatures with regex rules from the CLI.
- Filter scans with include/exclude globs for more realistic repository workflows.
- Skip binary files by default while allowing explicit opt-in byte scanning.
- Produce human-readable text output or JSON suitable for automation.
- Limit findings per file to keep reports bounded and deterministic.
- Report unreadable files and matcher failures per file instead of aborting the scan, and
  reflect them in the exit status.

## Architecture

### Core Components

- `IRule`: rule strategy interface for all detection logic.
- `StringMatchRule`: exact-match rule for secrets, markers, and policy strings.
- `RegexRule`: regex-backed rule for richer pattern matching.
- `Scanner`: streaming engine that scans files, aggregates findings, and produces scan summaries.
- `ThreadPool`: reusable concurrency primitive for parallel directory scans.

### Data Flow

1. CLI arguments are converted into rule objects.
2. `Scanner` enumerates target files.
3. Files are distributed across the thread pool.
4. Each file is scanned in fixed-size chunks. Every rule declares the longest match it can
   produce, and that many bytes are carried over between chunks so a match straddling a
   boundary is reported exactly once.
5. Findings are merged into a deterministic summary and rendered as text or JSON.

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
    - [regex-1] offset=0 length=20 :: Matched regex pattern 'AKIA[0-9A-Z]{16}'
  "./src/config/dev.env"
    - [API_KEY] offset=14 length=7 :: Matched fixed signature 'API_KEY'
```

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

- rule behavior and invalid input handling
- chunk-boundary correctness for literal and regex rules, including files whose size is an
  exact multiple of the chunk size
- per-file error reporting for unreadable files and matcher failures
- summary aggregation across multiple files
- include/exclude filtering, `**` globs, symbolic-link handling and binary-file policy
- compatibility of the simple boolean scanning API

CI runs the suite on Linux and macOS, under AddressSanitizer + UndefinedBehaviorSanitizer and
ThreadSanitizer, and gates on `clang-format` and `clang-tidy`.

## Roadmap

- SARIF export for code-scanning integrations.
- Config-driven rule packs loaded from JSON or YAML.
- Severity levels and remediation guidance per rule.
- Benchmarks for throughput and scaling curves.

## License

Sentinel-CPP is released under the MIT license. See [LICENSE](./LICENSE) for details.
