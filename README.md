# Sentinel-CPP

[![Sentinel-CPP-CI](https://github.com/azizbekasadov/Sentinel-CPP/actions/workflows/ci.yml/badge.svg)](https://github.com/azizbekasadov/Sentinel-CPP/actions/workflows/ci.yml)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-brightgreen)](https://isocpp.org)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](./LICENSE)

**Sentinel-CPP** is a modern C++20 static scanning engine for detecting unsafe literals and suspicious patterns in large codebases. It is designed to showcase production-quality C++ fundamentals: clean interfaces, RAII, concurrent execution, deterministic reporting, and testable architecture.

## Why This Is A Strong Portfolio Project

- Concurrent file scanning with a reusable thread-pool abstraction.
- Extensible rule system with both fixed-string and regex-based strategies.
- Streaming file scanner that handles chunk boundaries correctly for large files.
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
4. Each file is scanned in fixed-size chunks with overlap preservation.
5. Findings are merged into a deterministic summary and rendered as text or JSON.

More implementation notes live in [docs/architecture.md](./docs/architecture.md).

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
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
  --exclude "build/*" \
  --exclude "out/*"
```

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
Root: ./src
Files scanned: 42
Files with detections: 2
Files skipped: 3
Bytes scanned: 194823
Threads: auto
Findings:
  ./src/config/dev.env
    - [API_KEY] offset=14 :: Matched fixed signature 'API_KEY'
  ./src/auth/keys.txt
    - [regex-1] offset=0 :: Matched regex pattern 'AKIA[0-9A-Z]{16}'
```

## Testing

The test suite covers:

- rule behavior and invalid input handling
- chunk-boundary correctness for streaming scans
- summary aggregation across multiple files
- include/exclude filtering and binary-file policy
- compatibility of the simple boolean scanning API

## Roadmap

- SARIF export for code-scanning integrations.
- Config-driven rule packs loaded from JSON or YAML.
- File filtering and ignore-glob support.
- Severity levels and remediation guidance per rule.
- Benchmarks for throughput and scaling curves.

## License

Sentinel-CPP is released under the MIT license. See [LICENSE](./LICENSE) for details.
