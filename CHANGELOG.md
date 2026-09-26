# Changelog

All notable changes to Sentinel-CPP are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-09-26

### Added

- Severity (`info`, `low`, `medium`, `high`, `critical`) and remediation guidance on every rule,
  reported per finding and summarised once per triggered rule in text output.
- JSON rule packs loaded with `--rules <pack.json>`, repeatable and combinable with inline
  `--signature` and `--regex` rules. A starter pack ships in `rules/secrets.json`.
- SARIF 2.1.0 output via `--format sarif`, including the rule catalogue, byte-offset regions
  relative to the scan root and tool notifications for unreadable files.
- `--version` flag; the version is baked in from the CMake project version.
- A dependency-free JSON parser and serializer in `engine/Json`.
- Catch2 benchmarks (`benchmarks` target) covering rule matching, single-file throughput and
  directory scaling across thread counts.
- `install` rules for the binary and bundled rule packs.

### Performance

- Regex rules now extract the literal prefix every match must start with and only invoke
  `std::regex` at positions where that prefix occurs. On an 8 MiB file with three regex rules
  this took scanning from 1.5 s to 7 ms in a Release build; patterns that begin with a class,
  anchor, group or top-level alternation fall back to a full scan.

### Changed

- The built-in default rules now have descriptive ids (`password-literal`, `api-key-literal`,
  ...) instead of using the literal text as the id.
- JSON output gained `filesWithErrors`, `incomplete`, a `rules` catalogue and per-finding
  `length` and `severity`.
- Report rendering and CLI parsing moved from `main.cpp` into the engine so they are unit
  tested.

## [0.3.0] - 2026-09-26

### Fixed

- Regex matches spanning the 64 KiB chunk boundary were missed or reported twice. Rules now
  declare `maxMatchLength()` and the scanner defers matches that start inside the carried
  overlap to the next window, reporting each match exactly once.
- A rule that threw while matching (for example a `std::regex` complexity error) aborted the
  entire directory scan. Failures are now recorded per file and other files keep scanning.
- Unreadable files no longer produce a successful exit code. Exit status is `0` clean,
  `1` findings, `2` usage error or incomplete scan.
- `--threads` and `--max-findings` rejected nothing: `-1`, `abc` and `5xyz` were accepted or
  wrapped. Values are now validated strictly.
- JSON output was invalid when a path or message contained control characters.
- An unknown trailing flag was reported as a missing value.
- `--max-findings 0` limited output to one finding; it now means unlimited.
- Globs: `*` and `?` no longer cross `/`, `**` is supported, and a pattern without `/` matches
  the file name at any depth. Symbolic links are no longer followed.
- Files were opened twice (binary sniff and scan); they are now opened once.
- `ThreadPool` joined nothing if a worker failed to start and rethrew a stale exception on
  reuse.

### Added

- `clang-format` and `clang-tidy` configuration, `format` and `format-check` targets.
- CMake options `SENTINEL_SANITIZER`, `SENTINEL_ENABLE_CLANG_TIDY` and
  `SENTINEL_WARNINGS_AS_ERRORS`.
- CI jobs for formatting, static analysis, and ASan/UBSan and TSan test runs.

## [0.2.0]

- Initial public engine: string and regex rules, chunked scanning, thread pool, text and JSON
  reports, include/exclude globs and binary-file skipping.
