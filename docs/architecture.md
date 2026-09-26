# Sentinel-CPP Architecture

Sentinel-CPP is intentionally structured as a small but production-minded scanning engine. The design favors deterministic behavior, bounded memory usage, and testable seams over framework-heavy abstractions.

## Design Goals

- Keep rule evaluation open for extension without coupling the scanner to any one matching strategy.
- Support large-file scanning without loading entire files into memory.
- Preserve deterministic ordering in reports even when directory scans run concurrently.
- Expose enough structured output for CI and automation use cases.

## Component Breakdown

### `IRule`

`IRule` is the strategy boundary for all detection logic. Both fixed-string and regex rules implement the same `apply(std::string_view)` contract, which keeps the scanner focused on orchestration rather than pattern semantics.

Every rule also reports `maxMatchLength()`, the longest match it can produce. Literal rules return their pattern length; regex rules take an explicit bound (4 KiB by default) because a regular expression has no intrinsic limit. The scanner uses the largest bound across the active rule set to size the overlap between chunks.

### `Scanner`

`Scanner` owns file enumeration, chunked file reads, overlap preservation between chunks, result aggregation, and scan summaries. The engine keeps offsets absolute so findings remain stable regardless of buffering strategy.

#### Chunk boundaries

Files are read in 64 KiB chunks. Each window handed to the rules consists of the last `overlap` bytes of the previous chunk followed by the new chunk. Rules see the whole window, but only matches that start in the leading `window_size - overlap` bytes are reported from it; matches starting inside the trailing overlap are deferred to the next window, where they are evaluated with complete context. The final window reports everything. This yields exactly one report per match for every match no longer than `overlap`, without any de-duplication pass, and works for variable-length regex matches as well as fixed literals.

#### Failure handling

A file that cannot be opened, or a rule that throws while matching (for example `std::regex` giving up on a pathological input), produces a `FileScanResult` with `error` set. The remaining files are still scanned, the summary counts the failure in `files_with_errors`, and `ScanSummary::isIncomplete()` lets callers refuse to treat the run as clean.

#### File selection

Globs follow gitignore conventions. A pattern with no `/` is matched against the file name at any depth; a pattern containing `/` is matched against the path relative to the scan root. `*` and `?` never cross a `/`, `**` does, and a leading `**/` may match zero directories. Symbolic links are never followed so a scan cannot escape its root or loop.

### `ThreadPool`

Directory scans distribute file work across a reusable thread pool. Results are merged under synchronization, then sorted for deterministic output. This provides concurrency without making report ordering nondeterministic.

## Operational Behavior

- Directory traversal skips permission-denied entries and records warnings instead of failing the entire scan.
- File selection supports lightweight wildcard filters (`*` and `?`) for repository-focused scans.
- Binary files are skipped by default to reduce noise; callers can opt in when they explicitly want raw byte scanning. Detection uses the first 512 bytes of the same read that feeds the scanner, so a file is opened exactly once.
- Findings per file are capped to keep memory and report volume bounded; a cap of `0` means unlimited.
- Findings are ordered by offset, then rule id, within each file, and files are ordered by path.

## Tradeoffs

- Regex matching currently uses the standard library engine for portability and zero extra dependencies. Its backtracking implementation can reject pathological inputs at match time; the scanner surfaces that as a per-file error rather than a crash.
- Regex matches longer than the configured `maxMatchLength` may be truncated at a chunk boundary. The bound is a constructor argument so callers with unusual patterns can raise it.
- Wildcard filters intentionally use simple semantics instead of a heavier glob library to keep the project self-contained.
- Binary scanning is opt-in because text rules over arbitrary bytes are useful in some investigations but noisy for day-to-day source scans.

## Tooling

- `.clang-format` defines the house style; `cmake --build build --target format-check` enforces it.
- `.clang-tidy` enables the bugprone, cert, concurrency, cppcoreguidelines, misc, modernize, performance, portability and readability check groups with a small set of exclusions. `tests/.clang-tidy` relaxes checks that fire on Catch2 macros.
- `-DSENTINEL_SANITIZER=address|thread` builds with ASan + UBSan or TSan; CI runs both.
- `-DSENTINEL_WARNINGS_AS_ERRORS=ON` is used in CI so new warnings cannot land silently.
