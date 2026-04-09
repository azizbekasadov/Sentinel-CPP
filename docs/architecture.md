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

### `Scanner`

`Scanner` owns file enumeration, chunked file reads, overlap preservation between chunks, result aggregation, and scan summaries. The engine keeps offsets absolute so findings remain stable regardless of buffering strategy.

### `ThreadPool`

Directory scans distribute file work across a reusable thread pool. Results are merged under synchronization, then sorted for deterministic output. This provides concurrency without making report ordering nondeterministic.

## Operational Behavior

- Directory traversal skips permission-denied entries and records warnings instead of failing the entire scan.
- File selection supports lightweight wildcard filters (`*` and `?`) for repository-focused scans.
- Binary files are skipped by default to reduce noise; callers can opt in when they explicitly want raw byte scanning.
- Findings per file are capped to keep memory and report volume bounded.

## Tradeoffs

- Regex matching currently uses the standard library engine for portability and zero extra dependencies.
- Wildcard filters intentionally use simple semantics instead of a heavier glob library to keep the project self-contained.
- Binary scanning is opt-in because text rules over arbitrary bytes are useful in some investigations but noisy for day-to-day source scans.
