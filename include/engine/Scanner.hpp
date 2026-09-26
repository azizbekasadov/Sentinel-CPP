#ifndef SENTINEL_ENGINE_SCANNER_HPP
#define SENTINEL_ENGINE_SCANNER_HPP

#include "engine/IRule.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sentinel::engine {

inline constexpr std::size_t kBufferSize = std::size_t {64} * 1024;

struct FileScanResult {
    std::filesystem::path path;
    std::uintmax_t bytes_scanned {0};
    std::vector<RuleMatch> findings;
    std::optional<std::string> error;
    std::optional<std::string> skipped_reason;

    [[nodiscard]] bool hasDetections() const noexcept {
        return !findings.empty();
    }

    [[nodiscard]] bool wasSkipped() const noexcept {
        return skipped_reason.has_value();
    }

    [[nodiscard]] bool hasError() const noexcept {
        return error.has_value();
    }
};

struct ScanSummary {
    std::filesystem::path root;
    std::size_t files_scanned {0};
    std::size_t files_with_detections {0};
    std::size_t files_with_errors {0};
    std::size_t files_skipped {0};
    std::uintmax_t bytes_scanned {0};
    std::vector<FileScanResult> file_results;
    std::vector<std::string> warnings;

    [[nodiscard]] bool hasDetections() const noexcept {
        return files_with_detections > 0;
    }

    // True when at least one file could not be fully scanned or enumeration emitted a warning.
    // Callers that treat a scan as a gate should not report a clean result in this case.
    [[nodiscard]] bool isIncomplete() const noexcept {
        return files_with_errors > 0 || !warnings.empty();
    }
};

struct FileScanOptions {
    // 0 means unlimited.
    std::size_t max_findings_per_file {64};
    bool scan_binary_files {true};
};

struct ScanOptions {
    std::size_t thread_count {0};
    // 0 means unlimited.
    std::size_t max_findings_per_file {64};
    bool include_clean_files {false};
    bool scan_binary_files {false};
    std::vector<std::string> include_globs;
    std::vector<std::string> exclude_globs;
};

// Matches `candidate` against a glob where `?` matches a single character other than '/',
// `*` matches any run of characters other than '/', and `**` matches any run of characters
// including '/'.
[[nodiscard]] bool wildcardMatch(std::string_view pattern, std::string_view candidate);

// Applies gitignore-style anchoring on top of wildcardMatch: a pattern without a '/' is matched
// against the file name at any depth, a pattern containing '/' is matched against the whole
// path relative to the scan root.
[[nodiscard]] bool globMatchesPath(std::string_view pattern, std::string_view relative_path);

class Scanner {
public:
    Scanner() = default;

    [[nodiscard]] FileScanResult scanFile(const std::filesystem::path& path,
                                          const std::vector<RulePtr>& rules,
                                          const FileScanOptions& options) const;

    [[nodiscard]] FileScanResult scanFile(const std::filesystem::path& path,
                                          const std::vector<RulePtr>& rules,
                                          std::size_t max_findings_per_file = 64) const;

    [[nodiscard]] FileScanResult scanFile(const std::filesystem::path& path,
                                          const std::vector<std::string>& signatures) const;

    [[nodiscard]] ScanSummary scanPath(const std::filesystem::path& path,
                                       const std::vector<RulePtr>& rules,
                                       const ScanOptions& options = {}) const;

    [[nodiscard]] bool scanDirectory(const std::filesystem::path& dir_path,
                                     const std::vector<std::string>& signatures,
                                     std::size_t thread_count = 0) const;

    [[nodiscard]] static std::vector<RulePtr> buildStringRules(
        const std::vector<std::string>& signatures);
};

}  // namespace sentinel::engine

#endif
