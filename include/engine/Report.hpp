#ifndef SENTINEL_ENGINE_REPORT_HPP
#define SENTINEL_ENGINE_REPORT_HPP

#include "engine/IRule.hpp"
#include "engine/Scanner.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sentinel::engine {

enum class ReportFormat : std::uint8_t {
    Text,
    Json,
    Sarif,
};

[[nodiscard]] std::optional<ReportFormat> parseReportFormat(std::string_view text) noexcept;

struct ReportOptions {
    // 0 means the scanner picked the thread count automatically.
    std::size_t thread_count {0};
    std::string tool_version;
};

// Human-readable report: counts, warnings, per-file findings tagged with severity, and a
// remediation section listing guidance once for every rule that fired.
[[nodiscard]] std::string renderText(const ScanSummary& summary,
                                     const std::vector<RulePtr>& rules,
                                     const ReportOptions& options);

// Machine-readable report mirroring ScanSummary, plus the rule catalogue that was applied.
[[nodiscard]] std::string renderJson(const ScanSummary& summary,
                                     const std::vector<RulePtr>& rules,
                                     const ReportOptions& options);

// SARIF 2.1.0 log suitable for GitHub code scanning and similar integrations. Findings become
// results with byte regions relative to the scan root; unreadable files and traversal warnings
// become tool execution notifications.
[[nodiscard]] std::string renderSarif(const ScanSummary& summary,
                                      const std::vector<RulePtr>& rules,
                                      const ReportOptions& options);

[[nodiscard]] std::string render(ReportFormat format,
                                 const ScanSummary& summary,
                                 const std::vector<RulePtr>& rules,
                                 const ReportOptions& options);

}  // namespace sentinel::engine

#endif
