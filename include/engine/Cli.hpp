#ifndef SENTINEL_ENGINE_CLI_HPP
#define SENTINEL_ENGINE_CLI_HPP

#include "engine/IRule.hpp"
#include "engine/Report.hpp"

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sentinel::engine {

struct CliOptions {
    std::filesystem::path target_path;
    std::vector<std::string> signatures;
    std::vector<std::string> regex_patterns;
    std::vector<std::filesystem::path> rule_packs;
    std::vector<std::string> include_globs;
    std::vector<std::string> exclude_globs;
    std::size_t threads {0};
    std::size_t max_findings_per_file {64};
    ReportFormat format {ReportFormat::Text};
    bool include_clean_files {false};
    bool scan_binary_files {false};
    bool show_help {false};
    bool show_version {false};
};

// Version string baked in at build time from the CMake project version.
[[nodiscard]] std::string_view toolVersion() noexcept;

[[nodiscard]] std::string_view usageText() noexcept;

// Parses argv (including the program name at index 0). Throws std::invalid_argument with a
// user-facing message on any problem. --help and --version short-circuit validation.
[[nodiscard]] CliOptions parseArguments(std::span<const char* const> args);

// Builds the rule set: inline signatures, then inline regexes, then rule packs in order. Falls
// back to the built-in defaults when none were given. Throws std::invalid_argument when a pack
// cannot be loaded or a rule id is used twice.
[[nodiscard]] std::vector<RulePtr> buildRules(const CliOptions& options);

}  // namespace sentinel::engine

#endif
