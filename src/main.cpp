#include "engine/Cli.hpp"
#include "engine/Report.hpp"
#include "engine/Scanner.hpp"

#include <cstddef>
#include <exception>
#include <filesystem>
#include <iostream>
#include <span>
#include <string>
#include <system_error>

namespace {

using sentinel::engine::buildRules;
using sentinel::engine::CliOptions;
using sentinel::engine::parseArguments;
using sentinel::engine::render;
using sentinel::engine::ReportOptions;
using sentinel::engine::Scanner;
using sentinel::engine::ScanOptions;

// Exit codes follow the grep convention so the tool composes well in CI pipelines.
constexpr int kExitClean = 0;
constexpr int kExitDetections = 1;
constexpr int kExitError = 2;

}  // namespace

int main(int argc, char* argv[]) {
    CliOptions options;
    try {
        options =
            parseArguments(std::span<const char* const>(argv, static_cast<std::size_t>(argc)));
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n' << sentinel::engine::usageText();
        return kExitError;
    }

    if (options.show_help) {
        std::cout << sentinel::engine::usageText();
        return kExitClean;
    }

    if (options.show_version) {
        std::cout << "sentinel " << sentinel::engine::toolVersion() << '\n';
        return kExitClean;
    }

    try {
        const auto rules = buildRules(options);

        std::error_code fs_error;
        if (!std::filesystem::exists(options.target_path, fs_error) || fs_error) {
            std::cerr << "Target path does not exist: " << options.target_path << '\n';
            return kExitError;
        }

        const Scanner scanner;
        const auto summary =
            scanner.scanPath(options.target_path,
                             rules,
                             ScanOptions {
                                 .thread_count = options.threads,
                                 .max_findings_per_file = options.max_findings_per_file,
                                 .include_clean_files = options.include_clean_files,
                                 .scan_binary_files = options.scan_binary_files,
                                 .include_globs = options.include_globs,
                                 .exclude_globs = options.exclude_globs,
                             });

        std::cout << render(options.format,
                            summary,
                            rules,
                            ReportOptions {
                                .thread_count = options.threads,
                                .tool_version = std::string(sentinel::engine::toolVersion()),
                            });

        if (summary.hasDetections()) {
            return kExitDetections;
        }
        return summary.isIncomplete() ? kExitError : kExitClean;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return kExitError;
    }
}
