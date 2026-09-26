#include "engine/RegexRule.hpp"
#include "engine/Scanner.hpp"
#include "engine/StringMatch.hpp"

#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

using sentinel::engine::RulePtr;
using sentinel::engine::Scanner;
using sentinel::engine::ScanOptions;
using sentinel::engine::ScanSummary;

// Exit codes follow the grep convention so the tool composes well in CI pipelines.
constexpr int kExitClean = 0;
constexpr int kExitDetections = 1;
constexpr int kExitError = 2;

struct CliOptions {
    std::filesystem::path target_path;
    std::vector<std::string> signatures;
    std::vector<std::string> regex_patterns;
    std::vector<std::string> include_globs;
    std::vector<std::string> exclude_globs;
    std::size_t threads {0};
    std::size_t max_findings_per_file {64};
    bool json_output {false};
    bool include_clean_files {false};
    bool scan_binary_files {false};
    bool show_help {false};
};

constexpr std::string_view kUsage =
    "Usage: sentinel --path <target> [--signature <text> ...] [--regex <expr> ...]\n"
    "                [--threads <n>] [--max-findings <n>] [--format text|json]\n"
    "                [--include-clean-files] [--include <glob> ...] [--exclude <glob> ...]\n"
    "                [--scan-binary-files]\n"
    "\n"
    "Options:\n"
    "  --threads <n>        Worker threads; 0 or omitted selects the hardware default.\n"
    "  --max-findings <n>   Findings reported per file; 0 means unlimited (default 64).\n"
    "  --include <glob>     Only scan matching files. A glob without '/' matches the file\n"
    "                       name at any depth; '*' and '?' never cross '/', '**' does.\n"
    "  --exclude <glob>     Skip matching files; evaluated after --include.\n"
    "\n"
    "Exit status:\n"
    "  0  no findings and every file was scanned\n"
    "  1  at least one finding\n"
    "  2  invalid arguments, or the scan was incomplete (unreadable files or warnings)\n"
    "\n"
    "Examples:\n"
    "  sentinel --path ./src\n"
    "  sentinel --path ./src --signature API_KEY --signature password=\n"
    "  sentinel --path ./src --regex \"AKIA[0-9A-Z]{16}\" --format json\n"
    "  sentinel --path . --include \"*.cpp\" --exclude \"build/**\"\n";

std::vector<std::string> defaultSignatures() {
    return {"EVIL_CODE", "VIRUS_END", "MALWARE_START", "API_KEY", "password="};
}

void printUsage(std::ostream& stream) {
    stream << kUsage;
}

std::string escapeJson(std::string_view input) {
    static constexpr std::string_view kHexDigits = "0123456789abcdef";

    std::string output;
    output.reserve(input.size() + 16);

    for (const char ch : input) {
        switch (ch) {
            case '\\':
                output += "\\\\";
                break;
            case '"':
                output += "\\\"";
                break;
            case '\b':
                output += "\\b";
                break;
            case '\f':
                output += "\\f";
                break;
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default: {
                const auto byte = static_cast<unsigned char>(ch);
                if (byte < 0x20 || byte == 0x7F) {
                    output += "\\u00";
                    output += kHexDigits[byte >> 4U];
                    output += kHexDigits[byte & 0x0FU];
                } else {
                    output += ch;
                }
                break;
            }
        }
    }

    return output;
}

std::size_t parseSizeArgument(std::string_view name, std::string_view text) {
    std::size_t value = 0;
    const auto* const first = text.data();
    const auto* const last = first + text.size();
    const auto [end, ec] = std::from_chars(first, last, value);

    if (ec == std::errc::result_out_of_range) {
        throw std::invalid_argument("Value for " + std::string(name) + " is too large: '" +
                                    std::string(text) + "'");
    }

    if (ec != std::errc {} || end != last || text.empty()) {
        throw std::invalid_argument("Value for " + std::string(name) +
                                    " must be a non-negative integer, got '" + std::string(text) +
                                    "'");
    }

    return value;
}

CliOptions parseArguments(std::span<const char* const> args) {
    CliOptions options;

    const auto require_value = [&](std::size_t& index, std::string_view name) -> std::string_view {
        if (index + 1 >= args.size()) {
            throw std::invalid_argument("Missing value for argument: " + std::string(name));
        }
        return args[++index];
    };

    for (std::size_t i = 1; i < args.size(); ++i) {
        const std::string_view arg = args[i];

        if (arg == "--help" || arg == "-h") {
            options.show_help = true;
            return options;
        }

        if (arg == "--include-clean-files") {
            options.include_clean_files = true;
        } else if (arg == "--scan-binary-files") {
            options.scan_binary_files = true;
        } else if (arg == "--path") {
            options.target_path = std::string(require_value(i, arg));
        } else if (arg == "--signature") {
            options.signatures.emplace_back(require_value(i, arg));
        } else if (arg == "--regex") {
            options.regex_patterns.emplace_back(require_value(i, arg));
        } else if (arg == "--include") {
            options.include_globs.emplace_back(require_value(i, arg));
        } else if (arg == "--exclude") {
            options.exclude_globs.emplace_back(require_value(i, arg));
        } else if (arg == "--threads") {
            options.threads = parseSizeArgument(arg, require_value(i, arg));
        } else if (arg == "--max-findings") {
            options.max_findings_per_file = parseSizeArgument(arg, require_value(i, arg));
        } else if (arg == "--format") {
            const auto format = require_value(i, arg);
            if (format == "json") {
                options.json_output = true;
            } else if (format != "text") {
                throw std::invalid_argument("Unsupported format: " + std::string(format));
            }
        } else {
            throw std::invalid_argument("Unknown argument: " + std::string(arg));
        }
    }

    if (options.target_path.empty()) {
        throw std::invalid_argument("You must provide --path");
    }

    if (options.signatures.empty() && options.regex_patterns.empty()) {
        options.signatures = defaultSignatures();
    }

    return options;
}

std::vector<RulePtr> buildRules(const CliOptions& options) {
    auto rules = Scanner::buildStringRules(options.signatures);

    std::size_t regex_index = 0;
    for (const auto& pattern : options.regex_patterns) {
        ++regex_index;
        std::ostringstream rule_id;
        rule_id << "regex-" << regex_index;
        rules.push_back(std::make_shared<sentinel::engine::RegexRule>(
            rule_id.str(), pattern, "Matched regex pattern '" + pattern + "'"));
    }

    return rules;
}

void printTextReport(const ScanSummary& summary, std::size_t configured_threads) {
    std::cout << "Sentinel-CPP Scan Report\n";
    std::cout << "Root: " << summary.root << '\n';
    std::cout << "Files scanned: " << summary.files_scanned << '\n';
    std::cout << "Files with detections: " << summary.files_with_detections << '\n';
    std::cout << "Files with errors: " << summary.files_with_errors << '\n';
    std::cout << "Files skipped: " << summary.files_skipped << '\n';
    std::cout << "Bytes scanned: " << summary.bytes_scanned << '\n';
    std::cout << "Threads: "
              << (configured_threads == 0 ? std::string("auto")
                                          : std::to_string(configured_threads))
              << '\n';
    if (!summary.warnings.empty()) {
        std::cout << "Warnings:\n";
        for (const auto& warning : summary.warnings) {
            std::cout << "  - " << warning << '\n';
        }
    }

    if (summary.file_results.empty()) {
        std::cout << "Findings: none\n";
        return;
    }

    std::cout << "Findings:\n";
    for (const auto& file_result : summary.file_results) {
        std::cout << "  " << file_result.path << '\n';

        if (file_result.error) {
            std::cout << "    error: " << *file_result.error << '\n';
        }

        if (file_result.skipped_reason) {
            std::cout << "    skipped: " << *file_result.skipped_reason << '\n';
            continue;
        }

        if (file_result.findings.empty()) {
            if (!file_result.error) {
                std::cout << "    clean\n";
            }
            continue;
        }

        for (const auto& finding : file_result.findings) {
            std::cout << "    - [" << finding.rule_id << "] offset=" << finding.offset
                      << " length=" << finding.length << " :: " << finding.description << '\n';
        }
    }
}

void printJsonString(std::string_view key, const std::optional<std::string>& value) {
    std::cout << '"' << key << "\": ";
    if (value) {
        std::cout << '"' << escapeJson(*value) << '"';
    } else {
        std::cout << "null";
    }
}

void printJsonReport(const ScanSummary& summary, std::size_t configured_threads) {
    std::cout << "{\n";
    std::cout << "  \"root\": \"" << escapeJson(summary.root.string()) << "\",\n";
    std::cout << "  \"filesScanned\": " << summary.files_scanned << ",\n";
    std::cout << "  \"filesWithDetections\": " << summary.files_with_detections << ",\n";
    std::cout << "  \"filesWithErrors\": " << summary.files_with_errors << ",\n";
    std::cout << "  \"filesSkipped\": " << summary.files_skipped << ",\n";
    std::cout << "  \"bytesScanned\": " << summary.bytes_scanned << ",\n";
    std::cout << "  \"threads\": ";
    if (configured_threads == 0) {
        std::cout << "\"auto\",\n";
    } else {
        std::cout << configured_threads << ",\n";
    }
    std::cout << "  \"warnings\": [\n";
    for (std::size_t i = 0; i < summary.warnings.size(); ++i) {
        std::cout << "    \"" << escapeJson(summary.warnings[i]) << "\""
                  << (i + 1 == summary.warnings.size() ? '\n' : ',');
    }
    std::cout << "  ],\n";
    std::cout << "  \"results\": [\n";

    for (std::size_t i = 0; i < summary.file_results.size(); ++i) {
        const auto& file_result = summary.file_results[i];
        std::cout << "    {\n";
        std::cout << "      \"path\": \"" << escapeJson(file_result.path.string()) << "\",\n";
        std::cout << "      \"bytesScanned\": " << file_result.bytes_scanned << ",\n";
        std::cout << "      ";
        printJsonString("error", file_result.error);
        std::cout << ",\n      ";
        printJsonString("skippedReason", file_result.skipped_reason);
        std::cout << ",\n";

        std::cout << "      \"findings\": [\n";
        for (std::size_t j = 0; j < file_result.findings.size(); ++j) {
            const auto& finding = file_result.findings[j];
            std::cout << "        {\n";
            std::cout << "          \"ruleId\": \"" << escapeJson(finding.rule_id) << "\",\n";
            std::cout << "          \"description\": \"" << escapeJson(finding.description)
                      << "\",\n";
            std::cout << "          \"offset\": " << finding.offset << ",\n";
            std::cout << "          \"length\": " << finding.length << '\n';
            std::cout << "        }" << (j + 1 == file_result.findings.size() ? '\n' : ',');
        }
        std::cout << "      ]\n";
        std::cout << "    }" << (i + 1 == summary.file_results.size() ? '\n' : ',');
    }

    std::cout << "  ]\n";
    std::cout << "}\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    CliOptions options;
    try {
        options =
            parseArguments(std::span<const char* const>(argv, static_cast<std::size_t>(argc)));
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        printUsage(std::cerr);
        return kExitError;
    }

    if (options.show_help) {
        printUsage(std::cout);
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

        if (options.json_output) {
            printJsonReport(summary, options.threads);
        } else {
            printTextReport(summary, options.threads);
        }

        if (summary.hasDetections()) {
            return kExitDetections;
        }
        return summary.isIncomplete() ? kExitError : kExitClean;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return kExitError;
    }
}
