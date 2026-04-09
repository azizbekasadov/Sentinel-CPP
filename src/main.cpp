#include "engine/RegexRule.hpp"
#include "engine/Scanner.hpp"
#include "engine/StringMatch.hpp"

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using sentinel::engine::RulePtr;
using sentinel::engine::ScanOptions;
using sentinel::engine::ScanSummary;
using sentinel::engine::Scanner;

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
};

constexpr std::string_view kUsage =
    "Usage: sentinel --path <target> [--signature <text> ...] [--regex <expr> ...]\n"
    "                [--threads <n>] [--max-findings <n>] [--format text|json]\n"
    "                [--include-clean-files] [--include <glob> ...] [--exclude <glob> ...]\n"
    "                [--scan-binary-files]\n"
    "\n"
    "Examples:\n"
    "  sentinel --path ./src\n"
    "  sentinel --path ./src --signature API_KEY --signature password=\n"
    "  sentinel --path ./src --regex \"AKIA[0-9A-Z]{16}\" --format json\n"
    "  sentinel --path . --include \"*.cpp\" --exclude \"build/*\"\n";

std::vector<std::string> defaultSignatures() {
    return {"EVIL_CODE", "VIRUS_END", "MALWARE_START", "API_KEY", "password="};
}

void printUsage(std::ostream& stream) {
    stream << kUsage;
}

std::string escapeJson(std::string_view input) {
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
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default:
                output += ch;
                break;
        }
    }

    return output;
}

CliOptions parseArguments(int argc, char* argv[]) {
    CliOptions options;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            printUsage(std::cout);
            std::exit(EXIT_SUCCESS);
        }

        if (i + 1 >= argc && arg != "--include-clean-files" && arg != "--scan-binary-files") {
            throw std::invalid_argument("Missing value for argument: " + arg);
        }

        if (arg == "--path") {
            options.target_path = argv[++i];
            continue;
        }

        if (arg == "--signature") {
            options.signatures.emplace_back(argv[++i]);
            continue;
        }

        if (arg == "--regex") {
            options.regex_patterns.emplace_back(argv[++i]);
            continue;
        }

        if (arg == "--include") {
            options.include_globs.emplace_back(argv[++i]);
            continue;
        }

        if (arg == "--exclude") {
            options.exclude_globs.emplace_back(argv[++i]);
            continue;
        }

        if (arg == "--threads") {
            options.threads = std::stoul(argv[++i]);
            continue;
        }

        if (arg == "--max-findings") {
            options.max_findings_per_file = std::stoul(argv[++i]);
            continue;
        }

        if (arg == "--format") {
            const std::string format = argv[++i];
            if (format == "json") {
                options.json_output = true;
            } else if (format != "text") {
                throw std::invalid_argument("Unsupported format: " + format);
            }
            continue;
        }

        if (arg == "--include-clean-files") {
            options.include_clean_files = true;
            continue;
        }

        if (arg == "--scan-binary-files") {
            options.scan_binary_files = true;
            continue;
        }

        throw std::invalid_argument("Unknown argument: " + arg);
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
            rule_id.str(),
            pattern,
            "Matched regex pattern '" + pattern + "'"));
    }

    return rules;
}

void printTextReport(const ScanSummary& summary, std::size_t configured_threads) {
    std::cout << "Sentinel-CPP Scan Report\n";
    std::cout << "Root: " << summary.root << '\n';
    std::cout << "Files scanned: " << summary.files_scanned << '\n';
    std::cout << "Files with detections: " << summary.files_with_detections << '\n';
    std::cout << "Files skipped: " << summary.files_skipped << '\n';
    std::cout << "Bytes scanned: " << summary.bytes_scanned << '\n';
    std::cout << "Threads: "
              << (configured_threads == 0 ? std::string("auto") : std::to_string(configured_threads))
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
            continue;
        }

        if (file_result.skipped_reason) {
            std::cout << "    skipped: " << *file_result.skipped_reason << '\n';
            continue;
        }

        if (file_result.findings.empty()) {
            std::cout << "    clean\n";
            continue;
        }

        for (const auto& finding : file_result.findings) {
            std::cout << "    - [" << finding.rule_id << "] offset=" << finding.offset
                      << " :: " << finding.description << '\n';
        }
    }
}

void printJsonReport(const ScanSummary& summary, std::size_t configured_threads) {
    std::cout << "{\n";
    std::cout << "  \"root\": \"" << escapeJson(summary.root.string()) << "\",\n";
    std::cout << "  \"filesScanned\": " << summary.files_scanned << ",\n";
    std::cout << "  \"filesWithDetections\": " << summary.files_with_detections << ",\n";
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

        if (file_result.error) {
            std::cout << "      \"error\": \"" << escapeJson(*file_result.error) << "\",\n";
        } else {
            std::cout << "      \"error\": null,\n";
        }

        if (file_result.skipped_reason) {
            std::cout << "      \"skippedReason\": \"" << escapeJson(*file_result.skipped_reason)
                      << "\",\n";
        } else {
            std::cout << "      \"skippedReason\": null,\n";
        }

        std::cout << "      \"findings\": [\n";
        for (std::size_t j = 0; j < file_result.findings.size(); ++j) {
            const auto& finding = file_result.findings[j];
            std::cout << "        {\n";
            std::cout << "          \"ruleId\": \"" << escapeJson(finding.rule_id) << "\",\n";
            std::cout << "          \"description\": \"" << escapeJson(finding.description) << "\",\n";
            std::cout << "          \"offset\": " << finding.offset << '\n';
            std::cout << "        }" << (j + 1 == file_result.findings.size() ? '\n' : ',') ;
        }
        std::cout << "      ]\n";
        std::cout << "    }" << (i + 1 == summary.file_results.size() ? '\n' : ',') ;
    }

    std::cout << "  ]\n";
    std::cout << "}\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        const auto options = parseArguments(argc, argv);
        const auto rules = buildRules(options);

        if (!std::filesystem::exists(options.target_path)) {
            std::cerr << "Target path does not exist: " << options.target_path << '\n';
            return EXIT_FAILURE;
        }

        const Scanner scanner;
        const auto summary = scanner.scanPath(
            options.target_path,
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

        return summary.hasDetections() ? EXIT_FAILURE : EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        printUsage(std::cerr);
        return EXIT_FAILURE;
    }
}
