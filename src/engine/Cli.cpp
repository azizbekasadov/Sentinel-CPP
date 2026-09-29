#include "engine/Cli.hpp"

#include "engine/RegexRule.hpp"
#include "engine/RulePack.hpp"
#include "engine/StringMatch.hpp"

#include <charconv>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#ifndef SENTINEL_VERSION
#define SENTINEL_VERSION "0.0.0"
#endif

namespace sentinel::engine {
namespace {

constexpr std::string_view kVersion = SENTINEL_VERSION;

constexpr std::string_view kUsage =
    "Usage: sentinel --path <target> [--signature <text> ...] [--regex <expr> ...]\n"
    "                [--rules <pack.json> ...] [--threads <n>] [--max-findings <n>]\n"
    "                [--format text|json|sarif] [--include-clean-files]\n"
    "                [--include <glob> ...] [--exclude <glob> ...] [--scan-binary-files]\n"
    "       sentinel --help | --version\n"
    "\n"
    "Options:\n"
    "  --signature <text>   Literal to search for. Repeatable.\n"
    "  --regex <expr>       ECMAScript regular expression to search for. Repeatable.\n"
    "  --rules <pack.json>  JSON rule pack with ids, severities and remediation. Repeatable.\n"
    "                       Without any rule option the built-in defaults are used.\n"
    "  --threads <n>        Worker threads; 0 or omitted selects the hardware default.\n"
    "  --max-findings <n>   Findings reported per file; 0 means unlimited (default 64).\n"
    "  --format <fmt>       text (default), json, or sarif (SARIF 2.1.0).\n"
    "  --include <glob>     Only scan matching files. A glob without '/' matches the file\n"
    "                       name at any depth; '*' and '?' never cross '/', '**' does.\n"
    "  --exclude <glob>     Skip matching files; evaluated after --include.\n"
    "  --include-clean-files  Report files without findings as well.\n"
    "  --scan-binary-files  Scan files that look binary instead of skipping them.\n"
    "\n"
    "Exit status:\n"
    "  0  no findings and every file was scanned\n"
    "  1  at least one finding\n"
    "  2  invalid arguments, or the scan was incomplete (unreadable files or warnings)\n"
    "\n"
    "Examples:\n"
    "  sentinel --path ./src\n"
    "  sentinel --path ./src --rules rules/secrets.json --format sarif > results.sarif\n"
    "  sentinel --path ./src --regex \"AKIA[0-9A-Z]{16}\" --format json\n"
    "  sentinel --path . --include \"*.cpp\" --exclude \"build/**\"\n";

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

std::vector<RulePtr> defaultRules() {
    return {
        std::make_shared<StringMatchRule>(
            RuleMetadata {
                .id = "evil-code-marker",
                .description = "Test marker string EVIL_CODE",
                .severity = Severity::High,
                .remediation = "Remove the marker; it is used to validate scanner coverage.",
            },
            "EVIL_CODE"),
        std::make_shared<StringMatchRule>(
            RuleMetadata {
                .id = "virus-end-marker",
                .description = "Test marker string VIRUS_END",
                .severity = Severity::High,
                .remediation = "Remove the marker; it is used to validate scanner coverage.",
            },
            "VIRUS_END"),
        std::make_shared<StringMatchRule>(
            RuleMetadata {
                .id = "malware-start-marker",
                .description = "Test marker string MALWARE_START",
                .severity = Severity::High,
                .remediation = "Remove the marker; it is used to validate scanner coverage.",
            },
            "MALWARE_START"),
        std::make_shared<StringMatchRule>(
            RuleMetadata {
                .id = "api-key-literal",
                .description = "Literal API_KEY token",
                .severity = Severity::Medium,
                .remediation =
                    "Load API keys from the environment or a secret store instead of source.",
            },
            "API_KEY"),
        std::make_shared<StringMatchRule>(
            RuleMetadata {
                .id = "password-literal",
                .description = "Literal password assignment",
                .severity = Severity::High,
                .remediation = "Read passwords from configuration injected at deploy time and "
                               "rotate the exposed value.",
            },
            "password="),
    };
}

void addRule(std::vector<RulePtr>& rules, std::set<std::string>& ids, RulePtr rule) {
    const std::string id(rule->id());
    if (!ids.insert(id).second) {
        throw std::invalid_argument("Rule id '" + id + "' is defined more than once");
    }
    rules.push_back(std::move(rule));
}

}  // namespace

std::string_view toolVersion() noexcept {
    return kVersion;
}

std::string_view usageText() noexcept {
    return kUsage;
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

        if (arg == "--version") {
            options.show_version = true;
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
        } else if (arg == "--rules") {
            options.rule_packs.emplace_back(std::string(require_value(i, arg)));
        } else if (arg == "--include") {
            options.include_globs.emplace_back(require_value(i, arg));
        } else if (arg == "--exclude") {
            options.exclude_globs.emplace_back(require_value(i, arg));
        } else if (arg == "--threads") {
            options.threads = parseSizeArgument(arg, require_value(i, arg));
        } else if (arg == "--max-findings") {
            options.max_findings_per_file = parseSizeArgument(arg, require_value(i, arg));
        } else if (arg == "--format") {
            const auto text = require_value(i, arg);
            const auto format = parseReportFormat(text);
            if (!format) {
                throw std::invalid_argument("Unsupported format: " + std::string(text) +
                                            " (expected text, json or sarif)");
            }
            options.format = *format;
        } else {
            throw std::invalid_argument("Unknown argument: " + std::string(arg));
        }
    }

    if (options.target_path.empty()) {
        throw std::invalid_argument("You must provide --path");
    }

    return options;
}

std::vector<RulePtr> buildRules(const CliOptions& options) {
    if (options.signatures.empty() && options.regex_patterns.empty() &&
        options.rule_packs.empty()) {
        return defaultRules();
    }

    std::vector<RulePtr> rules;
    std::set<std::string> ids;

    for (const auto& signature : options.signatures) {
        addRule(rules,
                ids,
                std::make_shared<StringMatchRule>(
                    RuleMetadata {
                        .id = signature,
                        .description = "Matched fixed signature '" + signature + "'",
                        .severity = Severity::Medium,
                        .remediation = {},
                    },
                    signature));
    }

    std::size_t regex_index = 0;
    for (const auto& pattern : options.regex_patterns) {
        ++regex_index;
        addRule(rules,
                ids,
                std::make_shared<RegexRule>(
                    RuleMetadata {
                        .id = "regex-" + std::to_string(regex_index),
                        .description = "Matched regex pattern '" + pattern + "'",
                        .severity = Severity::Medium,
                        .remediation = {},
                    },
                    pattern));
    }

    for (const auto& pack_path : options.rule_packs) {
        RulePack pack;
        try {
            pack = loadRulePack(pack_path);
        } catch (const RulePackError& error) {
            throw std::invalid_argument(error.what());
        }
        for (auto& rule : pack.rules) {
            addRule(rules, ids, std::move(rule));
        }
    }

    return rules;
}

}  // namespace sentinel::engine
