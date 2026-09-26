#include "engine/Cli.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using sentinel::engine::buildRules;
using sentinel::engine::CliOptions;
using sentinel::engine::parseArguments;
using sentinel::engine::ReportFormat;
using sentinel::engine::Severity;

namespace {

CliOptions parse(std::vector<const char*> args) {
    args.insert(args.begin(), "sentinel");
    return parseArguments(std::span<const char* const>(args.data(), args.size()));
}

std::string errorOf(std::vector<const char*> args) {
    try {
        [[maybe_unused]] const auto options = parse(std::move(args));
    } catch (const std::invalid_argument& error) {
        return error.what();
    }
    return {};
}

}  // namespace

TEST_CASE("parseArguments reads the full option set", "[cli]") {
    const auto options = parse({"--path",
                                "src",
                                "--signature",
                                "API_KEY",
                                "--regex",
                                "AKIA[0-9A-Z]{16}",
                                "--include",
                                "*.cpp",
                                "--exclude",
                                "build/**",
                                "--threads",
                                "8",
                                "--max-findings",
                                "10",
                                "--format",
                                "json",
                                "--include-clean-files",
                                "--scan-binary-files"});

    REQUIRE(options.target_path == "src");
    REQUIRE(options.signatures == std::vector<std::string> {"API_KEY"});
    REQUIRE(options.regex_patterns == std::vector<std::string> {"AKIA[0-9A-Z]{16}"});
    REQUIRE(options.include_globs == std::vector<std::string> {"*.cpp"});
    REQUIRE(options.exclude_globs == std::vector<std::string> {"build/**"});
    REQUIRE(options.threads == 8);
    REQUIRE(options.max_findings_per_file == 10);
    REQUIRE(options.format == ReportFormat::Json);
    REQUIRE(options.include_clean_files);
    REQUIRE(options.scan_binary_files);
    REQUIRE_FALSE(options.show_help);
    REQUIRE_FALSE(options.show_version);
}

TEST_CASE("parseArguments defaults to text output and automatic threads", "[cli]") {
    const auto options = parse({"--path", "."});

    REQUIRE(options.format == ReportFormat::Text);
    REQUIRE(options.threads == 0);
    REQUIRE(options.max_findings_per_file == 64);
    REQUIRE(options.rule_packs.empty());
}

TEST_CASE("parseArguments accepts sarif output", "[cli]") {
    REQUIRE(parse({"--path", ".", "--format", "sarif"}).format == ReportFormat::Sarif);
    REQUIRE(errorOf({"--path", ".", "--format", "xml"}).find("xml") != std::string::npos);
}

TEST_CASE("parseArguments handles --help and --version without requiring --path", "[cli]") {
    REQUIRE(parse({"--help"}).show_help);
    REQUIRE(parse({"-h"}).show_help);
    REQUIRE(parse({"--version"}).show_version);
}

TEST_CASE("parseArguments requires --path", "[cli][errors]") {
    REQUIRE(errorOf({}).find("--path") != std::string::npos);
    REQUIRE(errorOf({"--signature", "x"}).find("--path") != std::string::npos);
}

TEST_CASE("parseArguments rejects malformed numeric values", "[cli][errors]") {
    REQUIRE(errorOf({"--path", ".", "--threads", "-1"}).find("-1") != std::string::npos);
    REQUIRE(errorOf({"--path", ".", "--threads", "abc"}).find("abc") != std::string::npos);
    REQUIRE(errorOf({"--path", ".", "--threads", "5xyz"}).find("5xyz") != std::string::npos);
    REQUIRE(errorOf({"--path", ".", "--threads", ""}).find("--threads") != std::string::npos);
    REQUIRE(errorOf({"--path", ".", "--max-findings", "99999999999999999999"}).find("too large") !=
            std::string::npos);
}

TEST_CASE("parseArguments distinguishes unknown flags from missing values", "[cli][errors]") {
    REQUIRE(errorOf({"--path", ".", "--bogus"}).find("Unknown argument: --bogus") !=
            std::string::npos);
    REQUIRE(errorOf({"--path"}).find("Missing value for argument: --path") != std::string::npos);
    REQUIRE(errorOf({"--path", ".", "--threads"}).find("Missing value") != std::string::npos);
}

TEST_CASE("parseArguments collects rule pack paths", "[cli]") {
    const auto options = parse({"--path", ".", "--rules", "a.json", "--rules", "b.json"});

    REQUIRE(options.rule_packs.size() == 2);
    REQUIRE(options.rule_packs[0] == "a.json");
    REQUIRE(options.rule_packs[1] == "b.json");
}

TEST_CASE("buildRules falls back to the built-in defaults", "[cli][rules]") {
    const auto rules = buildRules(parse({"--path", "."}));

    REQUIRE(rules.size() >= 5);
    bool saw_password = false;
    for (const auto& rule : rules) {
        REQUIRE_FALSE(rule->description().empty());
        REQUIRE_FALSE(rule->remediation().empty());
        if (rule->id() == "password-literal") {
            saw_password = true;
            REQUIRE(rule->severity() == Severity::High);
            REQUIRE(rule->apply("password=x").size() == 1);
        }
    }
    REQUIRE(saw_password);
}

TEST_CASE("buildRules uses only explicit signatures and regexes when given", "[cli][rules]") {
    const auto rules =
        buildRules(parse({"--path", ".", "--signature", "EVIL", "--regex", "[0-9]{4}"}));

    REQUIRE(rules.size() == 2);
    REQUIRE(rules[0]->id() == "EVIL");
    REQUIRE(rules[1]->id() == "regex-1");
    REQUIRE(rules[1]->apply("year 2024").size() == 1);
}

TEST_CASE("buildRules loads rule packs and combines them with inline rules", "[cli][rules]") {
    const auto pack_path = std::filesystem::temp_directory_path() / "sentinel_cli_pack.json";
    {
        std::ofstream stream(pack_path);
        stream << R"({"rules": [{"id": "from-pack", "type": "string", "pattern": "PACKED"}]})";
    }

    const auto rules = buildRules(
        parse({"--path", ".", "--rules", pack_path.string().c_str(), "--signature", "INLINE"}));
    std::filesystem::remove(pack_path);

    REQUIRE(rules.size() == 2);
    REQUIRE(rules[0]->id() == "INLINE");
    REQUIRE(rules[1]->id() == "from-pack");
}

TEST_CASE("buildRules rejects rule ids that collide across sources", "[cli][rules][errors]") {
    const auto pack_path = std::filesystem::temp_directory_path() / "sentinel_cli_dup.json";
    {
        std::ofstream stream(pack_path);
        stream << R"({"rules": [{"id": "SAME", "type": "string", "pattern": "x"}]})";
    }

    const auto options =
        parse({"--path", ".", "--rules", pack_path.string().c_str(), "--signature", "SAME"});
    std::string message;
    try {
        [[maybe_unused]] const auto rules = buildRules(options);
    } catch (const std::invalid_argument& error) {
        message = error.what();
    }
    std::filesystem::remove(pack_path);

    REQUIRE(message.find("SAME") != std::string::npos);
}

TEST_CASE("buildRules surfaces rule pack errors as invalid arguments", "[cli][rules][errors]") {
    const auto options = parse({"--path", ".", "--rules", "/definitely/missing/pack.json"});

    REQUIRE_THROWS_AS(buildRules(options), std::invalid_argument);
}
