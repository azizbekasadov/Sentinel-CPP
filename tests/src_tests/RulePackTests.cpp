#include "engine/RulePack.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

using sentinel::engine::loadRulePack;
using sentinel::engine::parseRulePack;
using sentinel::engine::RulePackError;
using sentinel::engine::Severity;

namespace {

std::string messageOf(const std::string& json_text) {
    try {
        [[maybe_unused]] const auto pack = parseRulePack(json_text, "test-pack");
    } catch (const RulePackError& error) {
        return error.what();
    }
    return {};
}

}  // namespace

TEST_CASE("parseRulePack builds string and regex rules with their metadata", "[rulepack]") {
    const auto pack = parseRulePack(R"({
        "name": "secrets",
        "version": "1.2.0",
        "rules": [
            {
                "id": "aws-access-key",
                "type": "regex",
                "pattern": "AKIA[0-9A-Z]{16}",
                "description": "AWS access key id",
                "severity": "high",
                "remediation": "Revoke the key in IAM and rotate it.",
                "maxMatchLength": 64
            },
            {
                "id": "password-literal",
                "type": "string",
                "pattern": "password=",
                "description": "Hardcoded password assignment",
                "severity": "critical"
            }
        ]
    })");

    REQUIRE(pack.name == "secrets");
    REQUIRE(pack.version == "1.2.0");
    REQUIRE(pack.rules.size() == 2);

    const auto& aws = *pack.rules[0];
    REQUIRE(aws.id() == "aws-access-key");
    REQUIRE(aws.description() == "AWS access key id");
    REQUIRE(aws.severity() == Severity::High);
    REQUIRE(aws.remediation() == "Revoke the key in IAM and rotate it.");
    REQUIRE(aws.maxMatchLength() == 64);
    REQUIRE(aws.apply("key=AKIA1234567890ABCDEF").size() == 1);

    const auto& password = *pack.rules[1];
    REQUIRE(password.id() == "password-literal");
    REQUIRE(password.severity() == Severity::Critical);
    REQUIRE(password.remediation().empty());
    REQUIRE(password.maxMatchLength() == 9);
    REQUIRE(password.apply("password=x").size() == 1);
}

TEST_CASE("parseRulePack applies defaults for optional fields", "[rulepack]") {
    const auto pack = parseRulePack(R"({
        "rules": [{"id": "r", "type": "regex", "pattern": "[0-9]+"}]
    })");

    REQUIRE(pack.name.empty());
    REQUIRE(pack.version.empty());
    REQUIRE(pack.rules.size() == 1);
    REQUIRE(pack.rules[0]->description().empty());
    REQUIRE(pack.rules[0]->severity() == Severity::Medium);
    REQUIRE(pack.rules[0]->maxMatchLength() == sentinel::engine::kDefaultRegexMaxMatchLength);
}

TEST_CASE("parseRulePack supports case-insensitive regex rules", "[rulepack]") {
    const auto pack = parseRulePack(R"({
        "rules": [{"id": "r", "type": "regex", "pattern": "secret", "flags": ["icase"]}]
    })");

    REQUIRE(pack.rules[0]->apply("SECRET Secret secret").size() == 3);
}

TEST_CASE("parseRulePack rejects structurally invalid packs", "[rulepack][errors]") {
    REQUIRE(messageOf("[]").find("must be an object") != std::string::npos);
    REQUIRE(messageOf("{}").find("\"rules\"") != std::string::npos);
    REQUIRE(messageOf(R"({"rules": {}})").find("array") != std::string::npos);
    REQUIRE(messageOf(R"({"rules": [1]})").find("rules[0]") != std::string::npos);
    REQUIRE(messageOf(R"({"rules": []})").find("at least one rule") != std::string::npos);
}

TEST_CASE("parseRulePack reports malformed JSON with the source name", "[rulepack][errors]") {
    const auto message = messageOf("{ not json");

    REQUIRE(message.find("test-pack") != std::string::npos);
    REQUIRE(message.find("line 1") != std::string::npos);
}

TEST_CASE("parseRulePack validates each rule", "[rulepack][errors]") {
    const std::string prefix = R"({"rules": [)";
    const std::string suffix = "]}";

    SECTION("missing id") {
        const auto message = messageOf(prefix + R"({"type": "string", "pattern": "x"})" + suffix);
        REQUIRE(message.find("rules[0]") != std::string::npos);
        REQUIRE(message.find("\"id\"") != std::string::npos);
    }

    SECTION("duplicate id") {
        const auto message =
            messageOf(prefix + R"({"id": "dup", "type": "string", "pattern": "a"},)" +
                      R"({"id": "dup", "type": "string", "pattern": "b"})" + suffix);
        REQUIRE(message.find("duplicate") != std::string::npos);
        REQUIRE(message.find("dup") != std::string::npos);
    }

    SECTION("unknown type") {
        const auto message =
            messageOf(prefix + R"({"id": "r", "type": "glob", "pattern": "x"})" + suffix);
        REQUIRE(message.find("glob") != std::string::npos);
        REQUIRE(message.find("string") != std::string::npos);
        REQUIRE(message.find("regex") != std::string::npos);
    }

    SECTION("missing pattern") {
        const auto message = messageOf(prefix + R"({"id": "r", "type": "string"})" + suffix);
        REQUIRE(message.find("\"pattern\"") != std::string::npos);
    }

    SECTION("unknown severity") {
        const auto message = messageOf(
            prefix + R"({"id": "r", "type": "string", "pattern": "x", "severity": "urgent"})" +
            suffix);
        REQUIRE(message.find("urgent") != std::string::npos);
        REQUIRE(message.find("critical") != std::string::npos);
    }

    SECTION("non-positive maxMatchLength") {
        const auto message = messageOf(
            prefix + R"({"id": "r", "type": "regex", "pattern": "x", "maxMatchLength": 0})" +
            suffix);
        REQUIRE(message.find("maxMatchLength") != std::string::npos);
    }

    SECTION("unknown flag") {
        const auto message = messageOf(
            prefix + R"({"id": "r", "type": "regex", "pattern": "x", "flags": ["dotall"]})" +
            suffix);
        REQUIRE(message.find("dotall") != std::string::npos);
    }

    SECTION("invalid regex names the rule") {
        const auto message =
            messageOf(prefix + R"({"id": "broken", "type": "regex", "pattern": "("})" + suffix);
        REQUIRE(message.find("broken") != std::string::npos);
    }

    SECTION("wrong field type") {
        const auto message =
            messageOf(prefix + R"({"id": 7, "type": "string", "pattern": "x"})" + suffix);
        REQUIRE(message.find("\"id\"") != std::string::npos);
        REQUIRE(message.find("string") != std::string::npos);
    }
}

TEST_CASE("loadRulePack reads a pack from disk", "[rulepack][file]") {
    const auto path = std::filesystem::temp_directory_path() / "sentinel_rulepack_test.json";
    {
        std::ofstream stream(path);
        stream << R"({"name": "disk", "rules": [{"id": "r", "type": "string", "pattern": "x"}]})";
    }

    const auto pack = loadRulePack(path);
    std::filesystem::remove(path);

    REQUIRE(pack.name == "disk");
    REQUIRE(pack.rules.size() == 1);
}

TEST_CASE("loadRulePack reports a missing file with its path", "[rulepack][file]") {
    const auto path = std::filesystem::temp_directory_path() / "sentinel_missing_pack.json";

    try {
        [[maybe_unused]] const auto pack = loadRulePack(path);
        FAIL("expected RulePackError");
    } catch (const RulePackError& error) {
        REQUIRE(std::string(error.what()).find(path.filename().string()) != std::string::npos);
    }
}

TEST_CASE("the bundled secrets pack loads and documents every rule", "[rulepack][bundled]") {
    const auto pack =
        loadRulePack(std::filesystem::path(SENTINEL_SOURCE_DIR) / "rules" / "secrets.json");

    REQUIRE(pack.name == "secrets");
    REQUIRE(pack.rules.size() >= 6);
    for (const auto& rule : pack.rules) {
        INFO("rule " << rule->id());
        REQUIRE_FALSE(rule->description().empty());
        REQUIRE_FALSE(rule->remediation().empty());
    }
}

TEST_CASE("the bundled secrets pack detects common credential shapes", "[rulepack][bundled]") {
    const auto pack =
        loadRulePack(std::filesystem::path(SENTINEL_SOURCE_DIR) / "rules" / "secrets.json");

    std::string sample = "aws=AK";
    sample += "IA1234567890ABCDEF\n";
    sample += "-----BEGIN RSA PRIVATE KEY-----\n";
    sample += "github=gh";
    sample += "p_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\n";
    sample += "slack=xox";
    sample += "b-123456789012-123456789012-abcdefghijklmnopqrstuvwx\n";
    sample += "password=hunter2\n";

    std::size_t hits = 0;
    for (const auto& rule : pack.rules) {
        hits += rule->apply(sample).size();
    }

    REQUIRE(hits >= 5);
}
