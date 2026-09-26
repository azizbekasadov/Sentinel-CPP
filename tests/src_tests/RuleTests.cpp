#include "engine/RegexRule.hpp"
#include "engine/StringMatch.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <stdexcept>
#include <string>

namespace sentinel::engine {
namespace {

RulePtr makeStringRule(std::string id, std::string pattern, std::string description = "test rule") {
    return std::make_shared<StringMatchRule>(
        std::move(id), std::move(pattern), std::move(description));
}

}  // namespace
}  // namespace sentinel::engine

using sentinel::engine::RegexRule;
using sentinel::engine::RuleMatch;
using sentinel::engine::RulePtr;
using sentinel::engine::StringMatchRule;

TEST_CASE("RuleMatch compares by value", "[rules]") {
    const RuleMatch lhs {.rule_id = "RULE", .description = "description", .offset = 17};
    const RuleMatch rhs {.rule_id = "RULE", .description = "description", .offset = 17};
    const RuleMatch different {.rule_id = "RULE", .description = "description", .offset = 18};

    REQUIRE(lhs == rhs);
    REQUIRE(lhs != different);
}

TEST_CASE("StringMatchRule detects overlapping occurrences", "[rules][string]") {
    const StringMatchRule rule("overlap", "ABA", "Detect ABA");

    const auto matches = rule.apply("ABABA");

    REQUIRE(matches.size() == 2);
    REQUIRE(matches[0].offset == 0);
    REQUIRE(matches[1].offset == 2);
}

TEST_CASE("StringMatchRule rejects an empty pattern", "[rules][string]") {
    REQUIRE_THROWS_AS(StringMatchRule("empty", "", "Invalid"), std::invalid_argument);
}

TEST_CASE("RegexRule reports match offsets", "[rules][regex]") {
    const RegexRule rule("aws-key", R"(AKIA[0-9A-Z]{16})", "AWS access key");

    const auto matches = rule.apply("prefix AKIA1234567890ABCDEF suffix");

    REQUIRE(matches.size() == 1);
    REQUIRE(matches.front().rule_id == "aws-key");
    REQUIRE(matches.front().offset == 7);
}

TEST_CASE("RegexRule rejects invalid expressions", "[rules][regex]") {
    REQUIRE_THROWS_AS(RegexRule("broken", "(", "Invalid regex"), std::invalid_argument);
}

TEST_CASE("Rules stay polymorphic behind RulePtr", "[rules][polymorphism]") {
    RulePtr rule =
        sentinel::engine::makeStringRule("literal-secret", "password=", "Hardcoded credential");

    const auto matches = rule->apply("password=super-secret");

    REQUIRE(matches.size() == 1);
    REQUIRE(rule->id() == "literal-secret");
}

TEST_CASE("Rules expose their maximum match length", "[rules]") {
    const StringMatchRule literal("literal", "password=", "credential");
    const RegexRule bounded("bounded", "[0-9]+", "digits", std::regex_constants::ECMAScript, 128);
    const RegexRule defaulted("defaulted", "[0-9]+", "digits");

    REQUIRE(literal.maxMatchLength() == 9);
    REQUIRE(bounded.maxMatchLength() == 128);
    REQUIRE(defaulted.maxMatchLength() == sentinel::engine::kDefaultRegexMaxMatchLength);
}

TEST_CASE("RegexRule rejects a zero maximum match length", "[rules][regex]") {
    REQUIRE_THROWS_AS(RegexRule("zero", "a", "Invalid", std::regex_constants::ECMAScript, 0),
                      std::invalid_argument);
}

TEST_CASE("Matches carry the matched length", "[rules]") {
    const StringMatchRule literal("literal", "abc", "letters");
    const RegexRule regex("regex", "[0-9]+", "digits");

    REQUIRE(literal.apply("xxabcxx").front().length == 3);
    REQUIRE(regex.apply("id=12345;").front().length == 5);
}

TEST_CASE("Severity converts to and from its textual form", "[rules][severity]") {
    using sentinel::engine::parseSeverity;
    using sentinel::engine::Severity;
    using sentinel::engine::severityToString;

    REQUIRE(severityToString(Severity::Info) == "info");
    REQUIRE(severityToString(Severity::Low) == "low");
    REQUIRE(severityToString(Severity::Medium) == "medium");
    REQUIRE(severityToString(Severity::High) == "high");
    REQUIRE(severityToString(Severity::Critical) == "critical");

    REQUIRE(parseSeverity("high") == Severity::High);
    REQUIRE(parseSeverity("critical") == Severity::Critical);
    REQUIRE_FALSE(parseSeverity("HIGH").has_value());
    REQUIRE_FALSE(parseSeverity("urgent").has_value());
}

TEST_CASE("Rules carry severity and remediation metadata", "[rules][severity]") {
    using sentinel::engine::RuleMetadata;
    using sentinel::engine::Severity;

    const StringMatchRule literal(
        RuleMetadata {
            .id = "hardcoded-password",
            .description = "Hardcoded credential",
            .severity = Severity::Critical,
            .remediation = "Move the secret to a vault and rotate it.",
        },
        "password=");

    const RegexRule regex(
        RuleMetadata {
            .id = "aws-key",
            .description = "AWS access key id",
            .severity = Severity::High,
            .remediation = "Revoke the key in IAM.",
        },
        R"(AKIA[0-9A-Z]{16})");

    REQUIRE(literal.id() == "hardcoded-password");
    REQUIRE(literal.severity() == Severity::Critical);
    REQUIRE(literal.remediation() == "Move the secret to a vault and rotate it.");
    REQUIRE(regex.severity() == Severity::High);
    REQUIRE(regex.remediation() == "Revoke the key in IAM.");
}

TEST_CASE("Legacy rule constructors default to medium severity with no remediation",
          "[rules][severity]") {
    const StringMatchRule literal("literal", "abc", "letters");
    const RegexRule regex("regex", "[0-9]+", "digits");

    REQUIRE(literal.severity() == sentinel::engine::Severity::Medium);
    REQUIRE(literal.remediation().empty());
    REQUIRE(regex.severity() == sentinel::engine::Severity::Medium);
}

TEST_CASE("Matches carry the severity of the rule that produced them", "[rules][severity]") {
    using sentinel::engine::RuleMetadata;
    using sentinel::engine::Severity;

    const StringMatchRule rule(
        RuleMetadata {.id = "id", .description = "desc", .severity = Severity::Low}, "abc");

    REQUIRE(rule.apply("xxabc").front().severity == Severity::Low);
}

TEST_CASE("Rules reject an empty id", "[rules]") {
    using sentinel::engine::RuleMetadata;

    REQUIRE_THROWS_AS(StringMatchRule(RuleMetadata {.id = "", .description = "d"}, "abc"),
                      std::invalid_argument);
    REQUIRE_THROWS_AS(RegexRule(RuleMetadata {.id = "", .description = "d"}, "abc"),
                      std::invalid_argument);
}
