#include "engine/RegexRule.hpp"
#include "engine/StringMatch.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <regex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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
        RuleMetadata {
            .id = "id",
            .description = "desc",
            .severity = Severity::Low,
            .remediation = {},
        },
        "abc");

    REQUIRE(rule.apply("xxabc").front().severity == Severity::Low);
}

TEST_CASE("Rules reject an empty id", "[rules]") {
    using sentinel::engine::RuleMetadata;

    REQUIRE_THROWS_AS(StringMatchRule(
                          RuleMetadata {
                              .id = "",
                              .description = "d",
                              .severity = sentinel::engine::Severity::Medium,
                              .remediation = {},
                          },
                          "abc"),
                      std::invalid_argument);
    REQUIRE_THROWS_AS(RegexRule(
                          RuleMetadata {
                              .id = "",
                              .description = "d",
                              .severity = sentinel::engine::Severity::Medium,
                              .remediation = {},
                          },
                          "abc"),
                      std::invalid_argument);
}

TEST_CASE("RegexRule extracts a literal prefix it can prefilter on", "[rules][regex][prefix]") {
    REQUIRE(RegexRule("r", R"(AKIA[0-9A-Z]{16})", "d").literalPrefix() == "AKIA");
    REQUIRE(RegexRule("r", "-----BEGIN (RSA )?PRIVATE KEY-----", "d").literalPrefix() ==
            "-----BEGIN ");
    REQUIRE(RegexRule("r", "gh[pousr]_[A-Za-z0-9]{36}", "d").literalPrefix() == "gh");
    REQUIRE(RegexRule("r", "plainliteral", "d").literalPrefix() == "plainliteral");

    // A quantifier applies to the preceding character, which is therefore not guaranteed.
    REQUIRE(RegexRule("r", "abc?d", "d").literalPrefix() == "ab");
    REQUIRE(RegexRule("r", "abc*", "d").literalPrefix() == "ab");
    REQUIRE(RegexRule("r", "abc{2,3}", "d").literalPrefix() == "ab");
    REQUIRE(RegexRule("r", "abc+", "d").literalPrefix() == "ab");

    // Anything that is not a plain literal at the start disables the prefilter.
    REQUIRE(RegexRule("r", "(AKIA|ASIA)[0-9A-Z]{16}", "d").literalPrefix().empty());
    REQUIRE(RegexRule("r", "[0-9]+", "d").literalPrefix().empty());
    REQUIRE(RegexRule("r", "^foo", "d").literalPrefix().empty());
    REQUIRE(RegexRule("r", R"(\bkey)", "d").literalPrefix().empty());
    REQUIRE(RegexRule("r", ".x", "d").literalPrefix().empty());
    REQUIRE(RegexRule("r", "a|b", "d").literalPrefix().empty());

    // Escaped characters and case-insensitive matching fall back to the full scan.
    REQUIRE(RegexRule("r", R"(a\.b)", "d").literalPrefix() == "a");
    REQUIRE(RegexRule("r", "secret", "d", std::regex_constants::icase).literalPrefix().empty());
}

TEST_CASE("RegexRule prefiltering reports the same matches as a plain scan",
          "[rules][regex][prefix]") {
    const std::string pattern = R"(AKIA[0-9A-Z]{16})";
    const RegexRule rule("aws", pattern, "aws key");
    REQUIRE_FALSE(rule.literalPrefix().empty());

    const std::string text =
        "AKIA1234567890ABCDEF start, then AKIA too short, AKIAAKIA1234567890ABCDEF adjacent, "
        "and one at the very end AKIAZZZZZZZZZZZZZZZZ";

    // Reference answer straight from the standard engine, without any prefiltering.
    std::vector<std::pair<std::size_t, std::size_t>> expected;
    const std::regex reference(pattern);
    for (auto it = std::sregex_iterator(text.begin(), text.end(), reference);
         it != std::sregex_iterator {};
         ++it) {
        expected.emplace_back(static_cast<std::size_t>(it->position()),
                              static_cast<std::size_t>(it->length()));
    }

    const auto matches = rule.apply(text);

    REQUIRE(matches.size() == expected.size());
    REQUIRE(matches.size() == 3);
    for (std::size_t i = 0; i < matches.size(); ++i) {
        REQUIRE(matches[i].offset == expected[i].first);
        REQUIRE(matches[i].length == expected[i].second);
    }
    REQUIRE(matches[0].offset == 0);
    REQUIRE(matches[1].offset == text.find("AKIAAKIA"));
    REQUIRE(matches[2].offset == text.size() - 20);
}

TEST_CASE("RegexRule prefiltering preserves anchors that look at the previous character",
          "[rules][regex][prefix]") {
    const RegexRule word_boundary("wb", R"(key\b[0-9])", "d");
    REQUIRE(word_boundary.apply("monkey 1 key 2").empty());

    const RegexRule bounded("b", R"(key[0-9]\b)", "d");
    const auto matches = bounded.apply("monkey1 key2 key33");
    REQUIRE(matches.size() == 2);
    REQUIRE(matches[0].offset == 3);
    REQUIRE(matches[1].offset == 8);
}

TEST_CASE("RegexRule prefiltering handles a prefix with no following match",
          "[rules][regex][prefix]") {
    const RegexRule rule("r", "sk_live_[0-9a-z]{4}", "d");

    REQUIRE(rule.apply("sk_live_ sk_live sk_live_12 sk_live_abcd!").size() == 1);
    REQUIRE(rule.apply("").empty());
    REQUIRE(rule.apply("sk_liv").empty());
}
