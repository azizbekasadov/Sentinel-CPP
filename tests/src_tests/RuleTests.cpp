#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <stdexcept>
#include <string>

#include "engine/RegexRule.hpp"
#include "engine/StringMatch.hpp"

namespace sentinel::engine {
namespace {

RulePtr makeStringRule(std::string id, std::string pattern, std::string description = "test rule") {
    return std::make_shared<StringMatchRule>(
        std::move(id),
        std::move(pattern),
        std::move(description));
}

}  // namespace
}  // namespace sentinel::engine

using sentinel::engine::RegexRule;
using sentinel::engine::RuleMatch;
using sentinel::engine::RulePtr;
using sentinel::engine::StringMatchRule;

TEST_CASE("RuleMatch compares by value", "[rules]") {
    const RuleMatch lhs {"RULE", "description", 17};
    const RuleMatch rhs {"RULE", "description", 17};
    const RuleMatch different {"RULE", "description", 18};

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
    RulePtr rule = sentinel::engine::makeStringRule("literal-secret", "password=", "Hardcoded credential");

    const auto matches = rule->apply("password=super-secret");

    REQUIRE(matches.size() == 1);
    REQUIRE(rule->id() == "literal-secret");
}
