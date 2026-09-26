#ifndef SENTINEL_ENGINE_STRING_MATCH_HPP
#define SENTINEL_ENGINE_STRING_MATCH_HPP

#include "engine/IRule.hpp"

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sentinel::engine {

class StringMatchRule final : public IRule {
public:
    StringMatchRule(RuleMetadata metadata, std::string pattern)
        : metadata_(std::move(metadata)),
          pattern_(std::move(pattern)) {
        if (metadata_.id.empty()) {
            throw std::invalid_argument("StringMatchRule: rule id must not be empty");
        }

        if (pattern_.empty()) {
            throw std::invalid_argument("StringMatchRule '" + metadata_.id +
                                        "': pattern must not be empty");
        }
    }

    StringMatchRule(std::string rule_id, std::string pattern, std::string description)
        : StringMatchRule(
              RuleMetadata {.id = std::move(rule_id), .description = std::move(description)},
              std::move(pattern)) {}

    [[nodiscard]] std::vector<RuleMatch> apply(std::string_view data) const override {
        std::vector<RuleMatch> matches;

        std::size_t pos = data.find(pattern_);
        while (pos != std::string_view::npos) {
            matches.push_back(RuleMatch {
                .rule_id = metadata_.id,
                .description = metadata_.description,
                .offset = pos,
                .length = pattern_.size(),
                .severity = metadata_.severity,
            });

            pos = data.find(pattern_, pos + 1);
        }

        return matches;
    }

    [[nodiscard]] std::string_view id() const override {
        return metadata_.id;
    }

    [[nodiscard]] std::string_view description() const override {
        return metadata_.description;
    }

    [[nodiscard]] Severity severity() const noexcept override {
        return metadata_.severity;
    }

    [[nodiscard]] std::string_view remediation() const override {
        return metadata_.remediation;
    }

    [[nodiscard]] std::size_t maxMatchLength() const noexcept override {
        return pattern_.size();
    }

    [[nodiscard]] std::string_view pattern() const {
        return pattern_;
    }

private:
    RuleMetadata metadata_;
    std::string pattern_;
};

}  // namespace sentinel::engine

#endif
