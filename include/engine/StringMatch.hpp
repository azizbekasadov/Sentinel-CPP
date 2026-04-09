#ifndef SENTINEL_ENGINE_STRING_MATCH_HPP
#define SENTINEL_ENGINE_STRING_MATCH_HPP

#include "engine/IRule.hpp"

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sentinel::engine {

class StringMatchRule final : public IRule {
public:
    StringMatchRule(std::string rule_id, std::string pattern, std::string description)
        : rule_id_(std::move(rule_id)),
          pattern_(std::move(pattern)),
          description_(std::move(description)) {
        if (pattern_.empty()) {
            throw std::invalid_argument(
                "StringMatchRule '" + rule_id_ + "': pattern must not be empty");
        }
    }

    [[nodiscard]] std::vector<RuleMatch> apply(std::string_view data) const override {
        std::vector<RuleMatch> matches;

        std::size_t pos = data.find(pattern_);
        while (pos != std::string_view::npos) {
            matches.push_back(RuleMatch {
                .rule_id = rule_id_,
                .description = description_,
                .offset = pos,
            });

            pos = data.find(pattern_, pos + 1);
        }

        return matches;
    }

    [[nodiscard]] std::string_view id() const override {
        return rule_id_;
    }

    [[nodiscard]] std::string_view description() const override {
        return description_;
    }

    [[nodiscard]] std::string_view pattern() const {
        return pattern_;
    }

private:
    std::string rule_id_;
    std::string pattern_;
    std::string description_;
};

}  // namespace sentinel::engine

#endif
