#ifndef SENTINEL_ENGINE_REGEX_RULE_HPP
#define SENTINEL_ENGINE_REGEX_RULE_HPP

#include "engine/IRule.hpp"

#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sentinel::engine {

class RegexRule final : public IRule {
public:
    RegexRule(
        std::string rule_id,
        std::string pattern,
        std::string description,
        std::regex_constants::syntax_option_type flags = std::regex_constants::ECMAScript)
        : rule_id_(std::move(rule_id)),
          pattern_str_(std::move(pattern)),
          description_(std::move(description)) {
        if (pattern_str_.empty()) {
            throw std::invalid_argument(
                "RegexRule '" + rule_id_ + "': pattern must not be empty");
        }

        try {
            pattern_ = std::regex(pattern_str_, flags);
        } catch (const std::regex_error& error) {
            throw std::invalid_argument(
                "RegexRule '" + rule_id_ + "' has invalid pattern '" + pattern_str_ +
                "': " + error.what());
        }
    }

    [[nodiscard]] std::vector<RuleMatch> apply(std::string_view data) const override {
        std::vector<RuleMatch> matches;

        auto begin = std::cregex_iterator(data.begin(), data.end(), pattern_);
        auto end = std::cregex_iterator {};

        for (auto it = begin; it != end; ++it) {
            const auto& match = *it;
            matches.push_back(RuleMatch {
                .rule_id = rule_id_,
                .description = description_,
                .offset = static_cast<std::size_t>(match.position()),
            });
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
        return pattern_str_;
    }

private:
    std::string rule_id_;
    std::string pattern_str_;
    std::string description_;
    std::regex pattern_;
};

}  // namespace sentinel::engine

#endif
