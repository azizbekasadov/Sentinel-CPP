#ifndef SENTINEL_ENGINE_REGEX_RULE_HPP
#define SENTINEL_ENGINE_REGEX_RULE_HPP

#include "engine/IRule.hpp"

#include <cstddef>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sentinel::engine {

// Regular expressions have no intrinsic upper bound on match length, so the scanner needs an
// explicit one to size the overlap between chunks. 4 KiB comfortably covers keys, tokens and
// PEM headers while keeping the per-file working set small.
inline constexpr std::size_t kDefaultRegexMaxMatchLength = std::size_t {4} * 1024;

class RegexRule final : public IRule {
public:
    RegexRule(std::string rule_id,
              std::string pattern,
              std::string description,
              std::regex_constants::syntax_option_type flags = std::regex_constants::ECMAScript,
              std::size_t max_match_length = kDefaultRegexMaxMatchLength)
        : rule_id_(std::move(rule_id)),
          pattern_str_(std::move(pattern)),
          description_(std::move(description)),
          max_match_length_(max_match_length) {
        if (pattern_str_.empty()) {
            throw std::invalid_argument("RegexRule '" + rule_id_ + "': pattern must not be empty");
        }

        if (max_match_length_ == 0) {
            throw std::invalid_argument("RegexRule '" + rule_id_ +
                                        "': max match length must be positive");
        }

        try {
            pattern_ = std::regex(pattern_str_, flags);
        } catch (const std::regex_error& error) {
            throw std::invalid_argument("RegexRule '" + rule_id_ + "' has invalid pattern '" +
                                        pattern_str_ + "': " + error.what());
        }
    }

    [[nodiscard]] std::vector<RuleMatch> apply(std::string_view data) const override {
        std::vector<RuleMatch> matches;

        const auto begin = std::cregex_iterator(data.data(), data.data() + data.size(), pattern_);
        const auto end = std::cregex_iterator {};

        for (auto it = begin; it != end; ++it) {
            const auto& match = *it;
            matches.push_back(RuleMatch {
                .rule_id = rule_id_,
                .description = description_,
                .offset = static_cast<std::size_t>(match.position()),
                .length = static_cast<std::size_t>(match.length()),
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

    [[nodiscard]] std::size_t maxMatchLength() const noexcept override {
        return max_match_length_;
    }

    [[nodiscard]] std::string_view pattern() const {
        return pattern_str_;
    }

private:
    std::string rule_id_;
    std::string pattern_str_;
    std::string description_;
    std::size_t max_match_length_;
    std::regex pattern_;
};

}  // namespace sentinel::engine

#endif
