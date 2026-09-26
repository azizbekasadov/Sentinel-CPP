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
    RegexRule(RuleMetadata metadata,
              std::string pattern,
              std::regex_constants::syntax_option_type flags = std::regex_constants::ECMAScript,
              std::size_t max_match_length = kDefaultRegexMaxMatchLength)
        : metadata_(std::move(metadata)),
          pattern_str_(std::move(pattern)),
          max_match_length_(max_match_length) {
        if (metadata_.id.empty()) {
            throw std::invalid_argument("RegexRule: rule id must not be empty");
        }

        if (pattern_str_.empty()) {
            throw std::invalid_argument("RegexRule '" + metadata_.id +
                                        "': pattern must not be empty");
        }

        if (max_match_length_ == 0) {
            throw std::invalid_argument("RegexRule '" + metadata_.id +
                                        "': max match length must be positive");
        }

        try {
            pattern_ = std::regex(pattern_str_, flags);
        } catch (const std::regex_error& error) {
            throw std::invalid_argument("RegexRule '" + metadata_.id + "' has invalid pattern '" +
                                        pattern_str_ + "': " + error.what());
        }
    }

    RegexRule(std::string rule_id,
              std::string pattern,
              std::string description,
              std::regex_constants::syntax_option_type flags = std::regex_constants::ECMAScript,
              std::size_t max_match_length = kDefaultRegexMaxMatchLength)
        : RegexRule(RuleMetadata {.id = std::move(rule_id), .description = std::move(description)},
                    std::move(pattern),
                    flags,
                    max_match_length) {}

    [[nodiscard]] std::vector<RuleMatch> apply(std::string_view data) const override {
        std::vector<RuleMatch> matches;

        const auto begin = std::cregex_iterator(data.data(), data.data() + data.size(), pattern_);
        const auto end = std::cregex_iterator {};

        for (auto it = begin; it != end; ++it) {
            const auto& match = *it;
            matches.push_back(RuleMatch {
                .rule_id = metadata_.id,
                .description = metadata_.description,
                .offset = static_cast<std::size_t>(match.position()),
                .length = static_cast<std::size_t>(match.length()),
                .severity = metadata_.severity,
            });
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
        return max_match_length_;
    }

    [[nodiscard]] std::string_view pattern() const {
        return pattern_str_;
    }

private:
    RuleMetadata metadata_;
    std::string pattern_str_;
    std::size_t max_match_length_;
    std::regex pattern_;
};

}  // namespace sentinel::engine

#endif
