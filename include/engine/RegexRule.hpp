#ifndef SENTINEL_ENGINE_REGEX_RULE_HPP
#define SENTINEL_ENGINE_REGEX_RULE_HPP

#include "engine/IRule.hpp"

#include <algorithm>
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

        if ((flags & std::regex_constants::icase) == 0) {
            literal_prefix_ = extractLiteralPrefix(pattern_str_);
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
        if (literal_prefix_.empty()) {
            return applyFullScan(data);
        }
        return applyWithPrefilter(data);
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

    // Literal text every match must start with, or empty when the pattern does not begin with
    // plain characters. Used to skip the regex engine over regions that cannot match.
    [[nodiscard]] std::string_view literalPrefix() const noexcept {
        return literal_prefix_;
    }

private:
    // True when the pattern contains an alternation at nesting depth zero, in which case a
    // match may start with any branch and no single literal prefix exists.
    static bool hasTopLevelAlternation(std::string_view pattern) {
        int depth = 0;
        bool in_class = false;
        for (std::size_t i = 0; i < pattern.size(); ++i) {
            const char ch = pattern[i];
            if (ch == '\\') {
                ++i;
            } else if (in_class) {
                in_class = ch != ']';
            } else if (ch == '[') {
                in_class = true;
            } else if (ch == '(') {
                ++depth;
            } else if (ch == ')') {
                --depth;
            } else if (ch == '|' && depth == 0) {
                return true;
            }
        }
        return false;
    }

    static std::string extractLiteralPrefix(std::string_view pattern) {
        constexpr std::string_view kMetacharacters = R"(\^$.|?*+()[]{})";
        constexpr std::string_view kQuantifiers = "?*+{";

        if (hasTopLevelAlternation(pattern)) {
            return {};
        }

        std::size_t length = 0;
        while (length < pattern.size() &&
               kMetacharacters.find(pattern[length]) == std::string_view::npos) {
            ++length;
        }

        // A quantifier binds to the character before it, so that character is optional.
        if (length > 0 && length < pattern.size() &&
            kQuantifiers.find(pattern[length]) != std::string_view::npos) {
            --length;
        }

        return std::string(pattern.substr(0, length));
    }

    [[nodiscard]] RuleMatch toMatch(std::size_t offset, std::size_t length) const {
        return RuleMatch {
            .rule_id = metadata_.id,
            .description = metadata_.description,
            .offset = offset,
            .length = length,
            .severity = metadata_.severity,
        };
    }

    [[nodiscard]] std::vector<RuleMatch> applyFullScan(std::string_view data) const {
        std::vector<RuleMatch> matches;

        const auto begin = std::cregex_iterator(data.data(), data.data() + data.size(), pattern_);
        const auto end = std::cregex_iterator {};

        for (auto it = begin; it != end; ++it) {
            const auto& match = *it;
            matches.push_back(toMatch(static_cast<std::size_t>(match.position()),
                                      static_cast<std::size_t>(match.length())));
        }

        return matches;
    }

    // Every match starts with literal_prefix_, so only positions where the prefix occurs need
    // the regex engine. match_continuous anchors the attempt at the candidate and
    // match_prev_avail keeps ^ and \b aware of the preceding character.
    [[nodiscard]] std::vector<RuleMatch> applyWithPrefilter(std::string_view data) const {
        std::vector<RuleMatch> matches;
        const auto* const begin = data.data();
        const auto* const end = begin + data.size();

        std::size_t search_from = 0;
        while (search_from < data.size()) {
            const auto candidate = data.find(literal_prefix_, search_from);
            if (candidate == std::string_view::npos) {
                break;
            }

            auto flags = std::regex_constants::match_continuous;
            if (candidate > 0) {
                flags |= std::regex_constants::match_prev_avail;
            }

            std::cmatch match;
            if (std::regex_search(begin + candidate, end, match, pattern_, flags)) {
                const auto length = static_cast<std::size_t>(match.length());
                matches.push_back(toMatch(candidate, length));
                search_from = candidate + std::max<std::size_t>(length, 1);
            } else {
                search_from = candidate + 1;
            }
        }

        return matches;
    }

    RuleMetadata metadata_;
    std::string pattern_str_;
    std::size_t max_match_length_;
    std::regex pattern_;
    std::string literal_prefix_;
};

}  // namespace sentinel::engine

#endif
