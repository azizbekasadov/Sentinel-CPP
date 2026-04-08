//
//  RegexRule.hpp
//  Sentinel-CPP
//
//  Created by Azizbek Asadov on 08.04.2026.
//
//

#ifndef REGEXRULE_HPP
#define REGEXRULE_HPP

#include "IRule.hpp"

#include <regex>
#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>

using namespace std;

namespace sentinel::engine {

class RegexRule final : public IRule {
private:
    const string rule_id_;
    const string pattern_str_;
    const string description_;
    
    regex pattern_;
    
public:
    explicit RegexRule(string rule_id,
                       const string& pattern,
                       string description,
                       regex_constants::syntax_option_type flags = regex_constants::ECMAScript)
        : rule_id_(std::move(rule_id))
        , pattern_str_(pattern)
        , description_(std::move(description))
        , pattern_(pattern, flags)
    {
        if (pattern.empty()) {
            throw invalid_argument("RegexRule '" + rule_id_ + "': pattern must not be empty");
        }
    }
    
    [[nodiscard]] vector<RuleMatch> apply(string_view data) const override {
        vector<RuleMatch> matches;
        
        auto it  = cregex_iterator(data.begin(), data.end(), pattern_);
        auto end = cregex_iterator{};
        
        for (; it != end; ++it) {
            const cmatch& match = *it;
            
            const size_t offset =
            static_cast<size_t>(match[0].first - data.begin());
            
            matches.emplace_back(RuleMatch{
                .rule_id = rule_id_,
                .description = description_,
                .offset = offset
            });
        }
        
        return matches;
    }
    
    [[nodiscard]] string_view id() const override {
        return rule_id_;
    }
    
    [[nodiscard]] string_view description() const override {
        return description_;
    }
    
    [[nodiscard]] string_view pattern() const {
        return pattern_str_;
    }
};

} // namespace sentinel::engine


#endif
