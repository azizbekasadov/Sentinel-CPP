//
//  StringMatchRule.hpp
//  Sentinel-CPP
//
//  Created by Azizbek Asadov on 08.04.2026.
//
//

#ifndef STRINGMATCHRULE_HPP
#define STRINGMATCHRULE_HPP

#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>

// `stdexcept` - defines a standardized set of exception classes derived
// from std::exception to report errors. It provides exceptions for reporting
// logical errors (std::logic_error) and runtime errors (std::runtime_error).

using namespace std;

namespace sentinel::engine {

/// `StringMatchRule` - search for a fixed substring (exact match).
class StringMatchRule final : public IRule {
private:
    const string rule_id_;
    const string pattern_;
    const string description_;

public:
    explicit StringMatchRule(string rule_id, string pattern, string description)
                            : rule_id_(std::move(rule_id))
                            , pattern_(std::move(pattern))
                            , description_(std::move(description))
    {
        if (pattern_.empty()) {
            throw invalid_argument("StringMatchRule '" + rule_id_ + "': pattern must not be empty");
        }
    }
    
    [[nodiscard]] vector<RuleMatch> apply(string_view data) const override {
        vector<RuleMatch> matches;
        
        size_t pos = data.find(pattern_);
        
        while (pos != string_view::npos) {
            matches.emplace_back(
                RuleMatch {
                    .rule_id = rule_id_,
                    .description = description_,
                    .offset = pos
                }
            );
            
            pos = data.find(pattern_, pos + 1);
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
        return pattern_;
    }
};

} // namespace sentinel::engine

#endif
