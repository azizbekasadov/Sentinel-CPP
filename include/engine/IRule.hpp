//
//  IRule.hpp
//  Sentinel-CPP
//
//  Created by Azizbek Asadov on 08.04.2026.
//
//

#ifndef IRULE_HPP
#define IRULE_HPP

#include <string>
#include <vector>
#include <memory>
#include <string_view>

using namespace std;

namespace sentinel::engine {

struct RuleMatch {
    string rule_id;
    string description;
    size_t offset;
    
    bool operator==(const RuleMatch &) const = default;
};

class IRule {
public:
    virtual ~IRule() = default;
    
    IRule(const IRule&)              = delete;
    IRule& operator=(const IRule&)   = delete;
    IRule(IRule&&)                   = delete;
    IRule& operator=(IRule&&)       = delete;
    
    [[nodiscard]] virtual vector<RuleMatch> apply(string_view data) const = 0;
    [[nodiscard]] virtual string_view id() const = 0;
    [[nodiscard]] virtual string_view description() const = 0;
    
protected:
    IRule() = default;
};

// typealias like in Swift
using RulePtr = shared_ptr<IRule>;

} // namespace sentinel::engine

#endif
