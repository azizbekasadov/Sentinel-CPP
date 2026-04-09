#ifndef SENTINEL_ENGINE_IRULE_HPP
#define SENTINEL_ENGINE_IRULE_HPP

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace sentinel::engine {

struct RuleMatch {
    std::string rule_id;
    std::string description;
    std::size_t offset {0};

    bool operator==(const RuleMatch&) const = default;
};

class IRule {
public:
    IRule() = default;
    virtual ~IRule() = default;

    IRule(const IRule&) = delete;
    IRule& operator=(const IRule&) = delete;
    IRule(IRule&&) = delete;
    IRule& operator=(IRule&&) = delete;

    [[nodiscard]] virtual std::vector<RuleMatch> apply(std::string_view data) const = 0;
    [[nodiscard]] virtual std::string_view id() const = 0;
    [[nodiscard]] virtual std::string_view description() const = 0;
};

using RulePtr = std::shared_ptr<IRule>;

}  // namespace sentinel::engine

#endif
