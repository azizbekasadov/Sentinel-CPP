#ifndef SENTINEL_ENGINE_IRULE_HPP
#define SENTINEL_ENGINE_IRULE_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sentinel::engine {

enum class Severity : std::uint8_t {
    Info,
    Low,
    Medium,
    High,
    Critical,
};

[[nodiscard]] constexpr std::string_view severityToString(Severity severity) noexcept {
    switch (severity) {
        case Severity::Info:
            return "info";
        case Severity::Low:
            return "low";
        case Severity::Medium:
            return "medium";
        case Severity::High:
            return "high";
        case Severity::Critical:
            return "critical";
    }
    return "medium";
}

[[nodiscard]] constexpr std::optional<Severity> parseSeverity(std::string_view text) noexcept {
    if (text == "info") {
        return Severity::Info;
    }
    if (text == "low") {
        return Severity::Low;
    }
    if (text == "medium") {
        return Severity::Medium;
    }
    if (text == "high") {
        return Severity::High;
    }
    if (text == "critical") {
        return Severity::Critical;
    }
    return std::nullopt;
}

// Descriptive data shared by every rule type, kept apart from matching configuration so new
// fields do not ripple through every constructor.
struct RuleMetadata {
    std::string id;
    std::string description;
    Severity severity {Severity::Medium};
    std::string remediation;
};

struct RuleMatch {
    std::string rule_id;
    std::string description;
    std::size_t offset {0};
    std::size_t length {0};
    Severity severity {Severity::Medium};

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
    [[nodiscard]] virtual Severity severity() const noexcept = 0;
    [[nodiscard]] virtual std::string_view remediation() const = 0;

    // Upper bound on the byte length of a single match. The scanner keeps this many bytes of
    // overlap between consecutive chunks so that a match may straddle a chunk boundary without
    // being missed or reported twice. Matches longer than this bound may be truncated.
    [[nodiscard]] virtual std::size_t maxMatchLength() const noexcept = 0;
};

using RulePtr = std::shared_ptr<IRule>;

}  // namespace sentinel::engine

#endif
