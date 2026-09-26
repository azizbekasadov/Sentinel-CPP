#ifndef SENTINEL_ENGINE_RULE_PACK_HPP
#define SENTINEL_ENGINE_RULE_PACK_HPP

#include "engine/IRule.hpp"
#include "engine/RegexRule.hpp"

#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace sentinel::engine {

// A named collection of rules loaded from a JSON document of the form:
//
//   {
//     "name": "secrets",
//     "version": "1.0.0",
//     "rules": [
//       {
//         "id": "aws-access-key",           // required, unique within the pack
//         "type": "regex",                  // required: "string" or "regex"
//         "pattern": "AKIA[0-9A-Z]{16}",    // required
//         "description": "AWS access key",  // optional
//         "severity": "high",               // optional: info|low|medium|high|critical
//         "remediation": "Rotate the key.", // optional
//         "maxMatchLength": 64,             // optional, regex only, positive integer
//         "flags": ["icase"]                // optional, regex only
//       }
//     ]
//   }
struct RulePack {
    std::string name;
    std::string version;
    std::vector<RulePtr> rules;
};

class RulePackError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Parses a rule pack from JSON text. `source_name` is used in error messages only.
[[nodiscard]] RulePack parseRulePack(std::string_view json_text,
                                     std::string_view source_name = "<memory>");

// Reads and parses a rule pack from disk.
[[nodiscard]] RulePack loadRulePack(const std::filesystem::path& path);

}  // namespace sentinel::engine

#endif
