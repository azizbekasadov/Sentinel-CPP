#include "engine/RulePack.hpp"

#include "engine/Json.hpp"
#include "engine/StringMatch.hpp"

#include <cstdint>
#include <fstream>
#include <iterator>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace sentinel::engine {
namespace {

class PackReader {
public:
    PackReader(std::string_view json_text, std::string_view source_name)
        : source_(source_name),
          text_(json_text) {}

    RulePack read() {
        json::Value document;
        try {
            document = json::parse(text_);
        } catch (const json::ParseError& error) {
            fail(std::string("invalid JSON: ") + error.what());
        }

        if (!document.isObject()) {
            fail("the document root must be an object");
        }

        RulePack pack;
        pack.name = optionalString(document, "name", "pack");
        pack.version = optionalString(document, "version", "pack");

        const auto* rules = document.find("rules");
        if (rules == nullptr) {
            fail("missing required \"rules\" array");
        }
        if (!rules->isArray()) {
            fail("\"rules\" must be an array");
        }
        if (rules->asArray().empty()) {
            fail("\"rules\" must contain at least one rule");
        }

        std::set<std::string> seen_ids;
        for (std::size_t index = 0; index < rules->asArray().size(); ++index) {
            const auto& entry = rules->asArray()[index];
            std::string context = "rules[";
            context += std::to_string(index);
            context += ']';

            if (!entry.isObject()) {
                fail(context + " must be an object");
            }

            auto rule = readRule(entry, context);
            const std::string id(rule->id());
            if (!seen_ids.insert(id).second) {
                std::string message = context;
                message += ": duplicate rule id '";
                message += id;
                message += '\'';
                fail(message);
            }
            pack.rules.push_back(std::move(rule));
        }

        return pack;
    }

private:
    [[noreturn]] void fail(const std::string& message) const {
        throw RulePackError("rule pack '" + std::string(source_) + "': " + message);
    }

    [[nodiscard]] std::string requiredString(const json::Value& object,
                                             std::string_view key,
                                             const std::string& context) const {
        const auto* value = object.find(key);
        if (value == nullptr) {
            fail(context + ": missing required \"" + std::string(key) + "\"");
        }
        if (!value->isString()) {
            fail(context + ": \"" + std::string(key) + "\" must be a string");
        }
        return value->asString();
    }

    [[nodiscard]] std::string optionalString(const json::Value& object,
                                             std::string_view key,
                                             const std::string& context) const {
        const auto* value = object.find(key);
        if (value == nullptr) {
            return {};
        }
        if (!value->isString()) {
            fail(context + ": \"" + std::string(key) + "\" must be a string");
        }
        return value->asString();
    }

    [[nodiscard]] RuleMetadata readMetadata(const json::Value& entry,
                                            const std::string& context) const {
        RuleMetadata metadata;
        metadata.id = requiredString(entry, "id", context);
        if (metadata.id.empty()) {
            fail(context + ": \"id\" must not be empty");
        }
        metadata.description = optionalString(entry, "description", context);
        metadata.remediation = optionalString(entry, "remediation", context);

        if (const auto* severity = entry.find("severity")) {
            if (!severity->isString()) {
                fail(context + ": \"severity\" must be a string");
            }
            const auto parsed = parseSeverity(severity->asString());
            if (!parsed) {
                fail(context + ": unknown severity '" + severity->asString() +
                     "' (expected one of info, low, medium, high, critical)");
            }
            metadata.severity = *parsed;
        }

        return metadata;
    }

    [[nodiscard]] std::size_t readMaxMatchLength(const json::Value& entry,
                                                 const std::string& context) const {
        const auto* value = entry.find("maxMatchLength");
        if (value == nullptr) {
            return kDefaultRegexMaxMatchLength;
        }
        if (!value->isInteger() || value->asInteger() <= 0) {
            fail(context + ": \"maxMatchLength\" must be a positive integer");
        }
        return static_cast<std::size_t>(value->asInteger());
    }

    [[nodiscard]] std::regex_constants::syntax_option_type readFlags(
        const json::Value& entry, const std::string& context) const {
        auto flags = std::regex_constants::ECMAScript;

        const auto* value = entry.find("flags");
        if (value == nullptr) {
            return flags;
        }
        if (!value->isArray()) {
            fail(context + ": \"flags\" must be an array of strings");
        }

        for (const auto& flag : value->asArray()) {
            if (!flag.isString()) {
                fail(context + ": \"flags\" must be an array of strings");
            }
            if (flag.asString() == "icase") {
                flags |= std::regex_constants::icase;
            } else {
                fail(context + ": unknown regex flag '" + flag.asString() +
                     "' (expected \"icase\")");
            }
        }

        return flags;
    }

    [[nodiscard]] RulePtr readRule(const json::Value& entry, const std::string& context) const {
        auto metadata = readMetadata(entry, context);
        const auto rule_context = context + " ('" + metadata.id + "')";
        const auto type = requiredString(entry, "type", rule_context);
        auto pattern = requiredString(entry, "pattern", rule_context);

        try {
            if (type == "string") {
                return std::make_shared<StringMatchRule>(std::move(metadata), std::move(pattern));
            }
            if (type == "regex") {
                const auto max_match_length = readMaxMatchLength(entry, rule_context);
                const auto flags = readFlags(entry, rule_context);
                return std::make_shared<RegexRule>(
                    std::move(metadata), std::move(pattern), flags, max_match_length);
            }
        } catch (const std::invalid_argument& error) {
            fail(rule_context + ": " + error.what());
        }

        fail(rule_context + ": unknown type '" + type + "' (expected \"string\" or \"regex\")");
    }

    std::string_view source_;
    std::string_view text_;
};

}  // namespace

RulePack parseRulePack(std::string_view json_text, std::string_view source_name) {
    return PackReader(json_text, source_name).read();
}

RulePack loadRulePack(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw RulePackError("rule pack '" + path.string() + "': unable to open file");
    }

    const std::string contents((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
    if (file.bad()) {
        throw RulePackError("rule pack '" + path.string() + "': read error");
    }

    return parseRulePack(contents, path.string());
}

}  // namespace sentinel::engine
