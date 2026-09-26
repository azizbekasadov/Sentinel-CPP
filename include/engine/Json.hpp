#ifndef SENTINEL_ENGINE_JSON_HPP
#define SENTINEL_ENGINE_JSON_HPP

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

// A deliberately small JSON implementation: enough to load rule packs and emit reports without
// a third-party dependency. Objects preserve insertion order so serialized output is
// deterministic and diff-friendly.
namespace sentinel::engine::json {

class Value;

using Array = std::vector<Value>;
using Object = std::vector<std::pair<std::string, Value>>;

class ParseError final : public std::runtime_error {
public:
    ParseError(const std::string& message, std::size_t line, std::size_t column)
        : std::runtime_error(message + " at line " + std::to_string(line) + ", column " +
                             std::to_string(column)),
          line_(line),
          column_(column) {}

    [[nodiscard]] std::size_t line() const noexcept {
        return line_;
    }

    [[nodiscard]] std::size_t column() const noexcept {
        return column_;
    }

private:
    std::size_t line_;
    std::size_t column_;
};

class Value {
public:
    using Storage =
        std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object>;

    // Implicit conversions are intentional: they let callers write literal JSON structures such
    // as Value::object({{"count", 3}, {"name", "x"}}) without wrapping every leaf.
    Value() = default;

    Value(std::nullptr_t)
        : storage_(nullptr) {}  // NOLINT(google-explicit-constructor)

    Value(bool value)
        : storage_(value) {}  // NOLINT(google-explicit-constructor)

    template <std::integral T>
        requires(!std::same_as<T, bool>)
    Value(T value)
        : storage_(static_cast<std::int64_t>(value)) {}  // NOLINT

    Value(double value)
        : storage_(value) {}  // NOLINT

    Value(const char* value)
        : storage_(std::string(value)) {}  // NOLINT

    Value(std::string value)
        : storage_(std::move(value)) {}  // NOLINT

    Value(std::string_view value)
        : storage_(std::string(value)) {}  // NOLINT

    Value(Array value)
        : storage_(std::move(value)) {}  // NOLINT

    Value(Object value)
        : storage_(std::move(value)) {}  // NOLINT

    [[nodiscard]] static Value object(std::initializer_list<std::pair<std::string, Value>> items) {
        return Value(Object(items.begin(), items.end()));
    }

    [[nodiscard]] static Value array(std::initializer_list<Value> items) {
        return Value(Array(items.begin(), items.end()));
    }

    [[nodiscard]] bool isNull() const noexcept {
        return std::holds_alternative<std::nullptr_t>(storage_);
    }

    [[nodiscard]] bool isBool() const noexcept {
        return std::holds_alternative<bool>(storage_);
    }

    [[nodiscard]] bool isInteger() const noexcept {
        return std::holds_alternative<std::int64_t>(storage_);
    }

    [[nodiscard]] bool isNumber() const noexcept {
        return isInteger() || std::holds_alternative<double>(storage_);
    }

    [[nodiscard]] bool isString() const noexcept {
        return std::holds_alternative<std::string>(storage_);
    }

    [[nodiscard]] bool isArray() const noexcept {
        return std::holds_alternative<Array>(storage_);
    }

    [[nodiscard]] bool isObject() const noexcept {
        return std::holds_alternative<Object>(storage_);
    }

    // Accessors throw std::bad_variant_access when the stored type does not match.
    [[nodiscard]] bool asBool() const {
        return std::get<bool>(storage_);
    }

    [[nodiscard]] std::int64_t asInteger() const {
        return std::get<std::int64_t>(storage_);
    }

    [[nodiscard]] double asNumber() const {
        if (const auto* integer = std::get_if<std::int64_t>(&storage_)) {
            return static_cast<double>(*integer);
        }
        return std::get<double>(storage_);
    }

    [[nodiscard]] const std::string& asString() const {
        return std::get<std::string>(storage_);
    }

    [[nodiscard]] const Array& asArray() const {
        return std::get<Array>(storage_);
    }

    [[nodiscard]] const Object& asObject() const {
        return std::get<Object>(storage_);
    }

    // Object member lookup; nullptr when this is not an object or the key is absent.
    [[nodiscard]] const Value* find(std::string_view key) const noexcept;

    // Adds or replaces an object member. A non-object value becomes an empty object first.
    Value& set(std::string key, Value value);

    // Appends an array element. A non-array value becomes an empty array first.
    Value& push(Value value);

    [[nodiscard]] const Storage& storage() const noexcept {
        return storage_;
    }

    bool operator==(const Value&) const = default;

private:
    Storage storage_;
};

// Parses a complete JSON document. Throws ParseError on malformed input.
[[nodiscard]] Value parse(std::string_view text);

// Serializes with two-space indentation when `indent` is true, otherwise on a single line.
[[nodiscard]] std::string dump(const Value& value, bool indent = true);

// Escapes text for JSON output, including the surrounding quotes.
[[nodiscard]] std::string quote(std::string_view text);

}  // namespace sentinel::engine::json

#endif
