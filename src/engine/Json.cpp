#include "engine/Json.hpp"

#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <locale>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

namespace sentinel::engine::json {
namespace {

constexpr std::size_t kMaxDepth = 256;

bool isDigit(char ch) noexcept {
    return ch >= '0' && ch <= '9';
}

class Parser {
public:
    explicit Parser(std::string_view text)
        : text_(text) {}

    Value parseDocument() {
        skipWhitespace();
        auto value = parseValue(0);
        skipWhitespace();
        if (pos_ != text_.size()) {
            fail("unexpected trailing content");
        }
        return value;
    }

private:
    [[noreturn]] void fail(const std::string& message) const {
        std::size_t line = 1;
        std::size_t column = 1;
        for (std::size_t i = 0; i < pos_ && i < text_.size(); ++i) {
            if (text_[i] == '\n') {
                ++line;
                column = 1;
            } else {
                ++column;
            }
        }
        throw ParseError(message, line, column);
    }

    [[nodiscard]] bool atEnd() const noexcept {
        return pos_ >= text_.size();
    }

    [[nodiscard]] char peek() const noexcept {
        return atEnd() ? '\0' : text_[pos_];
    }

    void skipWhitespace() noexcept {
        while (!atEnd()) {
            const char ch = text_[pos_];
            if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') {
                break;
            }
            ++pos_;
        }
    }

    void expect(char expected) {
        if (peek() != expected) {
            fail(std::string("expected '") + expected + "'");
        }
        ++pos_;
    }

    bool consumeLiteral(std::string_view literal) {
        if (text_.substr(pos_, literal.size()) == literal) {
            pos_ += literal.size();
            return true;
        }
        return false;
    }

    Value parseValue(std::size_t depth) {
        if (depth > kMaxDepth) {
            fail("nesting too deep");
        }

        if (atEnd()) {
            fail("unexpected end of input");
        }

        switch (peek()) {
            case '{':
                return parseObject(depth);
            case '[':
                return parseArray(depth);
            case '"':
                return {parseString()};
            case 't':
                if (consumeLiteral("true")) {
                    return {true};
                }
                break;
            case 'f':
                if (consumeLiteral("false")) {
                    return {false};
                }
                break;
            case 'n':
                if (consumeLiteral("null")) {
                    return {nullptr};
                }
                break;
            default:
                if (peek() == '-' || isDigit(peek())) {
                    return parseNumber();
                }
                break;
        }

        fail("unexpected character");
    }

    Value parseObject(std::size_t depth) {
        expect('{');
        Value result {Object {}};

        skipWhitespace();
        if (peek() == '}') {
            ++pos_;
            return result;
        }

        while (true) {
            skipWhitespace();
            if (peek() != '"') {
                fail("expected string key");
            }
            auto key = parseString();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            result.set(std::move(key), parseValue(depth + 1));

            skipWhitespace();
            if (peek() == ',') {
                ++pos_;
                continue;
            }
            if (peek() == '}') {
                ++pos_;
                return result;
            }
            fail("expected ',' or '}'");
        }
    }

    Value parseArray(std::size_t depth) {
        expect('[');
        Value result {Array {}};

        skipWhitespace();
        if (peek() == ']') {
            ++pos_;
            return result;
        }

        while (true) {
            skipWhitespace();
            result.push(parseValue(depth + 1));
            skipWhitespace();
            if (peek() == ',') {
                ++pos_;
                continue;
            }
            if (peek() == ']') {
                ++pos_;
                return result;
            }
            fail("expected ',' or ']'");
        }
    }

    std::uint32_t parseHex4() {
        if (pos_ + 4 > text_.size()) {
            fail("truncated \\u escape");
        }

        std::uint32_t code = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            const char ch = text_[pos_ + i];
            code <<= 4U;
            if (isDigit(ch)) {
                code |= static_cast<std::uint32_t>(ch - '0');
            } else if (ch >= 'a' && ch <= 'f') {
                code |= static_cast<std::uint32_t>(ch - 'a' + 10);
            } else if (ch >= 'A' && ch <= 'F') {
                code |= static_cast<std::uint32_t>(ch - 'A' + 10);
            } else {
                fail("invalid hex digit in \\u escape");
            }
        }
        pos_ += 4;
        return code;
    }

    static void appendUtf8(std::string& out, std::uint32_t code_point) {
        const auto byte = [](std::uint32_t bits) { return static_cast<char>(bits & 0xFFU); };

        if (code_point < 0x80) {
            out += byte(code_point);
        } else if (code_point < 0x800) {
            out += byte(0xC0U | (code_point >> 6U));
            out += byte(0x80U | (code_point & 0x3FU));
        } else if (code_point < 0x10000) {
            out += byte(0xE0U | (code_point >> 12U));
            out += byte(0x80U | ((code_point >> 6U) & 0x3FU));
            out += byte(0x80U | (code_point & 0x3FU));
        } else {
            out += byte(0xF0U | (code_point >> 18U));
            out += byte(0x80U | ((code_point >> 12U) & 0x3FU));
            out += byte(0x80U | ((code_point >> 6U) & 0x3FU));
            out += byte(0x80U | (code_point & 0x3FU));
        }
    }

    std::uint32_t parseUnicodeEscape() {
        const auto code = parseHex4();
        if (code >= 0xDC00 && code <= 0xDFFF) {
            fail("unpaired surrogate");
        }
        if (code < 0xD800 || code > 0xDBFF) {
            return code;
        }

        if (!consumeLiteral("\\u")) {
            fail("unpaired surrogate");
        }
        const auto low = parseHex4();
        if (low < 0xDC00 || low > 0xDFFF) {
            fail("invalid low surrogate");
        }
        return 0x10000 + ((code - 0xD800) << 10U) + (low - 0xDC00);
    }

    std::string parseString() {
        expect('"');
        std::string out;

        while (true) {
            if (atEnd()) {
                fail("unterminated string");
            }

            const char ch = text_[pos_];
            if (ch == '"') {
                ++pos_;
                return out;
            }

            if (static_cast<unsigned char>(ch) < 0x20) {
                fail("control character in string");
            }

            ++pos_;
            if (ch != '\\') {
                out += ch;
                continue;
            }

            if (atEnd()) {
                fail("unterminated escape sequence");
            }

            const char escape = text_[pos_];
            ++pos_;
            switch (escape) {
                case '"':
                    out += '"';
                    break;
                case '\\':
                    out += '\\';
                    break;
                case '/':
                    out += '/';
                    break;
                case 'b':
                    out += '\b';
                    break;
                case 'f':
                    out += '\f';
                    break;
                case 'n':
                    out += '\n';
                    break;
                case 'r':
                    out += '\r';
                    break;
                case 't':
                    out += '\t';
                    break;
                case 'u':
                    appendUtf8(out, parseUnicodeEscape());
                    break;
                default:
                    --pos_;
                    fail("invalid escape sequence");
            }
        }
    }

    Value parseNumber() {
        const auto start = pos_;
        bool is_integer = true;

        if (peek() == '-') {
            ++pos_;
        }

        if (peek() == '0') {
            ++pos_;
        } else if (isDigit(peek())) {
            while (isDigit(peek())) {
                ++pos_;
            }
        } else {
            fail("invalid number");
        }

        if (peek() == '.') {
            is_integer = false;
            ++pos_;
            if (!isDigit(peek())) {
                fail("invalid fraction");
            }
            while (isDigit(peek())) {
                ++pos_;
            }
        }

        if (peek() == 'e' || peek() == 'E') {
            is_integer = false;
            ++pos_;
            if (peek() == '+' || peek() == '-') {
                ++pos_;
            }
            if (!isDigit(peek())) {
                fail("invalid exponent");
            }
            while (isDigit(peek())) {
                ++pos_;
            }
        }

        const auto token = text_.substr(start, pos_ - start);
        const auto* const first = token.data();
        const auto* const last = first + token.size();

        if (is_integer) {
            std::int64_t integer = 0;
            const auto [end, ec] = std::from_chars(first, last, integer);
            if (ec == std::errc {} && end == last) {
                return {integer};
            }
            // Integers outside the 64-bit range degrade to floating point below.
        }

        double number = 0.0;
        std::istringstream stream {std::string(token)};
        stream.imbue(std::locale::classic());
        stream >> std::noskipws >> number;
        if (!stream || stream.peek() != std::char_traits<char>::eof()) {
            fail("invalid number");
        }
        return {number};
    }

    std::string_view text_;
    std::size_t pos_ {0};
};

void newline(std::string& out, bool indent, std::size_t level) {
    if (indent) {
        out += '\n';
        out.append(level * 2, ' ');
    }
}

void writeDouble(std::string& out, double number) {
    if (std::isnan(number) || std::isinf(number)) {
        out += "null";
        return;
    }

    std::array<char, 64> buffer {};
    const auto [end, ec] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), number);
    if (ec != std::errc {}) {
        out += "null";
        return;
    }
    out.append(buffer.data(), end);
}

void dumpValue(const Value& value, std::string& out, bool indent, std::size_t level);

void dumpArray(const Array& items, std::string& out, bool indent, std::size_t level) {
    if (items.empty()) {
        out += "[]";
        return;
    }

    out += '[';
    for (std::size_t i = 0; i < items.size(); ++i) {
        newline(out, indent, level + 1);
        dumpValue(items[i], out, indent, level + 1);
        if (i + 1 < items.size()) {
            out += ',';
        }
    }
    newline(out, indent, level);
    out += ']';
}

void dumpObject(const Object& members, std::string& out, bool indent, std::size_t level) {
    if (members.empty()) {
        out += "{}";
        return;
    }

    out += '{';
    for (std::size_t i = 0; i < members.size(); ++i) {
        newline(out, indent, level + 1);
        out += quote(members[i].first);
        out += indent ? ": " : ":";
        dumpValue(members[i].second, out, indent, level + 1);
        if (i + 1 < members.size()) {
            out += ',';
        }
    }
    newline(out, indent, level);
    out += '}';
}

void dumpValue(const Value& value, std::string& out, bool indent, std::size_t level) {
    std::visit(
        [&](const auto& stored) {
            using T = std::decay_t<decltype(stored)>;
            if constexpr (std::is_same_v<T, std::nullptr_t>) {
                out += "null";
            } else if constexpr (std::is_same_v<T, bool>) {
                out += stored ? "true" : "false";
            } else if constexpr (std::is_same_v<T, std::int64_t>) {
                out += std::to_string(stored);
            } else if constexpr (std::is_same_v<T, double>) {
                writeDouble(out, stored);
            } else if constexpr (std::is_same_v<T, std::string>) {
                out += quote(stored);
            } else if constexpr (std::is_same_v<T, Array>) {
                dumpArray(stored, out, indent, level);
            } else {
                dumpObject(stored, out, indent, level);
            }
        },
        value.storage());
}

}  // namespace

const Value* Value::find(std::string_view key) const noexcept {
    const auto* members = std::get_if<Object>(&storage_);
    if (members == nullptr) {
        return nullptr;
    }

    for (const auto& [member_key, member_value] : *members) {
        if (member_key == key) {
            return &member_value;
        }
    }
    return nullptr;
}

Value& Value::set(std::string key, Value value) {
    if (!isObject()) {
        storage_ = Object {};
    }

    auto& members = std::get<Object>(storage_);
    for (auto& [member_key, member_value] : members) {
        if (member_key == key) {
            member_value = std::move(value);
            return *this;
        }
    }

    members.emplace_back(std::move(key), std::move(value));
    return *this;
}

Value& Value::push(Value value) {
    if (!isArray()) {
        storage_ = Array {};
    }

    std::get<Array>(storage_).push_back(std::move(value));
    return *this;
}

Value parse(std::string_view text) {
    return Parser(text).parseDocument();
}

std::string quote(std::string_view text) {
    static constexpr std::string_view kHexDigits = "0123456789abcdef";

    std::string out;
    out.reserve(text.size() + 2);
    out += '"';

    for (const char ch : text) {
        switch (ch) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default: {
                const auto byte = static_cast<unsigned char>(ch);
                if (byte < 0x20 || byte == 0x7F) {
                    out += "\\u00";
                    out += kHexDigits[byte >> 4U];
                    out += kHexDigits[byte & 0x0FU];
                } else {
                    out += ch;
                }
                break;
            }
        }
    }

    out += '"';
    return out;
}

std::string dump(const Value& value, bool indent) {
    std::string out;
    dumpValue(value, out, indent, 0);
    return out;
}

}  // namespace sentinel::engine::json
