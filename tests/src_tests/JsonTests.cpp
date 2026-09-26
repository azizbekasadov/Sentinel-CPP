#include "engine/Json.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>

namespace json = sentinel::engine::json;

TEST_CASE("json::parse reads scalar values", "[json][parse]") {
    REQUIRE(json::parse("null").isNull());
    REQUIRE(json::parse("true").asBool() == true);
    REQUIRE(json::parse("false").asBool() == false);
    REQUIRE(json::parse("42").asInteger() == 42);
    REQUIRE(json::parse("-7").asInteger() == -7);
    REQUIRE(json::parse("3.5").asNumber() == 3.5);
    REQUIRE(json::parse("1e3").asNumber() == 1000.0);
    REQUIRE(json::parse(R"("text")").asString() == "text");
}

TEST_CASE("json::parse distinguishes integers from floating point numbers", "[json][parse]") {
    REQUIRE(json::parse("10").isInteger());
    REQUIRE_FALSE(json::parse("10.0").isInteger());
    REQUIRE(json::parse("10.0").isNumber());
    REQUIRE(json::parse("9223372036854775807").asInteger() == INT64_MAX);
    // Beyond the 64-bit range the value degrades to floating point instead of failing.
    REQUIRE(json::parse("18446744073709551616").isNumber());
}

TEST_CASE("json::parse decodes string escapes", "[json][parse]") {
    REQUIRE(json::parse(R"("a\"b\\c\/d")").asString() == "a\"b\\c/d");
    REQUIRE(json::parse(R"("\b\f\n\r\t")").asString() == "\b\f\n\r\t");
    REQUIRE(json::parse(R"("\u0041\u00e9")").asString() == "A\xc3\xa9");
    REQUIRE(json::parse(R"("\ud83d\ude00")").asString() == "\xf0\x9f\x98\x80");
}

TEST_CASE("json::parse builds arrays and order-preserving objects", "[json][parse]") {
    const auto value = json::parse(R"({
        "zebra": [1, 2, {"nested": true}],
        "apple": "fruit",
        "empty": {},
        "list": []
    })");

    REQUIRE(value.isObject());
    REQUIRE(value.asObject().size() == 4);
    REQUIRE(value.asObject()[0].first == "zebra");
    REQUIRE(value.asObject()[1].first == "apple");

    const auto* zebra = value.find("zebra");
    REQUIRE(zebra != nullptr);
    REQUIRE(zebra->isArray());
    REQUIRE(zebra->asArray().size() == 3);
    REQUIRE(zebra->asArray()[2].find("nested")->asBool());

    REQUIRE(value.find("apple")->asString() == "fruit");
    REQUIRE(value.find("empty")->asObject().empty());
    REQUIRE(value.find("list")->asArray().empty());
    REQUIRE(value.find("missing") == nullptr);
}

TEST_CASE("json::parse keeps the last value for a duplicated key", "[json][parse]") {
    const auto value = json::parse(R"({"a": 1, "a": 2})");

    REQUIRE(value.asObject().size() == 1);
    REQUIRE(value.find("a")->asInteger() == 2);
}

TEST_CASE("json::parse ignores surrounding whitespace", "[json][parse]") {
    REQUIRE(json::parse(" \n\t[ 1 , 2 ]\r\n").asArray().size() == 2);
}

TEST_CASE("json::parse rejects malformed documents with a position", "[json][parse]") {
    REQUIRE_THROWS_AS(json::parse(""), json::ParseError);
    REQUIRE_THROWS_AS(json::parse("{"), json::ParseError);
    REQUIRE_THROWS_AS(json::parse("[1,]"), json::ParseError);
    REQUIRE_THROWS_AS(json::parse("{\"a\" 1}"), json::ParseError);
    REQUIRE_THROWS_AS(json::parse("tru"), json::ParseError);
    REQUIRE_THROWS_AS(json::parse("01"), json::ParseError);
    REQUIRE_THROWS_AS(json::parse("1 2"), json::ParseError);
    REQUIRE_THROWS_AS(json::parse("\"unterminated"), json::ParseError);
    REQUIRE_THROWS_AS(json::parse("\"bad \\x escape\""), json::ParseError);
    REQUIRE_THROWS_AS(json::parse("\"\\ud83d\""), json::ParseError);
    REQUIRE_THROWS_AS(json::parse("\"tab\there\""), json::ParseError);

    try {
        [[maybe_unused]] const auto value = json::parse("{\n  \"a\": 1,\n  \"b\": oops\n}");
        FAIL("expected a parse error");
    } catch (const json::ParseError& error) {
        REQUIRE(error.line() == 3);
        REQUIRE(error.column() == 8);
        REQUIRE(std::string(error.what()).find("line 3") != std::string::npos);
    }
}

TEST_CASE("json::parse limits nesting depth", "[json][parse]") {
    const std::string deep(1000, '[');
    REQUIRE_THROWS_AS(json::parse(deep), json::ParseError);
}

TEST_CASE("json::quote escapes control characters and quotes", "[json][dump]") {
    REQUIRE(json::quote("plain") == "\"plain\"");
    REQUIRE(json::quote("a\"b\\c") == R"("a\"b\\c")");
    REQUIRE(json::quote("\n\t\r\b\f") == R"("\n\t\r\b\f")");
    REQUIRE(json::quote(std::string("x\x01y\x7f")) == R"("x\u0001y\u007f")");
    REQUIRE(json::quote("caf\xc3\xa9") == "\"caf\xc3\xa9\"");
}

TEST_CASE("json::dump produces compact output", "[json][dump]") {
    const auto value = json::Value::object({
        {"name", "sentinel"},
        {"count", 3},
        {"ratio", 0.5},
        {"flag", false},
        {"nothing", nullptr},
        {"items", json::Value::array({1, "two"})},
        {"empty", json::Value::object({})},
    });

    REQUIRE(json::dump(value, false) ==
            R"({"name":"sentinel","count":3,"ratio":0.5,"flag":false,"nothing":null,)"
            R"("items":[1,"two"],"empty":{}})");
}

TEST_CASE("json::dump produces two-space indented output", "[json][dump]") {
    const auto value = json::Value::object({
        {"a", json::Value::array({1, 2})},
        {"b", json::Value::object({{"c", "d"}})},
        {"e", json::Value::array({})},
    });

    const std::string expected =
        "{\n"
        "  \"a\": [\n"
        "    1,\n"
        "    2\n"
        "  ],\n"
        "  \"b\": {\n"
        "    \"c\": \"d\"\n"
        "  },\n"
        "  \"e\": []\n"
        "}";
    REQUIRE(json::dump(value) == expected);
}

TEST_CASE("json values round-trip through dump and parse", "[json][dump]") {
    const auto original = json::parse(
        R"({"rules":[{"id":"x","severity":"high","maxMatchLength":64,"ratio":1.25}],"ok":true})");

    REQUIRE(json::parse(json::dump(original)) == original);
    REQUIRE(json::parse(json::dump(original, false)) == original);
}

TEST_CASE("json::Value::set replaces existing keys and push appends", "[json][build]") {
    json::Value object;
    object.set("a", 1).set("b", 2).set("a", 3);

    REQUIRE(object.asObject().size() == 2);
    REQUIRE(object.find("a")->asInteger() == 3);

    json::Value list;
    list.push("x").push("y");
    REQUIRE(list.asArray().size() == 2);
    REQUIRE(list.asArray()[1].asString() == "y");
}

TEST_CASE("json::Value accepts unsigned and size_t integers", "[json][build]") {
    const std::size_t size = 65536;
    const std::uint64_t big = 1ULL << 40U;

    REQUIRE(json::Value(size).asInteger() == 65536);
    REQUIRE(json::dump(json::Value(big), false) == "1099511627776");
}
