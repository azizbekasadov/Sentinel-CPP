#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "engine/RegexRule.hpp"
#include "engine/Scanner.hpp"

namespace {

std::filesystem::path uniqueTempDir(const std::string& label) {
    const auto timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto root = std::filesystem::temp_directory_path() /
        ("sentinel_cpp_" + label + "_" + std::to_string(timestamp));
    std::filesystem::create_directories(root);
    return root;
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::ofstream stream(path, std::ios::binary);
    stream << content;
}

void writePaddedFile(
    const std::filesystem::path& path,
    std::size_t prefix_size,
    char fill,
    const std::string& suffix) {
    std::ofstream stream(path, std::ios::binary);
    stream << std::string(prefix_size, fill) << suffix;
}

}  // namespace

using sentinel::engine::RegexRule;
using sentinel::engine::ScanOptions;
using sentinel::engine::Scanner;

TEST_CASE("scanFile returns matched signatures with absolute offsets", "[scanner][file]") {
    const auto root = uniqueTempDir("file_signature");
    const auto file = root / "sample.txt";
    writeFile(file, "prefix password=super-secret suffix");

    const Scanner scanner;
    const auto result = scanner.scanFile(file, {"password="});

    REQUIRE(result.error == std::nullopt);
    REQUIRE(result.hasDetections());
    REQUIRE(result.findings.size() == 1);
    REQUIRE(result.findings.front().rule_id == "password=");
    REQUIRE(result.findings.front().offset == 7);

    std::filesystem::remove_all(root);
}

TEST_CASE("scanFile detects signatures that cross the chunk boundary", "[scanner][buffer]") {
    const auto root = uniqueTempDir("chunk_boundary");
    const auto file = root / "boundary.bin";
    const std::string signature = "EVIL_CODE";

    writePaddedFile(file, sentinel::engine::kBufferSize - 4, 'A', signature);

    const Scanner scanner;
    const auto result = scanner.scanFile(file, {signature});

    REQUIRE(result.hasDetections());
    REQUIRE(result.findings.front().offset == sentinel::engine::kBufferSize - 4);

    std::filesystem::remove_all(root);
}

TEST_CASE("scanPath aggregates file-level detections and metadata", "[scanner][path]") {
    const auto root = uniqueTempDir("path_summary");
    writeFile(root / "clean.cpp", "int main() { return 0; }");
    writeFile(root / "secrets.env", "API_KEY=demo\n");

    const Scanner scanner;
    const auto summary = scanner.scanPath(
        root,
        Scanner::buildStringRules({"API_KEY="}),
        ScanOptions {.thread_count = 2, .include_clean_files = true});

    REQUIRE(summary.files_scanned == 2);
    REQUIRE(summary.files_with_detections == 1);
    REQUIRE(summary.bytes_scanned > 0);
    REQUIRE(summary.file_results.size() == 2);

    std::filesystem::remove_all(root);
}

TEST_CASE("scanPath supports regex-based rules", "[scanner][regex]") {
    const auto root = uniqueTempDir("path_regex");
    writeFile(root / "config.txt", "aws=AKIA1234567890ABCDEF\n");

    const Scanner scanner;
    const auto summary = scanner.scanPath(
        root,
        {std::make_shared<RegexRule>("aws-key", R"(AKIA[0-9A-Z]{16})", "AWS key")},
        ScanOptions {.thread_count = 1});

    REQUIRE(summary.hasDetections());
    REQUIRE(summary.file_results.size() == 1);
    REQUIRE(summary.file_results.front().findings.front().rule_id == "aws-key");

    std::filesystem::remove_all(root);
}

TEST_CASE("wildcardMatch supports simple glob semantics", "[scanner][glob]") {
    REQUIRE(sentinel::engine::wildcardMatch("*.cpp", "src/main.cpp"));
    REQUIRE(sentinel::engine::wildcardMatch("src/*.cpp", "src/main.cpp"));
    REQUIRE(sentinel::engine::wildcardMatch("tests/??.txt", "tests/ab.txt"));
    REQUIRE_FALSE(sentinel::engine::wildcardMatch("include/*.hpp", "src/main.cpp"));
}

TEST_CASE("scanPath filters files using include and exclude globs", "[scanner][filter]") {
    const auto root = uniqueTempDir("filters");
    writeFile(root / "main.cpp", "password=demo");
    writeFile(root / "notes.txt", "password=ignored");
    std::filesystem::create_directories(root / "build");
    writeFile(root / "build" / "generated.cpp", "password=ignored");

    const Scanner scanner;
    const auto summary = scanner.scanPath(
        root,
        Scanner::buildStringRules({"password="}),
        ScanOptions {
            .thread_count = 2,
            .include_clean_files = true,
            .include_globs = {"*.cpp"},
            .exclude_globs = {"build/*"},
        });

    REQUIRE(summary.files_scanned == 1);
    REQUIRE(summary.files_with_detections == 1);
    REQUIRE(summary.file_results.size() == 1);
    REQUIRE(summary.file_results.front().path.filename() == "main.cpp");

    std::filesystem::remove_all(root);
}

TEST_CASE("scanPath skips binary files by default", "[scanner][binary]") {
    const auto root = uniqueTempDir("binary_skip");
    const auto binary_file = root / "payload.bin";

    {
        std::ofstream stream(binary_file, std::ios::binary);
        stream.write("ABCD", 4);
        stream.put('\0');
        stream.write("password=", 9);
    }

    const Scanner scanner;
    const auto summary = scanner.scanPath(
        root,
        Scanner::buildStringRules({"password="}),
        ScanOptions {.include_clean_files = true});

    REQUIRE(summary.files_scanned == 1);
    REQUIRE(summary.files_skipped == 1);
    REQUIRE(summary.file_results.size() == 1);
    REQUIRE(summary.file_results.front().skipped_reason == "binary file skipped");
    REQUIRE_FALSE(summary.hasDetections());

    std::filesystem::remove_all(root);
}

TEST_CASE("scanPath can opt into scanning binary files", "[scanner][binary]") {
    const auto root = uniqueTempDir("binary_scan");
    const auto binary_file = root / "payload.bin";

    {
        std::ofstream stream(binary_file, std::ios::binary);
        stream.write("ABCD", 4);
        stream.put('\0');
        stream.write("password=", 9);
    }

    const Scanner scanner;
    const auto summary = scanner.scanPath(
        root,
        Scanner::buildStringRules({"password="}),
        ScanOptions {.scan_binary_files = true});

    REQUIRE(summary.files_scanned == 1);
    REQUIRE(summary.files_skipped == 0);
    REQUIRE(summary.files_with_detections == 1);
    REQUIRE(summary.file_results.size() == 1);
    REQUIRE(summary.file_results.front().findings.front().rule_id == "password=");

    std::filesystem::remove_all(root);
}

TEST_CASE("scanDirectory remains compatible with the simple boolean API", "[scanner][compat]") {
    const auto root = uniqueTempDir("compat");
    writeFile(root / "payload.bin", "header EVIL_CODE trailer");

    const Scanner scanner;

    REQUIRE(scanner.scanDirectory(root, {"EVIL_CODE"}, 4));
    REQUIRE_FALSE(scanner.scanDirectory(root, {"MISSING_SIGNATURE"}, 4));

    std::filesystem::remove_all(root);
}
