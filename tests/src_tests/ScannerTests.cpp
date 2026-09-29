#include "engine/RegexRule.hpp"
#include "engine/Scanner.hpp"
#include "engine/StringMatch.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace {

using sentinel::engine::kBufferSize;

// Owns a unique temporary directory and removes it even when an assertion fails mid-test.
class TempDir {
public:
    explicit TempDir(const std::string& label) {
        static std::atomic<unsigned> counter {0};
        const auto timestamp = std::chrono::steady_clock::now().time_since_epoch().count();
        root_ = std::filesystem::temp_directory_path() /
                ("sentinel_cpp_" + label + "_" + std::to_string(timestamp) + "_" +
                 std::to_string(counter++));
        std::filesystem::create_directories(root_);
    }

    ~TempDir() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    TempDir(TempDir&&) = delete;
    TempDir& operator=(TempDir&&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return root_;
    }

    [[nodiscard]] std::filesystem::path operator/(const std::string& name) const {
        return root_ / name;
    }

private:
    std::filesystem::path root_;
};

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::ofstream stream(path, std::ios::binary);
    stream << content;
}

void writePaddedFile(const std::filesystem::path& path,
                     std::size_t prefix_size,
                     char fill,
                     const std::string& suffix) {
    std::ofstream stream(path, std::ios::binary);
    stream << std::string(prefix_size, fill) << suffix;
}

// A rule that fails at match time, standing in for std::regex complexity errors.
class ThrowingRule final : public sentinel::engine::IRule {
public:
    [[nodiscard]] std::vector<sentinel::engine::RuleMatch> apply(
        std::string_view /*data*/) const override {
        throw std::runtime_error("simulated matcher failure");
    }

    [[nodiscard]] std::string_view id() const override {
        return "throwing";
    }

    [[nodiscard]] std::string_view description() const override {
        return "always throws";
    }

    [[nodiscard]] sentinel::engine::Severity severity() const noexcept override {
        return sentinel::engine::Severity::Info;
    }

    [[nodiscard]] std::string_view remediation() const override {
        return {};
    }

    [[nodiscard]] std::size_t maxMatchLength() const noexcept override {
        return 1;
    }
};

}  // namespace

using sentinel::engine::RegexRule;
using sentinel::engine::RulePtr;
using sentinel::engine::Scanner;
using sentinel::engine::ScanOptions;

TEST_CASE("scanFile returns matched signatures with absolute offsets", "[scanner][file]") {
    const TempDir root("file_signature");
    const auto file = root / "sample.txt";
    writeFile(file, "prefix password=super-secret suffix");

    const Scanner scanner;
    const auto result = scanner.scanFile(file, {"password="});

    REQUIRE(result.error == std::nullopt);
    REQUIRE(result.hasDetections());
    REQUIRE(result.findings.size() == 1);
    REQUIRE(result.findings.front().rule_id == "password=");
    REQUIRE(result.findings.front().offset == 7);
    REQUIRE(result.findings.front().length == 9);
}

TEST_CASE("scanFile detects signatures that cross the chunk boundary", "[scanner][buffer]") {
    const TempDir root("chunk_boundary");
    const auto file = root / "boundary.bin";
    const std::string signature = "EVIL_CODE";

    writePaddedFile(file, kBufferSize - 4, 'A', signature);

    const Scanner scanner;
    const auto result = scanner.scanFile(file, {signature});

    REQUIRE(result.hasDetections());
    REQUIRE(result.findings.size() == 1);
    REQUIRE(result.findings.front().offset == kBufferSize - 4);
}

TEST_CASE("scanFile reports a signature ending exactly at the chunk boundary once",
          "[scanner][buffer]") {
    const TempDir root("chunk_edge");
    const auto file = root / "edge.bin";
    const std::string signature = "EVIL_CODE";

    writePaddedFile(file, kBufferSize - signature.size(), 'A', signature + "tail");

    const Scanner scanner;
    const auto result = scanner.scanFile(file, {signature});

    REQUIRE(result.findings.size() == 1);
    REQUIRE(result.findings.front().offset == kBufferSize - signature.size());
}

TEST_CASE("scanFile handles a file whose size is a multiple of the chunk size",
          "[scanner][buffer]") {
    const TempDir root("chunk_multiple");
    const auto file = root / "exact.bin";
    const std::string signature = "EVIL_CODE";

    writePaddedFile(file, kBufferSize - signature.size(), 'A', signature);

    const Scanner scanner;
    const auto result = scanner.scanFile(file, {signature});

    REQUIRE(result.bytes_scanned == kBufferSize);
    REQUIRE(result.findings.size() == 1);
    REQUIRE(result.findings.front().offset == kBufferSize - signature.size());
}

TEST_CASE("scanFile detects regex matches that cross the chunk boundary", "[scanner][regex]") {
    const TempDir root("regex_boundary");
    const auto file = root / "key.txt";
    const std::string key = "AKIA1234567890ABCDEF";

    writePaddedFile(file, kBufferSize - 8, 'x', key + "\n");

    const Scanner scanner;
    const auto result = scanner.scanFile(
        file, {std::make_shared<RegexRule>("aws-key", R"(AKIA[0-9A-Z]{16})", "AWS key")});

    REQUIRE(result.error == std::nullopt);
    REQUIRE(result.findings.size() == 1);
    REQUIRE(result.findings.front().offset == kBufferSize - 8);
    REQUIRE(result.findings.front().length == key.size());
}

TEST_CASE("scanFile reports a variable-length regex token straddling the boundary once",
          "[scanner][regex]") {
    const TempDir root("regex_straddle");
    const auto file = root / "digits.txt";

    writePaddedFile(file, kBufferSize - 3, 'x', "1234567\n");

    const Scanner scanner;
    const auto result = scanner.scanFile(
        file,
        {
            std::make_shared<RegexRule>("digits", "[0-9]+", "digit run"),
            std::make_shared<sentinel::engine::StringMatchRule>("zz", "zz", "unused"),
        });

    REQUIRE(result.findings.size() == 1);
    REQUIRE(result.findings.front().offset == kBufferSize - 3);
    REQUIRE(result.findings.front().length == 7);
}

TEST_CASE("scanFile orders findings by offset across rules", "[scanner][file]") {
    const TempDir root("ordering");
    const auto file = root / "mixed.txt";
    writeFile(file, "bbb aaa bbb aaa");

    const Scanner scanner;
    const auto result = scanner.scanFile(file, std::vector<std::string> {"aaa", "bbb"});

    REQUIRE(result.findings.size() == 4);
    REQUIRE(result.findings[0].offset == 0);
    REQUIRE(result.findings[1].offset == 4);
    REQUIRE(result.findings[2].offset == 8);
    REQUIRE(result.findings[3].offset == 12);
}

TEST_CASE("scanFile treats a zero findings limit as unlimited", "[scanner][file]") {
    const TempDir root("unlimited");
    const auto file = root / "many.txt";
    std::string content;
    for (int i = 0; i < 100; ++i) {
        content += "password= ";
    }
    writeFile(file, content);

    const Scanner scanner;
    const auto capped = scanner.scanFile(file, Scanner::buildStringRules({"password="}), 5);
    const auto unlimited = scanner.scanFile(file, Scanner::buildStringRules({"password="}), 0);

    REQUIRE(capped.findings.size() == 5);
    REQUIRE(unlimited.findings.size() == 100);
}

TEST_CASE("scanFile converts a rule failure into a per-file error", "[scanner][error]") {
    const TempDir root("rule_failure");
    const auto file = root / "input.txt";
    writeFile(file, "some content");

    const Scanner scanner;
    const auto result = scanner.scanFile(file, {std::make_shared<ThrowingRule>()});

    REQUIRE(result.hasError());
    const auto message = result.error.value_or("");
    REQUIRE(message.find("throwing") != std::string::npos);
    REQUIRE(message.find("simulated matcher failure") != std::string::npos);
    REQUIRE_FALSE(result.hasDetections());
}

TEST_CASE("scanPath keeps scanning other files when one rule fails", "[scanner][error]") {
    const TempDir root("partial_failure");
    writeFile(root / "a.txt", "password=one");
    writeFile(root / "b.txt", "password=two");

    const Scanner scanner;
    const auto summary = scanner.scanPath(
        root.path(),
        {
            std::make_shared<ThrowingRule>(),
            std::make_shared<sentinel::engine::StringMatchRule>("pw", "password=", "credential"),
        },
        ScanOptions {
            .thread_count = 2,
            .max_findings_per_file = 64,
            .include_clean_files = false,
            .scan_binary_files = false,
            .include_globs = {},
            .exclude_globs = {},
        });

    REQUIRE(summary.files_scanned == 2);
    REQUIRE(summary.files_with_errors == 2);
    REQUIRE(summary.isIncomplete());
    REQUIRE(summary.file_results.size() == 2);
    REQUIRE(summary.file_results.front().hasError());
}

TEST_CASE("scanPath counts unreadable files as errors", "[scanner][error]") {
    const TempDir root("unreadable");
    const auto file = root / "secret.txt";
    writeFile(file, "password=hidden");
    std::filesystem::permissions(file, std::filesystem::perms::none);

    const Scanner scanner;
    const auto summary = scanner.scanPath(root.path(), Scanner::buildStringRules({"password="}));

    std::filesystem::permissions(file, std::filesystem::perms::owner_all);

    if (summary.files_with_detections == 1) {
        // Running with elevated privileges makes the file readable regardless of its mode.
        SUCCEED("permissions are not enforced for this user");
        return;
    }

    REQUIRE(summary.files_with_errors == 1);
    REQUIRE(summary.isIncomplete());
    REQUIRE_FALSE(summary.hasDetections());
    REQUIRE(summary.file_results.size() == 1);
    REQUIRE(summary.file_results.front().error == "unable to open file");
}

TEST_CASE("scanPath aggregates file-level detections and metadata", "[scanner][path]") {
    const TempDir root("path_summary");
    writeFile(root / "clean.cpp", "int main() { return 0; }");
    writeFile(root / "secrets.env", "API_KEY=demo\n");

    const Scanner scanner;
    const auto summary = scanner.scanPath(root.path(),
                                          Scanner::buildStringRules({"API_KEY="}),
                                          ScanOptions {
                                              .thread_count = 2,
                                              .max_findings_per_file = 64,
                                              .include_clean_files = true,
                                              .scan_binary_files = false,
                                              .include_globs = {},
                                              .exclude_globs = {},
                                          });

    REQUIRE(summary.files_scanned == 2);
    REQUIRE(summary.files_with_detections == 1);
    REQUIRE(summary.files_with_errors == 0);
    REQUIRE(summary.bytes_scanned > 0);
    REQUIRE(summary.file_results.size() == 2);
    REQUIRE_FALSE(summary.isIncomplete());
}

TEST_CASE("scanPath supports regex-based rules", "[scanner][regex]") {
    const TempDir root("path_regex");
    writeFile(root / "config.txt", "aws=AKIA1234567890ABCDEF\n");

    const Scanner scanner;
    const auto summary =
        scanner.scanPath(root.path(),
                         {std::make_shared<RegexRule>("aws-key", R"(AKIA[0-9A-Z]{16})", "AWS key")},
                         ScanOptions {
                             .thread_count = 1,
                             .max_findings_per_file = 64,
                             .include_clean_files = false,
                             .scan_binary_files = false,
                             .include_globs = {},
                             .exclude_globs = {},
                         });

    REQUIRE(summary.hasDetections());
    REQUIRE(summary.file_results.size() == 1);
    REQUIRE(summary.file_results.front().findings.front().rule_id == "aws-key");
}

TEST_CASE("wildcardMatch keeps '*' and '?' within a single path segment", "[scanner][glob]") {
    using sentinel::engine::wildcardMatch;

    REQUIRE(wildcardMatch("*.cpp", "main.cpp"));
    REQUIRE_FALSE(wildcardMatch("*.cpp", "src/main.cpp"));
    REQUIRE(wildcardMatch("src/*.cpp", "src/main.cpp"));
    REQUIRE_FALSE(wildcardMatch("src/*.cpp", "src/deep/main.cpp"));
    REQUIRE(wildcardMatch("src/**", "src/deep/main.cpp"));
    REQUIRE(wildcardMatch("**/main.cpp", "src/deep/main.cpp"));
    REQUIRE(wildcardMatch("src/**/*.cpp", "src/deep/nested/main.cpp"));
    REQUIRE(wildcardMatch("tests/??.txt", "tests/ab.txt"));
    REQUIRE_FALSE(wildcardMatch("tests/??.txt", "tests/a/.txt"));
    REQUIRE_FALSE(wildcardMatch("include/*.hpp", "src/main.cpp"));
    REQUIRE(wildcardMatch("*", "main.cpp"));
    REQUIRE_FALSE(wildcardMatch("*", "src/main.cpp"));
    REQUIRE(wildcardMatch("**", "src/main.cpp"));
    REQUIRE(wildcardMatch("", ""));
    REQUIRE_FALSE(wildcardMatch("", "a"));
}

TEST_CASE("globMatchesPath matches bare patterns against the file name at any depth",
          "[scanner][glob]") {
    using sentinel::engine::globMatchesPath;

    REQUIRE(globMatchesPath("*.cpp", "src/deep/main.cpp"));
    REQUIRE(globMatchesPath("main.cpp", "src/main.cpp"));
    REQUIRE_FALSE(globMatchesPath("*.hpp", "src/main.cpp"));
    REQUIRE(globMatchesPath("build/*", "build/generated.cpp"));
    REQUIRE_FALSE(globMatchesPath("build/*", "build/nested/generated.cpp"));
    REQUIRE(globMatchesPath("build/**", "build/nested/generated.cpp"));
}

TEST_CASE("scanPath filters files using include and exclude globs", "[scanner][filter]") {
    const TempDir root("filters");
    writeFile(root / "main.cpp", "password=demo");
    writeFile(root / "notes.txt", "password=ignored");
    std::filesystem::create_directories(root / "src");
    writeFile(root / "src" / "util.cpp", "password=demo");
    std::filesystem::create_directories(root / "build" / "nested");
    writeFile(root / "build" / "generated.cpp", "password=ignored");
    writeFile(root / "build" / "nested" / "generated.cpp", "password=ignored");

    const Scanner scanner;
    const auto summary = scanner.scanPath(root.path(),
                                          Scanner::buildStringRules({"password="}),
                                          ScanOptions {
                                              .thread_count = 2,
                                              .max_findings_per_file = 64,
                                              .include_clean_files = true,
                                              .scan_binary_files = false,
                                              .include_globs = {"*.cpp"},
                                              .exclude_globs = {"build/**"},
                                          });

    REQUIRE(summary.files_scanned == 2);
    REQUIRE(summary.files_with_detections == 2);
    REQUIRE(summary.file_results.size() == 2);
    REQUIRE(summary.file_results[0].path.filename() == "main.cpp");
    REQUIRE(summary.file_results[1].path.filename() == "util.cpp");
}

TEST_CASE("scanPath does not follow symbolic links", "[scanner][filter]") {
    const TempDir root("symlinks");
    const TempDir outside("symlink_target");
    writeFile(outside / "secret.txt", "password=outside");
    writeFile(root / "inside.txt", "password=inside");

    std::error_code link_error;
    std::filesystem::create_symlink(outside / "secret.txt", root / "link.txt", link_error);
    if (link_error) {
        SUCCEED("symbolic links are not supported here");
        return;
    }

    const Scanner scanner;
    const auto summary = scanner.scanPath(root.path(), Scanner::buildStringRules({"password="}));

    REQUIRE(summary.files_scanned == 1);
    REQUIRE(summary.file_results.size() == 1);
    REQUIRE(summary.file_results.front().path.filename() == "inside.txt");
}

TEST_CASE("scanPath skips binary files by default", "[scanner][binary]") {
    const TempDir root("binary_skip");
    const auto binary_file = root / "payload.bin";

    {
        std::ofstream stream(binary_file, std::ios::binary);
        stream.write("ABCD", 4);
        stream.put('\0');
        stream.write("password=", 9);
    }

    const Scanner scanner;
    const auto summary = scanner.scanPath(root.path(),
                                          Scanner::buildStringRules({"password="}),
                                          ScanOptions {
                                              .thread_count = 0,
                                              .max_findings_per_file = 64,
                                              .include_clean_files = true,
                                              .scan_binary_files = false,
                                              .include_globs = {},
                                              .exclude_globs = {},
                                          });

    REQUIRE(summary.files_scanned == 1);
    REQUIRE(summary.files_skipped == 1);
    REQUIRE(summary.file_results.size() == 1);
    REQUIRE(summary.file_results.front().skipped_reason == "binary file skipped");
    REQUIRE_FALSE(summary.hasDetections());
    REQUIRE_FALSE(summary.isIncomplete());
}

TEST_CASE("scanPath can opt into scanning binary files", "[scanner][binary]") {
    const TempDir root("binary_scan");
    const auto binary_file = root / "payload.bin";

    {
        std::ofstream stream(binary_file, std::ios::binary);
        stream.write("ABCD", 4);
        stream.put('\0');
        stream.write("password=", 9);
    }

    const Scanner scanner;
    const auto summary = scanner.scanPath(root.path(),
                                          Scanner::buildStringRules({"password="}),
                                          ScanOptions {
                                              .thread_count = 0,
                                              .max_findings_per_file = 64,
                                              .include_clean_files = false,
                                              .scan_binary_files = true,
                                              .include_globs = {},
                                              .exclude_globs = {},
                                          });

    REQUIRE(summary.files_scanned == 1);
    REQUIRE(summary.files_skipped == 0);
    REQUIRE(summary.files_with_detections == 1);
    REQUIRE(summary.file_results.size() == 1);
    REQUIRE(summary.file_results.front().findings.front().rule_id == "password=");
}

TEST_CASE("scanDirectory remains compatible with the simple boolean API", "[scanner][compat]") {
    const TempDir root("compat");
    writeFile(root / "payload.bin", "header EVIL_CODE trailer");

    const Scanner scanner;

    REQUIRE(scanner.scanDirectory(root.path(), {"EVIL_CODE"}, 4));
    REQUIRE_FALSE(scanner.scanDirectory(root.path(), {"MISSING_SIGNATURE"}, 4));
    REQUIRE_FALSE(scanner.scanDirectory(root / "does-not-exist", {"EVIL_CODE"}, 4));
}
