// Throughput benchmarks for the scanning engine. Run the `benchmarks` target directly, e.g.
//   ./build/benchmarks --benchmark-samples 20
// Catch2 prints mean, low and high estimates per case so regressions are easy to spot.

#include "engine/RegexRule.hpp"
#include "engine/Scanner.hpp"
#include "engine/StringMatch.hpp"

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <vector>

using sentinel::engine::RegexRule;
using sentinel::engine::RulePtr;
using sentinel::engine::Scanner;
using sentinel::engine::ScanOptions;
using sentinel::engine::StringMatchRule;

namespace {

constexpr std::size_t kMiB = std::size_t {1024} * 1024;

class BenchmarkTree {
public:
    BenchmarkTree(std::size_t file_count, std::size_t bytes_per_file) {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        root_ =
            std::filesystem::temp_directory_path() / ("sentinel_bench_" + std::to_string(stamp));
        std::filesystem::create_directories(root_);

        // Deterministic content keeps runs comparable; this is not security-relevant.
        std::mt19937 rng(42);  // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed)
        std::uniform_int_distribution<int> letters('a', 'z');

        for (std::size_t i = 0; i < file_count; ++i) {
            std::string content;
            content.reserve(bytes_per_file);
            while (content.size() < bytes_per_file) {
                for (int word = 0; word < 8; ++word) {
                    content += static_cast<char>(letters(rng));
                }
                content += (rng() % 12 == 0) ? '\n' : ' ';
            }
            // One planted secret per file keeps the match path warm without dominating.
            content.replace(content.size() / 2, 20, "AKIA1234567890ABCDEF");

            std::ofstream stream(root_ / ("file_" + std::to_string(i) + ".txt"), std::ios::binary);
            stream << content;
        }
    }

    ~BenchmarkTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    BenchmarkTree(const BenchmarkTree&) = delete;
    BenchmarkTree& operator=(const BenchmarkTree&) = delete;
    BenchmarkTree(BenchmarkTree&&) = delete;
    BenchmarkTree& operator=(BenchmarkTree&&) = delete;

    [[nodiscard]] const std::filesystem::path& root() const noexcept {
        return root_;
    }

    [[nodiscard]] std::filesystem::path file(std::size_t index) const {
        return root_ / ("file_" + std::to_string(index) + ".txt");
    }

private:
    std::filesystem::path root_;
};

std::vector<RulePtr> literalRules() {
    return Scanner::buildStringRules(
        {"EVIL_CODE", "VIRUS_END", "MALWARE_START", "API_KEY", "password="});
}

std::vector<RulePtr> regexRules() {
    return {
        std::make_shared<RegexRule>("aws-key", R"(AKIA[0-9A-Z]{16})", "AWS key"),
        std::make_shared<RegexRule>(
            "private-key", R"(-----BEGIN [A-Z ]*PRIVATE KEY-----)", "PEM key"),
        std::make_shared<RegexRule>("github", R"(gh[pousr]_[A-Za-z0-9]{36,255})", "GitHub token"),
    };
}

std::vector<RulePtr> mixedRules() {
    auto rules = literalRules();
    for (auto& rule : regexRules()) {
        rules.push_back(std::move(rule));
    }
    return rules;
}

}  // namespace

TEST_CASE("Rule matching over a 64 KiB window", "[bench][rules]") {
    std::string window(sentinel::engine::kBufferSize, 'x');
    window.replace(window.size() / 3, 20, "AKIA1234567890ABCDEF");
    window.replace(window.size() / 2, 9, "password=");

    const StringMatchRule literal("password", "password=", "literal");
    const RegexRule regex("aws-key", R"(AKIA[0-9A-Z]{16})", "regex");

    BENCHMARK("StringMatchRule::apply") {
        return literal.apply(window).size();
    };

    BENCHMARK("RegexRule::apply") {
        return regex.apply(window).size();
    };
}

TEST_CASE("Single-file scanning throughput", "[bench][file]") {
    const BenchmarkTree tree(1, 8 * kMiB);
    const Scanner scanner;
    const auto literal = literalRules();
    const auto regex = regexRules();
    const auto mixed = mixedRules();

    BENCHMARK("8 MiB file, 5 literal rules") {
        return scanner.scanFile(tree.file(0), literal, 0).bytes_scanned;
    };

    BENCHMARK("8 MiB file, 3 regex rules") {
        return scanner.scanFile(tree.file(0), regex, 0).bytes_scanned;
    };

    BENCHMARK("8 MiB file, mixed rules") {
        return scanner.scanFile(tree.file(0), mixed, 0).bytes_scanned;
    };
}

TEST_CASE("Directory scanning scales with worker threads", "[bench][directory]") {
    const BenchmarkTree tree(64, std::size_t {256} * 1024);
    const Scanner scanner;
    const auto rules = mixedRules();

    for (const std::size_t threads :
         {std::size_t {1}, std::size_t {2}, std::size_t {4}, std::size_t {8}}) {
        BENCHMARK("64 x 256 KiB files, " + std::to_string(threads) + " thread(s)") {
            return scanner.scanPath(tree.root(), rules, ScanOptions {.thread_count = threads})
                .bytes_scanned;
        };
    }
}
