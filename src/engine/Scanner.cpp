#include "engine/Scanner.hpp"

#include "engine/StringMatch.hpp"
#include "engine/ThreadPool.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <exception>
#include <fstream>
#include <mutex>
#include <string_view>
#include <system_error>
#include <utility>

namespace sentinel::engine {
namespace {

constexpr std::size_t kBinarySniffBytes = 512;

struct CollectedFiles {
    std::vector<std::filesystem::path> files;
    std::vector<std::string> warnings;
};

std::size_t resolveThreadCount(std::size_t requested) {
    if (requested > 0) {
        return requested;
    }

    const auto detected = std::thread::hardware_concurrency();
    return detected == 0 ? 1U : static_cast<std::size_t>(detected);
}

std::string normalizePathForMatching(const std::filesystem::path& path) {
    auto normalized = path.generic_string();
    if (normalized.empty()) {
        normalized = path.string();
    }

    return normalized;
}

bool matchesAnyGlob(std::string_view relative_path, const std::vector<std::string>& patterns) {
    return std::ranges::any_of(patterns, [&](const std::string& pattern) {
        return globMatchesPath(pattern, relative_path);
    });
}

bool shouldScanPath(const std::filesystem::path& root,
                    const std::filesystem::path& candidate,
                    const ScanOptions& options) {
    const auto relative = candidate.lexically_relative(root);
    const auto match_target =
        normalizePathForMatching(relative.empty() ? candidate.filename() : relative);

    if (!options.include_globs.empty() && !matchesAnyGlob(match_target, options.include_globs)) {
        return false;
    }

    return !matchesAnyGlob(match_target, options.exclude_globs);
}

CollectedFiles collectFiles(const std::filesystem::path& root, const ScanOptions& options) {
    CollectedFiles collected;
    std::error_code error;

    if (std::filesystem::is_regular_file(root, error)) {
        if (shouldScanPath(root.parent_path(), root, options)) {
            collected.files.push_back(root);
        }
        return collected;
    }

    if (error) {
        collected.warnings.push_back("unable to inspect path '" + root.string() +
                                     "': " + error.message());
        return collected;
    }

    if (!std::filesystem::exists(root, error) || !std::filesystem::is_directory(root, error)) {
        if (error) {
            collected.warnings.push_back("unable to access path '" + root.string() +
                                         "': " + error.message());
        }
        return collected;
    }

    // Symbolic links are deliberately not followed: a link inside the tree could otherwise pull
    // in (and report on) files outside the requested root, or loop forever.
    std::filesystem::recursive_directory_iterator iterator(
        root, std::filesystem::directory_options::skip_permission_denied, error);
    const std::filesystem::recursive_directory_iterator end;

    if (error) {
        collected.warnings.push_back("unable to enumerate directory '" + root.string() +
                                     "': " + error.message());
        return collected;
    }

    while (iterator != end) {
        const auto current = iterator->path();
        std::error_code status_error;
        const auto status = iterator->symlink_status(status_error);
        if (status_error) {
            collected.warnings.push_back("unable to inspect entry '" + current.string() +
                                         "': " + status_error.message());
        } else if (std::filesystem::is_regular_file(status) &&
                   shouldScanPath(root, current, options)) {
            collected.files.push_back(current);
        }

        iterator.increment(error);
        if (error) {
            collected.warnings.push_back("directory traversal warning under '" + root.string() +
                                         "': " + error.message());
            error.clear();
        }
    }

    std::ranges::sort(collected.files);
    return collected;
}

std::size_t requiredOverlap(const std::vector<RulePtr>& rules) {
    std::size_t overlap = 0;
    for (const auto& rule : rules) {
        overlap = std::max(overlap, rule->maxMatchLength());
    }

    return overlap;
}

bool looksBinary(std::string_view sample) {
    if (sample.empty()) {
        return false;
    }

    std::size_t suspicious_bytes = 0;
    for (const char ch : sample) {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte == 0) {
            return true;
        }

        if (byte < 0x09 || (byte > 0x0D && byte < 0x20)) {
            ++suspicious_bytes;
        }
    }

    return suspicious_bytes * 5 > sample.size();
}

void sortFindings(std::vector<RuleMatch>& findings) {
    std::ranges::sort(findings, [](const RuleMatch& lhs, const RuleMatch& rhs) {
        if (lhs.offset != rhs.offset) {
            return lhs.offset < rhs.offset;
        }
        return lhs.rule_id < rhs.rule_id;
    });
}

// Recursive glob matcher. Patterns are short, so the potential backtracking is cheap, and a
// recursive formulation makes the '**' versus '*' distinction easy to get right.
bool matchGlobFrom(std::string_view pattern,
                   std::size_t p,
                   std::string_view candidate,
                   std::size_t c) {
    while (p < pattern.size()) {
        if (pattern[p] == '*') {
            std::size_t star_count = 0;
            while (p < pattern.size() && pattern[p] == '*') {
                ++p;
                ++star_count;
            }
            const bool crosses_separator = star_count > 1;

            // A '**/' prefix may also match zero directories, as in gitignore.
            if (crosses_separator && p < pattern.size() && pattern[p] == '/' &&
                matchGlobFrom(pattern, p + 1, candidate, c)) {
                return true;
            }

            for (std::size_t k = c;; ++k) {
                if (matchGlobFrom(pattern, p, candidate, k)) {
                    return true;
                }
                if (k >= candidate.size() || (!crosses_separator && candidate[k] == '/')) {
                    return false;
                }
            }
        }

        if (c >= candidate.size()) {
            return false;
        }

        const bool matches_char =
            pattern[p] == '?' ? candidate[c] != '/' : pattern[p] == candidate[c];
        if (!matches_char) {
            return false;
        }

        ++p;
        ++c;
    }

    return c == candidate.size();
}

}  // namespace

bool wildcardMatch(std::string_view pattern, std::string_view candidate) {
    return matchGlobFrom(pattern, 0, candidate, 0);
}

bool globMatchesPath(std::string_view pattern, std::string_view relative_path) {
    if (pattern.find('/') == std::string_view::npos) {
        const auto separator = relative_path.rfind('/');
        const auto filename = separator == std::string_view::npos
                                  ? relative_path
                                  : relative_path.substr(separator + 1);
        return wildcardMatch(pattern, filename);
    }

    return wildcardMatch(pattern, relative_path);
}

std::vector<RulePtr> Scanner::buildStringRules(const std::vector<std::string>& signatures) {
    std::vector<RulePtr> rules;
    rules.reserve(signatures.size());

    for (const auto& signature : signatures) {
        rules.push_back(std::make_shared<StringMatchRule>(
            signature, signature, "Matched fixed signature '" + signature + "'"));
    }

    return rules;
}

FileScanResult Scanner::scanFile(const std::filesystem::path& path,
                                 const std::vector<std::string>& signatures) const {
    return scanFile(path, buildStringRules(signatures));
}

FileScanResult Scanner::scanFile(const std::filesystem::path& path,
                                 const std::vector<RulePtr>& rules,
                                 std::size_t max_findings_per_file) const {
    return scanFile(path,
                    rules,
                    FileScanOptions {
                        .max_findings_per_file = max_findings_per_file,
                        .scan_binary_files = true,
                    });
}

FileScanResult Scanner::scanFile(const std::filesystem::path& path,
                                 const std::vector<RulePtr>& rules,
                                 const FileScanOptions& options) const {
    FileScanResult result;
    result.path = path;

    if (rules.empty()) {
        return result;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        result.error = "unable to open file";
        return result;
    }

    // Every window is scanned in full, but only matches that start in the leading
    // `window_size - overlap` bytes are reported from it. The trailing `overlap` bytes are carried
    // into the next window, where matches starting in them are seen with complete context. This
    // reports each match exactly once for any rule whose matches fit within `overlap` bytes.
    const auto overlap = requiredOverlap(rules);
    std::vector<char> buffer(kBufferSize + overlap);
    std::size_t carried = 0;
    std::uintmax_t consumed = 0;
    bool first_window = true;

    while (true) {
        file.read(buffer.data() + carried, static_cast<std::streamsize>(kBufferSize));
        if (file.bad()) {
            result.error = "read error";
            return result;
        }

        const auto bytes_read = static_cast<std::size_t>(file.gcount());
        const auto window_size = carried + bytes_read;
        if (window_size == 0) {
            break;
        }

        const std::string_view window(buffer.data(), window_size);
        const auto window_base = consumed - carried;

        if (first_window && !options.scan_binary_files &&
            looksBinary(window.substr(0, std::min(window_size, kBinarySniffBytes)))) {
            result.skipped_reason = "binary file skipped";
            return result;
        }
        first_window = false;

        const bool is_final = file.eof();
        std::size_t report_limit = window_size;
        if (!is_final) {
            report_limit = window_size > overlap ? window_size - overlap : 0;
        }

        for (const auto& rule : rules) {
            std::vector<RuleMatch> matches;
            try {
                matches = rule->apply(window);
            } catch (const std::exception& error) {
                result.error = "rule '" + std::string(rule->id()) + "' failed: " + error.what();
                result.bytes_scanned += bytes_read;
                sortFindings(result.findings);
                return result;
            }

            for (auto& match : matches) {
                if (match.offset >= report_limit) {
                    continue;
                }

                match.offset += static_cast<std::size_t>(window_base);
                result.findings.push_back(std::move(match));

                if (options.max_findings_per_file != 0 &&
                    result.findings.size() >= options.max_findings_per_file) {
                    result.bytes_scanned += bytes_read;
                    sortFindings(result.findings);
                    return result;
                }
            }
        }

        result.bytes_scanned += bytes_read;
        consumed += bytes_read;

        if (is_final) {
            break;
        }

        carried = std::min(window_size, overlap);
        if (carried > 0) {
            std::memmove(buffer.data(), buffer.data() + (window_size - carried), carried);
        }
    }

    sortFindings(result.findings);
    return result;
}

ScanSummary Scanner::scanPath(const std::filesystem::path& path,
                              const std::vector<RulePtr>& rules,
                              const ScanOptions& options) const {
    ScanSummary summary;
    summary.root = path;

    const auto collected = collectFiles(path, options);
    summary.warnings = collected.warnings;

    if (collected.files.empty() || rules.empty()) {
        return summary;
    }

    const auto worker_count =
        std::min(resolveThreadCount(options.thread_count), collected.files.size());
    ThreadPool pool(worker_count);

    const FileScanOptions file_options {
        .max_findings_per_file = options.max_findings_per_file,
        .scan_binary_files = options.scan_binary_files,
    };

    std::mutex results_mutex;
    std::atomic<std::size_t> detections {0};
    std::atomic<std::size_t> errors {0};
    std::atomic<std::size_t> skipped {0};

    for (const auto& file : collected.files) {
        // NOLINTNEXTLINE(bugprone-exception-escape): the pool captures anything the handler misses.
        pool.enqueue([&, file] {
            FileScanResult file_result;
            try {
                file_result = scanFile(file, rules, file_options);
            } catch (const std::exception& error) {
                file_result.path = file;
                file_result.error = error.what();
            }

            if (file_result.hasDetections()) {
                ++detections;
            }
            if (file_result.hasError()) {
                ++errors;
            }
            if (file_result.wasSkipped()) {
                ++skipped;
            }

            const bool keep = options.include_clean_files || file_result.hasDetections() ||
                              file_result.hasError();

            const std::scoped_lock lock(results_mutex);
            summary.bytes_scanned += file_result.bytes_scanned;
            if (keep) {
                summary.file_results.push_back(std::move(file_result));
            }
        });
    }

    pool.waitAll();

    summary.files_scanned = collected.files.size();
    summary.files_with_detections = detections.load();
    summary.files_with_errors = errors.load();
    summary.files_skipped = skipped.load();
    std::ranges::sort(
        summary.file_results,
        [](const FileScanResult& lhs, const FileScanResult& rhs) { return lhs.path < rhs.path; });

    return summary;
}

bool Scanner::scanDirectory(const std::filesystem::path& dir_path,
                            const std::vector<std::string>& signatures,
                            std::size_t thread_count) const {
    std::error_code error;
    if (!std::filesystem::is_directory(dir_path, error) || error) {
        return false;
    }

    if (signatures.empty()) {
        return false;
    }

    const auto summary = scanPath(dir_path,
                                  buildStringRules(signatures),
                                  ScanOptions {
                                      .thread_count = thread_count,
                                      .max_findings_per_file = 64,
                                      .include_clean_files = false,
                                      .scan_binary_files = false,
                                      .include_globs = {},
                                      .exclude_globs = {},
                                  });

    return summary.hasDetections();
}

}  // namespace sentinel::engine
