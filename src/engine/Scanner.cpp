#include "engine/Scanner.hpp"

#include "engine/StringMatch.hpp"
#include "engine/ThreadPool.hpp"

#include <algorithm>
#include <atomic>
#include <array>
#include <cstring>
#include <fstream>
#include <mutex>
#include <system_error>
#include <string_view>
#include <utility>

namespace sentinel::engine {
namespace {

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

bool matchesAnyGlob(std::string_view candidate, const std::vector<std::string>& patterns) {
    return std::ranges::any_of(patterns, [&](const std::string& pattern) {
        return wildcardMatch(pattern, candidate);
    });
}

bool shouldScanPath(const std::filesystem::path& root,
                    const std::filesystem::path& candidate,
                    const ScanOptions& options) {
    const auto relative = candidate.lexically_relative(root);
    const auto match_target = normalizePathForMatching(
        relative.empty() ? candidate.filename() : relative);

    if (!options.include_globs.empty() && !matchesAnyGlob(match_target, options.include_globs)) {
        return false;
    }

    if (matchesAnyGlob(match_target, options.exclude_globs)) {
        return false;
    }

    return true;
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
        collected.warnings.push_back(
            "unable to inspect path '" + root.string() + "': " + error.message());
        return collected;
    }

    if (!std::filesystem::exists(root, error) || !std::filesystem::is_directory(root, error)) {
        if (error) {
            collected.warnings.push_back(
                "unable to access path '" + root.string() + "': " + error.message());
        }
        return collected;
    }

    std::filesystem::recursive_directory_iterator iterator(
        root,
        std::filesystem::directory_options::skip_permission_denied,
        error);
    std::filesystem::recursive_directory_iterator end;

    if (error) {
        collected.warnings.push_back(
            "unable to enumerate directory '" + root.string() + "': " + error.message());
        return collected;
    }

    while (iterator != end) {
        const auto current = iterator->path();
        std::error_code status_error;
        const bool is_file = iterator->is_regular_file(status_error);
        if (status_error) {
            collected.warnings.push_back(
                "unable to inspect entry '" + current.string() + "': " + status_error.message());
        } else if (is_file && shouldScanPath(root, current, options)) {
            collected.files.push_back(current);
        }

        iterator.increment(error);
        if (error) {
            collected.warnings.push_back(
                "directory traversal warning under '" + root.string() + "': " + error.message());
            error.clear();
        }
    }

    std::sort(collected.files.begin(), collected.files.end());
    return collected;
}

std::size_t maxPatternLength(const std::vector<RulePtr>& rules) {
    std::size_t max_length = 1;
    for (const auto& rule : rules) {
        const auto* string_rule = dynamic_cast<const StringMatchRule*>(rule.get());
        if (string_rule != nullptr) {
            max_length = std::max(max_length, string_rule->pattern().size());
        }
    }

    return max_length;
}

bool shouldTreatAsBinary(std::string_view sample) {
    if (sample.empty()) {
        return false;
    }

    std::size_t suspicious_bytes = 0;
    for (const unsigned char byte : sample) {
        if (byte == 0) {
            return true;
        }

        if (byte < 0x09 || (byte > 0x0D && byte < 0x20)) {
            ++suspicious_bytes;
        }
    }

    return suspicious_bytes * 5 > sample.size();
}

bool isBinaryFile(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    std::array<char, 512> header {};
    file.read(header.data(), static_cast<std::streamsize>(header.size()));
    const auto header_bytes = static_cast<std::size_t>(file.gcount());
    return shouldTreatAsBinary(std::string_view(header.data(), header_bytes));
}

}  // namespace

bool wildcardMatch(std::string_view pattern, std::string_view candidate) {
    std::size_t pattern_index = 0;
    std::size_t candidate_index = 0;
    std::size_t star_index = std::string_view::npos;
    std::size_t match_index = 0;

    while (candidate_index < candidate.size()) {
        if (pattern_index < pattern.size()
            && (pattern[pattern_index] == '?'
                || pattern[pattern_index] == candidate[candidate_index])) {
            ++pattern_index;
            ++candidate_index;
            continue;
        }

        if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
            star_index = pattern_index++;
            match_index = candidate_index;
            continue;
        }

        if (star_index == std::string_view::npos) {
            return false;
        }

        pattern_index = star_index + 1;
        candidate_index = ++match_index;
    }

    while (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
        ++pattern_index;
    }

    return pattern_index == pattern.size();
}

std::vector<RulePtr> Scanner::buildStringRules(const std::vector<std::string>& signatures) {
    std::vector<RulePtr> rules;
    rules.reserve(signatures.size());

    for (const auto& signature : signatures) {
        rules.push_back(std::make_shared<StringMatchRule>(
            signature,
            signature,
            "Matched fixed signature '" + signature + "'"));
    }

    return rules;
}

FileScanResult Scanner::scanFile(
    const std::filesystem::path& path,
    const std::vector<std::string>& signatures) const {
    return scanFile(path, buildStringRules(signatures));
}

FileScanResult Scanner::scanFile(
    const std::filesystem::path& path,
    const std::vector<RulePtr>& rules,
    std::size_t max_findings_per_file) const {
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

    const auto overlap_length = maxPatternLength(rules) - 1;
    std::vector<char> buffer(kBufferSize + overlap_length);
    std::size_t bytes_in_overlap = 0;
    std::uintmax_t global_offset = 0;

    while (true) {
        file.read(buffer.data() + bytes_in_overlap, static_cast<std::streamsize>(kBufferSize));
        const auto bytes_read = static_cast<std::size_t>(file.gcount());

        if (bytes_read == 0 && bytes_in_overlap == 0) {
            break;
        }

        const auto window_size = bytes_in_overlap + bytes_read;
        const std::string_view window(buffer.data(), window_size);
        const auto window_base = global_offset >= bytes_in_overlap
            ? global_offset - bytes_in_overlap
            : 0;

        for (const auto& rule : rules) {
            for (auto match : rule->apply(window)) {
                match.offset += window_base;
                const auto already_reported = std::find(
                    result.findings.begin(),
                    result.findings.end(),
                    match);

                if (already_reported == result.findings.end()) {
                    result.findings.push_back(std::move(match));
                    if (result.findings.size() >= max_findings_per_file) {
                        result.bytes_scanned += bytes_read;
                        return result;
                    }
                }
            }
        }

        result.bytes_scanned += bytes_read;
        global_offset += bytes_read;

        if (file.eof()) {
            break;
        }

        if (window_size <= overlap_length) {
            bytes_in_overlap = window_size;
        } else if (overlap_length > 0) {
            std::memmove(
                buffer.data(),
                buffer.data() + (window_size - overlap_length),
                overlap_length);
            bytes_in_overlap = overlap_length;
        } else {
            bytes_in_overlap = 0;
        }
    }

    return result;
}

ScanSummary Scanner::scanPath(
    const std::filesystem::path& path,
    const std::vector<RulePtr>& rules,
    const ScanOptions& options) const {
    ScanSummary summary;
    summary.root = path;

    const auto collected = collectFiles(path, options);
    summary.warnings = collected.warnings;

    if (collected.files.empty() || rules.empty()) {
        return summary;
    }

    const auto worker_count = std::min(
        resolveThreadCount(options.thread_count),
        collected.files.size());
    ThreadPool pool(worker_count == 0 ? 1 : worker_count);

    std::mutex results_mutex;
    std::atomic<std::size_t> detections {0};
    std::atomic<std::size_t> skipped {0};

    for (const auto& file : collected.files) {
        pool.enqueue([&, file]() {
            FileScanResult file_result;
            file_result.path = file;

            if (!options.scan_binary_files && isBinaryFile(file)) {
                file_result.skipped_reason = "binary file skipped";
                ++skipped;
            } else {
                file_result = scanFile(file, rules, options.max_findings_per_file);
            }

            std::lock_guard<std::mutex> lock(results_mutex);
            summary.bytes_scanned += file_result.bytes_scanned;
            if (file_result.hasDetections()) {
                ++detections;
            }

            if (file_result.wasSkipped()) {
                if (options.include_clean_files) {
                    summary.file_results.push_back(std::move(file_result));
                }
                return;
            }

            if (options.include_clean_files || file_result.hasDetections() || file_result.error) {
                summary.file_results.push_back(std::move(file_result));
            }
        });
    }

    pool.waitAll();

    summary.files_scanned = collected.files.size();
    summary.files_with_detections = detections.load();
    summary.files_skipped = skipped.load();
    std::sort(
        summary.file_results.begin(),
        summary.file_results.end(),
        [](const FileScanResult& lhs, const FileScanResult& rhs) {
            return lhs.path < rhs.path;
        });

    return summary;
}

bool Scanner::scanDirectory(
    const std::filesystem::path& dir_path,
    const std::vector<std::string>& signatures,
    std::size_t thread_count) const {
    if (!std::filesystem::exists(dir_path) || !std::filesystem::is_directory(dir_path)) {
        return false;
    }

    if (signatures.empty()) {
        return false;
    }

    const auto summary = scanPath(
        dir_path,
        buildStringRules(signatures),
        ScanOptions {.thread_count = thread_count});

    return summary.hasDetections();
}

}  // namespace sentinel::engine
