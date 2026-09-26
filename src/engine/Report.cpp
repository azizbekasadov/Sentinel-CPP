#include "engine/Report.hpp"

#include "engine/Json.hpp"

#include <algorithm>
#include <filesystem>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace sentinel::engine {
namespace {

constexpr std::string_view kToolName = "Sentinel-CPP";
constexpr std::string_view kToolUri = "https://github.com/azizbekasadov/Sentinel-CPP";
constexpr std::string_view kSarifSchema =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json";
constexpr std::string_view kSourceRootId = "SRCROOT";

std::string_view sarifLevel(Severity severity) noexcept {
    switch (severity) {
        case Severity::Critical:
        case Severity::High:
            return "error";
        case Severity::Medium:
            return "warning";
        case Severity::Low:
        case Severity::Info:
            return "note";
    }
    return "warning";
}

std::string threadsLabel(std::size_t thread_count) {
    return thread_count == 0 ? std::string("auto") : std::to_string(thread_count);
}

json::Value threadsValue(std::size_t thread_count) {
    if (thread_count == 0) {
        return {"auto"};
    }
    return {thread_count};
}

json::Value optionalString(const std::optional<std::string>& value) {
    if (value) {
        return {*value};
    }
    return {nullptr};
}

// Percent-encodes everything outside the unreserved set and '/', which is enough for a
// file URI built from a filesystem path.
std::string encodeUriPath(std::string_view path) {
    static constexpr std::string_view kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(path.size());

    for (const char ch : path) {
        const auto byte = static_cast<unsigned char>(ch);
        const bool unreserved = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                                (byte >= '0' && byte <= '9') || ch == '-' || ch == '.' ||
                                ch == '_' || ch == '~' || ch == '/';
        if (unreserved) {
            out += ch;
        } else {
            out += '%';
            out += kHex[byte >> 4U];
            out += kHex[byte & 0x0FU];
        }
    }

    return out;
}

// The directory findings are reported relative to. When the scan root is itself a file, its
// parent directory is the base so the file gets a plain relative name.
std::filesystem::path sourceRootDirectory(const ScanSummary& summary) {
    const bool root_is_scanned_file = std::ranges::any_of(
        summary.file_results,
        [&](const FileScanResult& result) { return result.path == summary.root; });
    return root_is_scanned_file ? summary.root.parent_path() : summary.root;
}

std::string fileUri(const std::filesystem::path& directory) {
    std::error_code error;
    auto absolute = std::filesystem::absolute(directory, error);
    if (error) {
        absolute = directory;
    }

    auto generic = absolute.generic_string();
    if (generic.empty() || generic.back() != '/') {
        generic += '/';
    }
    if (!generic.empty() && generic.front() != '/') {
        generic.insert(generic.begin(), '/');
    }

    return "file://" + encodeUriPath(generic);
}

std::string relativeUri(const std::filesystem::path& path, const std::filesystem::path& base) {
    const auto relative = path.lexically_relative(base);
    if (relative.empty() || relative == ".") {
        return path.filename().generic_string();
    }
    return relative.generic_string();
}

json::Value rulesCatalogue(const std::vector<RulePtr>& rules) {
    json::Value catalogue {json::Array {}};
    for (const auto& rule : rules) {
        catalogue.push(json::Value::object({
            {"id", rule->id()},
            {"description", rule->description()},
            {"severity", severityToString(rule->severity())},
            {"remediation", rule->remediation()},
        }));
    }
    return catalogue;
}

}  // namespace

std::optional<ReportFormat> parseReportFormat(std::string_view text) noexcept {
    if (text == "text") {
        return ReportFormat::Text;
    }
    if (text == "json") {
        return ReportFormat::Json;
    }
    if (text == "sarif") {
        return ReportFormat::Sarif;
    }
    return std::nullopt;
}

std::string renderText(const ScanSummary& summary,
                       const std::vector<RulePtr>& rules,
                       const ReportOptions& options) {
    std::ostringstream out;
    out << "Sentinel-CPP Scan Report\n";
    out << "Root: " << summary.root << '\n';
    out << "Files scanned: " << summary.files_scanned << '\n';
    out << "Files with detections: " << summary.files_with_detections << '\n';
    out << "Files with errors: " << summary.files_with_errors << '\n';
    out << "Files skipped: " << summary.files_skipped << '\n';
    out << "Bytes scanned: " << summary.bytes_scanned << '\n';
    out << "Threads: " << threadsLabel(options.thread_count) << '\n';

    if (!summary.warnings.empty()) {
        out << "Warnings:\n";
        for (const auto& warning : summary.warnings) {
            out << "  - " << warning << '\n';
        }
    }

    if (summary.file_results.empty()) {
        out << "Findings: none\n";
        return out.str();
    }

    std::set<std::string_view> triggered_rules;

    out << "Findings:\n";
    for (const auto& file_result : summary.file_results) {
        out << "  " << file_result.path << '\n';

        if (file_result.error) {
            out << "    error: " << *file_result.error << '\n';
        }

        if (file_result.skipped_reason) {
            out << "    skipped: " << *file_result.skipped_reason << '\n';
            continue;
        }

        if (file_result.findings.empty()) {
            if (!file_result.error) {
                out << "    clean\n";
            }
            continue;
        }

        for (const auto& finding : file_result.findings) {
            triggered_rules.insert(finding.rule_id);
            out << "    - [" << severityToString(finding.severity) << "] [" << finding.rule_id
                << "] offset=" << finding.offset << " length=" << finding.length
                << " :: " << finding.description << '\n';
        }
    }

    bool wrote_header = false;
    for (const auto& rule : rules) {
        if (!triggered_rules.contains(rule->id()) || rule->remediation().empty()) {
            continue;
        }
        if (!wrote_header) {
            out << "Remediation:\n";
            wrote_header = true;
        }
        out << "  " << rule->id() << ": " << rule->remediation() << '\n';
    }

    return out.str();
}

std::string renderJson(const ScanSummary& summary,
                       const std::vector<RulePtr>& rules,
                       const ReportOptions& options) {
    json::Value results {json::Array {}};
    for (const auto& file_result : summary.file_results) {
        json::Value findings {json::Array {}};
        for (const auto& finding : file_result.findings) {
            findings.push(json::Value::object({
                {"ruleId", finding.rule_id},
                {"description", finding.description},
                {"offset", finding.offset},
                {"length", finding.length},
                {"severity", severityToString(finding.severity)},
            }));
        }

        results.push(json::Value::object({
            {"path", file_result.path.string()},
            {"bytesScanned", file_result.bytes_scanned},
            {"error", optionalString(file_result.error)},
            {"skippedReason", optionalString(file_result.skipped_reason)},
            {"findings", std::move(findings)},
        }));
    }

    json::Value warnings {json::Array {}};
    for (const auto& warning : summary.warnings) {
        warnings.push(json::Value(warning));
    }

    const auto document = json::Value::object({
        {"root", summary.root.string()},
        {"filesScanned", summary.files_scanned},
        {"filesWithDetections", summary.files_with_detections},
        {"filesWithErrors", summary.files_with_errors},
        {"filesSkipped", summary.files_skipped},
        {"bytesScanned", summary.bytes_scanned},
        {"threads", threadsValue(options.thread_count)},
        {"incomplete", summary.isIncomplete()},
        {"warnings", std::move(warnings)},
        {"rules", rulesCatalogue(rules)},
        {"results", std::move(results)},
    });

    return json::dump(document) + '\n';
}

std::string renderSarif(const ScanSummary& summary,
                        const std::vector<RulePtr>& rules,
                        const ReportOptions& options) {
    std::map<std::string_view, std::size_t> rule_indices;
    json::Value sarif_rules {json::Array {}};
    for (std::size_t index = 0; index < rules.size(); ++index) {
        const auto& rule = rules[index];
        rule_indices.emplace(rule->id(), index);

        json::Value entry = json::Value::object({
            {"id", rule->id()},
            {"name", rule->id()},
            {"shortDescription", json::Value::object({{"text", rule->description()}})},
            {"defaultConfiguration",
             json::Value::object({{"level", sarifLevel(rule->severity())}})},
            {"properties", json::Value::object({{"severity", severityToString(rule->severity())}})},
        });
        if (!rule->remediation().empty()) {
            entry.set("help", json::Value::object({{"text", rule->remediation()}}));
        }
        sarif_rules.push(std::move(entry));
    }

    const auto base_directory = sourceRootDirectory(summary);

    json::Value results {json::Array {}};
    json::Value notifications {json::Array {}};

    for (const auto& file_result : summary.file_results) {
        const auto uri = relativeUri(file_result.path, base_directory);
        const auto artifact = json::Value::object({
            {"uri", uri},
            {"uriBaseId", kSourceRootId},
        });

        if (file_result.error) {
            notifications.push(json::Value::object({
                {"level", "error"},
                {"message",
                 json::Value::object(
                     {{"text", file_result.path.string() + ": " + *file_result.error}})},
                {"locations",
                 json::Value::array({json::Value::object(
                     {{"physicalLocation",
                       json::Value::object({{"artifactLocation", artifact}})}})})},
            }));
        }

        for (const auto& finding : file_result.findings) {
            json::Value result = json::Value::object({
                {"ruleId", finding.rule_id},
            });
            if (const auto it = rule_indices.find(finding.rule_id); it != rule_indices.end()) {
                result.set("ruleIndex", it->second);
            }
            result.set("level", sarifLevel(finding.severity));
            result.set("message",
                       json::Value::object(
                           {{"text", finding.description + " (" + finding.rule_id + ")"}}));
            result.set("locations",
                       json::Value::array({json::Value::object({
                           {"physicalLocation",
                            json::Value::object({
                                {"artifactLocation", artifact},
                                {"region",
                                 json::Value::object({
                                     {"byteOffset", finding.offset},
                                     {"byteLength", finding.length},
                                 })},
                            })},
                       })}));
            results.push(std::move(result));
        }
    }

    for (const auto& warning : summary.warnings) {
        notifications.push(json::Value::object({
            {"level", "warning"},
            {"message", json::Value::object({{"text", warning}})},
        }));
    }

    const auto run = json::Value::object({
        {"tool",
         json::Value::object({
             {"driver",
              json::Value::object({
                  {"name", kToolName},
                  {"version", options.tool_version},
                  {"informationUri", kToolUri},
                  {"rules", std::move(sarif_rules)},
              })},
         })},
        {"originalUriBaseIds",
         json::Value::object({
             {std::string(kSourceRootId), json::Value::object({{"uri", fileUri(base_directory)}})},
         })},
        {"invocations",
         json::Value::array({json::Value::object({
             {"executionSuccessful", !summary.isIncomplete()},
             {"toolExecutionNotifications", std::move(notifications)},
         })})},
        {"results", std::move(results)},
    });

    const auto document = json::Value::object({
        {"$schema", kSarifSchema},
        {"version", "2.1.0"},
        {"runs", json::Value::array({run})},
    });

    return json::dump(document) + '\n';
}

std::string render(ReportFormat format,
                   const ScanSummary& summary,
                   const std::vector<RulePtr>& rules,
                   const ReportOptions& options) {
    switch (format) {
        case ReportFormat::Text:
            return renderText(summary, rules, options);
        case ReportFormat::Json:
            return renderJson(summary, rules, options);
        case ReportFormat::Sarif:
            return renderSarif(summary, rules, options);
    }
    return renderText(summary, rules, options);
}

}  // namespace sentinel::engine
