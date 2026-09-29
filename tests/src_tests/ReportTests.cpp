#include "engine/Json.hpp"
#include "engine/RegexRule.hpp"
#include "engine/Report.hpp"
#include "engine/Scanner.hpp"
#include "engine/StringMatch.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>
#include <vector>

namespace json = sentinel::engine::json;

using sentinel::engine::FileScanResult;
using sentinel::engine::parseReportFormat;
using sentinel::engine::RegexRule;
using sentinel::engine::render;
using sentinel::engine::renderJson;
using sentinel::engine::renderSarif;
using sentinel::engine::renderText;
using sentinel::engine::ReportFormat;
using sentinel::engine::ReportOptions;
using sentinel::engine::RuleMatch;
using sentinel::engine::RuleMetadata;
using sentinel::engine::RulePtr;
using sentinel::engine::ScanSummary;
using sentinel::engine::Severity;
using sentinel::engine::StringMatchRule;

namespace {

std::vector<RulePtr> sampleRules() {
    return {
        std::make_shared<RegexRule>(
            RuleMetadata {
                .id = "aws-key",
                .description = "AWS access key id",
                .severity = Severity::Critical,
                .remediation = "Rotate the key in IAM.",
            },
            R"(AKIA[0-9A-Z]{16})"),
        std::make_shared<StringMatchRule>(
            RuleMetadata {
                .id = "password",
                .description = "Hardcoded password",
                .severity = Severity::Medium,
                .remediation = {},
            },
            "password="),
        std::make_shared<StringMatchRule>(
            RuleMetadata {
                .id = "todo",
                .description = "Left-over TODO",
                .severity = Severity::Info,
                .remediation = {},
            },
            "TODO"),
    };
}

ScanSummary sampleSummary() {
    ScanSummary summary;
    summary.root = "/repo";
    summary.files_scanned = 4;
    summary.files_with_detections = 1;
    summary.files_with_errors = 1;
    summary.files_skipped = 1;
    summary.bytes_scanned = 4096;
    summary.warnings = {"directory traversal warning under '/repo': permission denied"};

    FileScanResult detected;
    detected.path = "/repo/src/config.env";
    detected.bytes_scanned = 120;
    detected.findings = {
        RuleMatch {
            .rule_id = "aws-key",
            .description = "AWS access key id",
            .offset = 4,
            .length = 20,
            .severity = Severity::Critical,
        },
        RuleMatch {
            .rule_id = "password",
            .description = "Hardcoded password",
            .offset = 40,
            .length = 9,
            .severity = Severity::Medium,
        },
    };

    FileScanResult failed;
    failed.path = "/repo/locked\x01.txt";
    failed.error = "unable to open file";

    FileScanResult skipped;
    skipped.path = "/repo/image.png";
    skipped.skipped_reason = "binary file skipped";

    FileScanResult clean;
    clean.path = "/repo/src/main.cpp";
    clean.bytes_scanned = 3000;

    summary.file_results = {detected, failed, skipped, clean};
    return summary;
}

const json::Value& member(const json::Value& object, std::string_view key) {
    const auto* value = object.find(key);
    REQUIRE(value != nullptr);
    return *value;
}

}  // namespace

TEST_CASE("parseReportFormat recognises the supported formats", "[report]") {
    REQUIRE(parseReportFormat("text") == ReportFormat::Text);
    REQUIRE(parseReportFormat("json") == ReportFormat::Json);
    REQUIRE(parseReportFormat("sarif") == ReportFormat::Sarif);
    REQUIRE_FALSE(parseReportFormat("xml").has_value());
    REQUIRE_FALSE(parseReportFormat("JSON").has_value());
}

TEST_CASE("renderText lists counts, severities, errors and remediation", "[report][text]") {
    const auto text = renderText(sampleSummary(), sampleRules(), ReportOptions {.thread_count = 4});

    REQUIRE(text.find("Files scanned: 4") != std::string::npos);
    REQUIRE(text.find("Files with detections: 1") != std::string::npos);
    REQUIRE(text.find("Files with errors: 1") != std::string::npos);
    REQUIRE(text.find("Files skipped: 1") != std::string::npos);
    REQUIRE(text.find("Threads: 4") != std::string::npos);
    REQUIRE(text.find("permission denied") != std::string::npos);
    REQUIRE(text.find("[critical] [aws-key] offset=4 length=20") != std::string::npos);
    REQUIRE(text.find("[medium] [password] offset=40 length=9") != std::string::npos);
    REQUIRE(text.find("error: unable to open file") != std::string::npos);
    REQUIRE(text.find("skipped: binary file skipped") != std::string::npos);
    REQUIRE(text.find("clean") != std::string::npos);

    // Remediation is printed once per triggered rule, not once per finding.
    REQUIRE(text.find("Remediation:") != std::string::npos);
    REQUIRE(text.find("aws-key: Rotate the key in IAM.") != std::string::npos);
    REQUIRE(text.find("todo:") == std::string::npos);
}

TEST_CASE("renderText reports auto thread selection and an empty result set", "[report][text]") {
    ScanSummary summary;
    summary.root = "/repo";

    const auto text = renderText(summary, {}, ReportOptions {});

    REQUIRE(text.find("Threads: auto") != std::string::npos);
    REQUIRE(text.find("Findings: none") != std::string::npos);
    REQUIRE(text.find("Remediation:") == std::string::npos);
}

TEST_CASE("renderJson emits a parseable document with the summary and rules", "[report][json]") {
    const auto output =
        renderJson(sampleSummary(), sampleRules(), ReportOptions {.thread_count = 2});
    const auto document = json::parse(output);

    REQUIRE(member(document, "root").asString() == "/repo");
    REQUIRE(member(document, "filesScanned").asInteger() == 4);
    REQUIRE(member(document, "filesWithDetections").asInteger() == 1);
    REQUIRE(member(document, "filesWithErrors").asInteger() == 1);
    REQUIRE(member(document, "filesSkipped").asInteger() == 1);
    REQUIRE(member(document, "bytesScanned").asInteger() == 4096);
    REQUIRE(member(document, "threads").asInteger() == 2);
    REQUIRE(member(document, "incomplete").asBool());
    REQUIRE(member(document, "warnings").asArray().size() == 1);

    const auto& rules = member(document, "rules").asArray();
    REQUIRE(rules.size() == 3);
    REQUIRE(member(rules[0], "id").asString() == "aws-key");
    REQUIRE(member(rules[0], "severity").asString() == "critical");
    REQUIRE(member(rules[0], "remediation").asString() == "Rotate the key in IAM.");

    const auto& results = member(document, "results").asArray();
    REQUIRE(results.size() == 4);

    const auto& detected = results[0];
    REQUIRE(member(detected, "path").asString() == "/repo/src/config.env");
    REQUIRE(member(detected, "error").isNull());
    REQUIRE(member(detected, "skippedReason").isNull());
    const auto& findings = member(detected, "findings").asArray();
    REQUIRE(findings.size() == 2);
    REQUIRE(member(findings[0], "ruleId").asString() == "aws-key");
    REQUIRE(member(findings[0], "offset").asInteger() == 4);
    REQUIRE(member(findings[0], "length").asInteger() == 20);
    REQUIRE(member(findings[0], "severity").asString() == "critical");

    const auto& failed = results[1];
    REQUIRE(member(failed, "path").asString() == "/repo/locked\x01.txt");
    REQUIRE(member(failed, "error").asString() == "unable to open file");

    REQUIRE(member(results[2], "skippedReason").asString() == "binary file skipped");
}

TEST_CASE("renderJson reports automatic thread selection as a string", "[report][json]") {
    const auto document = json::parse(renderJson(ScanSummary {}, {}, ReportOptions {}));

    REQUIRE(member(document, "threads").asString() == "auto");
    REQUIRE_FALSE(member(document, "incomplete").asBool());
    REQUIRE(member(document, "results").asArray().empty());
}

TEST_CASE("renderSarif produces a SARIF 2.1.0 log", "[report][sarif]") {
    const auto output = renderSarif(
        sampleSummary(), sampleRules(), ReportOptions {.thread_count = 2, .tool_version = "0.4.0"});
    const auto document = json::parse(output);

    REQUIRE(member(document, "version").asString() == "2.1.0");
    REQUIRE(member(document, "$schema").asString().find("sarif-schema-2.1.0") != std::string::npos);

    const auto& runs = member(document, "runs").asArray();
    REQUIRE(runs.size() == 1);
    const auto& run = runs[0];

    const auto& driver = member(member(run, "tool"), "driver");
    REQUIRE(member(driver, "name").asString() == "Sentinel-CPP");
    REQUIRE(member(driver, "version").asString() == "0.4.0");
    REQUIRE(member(driver, "informationUri").asString().find("github.com") != std::string::npos);

    const auto& rules = member(driver, "rules").asArray();
    REQUIRE(rules.size() == 3);
    REQUIRE(member(rules[0], "id").asString() == "aws-key");
    REQUIRE(member(member(rules[0], "shortDescription"), "text").asString() == "AWS access key id");
    REQUIRE(member(member(rules[0], "help"), "text").asString() == "Rotate the key in IAM.");
    REQUIRE(member(member(rules[0], "defaultConfiguration"), "level").asString() == "error");
    REQUIRE(member(member(rules[1], "defaultConfiguration"), "level").asString() == "warning");
    REQUIRE(member(member(rules[2], "defaultConfiguration"), "level").asString() == "note");
    REQUIRE(member(member(rules[0], "properties"), "severity").asString() == "critical");

    const auto& results = member(run, "results").asArray();
    REQUIRE(results.size() == 2);
    const auto& first = results[0];
    REQUIRE(member(first, "ruleId").asString() == "aws-key");
    REQUIRE(member(first, "ruleIndex").asInteger() == 0);
    REQUIRE(member(first, "level").asString() == "error");
    REQUIRE(member(member(first, "message"), "text").asString().find("AWS access key id") !=
            std::string::npos);

    const auto& location = member(member(first, "locations").asArray()[0], "physicalLocation");
    const auto& artifact = member(location, "artifactLocation");
    REQUIRE(member(artifact, "uri").asString() == "src/config.env");
    REQUIRE(member(artifact, "uriBaseId").asString() == "SRCROOT");
    const auto& region = member(location, "region");
    REQUIRE(member(region, "byteOffset").asInteger() == 4);
    REQUIRE(member(region, "byteLength").asInteger() == 20);

    REQUIRE(member(results[1], "level").asString() == "warning");

    const auto& base_ids = member(run, "originalUriBaseIds");
    REQUIRE(member(member(base_ids, "SRCROOT"), "uri").asString() == "file:///repo/");

    const auto& invocation = member(run, "invocations").asArray()[0];
    REQUIRE_FALSE(member(invocation, "executionSuccessful").asBool());
    const auto& notifications = member(invocation, "toolExecutionNotifications").asArray();
    REQUIRE(notifications.size() == 2);
    REQUIRE(member(notifications[0], "level").asString() == "error");
    REQUIRE(member(member(notifications[0], "message"), "text")
                .asString()
                .find("unable to open file") != std::string::npos);
    REQUIRE(member(notifications[1], "level").asString() == "warning");
}

TEST_CASE("renderSarif marks a complete clean run as successful", "[report][sarif]") {
    ScanSummary summary;
    summary.root = "/repo";
    summary.files_scanned = 1;

    const auto document = json::parse(renderSarif(summary, sampleRules(), ReportOptions {}));
    const auto& run = member(document, "runs").asArray()[0];

    REQUIRE(member(run, "results").asArray().empty());
    const auto& invocation = member(run, "invocations").asArray()[0];
    REQUIRE(member(invocation, "executionSuccessful").asBool());
    REQUIRE(member(invocation, "toolExecutionNotifications").asArray().empty());
}

TEST_CASE("renderSarif uses a file's own path when it is not under the root", "[report][sarif]") {
    ScanSummary summary;
    summary.root = "/repo/file.txt";
    summary.files_with_detections = 1;

    FileScanResult result;
    result.path = "/repo/file.txt";
    result.findings = {RuleMatch {.rule_id = "password", .description = "d", .offset = 0}};
    summary.file_results = {result};

    const auto document = json::parse(renderSarif(summary, sampleRules(), ReportOptions {}));
    const auto& run = member(document, "runs").asArray()[0];
    const auto& location = member(
        member(member(run, "results").asArray()[0], "locations").asArray()[0], "physicalLocation");

    REQUIRE(member(member(location, "artifactLocation"), "uri").asString() == "file.txt");
}

TEST_CASE("render dispatches on the requested format", "[report]") {
    const auto summary = sampleSummary();
    const auto rules = sampleRules();
    const ReportOptions options {};

    REQUIRE(render(ReportFormat::Text, summary, rules, options) ==
            renderText(summary, rules, options));
    REQUIRE(render(ReportFormat::Json, summary, rules, options) ==
            renderJson(summary, rules, options));
    REQUIRE(render(ReportFormat::Sarif, summary, rules, options) ==
            renderSarif(summary, rules, options));
}
