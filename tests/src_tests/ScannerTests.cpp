//
//  ScannerTests.cpp
//  unit_tests
//
//  Created by Azizbek Asadov on 06.04.2026.
//

#include <chrono>
#include <thread>
#include <fstream>
#include <catch2/catch_test_macros.hpp>

#include "engine/Scanner.hpp"

#define EVIL_CODE "EVIL_CODE"
#define BAD_SIGNATURE "BAD_SIGNATURE"

using namespace sentinel::engine;
using namespace std;

// MARK: - Helpers

const filesystem::path makeNonExistingPath() {
    return "/tmp/definitely_not_exists_2edqw";
}

const filesystem::path makeTestFile() {
    return "test_target.text";
}

const filesystem::path makeTestDir() {
    return "test_dir";
}

const filesystem::path makeBadFile() {
    return "bad_file.bin";
}

const filesystem::path makeTempDirectory() {
    return filesystem::temp_directory_path();
}

const filesystem::path makeInnerFolder() {
    return "inner_folder";
}

void makeEmptyFile(const filesystem::path empty_file) {
    ofstream(empty_file) << "";
}

filesystem::path createTestDirectory(const filesystem::path tempFile) {
    filesystem::path root = makeTempDirectory() / makeTestDir();
    filesystem::path subDir = root / tempFile;
    filesystem::create_directories(subDir);
    
    return root;
}

const filesystem::path createTempDirectory(const filesystem::path temp_dir)  {
    filesystem::path root = makeTempDirectory() / temp_dir;
    filesystem::create_directories(root);
    
    return root;
}



// MARK: - Test Cases for `Scanner`

// Test: Scanning for any malicious signatures in the file
TEST_CASE("Scanner detects malicious signatures", "[scanner]") {
    Scanner scanner;
    filesystem::path test_file = makeTestFile();
    
    SECTION("Positive case: signature found") {
        ofstream(test_file) << "some data and BAD_SIGNATURE found here" << endl;
        
        auto result = scanner.scanFile(test_file, { BAD_SIGNATURE });
        
        REQUIRE(result.found_malicious);
        REQUIRE(!result.signatures.empty());
        
        filesystem::remove(test_file);
    }
}

// Test: Scanning for any malicious signatures in the directory
TEST_CASE("Scanner handles directory recursion", "[scanner][filesystem]") {
    Scanner scanner;
    filesystem::path root = makeTempDirectory() / makeTestDir();
    filesystem::path sub_dir = root / makeInnerFolder();
    filesystem::create_directories(sub_dir);
    
    SECTION("Detects thread in the provided sub-folder") {
        ofstream(sub_dir / makeBadFile()) << "prelude EVIL_CODE suffix";
        
        // injecting path to the root to allow scanner to detect file in the sub-folder
        bool is_found = scanner.scanDirectory(root);
        
        REQUIRE(is_found);
    }
    
    filesystem::remove_all(root);
}

// Test: scanning for edge cases while scanning for malicious files in the provided temp dir
TEST_CASE("Scanner Edge Cases", "[scanner][robustness]") {
    Scanner scanner;
    
    filesystem::path root = createTempDirectory("edge_cases");
    
    const int max_files_count = 100;
    
    SECTION("Empty directory returns false") {
        REQUIRE_FALSE(scanner.scanDirectory(root));
    }
    
    SECTION("Large number of small files - stress testing") {
        for (int i = 0; i < max_files_count; ++i) {
            filesystem::path temp_bin_path = "file_" + to_string(i) + ".bin";
            ofstream(root / temp_bin_path) << "clean data";
        }
        
        filesystem::path malware_filename = "malware.bin";
        ofstream(root / malware_filename) << EVIL_CODE;
        
        REQUIRE(scanner.scanDirectory(root) == true);
    }
    
    SECTION("Non-existent path handling") {
        REQUIRE_FALSE(scanner.scanDirectory(makeNonExistingPath()));
    }
    
    filesystem::remove_all(root);
}

// Test: validating empty files, files with restricted permissions and signature overlap of the Scanner
TEST_CASE("Scanner Advanced Robustness", "[scanner][advanced]") {
    Scanner scanner;
    
    filesystem::path root = createTempDirectory("advanced_tests");
    
    SECTION("Empty file should not trigger false positives") {
        filesystem::path empty_file_name = "empty.bin";
        filesystem::path empty_file = root / empty_file_name;
        
        makeEmptyFile(empty_file);
        
        auto result = scanner.scanFile(empty_file, { EVIL_CODE });
        REQUIRE_FALSE(result.found_malicious);
    }
    
    SECTION("Handling files with no read permissions ~ chmod") {
        filesystem::path locked_filename = "locked.bin";
        filesystem::path locked_file = root / locked_filename;
        ofstream(locked_file) << "some secret encrypted data";
        
        // chmod of the temp file
        filesystem::permissions(
            locked_file,
            filesystem::perms::none,
            filesystem::perm_options::replace
        );
        
        // scanner must return an empty result without any failure
        auto result = scanner.scanFile(locked_file, { "secret" });
        REQUIRE_FALSE(result.found_malicious);
        
        filesystem::permissions(locked_file, filesystem::perms::owner_all);
        
        SECTION("Signature split across buffer boundaries") {
            filesystem::path split_filename = "split.bin";
            filesystem::path split_file = root / split_filename;
            string padding(BUFFER_SIZE, 'A'); // filling out the entire buffer with random data
            ofstream(split_file) << padding << EVIL_CODE;
            
            auto result = scanner.scanFile(split_file, { EVIL_CODE });
            REQUIRE(result.found_malicious);
        }
    }
    
    filesystem::remove_all(root);
}

// Test: Scanner scanFile detects multiple different signatures if any, signature at the end of the buffer is read properly, detecting and handling overlapping signatures
TEST_CASE("Scanner Deep Dive", "[scanner][internal]") {
    Scanner scanner;
    filesystem::path root = createTempDirectory("deep_scan_tests");
    
    const string SIG1 = "MALWARE_START";
    const string SIG2 = "VIRUS_END";
    const vector<string> targets = { SIG1, SIG2 };
    
    SECTION("Detects multiple different signatures") {
        filesystem::path multi_filename = "multi.bin";
        filesystem::path multi_file = root / multi_filename;
        
        ofstream(multi_file) << "some " << SIG1 << " middle " << SIG2 << " EOF";
        
        auto result = scanner.scanFile(multi_file, targets);
        
        REQUIRE(result.found_malicious);
        REQUIRE(result.signatures.size() == 2);
    }
    
    SECTION("Boundary Test: Signature exactly at the end of buffer") {
        filesystem::path boundary_filename = "boundary.bin";
        filesystem::path boundary_file = root / boundary_filename;
        
        string padding(BUFFER_SIZE - SIG1.length(), 'A');
        
        ofstream(boundary_file) << padding << SIG1;
        
        auto result = scanner.scanFile(boundary_file, { SIG1 });
        
        REQUIRE(result.found_malicious);
    }
    
    SECTION("Overlapping signatures") {
        filesystem::path overlap_filename = "overlap.bin";
        filesystem::path overlap_file = root / overlap_filename;
        
        ofstream(overlap_file) << "AAAAA";
        
        auto result = scanner.scanFile(overlap_file, { "AAA" });
        
        REQUIRE(result.found_malicious);
    }
    
    filesystem::remove_all(root);
}

// Test: checking performance in the scanDirectory method, it should not take a lot of time
TEST_CASE("Scanner Multithreading Efficiency", "[scanner][performance]") {
    Scanner scanner;
    
    auto root = createTempDirectory("mt_test");

    const int file_count = 10;
    
    for (int i = 0; i < file_count; ++i) {
        ofstream(root / ("file_" + to_string(i) + ".bin")) << "clean data";
    }

    auto start = chrono::high_resolution_clock::now();
    bool detected = scanner.scanDirectory(root, 8);
    
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();

    // sanity check
    REQUIRE_FALSE(detected);
    REQUIRE(duration < 500);
    
    filesystem::remove_all(root);
}

// Test: prevention of the Race Condition
TEST_CASE("Scanner Thread Safety - Concurrent Detection", "[scanner][threads]") {
    Scanner scanner;
    auto root = createTempDirectory("race_test");

    for (int i = 0; i < 20; ++i) {
        string content = (i % 4 == 0) ? EVIL_CODE : "safe";
        auto file_bin = "file_" + to_string(i) + ".bin";
        ofstream(root / file_bin) << content;
    }

    REQUIRE(scanner.scanDirectory(root, 16) == true);

    filesystem::remove_all(root);
}
