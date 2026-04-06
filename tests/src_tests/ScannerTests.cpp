//
//  ScannerTests.cpp
//  unit_tests
//
//  Created by Azizbek Asadov on 06.04.2026.
//

#include <catch2/catch_test_macros.hpp>
#include <fstream>

#include "engine/Scanner.hpp"

using namespace sentinel::engine;
using namespace std;

// MARK: - Helpers

filesystem::path makeNonExistingPath() {
    return "/tmp/definitely_not_exists_2edqw";
}

filesystem::path makeTestFile() {
    return "test_target.text";
}

filesystem::path makeTestDir() {
    return "test_dir";
}

filesystem::path makeBadFile() {
    return "bad_file.bin";
}

filesystem::path makeTempDirectory() {
    return filesystem::temp_directory_path();
}

filesystem::path makeInnerFolder() {
    return "inner_folder";
}

filesystem::path createTestDirectory(const filesystem::path tempFile) {
    filesystem::path root = makeTempDirectory() / makeTestDir();
    filesystem::path subDir = root / tempFile;
    filesystem::create_directories(subDir);
    
    return root;
}

// MARK: - Test Cases for `Scanner`

// Test: Scanning for any malicious signatures in the file
TEST_CASE("Scanner detects malicious signatures", "[scanner]") {
    Scanner scanner;
    filesystem::path testFile = makeTestFile();
    
    SECTION("Positive case: signature found") {
        ofstream(testFile) << "some data and BAD_SIGNATURE found here" << endl;
        
        auto result = scanner.scanFile(testFile, { "BAD_SIGNATURE" });
        
        REQUIRE(result.found_malicious == true);
        REQUIRE(!result.signatures.empty());
        
        filesystem::remove(testFile);
    }
}

// Test: Scanning for any malicious signatures in the directory
TEST_CASE("Scanner handles directory recursion", "[scanner][filesystem]") {
    Scanner scanner;
    filesystem::path root = makeTempDirectory() / makeTestDir();
    filesystem::path subDir = root / makeInnerFolder();
    filesystem::create_directories(subDir);
    
    SECTION("Detects thread in the provided sub-folder") {
        ofstream(subDir / makeBadFile()) << "prelude EVIL_CODE suffix";
        
        // injecting path to the root to allow scanner to detect file in the sub-folder
        bool is_found = scanner.scanDirectory(root);
        
        REQUIRE(is_found);
    }
    
    filesystem::remove_all(root);
}

// Test: scanning for edge cases while scanning for malicious files in the provided temp dir
TEST_CASE("Scanner Edge Cases", "[scanner][robustness]") {
    Scanner scanner;
    
    filesystem::path temp_dir = "edge_cases";
    filesystem::path root = makeTempDirectory() / temp_dir;
    filesystem::create_directories(root);
    
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
        ofstream(root / malware_filename) << "EVIL_CODE";
        
        REQUIRE(scanner.scanDirectory(root) == true);
    }
    
    SECTION("Non-existent path handling") {
        REQUIRE_FALSE(scanner.scanDirectory(makeNonExistingPath()));
    }
    
    filesystem::remove_all(root);
}
