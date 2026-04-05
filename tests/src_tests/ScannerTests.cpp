//
//  ScannerTests.cpp
//  unit_tests
//
//  Created by Azizbek Asadov on 06.04.2026.
//

#include "ScannerTests.hpp"

// MARK: - Helpers

const string anyFilePath() {
    return "./any_file.txt";
}

const string anyFileInvalidPath() {
    return ".z1~/q1.q12s1";
}

// MARK: - ScannerTests Test Suite

TEST_CASE("scanner checkFile(_:) should return false for invalid file names") {
    // given
    Scanner scanner;
    const string invalidFilePath = anyFileInvalidPath();
    
    // when
    bool res = scanner.checkFile(invalidFilePath);
    
    // then
    REQUIRE_FALSE(res);
}

