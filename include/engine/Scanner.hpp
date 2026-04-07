//
//  Scanner.hpp
//  Sentinel-CPP
//
//  Created by Azizbek Asadov on 05.04.2026.
//

#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <string>
#include <filesystem>
#include <vector>

#define BUFFER_SIZE 65536

using namespace std;

namespace sentinel::engine {

// ===========================================================================
// MARK: - ScanResult - result logging
// ===========================================================================

struct ScanResult {
    bool found_malicious { false };
    vector<string> signatures;
};

// ===========================================================================
// MARK: - Scanner
// ===========================================================================


class Scanner {
public:
    Scanner() = default;
    ~Scanner() = default;
    
    ScanResult scanFile(const filesystem::path &path, const vector<string> &targets) const;
    
    bool scanDirectory(
        const filesystem::path& dirPath,
        const vector<string>& signatures,
        size_t threadCount = 0
    ) const;

};

}

#endif
