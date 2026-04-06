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

struct ScanResult {
    bool found_malicious{false};
    vector<string> signatures;
};

class Scanner {
public:
    Scanner() = default;
    ~Scanner() = default;
    
    ScanResult scanFile(const filesystem::path &path, const vector<string> &targets) const;
    
    /// Used to return a boolean flag indicating whether the directory scanning has been done successfully or not.
    /// - Returns:
    ///     - false if the path does not exist, or if the path exists but not a directory.
    ///     - true if the scanning has been done successfully.
    [[nodiscard]] bool scanDirectory(const filesystem::path &dirPath, size_t threadCount = 4) const;
};

}

#endif
