//
//  main.cpp
//  Sentinel-CPP
//
//  Created by Azizbek Asadov on 01.04.2026.
//

#include <string>
#include <fstream>
#include <vector>
#include <future>
#include <string_view>
#include "engine/Scanner.hpp"

using namespace std;

namespace sentinel::engine {

#define MALICIOUS_SIGNATURES {"EVIL_CODE"}
    
ScanResult Scanner::scanFile(const filesystem::path& path, const vector<std::string>& targets) const {
    ScanResult result;
    
    // check if the file exists at the provided destination
    if (!filesystem::exists(path))
        return result;
    
    // check if the read could be read.
    ifstream file(path, ios::binary);
    if (!file.is_open())
        return result;
    
    // 64Kb buffer
    char buffer[BUFFER_SIZE];
    
    // reading the contents of the file
    while(file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        string_view chunk(buffer, file.gcount());
        
        for (const auto &signature : targets) {
            if (chunk.find(signature) != string_view::npos) {
                result.found_malicious = true;
                result.signatures.push_back(signature);
            }
        }
    }
    
    return result;
}

bool Scanner::scanDirectory(const filesystem::path &dirPath, size_t threadCount) const {
    if (!filesystem::exists(dirPath) || !filesystem::is_directory(dirPath)) {
        return false;
    }
    
    vector<filesystem::path> files;
    for (const auto &entry : filesystem::recursive_directory_iterator(dirPath)) {
        if (entry.is_regular_file())
            files.push_back(entry.path());
    }
    
    vector<future<ScanResult>> futures;
    vector<string> signatures = MALICIOUS_SIGNATURES;
    
    for (const auto &filePath : files) {
        // scanning each file async
        futures.push_back(async(launch::async, &Scanner::scanFile, this, filePath, signatures));
    }
    
    bool is_detected = false;
    
    for(auto &future : futures) {
        if (future.get().found_malicious)
            is_detected = true;
    }
    
    return is_detected;
}

}

// const _Path & path() const noexcept;

// Why not to use Batch Processing or just Thread Pool?
// - for the pure Batch Processing we can get Load Imbalance with imbalanced workload on each thread.
// - Thread-Pool uses Producer-Consumer pattern, we create a queue with tasks and available workers (threads) pick up the workitems for processing. All CPU cores are loaded evenly.
// Where to use a pure Batch Processing? - for tiny files a pure Thread Pool might be overkill. Additional check-ups for task creation and queue synchronization can ease down the performance of the file scan.

// Hence: I use both. Group batches first and then delegate them to the Thread Pool.
