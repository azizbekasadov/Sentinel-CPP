//
//  main.cpp
//  Sentinel-CPP
//
//  Created by Azizbek Asadov on 01.04.2026.
//

#include <mutex>
#include <queue>
#include <thread>
#include <string>
#include <fstream>
#include <vector>
#include <future>
#include <string_view>
#include <condition_variable>
#include "engine/Scanner.hpp"

using namespace std;

namespace sentinel::engine {

#define MALICIOUS_SIGNATURES {"EVIL_CODE"}
#define BATCH_SIZE 20
    
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
    
    if (files.empty())
        return false;
    
    const size_t batch_size = BATCH_SIZE;
    queue<vector<filesystem::path>> task_queue;
    
    for (size_t i = 0; i < files.size(); i += batch_size) {
        auto last = min(files.size(), i + batch_size);
        task_queue.emplace(files.begin() + i, files.begin() + last);
    }
    
    atomic<bool> is_detected { false };
    mutex queue_mutex;
    vector<thread> workers;
    
    size_t actual_threads = (threadCount > 0) ? threadCount : thread::hardware_concurrency();
    const vector<string> signatures = MALICIOUS_SIGNATURES;
    
    for (size_t i = 0; i < actual_threads; ++i) {
        workers.emplace_back([&]()  {
            while (1) {
                vector<filesystem::path> current_batch;
                
                {
                    lock_guard<mutex> lock(queue_mutex);
                    
                    if (task_queue.empty()) return; // terminating
                    
                    current_batch = std::move(task_queue.front());
                    task_queue.pop();
                    
                    for (const auto &file : current_batch) {
                        if (is_detected.load()) return;
                        
                        if (scanFile(file, signatures).found_malicious) {
                            is_detected.store(true);
                            return;
                        }
                    }
                }
            }
        });
        
        // wait for workers completion
        for (auto &worker : workers) {
            if (worker.joinable())
                worker.join();
        }
        
        return is_detected.load();
    }
}

}

// const _Path & path() const noexcept;

// Why not to use Batch Processing or just Thread Pool?
// - for the pure Batch Processing we can get Load Imbalance with imbalanced workload on each thread.
// - Thread-Pool uses Producer-Consumer pattern, we create a queue with tasks and available workers (threads) pick up the workitems for processing. All CPU cores are loaded evenly.
// Where to use a pure Batch Processing? - for tiny files a pure Thread Pool might be overkill. Additional check-ups for task creation and queue synchronization can ease down the performance of the file scan.

// Hence: I use both. Group batches first and then delegate them to the Thread Pool.

// To limit number of threads used in the processing use `std::thread::hardware_concurrency()`
