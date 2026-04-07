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
#include <vector>
#include <future>
#include <chrono>
#include <fstream>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <string_view>
#include <condition_variable>

#include "engine/Scanner.hpp"

// ===========================================================================
// MARK: - Macros
// ===========================================================================

#define MALICIOUS_SIGNATURES {"EVIL_CODE"}
#define BATCH_SIZE 20

using namespace std;


// ===========================================================================
// MARK: - Engine Business Logic
// ===========================================================================

namespace sentinel::engine {
 
ScanResult Scanner::scanFile(const filesystem::path& path, const vector<string>& targets) const {
    ScanResult result;
    ifstream file(path, ios::binary);
 
    if (!file.is_open()) return result;
 
    size_t max_signature_length = 0;
 
    for (const auto& signature : targets) {
        max_signature_length = max(max_signature_length, signature.length());
    }
 
    if (max_signature_length == 0) return result;
 
    const size_t overlap_length = max_signature_length - 1;
 
    vector<char> buffer(overlap_length + BUFFER_SIZE);
    size_t bytes_in_overlap = 0;
 
    while (true) {
        file.read(buffer.data() + bytes_in_overlap, BUFFER_SIZE);
        size_t bytes_read = file.gcount();
 
        if (bytes_read == 0 && bytes_in_overlap == 0) break;
 
        string_view currentWindow(buffer.data(), bytes_in_overlap + bytes_read);
 
        for (const auto& signature : targets) {
            if (currentWindow.find(signature) != string_view::npos) {
                result.found_malicious = true;
 
                if (find(result.signatures.begin(), result.signatures.end(), signature) == result.signatures.end()) {
                    result.signatures.push_back(signature);
                }
            }
        }
 
        if (file.eof() && bytes_read == 0) break;
 
        size_t total_data = bytes_in_overlap + bytes_read;
 
        if (total_data >= overlap_length) {
            memmove(buffer.data(), buffer.data() + total_data - overlap_length, overlap_length);
            bytes_in_overlap = overlap_length;
        } else {
            bytes_in_overlap = total_data;
        }
 
        if (file.eof()) break;
    }
 
    return result;
}

bool Scanner::scanDirectory(
    const filesystem::path& dirPath,
    const vector<string>& signatures,
    size_t threadCount) const
{
    if (!filesystem::exists(dirPath) || !filesystem::is_directory(dirPath)) return false;

    if (signatures.empty()) return false;
 
    vector<filesystem::path> files;
 
    for (const auto& entry : filesystem::recursive_directory_iterator(dirPath)) {
        if (entry.is_regular_file())
            files.push_back(entry.path());
    }
 
    if (files.empty()) return false;
 
    sort(files.begin(), files.end());
    
    queue<vector<filesystem::path>> task_queue;
    const size_t batch_size = 50;
 
    for (size_t i = 0; i < files.size(); i += batch_size) {
        auto last = min(files.size(), i + batch_size);
        task_queue.emplace(files.begin() + i, files.begin() + last);
    }
 
    atomic<bool> is_detected{false};
    mutex queue_mutex;
    vector<thread> workers;
 
    size_t actual_threads = (threadCount > 0) ? threadCount : thread::hardware_concurrency();
 
    for (size_t i = 0; i < actual_threads; ++i) {
        workers.emplace_back([&]() {
            while (true) {
                if (is_detected.load(memory_order_relaxed)) return;
 
                vector<filesystem::path> current_batch;
                {
                    lock_guard<mutex> lock(queue_mutex);
                    if (task_queue.empty()) return;
 
                    current_batch = std::move(task_queue.front());
                    task_queue.pop();
                }
 
                for (const auto& file : current_batch) {
                    if (is_detected.load(memory_order_relaxed)) return;
 
                    if (scanFile(file, signatures).found_malicious) {
                        is_detected.store(true, memory_order_release);
                        return;
                    }
                }
            }
        });
    }
 
    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }
 
    return is_detected.load(memory_order_acquire);
}
 
} // namespace sentinel::engine



// ============================================================================================================================

// const _Path & path() const noexcept;

// Why not to use Batch Processing or just Thread Pool?
// - for the pure Batch Processing we can get Load Imbalance with imbalanced workload on each thread.
// - Thread-Pool uses Producer-Consumer pattern, we create a queue with tasks and available workers (threads) pick up the workitems for processing. All CPU cores are loaded evenly.
// Where to use a pure Batch Processing? - for tiny files a pure Thread Pool might be overkill. Additional check-ups for task creation and queue synchronization can ease down the performance of the file scan.

// Hence: I use both. Group batches first and then delegate them to the Thread Pool.

// To limit number of threads used in the processing use `std::thread::hardware_concurrency()`

// **Optimization trick: Zero-Allocation Buffer**
// instead of append(...) of strings, we will:
// - 1. allocate a buffer with the size: BUFFER_SIZE + MAX_SIGNATURE_LENGTH
// - 2. leave some space for the tail chunk of the previous chunk
// - 3. read new values right after the tail

// std::memmove -> guarantees correct copying even if the source and destination overlap

// std::memcpy => naïve approach of moving each byte (byte by byte). in case of overlapping => overrides the data that it was not able to copy beforehand, i.e. returns Undefined Behavior. Faster.

// std::memmove - checks where a target address is relative to the source address. if they overlap, it will automaticaly start copying from the end to the beginning in order to avoid data overriding. More reliable.

// ============================================================================================================================
