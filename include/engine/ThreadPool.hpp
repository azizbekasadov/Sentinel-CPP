//
//  ThreadPool.hpp
//  Sentinel-CPP
//
//  Created by Azizbek Asadov on 07.04.2026.
//

#ifndef ThreadPool_h
#define ThreadPool_h

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

namespace sentinel::engine {

class ThreadPool {
public:
    explicit ThreadPool(size_t threadCount);
    ~ThreadPool();

    void enqueue(function<void()> task);
    void waitAll();

private:
    vector<thread> workers_;
    queue<function<void()>> tasks_;
    mutex mutex_;
    condition_variable cv_;
    atomic<bool> stop_{false};
};

}

#endif /* ThreadPool_h */
