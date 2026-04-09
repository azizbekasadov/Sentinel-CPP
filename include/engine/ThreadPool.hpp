#ifndef SENTINEL_ENGINE_THREAD_POOL_HPP
#define SENTINEL_ENGINE_THREAD_POOL_HPP

#include <condition_variable>
#include <cstddef>
#include <exception>
#include <functional>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace sentinel::engine {

class ThreadPool {
public:
    explicit ThreadPool(std::size_t thread_count) {
        if (thread_count == 0) {
            throw std::invalid_argument("ThreadPool requires at least one worker");
        }

        workers_.reserve(thread_count);
        for (std::size_t i = 0; i < thread_count; ++i) {
            workers_.emplace_back([this]() { workerLoop(); });
        }
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }

        cv_.notify_all();

        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

    void enqueue(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                throw std::runtime_error("cannot enqueue work on a stopping ThreadPool");
            }

            tasks_.push(std::move(task));
            ++pending_tasks_;
        }

        cv_.notify_one();
    }

    void waitAll() {
        std::unique_lock<std::mutex> lock(mutex_);
        idle_cv_.wait(lock, [this]() { return pending_tasks_ == 0; });

        if (worker_exception_) {
            std::rethrow_exception(worker_exception_);
        }
    }

private:
    void workerLoop() {
        while (true) {
            std::function<void()> task;

            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this]() { return stopping_ || !tasks_.empty(); });

                if (stopping_ && tasks_.empty()) {
                    return;
                }

                task = std::move(tasks_.front());
                tasks_.pop();
            }

            try {
                task();
            } catch (...) {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!worker_exception_) {
                    worker_exception_ = std::current_exception();
                }
            }

            {
                std::lock_guard<std::mutex> lock(mutex_);
                --pending_tasks_;
                if (pending_tasks_ == 0) {
                    idle_cv_.notify_all();
                }
            }
        }
    }

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::condition_variable idle_cv_;
    std::size_t pending_tasks_ {0};
    bool stopping_ {false};
    std::exception_ptr worker_exception_;
};

}  // namespace sentinel::engine

#endif
