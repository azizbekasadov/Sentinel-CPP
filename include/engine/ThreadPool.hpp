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
        try {
            for (std::size_t i = 0; i < thread_count; ++i) {
                workers_.emplace_back([this] { workerLoop(); });
            }
        } catch (...) {
            shutdown();
            throw;
        }
    }

    ~ThreadPool() {
        shutdown();
    }

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    void enqueue(std::function<void()> task) {
        {
            const std::scoped_lock lock(mutex_);
            if (stopping_) {
                throw std::runtime_error("cannot enqueue work on a stopping ThreadPool");
            }

            tasks_.push(std::move(task));
            ++pending_tasks_;
        }

        cv_.notify_one();
    }

    // Blocks until every enqueued task has finished. If any task threw, the first exception is
    // rethrown here and cleared so the pool can be reused.
    void waitAll() {
        std::unique_lock lock(mutex_);
        idle_cv_.wait(lock, [this] { return pending_tasks_ == 0; });

        if (worker_exception_) {
            std::rethrow_exception(std::exchange(worker_exception_, nullptr));
        }
    }

private:
    void shutdown() noexcept {
        {
            const std::scoped_lock lock(mutex_);
            stopping_ = true;
        }

        cv_.notify_all();

        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

    void workerLoop() {
        while (true) {
            std::function<void()> task;

            {
                std::unique_lock lock(mutex_);
                cv_.wait(lock, [this] { return stopping_ || !tasks_.empty(); });

                if (stopping_ && tasks_.empty()) {
                    return;
                }

                task = std::move(tasks_.front());
                tasks_.pop();
            }

            try {
                task();
            } catch (...) {
                const std::scoped_lock lock(mutex_);
                if (!worker_exception_) {
                    worker_exception_ = std::current_exception();
                }
            }

            {
                const std::scoped_lock lock(mutex_);
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
