#include "ThreadPool.h"

ThreadPool::ThreadPool(size_t numThreads) : stop_(false) {
    for (size_t i = 0; i < numThreads; ++i)
        workers_.emplace_back(&ThreadPool::worker, this);
}

ThreadPool::~ThreadPool() {
    stop_.store(true);
    condition_.notify_all();
    for (std::thread &worker: workers_)
        if (worker.joinable())
            worker.join();
}

void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        tasks_.emplace(task);
    }
    condition_.notify_one();
}

void ThreadPool::worker() {
    while (!stop_.load()) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            condition_.wait(lock, [this] { return stop_.load() || !tasks_.empty(); });
            if (stop_.load() && tasks_.empty())
                return;
            task = std::move(tasks_.front());
            tasks_.pop();
        }
        task();
    }
}