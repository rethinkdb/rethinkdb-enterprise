// Copyright 2010-2016 RethinkDB, all rights reserved.
#ifndef CONCURRENCY_CROSS_THREAD_AUTO_DRAINER_HPP_
#define CONCURRENCY_CROSS_THREAD_AUTO_DRAINER_HPP_

#include <atomic>

#include "concurrency/cond_var.hpp"
#include "threading.hpp"

class cross_thread_auto_drainer_t : public home_thread_mixin_t {
public:
    cross_thread_auto_drainer_t();
    ~cross_thread_auto_drainer_t();

    class lock_t {
    public:
        lock_t();
        ~lock_t();
        explicit lock_t(cross_thread_auto_drainer_t *);
        lock_t(const lock_t &);
        lock_t &operator=(const lock_t &);
        lock_t(lock_t &&);
        lock_t &operator=(lock_t &&);

        void reset();
    private:
        cross_thread_auto_drainer_t *parent;
    };

    lock_t lock();

    void drain();
private:
    void incref();
    void decref();

    std::atomic_bool draining;
    std::atomic_int refcount;
    cond_t drained;
};

#endif // CONCURRENCY_CROSS_THREAD_AUTO_DRAINER_HPP_
