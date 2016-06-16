// Copyright 2010-2016 RethinkDB, all rights reserved.
#include "concurrency/cross_thread_auto_drainer.hpp"

#include "arch/runtime/runtime.hpp"

cross_thread_auto_drainer_t::cross_thread_auto_drainer_t() :
	draining(false),
	refcount(1) { }

cross_thread_auto_drainer_t::~cross_thread_auto_drainer_t() {
    if (!draining) {
        drain();
    }
    // TODO
    guarantee(refcount == 0);
}

cross_thread_auto_drainer_t::lock_t::lock_t() : parent(nullptr) {
}

cross_thread_auto_drainer_t::lock_t::lock_t(cross_thread_auto_drainer_t *p)
    : parent(p) {
    guarantee(parent != nullptr);
    // TODO guarantee not draining
    parent->incref();
}

cross_thread_auto_drainer_t::lock_t::lock_t(const lock_t &l) : parent(l.parent) {
    if (parent) parent->incref();
}

cross_thread_auto_drainer_t::lock_t &
cross_thread_auto_drainer_t::lock_t::operator=(const lock_t &l) {
    if (l.parent) l.parent->incref();
    if (parent) parent->decref();
    parent = l.parent;
    return *this;
}

cross_thread_auto_drainer_t::lock_t::lock_t(lock_t &&l) : parent(l.parent) {
    l.parent = nullptr;
}

cross_thread_auto_drainer_t::lock_t &
cross_thread_auto_drainer_t::lock_t::operator=(lock_t &&l) {
    lock_t tmp(std::move(l));
    std::swap(parent, tmp.parent);
    return *this;
}

cross_thread_auto_drainer_t::lock_t cross_thread_auto_drainer_t::lock() {
    return cross_thread_auto_drainer_t::lock_t(this);
}

void cross_thread_auto_drainer_t::lock_t::reset() {
    if (parent) parent->decref();
    parent = nullptr;
}

cross_thread_auto_drainer_t::lock_t::~lock_t() {
    if (parent) parent->decref();
}

void cross_thread_auto_drainer_t::drain() {
    draining = true;
    decref();
    call_on_thread(home_thread(),
                   [&] () {
                       drained.wait_lazily_unordered();
                   });
}

void cross_thread_auto_drainer_t::incref() {
    ++refcount;
}

void cross_thread_auto_drainer_t::decref() {
    --refcount;
    if (refcount == 0) {
        call_on_thread(home_thread(),
                       [&] () {
                           drained.pulse();
                       });
    }
}
