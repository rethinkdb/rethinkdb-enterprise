// Copyright 2010-2016 RethinkDB, all rights reserved.
#ifndef CLUSTERING_ADMINISTRATION_LOGS_AUDIT_LOG_HPP_
#define CLUSTERING_ADMINISTRATION_LOGS_AUDIT_LOG_HPP_

#include <stdio.h>
#include <syslog.h>

#include <string>

#include "clustering/administration/logs/log_writer.hpp"
#include "concurrency/new_mutex.hpp"
#include "containers/uuid.hpp"

#include "logger.hpp"
#include "utils.hpp"

class audit_log_message_t {
public:
    audit_log_message_t() { }
    // TODO remove this hack
    explicit audit_log_message_t(std::string _message) : message(_message) { }
    audit_log_message_t(struct timespec _timestamp,
                        log_level_t _level,
                         uuid_u _connection_id,
                        uuid_u _query_id,
                        std::string _message) :
        timestamp(_timestamp),
        level(_level),
        connection_id(_connection_id),
        query_id(_query_id),
        message(_message) { }
    struct timespec timestamp;
    log_level_t level;
    uuid_u connection_id;
    uuid_u query_id;
    std::string message;
};

RDB_DECLARE_SERIALIZABLE(audit_log_message_t);

// Handles output to a file, syslog, or other output target.
// Should also handle locking for non thread-safe resources used for output.

class audit_log_output_target_t {
public:
    audit_log_output_target_t() { }

    virtual ~audit_log_output_target_t() { }

    // Maybe I can't actually generalize the locking behavior, we'll see
    virtual void write_internal(const audit_log_message_t &msg, std::string *err_msg, bool *ok) = 0;
    virtual void write(const audit_log_message_t &msg) = 0;
protected:
    new_mutex_t write_mutex;
};

class syslog_output_target_t : public audit_log_output_target_t {
public:
    syslog_output_target_t() : audit_log_output_target_t() {
        openlog("rethinkdb", LOG_PID, 0);
    }

    ~syslog_output_target_t() {
        closelog();
    }

    void write(const audit_log_message_t &msg) final;
    void write_internal(const audit_log_message_t &msg, std::string *, bool *ok) final {
        int priority_level = 0;
        switch (msg.level) {
        case log_level_info:
            priority_level = LOG_INFO;
            break;
        case log_level_notice:
            priority_level = LOG_NOTICE;
            break;
        case log_level_debug:
            priority_level = LOG_DEBUG;
            break;
        case log_level_warn:
            priority_level = LOG_WARNING;
            break;
        case log_level_error:
            priority_level = LOG_ERR;
            break;
        default:
            unreachable();
        }
        // TODO: Does this need anything else?
        syslog(priority_level, "%s", msg.message.c_str());
        *ok = true;
    }
};

void audit_log_internal(log_level_t level, const char *format, ...)
    ATTR_FORMAT(printf, 2, 3);

class thread_pool_audit_log_writer_t : public home_thread_mixin_t {
public:
    thread_pool_audit_log_writer_t();
    ~thread_pool_audit_log_writer_t();

    void write(const audit_log_message_t &msg);

private:
    void install_on_thread(int i);
    void uninstall_on_thread(int i);

    syslog_output_target_t syslog_target;
    DISABLE_COPYING(thread_pool_audit_log_writer_t);
};

#endif //CLUSTERING_ADMINISTRATION_LOGS_AUDIT_LOG_HPP_
