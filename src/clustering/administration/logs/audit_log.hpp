// Copyright 2010-2016 RethinkDB, all rights reserved.
#ifndef CLUSTERING_ADMINISTRATION_LOGS_AUDIT_LOG_HPP_
#define CLUSTERING_ADMINISTRATION_LOGS_AUDIT_LOG_HPP_

#include <stdio.h>
#include <syslog.h>

#include <string>

#include "arch/io/disk.hpp"
#include "clustering/administration/logs/log_writer.hpp"
#include "concurrency/new_mutex.hpp"
#include "containers/uuid.hpp"

#include "logger.hpp"
#include "utils.hpp"

class audit_log_message_t {
public:
    audit_log_message_t() { }
    // TODO remove this hack
    explicit audit_log_message_t(std::string _message) :
        timestamp(clock_realtime()),
            message(_message)
    { }

    audit_log_message_t(log_level_t _level,
                        uuid_u _connection_id,
                        uuid_u _query_id,
                        std::string _message) :
        level(_level),
        connection_id(_connection_id),
        query_id(_query_id),
        message(_message) {
        timestamp = clock_realtime();
    }
    struct timespec timestamp;
    log_type_t type;
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
    virtual void write_internal(const audit_log_message_t &msg, std::string *err_msg, bool *ok_out) = 0;
    virtual void write(const audit_log_message_t &msg) = 0;
protected:
    new_mutex_t write_mutex;
};

class file_output_target_t : public audit_log_output_target_t {
public:
    file_output_target_t(std::string _filename) :
        audit_log_output_target_t(),
        filename(base_path_t(_filename)) { }

    void write(const audit_log_message_t &msg) final;

    void install() {
        int res;
        do {
            res = open(filename.path().c_str(), O_WRONLY|O_APPEND|O_CREAT, 0644);
        } while (res == INVALID_FD && get_errno() == EINTR);

        fd.reset(res);
        if (fd.get() == INVALID_FD) {
            throw std::runtime_error(strprintf("Failed to open log file '%s': %s",
                                               filename.path().c_str(),
                                               errno_string(errno).c_str()).c_str());
        }
        // Get the absolute path for the log file, so it will still be valid if
        //  the working directory changes
        filename.make_absolute();

        // For the case that the log file was newly created,
        // call fsync() on the parent directory to guarantee that its
        // directory entry is persisted to disk.
        int sync_res = fsync_parent_directory(filename.path().c_str());
        if (sync_res != 0) {
            char errno_str_buf[250];
            const char *errno_str = errno_string_maybe_using_buffer(sync_res,
                                                                    errno_str_buf, sizeof(errno_str_buf));
            logWRN("Parent directory of log file (%s) could not be synced. (%s)\n",
                   filename.path().c_str(), errno_str);
        }
    }

private:
    void write_internal(const audit_log_message_t &msg, std::string *err_msg, bool *ok_out) final;

    scoped_fd_t fd;
    base_path_t filename;
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
private:
    void write_internal(const audit_log_message_t &msg, std::string *, bool *ok_out) final;

};

void audit_log_internal(log_type_t type, log_level_t level, const char *format, ...)
    ATTR_FORMAT(printf, 3, 4);


class thread_pool_audit_log_writer_t : public home_thread_mixin_t {
public:
    thread_pool_audit_log_writer_t();
    ~thread_pool_audit_log_writer_t();

    static std::string format_audit_log_message(const audit_log_message_t &msg);
    void write(const audit_log_message_t &msg);

private:
    void install_on_thread(int i);
    void uninstall_on_thread(int i);

    syslog_output_target_t syslog_target;
    file_output_target_t file_target;
    file_output_target_t data_file_target;

    base_path_t config_filename;

    std::vector<file_output_target_t> file_targets;
    std::map<int, audit_log_output_source_t *> priority_routing;
    //TODO    std::map<std::string, audit_log_output_source_t *> text_routing;

    DISABLE_COPYING(thread_pool_audit_log_writer_t);
};

#endif //CLUSTERING_ADMINISTRATION_LOGS_AUDIT_LOG_HPP_
