// Copyright 2010-2016 RethinkDB, all rights reserved.
#ifndef CLUSTERING_ADMINISTRATION_LOGS_AUDIT_LOG_HPP_
#define CLUSTERING_ADMINISTRATION_LOGS_AUDIT_LOG_HPP_

#include <stdio.h>

#include <string>

#include "arch/io/disk.hpp"
#include "clustering/administration/logs/log_writer.hpp"
#include "clustering/administration/issues/log_write.hpp"
#include "concurrency/new_mutex.hpp"
#include "concurrency/cross_thread_auto_drainer.hpp"
#include "containers/counted.hpp"
#include "containers/uuid.hpp"

#include "logger.hpp"
#include "time.hpp"
#include "utils.hpp"

const size_t AUDIT_MESSAGE_QUEUE_MESSAGE_LIMIT = 512;
const size_t AUDIT_MESSAGE_QUEUE_SIZE_LIMIT = 256 * MEGABYTE;

void install_logfile_output_target(const std::string &dirpath,
                                   const std::string &filename,
                                   const std::string &config_filename);

class audit_log_message_t : public slow_atomic_countable_t<audit_log_message_t> {
private:
    // This is initialized once at program start when there is only one thread.
    static struct timespec _uptime_reference;
public:
    audit_log_message_t(log_level_t _level,
                        log_type_t _type,
                        std::string _message) :
        timestamp(clock_realtime()),
        uptime(subtract_timespecs(clock_monotonic(), _uptime_reference)),
        type(_type),
        level(_level),
        message(std::move(_message)) { }

    static void set_uptime_reference() {
        _uptime_reference = clock_monotonic();
    }
    timespec timestamp;
    timespec uptime;

    log_type_t type;
    log_level_t level;
    // The `const` here is important for correctness.
    // In the pre-GCC 5.0 ABI, std::string was COW which would break
    // the logging code. Having this field `const` avoids copies when
    // calling certain operations on the string, such as `message.back()`.
    const std::string message;
};

// Handles output to a file, syslog, or other output target.
// Should also handle locking for non thread-safe resources used for output.

class audit_log_output_target_t : public home_thread_mixin_t {
public:
    friend class thread_pool_audit_log_writer_t;
    audit_log_output_target_t(bool _respects_enabled_flag, int _min_severity) :
        min_severity(_min_severity),
        respects_enabled_flag(_respects_enabled_flag),
        queue_size(0),
        write_pump([&] (signal_t*) {flush();}) { }

    virtual ~audit_log_output_target_t() { }

    virtual bool write_internal(std::vector<counted_t<audit_log_message_t> > *local_queue,
                                std::string *error_message) = 0;

    void emplace_message(counted_t<audit_log_message_t> msg, bool ignore_capacity);

protected:
    int min_severity;

    const bool respects_enabled_flag;
private:
    void flush();

    std::vector<log_type_t> tags;

    spinlock_t queue_mutex;

    std::vector<counted_t<audit_log_message_t> > queue;
    size_t queue_size;
    pump_coro_t write_pump;

    cross_thread_auto_drainer_t drainer;
};

class file_output_target_t : public audit_log_output_target_t {
public:
    static std::string logfilename;
    static std::string dirpath;
    explicit file_output_target_t(bool _respects_enabled_flag,
                                  int _min_severity,
                                  std::string _filename,
                                  bool _is_logfile);

    ~file_output_target_t() final { }

    bool install();

    bool write_internal(std::vector<counted_t<audit_log_message_t> > *local_queue,
                        std::string *error_out) final;
private:
    base_path_t filename;
    scoped_fd_t fd;
    bool is_logfile;
};

class syslog_output_target_t : public audit_log_output_target_t {
public:
    syslog_output_target_t(bool _respects_enabled_flag, int _min_severity);

    ~syslog_output_target_t();

private:
    bool write_internal(std::vector<counted_t<audit_log_message_t> > *local_queue,
                        std::string *error_out) final;
#ifdef _WIN32
	HANDLE hEventLog;
#endif
};

class console_output_target_t : public audit_log_output_target_t {
public:
    explicit console_output_target_t(int _min_severity) :
        audit_log_output_target_t( false, _min_severity) {
    }

    ~console_output_target_t() { }

    bool write_internal(std::vector<counted_t<audit_log_message_t> > *local_queue,
                        std::string *error_out) final;
};

void audit_log_internal(log_type_t type, log_level_t level, const char *format, ...)
    ATTR_FORMAT(printf, 3, 4);


class thread_pool_audit_log_writer_t : public home_thread_mixin_t {
public:
    static std::string config_file_path;
    explicit thread_pool_audit_log_writer_t(log_write_issue_tracker_t *log_tracker);
    ~thread_pool_audit_log_writer_t();

    static std::string format_audit_log_message(
        const counted_t<audit_log_message_t> &msg,
        bool for_console);
    void write(counted_t<audit_log_message_t> msg);

    bool enable_auditing() { return enable_auditing_; }

private:
    void install_on_thread(int i);
    void uninstall_on_thread(int i);

    base_path_t config_filename;

    std::vector<scoped_ptr_t<audit_log_output_target_t> > priority_routing;

    bool enable_auditing_;

    new_mutex_t write_mutex;
    cross_thread_auto_drainer_t drainer;
    DISABLE_COPYING(thread_pool_audit_log_writer_t);
};

#endif //CLUSTERING_ADMINISTRATION_LOGS_AUDIT_LOG_HPP_
