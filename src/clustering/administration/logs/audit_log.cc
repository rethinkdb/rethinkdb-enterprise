//Copyright RethinkDB 2010-2016, all rights reservec.

#include "clustering/administration/logs/audit_log.hpp"

#include "errors.hpp"
#include <boost/bind.hpp>

#include "arch/runtime/thread_pool.hpp"
#include "clustering/administration/logs/log_writer.hpp"
#import "thread_local.hpp"


thread_pool_audit_log_writer_t::thread_pool_audit_log_writer_t() {
    pmap(
        get_num_threads(),
        boost::bind(&thread_pool_audit_log_writer_t::install_on_thread, this, _1));
}
thread_pool_audit_log_writer_t::~thread_pool_audit_log_writer_t() {
    pmap(
        get_num_threads(),
        boost::bind(&thread_pool_audit_log_writer_t::uninstall_on_thread, this, _1));
}

TLS_with_init(thread_pool_audit_log_writer_t *, global_audit_log_writer, nullptr);
TLS_with_init(auto_drainer_t *, global_audit_log_drainer, nullptr);
TLS_with_init(int, audit_log_writer_block, 0);

void thread_pool_audit_log_writer_t::install_on_thread(int i) {
    on_thread_t thread_switcher((threadnum_t(i)));
    guarantee(TLS_get_global_audit_log_writer() == nullptr);
    TLS_set_global_audit_log_drainer(new auto_drainer_t);
    TLS_set_global_audit_log_writer(this);
}

void thread_pool_audit_log_writer_t::uninstall_on_thread(int i) {
    on_thread_t thread_switcher((threadnum_t(i)));
    guarantee(TLS_get_global_audit_log_writer() == this);
    TLS_set_global_audit_log_writer(nullptr);
    delete TLS_get_global_audit_log_drainer();
    TLS_set_global_audit_log_drainer(nullptr);
}

void thread_pool_audit_log_writer_t::write(const audit_log_message_t &msg) {
    // TODO: read configuration and routing and filtering information and route logs.

    // ALSO TODO: implement those things so we can read them.
    syslog_target.write(msg);
}

void audit_log_coro(thread_pool_audit_log_writer_t *writer,
                    log_level_t,
                    const std::string &message,
                    auto_drainer_t::lock_t) {
    on_thread_t thread_switcher(writer->home_thread());

    // TODO: actually properly construct these writers
    audit_log_message_t log_msg = audit_log_message_t(message);
    log_msg.level = log_level_info;
    writer->write(log_msg);
}

void vaudit_log_internal(log_level_t level, const char *format, va_list args) {
    thread_pool_audit_log_writer_t *writer;
    writer = TLS_get_global_audit_log_writer();
    int writer_block = TLS_get_audit_log_writer_block();
    if (writer != nullptr && writer_block == 0) {
        auto_drainer_t::lock_t lock(TLS_get_global_audit_log_drainer());
        std::string message = vstrprintf(format, args);
        coro_t::spawn_sometime(
            boost::bind(
                &audit_log_coro,
                writer,
                level,
                message,
                lock));
    } else {
        // TODO: change this to something that actually solves the problem,
        // or at least fails properly.
        fprintf(stderr, "global audit writer not ready for some freaking reason.\n");
    }
}

void audit_log_internal(log_level_t level, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vaudit_log_internal(level, format, args);
    va_end(args);
}

void syslog_output_target_t::write(const audit_log_message_t &msg) {
    std::string error_message;
    bool ok;
    thread_pool_t::run_in_blocker_pool(
        boost::bind(
            &syslog_output_target_t::write_internal,
            this,
            msg,
            &error_message,
            &ok));

    //TODO proper error reporting
    if (ok) {
        fprintf(stderr, "Audit log message ok\n");
    } else {
        fprintf(stderr, "Audit log message FAILED\n");
    }
}
