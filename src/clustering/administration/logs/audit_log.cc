//Copyright RethinkDB 2010-2016, all rights reservec.

#include "clustering/administration/logs/audit_log.hpp"

#include "errors.hpp"
#include <boost/bind.hpp>

#include "arch/runtime/thread_pool.hpp"
#include "clustering/administration/logs/log_writer.hpp"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/filereadstream.h"
#include "thread_local.hpp"

// Setup type routing
std::map<std::string, log_type_t> string_to_type{
    {"log", log_type_t::log},
    {"data", log_type_t::data},
    {"blarg", log_type_t::blarg},
    {"blah", log_type_t::blah}};

thread_pool_audit_log_writer_t::thread_pool_audit_log_writer_t() :
    config_filename("audit_config.json") {

    config_filename.make_absolute();

    char readBuffer[65536];
    FILE *fp = fopen(config_filename.path().c_str(), "r");
    rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));

    rapidjson::Document d;

    if (d.ParseStream(is).HasParseError()) {
        fprintf(stderr, "\nAudit Config file Error(offset %u): %s\n", 
                (unsigned)d.GetErrorOffset(),
                GetParseError_En(d.GetParseError()));
        fprintf(stderr, "Using default auditing configuration.\n");
    } else {
        // TODO, add a default for everything rapidjson reads,
        // and check things exist before reading them
        // TODO don't require files
        // Parse output file configuration from config file.
        guarantee(d["files"].IsArray());
        const rapidjson::Value& files = d["files"];
        for (rapidjson::SizeType i = 0; i < files.Size(); ++i) {
            guarantee(files[i]["filename"].IsString());

            counted_t<file_output_target_t> new_file = make_counted<file_output_target_t>(
                files[i]["filename"].GetString());

            int min_severity;
            if (files[i]["min_severity"].IsInt()) {
                min_severity = files[i]["min_severity"].GetInt();
            } else {
                min_severity = 0;
            }
            priority_routing.insert(
                std::pair<int, counted_t<audit_log_output_target_t> >(
                    min_severity,
                    new_file));

            // Setup type routing.
            if (files[i].HasMember("tags")) {
                const rapidjson::Value& tags = files[i]["tags"];
                if (tags.IsArray()) {
                    // Why would rapidjson use Begin rather than begin, cmon.
                    for (auto it = tags.Begin(); it != tags.End(); ++it) {
                        auto tag = string_to_type.find(it->GetString());
                        if (tag == string_to_type.end()) {
                            //TODO handle these errors better
                            fprintf(stderr,
                                    "Config Error: unknown tag %s\n",
                                    it->GetString());
                        } else {
                            new_file->tags.insert(tag->second);
                        }
                    }
                }
            }
            new_file->install();
            file_targets.push_back(std::move(new_file));
        }
    }

    // TODO don't require syslog
    if (d["syslog"].IsObject()) {
        int min_severity;
        if (d["syslog"]["min_severity"].IsInt()) {
            min_severity = d["syslog"]["min_severity"].GetInt();
        } else {
            min_severity = 0;
        }
        counted_t<syslog_output_target_t> syslog_target = make_counted<syslog_output_target_t>();
        priority_routing.insert(
            std::pair<int, counted_t<audit_log_output_target_t> >(
                min_severity,
                counted_t<audit_log_output_target_t>(syslog_target)));

        file_targets.push_back(std::move(syslog_target));
    }
    // TODO, actually do this

    fclose(fp);
    pmap(
        get_num_threads(),
        boost::bind(&thread_pool_audit_log_writer_t::install_on_thread, this, _1));
}
thread_pool_audit_log_writer_t::~thread_pool_audit_log_writer_t() {
    fprintf(stderr, "DESTRUCTOR CALLED");
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

std::string thread_pool_audit_log_writer_t::format_audit_log_message(
    const audit_log_message_t &msg) {
    // TODO: actual formatting depending on settings
    std::string msg_string;
    std::string prepend = strprintf("%s %s: ",
                                    format_time(msg.timestamp, local_or_utc_time_t::utc).c_str(),
                                    format_log_level(msg.level).c_str());
    msg_string = strprintf("%s%s",
                           prepend.c_str(),
                           msg.message.c_str());

    return msg_string;
}

void thread_pool_audit_log_writer_t::write(const audit_log_message_t &msg) {
    new_mutex_acq_t blah(&write_mutex);
    // TODO: read configuration and routing and filtering information and route logs.
    fprintf(stderr, "Writing a log message with priority %d\n", msg.level);
    // Select targets by configured severity level
    for (auto it = priority_routing.begin();
         it != priority_routing.upper_bound(static_cast<int>(msg.level));
         ++it) {
        // TODO: make sure this logic works
        guarantee(it != priority_routing.end());

        if (static_cast<int>(msg.type) == 3) {
            fprintf(stderr, "3");
        }
        
        fprintf(stderr, "Writing a log message with tag %d\n", msg.type);
        //if (it->second->tags.find(msg.type) != it->second->tags.end()) {
        it->second->write(msg);
            //}
    }
}

void audit_log_coro(thread_pool_audit_log_writer_t *writer,
                    log_type_t type,
                    log_level_t level,
                    const std::string &message,
                    auto_drainer_t::lock_t) {
    on_thread_t thread_switcher(writer->home_thread());
    auto_drainer_t::lock_t lock(TLS_get_global_audit_log_drainer());
    // TODO: actually properly construct these writers
    audit_log_message_t log_msg = audit_log_message_t(message);
    log_msg.type = type;
    log_msg.level = level;
    writer->write(log_msg);
}

void vaudit_log_internal(log_type_t type, log_level_t level, const char *format, va_list args) {
    thread_pool_audit_log_writer_t *writer;
    writer = TLS_get_global_audit_log_writer();
    int writer_block = TLS_get_audit_log_writer_block();
    if (writer != nullptr && writer_block == 0) {
        auto_drainer_t::lock_t lock(TLS_get_global_audit_log_drainer());
        std::string message = vstrprintf(format, args);
        fprintf(stderr, "Spawn sometime!\n");
        coro_t::spawn_sometime(
            boost::bind(
                &audit_log_coro,
                writer,
                type,
                level,
                message,
                lock));
    } else {
        // TODO: change this to something that actually solves the problem,
        // or at least fails properly.
        fprintf(stderr, "global audit writer not ready for some freaking reason.\n");
    }
}

void audit_log_internal(log_type_t type, log_level_t level, const char *format, ...) {
    fprintf(stderr, "Is this doesn't print, I guess fprintf is delayed\n");
    va_list args;
    va_start(args, format);
    vaudit_log_internal(type, level, format, args);
    va_end(args);
}


void file_output_target_t::write_internal(const audit_log_message_t &msg, std::string *error_out, bool *ok_out) {
    FILE* write_stream = nullptr;
    int fileno = -1;
    int priority_level = 0;

    if (fd.get() == INVALID_FD) {
        error_out->assign("cannot open or find log file");
        *ok_out = false;
        return;
    }

    std::string msg_str = thread_pool_audit_log_writer_t::format_audit_log_message(msg);
    ssize_t write_res = ::write(fd.get(), msg_str.data(), msg_str.length());
    if (write_res != static_cast<ssize_t>(msg_str.length())) {
        error_out->assign("Cannot write to log file: " + errno_string(get_errno()));
        *ok_out = false;
        return;
    }

    fprintf(stderr, "Successfully wrote to file \n");
    *ok_out = true;
    return;
}

void syslog_output_target_t::write_internal(const audit_log_message_t &msg, std::string *, bool *ok_out) {
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
    case log_level_critical:
        priority_level = LOG_CRIT;
        break;
    case log_level_alert:
        priority_level = LOG_ALERT;
        break;
    case log_level_emergency:
        priority_level = LOG_EMERG;
        break;
    default:
        unreachable();
    }
    // TODO: Does this need anything else?
    //    syslog(priority_level, "%s",
    //        thread_pool_audit_log_writer_t::format_audit_log_message(msg).c_str());
    *ok_out = true;
}

void syslog_output_target_t::write(const audit_log_message_t &msg) {
    new_mutex_acq_t write_acq(&write_mutex);
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
        fprintf(stderr, "Audit syslog log message ok\n");
    } else {
        fprintf(stderr, "Audit syslog log message FAILED\n");
    }
}

void file_output_target_t::write(const audit_log_message_t &msg) {
    // Lock for file access
    new_mutex_acq_t write_acq(&write_mutex);
    std::string error_message;
    bool ok;
    thread_pool_t::run_in_blocker_pool(
        boost::bind(
            &file_output_target_t::write_internal,
            this,
            msg,
            &error_message,
            &ok));

    //TODO proper error reporting
    if (ok) {
        fprintf(stderr, "Audit file log message ok\n");
    } else {
        fprintf(stderr, "Audit file log message FAILED\n");
    }
}
