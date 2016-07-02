//Copyright RethinkDB 2010-2016, all rights reservec.

#include "clustering/administration/logs/audit_log.hpp"

#ifdef _WIN32
// For Windows event log.
#include <io.h>
#include <evntprov.h>
#include <conio.h>
#include <Shlwapi.h>
#else
#include <syslog.h>
#endif

#include <sys/stat.h>

#include "errors.hpp"
#include <boost/bind.hpp>

#include "arch/runtime/thread_pool.hpp"
#include "clustering/administration/logs/log_writer.hpp"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/filereadstream.h"
#include "thread_local.hpp"

#ifdef _WIN32
#include "audit/RethinkDBAudit.h"
#endif

TLS_with_init(thread_pool_audit_log_writer_t *, global_audit_log_writer, nullptr);
TLS_with_init(auto_drainer_t *, global_audit_log_drainer, nullptr);

log_write_issue_tracker_t *log_write_issue_tracker;

std::string thread_pool_audit_log_writer_t::config_file_path;

struct timespec audit_log_message_t::_uptime_reference;
std::string file_output_target_t::logfilename;
std::string file_output_target_t::dirpath;

void report_success() {
    coro_t::spawn_on_thread([](){
            log_write_issue_tracker->report_success();
        }, log_write_issue_tracker->home_thread());
}


void report_error(std::string msg) {
    coro_t::spawn_on_thread([msg](){
            log_write_issue_tracker->report_error(msg);
        }, log_write_issue_tracker->home_thread());
}

void log_error_once(std::string msg) {
    fallback_log_message(log_level_t::log_level_error, msg);
}

// Allow specifiying direct file path for logs table logs.
file_output_target_t::file_output_target_t(bool _respects_enabled_flag, 
                                           int _min_severity, 
                                           std::string _filename, 
                                           bool _is_logfile) :
    audit_log_output_target_t(_respects_enabled_flag, _min_severity),
    is_logfile(_is_logfile) {
    guarantee(_filename != "");
    bool relative;
#ifdef _WIN32
    relative = PathIsRelative(_filename.c_str());
#else
    relative = (_filename[0] != '/');
#endif
    if (relative) {
        filename = base_path_t(dirpath + "/" + _filename);
    } else {
        filename = base_path_t(_filename);
    }
}

std::map<std::string, log_type_t> string_to_type {
    {"log", log_type_t::log},
    {"query", log_type_t::query},
    {"connection", log_type_t::connection},
    {"data", log_type_t::data}};

std::map<log_type_t, std::string> type_to_string {
    {log_type_t::log, "log"},
    {log_type_t::query, "query"},
    {log_type_t::connection, "connection"},
    {log_type_t::data, "data"}};

thread_pool_audit_log_writer_t::thread_pool_audit_log_writer_t(
    log_write_issue_tracker_t *log_tracker) :
    config_filename(config_file_path),
    enable_auditing_(true) {

    log_write_issue_tracker = log_tracker;

    pmap(
        get_num_threads(),
        boost::bind(&thread_pool_audit_log_writer_t::install_on_thread, this, _1));

    file_output_target_t *logfile =
        new file_output_target_t(false, 0, file_output_target_t::logfilename, true);
    logfile->install();
    // We only want this target to save logs.
    logfile->tags.push_back(log_type_t::log);

    priority_routing.push_back(scoped_ptr_t<audit_log_output_target_t>(logfile));

    console_output_target_t *console_target =
        new console_output_target_t(log_level_t::log_level_notice);
    priority_routing.push_back(scoped_ptr_t<audit_log_output_target_t>(console_target));

    // This is how rapidjson recommends doing this.
    char readBuffer[65536];
    FILE *fp = nullptr;
    if (config_file_path != "") {
        fp = fopen(config_filename.path().c_str(), "r");
    }
    rapidjson::Document d;

    if (fp != nullptr) {
        rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
        d.ParseStream(is);
    } else {
        enable_auditing_ = false;
    }

    if (d.HasParseError()) {
        logERR("\nAudit Config file Error(offset %u): %s\n",
               static_cast<unsigned>(d.GetErrorOffset()),
               GetParseError_En(d.GetParseError()));
        logERR("Audit logging will be DISABLED.\n");

        enable_auditing_ = false;
    } else if (enable_auditing_ &&
               d.HasMember("enable_auditing") && d["enable_auditing"].GetBool() == false) {
        // Auditing config is otherwise correct, but has disabled auditing.
        enable_auditing_ = false;
    } else if (enable_auditing_) {
        // Set up file and syslog targets for audit log.
        if (d.HasMember("files") && d["files"].IsArray()) {
            const rapidjson::Value &files = d["files"];
            for (rapidjson::SizeType i = 0; i < files.Size(); ++i) {
                guarantee(files[i]["filename"].IsString());

                std::string newfilename = files[i].GetString();
                if (newfilename.length() == 0) {
                    logWRN("Auditing configuration error: invalid filename.\n");
                    enable_auditing_ = false;
                    break;
                }
                int new_min_severity = 0;
                if (files[i]["min_severity"].IsInt()) {
                    new_min_severity = files[i]["min_severity"].GetInt();
                }
                file_output_target_t *new_file =
                    new file_output_target_t(
                        true,
                        new_min_severity,
                        files[i]["filename"].GetString(),
                        false);

                // Setup type routing.
                if (files[i].HasMember("tags")) {
                    const rapidjson::Value &tags = files[i]["tags"];
                    if (tags.IsArray()) {
                        // Why would rapidjson use Begin rather than begin, cmon.
                        for (auto it = tags.Begin(); it != tags.End(); ++it) {
                            auto tag = string_to_type.find(it->GetString());
                            if (tag == string_to_type.end()) {
                                logWRN("Auditing configuration error: unknown tag %s\n",
                                       it->GetString());
                            } else {
                                new_file->tags.push_back(tag->second);
                            }
                        }
                    }
                }
                // Setup file output for this file.
                bool install_ok = new_file->install();
                if (!install_ok) {
                    // install() will log why the file failed to open.
                    enable_auditing_ = false;
                    break;
                }
				priority_routing.push_back(
					scoped_ptr_t<audit_log_output_target_t>(new_file));
            }
        }
    }

    if (enable_auditing_ && d.HasMember("system") && d["system"].IsObject()) {
        int new_min_severity = 0;
        if (d["system"]["min_severity"].IsInt()) {
            new_min_severity = d["system"]["min_severity"].GetInt();
        }
		syslog_output_target_t *syslog_target =
			new syslog_output_target_t(true, new_min_severity);
        priority_routing.push_back(scoped_ptr_t<audit_log_output_target_t>(syslog_target));
    }

    if (enable_auditing_) {
        logNTC("Audit logging enabled.\n");
    } else {
        logWRN("Audit logging disabled\n");
    }

    if (fp != nullptr) {
        int res = fclose(fp);
        if (res != 0) {
            logERR("Failed to close audit config file.\n");
        }
    }
}
thread_pool_audit_log_writer_t::~thread_pool_audit_log_writer_t() {
    pmap(
        get_num_threads(),
        boost::bind(&thread_pool_audit_log_writer_t::uninstall_on_thread, this, _1));

    drainer.drain();
    for (auto &&output_target : priority_routing) {
        on_thread_t rethreader(output_target->home_thread());
        output_target.reset();
    }
    priority_routing.clear();
    while (priority_routing.size() > 0) {
        auto it = priority_routing.begin();
        on_thread_t rethreader((*it)->home_thread());
        priority_routing.erase(it);
    }

    log_write_issue_tracker = nullptr;
}

void install_logfile_output_target(const std::string &dirpath, 
                                   const std::string &filename, 
                                   const std::string &config_file_name) {
    thread_pool_audit_log_writer_t::config_file_path = config_file_name;
    audit_log_message_t::set_uptime_reference();
	file_output_target_t::logfilename = filename;
	file_output_target_t::dirpath = dirpath;
}

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
    counted_t<audit_log_message_t> msg,
    bool for_console = false) {
    std::string msg_string;

    bool ends_in_newline = 
        msg->message.length() == 0 ? false : msg->message.back() == '\n';
    if (!for_console) {
        msg_string = strprintf("%s %s [%s]: %s%s",
                               format_time(msg->timestamp, local_or_utc_time_t::utc).c_str(),
                               format_log_level(msg->level).c_str(),
                               type_to_string[msg->type].c_str(),
                               msg->message.c_str(),
                               ends_in_newline ? "" : "\n");
    } else {
        msg_string = strprintf("%s%s",
                               msg->message.c_str(),
                               ends_in_newline ? "" : "\n");
    }
    return msg_string;
}

std::string format_log_message(const counted_t<audit_log_message_t> &m, bool for_console) {
    // never write an info level message to console
    guarantee(!(for_console && m->level == log_level_info));

    std::string message = m->message;
    std::string message_reformatted;

    std::string prepend;
    if (!for_console) {
        prepend = strprintf("%s %ld.%06llds %s: ",
                            format_time(m->timestamp, local_or_utc_time_t::utc).c_str(),
                            m->uptime.tv_sec,
                            m->uptime.tv_nsec / THOUSAND,
                            format_log_level(m->level).c_str());
    } else {
        if (m->level != log_level_info && m->level != log_level_notice) {
            prepend = strprintf("%s: ", format_log_level(m->level).c_str());
        }
    }
    ssize_t prepend_length = prepend.length();

    ssize_t start = 0, end = message.length() - 1;
    while (start < static_cast<ssize_t>(message.length()) && message[start] == '\n') {
        ++start;
    }
    while (end >= 0 && (message[end] == '\n' || message[end] == '\r')) {
        end--;
    }
    for (int i = start; i <= end; i++) {
        if (message[i] == '\n') {
            if (for_console) {
                message_reformatted.push_back('\n');
                message_reformatted.append(prepend_length, ' ');
            } else {
                message_reformatted.append("\\n");
            }
        } else if (message[i] == '\t') {
            if (for_console) {
                message_reformatted.push_back('\t');
            } else {
                message_reformatted.append("\\t");
            }
        } else if (message[i] == '\\') {
            if (for_console) {
                message_reformatted.push_back(message[i]);
            } else {
                message_reformatted.append("\\\\");
            }
        } else if (message[i] < ' ' || message[i] > '~') {
#if !defined(NDEBUG)
             crash("We can't have special characters in log messages because then it "
                   "would be difficult to parse the log file. Message: %s",
                   message.c_str());
#else
            message_reformatted.push_back('?');
#endif
        } else {
            message_reformatted.push_back(message[i]);
        }
    }

    return prepend + message_reformatted;
}


void thread_pool_audit_log_writer_t::write(counted_t<audit_log_message_t> msg) {
    // Select targets by configured severity level
    for (const auto &it : priority_routing) {
        if (it->min_severity <= msg->level) {

            if (it->tags.empty() ||
                std::find(it->tags.begin(),
                          it->tags.end(),
                          msg->type) != it->tags.end()) {

                if (enable_auditing() || !it->respects_enabled_flag) {
                    it->emplace_message(msg, false);
                }
            }
        }
    }
}

void audit_log_output_target_t::emplace_message(counted_t<audit_log_message_t> msg,
                                                bool ignore_capacity) {
    auto keepalive = drainer.lock();
    size_t msg_size = msg->message.size();
    {
        spinlock_acq_t s_acq(&queue_mutex);
        queue.push_back(msg);
        queue_size += msg_size;
    }
    // Add messages to intrusive list unless the batch is full,
    // then the code will block until a file write is done.
    bool over_capacity = queue.size() > AUDIT_MESSAGE_QUEUE_MESSAGE_LIMIT
        || queue_size > AUDIT_MESSAGE_QUEUE_SIZE_LIMIT;
    if (!ignore_capacity && over_capacity) {
        {
            spinlock_acq_t a_acq(&queue_mutex);
            queue_size = 0;
        }
        on_thread_t rethreader(write_pump.home_thread());
        write_pump.notify();
        cond_t non_interruptor;
        write_pump.flush(&non_interruptor);
    } else {
        // Call the file output function, unless it's already happening.
        call_on_thread(write_pump.home_thread(),
                       [&, keepalive]() {
                           write_pump.notify();
                       });
    }
}

void audit_log_output_target_t::flush() {
    // Grab all the logs in the local queue to write out, and reset queue.
    std::deque<counted_t<audit_log_message_t> > local_queue;
    {
        spinlock_acq_t s_acq(&queue_mutex);
        local_queue.swap(queue);
    }
    std::string error_message;
    bool res;
    thread_pool_t::run_in_blocker_pool([&]() {
            // This may block on disk usage.
            res = write_internal(&local_queue, &error_message);
        });
    if (res) {
        report_success();
    } else {
        report_error(error_message);
    }
}

void vaudit_log_internal(log_type_t type,
                         log_level_t level,
                         const char *format,
                         va_list args) {
#ifndef _WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
    std::string message = vstrprintf(format, args);

    counted_t<audit_log_message_t> log_msg =
        make_counted<audit_log_message_t>(level, type, message);
    thread_pool_audit_log_writer_t *writer = TLS_get_global_audit_log_writer();
    if (writer != nullptr) {
        auto_drainer_t::lock_t lock(TLS_get_global_audit_log_drainer());
        writer->write(log_msg);

    } else {
        if (type == log_type_t::log) {
            // These should be startup messages, forward to fallback_log_writer.
            fallback_log_message(level, message);
        } else {
            // These messages shouldn't usually happen. Forward to console only.
            fprintf(stderr, "%s\n", message.c_str());
        }
    }
#ifndef _WIN32
#pragma GCC diagnostic pop
#endif
}

void audit_log_internal
(log_type_t type, log_level_t level, const char *format, ...) {
        va_list args;
        va_start(args, format);
        vaudit_log_internal(type, level, format, args);
        va_end(args);
}

bool file_output_target_t::install() {
#ifdef _WIN32
    HANDLE h = CreateFile(filename.path().c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    fd.reset(h);

    if (fd.get() == INVALID_FD) {
        logERR("Failed to open log file '%s': %s",
            filename.path().c_str(),
            winerr_string(GetLastError()).c_str());
        return false;
    }
#else
    int res;
    do {
        res = open(filename.path().c_str(), O_WRONLY | O_APPEND | O_CREAT, 0644);
    } while (res == INVALID_FD && get_errno() == EINTR);

    fd.reset(res);
    if (fd.get() == INVALID_FD) {
        logERR("Failed to open log file '%s': %s",
            filename.path().c_str(),
            errno_string(errno).c_str());
        return false;
    }
#endif // _WIN32
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
    return true;
}

bool file_output_target_t::write_internal(
    std::deque<counted_t<audit_log_message_t> > *local_queue,
    std::string *error_message) {

    bool ok = true;
    if (fd.get() == INVALID_FD) {
        *error_message = strprintf("Log file is invalid: %s",
                                   errno_string(get_errno()).c_str());
        log_error_once(*error_message);
        return false;
    }

    for (const auto &msg : *local_queue) {
        std::string msg_str;
        if (!is_logfile) {
            msg_str  =
                thread_pool_audit_log_writer_t::format_audit_log_message(msg);
        } else {
            msg_str = format_log_message(msg, false) + '\n';
        }
#ifdef _WIN32
        DWORD bytes_written;
        BOOL res = WriteFile(fd.get(),
                             msg_str.data(),
                             msg_str.length(),
                             &bytes_written,
                             nullptr);
        if (!res) {
          *error_message = strprintf("cannot write to log file: %s", winerr_string(GetLastError()).c_str());
            ok = false;
            log_error_once(*error_message);
        }
#else
        ssize_t write_res = ::write(fd.get(),
                                    msg_str.data(),
                                    msg_str.length());
        if (write_res != static_cast<ssize_t>(msg_str.length())) {
            *error_message = strprintf("Cannot write to log file: %s",
                                      errno_string(get_errno()).c_str());
            ok = false;
            log_error_once(*error_message);
        }
#endif
    }
    return ok;
}

bool console_output_target_t::write_internal(std::deque<counted_t<audit_log_message_t> > *local_queue,
                                             UNUSED std::string *error_message) {
    for (const auto &msg : *local_queue) {
#ifdef _MSC_VER
        static int STDOUT_FILENO = -1;
        static int STDERR_FILENO = -1;
        if (STDOUT_FILENO == -1) {
            STDOUT_FILENO = _open("conout$", _O_RDONLY, 0);
            STDERR_FILENO = STDOUT_FILENO;
        }
#endif

        int fileno = -1;
        switch (msg->level) {
        case log_level_info:
            // no message on stdout/stderr
            break;
        case log_level_notice:
            fileno = STDOUT_FILENO;
            break;
        case log_level_debug:
        case log_level_warn:
        case log_level_error:
        case log_level_critical:
        case log_level_alert:
        case log_level_emergency:
            fileno = STDERR_FILENO;
            break;
        default:
            unreachable();
        }
        std::string msg_str =
            thread_pool_audit_log_writer_t::format_audit_log_message(msg, true);
#ifdef _WIN32
        size_t write_res = fwrite(msg_str.data(), 1, msg_str.size(), stderr);
        guarantee(write_res == msg_str.size());
#else
        const char* data = msg_str.c_str();
        const char* end = data + msg_str.size();
        while (data < end) {
            ssize_t written = ::write(fileno, data, end - data);
            if (written == -1) {
                int err_no = get_errno();
                if (err_no != EINTR) {
                    crash("Error while writing to console: %d", err_no);
                }
            } else {
                data += written;
            }
        }
#endif
    }
    return true;
}

syslog_output_target_t::syslog_output_target_t(bool _respects_enabled_flag, int _min_severity) : 
    audit_log_output_target_t(_respects_enabled_flag, _min_severity) {
#ifdef _WIN32
    EventRegisterRethinkDB();
#else
    openlog("rethinkdb", LOG_PID, 0);
#endif
}

syslog_output_target_t::~syslog_output_target_t() {
#ifdef _WIN32
    EventUnregisterRethinkDB();
#else
	closelog();
#endif
}

bool syslog_output_target_t::write_internal(std::deque<counted_t<audit_log_message_t> > *local_queue,
                                            UNUSED std::string *error_message) {
#ifdef _WIN32
    for (const auto &msg : *local_queue) {
        LPCTSTR pInsertStrings[1] = { nullptr };

        pInsertStrings[0] = msg->message.c_str();

        int buffer_size = MultiByteToWideChar(CP_UTF8, 0, msg->message.c_str(), -1, nullptr, 0);
        wchar_t* temp = new wchar_t[buffer_size];

        int res = MultiByteToWideChar(CP_UTF8, 0, msg->message.c_str(), -1, temp, buffer_size);
        if (!res) {
            *error_message = strprintf("Cannot write to Windows Event Viewer: %s", winerr_string(GetLastError()).c_str());
            log_error_once(*error_message);
            return false;
        }

        switch (msg->level) {
        case log_level_debug:
        case log_level_info:
            EventWriteAuditLogInfo(temp);
            break;
        case log_level_notice:
            EventWriteAuditLogNotice(temp);
            break;
        case log_level_warn:
            EventWriteAuditLogWarn(temp);
            break;
        case log_level_error:
            EventWriteAuditLogError(temp);
            break;
        case log_level_critical:
            EventWriteAuditLogCritical(temp);
            break;
        case log_level_alert:
            EventWriteAuditLogAlert(temp);
            break;
        case log_level_emergency:
            EventWriteAuditLogEmergency(temp);
        default:
            unreachable();
        }
        delete[] temp;
    }
#else
    for (const auto &msg : *local_queue) {
        int priority_level = 0;
        switch (msg->level) {
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
        syslog(priority_level, "%s",
               thread_pool_audit_log_writer_t::format_audit_log_message(msg).c_str());
    }
#endif
    return true;
}
