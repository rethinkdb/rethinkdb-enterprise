//Copyright RethinkDB 2010-2016, all rights reservec.

#include "clustering/administration/logs/audit_log.hpp"

#include "errors.hpp"
#include <boost/bind.hpp>
#include <sys/stat.h>

#include "arch/runtime/thread_pool.hpp"
#include "clustering/administration/logs/log_writer.hpp"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/filereadstream.h"
#include "thread_local.hpp"

#ifdef _WIN32

// For Windows event log.
#include <io.h>
#include <evntprov.h>
#include <conio.h>
#include "RethinkDBAuditManifest.h"

#else
#include <syslog.h>
#endif

TLS_with_init(thread_pool_audit_log_writer_t *, global_audit_log_writer, nullptr);
TLS_with_init(auto_drainer_t *, global_audit_log_drainer, nullptr);
TLS_with_init(int, audit_log_writer_block, 0);

// We need to set this in command_line.cc
file_output_target_t *global_logfile_target;
console_output_target_t *global_console_target;

log_write_issue_tracker_t *log_write_issue_tracker;

const std::string config_base_path = "audit/audit_config.json";
const std::string logs_base_path = "/../audit/logs/";

struct timespec audit_log_message_t::_uptime_reference;
std::string file_output_target_t::logfilename;
std::string file_output_target_t::dirpath;

void report_success() {
    coro_t::spawn_on_thread([] () {
            log_write_issue_tracker->report_success();
        }, log_write_issue_tracker->home_thread());
}


void report_error(std::string msg) {
    coro_t::spawn_on_thread([msg] () {
            log_write_issue_tracker->report_error(msg);
        }, log_write_issue_tracker->home_thread());
}

void log_error_once(std::string msg) {
    //fprintf(stderr, "log_error_once\n");
    counted_t<audit_log_message_t> log_msg =
        make_counted<audit_log_message_t>(log_level_t::log_level_error,
                                          log_type_t::log,
                                          msg);
    intrusive_list_t<audit_log_message_node_t> temp_queue;
    temp_queue.push_back(new audit_log_message_node_t(log_msg));
    //global_logfile_target->write_internal(&temp_queue);
    // This should never fail.
    //fprintf(stderr, "%s\n", msg.c_str());
    UNUSED bool res = global_console_target->write_internal(&temp_queue, nullptr);
}

file_output_target_t::file_output_target_t(std::string server_name, std::string _filename) :
    audit_log_output_target_t(),
    filename(strprintf("%s%s%s_%s",
		file_output_target_t::dirpath.c_str(),
		logs_base_path.c_str(),
        server_name.c_str(),
        _filename.c_str()).c_str()),
    is_logfile(false) { }

// Allow specifiying direct file path for logs table logs.
file_output_target_t::file_output_target_t(std::string _filename) :
    audit_log_output_target_t(),
    filename(_filename.c_str()),
    is_logfile(true) { }

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
    std::string server_name,
    log_write_issue_tracker_t *log_tracker) :
    config_filename(config_base_path),
    _enable_auditing(true) {

    //fprintf(stderr, "thread_pool_audit_log_writer_t\n");
    log_write_issue_tracker = log_tracker;

    pmap(
        get_num_threads(),
        boost::bind(&thread_pool_audit_log_writer_t::install_on_thread, this, _1));

	//fprintf(stderr, "install_logfile_output_target\n");

	global_logfile_target = new file_output_target_t(file_output_target_t::logfilename);
	global_logfile_target->respects_enabled_flag = false;
	global_logfile_target->install();
	// We only want this target to save logs.
	global_logfile_target->tags.push_back(log_type_t::log);

	global_console_target = new console_output_target_t();
	global_console_target->respects_enabled_flag = false;

    counted_t<file_output_target_t> logfile(global_logfile_target);
    logfile->tags.push_back(log_type_t::log);
    logfile->install();
    priority_routing.push_back(counted_t<audit_log_output_target_t>(logfile));

    counted_t<console_output_target_t> console_target(global_console_target);
    console_target->min_severity = log_level_t::log_level_notice;
    priority_routing.push_back(counted_t<audit_log_output_target_t>(console_target));

    // This is how rapidjson recommends doing this.
    char readBuffer[65536];
    FILE *fp = fopen(config_filename.path().c_str(), "r");

    rapidjson::Document d;

    if (fp != nullptr) {
        rapidjson::FileReadStream is(fp, readBuffer, sizeof(readBuffer));
        d.ParseStream(is);
    } else {
        _enable_auditing = false;
    }

    if (d.HasParseError()) {
        logERR("\nAudit Config file Error(offset %u): %s\n",
               (unsigned)d.GetErrorOffset(),
               GetParseError_En(d.GetParseError()));
        logERR("Audit logging will be DISABLED.\n");

        // Disable auditing and exit
        _enable_auditing = false;
    } else if (_enable_auditing &&
               d.HasMember("enable_auditing") && d["enable_auditing"].GetBool() == false) {
        // Auditing config is otherwise correct, but has disabled auditing.
        _enable_auditing = false;
    } else if (_enable_auditing) {
        // Set up file and syslog targets for audit log.
        if (d.HasMember("files") && d["files"].IsArray()) {
            const rapidjson::Value& files = d["files"];
            for (rapidjson::SizeType i = 0; i < files.Size(); ++i) {
                guarantee(files[i]["filename"].IsString());

                counted_t<file_output_target_t> new_file =
                    make_counted<file_output_target_t>(
                    server_name,
                    files[i]["filename"].GetString());

                if (files[i]["min_severity"].IsInt()) {
                    new_file->min_severity = files[i]["min_severity"].GetInt();
                }

                // Setup type routing.
                if (files[i].HasMember("tags")) {
                    const rapidjson::Value& tags = files[i]["tags"];
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
                    _enable_auditing = false;
                    break;
                }
				priority_routing.push_back(
					counted_t<audit_log_output_target_t>(new_file));
            }
        }
    }

    if (_enable_auditing && d.HasMember("syslog") && d["syslog"].IsObject()) {
		counted_t<syslog_output_target_t> syslog_target =
			make_counted<syslog_output_target_t>();
        if (d["syslog"]["min_severity"].IsInt()) {
            syslog_target->min_severity = d["syslog"]["min_severity"].GetInt();
        }
        priority_routing.push_back(counted_t<audit_log_output_target_t>(syslog_target));
    }

    if (_enable_auditing) {
        logNTC("Audit logging enabled.\n");
    } else {
        logWRN("Audit logging disabled\n");
    }


    if (fp != nullptr) {
        fclose(fp);
    }
}
thread_pool_audit_log_writer_t::~thread_pool_audit_log_writer_t() {
    pmap(
        get_num_threads(),
        boost::bind(&thread_pool_audit_log_writer_t::uninstall_on_thread, this, _1));

    while (priority_routing.size() > 0) {
        auto it = priority_routing.begin();
        on_thread_t rethreader((*it)->home_thread());
        priority_routing.erase(it);
    }

    log_write_issue_tracker = nullptr;
}

void install_logfile_output_target(std::string dirpath, std::string filename) {
    audit_log_message_t::set_uptime_reference();
	file_output_target_t::logfilename = filename;
	file_output_target_t::dirpath = dirpath;
}

void thread_pool_audit_log_writer_t::install_on_thread(int i) {
 // fprintf(stderr, "Installing on thread %d\n", i);
    on_thread_t thread_switcher((threadnum_t(i)));
    guarantee(TLS_get_global_audit_log_writer() == nullptr);
    TLS_set_global_audit_log_drainer(new auto_drainer_t);
    TLS_set_global_audit_log_writer(this);
}

void thread_pool_audit_log_writer_t::uninstall_on_thread(int i) {
   // fprintf(stderr, "uninstall_on_thread %d\n", i);
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

    bool ends_in_newline = msg->message.back() == '\n';
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

std::string format_log_message(counted_t<audit_log_message_t> &m, bool for_console) {
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
    for (auto it : priority_routing) {
        if (it->min_severity <= msg->level) {

            if (it->tags.empty() ||
                std::find(it->tags.begin(),
                          it->tags.end(),
                          msg->type) != it->tags.end()) {

                if (enable_auditing() || !it->respects_enabled_flag) {
                    //fprintf(stderr, "Message: %s", msg->message.c_str());
                    it->emplace_message(msg, false);
                }
            }
        }
    }
}

void audit_log_output_target_t::emplace_message(counted_t<audit_log_message_t> msg,
                                                bool ignore_capacity) {
   // fprintf(stderr, "emplace_message\n");
    auto keepalive = drainer.lock();
    size_t msg_size = sizeof(msg->message);
    bool over_capacity;
    {
        spinlock_acq_t s_acq(&queue_mutex);
       // fprintf(stderr, "HERE\n");
        queue.push_back(new audit_log_message_node_t(msg));
       // fprintf(stderr, "end HERE\n");
        queue_size += msg_size;
    }
    // Add messages to intrusive list unless the batch is full,
    // then the code will block until a file write is done.
    over_capacity = queue.size() > AUDIT_MESSAGE_QUEUE_MESSAGE_LIMIT
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
    //fprintf(stderr, "end emplace_message\n");
}

void audit_log_output_target_t::flush() {
    // Grab all the logs in the local queue to write out, and reset queue.
    intrusive_list_t<audit_log_message_node_t> local_queue;
    {
        spinlock_acq_t s_acq(&queue_mutex);
        local_queue.append_and_clear(&queue);
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
 // fprintf(stderr, "\nvaudit_log_internal: %s\n\n", format);
#ifdef _MSC_VER
    static int STDOUT_FILENO = -1;
    static int STDERR_FILENO = -1;
    if (STDOUT_FILENO == -1) {
        STDOUT_FILENO = _open("conout$", _O_RDONLY, 0);
        STDERR_FILENO = STDOUT_FILENO;
    }
#endif
#ifndef _WIN32
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
   std::string message = vstrprintf(format, args);

     // fprintf(stderr, "1");
    counted_t<audit_log_message_t> log_msg =
        make_counted<audit_log_message_t>(level, type, message);
    thread_pool_audit_log_writer_t *writer = TLS_get_global_audit_log_writer();
      // fprintf(stderr, "2");
      // fprintf(stderr, "MESSAGE: %s", message.c_str());
    if (writer != nullptr) {
        auto_drainer_t::lock_t lock(TLS_get_global_audit_log_drainer());
        int writer_block = TLS_get_audit_log_writer_block();
        if (writer_block == 0) {
            writer->write(log_msg);
        } else {
            log_error_once("Failed to write audit log message.\n");
        }
    } else {
         /*fprintf(stderr, "3");
        // We don't have the thread pool yet, should only be startup logs.
        guarantee(type == log_type_t::log);
        UNUSED ssize_t write_res = ::write(STDOUT_FILENO,
                                           message.c_str(),
                                           message.length());

        intrusive_list_t<audit_log_message_node_t> temp_queue;
        temp_queue.push_back(new audit_log_message_node_t(log_msg));
        std::string error_message;
	   fprintf(stderr, "5");
        UNUSED bool res = global_logfile_target->write_internal(&temp_queue, &error_message);*/
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

bool file_output_target_t::write_internal(
    intrusive_list_t<audit_log_message_node_t> *local_queue,
    std::string *error_message) {

 // fprintf(stderr, "\nwrite_internal\n");
    bool ok = true;
    if (fd.get() == INVALID_FD) {
        *error_message = strprintf("Log file is invalid: %s",
                                   errno_string(get_errno()).c_str());
        log_error_once(*error_message);
        while (auto msg = local_queue->head()) {
            local_queue->pop_front();
            delete msg;
        }
        return false;
    }

   // fprintf(stderr, "Loop\n");

    while (auto msg = local_queue->head()) {
        local_queue->pop_front();
        std::string msg_str;
	//fprintf(stderr, "Formatting message\n");
        if (!is_logfile) {
            msg_str  =
                thread_pool_audit_log_writer_t::format_audit_log_message(msg->msg);
        } else {
            msg_str = format_log_message(msg->msg, false) + '\n';
        }
#ifdef _WIN32
        DWORD bytes_written;
	//fprintf(stderr, "Writing to file\n");
        BOOL res = WriteFile(fd.get(),
                             msg_str.data(),
                             msg_str.length(),
                             &bytes_written,
                             nullptr);
	//fprintf(stderr, "Done writing to file\n");
        if (!res) {
          *error_message = strprintf("cannot write to log file: %s", winerr_string(GetLastError()).c_str());
            ok = false;
            log_error_once(*error_message);
        }
	//fprintf(stderr, "Done writing.\n");
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
	//fprintf(stderr, "About to delete msg\n");
        delete msg;
	//fprintf(stderr, "Deleted msg\n");
    }
    return ok;
}

bool console_output_target_t::write_internal(intrusive_list_t<audit_log_message_node_t> *local_queue,
                                             UNUSED std::string *error_message) {
    while(auto msg = local_queue->head()) {
#ifdef _MSC_VER
        static int STDOUT_FILENO = -1;
        static int STDERR_FILENO = -1;
        if (STDOUT_FILENO == -1) {
            STDOUT_FILENO = _open("conout$", _O_RDONLY, 0);
            STDERR_FILENO = STDOUT_FILENO;
        }
#endif

        int fileno = -1;
        local_queue->pop_front();
        switch (msg->msg->level) {
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
            thread_pool_audit_log_writer_t::format_audit_log_message(msg->msg, true);
#ifdef _WIN32
        size_t write_res = fwrite(msg_str.data(), 1, msg_str.length(), stderr);
#else
        UNUSED ssize_t write_res = ::write(fileno, msg_str.c_str(), msg_str.length());
#endif
        delete msg;
    }
    return true;
}

syslog_output_target_t::syslog_output_target_t() : audit_log_output_target_t() {

#ifdef _WIN32
		EventRegisterRethinkDB();
#else
		openlog("rethinkdb", LOG_PID, 0);
#endif
}

syslog_output_target_t::~syslog_output_target_t() {
#ifdef _WIN32
	if (hEventLog) {
	}
#else
	closelog();
#endif
}

bool syslog_output_target_t::write_internal(intrusive_list_t<audit_log_message_node_t> *local_queue,
                                            UNUSED std::string *error_message) {
#ifdef _WIN32
	while (auto msg = local_queue->head()) {
		local_queue->pop_front();
		LPCTSTR pInsertStrings[1] = { nullptr };

		pInsertStrings[0] = msg->msg->message.c_str();
		
		int buffer_size = MultiByteToWideChar(CP_UTF8, 0, msg->msg->message.c_str(), -1, nullptr, 0);
		wchar_t* temp = new wchar_t[buffer_size];
		// TODO: can this fail? Need to consult arcane windows API
		MultiByteToWideChar(CP_UTF8, 0, msg->msg->message.c_str(), -1, temp, buffer_size);

		switch (msg->msg->level) {
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
		
		delete msg;
	}
#else
    while(auto msg = local_queue->head()) {
        local_queue->pop_front();
        int priority_level = 0;
        switch (msg->msg->level) {
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
               thread_pool_audit_log_writer_t::format_audit_log_message(msg->msg).c_str());
        delete msg;
    }
#endif
    return true;
}
