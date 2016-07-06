// Copyright 2010-2016 RethinkDB, all rights reserved.
#include "clustering/administration/logs/job_id_t.hpp"

RDB_IMPL_SERIALIZABLE_1_SINCE_v1_13(job_id_t, uuid);

// Universal serialization functions: you MUST NOT change their implementations.
// (You could find a way to remove these functions, though.)
void serialize_universal(write_message_t *wm, const job_id_t &job_id) {
    serialize_universal(wm, job_id.get_uuid());
}
archive_result_t deserialize_universal(read_stream_t *s, job_id_t *job_id) {
    uuid_u uuid;
    archive_result_t res = deserialize_universal(s, &uuid);
    if (bad(res)) { return res; }
    *job_id = job_id_t(uuid);
    return archive_result_t::SUCCESS;
}

void debug_print(printf_buffer_t *buf, const job_id_t &job_id) {
    debug_print(buf, job_id.get_uuid());
}

