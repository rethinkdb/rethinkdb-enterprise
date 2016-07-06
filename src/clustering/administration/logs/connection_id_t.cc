// Copyright 2010-2016 RethinkDB, all rights reserved.
#include "clustering/administration/logs/connection_id_t.hpp"

RDB_IMPL_SERIALIZABLE_1_SINCE_v1_13(connection_id_t, uuid);

// Universal serialization functions: you MUST NOT change their implementations.
// (You could find a way to remove these functions, though.)
void serialize_universal(write_message_t *wm, const connection_id_t &connection_id) {
    serialize_universal(wm, connection_id.get_uuid());
}
archive_result_t deserialize_universal(read_stream_t *s, connection_id_t *connection_id) {
    uuid_u uuid;
    archive_result_t res = deserialize_universal(s, &uuid);
    if (bad(res)) { return res; }
    *connection_id = connection_id_t(uuid);
    return archive_result_t::SUCCESS;
}

void debug_print(printf_buffer_t *buf, const connection_id_t &connection_id) {
    debug_print(buf, connection_id.get_uuid());
}

