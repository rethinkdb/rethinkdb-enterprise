// Copyright 2010-2016 RethinkDB, all rights reserved.
#ifndef CLUSTERING_ADMINISTRATION_LOGS_CONNECTION_ID_HPP_
#define CLUSTERING_ADMINISTRATION_LOGS_CONNECTION_ID_HPP_

#include "containers/uuid.hpp"
#include "rpc/serialize_macros.hpp"

/* `connection_id_t` is a wrapper around a `uuid_u`. These
are used by the audit logger to associate queries and data
modified with certain connections. */

class connection_id_t {
public:
    bool operator==(const connection_id_t &p) const {
        return p.uuid == uuid;
    }
    bool operator!=(const connection_id_t &p) const {
        return p.uuid != uuid;
    }

    /* This allows us to have maps keyed by `connection_id_t` */
    bool operator<(const connection_id_t &p) const {
        return p.uuid < uuid;
    }

    connection_id_t()
        : uuid(nil_uuid()) {
    }

    explicit connection_id_t(uuid_u u) : uuid(u) {}

    uuid_u get_uuid() const {
        return uuid;
    }

    bool is_nil() const {
        return uuid.is_nil();
    }

    RDB_DECLARE_ME_SERIALIZABLE(connection_id_t);

private:
    uuid_u uuid;
};

void serialize_universal(write_message_t *wm, const connection_id_t &connection_id);
archive_result_t deserialize_universal(read_stream_t *s, connection_id_t *connection_id);

void debug_print(printf_buffer_t *buf, const connection_id_t &connection_id);

#endif /* CLUSTERING_ADMINISTRATION_LOGS_CONNECTION_ID_HPP_ */

