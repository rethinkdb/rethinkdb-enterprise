// Copyright 2010-2016 RethinkDB, all rights reserved.
#ifndef CLUSTERING_ADMINISTRATION_LOGS_JOB_ID_HPP_
#define CLUSTERING_ADMINISTRATION_LOGS_JOB_ID_HPP_

#include "containers/uuid.hpp"
#include "rpc/serialize_macros.hpp"

/* `job_id_t` is a wrapper around a `uuid_u`. These
are used by the audit logger to associate modified data with
a query. */
class job_id_t {
public:
    bool operator==(const job_id_t &p) const {
        return p.uuid == uuid;
    }
    bool operator!=(const job_id_t &p) const {
        return p.uuid != uuid;
    }

    /* This allows us to have maps keyed by `job_id_t` */
    bool operator<(const job_id_t &p) const {
        return p.uuid < uuid;
    }

    job_id_t()
        : uuid(nil_uuid()) {
    }

    explicit job_id_t(uuid_u u) : uuid(u) {}

    uuid_u get_uuid() const {
        return uuid;
    }

    bool is_nil() const {
        return uuid.is_nil();
    }

    RDB_DECLARE_ME_SERIALIZABLE(job_id_t);

private:
    uuid_u uuid;
};

void serialize_universal(write_message_t *wm, const job_id_t &job_id);
archive_result_t deserialize_universal(read_stream_t *s, job_id_t *job_id);

void debug_print(printf_buffer_t *buf, const job_id_t &job_id);

#endif /* CLUSTERING_ADMINISTRATION_LOGS_JOB_ID_HPP_ */

