// Copyright 2010-2016 RethinkDB, all rights reserved.
#ifndef RDB_PROTOCOL_READ_ROUTING_HPP_
#define RDB_PROTOCOL_READ_ROUTING_HPP_

#include <set>

#include "containers/name_string.hpp"
#include "rdb_protocol/datum.hpp"
#include "rpc/connectivity/server_id.hpp"
#include "rpc/serialize_macros.hpp"

class server_config_client_t;
class table_meta_client_t;

class read_routing_t {
public:
    enum class on_unavailable_t { TRY_ANY, ERROR };

    read_routing_t();
    explicit read_routing_t(ql::datum_t const &datum);

    bool is_try_any() const;
    bool is_prefer_local() const;

    std::set<server_id_t> get_server_ids(server_config_client_t *) const;

    RDB_DECLARE_ME_SERIALIZABLE(read_routing_t);

private:
    std::set<name_string_t> m_replica_tags;
    std::set<name_string_t> m_replicas;
    on_unavailable_t m_on_unavailable;
    bool m_prefer_local;
};

ARCHIVE_PRIM_MAKE_RANGED_SERIALIZABLE(
    read_routing_t::on_unavailable_t,
    int8_t,
    read_routing_t::on_unavailable_t::TRY_ANY,
    read_routing_t::on_unavailable_t::ERROR);

#endif // RDB_PROTOCOL_READ_ROUTING_HPP_
