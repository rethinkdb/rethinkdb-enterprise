// Copyright 2010-2016 RethinkDB, all rights reserved.
#include "rdb_protocol/read_routing.hpp"

#include <string>

#include "errors.hpp"
#include <boost/algorithm/string/join.hpp>

#include "clustering/administration/servers/config_client.hpp"
#include "rpc/serialize_macros.hpp"

read_routing_t::read_routing_t()
    : m_on_unavailable(read_routing_t::on_unavailable_t::TRY_ANY),
      m_prefer_local(true) {
}

name_string_t datum_to_name_string(ql::datum_t const &datum) {
    name_string_t name_string;
    if (!name_string.assign_value(datum.as_str())) {
        rfail_datum(
            ql::base_exc_t::LOGIC,
            "%s",
            ("\"" + datum.trunc_print() + "\" contains invalid characters.").c_str());
    }
    return name_string;
}

std::set<name_string_t> datum_to_set_name_string(ql::datum_t const &datum) {
    std::set<name_string_t> name_strings;

    switch (datum.get_type()) {
        case ql::datum_t::R_STR:
            name_strings.insert(datum_to_name_string(datum));
            break;
        case ql::datum_t::R_ARRAY:
            for (size_t i = 0; i < datum.arr_size(); ++i) {
                name_strings.insert(datum_to_name_string(datum.get(i)));
            }
            break;
        case ql::datum_t::UNINITIALIZED:
        case ql::datum_t::MINVAL:
        case ql::datum_t::R_BINARY:
        case ql::datum_t::R_BOOL:
        case ql::datum_t::R_NULL:
        case ql::datum_t::R_NUM:
        case ql::datum_t::R_OBJECT:
        case ql::datum_t::MAXVAL:
        default:
            rfail_datum(
                ql::base_exc_t::LOGIC,
                "%s",
                ("Expected a string or array, got " + datum.trunc_print() +
                    ".").c_str());
    }

    return name_strings;
}

read_routing_t::read_routing_t(ql::datum_t const &datum)
    : m_on_unavailable(read_routing_t::on_unavailable_t::TRY_ANY),
      m_prefer_local(true) {
    std::set<std::string> keys;
    for (size_t i = 0; i < datum.obj_size(); ++i) {
        keys.insert(datum.get_pair(i).first.to_std());
    }

    ql::datum_t replica_tags = datum.get_field("replica_tags", ql::NOTHROW);
    if (replica_tags.has()) {
        m_replica_tags = datum_to_set_name_string(replica_tags);
        keys.erase("replica_tags");
    }

    ql::datum_t replicas = datum.get_field("replicas", ql::NOTHROW);
    if (replicas.has()) {
        m_replicas = datum_to_set_name_string(replicas);
        keys.erase("replicas");
    }

    if (m_replica_tags.empty() && m_replicas.empty()) {
        rfail_datum(
            ql::base_exc_t::LOGIC, "`replica_tags` or `replicas` must be specified.");
    }

    ql::datum_t prefer_local = datum.get_field("prefer_local", ql::NOTHROW);
    if (prefer_local.has()) {
        m_prefer_local = prefer_local.as_bool();
    }
    keys.erase("prefer_local");

    ql::datum_t on_unavailable = datum.get_field("on_unavailable", ql::NOTHROW);
    if (on_unavailable.has()) {
        datum_string_t on_unavailable_str = on_unavailable.as_str();
        if (on_unavailable_str == "try_any") {
            m_on_unavailable = read_routing_t::on_unavailable_t::TRY_ANY;
        } else if (on_unavailable_str == "error") {
            m_on_unavailable = read_routing_t::on_unavailable_t::ERROR;
        } else {
            rfail_datum(
                ql::base_exc_t::LOGIC,
                "`on_unavailable` has to be either `\"try_any\"` or `\"error\"`.");
        }
        keys.erase("on_unavailable");
    }

    if (!keys.empty()) {
        rfail_datum(
            ql::base_exc_t::LOGIC,
            "%s",
            ("Unexpected key(s) `" + boost::algorithm::join(keys, "`, `") + "`.").c_str());
    }
}

bool read_routing_t::is_try_any() const {
    return m_on_unavailable == on_unavailable_t::TRY_ANY;
}

bool read_routing_t::is_prefer_local() const {
    return m_prefer_local;
}

std::set<server_id_t> read_routing_t::get_server_ids(
        server_config_client_t *server_config_client) const {
    std::set<server_id_t> servers;

    server_config_client->get_server_config_map()->read_all(
        [&](server_id_t const &server_id, server_config_versioned_t const *config) {
            if (m_replicas.count(config->config.name) == 1 ||
                std::any_of(
                    m_replica_tags.begin(),
                    m_replica_tags.end(),
                    [&](name_string_t const &replica_tag) {
                        return config->config.tags.count(replica_tag) == 1;
                    })) {
                servers.insert(server_id);
            }
        });

    return servers;
}

RDB_IMPL_SERIALIZABLE_2(read_routing_t, m_prefer_local, m_on_unavailable);
INSTANTIATE_SERIALIZABLE_SINCE_v2_3(read_routing_t);
