// Copyright 2010-2014 RethinkDB, all rights reserved.
#ifndef CLUSTERING_ADMINISTRATION_SERVERS_SERVER_CONFIG_HPP_
#define CLUSTERING_ADMINISTRATION_SERVERS_SERVER_CONFIG_HPP_

#include <string>
#include <vector>

#include "errors.hpp"
#include <boost/shared_ptr.hpp>

#include "clustering/administration/servers/server_common.hpp"
#include "clustering/administration/servers/server_metadata.hpp"
#include "rdb_protocol/artificial_table/backend.hpp"
#include "rpc/semilattice/view.hpp"

class server_config_client_t;

class server_config_artificial_table_backend_t :
    public common_server_artificial_table_backend_t
{
public:
    server_config_artificial_table_backend_t(
            watchable_map_t<peer_id_t, cluster_directory_metadata_t> *_directory,
            server_config_client_t *_server_config_client);
    ~server_config_artificial_table_backend_t();

    bool write_row(
            job_id_t job_id,
            ql::datum_t primary_key,
            bool pkey_was_autogenerated,
            ql::datum_t *new_value_inout,
            signal_t *interruptor_on_caller,
            admin_err_t *error_out);

private:
    bool format_row(
            server_id_t const & server_id,
            peer_id_t const & peer_id,
            cluster_directory_metadata_t const & metadata,
            signal_t *interruptor_on_home,
            ql::datum_t *row_out,
            admin_err_t *error_out);

    /* All writes to this pseudo-table must acquire this mutex. This makes it impossible
    for multiple concurrent changes via this one server to cause a name conflict. Name
    conflicts are still possible if changes are made via multiple servers. */
    new_mutex_t write_mutex;
};

#endif /* CLUSTERING_ADMINISTRATION_SERVERS_SERVER_CONFIG_HPP_ */

