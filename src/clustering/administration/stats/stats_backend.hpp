// Copyright 2010-2014 RethinkDB, all rights reserved.
#ifndef CLUSTERING_ADMINISTRATION_STATS_STATS_BACKEND_HPP_
#define CLUSTERING_ADMINISTRATION_STATS_STATS_BACKEND_HPP_

#include <string>
#include <vector>

#include "errors.hpp"
#include <boost/shared_ptr.hpp>

#include "rdb_protocol/artificial_table/caching_cfeed_backend.hpp"
#include "clustering/administration/metadata.hpp"
#include "clustering/administration/servers/config_client.hpp"
#include "concurrency/watchable.hpp"

class stats_artificial_table_backend_t :
    public timer_cfeed_artificial_table_backend_t
{
public:
    stats_artificial_table_backend_t(
        const clone_ptr_t<watchable_t<change_tracking_map_t<peer_id_t,
            cluster_directory_metadata_t> > >
                &_directory_view,
        boost::shared_ptr<semilattice_read_view_t<cluster_semilattice_metadata_t> >
            _cluster_sl_view,
        server_config_client_t *_server_config_client,
        table_meta_client_t *_table_meta_client,
        mailbox_manager_t *_mailbox_manager,
        admin_identifier_format_t _admin_format);
    ~stats_artificial_table_backend_t();

    std::string get_primary_key_name();

    bool read_all_rows_as_vector(signal_t *interruptor_on_caller,
                                 std::vector<ql::datum_t> *rows_out,
                                 admin_err_t *error_out);

    bool read_row(ql::datum_t primary_key,
                  signal_t *interruptor_on_caller,
                  ql::datum_t *row_out,
                  admin_err_t *error_out);

    bool write_row(UNUSED job_id_t job_id,
                   ql::datum_t primary_key,
                   bool pkey_was_autogenerated,
                   ql::datum_t *new_value_inout,
                   signal_t *interruptor_on_caller,
                   admin_err_t *error_out);

private:
    void get_peer_stats(const peer_id_t &peer,
                        const std::set<std::vector<std::string> > &filter,
                        ql::datum_t *result_out,
                        signal_t *interruptor_on_home);

    void perform_stats_request(const std::vector<peer_id_t> &peers,
                               const std::set<std::vector<std::string> > &filter,
                               std::vector<ql::datum_t> *results_out,
                               signal_t *interruptor_on_home);

    clone_ptr_t<watchable_t<change_tracking_map_t<peer_id_t,
        cluster_directory_metadata_t> > > directory_view;
    boost::shared_ptr<semilattice_read_view_t<cluster_semilattice_metadata_t> >
        cluster_sl_view;
    server_config_client_t *server_config_client;
    table_meta_client_t *table_meta_client;
    mailbox_manager_t *mailbox_manager;
    admin_identifier_format_t admin_format;
};

#endif /* CLUSTERING_ADMINISTRATION_STATS_STATS_BACKEND_HPP_ */
