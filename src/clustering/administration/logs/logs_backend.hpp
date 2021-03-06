// Copyright 2010-2014 RethinkDB, all rights reserved.
#ifndef CLUSTERING_ADMINISTRATION_LOGS_LOGS_BACKEND_HPP_
#define CLUSTERING_ADMINISTRATION_LOGS_LOGS_BACKEND_HPP_

#include <map>
#include <set>
#include <string>
#include <vector>

#include "rdb_protocol/artificial_table/caching_cfeed_backend.hpp"
#include "clustering/administration/metadata.hpp"

class server_config_client_t;

/* This backend assumes that the entries in the log file have timestamps that are unique
and monotonically increasing. These assumptions can be broken if the system clock runs
backwards while the server is turned off, or if the user manually edits the log file. If
these assumptions are broken, the system shouldn't crash, but the contents of
`rethinkdb.logs` are undefined. In particular, the following things will go wrong:
  * The `rethinkdb.logs` table might have multiple entries with the same primary key.
  * Log entries might appear in `r.db("rethinkdb").table("logs")` but not if the user
    runs `r.db("rethinkdb").table("logs").get(primary_key)`
  * Changefeeds on `rethinkdb.logs` might skip some changes.
*/

class logs_artificial_table_backend_t :
    public cfeed_artificial_table_backend_t
{
public:
    logs_artificial_table_backend_t(
            mailbox_manager_t *_mailbox_manager,
            watchable_map_t<peer_id_t, cluster_directory_metadata_t> *_directory,
            server_config_client_t *_server_config_client,
            admin_identifier_format_t _identifier_format) :
        mailbox_manager(_mailbox_manager),
        directory(_directory),
        server_config_client(_server_config_client),
        identifier_format(_identifier_format) { }
    ~logs_artificial_table_backend_t();

    std::string get_primary_key_name();

    bool read_all_rows_as_vector(signal_t *interruptor,
                                 std::vector<ql::datum_t> *rows_out,
                                 admin_err_t *error_out);

    bool read_row(ql::datum_t primary_key,
                  signal_t *interruptor,
                  ql::datum_t *row_out,
                  admin_err_t *error_out);

    bool write_row(job_id_t job_id,
                   ql::datum_t primary_key,
                   bool pkey_was_autogenerated,
                   ql::datum_t *new_value_inout,
                   signal_t *interruptor,
                   admin_err_t *error_out);

private:
    class cfeed_machinery_t : public cfeed_artificial_table_backend_t::machinery_t {
    public:
        explicit cfeed_machinery_t(logs_artificial_table_backend_t *_parent);

        /* `on_change()` checks for newly-connected peers. If it finds one, it puts an
        entry in `peers_handled` and spawns an instance of `run()`. */
        void on_change(const peer_id_t &peer, const cluster_directory_metadata_t *dir);

        /* One instance of `run` will be running for each server we're in contact with
        that hasn't been permanently removed. It first fetches the latest entry of each
        server's log, then repeatedly checks for newer log entries at a regular interval.
        If it sees that the server is disconnected, then it removes itself from
        `peers_handled` and stops. */
        void run(
            const peer_id_t &peer,
            const server_id_t &server_id,
            const log_server_business_card_t &bcard,
            bool is_a_starter,
            auto_drainer_t::lock_t keepalive);

        /* Helper function for `run()`. Checks if the server is no longer present in the
        directory; if so, removes the entry from `peers_handled` and returns `false`. */
        bool check_disconnected(const peer_id_t &peer);

        /* Called by `cfeed_artificial_table_backend_t` to fetch the initial values for a
        new changefeed */
        bool get_initial_values(
            const new_mutex_acq_t *proof,
            std::vector<ql::datum_t> *initial_values_out,
            signal_t *interruptor);

        logs_artificial_table_backend_t *parent;
        std::set<peer_id_t> peers_handled;
        std::map<peer_id_t, timespec> last_timestamps;

        /* `all_starters_done` is pulsed when we've fetched logs from every peer that was
        connected to the `cfeed_machinery_t` when it was first created. When the
        `cfeed_machinery_t` is first created, `starting` is true, and any instance of
        `run()` that are spawned in the first group have `is_a_starter` set to `true`.
        `num_starters_left` is initially the number of such coroutines. As soon as the
        initial batch are spawned, `starting` is set to `false`, so any further instances
        that are spawned for newly-connected servers will have `is_a_starter` set to
        `false`. As each instance with `is_a_starter` set to `true` finishes fetching the
        initial timestamp, it decrements `num_starters_left`. The last one pulses
        `all_starters_done`.*/
        bool starting;
        int num_starters_left;
        cond_t all_starters_done;

        auto_drainer_t drainer;
        watchable_map_t<peer_id_t, cluster_directory_metadata_t>::all_subs_t dir_subs;
    };

    bool read_all_rows_raw(
        const std::function<void(
            const log_message_t &message,
            const peer_id_t &peer_id,
            const server_id_t &server_id,
            const ql::datum_t &server_name_datum)> &callback,
        signal_t *interruptor,
        admin_err_t *error_out);

    scoped_ptr_t<cfeed_artificial_table_backend_t::machinery_t>
        construct_changefeed_machinery(signal_t *interruptor);

    mailbox_manager_t *mailbox_manager;
    watchable_map_t<peer_id_t, cluster_directory_metadata_t> *directory;
    server_config_client_t *server_config_client;
    admin_identifier_format_t identifier_format;
};

#endif /* CLUSTERING_ADMINISTRATION_LOGS_LOGS_BACKEND_HPP_ */
