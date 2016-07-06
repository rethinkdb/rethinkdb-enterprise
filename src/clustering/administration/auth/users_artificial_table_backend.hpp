// Copyright 2010-2015 RethinkDB, all rights reserved.
#ifndef CLUSTERING_ADMINISTRATION_AUTH_USER_ARTIFICIAL_TABLE_BACKEND_HPP
#define CLUSTERING_ADMINISTRATION_AUTH_USER_ARTIFICIAL_TABLE_BACKEND_HPP

#include "clustering/administration/auth/base_artificial_table_backend.hpp"

namespace auth {

class users_artificial_table_backend_t :
    public base_artificial_table_backend_t
{
public:
    users_artificial_table_backend_t(
        boost::shared_ptr<semilattice_readwrite_view_t<auth_semilattice_metadata_t>>
            auth_semilattice_view,
        boost::shared_ptr<semilattice_read_view_t<cluster_semilattice_metadata_t>>
            cluster_semilattice_view);

    bool read_all_rows_as_vector(
        signal_t *interruptor,
        std::vector<ql::datum_t> *rows_out,
        admin_err_t *error_out);

    bool read_row(
        ql::datum_t primary_key,
        signal_t *interruptor,
        ql::datum_t *row_out,
        admin_err_t *error_out);

    bool write_row(
        job_id_t job_id,
        ql::datum_t primary_key,
        bool pkey_was_autogenerated,
        ql::datum_t *new_value_inout,
        signal_t *interruptor,
        admin_err_t *error_out);
};

}  // namespace auth

#endif  // CLUSTERING_ADMINISTRATION_AUTH_USER_ARTIFICIAL_TABLE_BACKEND_HPP
