/* pgseccomp--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgseccomp" to load this file. \quit

CREATE FUNCTION seccomp_filter
(
  OUT syscall text,
  OUT syscallnum int4,
  OUT filter_action text,
  OUT context text
)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pg_get_seccomp_filter'
LANGUAGE C STABLE PARALLEL RESTRICTED;

REVOKE EXECUTE ON FUNCTION seccomp_filter() FROM PUBLIC;

CREATE FUNCTION set_client_filter
(
  default_action text,
  allow_list text,
  log_list text,
  error_list text,
  kill_list text
)
RETURNS text
AS 'MODULE_PATHNAME', 'pg_set_client_filter'
LANGUAGE C IMMUTABLE PARALLEL UNSAFE CALLED ON NULL INPUT;

REVOKE EXECUTE ON FUNCTION set_client_filter(text, text, text, text, text) FROM PUBLIC;
