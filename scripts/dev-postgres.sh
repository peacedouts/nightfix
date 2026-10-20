#!/usr/bin/env bash
# Start a throwaway local Postgres for development and the demo.
#
#   scripts/dev-postgres.sh start   # init (first time) and start on $PGPORT (default 54329)
#   scripts/dev-postgres.sh stop
#   scripts/dev-postgres.sh reset   # stop and delete the data directory
#
# Uses the Postgres server binaries already installed on the machine
# (pg_ctl / initdb). Prints the superuser DSN on start.
set -euo pipefail

PGPORT="${PGPORT:-54329}"
DATA="${NIGHTFIX_PGDATA:-${TMPDIR:-/tmp}/nightfix-pg}"

find_bin() {
  if command -v pg_ctl >/dev/null 2>&1; then dirname "$(command -v pg_ctl)"; return; fi
  for d in /usr/lib/postgresql/*/bin /opt/homebrew/opt/postgresql@*/bin /usr/local/opt/postgresql@*/bin; do
    [ -x "$d/pg_ctl" ] && { echo "$d"; return; }
  done
  echo "pg_ctl not found; install PostgreSQL 15+ server binaries" >&2; exit 1
}
BIN="$(find_bin)"

# Postgres refuses to run as root; fall back to the postgres system user.
as_pg() {
  if [ "$(id -u)" = "0" ]; then runuser -u postgres -- "$@"; else "$@"; fi
}

case "${1:-start}" in
  start)
    if [ ! -f "$DATA/PG_VERSION" ]; then
      mkdir -p "$DATA"
      [ "$(id -u)" = "0" ] && chown postgres "$DATA"
      as_pg "$BIN/initdb" -D "$DATA" -U postgres --auth=trust -E UTF8 >/dev/null
    fi
    if ! as_pg "$BIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1; then
      as_pg "$BIN/pg_ctl" -D "$DATA" -l "$DATA/server.log" -w \
        -o "-p $PGPORT -k $DATA -c listen_addresses=127.0.0.1" start >/dev/null
    fi
    echo "postgres://postgres@127.0.0.1:$PGPORT/postgres?sslmode=disable"
    ;;
  stop)
    as_pg "$BIN/pg_ctl" -D "$DATA" -m fast stop >/dev/null 2>&1 || true
    ;;
  reset)
    as_pg "$BIN/pg_ctl" -D "$DATA" -m fast stop >/dev/null 2>&1 || true
    rm -rf "$DATA"
    ;;
  *)
    echo "usage: $0 start|stop|reset" >&2; exit 2
    ;;
esac
