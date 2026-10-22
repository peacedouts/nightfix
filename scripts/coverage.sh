#!/usr/bin/env bash
# Summarises a coverage profile from
#   go test -coverpkg=./... -coverprofile=cover.out ./...
# and fails if total statement coverage is below the floor.
#
#   scripts/coverage.sh cover.out [floor-percent]
#
# Coverage is counted across packages: a statement in internal/controlplane
# that only the end-to-end tests run still counts as covered. Commands
# (cmd/*), the dev stub and test helpers are left out of the total.
set -euo pipefail
profile="${1:?usage: scripts/coverage.sh cover.out [floor]}"
floor="${2:-70}"

awk -v floor="$floor" '
  NR == 1 { next }                                  # "mode: ..."
  {
    # file.go:12.3,14.5 <statements> <count>
    split($1, loc, ":"); file = loc[1]
    pkg = file; sub(/\/[^\/]*$/, "", pkg); sub(/^github.com\/peacedouts\/nightfix\//, "", pkg)
    if (pkg ~ /^cmd\// || pkg ~ /devstub/ || pkg ~ /testdb/ || pkg ~ /auth0test/) next
    key = $1
    stmts[key] = $2
    if ($3 > 0) hit[key] = 1
    pkgOf[key] = pkg
  }
  END {
    for (k in stmts) {
      p = pkgOf[k]; total[p] += stmts[k]; all += stmts[k]
      if (k in hit) { cov[p] += stmts[k]; allCov += stmts[k] }
    }
    n = 0; for (p in total) names[++n] = p
    # insertion sort for stable output
    for (i = 2; i <= n; i++) { v = names[i]; j = i - 1; while (j > 0 && names[j] > v) { names[j+1] = names[j]; j-- } names[j+1] = v }
    printf "| Package | Coverage | Statements |\n|---|---:|---:|\n"
    for (i = 1; i <= n; i++) { p = names[i]; printf "| %s | %.1f%% | %d |\n", p, 100 * cov[p] / total[p], total[p] }
    pct = 100 * allCov / all
    printf "| **Total** | **%.1f%%** | %d |\n", pct, all
    if (pct < floor) { printf "\nCoverage %.1f%% is below the %s%% floor.\n", pct, floor; exit 1 }
  }
' "$profile"
