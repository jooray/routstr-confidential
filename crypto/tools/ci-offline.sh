#!/usr/bin/env bash
# The offline checks of the main repo: what .github/workflows/ci.yml runs on
# every push and pull request, runnable locally with the same result.
#
#   crypto/tools/ci-offline.sh            # from anywhere inside the checkout
#
# No provider, no node, no secrets, no network beyond fetching dependencies:
#   1. cargo test of the sidecar, cu-crypto, zkbench and twopc (--locked, release);
#   2. provider-profile-check.py --self-test (mocked transport);
#   3. the reference client's offline checks (src/{h2-selfcheck,h2-conn-test,
#      fork-selfcheck}.ts and every test/*-check.ts);
#   4. gen-client-roots.py regenerates the TLS fork's root store byte for byte;
#   5. every copy of a shared vector of crypto/conformance in this checkout is
#      byte-identical to the original;
#   6. a secret scan of the files git would see (tracked and untracked, not
#      ignored): key shapes, and the value of every *_API_KEY variable set in
#      the environment. A hit prints the file and line, never the match.
#
# Every step runs; the exit status is non-zero if any failed.
# Environment: CI=true installs the client's dependencies with `npm ci` (locally
# that happens only when crypto/client/node_modules is missing).
# CU_CI_SKIP_CARGO=1 skips step 1 (for a quick rerun of the others).
set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CRYPTO=$ROOT/crypto
TMP=$(mktemp -d "${TMPDIR:-/tmp}/ci-offline.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
FAILED=()

step() { printf '\n== %s\n' "$1"; }
pass() { printf 'PASS %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; FAILED+=("$1"); }

# 1. Rust unit tests
step "cargo test (cu-sidecar, cu-crypto, zkbench, twopc)"
if [ "${CU_CI_SKIP_CARGO:-0}" = 1 ]; then
  echo "skipped (CU_CI_SKIP_CARGO=1)"
elif (cd "$CRYPTO" && cargo test --locked --release --no-fail-fast -p cu-sidecar -p cu-crypto -p zkbench -p twopc); then
  pass "cargo test"
else
  fail "cargo test"
fi

# 2. provider profile check, negative controls offline
step "provider-profile-check.py --self-test"
if python3 -I "$CRYPTO/tools/provider-profile-check.py" --self-test > "$TMP/profile.log" 2>&1; then
  tail -1 "$TMP/profile.log"; pass "provider-profile-check --self-test"
else
  cat "$TMP/profile.log"; fail "provider-profile-check --self-test"
fi

# 3. reference client, offline checks
step "reference client offline checks"
CLIENT=$CRYPTO/client
deps_ok=1
if [ "${CI:-}" = true ] || [ ! -d "$CLIENT/node_modules" ]; then
  if ! (cd "$CLIENT" && npm ci --no-audit --no-fund); then
    fail "npm ci (crypto/client)"; deps_ok=0
  fi
fi
if [ "$deps_ok" = 1 ]; then
  checks=(src/h2-selfcheck.ts src/h2-conn-test.ts src/fork-selfcheck.ts)
  for f in "$CLIENT"/test/*-check.ts; do
    [ -e "$f" ] && checks+=("test/${f##*/}")
  done
  for c in "${checks[@]}"; do
    if (cd "$CLIENT" && node --experimental-strip-types "$c") > "$TMP/client.log" 2>&1; then
      printf 'PASS client %s: %s\n' "$c" "$(tail -1 "$TMP/client.log")"
    else
      cat "$TMP/client.log"; fail "client $c"
    fi
  done
fi

# 4. the client's root store is what gen-client-roots.py makes of the pinned webpki-roots
step "client root store equals gen-client-roots.py output"
ROOTS=$CLIENT/vendor/tls/lib/utils/mozilla-root-cas.js
if (cd "$CRYPTO" && cargo fetch --locked > "$TMP/fetch.log" 2>&1) \
   && python3 -I "$CRYPTO/tools/gen-client-roots.py" "$TMP/roots.js" \
   && cmp -s "$TMP/roots.js" "$ROOTS"; then
  pass "root store"
else
  [ -s "$TMP/fetch.log" ] && tail -5 "$TMP/fetch.log"
  fail "root store (regenerate: crypto/tools/gen-client-roots.py ${ROOTS#$ROOT/})"
fi

# 5. shared vectors: every copy in this checkout is byte-identical
step "shared vectors are byte-identical in every copy"
cd "$ROOT"
ALLFILES=$TMP/files
git ls-files -co --exclude-standard > "$ALLFILES"
vec_ok=1
for v in crypto/conformance/*; do
  [ -f "$v" ] || continue
  name=${v##*/}
  copies=0
  while IFS= read -r c; do
    [ "$c" = "$v" ] && continue
    [ -f "$c" ] || continue
    copies=$((copies + 1))
    if cmp -s "$v" "$c"; then
      echo "same  $c"
    else
      echo "DIFF  $c (differs from $v)"; vec_ok=0
    fi
  done < <(grep -E "(^|/)${name//./\\.}\$" "$ALLFILES")
  # The SDK and browser-library checkouts, when present beside this one (git-ignored here).
  for c in "routstr-sdk/tests/unit/fixtures/$name" "../routstr-confidential-web/test/fixtures/$name"; do
    [ -f "$c" ] || continue
    copies=$((copies + 1))
    if cmp -s "$v" "$c"; then echo "same  $c"; else echo "DIFF  $c (differs from $v)"; vec_ok=0; fi
  done
  echo "$v: $copies cop$([ $copies = 1 ] && echo y || echo ies)"
done
if [ "$vec_ok" = 1 ]; then pass "shared vectors"; else fail "shared vectors"; fi

# 6. secret scan
step "secret scan"
PATTERN='nsec1[02-9ac-hj-np-z]{58}|cashu[AB][A-Za-z0-9_=-]{60,}|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----|sk-[A-Za-z0-9_-]{32,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|xox[abprs]-[A-Za-z0-9-]{10,}'
sec_ok=1
hits=$(git grep --untracked -nIE "$PATTERN" | cut -d: -f1,2)
if [ -n "$hits" ]; then
  echo "key-shaped strings at (match not shown):"; echo "$hits"; sec_ok=0
fi
for var in $(env | sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*_API_KEY\)=.*/\1/p'); do
  val=${!var}
  [ ${#val} -ge 16 ] || continue
  files=$(git grep --untracked -lIF -e "$val")
  if [ -n "$files" ]; then
    echo "the value of \$$var occurs in:"; echo "$files"; sec_ok=0
  fi
done
if [ "$sec_ok" = 1 ]; then pass "secret scan"; else fail "secret scan"; fi

printf '\n'
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "ci-offline: all steps passed"
else
  echo "ci-offline: ${#FAILED[@]} failed:"; printf '  %s\n' "${FAILED[@]}"
  exit 1
fi
