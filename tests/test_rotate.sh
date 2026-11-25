#!/usr/bin/env bash
# Tests for rotate with fake vault and podman that record their argv and stdin.
# Run: bash tests/test_rotate.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
rotate="$here/../rotate"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fails=0

fail() { echo "FAIL: $*"; fails=$((fails + 1)); }

mkdir -p "$work/bin"
cat >"$work/bin/vault" <<'EOF'
#!/usr/bin/env bash
state="$FAKE_STATE"
printf '%s\n' "vault $*" >>"$state/argv"
case "$*" in
  "kv metadata get -format=json app/db")
    [ -f "$state/version" ] || { echo "No value found at app/metadata/db" >&2; exit 2; }
    printf '{"data":{"current_version": %s, "max_versions": 0}}\n' "$(cat "$state/version")" ;;
  "kv put app/db username=acme password=-"|"kv patch app/db password=-")
    cat >"$state/vault-stdin"
    v=$(( $(cat "$state/version" 2>/dev/null || echo 0) + 1 ))
    echo "$v" >"$state/version"
    echo "== Secret Path ==" ;;
  *) echo "unexpected vault call: $*" >&2; exit 9 ;;
esac
EOF
cat >"$work/bin/podman" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "podman $*" >>"$FAKE_STATE/argv"
cat >"$FAKE_STATE/psql-stdin"
[ -z "${FAKE_DB_DOWN:-}" ] || { echo "connection refused" >&2; exit 2; }
echo "ALTER ROLE"
EOF
cat >"$work/bin/ssh" <<'EOF2'
#!/usr/bin/env bash
printf '%s\n' "ssh $*" >>"$FAKE_STATE/argv"
cat >"$FAKE_STATE/psql-stdin"
[ -z "${FAKE_DB_DOWN:-}" ] || { echo "ssh: connect to host: Connection timed out" >&2; exit 255; }
echo "ALTER ROLE"
EOF2
chmod +x "$work/bin/vault" "$work/bin/podman" "$work/bin/ssh"

run_rotate() { # stdin is passed through; prints stdout to $state/out
  PATH="$work/bin:$PATH" FAKE_STATE="$1" KVS_DB_CONTAINER=acme-db \
    "$BASH" "$rotate" >"$1/out" 2>"$1/err"   # the bash running this test (3.2 or later)
}

check_secret_handling() { # $1 state dir, $2 password
  local s="$1" pw="$2"
  if grep -qF -- "$pw" "$s/argv"; then fail "password on argv: $(cat "$s/argv")"; fi
  if grep -qF -- "$pw" "$s/out" "$s/err"; then fail "password printed"; fi
  [ "$(cat "$s/vault-stdin")" = "$pw" ] || fail "vault did not get the password on stdin"
  local q="'" qq="''"
  grep -qF -- "${pw//$q/$qq}" "$s/psql-stdin" || fail "psql did not get the password on stdin"
  grep -q "ALTER ROLE acme" "$s/psql-stdin" || fail "no ALTER ROLE acme in the SQL"
  [ "$(head -n1 "$s/psql-stdin")" = "SET log_min_error_statement = panic;" ] ||
    fail "SQL does not start with SET log_min_error_statement = panic;"
  [ "${3:-podman}" != podman ] || grep -q "^podman exec -i acme-db psql" "$s/argv" || fail "psql not run with podman exec -i"
}

# 1. First run: app/db does not exist, so rotate creates it with kv put.
s1="$work/s1"; mkdir -p "$s1"
pw1="Given-on-stdin-$RANDOM-first-rotation"
printf '%s\n' "$pw1" | run_rotate "$s1" || fail "rotate exited non-zero: $(cat "$s1/err")"
grep -q "^vault kv put app/db username=acme password=-$" "$s1/argv" || fail "first run did not use kv put"
check_secret_handling "$s1" "$pw1"
[ "$(tail -n1 "$s1/out")" = "1" ] || fail "first run should print version 1, got '$(cat "$s1/out")'"

# 2. Second run: app/db exists, so rotate patches it, and a quote in the password is safe.
pw2="It's-$RANDOM-second-rotation"
printf '%s\n' "$pw2" | run_rotate "$s1" || fail "second rotate exited non-zero: $(cat "$s1/err")"
grep -q "^vault kv patch app/db password=-$" "$s1/argv" || fail "second run did not use kv patch"
check_secret_handling "$s1" "$pw2"
grep -qF "It''s-" "$s1/psql-stdin" || fail "single quote not escaped in SQL"
[ "$(tail -n1 "$s1/out")" = "2" ] || fail "second run should print version 2, got '$(cat "$s1/out")'"

# 3. No password given: rotate generates one, and it still never reaches argv.
s3="$work/s3"; mkdir -p "$s3"; echo 4 >"$s3/version"
run_rotate "$s3" </dev/null || fail "generated rotate exited non-zero: $(cat "$s3/err")"
gen="$(cat "$s3/vault-stdin")"
[ "${#gen}" -ge 20 ] || fail "generated password too short"
check_secret_handling "$s3" "$gen"
[ "$(tail -n1 "$s3/out")" = "5" ] || fail "should print version 5, got '$(cat "$s3/out")'"

# 4. A password on stdin shorter than 20 characters is refused before anything changes.
s4="$work/s4"; mkdir -p "$s4"; echo 7 >"$s4/version"
set +e
printf '%s\n' "Short-$RANDOM" | run_rotate "$s4"
rc=$?
set -e
[ "$rc" -eq 2 ] || fail "short password should exit 2, got $rc"
grep -q "at least 20 characters" "$s4/err" || fail "short password message missing: $(cat "$s4/err")"
[ ! -s "$s4/argv" ] || fail "short password still called: $(cat "$s4/argv")"
[ "$(cat "$s4/version")" = "7" ] || fail "short password changed the Vault version"

# 5. KVS_DB_EXEC runs psql over SSH: the same podman exec -i on the instance, with the
#    password and SQL on stdin. Nothing runs podman locally.
s5="$work/s5"; mkdir -p "$s5"; echo 3 >"$s5/version"
pw5="Over-ssh-$RANDOM-fifth-rotation"
printf '%s\n' "$pw5" | KVS_DB_EXEC="ssh ec2-user@192.0.2.10 sudo podman exec -i acme-db" run_rotate "$s5" ||
  fail "rotate over SSH exited non-zero: $(cat "$s5/err")"
grep -qx "ssh ec2-user@192.0.2.10 sudo podman exec -i acme-db psql -q -v ON_ERROR_STOP=1 -U postgres -d acme" "$s5/argv" ||
  fail "KVS_DB_EXEC not used as the database command: $(cat "$s5/argv")"
if grep -q "^podman " "$s5/argv"; then fail "podman ran locally although KVS_DB_EXEC was set"; fi
check_secret_handling "$s5" "$pw5" ssh
[ "$(tail -n1 "$s5/out")" = "4" ] || fail "over SSH should print version 4, got '$(cat "$s5/out")'"

# 6. KVS_DB_EXEC is split on whitespace only: no glob expansion and no eval.
s6="$work/s6"; mkdir -p "$s6/cwd"; echo 1 >"$s6/version"; touch "$s6/cwd/should-not-appear"
pw6="No-glob-$RANDOM-sixth-rotation"
( cd "$s6/cwd" && printf '%s\n' "$pw6" |
  KVS_DB_EXEC='ssh  host-*  $(touch injected)  podman exec -i acme-db' run_rotate "$s6" ) ||
  fail "rotate with a literal glob exited non-zero: $(cat "$s6/err")"
grep -qxF 'ssh host-* $(touch injected) podman exec -i acme-db psql -q -v ON_ERROR_STOP=1 -U postgres -d acme' "$s6/argv" ||
  fail "KVS_DB_EXEC words were changed: $(cat "$s6/argv")"
[ ! -e "$s6/cwd/injected" ] || fail "KVS_DB_EXEC was evaluated by a shell"
check_secret_handling "$s6" "$pw6" ssh

# 7. Pre-flight: when the database cannot be reached, rotate stops before Vault changes.
s7="$work/s7"; mkdir -p "$s7"; echo 5 >"$s7/version"
set +e
printf '%s\n' "Db-down-$RANDOM-seventh-rotation" |
  FAKE_DB_DOWN=1 KVS_DB_EXEC="ssh ec2-user@192.0.2.10 sudo podman exec -i acme-db" run_rotate "$s7"
rc=$?
set -e
[ "$rc" -eq 3 ] || fail "database down should exit 3, got $rc"
if grep -qE "^vault kv (put|patch)" "$s7/argv"; then fail "database down still wrote to Vault: $(cat "$s7/argv")"; fi
[ "$(cat "$s7/version")" = "5" ] || fail "database down changed the Vault version"
grep -q "nothing was changed" "$s7/err" || fail "database down message missing: $(cat "$s7/err")"
[ "$(cat "$s7/psql-stdin")" = "SELECT 1;" ] || fail "pre-flight did not send SELECT 1 on stdin"
grep -qx "ssh ec2-user@192.0.2.10 sudo podman exec -i acme-db psql -q -v ON_ERROR_STOP=1 -U postgres -d acme" "$s7/argv" ||
  fail "pre-flight did not use KVS_DB_EXEC: $(cat "$s7/argv")"

if [ "$fails" -eq 0 ]; then echo "test_rotate.sh: 7 scenarios passed (bash $BASH_VERSION)"; else echo "test_rotate.sh: $fails failures"; exit 1; fi
