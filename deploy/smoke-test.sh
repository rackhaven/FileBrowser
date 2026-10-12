#!/usr/bin/env bash
#
# smoke-test.sh - verify a deployed Files instance actually behaves.
#
#   FB_ADMIN_PASSWORD='...' ./smoke-test.sh https://files.example.com
#   FB_ADMIN_PASSWORD='...' ./smoke-test.sh http://127.0.0.1:8080
#
# Uses only bash, curl and coreutils, so it runs on a bare Debian install with
# nothing installed. Exits non-zero if any check fails.
#
# It creates its own fixtures through the API and removes them afterwards, so
# the only thing it needs is an admin account. It also creates and deletes a
# throwaway user to prove that per-folder permissions actually isolate people.

set -uo pipefail

BASE="${1:-http://127.0.0.1:8080}"
BASE="${BASE%/}"

ADMIN_USER="${FB_ADMIN_USER:-admin}"
if [ -z "${FB_ADMIN_PASSWORD:-}" ]; then
  echo "FB_ADMIN_PASSWORD must be set to the administrator's password" >&2
  exit 2
fi
ADMIN_PASS="$FB_ADMIN_PASSWORD"

RUN="smoke-$$-$(date +%s)"
TEST_USER="smokeuser$$"
TEST_PASS="smoke-$RUN-pass"
FILE_BODY="smoke-test-payload-$RUN"

TMP="$(mktemp -d)"
ADMIN_JAR="$TMP/admin.jar"
# A second admin session reserved for cleanup. The logout test at the end kills
# ADMIN_JAR, so cleanup must not depend on it or the fixtures would be left
# behind every run.
CLEANUP_JAR="$TMP/cleanup.jar"
USER_JAR="$TMP/user.jar"
CLEANUP_PATHS=()
CLEANUP_USERS=()

cleanup() {
  for u in "${CLEANUP_USERS[@]:-}"; do
    [ -n "$u" ] && curl -sS -b "$CLEANUP_JAR" -X DELETE \
      "$BASE/api/admin/users/$u" >/dev/null 2>&1
  done
  for p in "${CLEANUP_PATHS[@]:-}"; do
    [ -n "$p" ] && curl -sS -b "$CLEANUP_JAR" -X POST \
      "$BASE/api/fs/delete?path=$p" >/dev/null 2>&1
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

# ---------------------------------------------------------------- reporting --

if [ -t 1 ]; then G=$'\033[32m'; R=$'\033[31m'; B=$'\033[1m'; N=$'\033[0m'
else G=""; R=""; B=""; N=""; fi

PASS=0
FAIL=0
FAILED_NAMES=()

section() { printf '\n%s== %s ==%s\n' "$B" "$1" "$N"; }
ok()      { PASS=$((PASS+1)); printf '  %sPASS%s  %s\n' "$G" "$N" "$1"; }
bad()     { FAIL=$((FAIL+1)); FAILED_NAMES+=("$1"); printf '  %sFAIL%s  %s\n' "$R" "$N" "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }

# req <method> <url> [curl args...] -> sets HTTP_CODE and BODY
req() {
  local method="$1" url="$2"; shift 2
  local out
  out="$(curl -sS -o "$TMP/body" -w '%{http_code}' -X "$method" "$@" "$url" 2>"$TMP/err")"
  HTTP_CODE="$out"
  BODY="$(cat "$TMP/body")"
}

expect() { # expect <name> <want> <got>
  if [ "$3" = "$2" ]; then ok "$1  [$3]"; else bad "$1" "got $3, want $2"; fi
}

for tool in curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 2; }
done

printf '%sSmoke test%s  target=%s  as=%s\n' "$B" "$N" "$BASE" "$ADMIN_USER"

# ------------------------------------------------------------------ public --

section "Service is up"

req GET "$BASE/healthz"
expect "health endpoint responds" "200" "$HTTP_CODE"

req GET "$BASE/api/status"
expect "status endpoint responds" "200" "$HTTP_CODE"
case "$BODY" in
  *'"version"'*) ok "status reports a version" ;;
  *) bad "status reports a version" "$BODY" ;;
esac

req GET "$BASE/"
expect "web app shell is served" "200" "$HTTP_CODE"
case "$BODY" in
  *"<title>"*) ok "shell is HTML" ;;
  *) bad "shell is HTML" ;;
esac

req GET "$BASE/manifest.webmanifest"
expect "manifest is served" "200" "$HTTP_CODE"

req GET "$BASE/sw.js"
expect "service worker is served" "200" "$HTTP_CODE"

# ------------------------------------------------------------- unauthorised --

section "Unauthenticated access is refused"

for path in "/api/fs/list?path=/" "/api/auth/me" "/api/admin/users"; do
  req GET "$BASE$path"
  expect "no session: $path" "401" "$HTTP_CODE"
done

req GET "$BASE/api/fs/download?path=/etc/passwd"
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "404" ]; then
  ok "no session: download is refused  [$HTTP_CODE]"
else
  bad "no session: download is refused" "got $HTTP_CODE, want 401 or 404"
fi

# ------------------------------------------------------------------- login --

section "Sign in"

req POST "$BASE/api/auth/login" \
  -c "$ADMIN_JAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}"
expect "admin can sign in" "200" "$HTTP_CODE"

# A second session that survives the logout test, used only to remove fixtures.
req POST "$BASE/api/auth/login" \
  -c "$CLEANUP_JAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}"
expect "a second admin session for cleanup" "200" "$HTTP_CODE"

req POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"definitely-not-the-password\"}"
expect "a wrong password is rejected" "401" "$HTTP_CODE"

# ---------------------------------------------------------------- fixtures --

section "Create fixtures"

ALLOWED="$RUN/allowed"
DENIED="$RUN/denied.txt"

req POST "$BASE/api/fs/mkdir" -b "$ADMIN_JAR" -H 'Content-Type: application/json' \
  -d "{\"path\":\"/\",\"name\":\"$RUN\"}"
expect "create the test folder" "201" "$HTTP_CODE"
CLEANUP_PATHS+=("/$RUN")

req POST "$BASE/api/fs/mkdir" -b "$ADMIN_JAR" -H 'Content-Type: application/json' \
  -d "{\"path\":\"/$RUN\",\"name\":\"allowed\"}"
expect "create the allowed subfolder" "201" "$HTTP_CODE"

printf '%s' "$FILE_BODY" > "$TMP/payload"
req PUT "$BASE/api/fs/upload?path=%2F$RUN%2Fallowed&name=payload.txt" \
  -b "$ADMIN_JAR" --data-binary "@$TMP/payload"
expect "upload a file" "200" "$HTTP_CODE"

printf '%s' "$DENIED" > "$TMP/denied"
req PUT "$BASE/api/fs/upload?path=%2F$RUN&name=denied.txt" \
  -b "$ADMIN_JAR" --data-binary "@$TMP/denied"
expect "upload a file outside the grant" "200" "$HTTP_CODE"

# ------------------------------------------------------------ read and list --

section "Browse and download"

req GET "$BASE/api/fs/list?path=/$RUN/allowed" -b "$ADMIN_JAR"
expect "list the test folder" "200" "$HTTP_CODE"
case "$BODY" in
  *payload.txt*) ok "the uploaded file is listed" ;;
  *) bad "the uploaded file is listed" "$BODY" ;;
esac

req GET "$BASE/api/fs/download?path=/$RUN/allowed/payload.txt" -b "$ADMIN_JAR"
expect "download the file" "200" "$HTTP_CODE"
if [ "$BODY" = "$FILE_BODY" ]; then
  ok "downloaded content matches what was uploaded"
else
  bad "downloaded content matches" "got '$BODY', want '$FILE_BODY'"
fi

if curl -sS -o /dev/null -D "$TMP/h" -b "$ADMIN_JAR" \
     "$BASE/api/fs/download?path=/$RUN/allowed/payload.txt"; then
  grep -qi 'content-disposition:.*attachment' "$TMP/h" \
    && ok "downloads are sent as an attachment" \
    || bad "downloads are sent as an attachment" "$(grep -i content-disposition "$TMP/h")"
fi

# ------------------------------------------------------------ range requests --

section "Resumable downloads"

BODY="$(curl -sS -b "$ADMIN_JAR" -H 'Range: bytes=6-' \
  -o "$TMP/part" -w '%{http_code}' \
  "$BASE/api/fs/download?path=/$RUN/allowed/payload.txt")"
expect "a Range request returns 206" "206" "$BODY"
EXPECT_PART="${FILE_BODY#??????}"
if [ "$(cat "$TMP/part")" = "$EXPECT_PART" ]; then
  ok "the partial body is correct"
else
  bad "the partial body is correct" "got '$(cat "$TMP/part")', want '$EXPECT_PART'"
fi

# ------------------------------------------------------------------ writing --

section "Modify files"

req POST "$BASE/api/fs/rename" -b "$ADMIN_JAR" -H 'Content-Type: application/json' \
  -d "{\"from\":\"/$RUN/allowed/payload.txt\",\"to_dir\":\"/$RUN/allowed\",\"new_name\":\"renamed.txt\"}"
expect "rename a file" "200" "$HTTP_CODE"

req GET "$BASE/api/fs/download?path=/$RUN/allowed/renamed.txt" -b "$ADMIN_JAR"
expect "the renamed file downloads" "200" "$HTTP_CODE"

req POST "$BASE/api/fs/delete?path=/$RUN/allowed/renamed.txt" -b "$ADMIN_JAR" \
  -H 'Content-Type: application/json' -d '{}'
expect "delete a file" "200" "$HTTP_CODE"

req GET "$BASE/api/fs/download?path=/$RUN/allowed/renamed.txt" -b "$ADMIN_JAR"
expect "the deleted file is gone" "404" "$HTTP_CODE"

req POST "$BASE/api/fs/mkdir" -b "$ADMIN_JAR" -H 'Content-Type: application/json' \
  -d "{\"path\":\"/$RUN\",\"name\":\"throwaway\"}"
expect "create a folder to delete" "201" "$HTTP_CODE"
req POST "$BASE/api/fs/delete?path=/$RUN/throwaway" -b "$ADMIN_JAR" \
  -H 'Content-Type: application/json' -d '{}'
expect "delete a folder" "200" "$HTTP_CODE"

# ------------------------------------------------------------- path escapes --

section "Path traversal is contained"

# These are virtual paths. ".." clamps to the root, it never escapes, so the
# real system files must never come back.
for probe in \
  "/../../../../etc/passwd" \
  "/%2e%2e/%2e%2e/%2e%2e/etc/passwd" \
  "/..%2f..%2f..%2fetc%2fpasswd" \
  "/....//....//etc/passwd" \
  "/$RUN/../../etc/passwd"
do
  out="$(curl -sS -b "$ADMIN_JAR" -o "$TMP/t" -w '%{http_code}' \
    --path-as-is "$BASE/api/fs/download?path=$probe")"
  if [ "$out" = "200" ] && grep -qE 'root:x:|^[^ ]+:[^:]*:[0-9]+:' "$TMP/t"; then
    bad "traversal $probe" "LEAKED /etc/passwd"
  elif [ "$out" = "200" ]; then
    bad "traversal $probe" "returned 200 (should not resolve to a system file)"
  else
    ok "traversal $probe contained  [$out]"
  fi
done

req POST "$BASE/api/fs/mkdir" -b "$ADMIN_JAR" -H 'Content-Type: application/json' \
  -d "{\"path\":\"/$RUN\",\"name\":\"..\"}"
if [ "$HTTP_CODE" != "201" ]; then
  ok "a folder name of '..' is refused  [$HTTP_CODE]"
else
  bad "a folder name of '..' is refused" "it was accepted"
fi

req PUT "$BASE/api/fs/upload?path=%2F$RUN&name=..%2F..%2Fescaped.txt" \
  -b "$ADMIN_JAR" --data-binary "escaped"
if [ "$HTTP_CODE" != "200" ]; then
  ok "an upload filename with .. is refused  [$HTTP_CODE]"
else
  bad "an upload filename with .. is refused" "it was accepted"
fi

# ------------------------------------------------------- per-folder access --

section "Per-folder permissions isolate users"

req POST "$BASE/api/admin/users" -b "$ADMIN_JAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\",\"admin\":false,\"grants\":[{\"path\":\"/$ALLOWED\",\"level\":\"read\"}]}"
expect "create a user limited to $ALLOWED" "201" "$HTTP_CODE"
CLEANUP_USERS+=("$(printf '%s' "$BODY" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')")

req POST "$BASE/api/auth/login" -c "$USER_JAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\"}"
expect "the limited user can sign in" "200" "$HTTP_CODE"

req GET "$BASE/api/fs/list?path=/$ALLOWED" -b "$USER_JAR"
expect "the limited user can list its granted folder" "200" "$HTTP_CODE"

req GET "$BASE/api/fs/download?path=/$ALLOWED/payload.txt" -b "$USER_JAR"
# payload.txt was deleted above, so re-upload before checking.
printf '%s' "$FILE_BODY" > "$TMP/payload"
req PUT "$BASE/api/fs/upload?path=%2F$RUN%2Fallowed&name=payload.txt" \
  -b "$ADMIN_JAR" --data-binary "@$TMP/payload" >/dev/null
req GET "$BASE/api/fs/download?path=/$ALLOWED/payload.txt" -b "$USER_JAR"
expect "the limited user can download from its grant" "200" "$HTTP_CODE"

req GET "$BASE/api/fs/download?path=/$DENIED" -b "$USER_JAR"
expect "the limited user is refused outside its grant" "403" "$HTTP_CODE"

req GET "$BASE/api/fs/list?path=/$DENIED" -b "$USER_JAR"
if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "404" ]; then
  ok "the limited user cannot list outside its grant  [$HTTP_CODE]"
else
  bad "the limited user cannot list outside its grant" "got $HTTP_CODE"
fi

req GET "$BASE/api/fs/list?path=/$RUN" -b "$USER_JAR"
expect "the limited user can open the parent folder" "200" "$HTTP_CODE"
case "$BODY" in
  *denied.txt*) bad "the parent listing hides ungranted files" "denied.txt was visible" ;;
  *) ok "the parent listing hides ungranted files" ;;
esac

req GET "$BASE/api/fs/list?path=/" -b "$USER_JAR"
expect "the limited user can open the root" "200" "$HTTP_CODE"
case "$BODY" in
  *"$RUN"*) ok "a granted folder still shows in the root listing" ;;
  *) bad "a granted folder still shows in the root listing" "$RUN was not visible" ;;
esac

req POST "$BASE/api/fs/mkdir" -b "$USER_JAR" -H 'Content-Type: application/json' \
  -d "{\"path\":\"/$ALLOWED\",\"name\":\"nope\"}"
expect "the limited user cannot write in a read-only grant" "403" "$HTTP_CODE"

req GET "$BASE/api/admin/users" -b "$USER_JAR"
expect "the limited user cannot manage users" "403" "$HTTP_CODE"

# The limited user must be locked out of everything else, not just this folder.
req GET "$BASE/api/fs/list?path=/etc" -b "$USER_JAR"
if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "404" ]; then
  ok "the limited user is refused other top-level folders  [$HTTP_CODE]"
else
  bad "the limited user is refused other top-level folders" "got $HTTP_CODE"
fi

# --------------------------------------------------------- grant validation --

section "Grant validation"

req POST "$BASE/api/admin/users" -b "$ADMIN_JAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"badevil$$\",\"password\":\"$TEST_PASS\",\"grants\":[{\"path\":\"../etc\",\"level\":\"read\"}]}"
expect "a grant of ../etc is rejected" "400" "$HTTP_CODE"

req POST "$BASE/api/admin/users" -b "$ADMIN_JAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"badlevel$$\",\"password\":\"$TEST_PASS\",\"grants\":[{\"path\":\"/x\",\"level\":\"superuser\"}]}"
expect "an unknown access level is rejected" "400" "$HTTP_CODE"

req POST "$BASE/api/admin/users" -b "$ADMIN_JAR" -H 'Content-Type: application/json' \
  -d "{\"username\":\"weak$$\",\"password\":\"short\"}"
expect "a short password is rejected" "400" "$HTTP_CODE"

# ------------------------------------------------------------------ logout --

section "Sign out"

req POST "$BASE/api/auth/logout" -b "$ADMIN_JAR" -H 'Content-Type: application/json' -d '{}'
expect "logout succeeds" "200" "$HTTP_CODE"

req GET "$BASE/api/fs/list?path=/" -b "$ADMIN_JAR"
expect "the session is dead after logout" "401" "$HTTP_CODE"

# ------------------------------------------------------------------ verdict --

printf '\n%s%d passed, %d failed%s\n' "$B" "$PASS" "$FAIL" "$N"
if [ "$FAIL" -ne 0 ]; then
  printf '%sFailed:%s\n' "$R" "$N"
  for n in "${FAILED_NAMES[@]}"; do printf '  - %s\n' "$n"; done
  exit 1
fi
printf '%sAll checks passed.%s\n' "$G" "$N"
exit 0
