#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 riotcore
# SPDX-License-Identifier: MIT

set -Eeuo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="$(mktemp -d /tmp/telnet-public-release-check.XXXXXX)"
SERVER_PID=""

cleanup()
{
    if [[ -n "$SERVER_PID" ]]
    then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi

    rm -rf "$TMP_ROOT"
}

trap cleanup EXIT

fail()
{
    printf "FAIL: %s\n" "$*" >&2
    exit 1
}

need()
{
    command -v "$1" >/dev/null 2>&1 ||
        fail "required command not found: $1"
}

run_logged()
{
    label="$1"
    log="$2"
    shift 2

    echo
    echo "===== $label ====="

    if "$@" >"$log" 2>&1; then
        tail -n 12 "$log" || true
        echo "PASS: $label"
    else
        status=$?
        cat "$log" >&2
        printf "FAIL: %s exited with status %s\n" "$label" "$status" >&2
        return "$status"
    fi
}

cd "$REPO"

for command_name in \
    cmake \
    ctest \
    git \
    grep \
    timeout \
    python3 \
    openssl \
    ssh \
    ssh-keygen \
    setsid
do
    need "$command_name"
done

echo "===== RELEASE GUARDS ====="

git diff --check
echo "PASS: git diff check"

grep -Fq "## Roadmap and future considerations" README.md ||
    fail "README roadmap section missing"

grep -Fq "tests/fuzz_player_store.c" CMakeLists.txt ||
    fail "fuzz player store is not wired into CMake"

grep -Fq "Original project and implementation by **Riot" README.md ||
    fail "README attribution missing"

test -f CREDITS.md ||
    fail "CREDITS.md missing"

test -f include/terminal_application.h ||
    fail "terminal application interface missing"

test -f src/ssh_transport.c ||
    fail "SSH transport implementation missing"

test -f src/ssh_transport.h ||
    fail "SSH transport header missing"

test -f tests/protocol_extensions_test.c ||
    fail "protocol extension tests missing"

test -f tests/ssh_transport_test.c ||
    fail "SSH transport tests missing"

echo "PASS: repository release guards"

STRICT="$TMP_ROOT/strict"
SAN="$TMP_ROOT/sanitized"
FUZZ="$TMP_ROOT/fuzz"

run_logged     "STRICT CONFIGURE"     "$TMP_ROOT/strict-configure.log"     cmake         -S "$REPO"         -B "$STRICT"         -DCMAKE_BUILD_TYPE=Debug         "-DCMAKE_C_FLAGS=-Wall -Wextra -Wpedantic -Werror"

run_logged     "STRICT BUILD"     "$TMP_ROOT/strict-build.log"     cmake --build "$STRICT" -j

run_logged     "STRICT TESTS"     "$TMP_ROOT/strict-tests.log"     ctest --test-dir "$STRICT" --output-on-failure

run_logged     "ASAN UBSAN CONFIGURE"     "$TMP_ROOT/san-configure.log"     cmake         -S "$REPO"         -B "$SAN"         -DCMAKE_BUILD_TYPE=Debug         "-DCMAKE_C_FLAGS=-Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-omit-frame-pointer"         "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined"

run_logged     "ASAN UBSAN BUILD"     "$TMP_ROOT/san-build.log"     cmake --build "$SAN" -j

run_logged     "ASAN UBSAN TESTS"     "$TMP_ROOT/san-tests.log"     env         ASAN_OPTIONS=detect_leaks=1:abort_on_error=1         UBSAN_OPTIONS=halt_on_error=1         ctest --test-dir "$SAN" --output-on-failure

if command -v clang >/dev/null 2>&1
then
    run_logged         "LIBFUZZER CONFIGURE"         "$TMP_ROOT/fuzz-configure.log"         cmake             -S "$REPO"             -B "$FUZZ"             -DCMAKE_C_COMPILER=clang             -DENABLE_FUZZING=ON             -DCMAKE_BUILD_TYPE=Debug

    run_logged         "LIBFUZZER BUILD"         "$TMP_ROOT/fuzz-build.log"         cmake --build "$FUZZ" --target telnet_fuzz -j

    echo
    echo "===== 10 SECOND LIBFUZZER SMOKE ====="

    FUZZ_LOG="$TMP_ROOT/fuzz.log"

    set +e

    env         TERM=dumb         DEBUGINFOD_URLS=         timeout             --preserve-status             --signal=INT             --kill-after=5s             20s             "$FUZZ/telnet_fuzz"                 -max_total_time=10                 -timeout=5                 -max_len=4096                 -verbosity=0                 -print_final_stats=1                 >"$FUZZ_LOG" 2>&1

    FUZZ_STATUS=$?

    set -e

    if [[ "$FUZZ_STATUS" -ne 0 ]]
    then
        cat "$FUZZ_LOG" >&2
        fail "libFuzzer smoke exited with status $FUZZ_STATUS"
    fi

    grep -E         "Done [0-9]+ runs|stat::number_of_executed_units|stat::average_exec_per_sec|stat::new_units_added|stat::slowest_unit_time_sec|stat::peak_rss_mb"         "$FUZZ_LOG" ||
        tail -n 20 "$FUZZ_LOG"

    echo "PASS: libFuzzer smoke"
else
    echo
    echo "SKIP: clang not installed"
fi

if command -v clang >/dev/null 2>&1
then
    CLANG_STRICT="$TMP_ROOT/clang-strict"

    run_logged "STRICT CLANG CONFIGURE" "$TMP_ROOT/clang-configure.log" cmake -S "$REPO" -B "$CLANG_STRICT" -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug "-DCMAKE_C_FLAGS=-Wall -Wextra -Wpedantic -Werror"
    run_logged "STRICT CLANG BUILD" "$TMP_ROOT/clang-build.log" cmake --build "$CLANG_STRICT" -j
    run_logged "STRICT CLANG TESTS" "$TMP_ROOT/clang-tests.log" ctest --test-dir "$CLANG_STRICT" --output-on-failure
else
    echo
    echo "SKIP: clang not installed, strict Clang full tree"
fi

echo
echo "===== LIVE LOCALHOST TELNET TLS SSH IPV6 SMOKE ====="

RUNTIME="$TMP_ROOT/live"
mkdir -p "$RUNTIME"

openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -days 1 \
    -subj '/CN=localhost' \
    -keyout "$RUNTIME/server.key" \
    -out "$RUNTIME/server.crt" \
    >/dev/null 2>&1

chmod 600 "$RUNTIME/server.key"

ssh-keygen \
    -q \
    -t ed25519 \
    -N '' \
    -f "$RUNTIME/ssh_host_ed25519_key"

chmod 600 "$RUNTIME/ssh_host_ed25519_key"

(
    cd "$RUNTIME"

    exec "$STRICT/mud_terminal_server" \
        "$RUNTIME/server.crt" \
        "$RUNTIME/server.key" \
        "$RUNTIME/ssh_host_ed25519_key" \
        >"$RUNTIME/server.out" 2>&1
) &

SERVER_PID=$!

python3 - "$SERVER_PID" <<'PYWAIT'
import os
import socket
import ssl
import sys
import time

pid = int(sys.argv[1])

for _ in range(80):
    try:
        os.kill(pid, 0)
    except OSError:
        raise SystemExit(
            "reference server exited before smoke testing"
        )

    try:
        with socket.create_connection(
            ("127.0.0.1", 3333),
            timeout=0.2,
        ):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit(
        "reference server did not open IPv4 Telnet port 3333"
    )

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3

with socket.create_connection(
    ("127.0.0.1", 3334),
    timeout=3,
) as raw:
    with context.wrap_socket(
        raw,
        server_hostname="localhost",
    ) as tls:
        version = tls.version()

        if version != "TLSv1.3":
            raise SystemExit(
                f"expected TLSv1.3, got {version!r}"
            )

print("PASS: IPv4 TLS 1.3 handshake")

try:
    probe = socket.socket(
        socket.AF_INET6,
        socket.SOCK_STREAM,
    )

    probe.setsockopt(
        socket.IPPROTO_IPV6,
        socket.IPV6_V6ONLY,
        1,
    )

    probe.bind(("::1", 0))
except OSError:
    print("SKIP: IPv6 loopback unavailable")
else:
    probe.close()

    for port in (3333, 3334, 3335):
        sock = socket.socket(
            socket.AF_INET6,
            socket.SOCK_STREAM,
        )

        sock.settimeout(3)

        try:
            sock.connect(("::1", port))
        except OSError as exc:
            raise SystemExit(
                f"IPv6 listener [::1]:{port} unavailable: {exc}"
            )
        finally:
            sock.close()

    print("PASS: IPv6 loopback listeners")
PYWAIT

SMOKE_USER="MudRef9"
SMOKE_PASSWORD="MudRef-9f4c8a27!"

python3 - "$SMOKE_USER" "$SMOKE_PASSWORD" <<'PYTELNET'
import socket
import sys
import time

user = sys.argv[1].encode("ascii")
password = sys.argv[2].encode("ascii")

sock = socket.create_connection(
    ("127.0.0.1", 3333),
    timeout=5,
)

sock.settimeout(5)
buffer = b""


def wait_for(marker):
    global buffer

    deadline = time.monotonic() + 5

    while marker not in buffer:
        if time.monotonic() > deadline:
            raise SystemExit(
                f"timed out waiting for {marker!r}; "
                f"received {buffer[-800:]!r}"
            )

        try:
            part = sock.recv(4096)
        except socket.timeout:
            continue

        if not part:
            raise SystemExit(
                f"connection closed waiting for {marker!r}; "
                f"received {buffer[-800:]!r}"
            )

        buffer += part

    position = buffer.index(marker) + len(marker)
    buffer = buffer[position:]


def send_line(data):
    sock.sendall(data + b"\r\n")


wait_for(b"Player name:")
send_line(user)

wait_for(b"Create a password")
send_line(password)

wait_for(b"Confirm password:")
send_line(password)

wait_for(b"Authenticated terminal session.")

send_line(b"PING")
wait_for(b"PONG")

send_line(b"QUIT")
sock.close()

print(
    "PASS: plain Telnet no negotiation "
    "account and application smoke"
)
PYTELNET

printf '%s\n' \
    '#!/bin/sh' \
    "printf '%s\\n' '$SMOKE_PASSWORD'" \
    >"$RUNTIME/askpass.sh"

chmod 700 "$RUNTIME/askpass.sh"

printf '%s\n' \
    'PING' \
    'WHOAMI' \
    'CAPS' \
    'QUIT' \
    >"$RUNTIME/ssh-input.txt"

set +e

SSH_ASKPASS="$RUNTIME/askpass.sh" \
SSH_ASKPASS_REQUIRE=force \
DISPLAY=:1 \
setsid -w \
ssh -tt \
    -o LogLevel=ERROR \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o PubkeyAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o PreferredAuthentications=password \
    -o NumberOfPasswordPrompts=1 \
    -o ConnectTimeout=5 \
    -p 3335 \
    "$SMOKE_USER@127.0.0.1" \
    <"$RUNTIME/ssh-input.txt" \
    >"$RUNTIME/ssh.out" 2>&1

SSH_STATUS=$?

set -e

if ! grep -Fq "PONG" "$RUNTIME/ssh.out" ||
   ! grep -Fq "$SMOKE_USER" "$RUNTIME/ssh.out" ||
   ! grep -Fq "Authenticated terminal session." "$RUNTIME/ssh.out"
then
    cat "$RUNTIME/ssh.out" >&2
    printf 'ssh client exit status: %s\n' "$SSH_STATUS" >&2
    fail "SSH smoke did not reach the shared terminal application"
fi

echo "PASS: SSH shared terminal application smoke"

if ! kill -0 "$SERVER_PID" 2>/dev/null
then
    cat "$RUNTIME/server.out" >&2
    fail "reference server exited during live smoke testing"
fi

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

echo "PASS: live localhost protocol smoke"

echo
echo "===== COMPLETE RELEASE VALIDATION PASSED ====="
