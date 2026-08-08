# Telnet/TLS server foundation in C

I'm publishing the networking and login slice of a larger C17 text-server
project because I want this layer reviewed before I build more application code
on top of it.

Maintained by [@riotcore](https://github.com/riotcore).

The server is still development-only and binds to `127.0.0.1:3333`. OpenSSL
handles TLS 1.3. libsodium handles Argon2id password hashing. The application
owns player accounts and login state.

The connection path is:

```text
TLS 1.3 -> Telnet -> account/login -> authenticated session
```

## What's here

The Telnet layer handles NVT line rules, IAC escaping, bounded
subnegotiation, RFC 1143-style option state, BINARY, SUPPRESS-GO-AHEAD, NAWS,
TERMINAL-TYPE, CHARSET/UTF-8 negotiation, ECHO during password entry, and the
core Telnet control commands used by the session.

The surrounding server adds connection limits, login backoff, account-creation
limits, byte/line/command ceilings, handshake/login/idle/session deadlines,
private account files, atomic credential updates, bounded audit-log rotation,
and terminal-text filtering.

The local development client verifies the development certificate, exercises
the same Telnet option state, tracks NAWS changes, and filters network text
before writing it to the terminal. It's a protocol test client with a small
feature set.

## What I'd like reviewed

I'm especially interested in parser edge cases, TLS lifecycle mistakes,
concurrency or ownership problems, memory/resource exhaustion, authentication
policy, filesystem races, terminal/Unicode handling, and tests I should add.

The code has been compiled with `-Wall -Wextra -Wpedantic -Werror`, checked with
Clang's static analyzer, exercised with ASan/UBSan, and run through libFuzzer.
Those checks are useful evidence. They aren't a security claim.

## Known development limits

The listener is IPv4 loopback-only. Public bind/firewall/certificate handling
is outside the current scope.

Player passwords currently accept 8-128 characters. The built-in weak-password
list is small. A public deployment should use a maintained compromised-password
corpus as part of account policy.

Rate-limit state is held in fixed-size in-memory tables. The design bounds
memory use and fits the current single-process server. A public multi-process or
multi-host deployment would need shared policy state.

The development client exists for local testing. Dedicated text-game clients
are the expected real clients once the transport is exposed beyond localhost.

## Protocol references

The Telnet implementation follows the relevant protocol specifications,
including RFC 854 (Telnet), RFC 856 (BINARY), RFC 858 (SUPPRESS-GO-AHEAD), RFC
1073 (NAWS), RFC 1091 (TERMINAL-TYPE), RFC 1143 (Q Method), and RFC 2066
(CHARSET).

Implementation work used the RFCs plus the official OpenSSL and libsodium
interfaces as source material. A later source comparison served as a provenance
check after this layer already existed.

## Build

On Ubuntu/Debian:

```bash
sudo apt install -y build-essential cmake pkg-config libsodium-dev libssl-dev

cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The normal test suite contains:

```text
security_test
player_store_test
telnet_test
```

The checks stay active even when `NDEBUG` is defined.

## Local TLS certificate

Runtime credentials are ignored by Git. For local testing:

```bash
mkdir -p local_tls

openssl req \
  -x509 \
  -newkey rsa:3072 \
  -sha256 \
  -nodes \
  -keyout local_tls/server.key \
  -out local_tls/server.crt \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

chmod 600 local_tls/server.key
chmod 644 local_tls/server.crt
```

Because TLS is established before Telnet negotiation, a plain telnet command won't connect directly. For local testing, use the included telnet_client.

Start the server from the repository root:

```bash
./build/telnet_server
```

Then run the local test client in another terminal:

```bash
./build/telnet_client
```

Account files will be created under `data/players/` and audit output under
`logs/`. Both paths are ignored by Git.

## Fuzzing

With Clang installed:

```bash
cmake \
  -S . \
  -B build-fuzz \
  -DENABLE_FUZZING=ON \
  -DCMAKE_C_COMPILER=clang

cmake --build build-fuzz --target telnet_fuzz
./build-fuzz/telnet_fuzz -max_total_time=60
```

## License

Copyright (c) 2026 riotcore.

This project is released under the MIT License. See `LICENSE` for the full terms.
