# C MUD Telnet/TLS Foundation

A small C17 networking, Telnet, login, and security foundation intended for
**MUD servers and other terminal-based multiplayer games written in C**.

This repository was split out of a larger C game server so the connection
boundary can be reviewed, tested, and reused without bringing along a complete
game engine. It focuses on the part many C MUD codebases eventually have to
solve themselves: socket lifecycle, Telnet framing and negotiation, terminal
capability discovery, protected and compatibility transports, credential
handling, and abuse controls.

It is **not a complete MUD engine** and it is not meant to dictate a game's
world, command, combat, or persistence architecture. The intended seam is that
a C MUD can embed or adapt this connection layer and attach its own account,
session, and game systems above it.

Maintained by [@riotcore](https://github.com/riotcore).

## Who this is for

This project is primarily aimed at:

- maintainers of existing C MUD codebases who want to modernize Telnet,
  transport security, and login handling without replacing the game;
- authors of new C MUD or text-multiplayer servers who want a conservative,
  testable Telnet foundation instead of ad-hoc socket parsing; and
- people reviewing MUD protocol, interoperability, terminal, or connection
  security behavior independently from a large game codebase.

The compatibility goal is deliberate: an old or very simple Telnet client
should still be able to reach the same game as a modern MUD client. Newer
features are progressive enhancements; refusing them must never make the login
path unusable.

The current development paths are:

```text
plain TCP --------> Telnet --\
                             +--> account/login --> authenticated session
TLS 1.3 ----------> Telnet --/

future SSH -----------------+--> the same account/session layer
```

Plain Telnet exists for compatibility. TLS Telnet is the preferred endpoint
because passwords sent over plain Telnet are not encrypted. SSH is an intended
sibling transport, not Telnet tunneled through SSH.

## What's here

The Telnet layer implements a streaming parser, NVT line rules, IAC escaping,
bounded subnegotiation, RFC 1143-style option state, BINARY,
SUPPRESS-GO-AHEAD, NAWS, TERMINAL-TYPE with bounded MTTS discovery,
bidirectional CHARSET/UTF-8 negotiation, EOR prompt markers,
NEW-ENVIRON/MNES capability discovery, and ECHO during password entry.
Negotiation starts immediately but never delays the first login prompt.

The receiver is intentionally tolerant of harmless, well-formed Telnet
behavior from old or unusual clients while remaining strict about malformed
framing, bounded buffers, input ceilings, and resource abuse.

The surrounding server adds shared connection limits across both listeners,
login backoff, account-creation limits, byte/line/command ceilings,
handshake/login/idle/session deadlines, private account files, Argon2id
password verifiers and hash upgrades, atomic credential updates, bounded audit
logging, and terminal-text filtering.

The local development client exercises the encrypted endpoint, Telnet option
state, MTTS/NEW-ENVIRON responses, CHARSET, NAWS changes, and terminal-text
filtering. It is a protocol test tool rather than an attempt to replace a real
MUD client.

## Code map

The public tree is intentionally divided by responsibility so a MUD can replace
one concern without quietly coupling itself to the others:

- `app/server_main.c` is only the local executable harness and default paths.
  A larger MUD would normally provide its own process entry point and config.
- `src/secure_server.c` / `include/secure_server.h` own sockets, listeners, TLS,
  worker lifetime, transport deadlines, and shared connection admission. They
  feed bytes into Telnet but do not implement Telnet framing.
- `src/telnet_protocol.c` / `include/telnet_protocol.h` own the Telnet byte
  stream, NVT rules, option/subnegotiation handling, terminal capabilities, and
  the small runnable login/session surface used by this standalone slice.
- `src/telnet_negotiation.c` owns only the RFC 1143 option state machine. Keeping
  option state separate from byte framing makes negotiation loops independently
  testable.
- `src/player_store.c` / `include/player_store.h` own credential persistence and
  password verification. They intentionally know nothing about TCP, TLS, or
  Telnet so future SSH can use the same account data.
- `src/security_policy.c` / `include/security_policy.h` own abuse/backoff state
  shared across listeners. Switching from the plain port to the TLS port must
  not bypass the same peer/account policy.
- `src/terminal_text.c` / `include/terminal_text.h` own terminal-safe untrusted
  text handling, independent of which transport delivered the session.
- `src/audit_log.c` / `include/audit_log.h` own bounded security-event logging,
  not gameplay history.
- `tests/` defines the behavioral contract; `tools/secure_client.c` is a local
  protocol exerciser rather than a player client.

The current standalone session still contains a minimal login/command loop so
this repository can be built and exercised by itself. In a larger game, account
and game-session ownership should sit above the Telnet adapter; that is also the
boundary that lets SSH become a sibling transport instead of Telnet-over-SSH.

## Why this shape

Telnet is kept as a compatibility floor rather than treated as the whole
application architecture. Terminal capabilities are represented as negotiated
facts so higher layers can eventually choose plain text, ANSI/256/truecolor,
accessible presentation, GMCP, or other enhancements without checking for a
particular client name.

That same separation is intended to let TLS, SSH, and later transports attach
to one account/game session instead of creating parallel versions of the game.
MSSP, GMCP, SSH, reconnectable game sessions, and browser transports are
planned work; they are **not** implemented by this repository yet.

## Modernizing an existing C MUD

This project is also an experiment in updating the connection boundary of an
older-style C MUD without requiring the game itself to be rewritten. Some of
the ideas here may be useful independently of this implementation:

- Separate socket and TLS ownership from Telnet parsing and from game-session
  logic. This makes it easier to add TLS, SSH, or another transport without
  creating another copy of the login or game.
- Treat plain Telnet as a compatibility floor and newer capabilities as
  progressive enhancements. A client that refuses every optional feature
  should still be able to play.
- Use an RFC 1143-style state machine for Telnet option negotiation instead of
  accumulating scattered `WILL`/`DO`/`WONT`/`DONT` flags and special cases.
- Keep network parsers bounded and persistent across partial reads. TCP does not
  preserve application message boundaries, so an `IAC` sequence or
  subnegotiation may arrive in pieces.
- Prefer capability checks over client-name checks. Detect UTF-8, terminal
  dimensions, color depth, accessibility needs, and protocol support directly
  where possible.
- Keep credentials independent from the transport so plain Telnet, TLS Telnet,
  and SSH can authenticate against the same account system.
- Centralize untrusted terminal-text handling instead of allowing player input
  to reach ANSI, OSC, or Telnet control paths directly.
- Compile with aggressive warnings, keep regression tests around protocol edge
  cases, and fuzz byte-oriented parsers where practical.
- Keep old-client tolerance separate from malformed-input tolerance. Harmless
  quirks can be ignored while framing, memory, rate, and resource limits remain
  strict.

These are design choices rather than requirements. Existing MUD codebases have
very different histories, and adopting one boundary at a time is often more
practical than attempting a networking rewrite.

## What I'd like reviewed

I'm especially interested in parser edge cases, transport lifecycle mistakes,
concurrency or ownership problems, memory/resource exhaustion, authentication
policy, filesystem races, terminal/Unicode handling, and tests I should add.

The code has been compiled with `-Wall -Wextra -Wpedantic -Werror`, checked with
Clang's static analyzer, exercised with ASan/UBSan, and run through libFuzzer.
Those checks are useful evidence. They aren't a security claim.

## Known development limits

Both listeners are currently IPv4 loopback-only. Public bind/firewall/
certificate handling and IPv6 listener work are outside the current local
harness.

Account identifiers currently accept 3-15 ASCII letters, digits, `_` or `-`.

Player passwords currently accept 8-128 characters. The built-in weak-password
list is small. A public deployment should use a maintained compromised-password
corpus as part of account policy.

Rate-limit state is held in fixed-size in-memory tables. The design bounds
memory use and fits the current single-process server. A public multi-process or
multi-host deployment would need shared policy state.

The development client exists for local testing. Dedicated text-game clients
are the expected real clients once the transports are exposed beyond localhost.

## Protocol references

The Telnet implementation follows the relevant protocol specifications,
including RFC 854 (Telnet), RFC 856 (BINARY), RFC 858 (SUPPRESS-GO-AHEAD), RFC
885 (EOR), RFC 1073 (NAWS), RFC 1091 (TERMINAL-TYPE), RFC 1143 (Q Method), RFC
1572 (NEW-ENVIRON), and RFC 2066 (CHARSET). MTTS and MNES are implemented as
bounded, optional MUD-client capability discovery on top of those Telnet
mechanisms.

Implementation work uses standards and the official OpenSSL/libsodium
interfaces as source material. Comparisons with established MUD servers are
used to find interoperability lessons, not as source code to transplant.

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

Start the server from the repository root:

```bash
./build/telnet_server
```

The development listeners are:

```text
127.0.0.1:3333  plain Telnet compatibility endpoint
127.0.0.1:3334  Telnet over TLS 1.3 (preferred)
```

A basic Telnet client can exercise the compatibility path directly:

```bash
telnet 127.0.0.1 3333
```

The included test client exercises the TLS path and defaults to port 3334:

```bash
./build/telnet_client
```

Account files are created under `data/players/` and audit output under `logs/`.
Both paths are ignored by Git.

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

## Recent changes

- **2026-08-09** — Clarified the project as a C17 MUD connection and
  protocol foundation and documented the ownership boundaries between
  transport, Telnet, credentials, security policy, and game code.
- **2026-08-09** — Added a plain Telnet listener alongside TLS 1.3, with both
  using the same Telnet and login path.
- **2026-08-09** — Expanded Telnet interoperability with EOR, bounded
  TTYPE/MTTS discovery, bidirectional CHARSET negotiation, and
  NEW-ENVIRON/MNES capability detection.
- **2026-08-09** — Made the Telnet receiver more tolerant of harmless legacy
  client behavior while retaining strict framing and resource limits.

See the Git history for detailed changes and implementation history.

## License

Copyright (c) 2026 riotcore.

This project is released under the MIT License. See `LICENSE` for the full terms.
