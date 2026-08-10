# mud-terminal-core

A small, reviewable **C17 connection and terminal-protocol foundation for MUD
servers and other terminal-based multiplayer games written in C**.

This project is meant to fill the space between a tiny raw-socket example and a
complete MUD engine. It shows one practical way to accept several clients,
separate transport from Telnet, negotiate useful terminal capabilities, share
credentials and abuse policy across transports, and hand an authenticated
terminal session to application code without making the application understand
IAC bytes, TLS records, or SSH packets.

It is **not** a complete game server and it is not intended to prescribe a
world, command, combat, character, or game-persistence architecture. The
included application is deliberately tiny so the connection boundary remains
visible.

Original project and implementation by **Riot / [riotcore](https://github.com/riotcore)**.
Released for use, study, adaptation, and review by the MUD community.

## Why this exists

A basic C socket example can demonstrate `socket()`, `bind()`, `listen()`,
`accept()`, `recv()`, and `send()` in a page or two. A long-running MUD has to
answer quite a few more questions:

- How do new players keep connecting when an existing client is slow or idle?
- Where does TCP/TLS/SSH ownership end and Telnet or application logic begin?
- How do you negotiate Telnet options without WILL/DO loops?
- What happens when `IAC`, UTF-8, or subnegotiation arrives across several TCP
  reads?
- How much odd but harmless behavior should an old client be allowed to send?
- Which bounds stop a peer from consuming unlimited input buffers, workers,
  password hashes, or audit-log space?
- How do terminal width, UTF-8, color depth, screen-reader hints, GMCP, or OSC 8
  become capabilities instead of client-name special cases?
- How can Telnet, Telnet-over-TLS, and SSH reach one application rather than
  growing into three copies of the server?

The goal is to keep the networking side understandable and bounded without
forcing a particular MUD architecture. It includes the surrounding connection
code as well as the Telnet parser.

## Design rules

A few rules drive the implementation more than any individual feature:

1. **Basic Telnet is the compatibility floor.** A client that negotiates no
   optional feature can still reach the account/login path.
2. **Modern features are progressive enhancements.** UTF-8, richer color,
   GMCP, OSC 8, TLS, and SSH improve the connection without redefining the
   game's basic text interface.
3. **Transport, Telnet, credentials, and application state are different
   concerns.** They are kept apart so one can change without quietly rewriting
   the others.
4. **TCP is a stream.** Parsers retain state across reads and never assume one
   `recv()` call equals one Telnet command or one user line.
5. **State is bounded.** Subnegotiation, input lines, rates, workers, account
   attempts, audit logs, and session lifetimes all have explicit ceilings.
6. **Send strictly; receive pragmatically.** Harmless, well-framed legacy
   behavior is ignored where possible. Malformed framing, repeated abuse, and
   resource exhaustion are not.
7. **Cryptography belongs to cryptographic libraries.** OpenSSL, libsodium, and
   libssh own TLS, Argon2id, and SSH cryptography respectively.
8. **The application sees capabilities, not protocol trivia.** Higher layers
   should ask whether UTF-8, truecolor, GMCP, or OSC 8 is available rather than
   ask whether the client happens to be Mudlet, TinTin++, or something else.

## Architecture at a glance

```text
plain TCP --------------------> Telnet adapter ---\
                                                \
TLS 1.3 over TCP -------------> Telnet adapter ----> terminal_application
                                                  /         |
SSH over TCP -----------------> libssh adapter ----/          v
                                                    your account/session/game
```

The standalone harness still performs its small Telnet account dialogue inside
the Telnet adapter. Once an account is authenticated, Telnet and SSH both meet
at `terminal_application`.

That interface carries account name, terminal capabilities, complete input
lines, trusted text and prompts, optional GMCP, optional links, and close
notification. A MUD can replace the harness without exposing transport framing
to its game systems.

## Connection and concurrency model

The reference server uses a deliberately simple model:

- one IPv4 loopback listener for plain Telnet;
- one IPv4 loopback listener for Telnet over TLS 1.3;
- one IPv4 loopback listener for SSH;
- `poll()` watches **the listener sockets**, not every connected client;
- each accepted connection is handed to a detached worker thread;
- a single process-wide active-connection cap bounds those workers;
- connection-start and authentication policy is shared across all transports.

This means a player who stops reading or typing can block their own worker, but
not the listener loop that accepts everyone else. The worker cap makes the
thread-per-connection choice explicit and bounded rather than accidental.

That is a reasonable reference model for modest MUD concurrency and makes the
ownership easy to follow in C. It is not a claim that one thread per player is
the right answer at every scale. A larger deployment can keep the protocol and
application boundaries while replacing the worker model with a thread pool,
`epoll`/`kqueue`, or another event architecture.

## Transports

### Plain Telnet

Default development endpoint: `127.0.0.1:3333`.

Plain Telnet exists because compatibility matters. It feeds the same Telnet
parser and account records as the protected Telnet endpoint.

It is **not confidential**. Suppressing password echo only stops the password
from being displayed locally; it does not encrypt the bytes on the network. The
server prints a one-time warning before password entry on this transport.

### Telnet over TLS 1.3

Default development endpoint: `127.0.0.1:3334`.

OpenSSL owns TLS. The server requires TLS 1.3 for this endpoint, applies a finite
handshake deadline, and then passes decrypted bytes to exactly the same Telnet
adapter used by the plain listener.

TLS is a transport property here, not a second Telnet implementation.

### SSH

Default development endpoint: `127.0.0.1:3335`.

SSH is implemented with **libssh as a sibling terminal transport**. It is not
Telnet tunneled through an SSH channel.

The first SSH slice is intentionally narrow:

- password authentication against the same existing account records used by
  Telnet;
- one interactive session channel;
- PTY terminal type and terminal dimensions;
- live window-size changes;
- `LANG`/`LC_CTYPE` and `COLORTERM` accepted only as terminal-capability hints;
- line-oriented input with small local editing support;
- the same `terminal_application` hooks reached after authentication.

It deliberately does **not** provide an operating-system shell, process
execution, SFTP, arbitrary subsystems, port forwarding, or a process
environment. SSH `shell` means “start the MUD terminal application.” `exec`,
subsystem, and `direct-tcpip` requests are rejected.

SSH public-key authentication is not implemented yet. SSH currently authenticates
against an account that already exists in the credential store.

## Telnet/NVT behavior

`src/telnet_protocol.c` is a persistent streaming parser. Important properties
include:

- IAC handling across arbitrary read boundaries;
- doubled-IAC data escaping;
- NVT CR/LF and CR/NUL handling;
- bounded subnegotiation storage;
- bounded protocol-violation handling;
- RFC 1143 Q-method option state rather than scattered WILL/DO flags;
- negotiation beginning immediately without delaying the login prompt;
- refusal of an optional feature never blocking basic login.

The receiver intentionally distinguishes *old-client tolerance* from
*malformed-input tolerance*. A harmless unknown command or option can be
ignored. Unbounded framing, repeated malformed input, and resource abuse still
have limits.

## Telnet options and MUD-facing extensions

Current protocol support includes:

| Feature | Purpose in this reference |
| --- | --- |
| ECHO | Server-side password-entry echo control. |
| SUPPRESS-GO-AHEAD | Conventional interactive Telnet behavior. |
| BINARY | Clean 8-bit data path when negotiated. |
| NAWS | Terminal columns and rows. |
| TERMINAL-TYPE | Terminal identity plus bounded MTTS discovery. |
| MTTS | ANSI/UTF-8/color/screen-reader and related capability hints. |
| CHARSET | Bidirectional UTF-8 negotiation for client compatibility. |
| EOR | Explicit prompt boundary when supported, with GA fallback. |
| NEW-ENVIRON | Bounded client capability/environment discovery. |
| MNES | MUD-oriented NEW-ENVIRON capability reporting. |
| MSSP | Small server-status snapshot from an application callback. |
| GMCP | Bounded framing, package extraction, application delivery, and Core.Ping. |
| OSC 8 | Safe hyperlink output when the client explicitly advertises support. |

### Bounded MTTS discovery

TERMINAL-TYPE can cycle through client-reported values. This implementation
caps discovery at four requests rather than asking indefinitely. Capabilities
are accumulated conservatively from the bounded results.

### CHARSET

The adapter accepts the traditional client-originated CHARSET path and can also
initiate UTF-8 negotiation. Supporting both directions costs little and avoids
making one historical client convention the only valid path.

### NEW-ENVIRON / MNES

The implementation requests a small set of terminal facts it knows how to use,
including client name/version, terminal type, color/UTF-8/accessibility hints,
and OSC 8 capability variables. Updates can change the live capability object
after authentication.

Unknown values are not treated as a reason to fail the session.

### MSSP

The protocol layer owns MSSP framing. The application supplies a snapshot of
values such as server name, player count, uptime, codebase, and advertised
Telnet/TLS ports.

The reference harness intentionally reports only data it actually knows. A real
MUD should fill the snapshot from its own runtime state rather than teach the
Telnet parser about game globals.

### GMCP

This repository implements the **wire mechanism**, not a made-up game API:

- Telnet GMCP option negotiation;
- bounded package/message parsing;
- delivery of parsed package + JSON payload to `terminal_application`;
- bounded outbound GMCP;
- `Core.Ping` response behavior.

Packages such as room, character, inventory, combat, or media data belong to
the integrating MUD because only that MUD knows what those objects mean.

### OSC 8

The server learns OSC 8 hyperlink support through NEW-ENVIRON/MNES and emits
links only when the client advertises the required capability.

Visible link text remains useful without OSC 8. Player-authored/untrusted text
should pass through `terminal_text` and never gain the ability to manufacture
server-trusted ANSI/OSC control sequences.

The reference currently supports conservative hyperlink output and capability
bits for basic links plus the advertised `send:`, `prompt:`, and tooltip-related
features it recognizes. Rich client-specific UI belongs above this layer.

## Shared terminal application seam

### Owner-thread application polling

`terminal_application_hooks.poll` is an optional post-authentication callback. Telnet, Telnet/TLS, and SSH invoke it only from the connection's owning worker thread. An application can therefore drain queued asynchronous output without a publisher thread writing another session's socket, TLS object, or SSH channel. The reference workers check for queued application work on a 250 ms cadence.

`include/terminal_application.h` is the transport/application handoff.

The application receives a `terminal_capabilities` snapshot with terminal
geometry, UTF-8/color/accessibility facts, transport security, client metadata,
and optional Telnet enhancements. Capability changes can be delivered later as
NAWS, NEW-ENVIRON, or SSH window/PTY information changes.

The output side intentionally separates ordinary text from optional protocol
features:

- trusted text;
- prompts;
- orderly close requests;
- GMCP, when the transport supports it;
- links, with plain visible text as the fallback.

GMCP is a Telnet option, so the SSH adapter reports that output mechanism as
unavailable. Likewise, the SSH adapter does not guess OSC 8 support merely from
a client banner.

## Security and resource boundaries

This is reference code, not a security certification. The implementation tries
to make important limits visible and testable:

- TLS 1.3 delegated to OpenSSL;
- SSH cryptography/key exchange delegated to libssh;
- password verification delegated to libsodium Argon2id;
- private credential directory/files;
- atomic account creation/update behavior;
- verifier rehash after successful login when work parameters need upgrading;
- shared peer/account authentication backoff across transports;
- bounded global and per-peer connection starts;
- bounded account creation;
- bounded input lines, byte rates, line rates, and command rates;
- bounded Telnet subnegotiation and GMCP payloads;
- authentication, idle, and maximum-session deadlines;
- finite socket/TLS shutdown/write behavior;
- fixed-size abuse-policy tables;
- bounded, rotated audit logging;
- terminal-control filtering for untrusted text;
- SSH host-key validation before the listener starts.

The SSH host key must be a regular file owned by the server user and must not be
group- or world-accessible. Symlink host-key paths are rejected.

The reference server also refuses to run as root. A real deployment should use
a dedicated unprivileged service account and make its external bind/firewall/
certificate policy explicit.

## Code map

The tree is organized so a reader can tell who owns what without tracing every
call first:

- `app/server_main.c` — runnable example and development defaults. It wires the
  listeners to the harness application and supplies a small MSSP snapshot. A
  MUD can replace this file with its own startup and configuration code.
- `app/harness_application.c` — small post-authentication terminal application
  used to exercise the same interface from Telnet and SSH.
- `include/terminal_application.h` — transport-neutral post-authentication seam
  for account name, terminal capabilities, input lines, and trusted output.
- `src/secure_server.c` / `include/secure_server.h` — listener sockets, TLS,
  bounded worker lifetime, transport deadlines, shared admission, and the SSH
  handoff. This file does not parse Telnet or SSH packets.
- `src/ssh_transport.c` — libssh-facing adapter: SSH authentication, one session
  channel, PTY/window handling, bounded line input, and application handoff. It
  never launches an OS shell.
- `src/telnet_protocol.c` / `include/telnet_protocol.h` — Telnet/NVT byte stream,
  subnegotiation, terminal capability discovery, MSSP/GMCP/OSC 8 support, and
  the small standalone Telnet account dialogue.
- `src/telnet_negotiation.c` — RFC 1143 option state only. Keeping it separate
  makes negotiation loops testable without the rest of the parser.
- `src/player_store.c` / `include/player_store.h` — account-name/password policy,
  Argon2id verifier persistence, atomic writes, and rehash upgrades. It has no
  socket/TLS/Telnet/SSH packet logic.
- `src/security_policy.c` / `include/security_policy.h` — process-wide peer and
  account abuse/backoff state shared by every listener.
- `src/terminal_text.c` / `include/terminal_text.h` — transport-independent
  filtering of untrusted terminal text.
- `src/audit_log.c` / `include/audit_log.h` — bounded security-event log, not
  gameplay history.
- `tests/` — behavioral contracts for security policy, credential persistence,
  Telnet negotiation/parser behavior, and the MUD-facing protocol extensions.
- `tools/secure_client.c` — local TLS/Telnet exerciser, not a replacement player
  client.

## Adapting it to an existing C MUD

The least disruptive integration path is usually incremental:

1. Keep the existing game loop, world, commands, characters, and persistence.
2. Replace the reference `app/server_main.c` with your own process lifecycle and
   configuration.
3. Implement `terminal_application_hooks` as the handoff into your account or
   game-session manager.
4. Map `terminal_capabilities` into whatever presentation state your MUD already
   uses instead of exposing Telnet option state to game code.
5. Adapt or replace `player_store` if your MUD already owns accounts. The
   important property is that all transports reach one credential/account
   owner rather than duplicating passwords per transport.
6. Keep game-specific GMCP packages and clickable-game behavior in the game.
   The reusable layer should only know how to carry them safely.
7. Replace the reference worker/listener policy if your deployment needs a
   different scaling model; the Telnet and terminal-application seams do not
   require thread-per-connection.

The repository is intentionally small enough that adopting one boundary at a
time is reasonable.

## Modernizing an older C MUD

Some design choices can be useful even if you do not use this code directly:

- Treat Telnet framing as a persistent parser, not a collection of `recv()`
  assumptions.
- Use RFC 1143-style option state rather than scattered WILL/DO/WONT/DONT flags.
- Separate plaintext compatibility from malformed-input tolerance.
- Put hard bounds on parser buffers and on expensive work such as connection
  starts and password hashing.
- Keep credentials independent from Telnet/TLS/SSH.
- Centralize terminal-safe handling of player-authored text.
- Model terminal features as capabilities instead of client-name hacks.
- Keep plain text complete; let GMCP/OSC 8/color enhance it.
- Keep transport adapters small enough that adding SSH does not create a second
  command loop or a second game.
- Compile with aggressive warnings and put byte-oriented parsers under
  regression tests, sanitizers, and fuzzing.

Older MUD codebases vary a lot. These pieces can be adopted individually without
requiring a rewrite of the game.

## Roadmap and future considerations

### Deliberate non-features and current limits

The current reference is intentionally not everything a production MUD might
want:

- reference listeners bind both IPv4 and IPv6 loopback by default, keeping the example local unless an integrator deliberately changes the bind policy;
- the reference concurrency model is bounded thread-per-connection;
- SSH currently supports password authentication, not account-bound public
  keys;
- SSH is not a Unix shell, SFTP server, forwarding endpoint, or command-exec
  service;
- there is no browser/WebSocket endpoint;
- no native MSDP, ATCP, MSP, or MXP implementation is included;
- MCCP is not enabled without a measured need for compression;
- GMCP intentionally stops at generic framing/Core behavior instead of defining
  game-specific packages;
- OSC 8 is preferred for focused hyperlink behavior; MXP would be a future
  compatibility decision rather than the default rich-output architecture.

Account identifiers currently accept 3-15 ASCII letters, digits, `_`, or `-`.
Passwords accept 8-128 bytes. The built-in weak-password list is intentionally
small; an Internet-facing deployment should define a stronger breached-password
policy appropriate to the service.

Rate-limit state lives in fixed-size in-memory tables. A multi-process or
multi-host deployment would need a shared policy store if limits must span
processes or hosts.

## Release validation

Before publishing or tagging a revision, run:

    ./tools/release_check.sh

The release check performs strict GCC and, when available, Clang warning as error builds, the deterministic test suite, AddressSanitizer and UndefinedBehaviorSanitizer passes, a time bounded libFuzzer parser smoke, and live localhost Telnet, TLS 1.3, SSH, and IPv6 checks when IPv6 loopback is available.

The fuzz smoke disables remote debuginfod lookup for its process so coverage symbolization does not depend on an external debug symbol service.

## Build

On Ubuntu/Debian:

```bash
sudo apt install -y \
  build-essential \
  cmake \
  pkg-config \
  libsodium-dev \
  libssl-dev \
  libssh-dev

# The SSH adapter uses the libssh 0.10+ server callback/API surface.
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The normal test suite includes:

```text
security_test
player_store_test
telnet_test
protocol_extensions_test
ssh_transport_test
```

Assertions used by the tests remain active even if `NDEBUG` is defined.

## Local credentials

Runtime credentials and state are ignored by Git.

### TLS certificate

For local testing:

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

### SSH host key

Generate a local Ed25519 host key:

```bash
mkdir -p local_ssh
ssh-keygen -q -t ed25519 -N '' -f local_ssh/ssh_host_ed25519_key
chmod 600 local_ssh/ssh_host_ed25519_key
```

The private key must be owned by the user running the reference server and must
not be group/world accessible.

## Run locally

Start from the repository root:

```bash
./build/mud_terminal_server
```

Default development listeners:

```text
127.0.0.1:3333  plain Telnet compatibility endpoint
127.0.0.1:3334  Telnet over TLS 1.3 (preferred Telnet endpoint)
127.0.0.1:3335  SSH terminal endpoint
```

A basic Telnet client can exercise the compatibility path:

```bash
telnet 127.0.0.1 3333
```

The included test client exercises the TLS/Telnet path:

```bash
./build/telnet_client
```

Create an account through either Telnet endpoint. The initial SSH implementation
then authenticates that same account with its password:

```bash
ssh -p 3335 AccountName@127.0.0.1
```

The SSH endpoint is an application terminal, so commands such as SFTP, remote
`exec`, or port forwarding are intentionally not available.

Once authenticated through Telnet, Telnet/TLS, or SSH, the reference harness
accepts a small command set. `PING` replies with `PONG`, `HELP` lists the
available commands, and `QUIT` closes the client session cleanly without
stopping the server. Command names are case-insensitive.

Account records are created under `data/players/` and security audit output
under `logs/`.

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

The fuzzer targets the byte-oriented Telnet parser. Fuzzing complements rather
than replaces deterministic protocol tests and sanitizers.

## What review is useful

Focused review is welcome; nobody needs to audit the whole tree to contribute.
Especially useful areas are:

- Telnet parser/framing edge cases;
- RFC 1143 state transitions;
- weird behavior from real MUD clients;
- TLS/SSH connection lifetime and shutdown;
- pthread ownership or listener/worker mistakes;
- resource-exhaustion paths;
- credential/filesystem races;
- terminal/Unicode handling;
- MSSP/GMCP/OSC 8 interoperability;
- portability issues on non-Linux POSIX systems;
- tests that would lock down a subtle behavior more clearly.

The project is regularly built with aggressive warnings and has been exercised
with ASan/UBSan and libFuzzer. Those are useful engineering checks, not a claim
that the code is vulnerability-free.

## Protocol and library references

Primary references used by the implementation include:

- [RFC 854 — Telnet Protocol Specification](https://www.rfc-editor.org/rfc/rfc854)
- [RFC 856 — Telnet BINARY](https://www.rfc-editor.org/rfc/rfc856)
- [RFC 858 — SUPPRESS-GO-AHEAD](https://www.rfc-editor.org/rfc/rfc858)
- [RFC 885 — End of Record](https://www.rfc-editor.org/rfc/rfc885)
- [RFC 1073 — NAWS](https://www.rfc-editor.org/rfc/rfc1073)
- [RFC 1091 — TERMINAL-TYPE](https://www.rfc-editor.org/rfc/rfc1091)
- [RFC 1143 — Q Method](https://www.rfc-editor.org/rfc/rfc1143)
- [RFC 1572 — NEW-ENVIRON](https://www.rfc-editor.org/rfc/rfc1572)
- [RFC 2066 — CHARSET](https://www.rfc-editor.org/rfc/rfc2066)
- [MUD Standards — MSSP](https://mudstandards.org/mud/mssp/)
- [MUD Standards — GMCP](https://mudstandards.org/mud/gmcp/)
- [MUD Standards — GMCP Core](https://mudstandards.org/gmcp/core/)
- [Mudlet — supported protocols / MNES / OSC 8 capabilities](https://wiki.mudlet.org/w/Manual%3ASupported_Protocols)
- [libssh server API](https://api.libssh.org/stable/group__libssh__server.html)
- [libssh callbacks](https://api.libssh.org/stable/group__libssh__callbacks.html)
- [OpenSSL documentation](https://docs.openssl.org/)
- [libsodium password hashing](https://doc.libsodium.org/password_hashing)

Standards, library documentation, interoperability testing, and community
feedback are used as references. Third-party source code is not claimed as part
of this project's authorship.

## Credits

Created and maintained by **Riot / `riotcore`**.

OpenSSL, libsodium, and libssh are independent projects with their own authors,
copyrights, and licenses. See [`CREDITS.md`](CREDITS.md) for the attribution
policy used by this repository.

## Recent changes

- **2026-08-09** — Added SSH as a sibling terminal transport using libssh, with
  shared password credentials, PTY/window capability mapping, and the same
  post-authentication application seam used by Telnet.
- **2026-08-09** — Added MSSP, bounded GMCP framing/Core.Ping, live OSC 8
  capability discovery, and safe OSC 8 hyperlink output.
- **2026-08-09** — Documented the project as a C MUD reference/foundation,
  expanded architectural rationale and integration guidance, and added project
  attribution.
- **2026-08-09** — Added plain Telnet alongside TLS 1.3 and expanded Telnet
  interoperability with EOR, bounded MTTS, bidirectional CHARSET, and
  NEW-ENVIRON/MNES.

See the Git history for detailed implementation history.

## License

Copyright (c) 2026 riotcore.

This project is released under the MIT License. See [`LICENSE`](LICENSE) for the
full terms.
