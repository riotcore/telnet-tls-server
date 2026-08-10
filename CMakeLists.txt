cmake_minimum_required(VERSION 3.20)

project(mud_terminal_core LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(LIBSSH REQUIRED IMPORTED_TARGET libssh>=0.10)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Threads REQUIRED)

# mud_terminal_core is the reusable connection/protocol slice. Keep the runnable
# harness below small so readers can see exactly where their own MUD takes over.
add_library(mud_terminal_core STATIC
    src/audit_log.c
    src/security_policy.c
    src/terminal_text.c
    src/telnet_negotiation.c
    src/player_store.c
    src/telnet_protocol.c
    src/ssh_transport.c
    src/secure_server.c
)

target_include_directories(mud_terminal_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(mud_terminal_core
    PUBLIC
        PkgConfig::SODIUM
        PkgConfig::LIBSSH
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(mud_terminal_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(mud_terminal_server
    app/server_main.c
    app/harness_application.c
)
target_link_libraries(mud_terminal_server PRIVATE mud_terminal_core)

# This client is a local test tool. It only needs the Telnet option state and
# terminal-text filter from the library implementation.
add_executable(telnet_client
    tools/secure_client.c
    src/telnet_negotiation.c
    src/terminal_text.c
)
target_include_directories(telnet_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(telnet_client PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(telnet_client PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()

add_executable(security_test tests/security_test.c)
target_link_libraries(security_test PRIVATE mud_terminal_core)
add_test(NAME security_test COMMAND security_test)

add_executable(player_store_test tests/player_store_test.c)
target_link_libraries(player_store_test PRIVATE mud_terminal_core)
add_test(NAME player_store_test COMMAND player_store_test)

add_executable(telnet_test tests/telnet_test.c)
target_include_directories(telnet_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(telnet_test PRIVATE mud_terminal_core)
add_test(NAME telnet_test COMMAND telnet_test)

# Focused coverage for MSSP, GMCP framing/Core.Ping, NEW-ENVIRON capability
# updates, OSC 8 output, and the post-authentication application seam.
add_executable(protocol_extensions_test tests/protocol_extensions_test.c)
target_include_directories(protocol_extensions_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(protocol_extensions_test PRIVATE mud_terminal_core)
add_test(NAME protocol_extensions_test COMMAND protocol_extensions_test)

# SSH protocol cryptography stays in libssh; this focused test protects the
# filesystem boundary around the private host key that the adapter is given.
add_executable(ssh_transport_test tests/ssh_transport_test.c)
target_include_directories(ssh_transport_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(ssh_transport_test PRIVATE mud_terminal_core)
add_test(NAME ssh_transport_test COMMAND ssh_transport_test)

option(ENABLE_FUZZING "Build the Clang/libFuzzer Telnet parser target" OFF)

if(ENABLE_FUZZING)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "ENABLE_FUZZING requires Clang.")
    endif()

    add_executable(telnet_fuzz
        tests/telnet_fuzz.c
        src/audit_log.c
        src/security_policy.c
        src/terminal_text.c
        src/telnet_negotiation.c
        tests/fuzz_player_store.c
        src/telnet_protocol.c
    )

    target_include_directories(telnet_fuzz PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_link_libraries(telnet_fuzz PRIVATE
        PkgConfig::SODIUM
        Threads::Threads
    )

    target_compile_options(telnet_fuzz PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(telnet_fuzz PRIVATE
        -fsanitize=fuzzer,address,undefined
    )
endif()
