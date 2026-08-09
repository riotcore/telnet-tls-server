cmake_minimum_required(VERSION 3.20)

project(telnet_foundation LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Threads REQUIRED)

# telnetcore is the reusable C MUD connection slice. The telnet_server target
# below is only a local harness; game/world ownership is intentionally outside
# this library boundary.
add_library(telnetcore STATIC
    src/audit_log.c
    src/security_policy.c
    src/terminal_text.c
    src/telnet_negotiation.c
    src/player_store.c
    src/telnet_protocol.c
    src/secure_server.c
)

target_include_directories(telnetcore
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(telnetcore
    PUBLIC
        PkgConfig::SODIUM
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(telnetcore PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(telnet_server
    app/server_main.c
)
target_link_libraries(telnet_server PRIVATE telnetcore)

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
target_link_libraries(security_test PRIVATE telnetcore)
add_test(NAME security_test COMMAND security_test)

add_executable(player_store_test tests/player_store_test.c)
target_link_libraries(player_store_test PRIVATE telnetcore)
add_test(NAME player_store_test COMMAND player_store_test)

add_executable(telnet_test tests/telnet_test.c)
target_include_directories(telnet_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(telnet_test PRIVATE telnetcore)
add_test(NAME telnet_test COMMAND telnet_test)

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
        src/player_store.c
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
