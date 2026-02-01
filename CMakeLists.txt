cmake_minimum_required(VERSION 3.16)

project(SHA256_Distribuito 
    VERSION 1.0.0
    DESCRIPTION "Servizio SHA-256 distribuito con IPC"
    LANGUAGES C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS "-Wall -Wextra -pthread -D_POSIX_C_SOURCE=200809L")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
include_directories(include)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

set(COMMON_SOURCES src/common.c)
set(SERVER_SOURCES
    src/server.c
    src/server_utils.c
    ${COMMON_SOURCES}
)
set(CLIENT_SOURCES
    src/client.c
    ${COMMON_SOURCES}
)
add_executable(server ${SERVER_SOURCES})
target_link_libraries(server Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
add_executable(client ${CLIENT_SOURCES})
target_link_libraries(client Threads::Threads)

add_custom_target(docs
    COMMAND ${CMAKE_COMMAND} -E echo "=== Compilazione documentazione ==="
    COMMAND bash -c "if command -v pdflatex >/dev/null 2>&1; then cd ${CMAKE_SOURCE_DIR}/doc && pdflatex relazione.tex && pdflatex relazione.tex && echo '✓ Documentazione compilata'; else echo '⚠️ pdflatex non trovato'; fi"
    COMMENT "Compila la documentazione LaTeX"
)
add_custom_target(run_tests
    COMMAND ${CMAKE_COMMAND} -E echo "=== Esecuzione test ==="
    COMMAND bash -c "cd ${CMAKE_SOURCE_DIR} && ./simple_test.sh"
    DEPENDS server client
    COMMENT "Esegue i test del sistema"
)
add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E echo "=== Pulizia completa ==="
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bin
    COMMAND bash -c "cd ${CMAKE_SOURCE_DIR}/doc && rm -f *.aux *.log *.out *.toc *.fdb_latexmk *.fls *.synctex.gz"
    COMMAND bash -c "cd ${CMAKE_SOURCE_DIR} && rm -f final.txt test.txt && rm -f /tmp/hash_server_*"
    COMMENT "Pulisce tutti i file generati"
)
add_custom_target(test
        COMMAND ${CMAKE_COMMAND} -E echo "=== Esecuzione test ==="
        COMMAND bash -c "cd ${CMAKE_SOURCE_DIR} && ./test.sh"
        DEPENDS server client
        COMMENT "Testa il sistema"
)
install(TARGETS server client
    RUNTIME DESTINATION bin
    COMPONENT binaries
)
