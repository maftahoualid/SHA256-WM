cmake_minimum_required(VERSION 3.16)

project(SHA256_Distribuito 
    VERSION 1.0.0
    DESCRIPTION "Servizio SHA-256 distribuito con IPC"
    LANGUAGES C)

# Standard C99
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Configurazione Build Type (Default: Release)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Flag di compilazione
# -D_POSIX_C_SOURCE=200809L è spesso utile per funzionalità POSIX (es. sigaction, mkfifo) in C99
set(CMAKE_C_FLAGS "-Wall -Wextra -pthread -D_POSIX_C_SOURCE=200809L")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# Output directory per gli eseguibili
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Directory degli Header (.h)
include_directories(include)

# Ricerca delle librerie necessarie
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# === Sorgenti ===

# File comuni a client e server
set(COMMON_SOURCES src/common.c)

# Sorgenti specifici del Server (Incluso server_utils.c che mancava)
set(SERVER_SOURCES
    src/server.c
    src/server_utils.c
    ${COMMON_SOURCES}
)

# Sorgenti specifici del Client
set(CLIENT_SOURCES
    src/client.c
    ${COMMON_SOURCES}
)

# === Target: Server ===
add_executable(server ${SERVER_SOURCES})
# Link alle librerie: Thread (pthread) e OpenSSL (libssl, libcrypto)
target_link_libraries(server Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

# === Target: Client ===
add_executable(client ${CLIENT_SOURCES})
# Link alle librerie: Thread (pthread)
target_link_libraries(client Threads::Threads)

# === Target ===

# Documentazione
add_custom_target(docs
    COMMAND ${CMAKE_COMMAND} -E echo "=== Compilazione documentazione ==="
    COMMAND bash -c "if command -v pdflatex >/dev/null 2>&1; then cd ${CMAKE_SOURCE_DIR}/doc && pdflatex relazione.tex && pdflatex relazione.tex && echo '✓ Documentazione compilata'; else echo '⚠️ pdflatex non trovato'; fi"
    COMMENT "Compila la documentazione LaTeX"
)

# Test
add_custom_target(run_tests
    COMMAND ${CMAKE_COMMAND} -E echo "=== Esecuzione test ==="
    COMMAND bash -c "cd ${CMAKE_SOURCE_DIR} && ./simple_test.sh"
    DEPENDS server client
    COMMENT "Esegue i test del sistema"
)

# Pulizia
add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E echo "=== Pulizia completa ==="
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bin
    COMMAND bash -c "cd ${CMAKE_SOURCE_DIR}/doc && rm -f *.aux *.log *.out *.toc *.fdb_latexmk *.fls *.synctex.gz"
    COMMAND bash -c "cd ${CMAKE_SOURCE_DIR} && rm -f final.txt test.txt && rm -f /tmp/hash_server_*"
    COMMENT "Pulisce tutti i file generati"
)

# Installazione
install(TARGETS server client
    RUNTIME DESTINATION bin
    COMPONENT binaries
)
