cmake_minimum_required(VERSION 3.16)

project(SHA256_Distribuito 
    VERSION 1.0.0
    DESCRIPTION "Servizio SHA-256 distribuito con IPC"
    LANGUAGES C)

# --- Impostazioni Standard C ---
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- Opzioni di Compilazione ---
# Aggiungiamo -D_POSIX_C_SOURCE=200809L per le feature POSIX (getopt, struct timespec, ecc.)
# Aggiungiamo -DOPENSSL_SUPPRESS_DEPRECATED per evitare warning su SHA256_Init su macOS/nuovi OpenSSL
add_compile_options(-Wall -Wextra -pthread -D_POSIX_C_SOURCE=200809L)

# Configurazioni Debug/Release
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# --- Output Directory ---
# Gli eseguibili finiranno nella cartella /bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# --- Dipendenze ---
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# --- Header Files ---
# Diciamo a CMake di cercare i file .h sia in 'include' che in 'src'
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# --- Definizione Sorgenti ---
set(COMMON_SOURCES src/common.c)

# Il server ha bisogno di server.c, server_utils.c e common.c
set(SERVER_SOURCES 
    src/server.c 
    src/server_utils.c 
    ${COMMON_SOURCES}
)

# Il client ha bisogno di client.c e common.c
set(CLIENT_SOURCES 
    src/client.c 
    ${COMMON_SOURCES}
)

# --- Target Server ---
add_executable(server ${SERVER_SOURCES})
# Il server deve linkare OpenSSL (per SHA256) e Threads (per il pool)
target_link_libraries(server PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

# --- Target Client ---
add_executable(client ${CLIENT_SOURCES})
# Il client usa solo funzioni di sistema e tempo, ma linkiamo Threads per sicurezza su Linux (rt library)
target_link_libraries(client PRIVATE Threads::Threads)

# --- Comandi Custom (Utility) ---

# Target per generare la documentazione
add_custom_target(docs
    COMMAND ${CMAKE_COMMAND} -E echo "=== Compilazione documentazione ==="
    COMMAND bash -c "if command -v pdflatex >/dev/null 2>&1; then cd ${CMAKE_SOURCE_DIR}/doc && pdflatex relazione.tex && pdflatex relazione.tex && echo '✓ Documentazione compilata'; else echo '⚠️ pdflatex non trovato'; fi"
    COMMENT "Compila la documentazione LaTeX"
)

# Target per pulire tutto (inclusi i file temporanei)
add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E echo "=== Pulizia completa ==="
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_SOURCE_DIR}/build
    COMMAND bash -c "rm -f ${CMAKE_SOURCE_DIR}/doc/*.aux ${CMAKE_SOURCE_DIR}/doc/*.log ${CMAKE_SOURCE_DIR}/doc/*.out ${CMAKE_SOURCE_DIR}/doc/*.toc"
    COMMAND bash -c "rm -f /tmp/hash_server /tmp/hash_client_*"
    COMMENT "Pulisce binari, build, log latex e FIFO temporanee"
)