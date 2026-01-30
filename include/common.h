#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>  // pid_t, ssize_t
#include <time.h>       // struct timespec
#include <stdbool.h>    // bool, true, false
#include <stddef.h>     // size_t

// --- COSTANTI DI SISTEMA E IPC ---
#define REQUEST_FIFO_PATH "/tmp/sha256_req_fifo"
#define CLIENT_FIFO_PREFIX "/tmp/sha256_resp_"
#define MAX_PATH_LEN 1024
#define HASH_HEX_LEN 64

// --- PROTOCOLLO DI COMUNICAZIONE ---

#define REQ_HASH_FILE 0
#define REQ_TERMINATE 1
#define REQ_STATS     2
#define RESP_HASH     3
#define RESP_ERROR    4
#define RESP_STATS    5

// Messaggio di richiesta (Client -> Server)
typedef struct {
    int type;
    char path[MAX_PATH_LEN];
    char resp_fifo[MAX_PATH_LEN];
    pid_t client_pid;
} request_msg_t;

// Messaggio di risposta (Server -> Client)
typedef struct {
    int type;
    char hash[HASH_HEX_LEN + 1];
    char error_msg[256];
    int error_code;
} response_msg_t;

// --- FUNZIONI DI UTILITÀ CONDIVISE (IPC & TEMPO) ---

// Crea una FIFO se non esiste e verifica che sia una FIFO
int ensure_fifo(const char* path, mode_t mode);

// Wrapper per open in lettura/scrittura
int open_fifo_read(const char* path);
int open_fifo_write(const char* path);
void send_response(const char* fifo, response_msg_t resp);

// Wrapper per read/write che gestiscono interruzioni e scritture parziali
int read_exact(int fd, void* buf, size_t n);
int write_exact(int fd, const void* buf, size_t n);

// Calcolo differenza tempo
double get_time_diff(struct timespec start, struct timespec end);

// Stampa utilizzo programma
void print_usage(const char* progname);

#endif // COMMON_H
