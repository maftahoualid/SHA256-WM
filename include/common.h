#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stddef.h>

#define REQUEST_FIFO_PATH "/tmp/hash_server"
#define CLIENT_FIFO_PREFIX "/tmp/hash_client_"
#define MAX_PATH_LEN 1024
#define HASH_HEX_LEN 64

#define REQ_HASH_FILE 0
#define REQ_TERMINATE 1
#define REQ_STATS     2
#define RESP_HASH     3
#define RESP_ERROR    4
#define RESP_STATS    5


#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define RES     "\x1b[0m"
#define BOLD    "\x1b[1m"

#define LOG_ERR(fmt, ...) do { \
    fprintf(stderr, BOLD RED "[ERRORE]" RES fmt "\n", ##__VA_ARGS__); \
} while(0);

#define FATAL(fmt, ...) do { \
    LOG_ERR(fmt, ##__VA_ARGS__); \
    exit(EXIT_FAILURE); \
} while(0);

#define EXIT_IF(cond, fmt, ...) do { \
    if (cond) { FATAL(fmt, ##__VA_ARGS__); } \
} while(0);

/* --- MACRO UTILI (da unificare poi in common.h) --- */

// Controlla allocazione memoria
#define CHECK_ALLOC(ptr) do { \
    if ((ptr) == NULL) { \
        LOG_ERR("Memory allocation failed"); \
        return -1; \
    } \
} while(0);

// Controlla funzioni pthread (ritornano errno, non -1)
#define CHECK(func_call) do { \
    int _err = (int)(func_call); \
    if (_err != 0) { \
        fprintf(stderr, BOLD RED "[ERRORE] %s Fallita: %s\n" RES, #func_call, strerror(_err)); \
    }; \
} while(0);

#define CHECK_RET(call) do { \
    int _error = (call); \
    if (_error != 0) { \
        fprintf(stderr, BOLD RED "[ERRORE] %s Fallita: %s\n" RES, #call, strerror(_error)); \
        return -1; \
    }; \
} while(0);

typedef struct {
    int type;
    char path[MAX_PATH_LEN];
    char response_fifo_path[MAX_PATH_LEN];
    pid_t pid;
} request_msg_t;

typedef struct {
    unsigned long total_requests;
    unsigned long cache_hits;
    unsigned long cache_misses;
    unsigned long files_processed;
    double avg_processing_time;
} stats_t;

typedef struct {
    int type;
    char hash[HASH_HEX_LEN + 1];
    char message[256];
    int error_code;
    stats_t stats;
} response_msg_t;

int create_fifo(const char* path, mode_t mode);

int open_fifo_read(const char* path);

int open_fifo_write(const char* path);

int send_response(const char* fifo, response_msg_t resp);

int send_request(const char* server_fifo, request_msg_t req);

int read_response(const char* fifo, response_msg_t* resp);

int read_exact(int fd, void* buf, size_t n);

int write_exact(int fd, const void* buf, size_t n);

double get_time_diff(struct timespec start, struct timespec end);

void print_usage(const char* progname);

#endif