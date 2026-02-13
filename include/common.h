#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stddef.h>

#define REQ_FIFO_PATH "/tmp/hash_server"
#define CLIENT_FIFO_PATH "/tmp/hash_client_"
#define PATH_MAX_LEN 1024
#define HASH_LEN 64

#define HASH_A_FILE     0
#define CLOSE_SERVER    1
#define GET_STATISTICS  2
#define SEND_HASH       3
#define SEND_ERROR      4
#define SEND_STATISTICS 5

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

#define CHECK_ALLOC(ptr) do { \
    if ((ptr) == NULL) { \
        LOG_ERR(BOLD RED"[ERRORE] Allocazione della memoria fallita"); \
    } \
} while(0);

#define CHECK(func_call) do { \
    int _err = (int)(func_call); \
    if (_err != 0) { \
        fprintf(stderr, BOLD RED "[ERRORE] %s Fallita: %s\n" RES, #func_call, strerror(_err)); \
    }; \
} while(0);

#define CHECK_RET(fcall) do { \
    int _error = (fcall); \
    if (_error != 0) { \
        fprintf(stderr, BOLD RED "[ERRORE] %s Fallita: %s\n" RES, #fcall, strerror(_error)); \
        return -1; \
    }; \
} while(0);

typedef struct {
    unsigned long num_processed;
    unsigned long num_requests;
    double average_proc_time;
    unsigned long cache_hits;
    unsigned long cache_misses;
} stats_t;

typedef struct {
    char path[PATH_MAX_LEN];
    char response_fifo_path[PATH_MAX_LEN];
    pid_t pid;
    int type;
} request_t;


typedef struct {
    char hash[HASH_LEN + 1];
    char message[256];
    int error_code;
    int type;
    stats_t stats;
} response_t;

int create_fifo(const char* path, mode_t mode);

int open_for_reading(const char* path);

int open_for_writing(const char* path);

int send_response(const char* fifo, response_t response);

int send_request(const char* server_fifo, request_t request);

int read_response(const char* fifo, response_t* response);

int read_message(int fd, void* buffer, size_t n);

int write_message(int fd, const void* buffer, size_t n);

double elapsed_time(struct timespec start, struct timespec end);

#endif