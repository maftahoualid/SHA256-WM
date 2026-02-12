#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stddef.h>

#define REQUEST_FIFO_PATH "/tmp/sha256_req_fifo"
#define CLIENT_FIFO_PREFIX "/tmp/sha256_resp_"
#define MAX_PATH_LEN 1024
#define HASH_HEX_LEN 64

#define REQ_HASH_FILE 0
#define REQ_TERMINATE 1
#define REQ_STATS     2
#define RESP_HASH     3
#define RESP_ERROR    4
#define RESP_STATS    5

typedef struct {
    int type;
    char path[MAX_PATH_LEN];
    char resp_fifo[MAX_PATH_LEN];
    pid_t client_pid;
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
    char error_msg[256];
    int error_code;
    stats_t stats;
} response_msg_t;

int ensure_fifo(const char* path, mode_t mode);

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