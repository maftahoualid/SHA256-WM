#ifndef SERVER_STRUCTS_H
#define SERVER_STRUCTS_H

#include "common.h"
#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#define MAX_THREADS 8
#define DEFAULT_THREADS 4
#define BUCKET_SIZE 1024
#define ASCENDANT  0
#define DESCENDANT 1

typedef struct job {
    char path[MAX_PATH_LEN];
    char response_fifo_path[MAX_PATH_LEN];
    pid_t pid;
    off_t size;
    struct job* next;
} job_t;

typedef struct {
    job_t* head;
    pthread_mutex_t mutex;
    pthread_cond_t cond_var;
    bool isclosed;
    int order;
    int dim;
} job_queue_t;

typedef struct cache_entry {
    char path[MAX_PATH_LEN];
    char hash[HASH_HEX_LEN + 1];
    bool iscomputed;
    bool iscomputing;
    int num_waiters;
    off_t sz;
    time_t last_upd_sec;
    long last_upd_nsec;
    pthread_mutex_t mutex;
    pthread_cond_t cond_var;
    struct cache_entry* next;
} cache_entry_t;

typedef struct {
    cache_entry_t** buckets;
    size_t dim;
    pthread_mutex_t mutex;
    unsigned long hits;
    unsigned long misses;
} cache_t;

typedef struct {
    pthread_t pthread;
    int thread_id;
    bool isactive;
} thread_t;

typedef struct {
    job_queue_t queue;
    cache_t cache;
    thread_t workers[MAX_THREADS];
    int num_workers;
    bool isrunning;
    stats_t stats;
    pthread_mutex_t stats_mtx;
} server_t;

#endif