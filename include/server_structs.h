#ifndef SERVER_STRUCTS_H
#define SERVER_STRUCTS_H

#include "common.h"
#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#define MAX_THREADS_NUM 8
#define DEFAULT_THREADS_NUM 4
#define LIST_SIZE 1024
#define ASCENDING  0
#define DESCENDING 1

typedef struct job {
    char path[PATH_MAX_LEN];
    char response_fifo_path[PATH_MAX_LEN];
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
    int num_jobs;
} job_queue_t;

typedef struct cache_entry {
    char path[PATH_MAX_LEN];
    char hash[HASH_LEN + 1];
    bool iscomputed;
    bool iscomputing;
    int threads_waiting;
    off_t size;
    time_t last_upd_sec;
    long last_upd_nsec;
    pthread_mutex_t mutex;
    pthread_cond_t cond_var;
    struct cache_entry* next;
} entry_t;

typedef struct {
    entry_t** lists;
    size_t num_lists;
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
    thread_t threads[MAX_THREADS_NUM];
    int n_threads;
    bool isrunning;
    stats_t stats;
    pthread_mutex_t stats_lock;
} server_t;

#endif