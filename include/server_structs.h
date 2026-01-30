#ifndef SERVER_STRUCTS_H
#define SERVER_STRUCTS_H

#include "common.h"
#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

// --- COSTANTI SERVER ---
#define MAX_THREADS 8
#define HASH_BUCKET_SIZE 1024

// --- DEFINIZIONI STRUTTURE DATI ---

// Statistiche
typedef struct {
    unsigned long total_requests;
    unsigned long cache_hits;
    unsigned long cache_misses;
    unsigned long files_processed;
    double avg_processing_time;
} stats_t;

// Ordinamento coda
#define ORDER_ASC  0
#define ORDER_DESC 1

// Elemento Coda (Job)
typedef struct job {
    char path[MAX_PATH_LEN];
    char resp_fifo[MAX_PATH_LEN];
    pid_t client_pid;
    off_t size;
    struct job* next;
} job_t;

// Coda dei Job
typedef struct {
    job_t* head;
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    bool closed;
    int order;
    int count;
} job_queue_t;

// Elemento Cache
typedef struct cache_entry {
    char path[MAX_PATH_LEN];
    char hash[HASH_HEX_LEN + 1];
    bool ready;
    bool computing;
    int waiters;
    off_t sz;
    time_t mtime_sec;
    long mtime_nsec;
    pthread_mutex_t mtx;
    pthread_cond_t cv;
    struct cache_entry* next;
} cache_entry_t;

// Tabella Hash Cache
typedef struct {
    cache_entry_t** buckets;
    size_t nbuckets;
    pthread_mutex_t mtx;
    unsigned long hits;
    unsigned long misses;
} cache_t;

// Struttura Worker Thread
typedef struct {
    pthread_t thread;
    int id;
    bool active;
} worker_t;

// Contesto Globale Server
typedef struct {
    job_queue_t job_queue;
    cache_t cache;
    worker_t workers[MAX_THREADS];
    int num_workers;
    bool running;
    stats_t stats;
    pthread_mutex_t stats_mtx;
} server_ctx_t;

#endif // SERVER_STRUCTS_H