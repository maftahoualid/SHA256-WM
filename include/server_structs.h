#ifndef SERVER_STRUCTS_H
#define SERVER_STRUCTS_H

#include "common.h"
#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#define MAX_THREADS 8
#define DEFAULT_WORKERS 4
#define HASH_BUCKET_SIZE 1024
#define ORDER_ASC  0
#define ORDER_DESC 1

typedef struct lavoro {
    char path[MAX_PATH_LEN];
    char fifo_risposta[MAX_PATH_LEN];
    pid_t pid_client;
    off_t dimensione;
    struct lavoro* prossimo;
} lavoro_t;

typedef struct {
    lavoro_t* testa;
    pthread_mutex_t mutex;
    pthread_cond_t cond_var;
    bool coda_chiusa;
    int ordine;
    int numero_elementi;
} coda_t;

typedef struct elemento_cache {
    char path[MAX_PATH_LEN];
    char hash[HASH_HEX_LEN + 1];
    bool hash_pronto;
    bool hash_in_calcolo;
    int thread_in_attesa;
    off_t dimensione;
    time_t ultima_modifica_sec;
    long ultima_modifica_nsec;
    pthread_mutex_t mutex;
    pthread_cond_t cond_var;
    struct elemento_cache* prossimo;
} elemento_cache_t;

typedef struct {
    elemento_cache_t** buckets;
    size_t nbuckets;
    pthread_mutex_t mutex;
    unsigned long hits;
    unsigned long misses;
} cache_t;

typedef struct {
    pthread_t thread;
    int id;
    bool attivo;
} thread_t;

typedef struct {
    coda_t coda;
    cache_t cache;
    thread_t threads[MAX_THREADS];
    int numero_thread;
    bool in_esecuzione;
    statistiche_t statistiche;
    pthread_mutex_t mutex_statistiche;
} server_t;

#endif