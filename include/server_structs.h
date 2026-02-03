#ifndef SERVER_STRUCTS_H
#define SERVER_STRUCTS_H

#include "common.h"
#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#define NUMERO_MAX_THREAD 8
#define NUMERO_DEFAULT_THREAD 4
#define DIMENSIONE_HASH_BUCKET 1024
#define ORDINE_ASCENDENTE 0
#define ORDER_DISCENDENTE 1

typedef struct lavoro {
    char path[LUNGHEZZA_MAX_PATH];
    char fifo_risposta[LUNGHEZZA_MAX_PATH];
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
    char path[LUNGHEZZA_MAX_PATH];
    char hash[LUNGHEZZA_HASH + 1];
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
    thread_t threads[NUMERO_MAX_THREAD];
    int numero_thread;
    bool in_esecuzione;
    statistiche_t statistiche;
    pthread_mutex_t mutex_statistiche;
} server_t;

#endif