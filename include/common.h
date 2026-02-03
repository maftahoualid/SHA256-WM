#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stddef.h>

#define REQUEST_FIFO_PATH "/tmp/fifo_richiesta_"
#define CLIENT_FIFO_PREFIX "/tmp/fifo_risposta"
#define MAX_PATH_LEN 1024
#define HASH_HEX_LEN 64

#define REQ_HASH_FILE 0
#define REQ_TERMINATE 1
#define REQ_STATS     2
#define RESP_HASH     3
#define RESP_ERROR    4
#define RESP_STATS    5

typedef struct {
    int tipo;
    char path[MAX_PATH_LEN];
    char fifo_risposta[MAX_PATH_LEN];
    pid_t pid_client;
} messaggio_richiesta_t;

typedef struct {
    unsigned long richieste_totali;
    unsigned long cache_hits;
    unsigned long cache_misses;
    unsigned long file_processati;
    double media_tempo_processamento;
} statistiche_t;

typedef struct {
    int tipo;
    char hash[HASH_HEX_LEN + 1];
    char messaggio[256];
    int codice;
    statistiche_t statistiche;
} messaggio_risposta_t;

int crea_fifo(const char* path, mode_t permessi);

int apri_fifo_lettura(const char* path);

int apri_fifo_scrittura(const char* path);

int invia_risposta(const char* fifo, messaggio_risposta_t risposta);

int invia_richiesta(const char* server_fifo, messaggio_richiesta_t richiesta);

int leggi_risposta(const char* fifo, messaggio_risposta_t* risposta);

int leggi_da_fifo(int fd, void* buffer, size_t n);

int scrivi_su(int fd, const void* buffer, size_t n);

double differenza(struct timespec inizio, struct timespec fine);

void stampa_menu(const char* prog);

#endif