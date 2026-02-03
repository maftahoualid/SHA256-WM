#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>
#include <time.h>
#include <stdbool.h>
#include <stddef.h>

#define PATH_FIFO_RICHIESTA "/tmp/fifo_richiesta_"
#define PATH_FIFO_CLIENT "/tmp/fifo_risposta"
#define LUNGHEZZA_MAX_PATH 1024
#define LUNGHEZZA_HASH 64

#define RICHIESTA_HASH 0
#define RISPOSTA_HASH     1
#define RICHIESTA_STATISTICHE     2
#define RISPOSTA_STATISTICHE    3
#define ERRORE    4
#define CHIUSURA 5

typedef struct {
    int tipo;
    char path[LUNGHEZZA_MAX_PATH];
    char fifo_risposta[LUNGHEZZA_MAX_PATH];
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
    char hash[LUNGHEZZA_HASH + 1];
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