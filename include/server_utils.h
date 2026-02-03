#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H

#include "server_structs.h"

extern server_t* server_varglobale;

off_t dimensione_file(const char* path);

int ultima_modifica(const char* path, time_t* sec, long* nsec);

int sha256_file(const char* filepath, char* hash_hex);

void elimina_coda(coda_t* q);

void aggiungi_alla_coda(coda_t* q, const char* path, const char* fifo_risposta, pid_t pid_client, off_t dimensione);

int estrai_dalla_coda(coda_t* q, lavoro_t* out);

void elimina_cache(cache_t* c);

elemento_cache_t* ottieni_elemento_cache(cache_t* c, const char* path);

bool controllo_cache(cache_t* c, const char* path, off_t dimensione, time_t ultima_modifica_sec, long ultima_modifica_nsec, char* hash_out);

void salva_in_cache(cache_t* c, const char* path, off_t dimensione, time_t ultima_modifica_sec, long ultima_modifica_nsec, const char* hash);

void gestore_segnali(int sig);

void* funzione_thread(void* arg);

int inizializza_server(server_t* ctx, int numero_thread, int ordine);

void chiudi_server(server_t* ctx);

int esegui_server(server_t* ctx);

void stampa_statistiche(const statistiche_t* statistiche);

#endif