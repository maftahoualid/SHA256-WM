#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H

#include "server_structs.h"
extern server_ctx_t* g_server_ctx;

/**
 * Restituisce la dimensione del file in byte.
 * Ritorna -1 in caso di errore.
 */
off_t file_size(const char* path);

/**
 * Ottiene il tempo di ultima modifica del file (secondi e nanosecondi).
 * Ritorna 0 su successo, -1 su errore.
 */
int get_file_mtime(const char* path, time_t* sec, long* nsec);

/**
 * Verifica se un file esiste ed è accessibile (F_OK).
 */
bool file_exists(const char* path);

/**
 * Calcola l'hash SHA256 del file specificato.
 * Scrive il risultato in esadecimale (64 char + null terminator) in hash_hex.
 * Ritorna 0 su successo, -1 su errore.
 */
int compute_sha256(const char* filepath, char* hash_hex);

/**
 * Inizializza la coda dei job.
 */
void jq_init(job_queue_t* q, int order);

/**
 * Distrugge la coda dei job liberando la memoria.
 */
void jq_destroy(job_queue_t* q);

/**
 * Segnala la chiusura della coda (per terminazione server).
 * Sveglia tutti i thread in attesa.
 */
void jq_close(job_queue_t* q);

/**
 * Inserisce un nuovo job nella coda.
 * L'inserimento è ordinato in base alla dimensione del file (ASC o DESC).
 */
void jq_push(job_queue_t* q, const char* path, const char* resp_fifo, pid_t client_pid, off_t size);

/**
 * Estrae un job dalla coda (bloccante se vuota).
 * Ritorna 0 su successo, -1 se la coda è chiusa/terminata.
 */
int jq_pop(job_queue_t* q, job_t* out);

/**
 * Funzione di hash DJB2 per le stringhe (per indicizzare la cache).
 */
unsigned long djb2_hash(const char* s);

/**
 * Inizializza la cache hash-map.
 */
void cache_init(cache_t* c, size_t nbuckets);

/**
 * Distrugge la cache liberando risorse e sincronizzazioni.
 */
void cache_destroy(cache_t* c);

/**
 * Cerca o crea una entry nella cache (gestione interna bucket).
 */
cache_entry_t* cache_get_or_create(cache_t* c, const char* path);

/**
 * Cerca un file in cache.
 * Verifica validità (stessa size, stesso mtime). Gestisce attesa se in calcolo.
 * Ritorna true se trovato (hash copiato in hash_out), false se non trovato o invalido.
 */
bool cache_lookup(cache_t* c, const char* path, off_t size, time_t mtime_sec, long mtime_nsec, char* hash_out);

/**
 * Salva un risultato calcolato in cache e sveglia eventuali thread in attesa.
 */
void cache_store(cache_t* c, const char* path, off_t size, time_t mtime_sec, long mtime_nsec, const char* hash);

/**
 * Gestore dei segnali (SIGINT, SIGTERM).
 */
void signal_handler(int sig);

/**
 * Funzione principale eseguita dai thread worker.
 */
void* worker_thread(void* arg);

/**
 * Inizializza il contesto del server, le strutture dati e avvia i worker.
 */
int server_init(server_ctx_t* ctx, int num_workers, int order);

/**
 * Pulisce le risorse del server, attende i worker e distrugge le code.
 */
void server_destroy(server_ctx_t* ctx);

/**
 * Loop principale del server. Gestisce le richieste dalla FIFO principale.
 */
int server_run(server_ctx_t* ctx);

/**
 * Stampa le statistiche del server su stdout (log lato server).
 */
void print_stats(const stats_t* stats);

#endif