#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H

// Include le definizioni delle strutture dati
#include "server_structs.h"

// Dichiarazione di una variabile globale puntatore al contesto (usata nel signal handler)
extern server_ctx_t* g_server_ctx;

/**
 * Restituisce la dimensione del file in byte.
 * Ritorna -1 in caso di errore (es. file non trovato).
 */
off_t file_size(const char* path);

/**
 * Ottiene il tempo di ultima modifica del file (secondi e nanosecondi).
 * Ritorna 0 su successo, -1 su errore.
 * Fondamentale per verificare se la cache è aggiornata.
 */
int get_file_mtime(const char* path, time_t* sec, long* nsec);

/**
 * Verifica se un file esiste ed è accessibile in lettura (F_OK).
 */
bool file_exists(const char* path);

/**
 * Calcola l'hash SHA256 del file specificato leggendolo a blocchi.
 * Scrive il risultato in esadecimale (64 char + null terminator) nel buffer hash_hex.
 * Ritorna 0 su successo, -1 su errore.
 */
int compute_sha256(const char* filepath, char* hash_hex);

/**
 * Inizializza la coda dei job, impostando i mutex e l'ordine di priorità.
 */
void jq_init(job_queue_t* q, int order);

/**
 * Distrugge la coda dei job liberando la memoria di eventuali nodi rimasti.
 */
void jq_destroy(job_queue_t* q);

/**
 * Segnala la chiusura della coda (per terminazione server).
 * Imposta il flag 'closed' e sveglia tutti i thread worker in attesa su cond_wait.
 */
void jq_close(job_queue_t* q);

/**
 * Inserisce un nuovo job nella coda.
 * L'inserimento è ordinato (Priority Queue) in base alla dimensione del file (ASC o DESC).
 */
void jq_push(job_queue_t* q, const char* path, const char* resp_fifo, pid_t client_pid, off_t size);

/**
 * Estrae un job dalla coda.
 * Funzione bloccante: se la coda è vuota, il thread si addormenta sulla condition variable.
 * Ritorna 0 su successo, -1 se la coda è stata chiusa (segnale di stop).
 */
int jq_pop(job_queue_t* q, job_t* out);

/**
 * Funzione di hash DJB2 per le stringhe (algoritmo veloce per mappare stringhe a indici bucket).
 */
unsigned long djb2_hash(const char* s);

/**
 * Inizializza la cache hash-map allocando i bucket e i mutex.
 */
void cache_init(cache_t* c, size_t nbuckets);

/**
 * Distrugge la cache liberando tutte le entry, i mutex e le condition variable interne.
 */
void cache_destroy(cache_t* c);

/**
 * Helper interno: Cerca o crea una entry nella cache dato un percorso.
 * Gestisce la logica di attraversamento della lista di collisione nel bucket.
 */
cache_entry_t* cache_get_or_create(cache_t* c, const char* path);

/**
 * Cerca un file in cache.
 * Verifica validità (stessa size, stesso mtime del file su disco).
 * Gestisce "Thundering Herd": se un thread sta già calcolando l'hash, gli altri aspettano.
 * Ritorna true se trovato (hash copiato in hash_out), false se non trovato o invalido.
 */
bool cache_lookup(cache_t* c, const char* path, off_t size, time_t mtime_sec, long mtime_nsec, char* hash_out);

/**
 * Salva un risultato calcolato in cache, imposta flag ready=true e sveglia thread in attesa.
 */
void cache_store(cache_t* c, const char* path, off_t size, time_t mtime_sec, long mtime_nsec, const char* hash);

/**
 * Gestore dei segnali (SIGINT, SIGTERM) per chiusura pulita.
 */
void signal_handler(int sig);

/**
 * Funzione principale eseguita dai thread worker (ciclo infinito di elaborazione job).
 */
void* worker_thread(void* arg);

/**
 * Inizializza il contesto del server, le strutture dati e avvia i thread worker.
 */
int server_init(server_ctx_t* ctx, int num_workers, int order);

/**
 * Pulisce le risorse del server, attende la terminazione dei worker (join) e distrugge le code.
 */
void server_destroy(server_ctx_t* ctx);

/**
 * Loop principale del server (Main Thread).
 * Legge le richieste dalla FIFO pubblica e le smista (Job Queue o Statistiche).
 */
int server_run(server_ctx_t* ctx);

/**
 * Stampa le statistiche del server su stdout (formattato per log lato server).
 */
void print_stats(const stats_t* stats);

#endif