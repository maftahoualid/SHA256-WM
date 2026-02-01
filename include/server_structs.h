#ifndef SERVER_STRUCTS_H
#define SERVER_STRUCTS_H

// Inclusione delle definizioni comuni condivise con il client
#include "common.h"
// Inclusione della libreria pthread per il multithreading (mutex, thread, cond variables)
#include <pthread.h>
// Inclusione per il tipo booleano (true/false)
#include <stdbool.h>
// Inclusione per i tipi di sistema (pid_t, off_t, ecc.)
#include <sys/types.h>
// Inclusione per le strutture temporali (time_t, struct timespec)
#include <time.h>

// Numero massimo di thread worker supportati dall'array statico
#define MAX_THREADS 8
// Numero di default di thread worker se non specificato dall'utente
#define DEFAULT_WORKERS 4
// Dimensione della tabella hash per la cache (numero di "secchi" o liste concatenate)
#define HASH_BUCKET_SIZE 1024

// Struttura per raccogliere le statistiche globali del server
typedef struct {
    unsigned long total_requests;      // Totale richieste ricevute
    unsigned long cache_hits;          // Richieste servite dalla cache (file non ricalcolato)
    unsigned long cache_misses;        // Richieste che hanno richiesto calcolo (file nuovo o modificato)
    unsigned long files_processed;     // Numero di file di cui è stato calcolato l'hash
    double avg_processing_time;        // Tempo medio di elaborazione (media mobile)
} stats_t;

// Costanti per l'ordinamento della coda di priorità
#define ORDER_ASC  0 // Ordine crescente (file piccoli prima)
#define ORDER_DESC 1 // Ordine decrescente (file grandi prima)

// Struttura che rappresenta un singolo lavoro (job) nella coda
typedef struct job {
    char path[MAX_PATH_LEN];       // Percorso assoluto del file da processare
    char resp_fifo[MAX_PATH_LEN];  // Percorso della FIFO privata del client per la risposta
    pid_t client_pid;              // PID del client (utile per debug o log)
    off_t size;                    // Dimensione del file (usata per l'ordinamento nella coda)
    struct job* next;              // Puntatore al prossimo job (lista concatenata semplice)
} job_t;

// Struttura che gestisce la coda dei lavori (Job Queue)
typedef struct {
    job_t* head;           // Testa della lista concatenata dei job
    pthread_mutex_t mtx;   // Mutex per proteggere l'accesso concorrente alla coda
    pthread_cond_t cv;     // Condition variable per notificare i worker quando c'è un nuovo job
    bool closed;           // Flag per indicare che la coda è chiusa (shutdown del server)
    int order;             // Criterio di ordinamento (ASC o DESC)
    int count;             // Numero attuale di elementi in coda
} job_queue_t;

// Struttura per una singola voce nella cache
typedef struct cache_entry {
    char path[MAX_PATH_LEN];         // Chiave: percorso del file
    char hash[HASH_HEX_LEN + 1];     // Valore: Hash SHA256 calcolato
    bool ready;                      // True se l'hash è valido e pronto per la lettura
    bool computing;                  // True se un thread sta attualmente calcolando l'hash per questa entry
    int waiters;                     // Numero di thread in attesa che il calcolo finisca (per evitare calcoli doppi)
    off_t sz;                        // Dimensione del file al momento del calcolo (per validazione cache)
    time_t mtime_sec;                // Ultima modifica (secondi) per validazione cache
    long mtime_nsec;                 // Ultima modifica (nanosecondi) per validazione cache
    pthread_mutex_t mtx;             // Mutex granulare: protegge solo questa specifica entry
    pthread_cond_t cv;               // Condition variable per svegliare i thread in attesa del calcolo di QUESTA entry
    struct cache_entry* next;        // Puntatore per gestire le collisioni hash (lista concatenata nel bucket)
} cache_entry_t;

// Struttura principale della Cache (Hash Table)
typedef struct {
    cache_entry_t** buckets; // Array di puntatori alle liste di entry (i "secchi")
    size_t nbuckets;         // Dimensione dell'array buckets
    pthread_mutex_t mtx;     // Mutex globale della cache (usato per statistiche hit/miss globali o inserimenti strutturali)
    unsigned long hits;      // Contatore hit interno alla cache
    unsigned long misses;    // Contatore miss interno alla cache
} cache_t;

// Struttura che rappresenta un thread worker
typedef struct {
    pthread_t thread; // Handle del thread POSIX
    int id;           // ID numerico assegnato al worker (0, 1, 2...)
    bool active;      // Flag per sapere se il thread è stato avviato correttamente
} worker_t;

// Contesto globale del server (Mega-struct che contiene tutto lo stato)
typedef struct {
    job_queue_t job_queue;          // La coda dei lavori condivisa
    cache_t cache;                  // La cache condivisa
    worker_t workers[MAX_THREADS];  // Array dei descrittori dei worker
    int num_workers;                // Numero di worker attivi configurati
    bool running;                   // Flag globale per il loop principale (true = server gira)
    stats_t stats;                  // Statistiche globali
    pthread_mutex_t stats_mtx;      // Mutex per proteggere l'aggiornamento delle statistiche
} server_ctx_t;

#endif