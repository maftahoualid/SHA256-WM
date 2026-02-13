// --- GUARDIE DI INCLUSIONE ---
// Solito meccanismo: "Se questo file non è già stato letto, leggilo ora".
#ifndef SERVER_STRUCTS_H
#define SERVER_STRUCTS_H

// Includiamo "common.h" per avere le costanti come PATH_MAX_LEN e le struct di base.
#include "common.h"
// Libreria per i Thread (pthread_t, pthread_mutex_t, pthread_cond_t).
#include <pthread.h>
// Per usare 'bool' (true/false).
#include <stdbool.h>
// Per i tipi di sistema (pid_t, off_t).
#include <sys/types.h>
// Per la gestione del tempo (time_t).
#include <time.h>

// --- COSTANTI DI CONFIGURAZIONE ---
// Il numero massimo assoluto di thread che possiamo creare (hard limit).
#define MAX_THREADS_NUM 8
// Se l'utente non specifica nulla con -t, ne usiamo 4.
#define DEFAULT_THREADS_NUM 4
// La grandezza iniziale della nostra Tabella Hash (il "parcheggio").
#define LIST_SIZE 2048
// Costanti per ricordarci cosa significano 0 e 1 quando ordiniamo la coda.
#define ASCENDING  0
#define DESCENDING 1

// --- STRUTTURA: IL SINGOLO LAVORO (JOB) ---
// Rappresenta un file che deve essere processato.
typedef struct {
    char path[PATH_MAX_LEN];              // Il percorso del file da leggere
    char response_fifo_path[PATH_MAX_LEN]; // Dove dobbiamo mandare la risposta
    pid_t pid;                            // Chi ce l'ha chiesto
    off_t size;                           // QUANTO È GRANDE IL FILE (Fondamentale per l'Heap!)
    // NOTA: Qui non c'è più "struct job* next". Perché?
    // Perché ora usiamo un array contiguo, non una lista sparsa. Molto più veloce.
} job_t; 

// --- STRUTTURA: LA CODA DI PRIORITÀ (HEAP) ---
// È la "Piramide" che contiene tutti i lavori in attesa.
typedef struct {
    job_t* jobs;          // Puntatore all'array dinamico (la memoria vera e propria)
    int capacity;         // Quanti posti abbiamo in totale nell'array (es. 128, 256...)
    int num_jobs;         // Quanti posti sono effettivamente occupati ora
    
    pthread_mutex_t mutex;    // Il lucchetto per proteggere la coda
    pthread_cond_t cond_var;  // La campana per svegliare i thread quando c'è lavoro
    
    bool isclosed;        // Flag: "La saracinesca è abbassata?" (true quando stiamo spegnendo)
    int order;            // ASCENDING o DESCENDING (decide chi sta in cima alla piramide)
} job_queue_t;

// --- ENUM: STATI DELLA CACHE (THUNDERING HERD) ---
// Questa è la nostra macchina a stati per gestire le richieste simultanee.
typedef enum {
    ENTRY_EMPTY = 0,    // Lo slot è vuoto, libero per chiunque
    ENTRY_PROCESSING,   // "Sto lavorando, non disturbare" (ma mettiti in coda se vuoi lo stesso file)
    ENTRY_READY         // "Ho finito, il risultato è pronto qui"
} entry_state_t;

// --- STRUTTURA: UNA VOCE DELLA CACHE ---
// Un singolo slot nel "parcheggio" della Hash Table.
typedef struct {
    char path[PATH_MAX_LEN];    // Il nome del file (la "targa" per riconoscerlo)
    char hash[HASH_LEN + 1];    // Il risultato del calcolo (se pronto)
    
    entry_state_t state;        // In che stato si trova? (Vedi enum sopra)
    
    // Questi campi servono a capire se il file è cambiato nel frattempo
    off_t size;                 // Dimensione del file quando l'abbiamo calcolato
    time_t last_upd_sec;        // Secondi dell'ultima modifica
    long last_upd_nsec;         // Nanosecondi dell'ultima modifica (precisione massima)
    
    // NOTA: Qui NON ci sono più mutex o cond_var per singola voce!
    // Abbiamo rimosso il "Fine-Grained Locking" per alleggerire la memoria.
} entry_t;

// --- STRUTTURA: LA TABELLA CACHE COMPLETA ---
// Il contenitore di tutte le voci.
typedef struct {
    entry_t* table;       // L'array gigante che contiene tutte le voci (il "parcheggio")
    size_t capacity;      // Quanti posti ci sono in totale
    size_t num_entries;   // Quanti posti sono occupati
    
    pthread_mutex_t mutex;     // Un unico lucchetto GLOBALE per tutta la cache
    pthread_cond_t global_cv;  // Qui dormono TUTTI i thread che aspettano un file che è in stato PROCESSING.
    
    unsigned long hits;        // Statistiche: quante volte abbiamo riciclato un risultato
    unsigned long misses;      // Statistiche: quante volte abbiamo dovuto calcolare
} cache_t;

// --- STRUTTURA: IL THREAD ---
// Serve solo per tenere traccia dei nostri "operai".
typedef struct {
    pthread_t pthread;    // L'oggetto thread di sistema (l'anima del thread)
    int thread_id;        // Un numero identificativo (0, 1, 2...)
    bool isactive;        // Sta lavorando o è morto?
} thread_t;

// --- STRUTTURA: IL SERVER (GOD OBJECT) ---
// La struttura madre che contiene tutto il resto.
typedef struct {
    job_queue_t queue;              // La Coda dei lavori
    cache_t cache;                  // La Cache dei risultati
    thread_t threads[MAX_THREADS_NUM]; // L'array dei lavoratori
    int n_threads;                  // Quanti ne abbiamo attivati
    bool isrunning;                 // Interruttore generale ON/OFF
    
    stats_t stats;                  // Le statistiche globali (da common.h)
    pthread_mutex_t stats_lock;     // Lucchetto per proteggere le statistiche
} server_t;

#endif // Chiude l'#ifndef iniziale