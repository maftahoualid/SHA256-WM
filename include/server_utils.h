// --- GUARDIE DI INCLUSIONE ---
// Solito meccanismo di sicurezza: "Se SERVER_UTILS_H non è stato ancora letto..."
#ifndef SERVER_UTILS_H
// "...allora leggilo adesso e definisci questa etichetta."
#define SERVER_UTILS_H

// Includiamo "server_structs.h" perché qui dentro usiamo le struct 'server_t', 'job_queue_t', ecc.
// Se non lo includessimo, il compilatore direbbe: "Che cos'è un server_t? Non lo conosco."
#include "server_structs.h"

// --- VARIABILE GLOBALE ESTERNA ---
// Questa riga è particolare. 'extern' dice al compilatore:
// "Guarda che esiste una variabile chiamata g_server di tipo puntatore a server_t,
// ma NON È QUI. È definita in un altro file (in server.c)."
// Serve perché il gestore dei segnali (sig_handler) deve poter accedere al server per spegnerlo,
// anche se il server è stato creato nel main.
extern server_t* g_server;

// --- FUNZIONI DI CALCOLO ---

// Calcola l'hash SHA256 di un file.
// Input: path (percorso del file).
// Output: hash_string (dove scrivere il risultato).
// Ritorna: 0 se ok, -1 se errore.
int compute_sha256(const char* path, char* hash_string);

// --- FUNZIONI PER LA GESTIONE DELLA CODA (HEAP) ---

// Chiude la coda e libera la memoria dell'array dei lavori.
void close_queue(job_queue_t* queue);

// Aggiunge un nuovo lavoro alla coda (la "Piramide").
// Parametri:
// - queue: puntatore alla coda
// - path: il file da calcolare
// - response_fifo_path: dove rispondere al client
// - pid: chi è il client (per loggarlo)
// - size: dimensione file (fondamentale per ordinare la piramide!)
void add_to_queue(job_queue_t* queue, const char* path, const char* response_fifo_path, pid_t pid, off_t size);

// Un thread lavoratore chiama questa funzione per farsi dare il prossimo lavoro.
// È bloccante: se la coda è vuota, il thread si addormenta qui dentro.
int get_from_queue(job_queue_t* queue, job_t* j);

// --- FUNZIONI PER LA GESTIONE DELLA CACHE (HASH TABLE) ---

// Chiude la cache, distrugge i lucchetti e libera la memoria del "parcheggio".
void close_cache(cache_t* cache);

// Cerca un file nella cache gestendo anche le richieste simultanee (Thundering Herd).
// Parametri extra (size, last_upd...) servono a garantire che il file non sia cambiato nel frattempo.
// Ritorna: true (trovato e valido), false (non c'è o è vecchio, devi calcolarlo).
bool search_cache(cache_t* cache, const char* path, off_t size, time_t last_upd_sec, long last_upd_nsec, char* hash_string);

// Inserisce un risultato calcolato nella cache e SVEGLIA tutti i thread in attesa.
void add_to_cache(cache_t* cache, const char* path, off_t size, time_t last_upd_sec, long last_upd_nsec, const char* hash);

// --- FUNZIONI DI GESTIONE DEL SERVER ---

// Funzione chiamata automaticamente quando premi CTRL+C.
void sig_handler(int sig);

// La funzione che ogni thread lavoratore esegue all'infinito.
// 'arg' sarà il puntatore al server (server_t*).
void* thread_function(void* arg);

// Prepara tutta la memoria (malloc/calloc) per coda, cache e thread.
// Ritorna 0 se successo, -1 se fallisce.
int init_server(server_t* server, int n_threads, int order);

// Chiude tutto gentilmente, aspettando che i thread finiscano.
void close_server(server_t* server);

// Il ciclo principale del server: apre la FIFO pubblica e smista le richieste.
int run_server(server_t* server);

// Stampa a video le statistiche (cache hit, miss, tempi, ecc.).
void show_statistics(const stats_t* stats);

// Stampa la guida se l'utente sbaglia a lanciare il programma.
void server_help(const char* name);

#endif // Chiude l'#ifndef iniziale