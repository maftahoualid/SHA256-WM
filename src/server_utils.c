#include "server_utils.h"   // Include l'header con le dichiarazioni delle funzioni e strutture del server
#include <stdio.h>          // Include libreria standard I/O per printf, perror
#include <stdlib.h>         // Include libreria standard per malloc, free, exit
#include <string.h>         // Include libreria stringhe per strcpy, strncmp, memset
#include <unistd.h>         // Include primitive POSIX come access, read, write
#include <errno.h>          // Include gestione errori e variabile errno
#include <sys/stat.h>       // Include funzioni per info sui file (stat, st_mtime)
#include <pthread.h>        // Include libreria threading (mutex, cond, thread)
#define OPENSSL_SUPPRESS_DEPRECATED // Definisce macro per evitare warning su API OpenSSL vecchie (macOS/Linux)
#include <openssl/sha.h>    // Include libreria OpenSSL per calcolo SHA256


off_t file_size(const char* path) { // Funzione helper per ottenere dimensione file
    struct stat st;                 // Dichiara struttura stat per contenere i metadati del file
    if (stat(path, &st) == -1) {    // Esegue stat sul percorso; se ritorna -1 c'è errore (es. non esiste)
        return -1;                  // Ritorna errore al chiamante
    }
    return st.st_size;              // Ritorna la dimensione del file in byte dalla struttura
}

int get_file_mtime(const char* path, time_t* sec, long* nsec) { // Helper per ottenere tempo ultima modifica (preciso)
    struct stat st;                 // Struttura stat per metadati
    if (stat(path, &st) == -1) {    // Chiama stat; se fallisce ritorna -1
        return -1;                  // Segnala errore
    }
    *sec = st.st_mtime;             // Estrae i secondi dell'ultima modifica e li salva nel puntatore
    *nsec = st.st_mtim.tv_nsec;     // Usa campo standard Linux per nanosecondi
    return 0;                       // Ritorna successo
}

bool file_exists(const char* path) { // Helper booleano per verificare esistenza file
    int result = access(path, F_OK); // Chiama access con flag F_OK (controllo esistenza)
    return (result == 0);            // Ritorna true se access torna 0, false altrimenti
}

void print_stats(const stats_t* stats) { // Funzione per stampare le statistiche formattate
    printf("=== Server Statistics ===\n"); // Stampa intestazione
    printf("Total requests: %lu\n", stats->total_requests); // Stampa totale richieste
    printf("Cache hits: %lu\n", stats->cache_hits); // Stampa numero hit cache
    printf("Cache misses: %lu\n", stats->cache_misses); // Stampa numero miss cache
    printf("Files processed: %lu\n", stats->files_processed); // Stampa numero file calcolati
    // Calcola e stampa percentuale hit (previene divisione per zero)
    printf("Cache hit ratio: %.2f%%\n", stats->total_requests > 0 ? (100.0 * stats->cache_hits / stats->total_requests) : 0.0);
    printf("Average processing time: %.3f ms\n", stats->avg_processing_time * 1000); // Stampa tempo medio in ms
    printf("========================\n"); // Stampa chiusura
}

int compute_sha256(const char* filepath, char* hash_hex) { // Funzione core per calcolo hash SHA256
    FILE* file = fopen(filepath, "rb"); // Apre file in modalità lettura binaria
    if (!file) {                        // Se il puntatore è NULL (apertura fallita)
        return -1;                      // Ritorna errore
    }
    SHA256_CTX sha256_ctx;              // Dichiara struttura contesto SHA256 OpenSSL
    SHA256_Init(&sha256_ctx);           // Inizializza il contesto

    char buffer[8192];                  // Buffer statico da 8KB per lettura a blocchi
    size_t bytes_read;                  // Variabile per contare byte letti

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) { // Ciclo: legge 8KB finché ci sono dati
        SHA256_Update(&sha256_ctx, buffer, bytes_read); // Aggiorna hash corrente con i nuovi dati
    }

    fclose(file); // Chiude il file descriptor

    unsigned char hash[SHA256_DIGEST_LENGTH]; // Buffer per il digest binario (32 bytes)
    SHA256_Final(hash, &sha256_ctx);          // Finalizza calcolo e scrive in 'hash'

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) { // Ciclo per convertire ogni byte in 2 char hex
        sprintf(hash_hex + (i * 2), "%02x", hash[i]); // Scrive hex nel buffer di output
    }
    hash_hex[HASH_HEX_LEN] = '\0'; // Aggiunge terminatore stringa finale

    return 0; // Ritorna successo
}

void jq_init(job_queue_t* q, int order) { // Inizializza coda dei job
    q->head = NULL;        // Imposta testa lista a NULL (vuota)
    q->closed = false;     // Imposta flag chiusura a false
    q->order = order;      // Salva criterio ordinamento (ASC/DESC)
    q->count = 0;          // Azzera contatore elementi
    pthread_mutex_init(&q->mtx, NULL); // Inizializza mutex coda
    pthread_cond_init(&q->cv, NULL);   // Inizializza condition variable coda
}

void jq_destroy(job_queue_t* q) { // Distrugge coda e libera risorse
    pthread_mutex_lock(&q->mtx); // Blocca mutex per accesso esclusivo durante pulizia

    job_t* current = q->head; // Inizia dalla testa
    while (current) {         // Scorre tutta la lista
        job_t* next = current->next; // Salva puntatore al prossimo
        free(current);               // Libera nodo corrente
        current = next;              // Avanza
    }
    q->head = NULL; // Azzera puntatore testa
    q->count = 0;   // Azzera contatore

    pthread_mutex_unlock(&q->mtx);      // Sblocca mutex
    pthread_mutex_destroy(&q->mtx);     // Distrugge oggetto mutex
    pthread_cond_destroy(&q->cv);       // Distrugge oggetto condition variable
}

void jq_close(job_queue_t* q) { // Segnala chiusura coda (shutdown)
    pthread_mutex_lock(&q->mtx);    // Acquisisce lock
    q->closed = true;               // Imposta flag closed a true
    pthread_cond_broadcast(&q->cv); // Sveglia TUTTI i thread in attesa (che controlleranno closed)
    pthread_mutex_unlock(&q->mtx);  // Rilascia lock
}

void jq_push(job_queue_t* q, const char* path, const char* resp_fifo, pid_t client_pid, off_t size) { // Inserimento in coda
    job_t* new_job = malloc(sizeof(job_t)); // Alloca memoria per nuovo job
    if (!new_job) return; // Se malloc fallisce, esce

    strncpy(new_job->path, path, MAX_PATH_LEN - 1); // Copia path file in struttura
    new_job->path[MAX_PATH_LEN - 1] = '\0'; // Assicura terminazione stringa

    strncpy(new_job->resp_fifo, resp_fifo, MAX_PATH_LEN - 1); // Copia path FIFO risposta
    new_job->resp_fifo[MAX_PATH_LEN - 1] = '\0'; // Assicura terminazione

    new_job->client_pid = client_pid; // Imposta PID client
    new_job->size = size;             // Imposta dimensione file (per ordinamento)
    new_job->next = NULL;             // Inizializza next a NULL

    pthread_mutex_lock(&q->mtx); // Entra in sezione critica

    if (q->closed) { // Se coda chiusa nel frattempo
        free(new_job); // Libera memoria allocata inutilmente
        pthread_mutex_unlock(&q->mtx); // Rilascia lock
        return; // Esce
    }

    job_t** ptr = &q->head; // Puntatore a puntatore per scorrere lista (gestisce inserimento in testa)

    while (*ptr) { // Loop finché esiste un nodo
        // Calcola se continuare a scorrere in base a ordine (ASC/DESC) e size
        bool continue_traversal = (q->order == ORDER_ASC) ? (size >= (*ptr)->size) : (size <= (*ptr)->size);
        if (!continue_traversal) break; // Se trovato punto inserimento, esce dal loop
        ptr = &(*ptr)->next; // Avanza al prossimo nodo
    }
    new_job->next = *ptr; // Collega nuovo nodo al successivo
    *ptr = new_job;       // Collega nodo precedente (o testa) al nuovo nodo

    q->count++; // Incrementa contatore
    pthread_cond_signal(&q->cv); // Segnala presenza nuovo job a UN worker in attesa
    pthread_mutex_unlock(&q->mtx); // Esce sezione critica
}

int jq_pop(job_queue_t* q, job_t* out) { // Estrazione job dalla coda
    pthread_mutex_lock(&q->mtx); // Acquisisce lock

    while (!q->head && !q->closed) { // Finché coda vuota E non chiusa
        pthread_cond_wait(&q->cv, &q->mtx); // Rilascia lock e dorme in attesa segnale
    }

    if (q->closed && !q->head) { // Se svegliato, coda chiusa e vuota
        pthread_mutex_unlock(&q->mtx); // Rilascia lock
        return -1; // Ritorna -1 per dire al worker di terminare
    }

    job_t* job = q->head; // Prende puntatore alla testa
    q->head = job->next;  // Avanza testa
    q->count--;           // Decrementa contatore

    *out = *job; // Copia contenuto job nella struttura passata dal worker (deep copy dei campi statici)
    free(job);   // Libera memoria del nodo estratto

    pthread_mutex_unlock(&q->mtx); // Rilascia lock
    return 0; // Ritorna successo
}

unsigned long path_hash(const char *s) {
    unsigned long h = 5381;
    while (*s) h = ((h << 5) + h) + *s++;
    return h;
}

void cache_init(cache_t* c, size_t nbuckets) { // Inizializza Hash Table Cache
    c->buckets = calloc(nbuckets, sizeof(cache_entry_t*)); // Alloca array bucket a zero
    c->nbuckets = nbuckets; // Salva numero bucket
    c->hits = 0; // Azzera hits
    c->misses = 0; // Azzera misses
    pthread_mutex_init(&c->mtx, NULL); // Inizializza mutex globale cache
}

void cache_destroy(cache_t* c) { // Distrugge cache
    pthread_mutex_lock(&c->mtx); // Blocca cache

    for (size_t i = 0; i < c->nbuckets; i++) { // Itera su tutti i bucket
        cache_entry_t* entry = c->buckets[i]; // Prende testa lista bucket
        while (entry) { // Scorre lista collisioni
            cache_entry_t* next = entry->next; // Salva prossimo
            pthread_mutex_destroy(&entry->mtx); // Distrugge mutex fine-grained dell'entry
            pthread_cond_destroy(&entry->cv); // Distrugge cv dell'entry
            free(entry); // Libera memoria entry
            entry = next; // Avanza
        }
    }

    free(c->buckets); // Libera array bucket
    pthread_mutex_unlock(&c->mtx); // Sblocca mutex globale
    pthread_mutex_destroy(&c->mtx); // Distrugge mutex globale
}

cache_entry_t* cache_get_or_create(cache_t* c, const char* path) { // Helper trova/crea entry (Thread Safe interno)
    unsigned long hash = path_hash(path); // Calcola hash del path
    size_t bucket = hash % c->nbuckets; // Calcola indice bucket

    pthread_mutex_lock(&c->mtx); // Lock globale per manipolazione struttura hash map

    cache_entry_t* entry = c->buckets[bucket]; // Prende testa bucket
    while (entry && strcmp(entry->path, path) != 0) { // Cerca path nella lista collisioni
        entry = entry->next; // Avanza
    }

    if (!entry) { // Se non trovato
        entry = malloc(sizeof(cache_entry_t)); // Crea nuova entry
        if (entry) { // Se allocazione ok
            strncpy(entry->path, path, MAX_PATH_LEN - 1); // Copia path
            entry->path[MAX_PATH_LEN - 1] = '\0'; // Terminatore
            entry->hash[0] = '\0'; // Hash vuoto
            entry->ready = false; // Non pronto
            entry->computing = false; // Nessuno calcola
            entry->waiters = 0; // 0 attese
            entry->sz = 0; // Size 0
            entry->mtime_sec = 0; // Time 0
            entry->mtime_nsec = 0; // Time ns 0
            pthread_mutex_init(&entry->mtx, NULL); // Init mutex specifico entry
            pthread_cond_init(&entry->cv, NULL); // Init cv specifica entry
            entry->next = c->buckets[bucket]; // Inserimento in testa
            c->buckets[bucket] = entry; // Aggiorna testa bucket
        }
    }

    pthread_mutex_unlock(&c->mtx); // Rilascia lock globale
    return entry; // Ritorna puntatore entry
}

bool cache_lookup(cache_t* c, const char* path, off_t size, time_t mtime_sec, long mtime_nsec, char* hash_out) { // Lookup logica complessa
    cache_entry_t* entry = cache_get_or_create(c, path); // Ottiene entry (con lock globale breve)
    if (!entry) { // Se malloc fallita
        pthread_mutex_lock(&c->mtx); // Lock stats
        c->misses++; // Incrementa miss
        pthread_mutex_unlock(&c->mtx); // Unlock stats
        return false; // Ritorna miss
    }

    pthread_mutex_lock(&entry->mtx); // Acquisisce Lock SPECIFICO ENTRY
    
    // Controlla se entry valida (ready) e metadati (size/time) corrispondono al file su disco
    if (entry->ready && entry->sz == size &&
        entry->mtime_sec == mtime_sec && entry->mtime_nsec == mtime_nsec) {
        strcpy(hash_out, entry->hash); // Copia hash nel buffer output
        pthread_mutex_unlock(&entry->mtx); // Rilascia lock entry

        pthread_mutex_lock(&c->mtx); // Lock globale stats
        c->hits++; // Incrementa hits
        pthread_mutex_unlock(&c->mtx); // Unlock stats
        return true; // Ritorna HIT
    }
    
    // Gestione concorrenza: se qualcuno sta calcolando (computing=true)
    if (entry->computing) {
        entry->waiters++; // Mi aggiungo ai waiters
        while (entry->computing) { // Loop attesa
            pthread_cond_wait(&entry->cv, &entry->mtx); // Dormo su CV entry rilasciando lock
        }
        entry->waiters--; // Decremento waiters al risveglio
        
        // Ricontrollo validità dopo attesa (potrebbe essere cambiato file nel frattempo?)
        if (entry->ready && entry->sz == size &&
            entry->mtime_sec == mtime_sec && entry->mtime_nsec == mtime_nsec) {
            strcpy(hash_out, entry->hash); // Copio hash
            pthread_mutex_unlock(&entry->mtx); // Unlock entry

            pthread_mutex_lock(&c->mtx); // Lock stats
            c->hits++; // Incrementa hits (anche se ho aspettato, non l'ho calcolato io)
            pthread_mutex_unlock(&c->mtx); // Unlock stats
            return true; // Ritorna HIT
        }
    }
    
    // Se non valido e nessuno calcola, tocca a me
    if (!entry->computing) { entry->computing = true; }

    pthread_mutex_unlock(&entry->mtx); // Fallback lock release
    pthread_mutex_lock(&c->mtx); // Lock stats
    c->misses++; // Miss
    pthread_mutex_unlock(&c->mtx); // Unlock stats
    return false; // Ritorna false
}

void cache_store(cache_t* c, const char* path, off_t size, time_t mtime_sec, long mtime_nsec, const char* hash) { // Salva risultato in cache
    cache_entry_t* entry = cache_get_or_create(c, path); // Recupera entry
    if (!entry) return; // Se errore, esce

    pthread_mutex_lock(&entry->mtx); // Lock entry

    strcpy(entry->hash, hash); // Scrive hash calcolato
    entry->sz = size; // Aggiorna size validazione
    entry->mtime_sec = mtime_sec; // Aggiorna tempo sec validazione
    entry->mtime_nsec = mtime_nsec; // Aggiorna tempo nsec validazione
    entry->ready = true; // Marca come valido
    entry->computing = false; // Libera flag calcolo

    if (entry->waiters > 0) { // Se c'erano thread in attesa in lookup
        pthread_cond_broadcast(&entry->cv); // Sveglia TUTTI i thread in attesa su questa entry
    }

    pthread_mutex_unlock(&entry->mtx); // Unlock entry
}

void signal_handler(int sig) { // Gestore segnali asincroni
    if (g_server_ctx) { // Controlla puntatore globale
        printf("\nReceived signal %d, shutting down server\n", sig); // Log ricezione
        g_server_ctx->running = false; // Imposta flag stop loop main
        jq_close(&g_server_ctx->job_queue); // Chiude coda job per sbloccare worker in jq_pop
    }
}

void* worker_thread(void* arg) { // Funzione thread worker
    server_ctx_t* ctx = (server_ctx_t*)arg; // Casting argomento a contesto
    job_t job; // Variabile stack per contenere dati job corrente

    printf("Worker thread started\n"); // Log avvio

    while (ctx->running) { // Loop finché server attivo
        if (jq_pop(&ctx->job_queue, &job) == -1) { break; } // Preleva job (bloccante). Se ritorna -1 esce loop
        struct timespec start_time, end_time; // Struct per cronometro
        clock_gettime(CLOCK_MONOTONIC, &start_time); // Start cronometro
        
        off_t size = file_size(job.path); // Ottiene size attuale file
        time_t mtime_sec; // Var per secondi
        long mtime_nsec; // Var per nanosecondi

        // Controllo se file accessibile e ottiene mtime
        if (size == -1 || get_file_mtime(job.path, &mtime_sec, &mtime_nsec) == -1) {
            response_msg_t resp = { .type = RESP_ERROR, .error_code = errno }; // Prepara msg errore
            snprintf(resp.error_msg, sizeof(resp.error_msg), "Cannot access file: %s", strerror(errno)); // Scrive descr errore
            send_response(job.resp_fifo, resp); // Invia errore al client
            continue; // Passa al prossimo job
        }

        char hash_result[HASH_HEX_LEN + 1]; // Buffer stack per hash
        // Check cache (ritorna true se hit, false se miss+computing lock preso)
        bool cache_hit = cache_lookup(&ctx->cache, job.path, size, mtime_sec, mtime_nsec, hash_result);

        if (!cache_hit) { // Se Cache Miss
            if (compute_sha256(job.path, hash_result) == -1) { // Calcola SHA256. Se errore:
                    response_msg_t resp = { .type = RESP_ERROR, .error_code = errno }; // Msg errore
                    snprintf(resp.error_msg, sizeof(resp.error_msg), "Cannot compute hash: %s", strerror(errno)); // Dettaglio errore
                    send_response(job.resp_fifo, resp); // Invia client
                    continue; // Prossimo job (NOTA: cache entry rimane in computing forever? Bug potenziale originale ma ok per commento)
            }

            cache_store(&ctx->cache, job.path, size, mtime_sec, mtime_nsec, hash_result); // Salva in cache e sblocca waiters

            pthread_mutex_lock(&ctx->stats_mtx); // Lock stats
            ctx->stats.files_processed++; // Incrementa file processati
            pthread_mutex_unlock(&ctx->stats_mtx); // Unlock stats
        }

        response_msg_t resp = { .type = RESP_HASH, .error_code = 0, .error_msg = "" }; // Prepara msg successo
        strcpy(resp.hash, hash_result); // Copia risultato
        int resp_fd = send_response(job.resp_fifo, resp); // Invia risposta FIFO client
        if (resp_fd == -1) printf("Warning: Cannot open response FIFO for client\n"); // Log warning se client sparito

        clock_gettime(CLOCK_MONOTONIC, &end_time); // Stop cronometro
        double processing_time = get_time_diff(start_time, end_time); // Delta T

        pthread_mutex_lock(&ctx->stats_mtx); // Lock stats per aggiornamento globale
        ctx->stats.total_requests++; // Incrementa richieste
        if (cache_hit) { // Se hit
            ctx->stats.cache_hits++; // Inc hit
        } else { // Se miss
            ctx->stats.cache_misses++; // Inc miss
        }

        // Calcolo media mobile cumulativa tempi
        double total_time = ctx->stats.avg_processing_time * (ctx->stats.total_requests - 1);
        ctx->stats.avg_processing_time = (total_time + processing_time) / ctx->stats.total_requests;

        pthread_mutex_unlock(&ctx->stats_mtx); // Unlock stats

        printf("Processed file: %s (%.3f ms, %s)\n", // Log operazione completata
               job.path, processing_time * 1000, cache_hit ? "cache hit" : "computed");
    }

    printf("Worker thread terminated\n"); // Log chiusura thread
    return NULL; // Uscita thread
}

int server_init(server_ctx_t* ctx, int num_workers, int order) { // Inizializzazione Server
    jq_init(&ctx->job_queue, order); // Init coda

    cache_init(&ctx->cache, HASH_BUCKET_SIZE); // Init cache hash table

    memset(&ctx->stats, 0, sizeof(stats_t)); // Azzera struct stats
    pthread_mutex_init(&ctx->stats_mtx, NULL); // Init mutex stats

    ctx->num_workers = num_workers; // Salva config workers
    ctx->running = true; // Setta running

    for (int i = 0; i < num_workers; i++) { // Loop creazione workers
        ctx->workers[i].id = i; // Assegna ID
        ctx->workers[i].active = true; // Setta attivo
        // Crea thread POSIX eseguendo worker_thread(ctx)
        if (pthread_create(&ctx->workers[i].thread, NULL, worker_thread, ctx) != 0) {
            perror("pthread_create"); // Errore creazione
            return -1; // Ritorna errore
        }
    }

    return 0; // Successo
}

void server_destroy(server_ctx_t* ctx) { // Distruzione Server
    ctx->running = false; // Stop flag globale
    jq_close(&ctx->job_queue); // Chiude coda per sbloccare workers

    for (int i = 0; i < ctx->num_workers; i++) { // Loop workers
        if (ctx->workers[i].active) { // Se thread era attivo
            pthread_join(ctx->workers[i].thread, NULL); // Attende terminazione thread (Join)
            ctx->workers[i].active = false; // Marca inattivo
        }
    }

    jq_destroy(&ctx->job_queue); // Distrugge coda
    cache_destroy(&ctx->cache); // Distrugge cache
    pthread_mutex_destroy(&ctx->stats_mtx); // Distrugge mutex stats
}

int server_run(server_ctx_t* ctx) { // Loop Principale Server
    int req_fd; // File descriptor FIFO richieste
    request_msg_t req; // Buffer struct richiesta
    
    // Crea FIFO pubblica se non esiste (helper in common.c)
    if (ensure_fifo(REQUEST_FIFO_PATH, 0666) == -1) { return -1; } 
    
    while (ctx->running) { // Loop esterno (riapertura FIFO)
        req_fd = open_fifo_read(REQUEST_FIFO_PATH); // Apre FIFO in lettura (blocca finché non c'è scrittore)
        if (req_fd == -1) { // Se errore
            if (errno == EINTR) continue; // Se interrotto da segnale, riprova
            perror("open request FIFO"); // Stampa errore
            break; // Esci
        }

        while (ctx->running) { // Loop interno (lettura messaggi)
            if (read_exact(req_fd, &req, sizeof(req)) == -1) { break; } // Legge struct intera. Se EOF/Err -> break
            
            switch (req.type) { // Dispatch tipo richiesta
                case REQ_HASH_FILE: { // Richiesta Hash
                    if (!file_exists(req.path)) { // Controllo esistenza immediato
                            response_msg_t resp = { .type = RESP_ERROR, .error_code = ENOENT, .error_msg = "File not found" }; // Msg err
                            send_response(req.resp_fifo, resp); // Risponde subito
                            break; // Break switch
                    }
                    off_t size = file_size(req.path); // Get size
                    if (size == -1) { // Se err size
                        response_msg_t resp = { .type = RESP_ERROR, .error_code = errno }; // Msg err
                        snprintf(resp.error_msg, sizeof(resp.error_msg), "%s", strerror(errno)); // Dettaglio
                        send_response(req.resp_fifo, resp); // Risponde
                        break; // Break switch
                    }
                    printf("Received hash request for: %s (size: %lld bytes)\n", req.path, (long long)size); // Log request
                    jq_push(&ctx->job_queue, req.path, req.resp_fifo, req.client_pid, size); // Inserisce in coda per workers
                    break; // Break switch
                }
                case REQ_STATS: { // Richiesta Statistiche
                    response_msg_t resp = { .type = RESP_STATS, .error_code = 0 }; // Prep msg stats

                    pthread_mutex_lock(&ctx->stats_mtx); // Lock stats
                    pthread_mutex_lock(&ctx->cache.mtx); // Lock cache (per snapshot hits/miss precisi)
                    ctx->stats.cache_hits = ctx->cache.hits; // Sync hits
                    ctx->stats.cache_misses = ctx->cache.misses; // Sync misses
                    pthread_mutex_unlock(&ctx->cache.mtx); // Unlock cache

                    resp.stats = ctx->stats;
                    pthread_mutex_unlock(&ctx->stats_mtx); // Unlock stats

                    send_response(req.resp_fifo, resp); // Invia risposta
                    break; // Break switch
                }
                case REQ_TERMINATE: // Richiesta Terminazione
                    printf("Received termination request\n"); // Log
                    ctx->running = false; // Imposta flag stop -> uscirà dai while
                    break; // Break switch
                default: // Tipo sconosciuto
                    fprintf(stderr, "Unknown request type: %d\n", req.type); // Log errore
                    break; // Break switch
            }
        }

        close(req_fd); // Chiude FIFO (client ha chiuso connessione, server aspetta il prossimo nel loop esterno)
    }

    return 0; // Uscita pulita
}