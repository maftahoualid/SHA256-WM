// Includiamo l'header file che contiene le dichiarazioni delle nostre funzioni e le struct (server_t, cache_t, ecc.)
#include "server_utils.h"
// Librerie standard per input/output (come printf, fopen)
#include <stdio.h>
// Libreria per l'allocazione dinamica della memoria (malloc, calloc, free) e funzioni generiche
#include <stdlib.h>
// Libreria per manipolare le stringhe (strcmp, strcpy, memset)
#include <string.h>
// Libreria per le chiamate di sistema POSIX (come unlink, access)
#include <unistd.h>
// Libreria per gestire gli errori di sistema (ci permette di leggere la variabile 'errno')
#include <errno.h>
// Libreria per ottenere informazioni sui file (come la dimensione o la data di modifica con 'stat')
#include <sys/stat.h>
// Libreria fondamentale per creare e gestire i Thread e la sincronizzazione (mutex, condition variables)
#include <pthread.h>

// Questa direttiva serve per dire alla libreria OpenSSL di non darci avvisi se stiamo usando vecchie funzioni
#define OPENSSL_SUPPRESS_DEPRECATED
// Libreria OpenSSL che contiene l'algoritmo vero e proprio per calcolare l'hash SHA-256
#include <openssl/sha.h>

// Forward declaration: Avvisiamo il compilatore che questa funzione esiste e sarà scritta più in basso.
// Prende una stringa (il percorso del file) e restituisce un grosso numero intero a 64 bit.
static uint64_t hash_fnv1a(const char* path);

// -------------------------------------------------------------------------------------
// FUNZIONE: sig_handler
// Questa funzione viene chiamata automaticamente dal sistema operativo se premi CTRL+C
// o mandi un segnale di chiusura al programma. Serve a chiudere tutto in modo pulito.
// -------------------------------------------------------------------------------------
void sig_handler(int sig) {
    // Controlliamo se il server è stato effettivamente inizializzato (g_server è il puntatore globale)
    if (g_server) {
        // Stampiamo a schermo in giallo che abbiamo ricevuto il segnale di chiusura
        printf(BOLD YELLOW"\n[SERVER][INFO] Signal %d Received - Closing Server"RES"\n", sig);
        
        // Impostiamo la variabile isrunning a false. Questo farà terminare i cicli while principali del server
        g_server->isrunning = false;

        // Blocchiamo il lucchetto (mutex) della coda prima di modificarla
        CHECK(pthread_mutex_lock(&g_server->queue.mutex));
        // Diciamo esplicitamente alla coda che è chiusa. Nessun nuovo file potrà entrarci.
        g_server->queue.isclosed = true;
        // Svegliamo TUTTI i thread che stavano dormendo aspettando un nuovo lavoro,
        // così si accorgeranno che il server è chiuso e termineranno.
        CHECK(pthread_cond_broadcast(&g_server->queue.cond_var));
        // Sblocchiamo il lucchetto della coda
        CHECK(pthread_mutex_unlock(&g_server->queue.mutex));
    }
}

// -------------------------------------------------------------------------------------
// FUNZIONE: init_server
// Prepara tutte le strutture dati (coda, cache, statistiche) prima di far partire il server.
// -------------------------------------------------------------------------------------
int init_server(server_t* server, int n_threads, int order) {
    
    // --- INIZIALIZZAZIONE DELLA CODA DEI JOB ---
    // Partiamo con uno spazio per 128 lavori nella coda
    server->queue.capacity = 128;
    // Chiediamo al sistema operativo la memoria per contenere questi 128 lavori (usando malloc)
    server->queue.jobs = malloc(server->queue.capacity * sizeof(job_t));
    // Controlliamo se la memoria ci è stata data con successo
    CHECK_ALLOC(server->queue.jobs);
    // All'inizio, ci sono 0 lavori nella coda
    server->queue.num_jobs = 0;
    // Impostiamo se i file vanno ordinati per dimensione crescente (ASC) o decrescente (DESC)
    server->queue.order = order;
    // La coda non è chiusa, è pronta ad accettare lavori
    server->queue.isclosed = false;
    // Inizializziamo la Condition Variable (la "sala d'attesa" per i thread senza lavoro)
    CHECK(pthread_cond_init(&server->queue.cond_var, NULL));
    // Inizializziamo il Mutex (il "lucchetto" per evitare che due thread modifichino la coda contemporaneamente)
    CHECK(pthread_mutex_init(&server->queue.mutex, NULL));

    // --- INIZIALIZZAZIONE DELLA CACHE ---
    // La capacità della cache (LIST_SIZE è definito nel file .h, di solito 2048)
    server->cache.capacity = LIST_SIZE;
    // Alloca la memoria per la tabella della cache. 'calloc' mette tutto a zero automaticamente (molto utile!)
    server->cache.table = calloc(server->cache.capacity, sizeof(entry_t));
    // Controlla che l'allocazione sia andata a buon fine
    CHECK_ALLOC(server->cache.table);
    // All'inizio, non c've nessun elemento memorizzato
    server->cache.num_entries = 0;
    // Azzeriamo il contatore dei file trovati in cache (Hit)
    server->cache.hits = 0;
    // Azzeriamo il contatore dei file calcolati da zero (Miss)
    server->cache.misses = 0;
    // Inizializziamo il lucchetto della cache
    CHECK(pthread_mutex_init(&server->cache.mutex, NULL));
    // Inizializziamo la Condition Variable GLOBALE. Qui dormiranno i thread che aspettano un file in calcolo.
    CHECK(pthread_cond_init(&server->cache.global_cv, NULL)); 

    // --- INIZIALIZZAZIONE DELLE STATISTICHE ---
    // Usiamo memset per riempire la struttura delle statistiche di zeri (azzera tutti i contatori e i tempi)
    memset(&server->stats, 0, sizeof(stats_t));
    // Inizializziamo il lucchetto per proteggere l'aggiornamento delle statistiche
    CHECK(pthread_mutex_init(&server->stats_lock, NULL));

    // --- INIZIALIZZAZIONE DEI THREAD ---
    // Salviamo quanti thread dobbiamo creare
    server->n_threads = n_threads;
    // Diciamo che il server è attualmente in esecuzione
    server->isrunning = true;

    // Facciamo un ciclo da 0 al numero di thread che vogliamo creare
    for (int i = 0; i < n_threads; i++) {
        // Assegniamo un ID fittizio al thread (0, 1, 2, 3...)
        server->threads[i].thread_id = i;
        // Diciamo che il thread è attivo
        server->threads[i].isactive = true;
        // Creiamo fisicamente il thread! Gli diciamo di iniziare a eseguire la funzione "thread_function"
        CHECK_RET(pthread_create(&server->threads[i].pthread, NULL, thread_function, server));
    }

    // Se arriviamo qui, l'inizializzazione è andata bene. Restituiamo 0 (successo).
    return 0;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: heap_compare (Helper interno)
// Confronta due elementi nella coda (per dimensione) per decidere chi ha la priorità.
// -------------------------------------------------------------------------------------
static bool heap_compare(job_queue_t* queue, int idx1, int idx2) {
    // Se l'ordine scelto all'avvio è Crescente (file piccoli prima)
    if (queue->order == ASCENDING) {
        // Restituisce VERO se la dimensione del file in pos. idx1 è MINORE del file in pos. idx2
        return queue->jobs[idx1].size < queue->jobs[idx2].size;
    } else {
        // Altrimenti (ordine Decrescente), restituisce VERO se è MAGGIORE
        return queue->jobs[idx1].size > queue->jobs[idx2].size;
    }
}

// -------------------------------------------------------------------------------------
// FUNZIONE: heap_swap (Helper interno)
// Scambia di posto due elementi nell'array della coda.
// -------------------------------------------------------------------------------------
static void heap_swap(job_queue_t* queue, int idx1, int idx2) {
    // Salva temporaneamente il primo elemento
    job_t temp = queue->jobs[idx1];
    // Sovrascrive il primo con il secondo
    queue->jobs[idx1] = queue->jobs[idx2];
    // Mette quello che era il primo (salvato in temp) al posto del secondo
    queue->jobs[idx2] = temp;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: thread_function
// Questo è il "cuore" dei lavoratori. Ogni thread creato esegue questo codice all'infinito,
// prelevando file dalla coda e calcolando l'hash.
// -------------------------------------------------------------------------------------
void* thread_function(void* arg) {
    // Convertiamo l'argomento generico (void*) nel nostro puntatore alla struttura server
    server_t* server = (server_t*)arg;
    
    // Stampiamo a schermo che il thread è nato ed è pronto a lavorare
    printf(BOLD GREEN"[SERVER][INFO] New Thread Started!"RES"\n");
    
    // Creiamo una variabile locale per contenere i dati del file su cui andremo a lavorare
    job_t job;
    
    // Ciclo infinito: i thread lavorano finché il server non si spegne (isrunning = false)
    while (server->isrunning) {
        
        // Cerchiamo di prendere un lavoro dalla coda. Se la funzione restituisce -1 (coda chiusa), usciamo dal ciclo.
        if (get_from_queue(&server->queue, &job) == -1) { break; }

        // Prepariamo due variabili per calcolare quanto tempo ci mettiamo
        struct timespec start_time, end_time;
        // Salviamo l'ora esatta di inizio elaborazione
        clock_gettime(1, &start_time);

        // Prepariamo una struttura per ospitare le informazioni del file su disco (data, dimensione)
        struct stat st;
        // La funzione stat() interroga il disco. Se restituisce -1, il file non esiste o non abbiamo i permessi
        if (stat(job.path, &st) == -1) {
            // Se c'è un errore, prepariamo un messaggio di "SEND_ERROR" per il client
            response_t resp = { .type = SEND_ERROR, .error_code = errno };
            // Formattiamo la stringa con il motivo dell'errore (strerror traduce il codice di errore)
            snprintf(resp.message, sizeof(resp.message), "[ERRORE] %s", strerror(errno));
            // Inviamo l'errore al client attraverso la sua pipe personale
            send_response(job.response_fifo_path, resp);
            // Salta il resto di questo ciclo e ricomincia da capo aspettando un nuovo lavoro
            continue;
        }

        // Se il file esiste, salviamo la sua dimensione
        off_t size = st.st_size;
        // Salviamo i secondi dell'ultima data di modifica
        time_t last_upd_sec = st.st_mtime;
        // Salviamo i nanosecondi dell'ultima data di modifica (per precisione estrema)
        long last_upd_nsec = st.st_mtim.tv_nsec;

        // Prepariamo una stringa (array di caratteri) lunga 64 + 1 per ospitare il risultato dell'hash
        char hash_result[HASH_LEN + 1];
        
        // Andiamo a cercare in cache se abbiamo già calcolato questo hash per questo file in passato
        // Ritorna VERO se l'ha trovato, FALSO se non c'è. Inoltre riempie "hash_result" se lo trova.
        bool cache_hit = search_cache(&server->cache, job.path, size, last_upd_sec, last_upd_nsec, hash_result);

        // Se NON l'abbiamo trovato in cache (cache_miss), dobbiamo fare la fatica di calcolarlo!
        if (!cache_hit) {
            
            // Chiamiamo la funzione che apre il file e fa il calcolo matematico. Se fallisce (restituisce -1):
            if (compute_sha256(job.path, hash_result) == -1) {
                    // Prepariamo il messaggio di errore per il client
                    response_t resp = { .type = SEND_ERROR, .error_code = errno };
                    snprintf(resp.message, sizeof(resp.message),"[SERVER][ERRORE] Cannot compute hash: %s", strerror(errno));
                    // Inviamo l'errore al client
                    send_response(job.response_fifo_path, resp);
                    
                    // --- INIZIO FIX DEADLOCK ---
                    // Siccome non siamo riusciti a calcolare l'hash, dobbiamo liberare il posto in cache
                    // che avevamo segnato come "IN ELABORAZIONE", altrimenti altri thread aspetteranno in eterno!
                    
                    // Chiudiamo il lucchetto della cache
                    CHECK(pthread_mutex_lock(&server->cache.mutex));
                    // Ricalcoliamo la posizione in tabella usando la nostra formula FNV
                    uint64_t h = hash_fnv1a(job.path);
                    size_t idx = h % server->cache.capacity;
                    // Scendiamo nell'array finché non troviamo il nostro file bloccato
                    while (server->cache.table[idx].state != ENTRY_EMPTY) {
                        if (strcmp(server->cache.table[idx].path, job.path) == 0) {
                            // Trovato! Diciamo che lo slot è di nuovo VUOTO
                            server->cache.table[idx].state = ENTRY_EMPTY; 
                            // Riduciamo il conteggio dei file totali in cache
                            server->cache.num_entries--;
                            // SVEGLIAMO eventuali thread che stavano aspettando questo file, così capiranno che è fallito
                            CHECK(pthread_cond_broadcast(&server->cache.global_cv));
                            break; // Usciamo dal ciclo di ricerca
                        }
                        // Se non era qui, passiamo alla cella successiva (Probing Lineare)
                        idx = (idx + 1) % server->cache.capacity;
                    }
                    // Sblocchiamo la cache
                    CHECK(pthread_mutex_unlock(&server->cache.mutex));
                    // --- FINE FIX DEADLOCK ---
                    
                    // Ricomincia dall'inizio aspettando un nuovo job
                    continue;
            }

            // Se il calcolo è andato a buon fine, dobbiamo salvare il risultato in cache per il futuro
            add_to_cache(&server->cache, job.path, size, last_upd_sec, last_upd_nsec, hash_result);

            // Adesso aggiorniamo le statistiche: blocchiamo il lucchetto delle statistiche
            CHECK(pthread_mutex_lock(&server->stats_lock));
            // Aumentiamo di 1 il numero totale di file effettivamente processati fisicamente
            server->stats.num_processed++;
            // Sblocchiamo le statistiche
            CHECK(pthread_mutex_unlock(&server->stats_lock));
        }

        // A questo punto, sia se preso dalla cache, sia se calcolato da zero, abbiamo l'hash.
        // Prepariamo la busta (response) con la dicitura SEND_HASH per il client.
        response_t resp = { .type = SEND_HASH, .error_code = 0, .message = "" };
        // Copiamo l'hash che abbiamo calcolato/trovato dentro la busta
        strcpy(resp.hash, hash_result);
        // Spediamo la risposta al client attraverso la sua Pipe
        CHECK(send_response(job.response_fifo_path, resp));

        // Prendiamo l'ora esatta di fine elaborazione
        clock_gettime(1, &end_time);
        // Calcoliamo quanto tempo è passato tra l'inizio e la fine
        double proc_time = elapsed_time(start_time, end_time);

        // Aggiorniamo di nuovo le statistiche generali, quindi blocchiamo il lucchetto
        CHECK(pthread_mutex_lock(&server->stats_lock));
        // Aumentiamo di 1 il numero totale di richieste ricevute dai client
        server->stats.num_requests++;
        // Se l'avevamo trovato in cache
        if (cache_hit) {
            server->stats.cache_hits++; // Aumenta i successi
        } else {
            server->stats.cache_misses++; // Altrimenti aumenta i fallimenti
        }

        // Calcolo della nuova media matematica del tempo di elaborazione 
        double tot_time = server->stats.average_proc_time * (server->stats.num_requests - 1);
        server->stats.average_proc_time = (tot_time + proc_time) / server->stats.num_requests;

        // Sblocchiamo le statistiche
        CHECK(pthread_mutex_unlock(&server->stats_lock));

        // Stampiamo nel terminale del server che abbiamo finito con successo questo file
        printf(BOLD GREEN"[SERVER][INFO] File: %s processato in %.3f ms. (%s)"RES"\n",
               job.path, proc_time * 1000, cache_hit ? "l'hash era in cache" : "l'hash è stato calcolato");
    }

    // Se usciamo dal ciclo infinito (perché isrunning è diventato false), il thread muore.
    printf(BOLD YELLOW"[SERVER][INFO] Thread Chiuso"RES"\n");
    return NULL;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: get_from_queue
// I thread usano questa funzione per prelevare il file con priorità più alta dalla coda.
// -------------------------------------------------------------------------------------
int get_from_queue(job_queue_t* queue, job_t* job) {
    // Chiudiamo il lucchetto della coda. Solo un thread alla volta può frugarci dentro.
    CHECK(pthread_mutex_lock(&queue->mutex));

    // Finché ci sono 0 lavori, e la coda non è in fase di chiusura...
    while (queue->num_jobs == 0 && !queue->isclosed) {
        // ...il thread si addormenta sulla "cond_var". Questo sblocca automaticamente il lucchetto 
        // finché qualcuno non urla "Sveglia!" inserendo un nuovo lavoro.
        CHECK(pthread_cond_wait(&queue->cond_var, &queue->mutex));
    }

    // Se il thread si sveglia e vede che la coda è chiusa e vuota
    if (queue->isclosed && queue->num_jobs == 0) {
        // Sblocca il lucchetto e restituisce -1, dicendo al thread di suicidarsi
        CHECK(pthread_mutex_unlock(&queue->mutex));
        return -1;
    }

    // Preleviamo l'elemento in cima alla coda (posizione 0). In un Heap, la radice è sempre il file a priorità più alta!
    *job = queue->jobs[0];
    
    // Riduciamo il conteggio dei lavori di 1
    queue->num_jobs--;
    
    // Se ci sono ancora elementi rimasti nella coda
    if (queue->num_jobs > 0) {
        // Per mantenere la forma della piramide (Heap), prendiamo l'ultimo elemento in fondo 
        // e lo mettiamo provvisoriamente in cima (posizione 0)
        queue->jobs[0] = queue->jobs[queue->num_jobs];
        
        // Ora dobbiamo far "sprofondare" questo elemento (Heapify-Down) finché non ritrova il suo posto giusto
        int current = 0;
        while (true) {
            // Calcoliamo la posizione matematica dei due "figli" sotto di lui nella piramide
            int left = 2 * current + 1;
            int right = 2 * current + 2;
            int best = current;

            // Se il figlio sinistro esiste ed è "migliore" (più priorità) del genitore
            if (left < queue->num_jobs && heap_compare(queue, left, best)) { best = left; }
            // Se il figlio destro esiste ed è "migliore" del migliore tra genitore e figlio sinistro
            if (right < queue->num_jobs && heap_compare(queue, right, best)) { best = right; }

            // Se uno dei figli era migliore del genitore
            if (best != current) {
                // Scambiali di posto!
                heap_swap(queue, current, best);
                // Aggiorna l'indice corrente e continua a farlo sprofondare
                current = best;
            } else {
                // Se il genitore è migliore di entrambi i figli, ha trovato il posto giusto! Interrompi il ciclo.
                break;
            }
        }
    }

    // Sblocca il lucchetto della coda
    CHECK(pthread_mutex_unlock(&queue->mutex));
    // Ritorna 0 per dire che il prelievo è andato a buon fine
    return 0;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: hash_fnv1a
// Algoritmo matematico che trasforma il percorso di un file (es. "/home/file.txt")
// in un numero casuale a 64 bit per decidere in quale posto del parcheggio della cache metterlo.
// -------------------------------------------------------------------------------------
static uint64_t hash_fnv1a(const char* path) {
    // Numero di partenza standard per l'algoritmo FNV
    uint64_t hash = 14695981039346656037ULL; 
    // Finché non arriviamo alla fine della stringa...
    while (*path) {
        // Applica l'operazione bit a bit XOR (^) tra l'hash e la lettera corrente
        hash ^= (uint8_t)(*path);
        // Moltiplica per un altro numero primo enorme standard FNV
        hash *= 1099511628211ULL;     
        // Vai alla lettera successiva
        path++;
    }
    return hash; // Restituisce il numerone generato
}

// -------------------------------------------------------------------------------------
// FUNZIONE: search_cache
// Cerca se abbiamo già calcolato l'hash di questo file. GESTISCE LE RICHIESTE SIMULTANEE.
// -------------------------------------------------------------------------------------
bool search_cache(cache_t* cache, const char* path, off_t size, time_t last_upd_sec, long last_upd_nsec, char* hash_string) {
    // Trasforma il path nel numerone hash
    uint64_t hash = hash_fnv1a(path);
    
    // Blocca l'intera cache (Lucchetto Globale)
    CHECK(pthread_mutex_lock(&cache->mutex));
    
    // Calcola l'indice nell'array usando il "Modulo" (Resto della divisione per la grandezza della cache)
    size_t idx = hash % cache->capacity;
    // Salva il punto di partenza (nel caso facessimo tutto il giro senza trovare posti liberi)
    size_t start_idx = idx;

    // Finché il posto che stiamo guardando NON È VUOTO
    while (cache->table[idx].state != ENTRY_EMPTY) {
        
        // Controlliamo se in questo posto c'è ESATTAMENTE il file che stiamo cercando (stesso percorso)
        if (strcmp(cache->table[idx].path, path) == 0) {
            
            // --- GESTIONE THUNDERING HERD (Richieste Simultanee) ---
            // Se troviamo il file, ma lo stato è "PROCESSING", significa che un altro thread lo sta calcolando ORA.
            while (cache->table[idx].state == ENTRY_PROCESSING) {
                // Ci addormentiamo sulla condition variable GLOBALE, aspettando che l'altro thread finisca.
                // Questo sblocca la cache permettendo ad altri di lavorarci nel frattempo!
                CHECK(pthread_cond_wait(&cache->global_cv, &cache->mutex));
            }
            
            // Ci siamo svegliati! L'altro thread ha finito. 
            // Verifichiamo se è pronto e, cosa fondamentale, se la dimensione e la data di modifica
            // sono le stesse. Se il file è stato modificato mentre aspettavamo, l'hash è vecchio!
            if (cache->table[idx].state == ENTRY_READY && 
                cache->table[idx].size == size &&
                cache->table[idx].last_upd_sec == last_upd_sec &&
                cache->table[idx].last_upd_nsec == last_upd_nsec) {
                
                // Tutto perfetto! Copiamo il risultato pronto
                strcpy(hash_string, cache->table[idx].hash);
                // Incrementiamo le statistiche dei successi
                cache->hits++;
                // Sblocchiamo la cache e usciamo dicendo VERO (trovato!)
                CHECK(pthread_mutex_unlock(&cache->mutex));
                return true;
            } else {
                // Il file era lì ma era obsoleto o ci sono stati errori. 
                // Segniamo che ORA CI PENSIAMO NOI a calcolarlo (impostiamo a PROCESSING)
                cache->table[idx].state = ENTRY_PROCESSING;
                // È un fallimento per la cache (Miss)
                cache->misses++;
                // Sblocchiamo la cache e restituiamo FALSO (devi calcolarlo)
                CHECK(pthread_mutex_unlock(&cache->mutex));
                return false;
            }
        }
        
        // Se il posto era occupato da UN ALTRO file, proviamo il posto successivo nell'array (Probing Lineare)
        idx = (idx + 1) % cache->capacity;
        // Se abbiamo fatto un giro intero e siamo tornati al punto di partenza, la tabella è piena! Esci dal ciclo.
        if (idx == start_idx) break; 
    }

    // Se arriviamo qui fuori dal ciclo, significa che abbiamo trovato uno slot VUOTO.
    // Nessuno aveva mai calcolato questo file. 
    // Occupiamo subito il posto segnandolo come "IN ELABORAZIONE", così se arrivano altri thread aspetteranno noi.
    cache->table[idx].state = ENTRY_PROCESSING;
    // Copiamo il percorso del file nella struttura
    strncpy(cache->table[idx].path, path, PATH_MAX_LEN - 1);
    cache->table[idx].path[PATH_MAX_LEN - 1] = '\0'; // Assicuriamo che la stringa termini correttamente
    
    // Abbiamo aggiunto una voce, aumentiamo il conteggio globale
    cache->num_entries++;
    // Fallimento per la cache
    cache->misses++;

    // Sblocchiamo la cache e diciamo FALSO (non c'era, calcolalo tu)
    CHECK(pthread_mutex_unlock(&cache->mutex));
    return false;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: compute_sha256
// Funzione "operaia". Apre il file a pezzi, lo butta dentro OpenSSL e produce l'hash a 64 caratteri.
// -------------------------------------------------------------------------------------
int compute_sha256(const char* filepath, char* hash_string) {
    // Apriamo il file in modalità Lettura Binaria ("rb")
    FILE* file = fopen(filepath, "rb");
    // Se non riusciamo ad aprirlo (es. non abbiamo i permessi), restituiamo -1
    if (!file) { return -1; }

    // Struttura di OpenSSL per mantenere lo stato del calcolo
    SHA256_CTX sha256_ctx;
    // Inizializza la struttura
    SHA256_Init(&sha256_ctx);

    // Creiamo un secchiello da 4096 byte (4 Kilobyte) per leggere il file a pezzettini senza intasare la RAM
    char buffer[4096];
    size_t bytes_read;

    // fread legge un blocco di file. Finché fread restituisce un numero > 0 (cioè sta leggendo qualcosa)...
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // ...butta i byte letti in pasto all'algoritmo di OpenSSL
        SHA256_Update(&sha256_ctx, buffer, bytes_read);
    }

    // Abbiamo finito di leggere tutto il file, lo chiudiamo
    fclose(file);

    // Array grezzo per raccogliere l'hash generato da OpenSSL (che produce 32 byte binari incomprensibili)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // Chiediamo a OpenSSL di concludere il calcolo e metterlo nell'array 'hash'
    SHA256_Final(hash, &sha256_ctx);

    // Dobbiamo tradurre i 32 byte binari in 64 lettere/numeri esadecimali leggibili da umani (es. "a1b2c3...")
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        // Usiamo sprintf per convertire 1 byte in 2 caratteri esadecimali (%02x)
        sprintf(hash_string + (i * 2), "%02x", hash[i]);
    }
    // Aggiungiamo il terminatore di stringa finale per evitare sbavature di memoria
    hash_string[HASH_LEN] = '\0';

    // Tutto è andato bene
    return 0;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: add_to_cache
// Chiamata dal thread dopo aver finito un calcolo faticoso per salvare il risultato.
// -------------------------------------------------------------------------------------
void add_to_cache(cache_t* cache, const char* path, off_t size, time_t last_upd_sec, long last_upd_nsec, const char* hash) {
    // Ricalcola la posizione esatta in tabella
    uint64_t h = hash_fnv1a(path);
    
    // Blocca il lucchetto della cache
    CHECK(pthread_mutex_lock(&cache->mutex));
    
    size_t idx = h % cache->capacity;
    size_t start_idx = idx;

    // Cerca scorrendo finché non trova lo slot occupato
    while (cache->table[idx].state != ENTRY_EMPTY) {
        // Controlla che sia esattamente la casella del NOSTRO file
        if (strcmp(cache->table[idx].path, path) == 0) {
            
            // Copia l'hash appena calcolato
            strcpy(cache->table[idx].hash, hash);
            // Salva le informazioni del file (dimensione, data) per capire in futuro se verrà modificato
            cache->table[idx].size = size;
            cache->table[idx].last_upd_sec = last_upd_sec;
            cache->table[idx].last_upd_nsec = last_upd_nsec;
            
            // ORA! Cambiamo lo stato in "PRONTO"
            cache->table[idx].state = ENTRY_READY;
            
            // Il momento magico: Broadcast! Usiamo il megafono per svegliare TUTTI i thread che
            // erano rimasti bloccati addormentati in 'search_cache' ad aspettare che finissimo.
            CHECK(pthread_cond_broadcast(&cache->global_cv));
            break; // Abbiamo finito l'aggiornamento, usciamo dal ciclo
        }
        // Se non era qui, guarda la casella dopo
        idx = (idx + 1) % cache->capacity;
        if (idx == start_idx) break; 
    }

    // Sblocchiamo la cache
    CHECK(pthread_mutex_unlock(&cache->mutex));
}

// -------------------------------------------------------------------------------------
// FUNZIONE: run_server
// Questo è il ciclo vitale del server principale. Ascolta i client sulla FIFO globale
// e smista il lavoro.
// -------------------------------------------------------------------------------------
int run_server(server_t* server) {
    request_t req; // Conterrà la richiesta inviata dal client

    // Crea fisicamente il file speciale (FIFO/Pipe) sul disco se non esiste (permessi 0666)
    CHECK_RET(create_fifo(REQ_FIFO_PATH, 0666));

    printf(BOLD GREEN"[SERVER][INFO] Server Started!"RES"\n");
    printf(BOLD GREEN"[SERVER][INFO] %d Workers, %s Order"RES"\n", server->n_threads, (server->queue.order==ASCENDING)?"Ascending":"Descending");

    // Finché non premiamo CTRL+C o non arriva un comando di chiusura
    while (server->isrunning) {
        
        // Apriamo la FIFO per ascoltare usando gli STREAM in lettura binaria.
        // Se non ci sono client connessi, il server si "ferma e aspetta" su questa riga.
        FILE* stream = fopen(REQ_FIFO_PATH, "rb");
        
        // Se c'è stato un problema ad aprire
        if (!stream) {
            // Se l'errore è un "Interrupt" (es. è arrivato un CTRL+C), riprova l'inizio del ciclo (dove poi si fermerà per via del isrunning)
            if (errno == EINTR) continue;
            // Se è un errore vero, stampalo e rompi il ciclo
            perror(BOLD RED"[SERVER][ERRORE] Impossibile aprire la FIFO Server"RES);
            break;
        }

        // Finché il server è attivo, E riusciamo a leggere un "pacchetto intero" di richiesta_t dallo stream della Pipe...
        while (server->isrunning && fread(&req, sizeof(request_t), 1, stream) == 1) {
            
            // Analizziamo il tipo di richiesta ricevuta
            switch (req.type) {
                
                // --- Caso 1: Un client ci chiede l'hash di un file ---
                case HASH_A_FILE: {
                    // Controlliamo velocemente con 'access' se il file esiste nel disco. Se F_OK fallisce...
                    if (access(req.path, F_OK)!=0) {
                            // Prepariamo l'errore ENOENT (Errore, Nessun Elemento / File non trovato)
                            response_t resp = { .type = SEND_ERROR, .error_code = ENOENT, .message = "File not found" };
                            // Lo inviamo e passiamo alla prossima richiesta
                            CHECK(send_response(req.response_fifo_path, resp));
                            break;
                    }
                    // Chiediamo a Linux la dimensione del file usando 'stat'
                    struct stat st; 
                    off_t size = (stat(req.path, &st) == 0) ? st.st_size : -1;
                    // Se c'è stato un errore strano a prendere la dimensione
                    if (size == -1) {
                        response_t resp = { .type = SEND_ERROR, .error_code = errno };
                        CHECK(snprintf(resp.message, sizeof(resp.message), "%s", strerror(errno)));
                        CHECK(send_response(req.response_fifo_path, resp));
                        break;
                    }
                    
                    // Stampiamo che abbiamo accettato la richiesta
                    printf(BOLD GREEN"[SERVER][INFO] Requested Hash For %s (%lld Bytes)"RES"\n", req.path, (long long)size);
                    // INSERIAMO IL LAVORO NELLA NOSTRA CODA! I thread se lo andranno a prendere.
                    add_to_queue(&server->queue, req.path, req.response_fifo_path, req.pid, size);
                    break;
                }
                
                // --- Caso 2: Un client ci chiede di stampare i numeri e le statistiche ---
                case GET_STATISTICS: {
                    printf(BOLD GREEN"[SERVER][INFO] Requested Statistics"RES"\n");
                    response_t resp = { .type = SEND_STATISTICS, .error_code = 0 };

                    // Blocchiamo i lucchetti per evitare che le statistiche cambino mentre le copiamo
                    CHECK(pthread_mutex_lock(&server->stats_lock));
                    CHECK(pthread_mutex_lock(&server->cache.mutex));
                    
                    // Aggiorniamo i campi della struttura principale con quelli della cache
                    server->stats.cache_hits = server->cache.hits;
                    server->stats.cache_misses = server->cache.misses;
                    
                    CHECK(pthread_mutex_unlock(&server->cache.mutex));

                    // Copiamo tutte le statistiche formattate dentro la risposta da inviare al client
                    resp.stats = server->stats;
                    
                    CHECK(pthread_mutex_unlock(&server->stats_lock));

                    // Spediamo le statistiche
                    CHECK(send_response(req.response_fifo_path, resp));
                    break;
                }
                
                // --- Caso 3: Un client esegue ./client --chiudi ---
                case CLOSE_SERVER:
                    printf(BOLD YELLOW"[SERVER][INFO] Requested Server Closing"RES"\n");
                    // Modifichiamo il flag globale. Tutto il server comincerà a crollare dolcemente.
                    server->isrunning = false;
                    break;
                
                // --- Caso di Errore: Messaggio incomprensibile ---
                default:
                    fprintf(stderr, BOLD RED"[SERVER][ERRORE] Unknown Request: %d"RES"\n", req.type);
                    break;
            }
        }

        // Finito di leggere tutto quello che il client aveva scritto nella pipe, chiudiamo il "rubinetto" (stream)
        fclose(stream); 
    }

    // Server terminato, ritorna 0
    return 0;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: add_to_queue
// Mette una nuova richiesta ricevuta dal server all'interno della Coda, mettendola nell'ordine giusto.
// -------------------------------------------------------------------------------------
void add_to_queue(job_queue_t* queue, const char* path, const char* response_fifo_path, pid_t pid, off_t size) {
    // Chiudiamo il lucchetto. Solo il server può aggiungere elementi.
    CHECK(pthread_mutex_lock(&queue->mutex));

    // Se la coda è stata contrassegnata come chiusa (es. stiamo spegnendo), ignora la richiesta.
    if (queue->isclosed) {
        CHECK(pthread_mutex_unlock(&queue->mutex));
        return;
    }

    // --- Gestione della memoria dinamica dell'array ---
    // Se abbiamo raggiunto la capacità massima dell'array (es. i 128 posti sono finiti)...
    if (queue->num_jobs == queue->capacity) {
        // Raddoppiamo la capacità! Da 128 a 256.
        queue->capacity *= 2;
        // Usiamo realloc per allargare lo spazio di memoria che avevamo chiesto al sistema operativo.
        queue->jobs = realloc(queue->jobs, queue->capacity * sizeof(job_t));
        CHECK_ALLOC(queue->jobs);
    }

    // Indice finale dove appoggiare il nuovo file: esattamente in fondo alla lista!
    int current = queue->num_jobs;
    // Copiamo tutte le informazioni del lavoro nella nuova cella in fondo
    strncpy(queue->jobs[current].path, path, PATH_MAX_LEN - 1);
    queue->jobs[current].path[PATH_MAX_LEN - 1] = '\0';
    strncpy(queue->jobs[current].response_fifo_path, response_fifo_path, PATH_MAX_LEN - 1);
    queue->jobs[current].response_fifo_path[PATH_MAX_LEN - 1] = '\0';
    queue->jobs[current].pid = pid;
    queue->jobs[current].size = size;

    // Aumentiamo il contatore dei file in attesa
    queue->num_jobs++;

    // --- HEAPIFY UP (Spostare verso l'alto nella piramide) ---
    // Finché il nostro nuovo elemento non si trova in cima (posizione 0)...
    while (current > 0) {
        // Calcola matematicamente l'indice del suo "Capo" (il nodo genitore)
        int parent = (current - 1) / 2;
        // Se il nostro nuovo file è PIÙ IMPORTANTE (es. più piccolo) del genitore...
        if (heap_compare(queue, current, parent)) {
            // ...scambiali di posto! Il file appena arrivato sale di grado.
            heap_swap(queue, current, parent);
            // Aggiorna la posizione attuale e riprova a vedere se può salire ancora.
            current = parent;
        } else {
            // Se il genitore è più importante di noi, siamo arrivati al posto giusto. Ferma la risalita.
            break;
        }
    }

    // Manda un segnale (una "botta" al gong) alla Condition Variable: "Ehi thread addormentati, c'è un nuovo lavoro!"
    CHECK(pthread_cond_signal(&queue->cond_var));
    // Riapre il lucchetto
    CHECK(pthread_mutex_unlock(&queue->mutex));
}

// -------------------------------------------------------------------------------------
// FUNZIONE: close_server
// Eseguita alla fine di tutto, aspetta che i thread finiscano di lavorare e distrugge tutto.
// -------------------------------------------------------------------------------------
void close_server(server_t* server) {
    server->isrunning = false;
    
    // Assicuriamoci che la coda sia chiusa
    CHECK(pthread_mutex_lock(&server->queue.mutex));
    server->queue.isclosed = true;
    CHECK(pthread_cond_broadcast(&server->queue.cond_var)); // Sveglia l'ultimo thread addormentato
    CHECK(pthread_mutex_unlock(&server->queue.mutex));

    // Per ogni thread creato all'inizio...
    for (int i = 0; i < server->n_threads; i++) {
        if (server->threads[i].isactive) {
            // ...pthread_join() blocca il programma finché quel thread non termina le sue operazioni. 
            // Aspettiamo che muoiano uno ad uno.
            CHECK(pthread_join(server->threads[i].pthread, NULL));
            server->threads[i].isactive = false;
        }
    }

    // Distruggiamo la memoria
    close_queue(&server->queue);
    close_cache(&server->cache);
    // Rompiamo l'ultimo lucchetto rimasto
    CHECK(pthread_mutex_destroy(&server->stats_lock));
}

// -------------------------------------------------------------------------------------
// FUNZIONE: close_queue
// Pulisce e restituisce al sistema operativo la memoria allocata per la coda dei lavori.
// -------------------------------------------------------------------------------------
void close_queue(job_queue_t* queue) {
    CHECK(pthread_mutex_lock(&queue->mutex));

    // Se l'array esiste, usa free() per svuotarlo dalla RAM
    if (queue->jobs) {
        free(queue->jobs);
        queue->jobs = NULL; // Prevenzione errori
    }
    queue->capacity = 0;
    queue->num_jobs = 0;

    CHECK(pthread_mutex_unlock(&queue->mutex));
    // Distrugge definitivamente i meccanismi di sincronizzazione per evitare memory leaks
    CHECK(pthread_mutex_destroy(&queue->mutex));
    CHECK(pthread_cond_destroy(&queue->cond_var));
}

// -------------------------------------------------------------------------------------
// FUNZIONE: close_cache
// Pulisce e restituisce al sistema la memoria usata per il parcheggio della cache.
// -------------------------------------------------------------------------------------
void close_cache(cache_t* cache) {
    CHECK(pthread_mutex_lock(&cache->mutex));
    
    // Semplicemente butta via l'intero array contiguo che avevamo allocato con calloc!
    if (cache->table) {
        free(cache->table);
        cache->table = NULL;
    }
    cache->capacity = 0;
    
    CHECK(pthread_mutex_unlock(&cache->mutex));
    // Distrugge gli strumenti
    CHECK(pthread_mutex_destroy(&cache->mutex));
    CHECK(pthread_cond_destroy(&cache->global_cv));
}

// -------------------------------------------------------------------------------------
// FUNZIONE: show_statistics
// Funzione di servizio che stampa a video (in blu) i dati della struct statistiche.
// -------------------------------------------------------------------------------------
void show_statistics(const stats_t* stats) {
    printf(BOLD BLUE"\tStatistiche"RES"\n");
    // Calcola la percentuale di successi. Se ho 0 richieste, stampo 0 per evitare errori matematici (divisione per zero)
    printf(BOLD BLUE"Cache Hit Ratio: %.2f"RES"\n", stats->num_requests > 0 ? (100.0 * stats->cache_hits / stats->num_requests) : 0.0);
    printf(BOLD BLUE"Numero File Processati: %lu"RES"\n", stats->num_processed);
    printf(BOLD BLUE"Tempo Medio di Processamento: %.3f ms"RES"\n", stats->average_proc_time * 1000);
    printf(BOLD BLUE"Numero Richieste: %lu"RES"\n", stats->num_requests);
    printf(BOLD BLUE"Numero Cache Hits: %lu"RES"\n", stats->cache_hits);
    printf(BOLD BLUE"Numero Cache Misses: %lu"RES"\n", stats->cache_misses);
}

// -------------------------------------------------------------------------------------
// FUNZIONE: server_help
// Viene richiamata se si lancia il server con parametri sbagliati o con -h
// -------------------------------------------------------------------------------------
void server_help(const char* name) {
    printf("Utilizzo: %s (opzioni)\n", name);
    printf(" -h, --help                               Mostra questo messaggio di aiuto\n");
    printf(" -t <num> oppure --threads <num>          Numero di Thread concorrenti (def: 4)\n");
    printf(" -o <asc|desc> oppure --ordine <asc|desc>  Ordine di processamento dei file (def: asc)\n");

    printf("ESEMPIO: ./bin/server -t 5 -o asc \n");
}