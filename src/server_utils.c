#include "server_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>


off_t dimensione_file(const char* path) {
    struct stat stat_file;
    if (stat(path, &stat_file) == -1) {
        return -1;
    }
    return stat_file.st_size;
}

int ultima_modifica(const char* path, time_t* secondi, long* nanosecondi) {
    struct stat stat_file;
    if (stat(path, &stat_file) == -1) {
        return -1;
    }
    *secondi = stat_file.st_mtime;
    *nanosecondi = stat_file.st_mtim.tv_nsec;
    return 0;
}

void stampa_statistiche(const statistiche_t* statistiche) {
    printf("=== Server Statistics ===\n");
    printf("Total requests: %lu\n", statistiche->richieste_totali);
    printf("Cache hits: %lu\n", statistiche->cache_hits);
    printf("Cache misses: %lu\n", statistiche->cache_misses);
    printf("Files processed: %lu\n", statistiche->file_processati);

    printf("Cache hit ratio: %.2f%%\n", statistiche->richieste_totali > 0 ? (100.0 * statistiche->cache_hits / statistiche->richieste_totali) : 0.0);
    printf("Average processing time: %.3f ms\n", statistiche->media_tempo_processamento * 1000);
    printf("========================\n");
}

int sha256_file(const char* path, char* hash_file) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        return -1;
    }
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);

    char buffer[4096];
    size_t letti;

    while ((letti = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&sha256_ctx, buffer, letti);
    }

    fclose(file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256_ctx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_file + (i * 2), "%02x", hash[i]);
    }
    hash_file[LUNGHEZZA_HASH] = '\0';

    return 0;
}

void elimina_coda(coda_t* coda) {
    pthread_mutex_lock(&coda->mutex);

    lavoro_t* corrente = coda->testa;
    while (corrente) {
        lavoro_t* prossimo = corrente->prossimo;
        free(corrente);
        corrente = prossimo;
    }
    coda->testa = NULL;
    coda->numero_elementi = 0;

    pthread_mutex_unlock(&coda->mutex);
    pthread_mutex_destroy(&coda->mutex);
    pthread_cond_destroy(&coda->cond_var);
}

void aggiungi_alla_coda(coda_t* coda, const char* path, const char* fifo_risposta, pid_t pid_client, off_t dimensione) {
    lavoro_t* lavoro = malloc(sizeof(lavoro_t));
    if (!lavoro) return;

    strncpy(lavoro->path, path, LUNGHEZZA_MAX_PATH - 1);
    lavoro->path[LUNGHEZZA_MAX_PATH - 1] = '\0';

    strncpy(lavoro->fifo_risposta, fifo_risposta, LUNGHEZZA_MAX_PATH - 1);
    lavoro->fifo_risposta[LUNGHEZZA_MAX_PATH - 1] = '\0';

    lavoro->pid_client = pid_client;
    lavoro->dimensione = dimensione;
    lavoro->prossimo = NULL;

    pthread_mutex_lock(&coda->mutex);

    if (coda->coda_chiusa) {
        free(lavoro);
        pthread_mutex_unlock(&coda->mutex);
        return;
    }

    lavoro_t** p = &coda->testa;

    while (*p) {

        bool scorri_avanti = (coda->ordine == ORDINE_ASCENDENTE) ? (dimensione >= (*p)->dimensione) : (dimensione <= (*p)->dimensione);
        if (!scorri_avanti) break;
        p = &(*p)->prossimo;
    }
    lavoro->prossimo = *p;
    *p = lavoro;

    coda->numero_elementi++;
    pthread_cond_signal(&coda->cond_var);
    pthread_mutex_unlock(&coda->mutex);
}

int estrai_dalla_coda(coda_t* coda, lavoro_t* lavoro) {
    pthread_mutex_lock(&coda->mutex);

    while (!coda->testa && !coda->coda_chiusa) {
        pthread_cond_wait(&coda->cond_var, &coda->mutex);
    }

    if (coda->coda_chiusa && !coda->testa) {
        pthread_mutex_unlock(&coda->mutex);
        return -1;
    }

    lavoro_t* elemento = coda->testa;
    coda->testa = elemento->prossimo;
    coda->numero_elementi--;

    *lavoro = *elemento;
    free(elemento);

    pthread_mutex_unlock(&coda->mutex);
    return 0;
}

unsigned long path_hash(const char *s) {
    unsigned long h = 5381;
    while (*s) h = ((h << 5) + h) + *s++;
    return h;
}

void elimina_cache(cache_t* cache) {
    pthread_mutex_lock(&cache->mutex);

    for (size_t i = 0; i < cache->nbuckets; i++) {
        elemento_cache_t* elemento = cache->buckets[i];
        while (elemento) {
            elemento_cache_t* prossimo = elemento->prossimo;
            pthread_mutex_destroy(&elemento->mutex);
            pthread_cond_destroy(&elemento->cond_var);
            free(elemento);
            elemento = prossimo;
        }
    }

    free(cache->buckets);
    pthread_mutex_unlock(&cache->mutex);
    pthread_mutex_destroy(&cache->mutex);
}

elemento_cache_t* ottieni_elemento_cache(cache_t* cache, const char* path) {
    unsigned long hash = path_hash(path);
    size_t bucket = hash % cache->nbuckets;

    pthread_mutex_lock(&cache->mutex);

    elemento_cache_t* elemento = cache->buckets[bucket];
    while (elemento && strcmp(elemento->path, path) != 0) {
        elemento = elemento->prossimo;
    }

    if (!elemento) {
        elemento = malloc(sizeof(elemento_cache_t));
        if (elemento) {
            *elemento = (elemento_cache_t){.prossimo = cache->buckets[bucket]};
            strncpy(elemento->path, path, LUNGHEZZA_MAX_PATH - 1);
            elemento->path[LUNGHEZZA_MAX_PATH - 1] = '\0';
            pthread_mutex_init(&elemento->mutex, NULL);
            pthread_cond_init(&elemento->cond_var, NULL);
            cache->buckets[bucket] = elemento;
        }
    }

    pthread_mutex_unlock(&cache->mutex);
    return elemento;
}

bool controllo_cache(cache_t* cache, const char* path, off_t dimensione, time_t ultima_modifica_sec, long ultima_modifica_nsec, char* hash_file) {
    elemento_cache_t* elemento = ottieni_elemento_cache(cache, path);
    if (!elemento) {
        pthread_mutex_lock(&cache->mutex);
        cache->misses++;
        pthread_mutex_unlock(&cache->mutex);
        return false;
    }

    pthread_mutex_lock(&elemento->mutex);
    

    if (elemento->hash_pronto && elemento->dimensione == dimensione &&
        elemento->ultima_modifica_sec == ultima_modifica_sec && elemento->ultima_modifica_nsec == ultima_modifica_nsec) {
        strcpy(hash_file, elemento->hash);
        pthread_mutex_unlock(&elemento->mutex);

        pthread_mutex_lock(&cache->mutex);
        cache->hits++;
        pthread_mutex_unlock(&cache->mutex);
        return true;
    }
    

    if (elemento->hash_in_calcolo) {
        elemento->thread_in_attesa++;
        while (elemento->hash_in_calcolo) {
            pthread_cond_wait(&elemento->cond_var, &elemento->mutex);
        }
        elemento->thread_in_attesa--;
        

        if (elemento->hash_pronto && elemento->dimensione == dimensione &&
            elemento->ultima_modifica_sec == ultima_modifica_sec && elemento->ultima_modifica_nsec == ultima_modifica_nsec) {
            strcpy(hash_file, elemento->hash);
            pthread_mutex_unlock(&elemento->mutex);

            pthread_mutex_lock(&cache->mutex);
            cache->hits++;
            pthread_mutex_unlock(&cache->mutex);
            return true;
        }
    }
    

    if (!elemento->hash_in_calcolo) { elemento->hash_in_calcolo = true; }

    pthread_mutex_unlock(&elemento->mutex);
    pthread_mutex_lock(&cache->mutex);
    cache->misses++;
    pthread_mutex_unlock(&cache->mutex);
    return false;
}

void salva_in_cache(cache_t* cache, const char* path, off_t dimensione, time_t ultima_modifica_sec, long ultima_modifica_nsec, const char* hash) {
    elemento_cache_t* elemento = ottieni_elemento_cache(cache, path);
    if (!elemento) return;

    pthread_mutex_lock(&elemento->mutex);

    strcpy(elemento->hash, hash);
    elemento->dimensione = dimensione;
    elemento->ultima_modifica_sec = ultima_modifica_sec;
    elemento->ultima_modifica_nsec = ultima_modifica_nsec;
    elemento->hash_pronto = true;
    elemento->hash_in_calcolo = false;

    if (elemento->thread_in_attesa > 0) {
        pthread_cond_broadcast(&elemento->cond_var);
    }

    pthread_mutex_unlock(&elemento->mutex);
}

void gestore_segnali(int sig) {
    if (server_varglobale) {
        printf("\nReceived signal %d, shutting down server\n", sig);
        server_varglobale->in_esecuzione = false;
        pthread_mutex_lock(&server_varglobale->coda.mutex);
        server_varglobale->coda.coda_chiusa = true;
        pthread_cond_broadcast(&server_varglobale->coda.cond_var);
        pthread_mutex_unlock(&server_varglobale->coda.mutex);
    }
}

void* funzione_thread(void* arg) {
    server_t* server = (server_t*)arg;
    lavoro_t lavoro;

    printf("Worker thread started\n");

    while (server->in_esecuzione) {
        if (estrai_dalla_coda(&server->coda, &lavoro) == -1) { break; }
        struct timespec inizio, fine;
        clock_gettime(1, &inizio);
        
        off_t dimensione = dimensione_file(lavoro.path);
        time_t ultima_modifica_sec;
        long ultima_modifica_nsec;


        if (dimensione == -1 || ultima_modifica(lavoro.path, &ultima_modifica_sec, &ultima_modifica_nsec) == -1) {
            messaggio_risposta_t risposta = { .tipo = ERRORE, .codice = errno };
            snprintf(risposta.messaggio, sizeof(risposta.messaggio), "Cannot access file: %s", strerror(errno));
            invia_risposta(lavoro.fifo_risposta, risposta);
            continue;
        }

        char hash[LUNGHEZZA_HASH + 1];

        bool cache_hit = controllo_cache(&server->cache, lavoro.path, dimensione, ultima_modifica_sec, ultima_modifica_nsec, hash);

        if (!cache_hit) {
            if (sha256_file(lavoro.path, hash) == -1) {
                    messaggio_risposta_t risposta = { .tipo = ERRORE, .codice = errno };
                    snprintf(risposta.messaggio, sizeof(risposta.messaggio), "Cannot compute hash: %s", strerror(errno));
                    invia_risposta(lavoro.fifo_risposta, risposta);
                    continue;
            }

            salva_in_cache(&server->cache, lavoro.path, dimensione, ultima_modifica_sec, ultima_modifica_nsec, hash);

            pthread_mutex_lock(&server->mutex_statistiche);
            server->statistiche.file_processati++;
            pthread_mutex_unlock(&server->mutex_statistiche);
        }

        messaggio_risposta_t risposta = { .tipo = RISPOSTA_HASH, .codice = 0, .messaggio = "" };
        strcpy(risposta.hash, hash);
        int fifo_risposta = invia_risposta(lavoro.fifo_risposta, risposta);
        if (fifo_risposta == -1) printf("Warning: Cannot open response FIFO for client\n");

        clock_gettime(1, &fine);
        double tempo_processamento = differenza(inizio, fine);

        pthread_mutex_lock(&server->mutex_statistiche);
        server->statistiche.richieste_totali++;
        if (cache_hit) {
            server->statistiche.cache_hits++;
        } else {
            server->statistiche.cache_misses++;
        }


        double tempo_totale = server->statistiche.media_tempo_processamento * (server->statistiche.richieste_totali - 1);
        server->statistiche.media_tempo_processamento = (tempo_totale + tempo_processamento) / server->statistiche.richieste_totali;

        pthread_mutex_unlock(&server->mutex_statistiche);

        printf("Processed file: %s (%.3f ms, %s)\n",
               lavoro.path, tempo_processamento * 1000, cache_hit ? "cache hit" : "computed");
    }

    printf("Worker thread terminated\n");
    return NULL;
}

int inizializza_server(server_t* server, int numero_thread, int ordine) {

    server->coda = (coda_t){ .testa=NULL, .coda_chiusa=false, .ordine=ordine, .numero_elementi=0 };
    pthread_cond_init(&server->coda.cond_var, NULL);
    pthread_mutex_init(&server->coda.mutex, NULL);

    server->cache = (cache_t){ .buckets = calloc(DIMENSIONE_HASH_BUCKET, sizeof(elemento_cache_t*)), .nbuckets = DIMENSIONE_HASH_BUCKET };
    pthread_mutex_init(&server->cache.mutex, NULL);

    memset(&server->statistiche, 0, sizeof(statistiche_t));
    pthread_mutex_init(&server->mutex_statistiche, NULL);

    server->numero_thread = numero_thread;
    server->in_esecuzione = true;

    for (int i = 0; i < numero_thread; i++) {
        server->threads[i].id = i;
        server->threads[i].attivo = true;

        if (pthread_create(&server->threads[i].thread, NULL, funzione_thread, server) != 0) {
            perror("pthread_create");
            return -1;
        }
    }

    return 0;
}

void chiudi_server(server_t* server) {
    server->in_esecuzione = false;

    pthread_mutex_lock(&server->coda.mutex);
    server->coda.coda_chiusa = true;
    pthread_cond_broadcast(&server->coda.cond_var);
    pthread_mutex_unlock(&server->coda.mutex);

    for (int i = 0; i < server->numero_thread; i++) {
        if (server->threads[i].attivo) {
            pthread_join(server->threads[i].thread, NULL);
            server->threads[i].attivo = false;
        }
    }

    elimina_coda(&server->coda);
    elimina_cache(&server->cache);
    pthread_mutex_destroy(&server->mutex_statistiche);
}

int esegui_server(server_t* server) {
    int fifo_richiesta;
    messaggio_richiesta_t richiesta;
    

    if (crea_fifo(PATH_FIFO_RICHIESTA, 0666) == -1) { return -1; } 
    
    while (server->in_esecuzione) {
        fifo_richiesta = apri_fifo_lettura(PATH_FIFO_RICHIESTA);
        if (fifo_richiesta == -1) {
            if (errno == EINTR) continue;
            perror("open request FIFO");
            break;
        }

        while (server->in_esecuzione) {
            if (leggi_da_fifo(fifo_richiesta, &richiesta, sizeof(richiesta)) == -1) { break; }
            
            switch (richiesta.tipo) {
                case RICHIESTA_HASH: {
                    if (!(access(richiesta.path, F_OK) == 0)) {
                            messaggio_risposta_t risposta = { .tipo = ERRORE, .codice = ENOENT, .messaggio = "File not found" };
                            invia_risposta(richiesta.fifo_risposta, risposta);
                            break;
                    }
                    off_t dimensione = dimensione_file(richiesta.path);
                    if (dimensione == -1) {
                        messaggio_risposta_t risposta = { .tipo = ERRORE, .codice = errno };
                        snprintf(risposta.messaggio, sizeof(risposta.messaggio), "%s", strerror(errno));
                        invia_risposta(richiesta.fifo_risposta, risposta);
                        break;
                    }
                    printf("Received hash request for: %s (size: %lld bytes)\n", richiesta.path, (long long)dimensione);
                    aggiungi_alla_coda(&server->coda, richiesta.path, richiesta.fifo_risposta, richiesta.pid_client, dimensione);
                    break;
                }
                case RICHIESTA_STATISTICHE: {
                    messaggio_risposta_t risposta = { .tipo = RISPOSTA_STATISTICHE, .codice = 0 };

                    pthread_mutex_lock(&server->mutex_statistiche);
                    pthread_mutex_lock(&server->cache.mutex);
                    server->statistiche.cache_hits = server->cache.hits;
                    server->statistiche.cache_misses = server->cache.misses;
                    pthread_mutex_unlock(&server->cache.mutex);

                    risposta.statistiche = server->statistiche;
                    pthread_mutex_unlock(&server->mutex_statistiche);

                    invia_risposta(richiesta.fifo_risposta, risposta);
                    break;
                }
                case CHIUSURA:
                    printf("Received termination request\n");
                    server->in_esecuzione = false;
                    break;
                default:
                    fprintf(stderr, "Unknown request type: %d\n", richiesta.tipo);
                    break;
            }
        }

        close(fifo_richiesta);
    }

    return 0;
}