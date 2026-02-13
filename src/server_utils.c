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

void sig_handler(int sig) {
    if (g_server) {
        printf(BOLD YELLOW"\n[SERVER][INFO] Signal %d Received - Closing Server"RES"\n", sig);
        g_server->isrunning = false;

        CHECK(pthread_mutex_lock(&g_server->queue.mutex));
        g_server->queue.isclosed = true;
        CHECK(pthread_cond_broadcast(&g_server->queue.cond_var));
        CHECK(pthread_mutex_unlock(&g_server->queue.mutex));
    }
}

int init_server(server_t* server, int n_threads, int order) {
    
    server->queue = (job_queue_t){ .order = order };
    CHECK(pthread_cond_init(&server->queue.cond_var, NULL));
    CHECK(pthread_mutex_init(&server->queue.mutex, NULL));

    server->cache = (cache_t){ .lists = calloc(LIST_SIZE, sizeof(entry_t*)), .num_lists = LIST_SIZE };
    CHECK_ALLOC(server->cache.lists);
    CHECK(pthread_mutex_init(&server->cache.mutex, NULL));

    memset(&server->stats, 0, sizeof(stats_t));
    CHECK(pthread_mutex_init(&server->stats_lock, NULL));

    server->n_threads = n_threads;
    server->isrunning = true;

    for (int i = 0; i < n_threads; i++) {
        server->threads[i].thread_id = i;
        server->threads[i].isactive = true;
        CHECK_RET(pthread_create(&server->threads[i].pthread, NULL, thread_function, server));
    }

    return 0;
}

void* thread_function(void* arg) {
    server_t* server = (server_t*)arg;
    
    printf(BOLD GREEN"[SERVER][INFO] New Thread Started!"RES"\n");
    
    job_t job;
    while (server->isrunning) {
        if (get_from_queue(&server->queue, &job) == -1) { break; }

        struct timespec start_time, end_time;
        clock_gettime(1, &start_time);

        struct stat st;
        if (stat(job.path, &st) == -1) {
            response_t resp = { .type = SEND_ERROR, .error_code = errno };
            snprintf(resp.message, sizeof(resp.message), "[ERRORE] %s", strerror(errno));
            send_response(job.response_fifo_path, resp);
            continue;
        }

        off_t size = st.st_size;
        time_t last_upd_sec = st.st_mtime;
        long last_upd_nsec = st.st_mtim.tv_nsec;

        char hash_result[HASH_LEN + 1];
        bool cache_hit = search_cache(&server->cache, job.path, size, last_upd_sec, last_upd_nsec, hash_result);

        if (!cache_hit) {
            if (compute_sha256(job.path, hash_result) == -1) {
                    response_t resp = { .type = SEND_ERROR, .error_code = errno };
                    snprintf(resp.message, sizeof(resp.message),"[SERVER][ERRORE] Cannot compute hash: %s", strerror(errno));
                    send_response(job.response_fifo_path, resp);
                    continue;
            }

            add_to_cache(&server->cache, job.path, size, last_upd_sec, last_upd_nsec, hash_result);

            CHECK(pthread_mutex_lock(&server->stats_lock));
            server->stats.num_processed++;
            CHECK(pthread_mutex_unlock(&server->stats_lock));
        }

        response_t resp = { .type = SEND_HASH, .error_code = 0, .message = "" };
        strcpy(resp.hash, hash_result);
        CHECK(send_response(job.response_fifo_path, resp));

        clock_gettime(1, &end_time);
        double proc_time = elapsed_time(start_time, end_time);

        CHECK(pthread_mutex_lock(&server->stats_lock));
        server->stats.num_requests++;
        if (cache_hit) {
            server->stats.cache_hits++;
        } else {
            server->stats.cache_misses++;
        }

        double tot_time = server->stats.average_proc_time * (server->stats.num_requests - 1);
        server->stats.average_proc_time = (tot_time + proc_time) / server->stats.num_requests;

        CHECK(pthread_mutex_unlock(&server->stats_lock));

        printf(BOLD GREEN"[SERVER][INFO] File: %s processato in %.3f ms. (%s)"RES"\n",
               job.path, proc_time * 1000, cache_hit ? "l'hash era in cache" : "l'hash è stato calcolato");
    }

    printf(BOLD YELLOW"[SERVER][INFO] Thread Chiuso"RES"\n");
    return NULL;
}

int get_from_queue(job_queue_t* queue, job_t* job) {
    CHECK(pthread_mutex_lock(&queue->mutex));

    while (!queue->head && !queue->isclosed) {
        CHECK(pthread_cond_wait(&queue->cond_var, &queue->mutex));
    }

    if (queue->isclosed && !queue->head) {
        CHECK(pthread_mutex_unlock(&queue->mutex));
        return -1;
    }

    job_t* j = queue->head;
    queue->head = j->next;
    queue->num_jobs--;

    *job = *j;
    free(j);

    CHECK(pthread_mutex_unlock(&queue->mutex));
    return 0;
}

bool search_cache(cache_t* cache, const char* path, off_t size, time_t last_upd_sec, long last_upd_nsec, char* hash_string) {
    entry_t* entry = get_cache_entry(cache, path);
    if (!entry) {
        CHECK(pthread_mutex_lock(&cache->mutex));
        cache->misses++;
        CHECK(pthread_mutex_unlock(&cache->mutex));
        return false;
    }

    CHECK(pthread_mutex_lock(&entry->mutex));
    

    if (entry->iscomputed && entry->size == size &&
        entry->last_upd_sec == last_upd_sec && entry->last_upd_nsec == last_upd_nsec) {
        strcpy(hash_string, entry->hash);
        CHECK(pthread_mutex_unlock(&entry->mutex));

        CHECK(pthread_mutex_lock(&cache->mutex));
        cache->hits++;
        CHECK(pthread_mutex_unlock(&cache->mutex));
        return true;
    }
    

    if (entry->iscomputing) {
        entry->threads_waiting++;
        while (entry->iscomputing) {
            CHECK(pthread_cond_wait(&entry->cond_var, &entry->mutex));
        }
        entry->threads_waiting--;
        

        if (entry->iscomputed && entry->size == size &&
            entry->last_upd_sec == last_upd_sec && entry->last_upd_nsec == last_upd_nsec) {
            strcpy(hash_string, entry->hash);
            CHECK(pthread_mutex_unlock(&entry->mutex));

            CHECK(pthread_mutex_lock(&cache->mutex));
            cache->hits++;
            CHECK(pthread_mutex_unlock(&cache->mutex));
            return true;
        }
    }
    

    if (!entry->iscomputing) { entry->iscomputing = true; }

    CHECK(pthread_mutex_unlock(&entry->mutex));
    CHECK(pthread_mutex_lock(&cache->mutex));
    cache->misses++;
    CHECK(pthread_mutex_unlock(&cache->mutex));
    return false;
}

entry_t* get_cache_entry(cache_t* cache, const char* path) {
    unsigned long hash = 5381;
    const char *p = path;
    while (*p) { hash = ((hash << 5) + hash) + *p; p++; } // hash del path
    size_t i = hash % cache->num_lists;

    CHECK(pthread_mutex_lock(&cache->mutex));

    entry_t* entry = cache->lists[i];
    while (entry && strcmp(entry->path, path) != 0) {
        entry = entry->next;
    }

    if (!entry) {
        entry = malloc(sizeof(entry_t));
        if (entry) {
            *entry = (entry_t){.next = cache->lists[i]};
            strncpy(entry->path, path,  PATH_MAX_LEN - 1);
            entry->path[PATH_MAX_LEN - 1] = '\0';
            pthread_mutex_init(&entry->mutex, NULL);
            pthread_cond_init(&entry->cond_var, NULL);
            cache->lists[i] = entry;
        }
    }

    CHECK(pthread_mutex_unlock(&cache->mutex));
    return entry;
}

int compute_sha256(const char* filepath, char* hash_string) {
    FILE* file = fopen(filepath, "rb");
    if (!file) { return -1; }

    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);

    char buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&sha256_ctx, buffer, bytes_read);
    }

    fclose(file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256_ctx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_string + (i * 2), "%02x", hash[i]);
    }
    hash_string[HASH_LEN] = '\0';

    return 0;
}

void add_to_cache(cache_t* cache, const char* path, off_t size, time_t last_upd_sec, long last_upd_nsec, const char* hash) {
    entry_t* entry = get_cache_entry(cache, path);
    if (!entry) return;

    CHECK(pthread_mutex_lock(&entry->mutex));

    strcpy(entry->hash, hash);
    entry->size = size;
    entry->last_upd_sec = last_upd_sec;
    entry->last_upd_nsec = last_upd_nsec;
    entry->iscomputed = true;
    entry->iscomputing = false;

    if (entry->threads_waiting > 0) {
        CHECK(pthread_cond_broadcast(&entry->cond_var));
    }

    CHECK(pthread_mutex_unlock(&entry->mutex));
}

int run_server(server_t* server) {
    request_t req;
    int fd;

    CHECK_RET(create_fifo(REQ_FIFO_PATH, 0666));

    printf(BOLD GREEN"[SERVER][INFO] Server Started!"RES"\n");
    printf(BOLD GREEN"[SERVER][INFO] %d Workers, %s Order"RES"\n", server->n_threads, (server->queue.order==ASCENDING)?"Ascending":"Descending");

    while (server->isrunning) {
        fd = open_for_reading(REQ_FIFO_PATH);
        if (fd == -1) {
            if (errno == EINTR) continue;
            else perror("[SERVER][ERRORE] Open Fifo Read");
            break;
        }

        while (server->isrunning) {
            if (read_message(fd, &req, sizeof(req)) == -1) { break; }
            
            switch (req.type) {
                case HASH_A_FILE: {
                    if (access(req.path, F_OK)!=0) {
                            response_t resp = { .type = SEND_ERROR, .error_code = ENOENT, .message = "File not found" };
                            CHECK(send_response(req.response_fifo_path, resp));
                            break;
                    }
                    struct stat st; off_t size = (stat(req.path, &st) == 0) ? st.st_size : -1;
                    if (size == -1) {
                        response_t resp = { .type = SEND_ERROR, .error_code = errno };
                        CHECK(snprintf(resp.message, sizeof(resp.message), "%s", strerror(errno)));
                        CHECK(send_response(req.response_fifo_path, resp));
                        break;
                    }
                    printf(BOLD GREEN"[SERVER][INFO] Requested Hash For %s (%lld Bytes)"RES"\n", req.path, (long long)size);
                    add_to_queue(&server->queue, req.path, req.response_fifo_path, req.pid, size);
                    break;
                }
                case GET_STATISTICS: {
                    printf(BOLD GREEN"[SERVER][INFO] Requested Statistics"RES"\n");
                    response_t resp = { .type = SEND_STATISTICS, .error_code = 0 };

                    CHECK(pthread_mutex_lock(&server->stats_lock));
                    CHECK(pthread_mutex_lock(&server->cache.mutex));
                    server->stats.cache_hits = server->cache.hits;
                    server->stats.cache_misses = server->cache.misses;
                    CHECK(pthread_mutex_unlock(&server->cache.mutex));

                    resp.stats = server->stats;
                    CHECK(pthread_mutex_unlock(&server->stats_lock));

                    CHECK(send_response(req.response_fifo_path, resp));
                    break;
                }
                case CLOSE_SERVER:
                    printf(BOLD YELLOW"[SERVER][INFO] Requested Server Closing"RES"\n");
                    server->isrunning = false;
                    break;
                default:
                    fprintf(stderr, BOLD RED"[SERVER][ERRORE] Unknown Request: %d"RES"\n", req.type);
                    break;
            }
        }

        close(fd);
    }

    return 0;
}

void add_to_queue(job_queue_t* queue, const char* path, const char* response_fifo_path, pid_t pid, off_t size) {
    job_t* new_job = malloc(sizeof(job_t));
    if (!new_job) return;

    strncpy(new_job->path, path, PATH_MAX_LEN - 1);
    new_job->path[PATH_MAX_LEN - 1] = '\0';

    strncpy(new_job->response_fifo_path, response_fifo_path, PATH_MAX_LEN - 1);
    new_job->response_fifo_path[PATH_MAX_LEN - 1] = '\0';

    new_job->pid = pid;
    new_job->size = size;
    new_job->next = NULL;

    CHECK(pthread_mutex_lock(&queue->mutex));

    if (queue->isclosed) {
        free(new_job);
        CHECK(pthread_mutex_unlock(&queue->mutex));
        return;
    }

    job_t** ptr = &queue->head;

    while (*ptr) {

        bool continue_traversal = (queue->order == ASCENDING) ? (size >= (*ptr)->size) : (size <= (*ptr)->size);
        if (!continue_traversal) break;
        ptr = &(*ptr)->next;
    }
    new_job->next = *ptr;
    *ptr = new_job;

    queue->num_jobs++;
    CHECK(pthread_cond_signal(&queue->cond_var));
    CHECK(pthread_mutex_unlock(&queue->mutex));
}

void close_server(server_t* server) {
    server->isrunning = false;
    
    CHECK(pthread_mutex_lock(&server->queue.mutex));
    server->queue.isclosed = true;
    CHECK(pthread_cond_broadcast(&server->queue.cond_var));
    CHECK(pthread_mutex_unlock(&server->queue.mutex));

    for (int i = 0; i < server->n_threads; i++) {
        if (server->threads[i].isactive) {
            CHECK(pthread_join(server->threads[i].pthread, NULL));
            server->threads[i].isactive = false;
        }
    }

    close_queue(&server->queue);
    close_cache(&server->cache);
    CHECK(pthread_mutex_destroy(&server->stats_lock));
}

void close_queue(job_queue_t* queue) {
    CHECK(pthread_mutex_lock(&queue->mutex));

    job_t* current = queue->head;
    while (current) {
        job_t* next = current->next;
        free(current);
        current = next;
    }
    queue->head = NULL;
    queue->num_jobs = 0;

    CHECK(pthread_mutex_unlock(&queue->mutex));
    CHECK(pthread_mutex_destroy(&queue->mutex));
    CHECK(pthread_cond_destroy(&queue->cond_var));
}

void close_cache(cache_t* cache) {
    CHECK(pthread_mutex_lock(&cache->mutex));

    for (size_t i = 0; i < cache->num_lists; i++) {
        entry_t* entry = cache->lists[i];
        while (entry) {
            entry_t* next = entry->next;
            CHECK(pthread_mutex_destroy(&entry->mutex));
            CHECK(pthread_cond_destroy(&entry->cond_var));
            free(entry);
            entry = next;
        }
    }

    free(cache->lists);
    CHECK(pthread_mutex_unlock(&cache->mutex));
    CHECK(pthread_mutex_destroy(&cache->mutex));
}

void show_statistics(const stats_t* stats) {
    printf(BOLD BLUE"\tStatistiche"RES"\n");
    printf(BOLD BLUE"Cache Hit Ratio: %.2f"RES"\n", stats->num_requests > 0 ? (100.0 * stats->cache_hits / stats->num_requests) : 0.0);
    printf(BOLD BLUE"Numero File Processati: %lu"RES"\n", stats->num_processed);
    printf(BOLD BLUE"Tempo Medio di Processamento: %.3f ms"RES"\n", stats->average_proc_time * 1000);
    printf(BOLD BLUE"Numero Richieste: %lu"RES"\n", stats->num_requests);
    printf(BOLD BLUE"Numero Cache Hits: %lu"RES"\n", stats->cache_hits);
    printf(BOLD BLUE"Numero Cache Misses: %lu"RES"\n", stats->cache_misses);
}

void server_help(const char* name) {
    printf("Utilizzo: %s (opzioni)\n", name);
    printf(" -h, --help                               Mostra questo messaggio di aiuto\n");
    printf(" -t <num> oppure --threads <num>          Numero di Thread concorrenti (def: 4)\n");
    printf(" -o <asc|desc> oppure --ordine <asc|desc>  Ordine di processamento dei file (def: asc)\n");

    printf("ESEMPIO: ./bin/server -t 5 -o asc \n");
}