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

int init_server(server_t* server, int num_workers, int order) {
    
    server->queue = (job_queue_t){ .head=NULL, .isclosed=false, .order=order, .dim=0 };
    CHECK(pthread_cond_init(&server->queue.cond_var, NULL));
    CHECK(pthread_mutex_init(&server->queue.mutex, NULL));

    server->cache = (cache_t){ .buckets = calloc(BUCKET_SIZE, sizeof(cache_entry_t*)), .dim = BUCKET_SIZE };
    CHECK_ALLOC(server->cache.buckets);
    CHECK(pthread_mutex_init(&server->cache.mutex, NULL));

    memset(&server->stats, 0, sizeof(stats_t));
    CHECK(pthread_mutex_init(&server->stats_mtx, NULL));

    server->num_workers = num_workers;
    server->isrunning = true;

    for (int i = 0; i < num_workers; i++) {
        server->workers[i].thread_id = i;
        server->workers[i].isactive = true;
        CHECK_RET(pthread_create(&server->workers[i].pthread, NULL, thread_function, server));
    }

    return 0;
}

void* thread_function(void* arg) {
    server_t* server = (server_t*)arg;
    job_t job;

    printf(BOLD GREEN"[SERVER][INFO] Started!"RES"\n");

    while (server->isrunning) {
        if (get_from_queue(&server->queue, &job) == -1) { break; }
        struct timespec start_time, end_time;
        clock_gettime(1, &start_time);

        struct stat st; int st_result = stat(job.path, &st);
        off_t size = (st_result) ? st.st_size : -1;
        time_t last_upd_sec = (st_result) ? st.st_mtime : -1;
        long last_upd_nsec = (st_result) ? st.st_mtim.tv_nsec : -1;

        if (st_result == -1) {
            response_msg_t resp = { .type = RESP_ERROR, .error_code = errno };
            snprintf(resp.message, sizeof(resp.message),"[SERVER][ERRORE] Cannot access file: %s", strerror(errno));
            send_response(job.response_fifo_path, resp);
            continue;
        }

        char hash_result[HASH_HEX_LEN + 1];

        bool cache_hit = search_cache(&server->cache, job.path, size, last_upd_sec, last_upd_nsec, hash_result);

        if (!cache_hit) {
            if (compute_sha256(job.path, hash_result) == -1) {
                    response_msg_t resp = { .type = RESP_ERROR, .error_code = errno };
                    snprintf(resp.message, sizeof(resp.message),"[SERVER][ERRORE] Cannot compute hash: %s", strerror(errno));
                    send_response(job.response_fifo_path, resp);
                    continue;
            }

            add_to_cache(&server->cache, job.path, size, last_upd_sec, last_upd_nsec, hash_result);

            CHECK(pthread_mutex_lock(&server->stats_mtx));
            server->stats.files_processed++;
            CHECK(pthread_mutex_unlock(&server->stats_mtx));
        }

        response_msg_t resp = { .type = RESP_HASH, .error_code = 0, .message = "" };
        strcpy(resp.hash, hash_result);
        CHECK(send_response(job.response_fifo_path, resp));

        clock_gettime(1, &end_time);
        double processing_time = get_time_diff(start_time, end_time);

        CHECK(pthread_mutex_lock(&server->stats_mtx));
        server->stats.total_requests++;
        if (cache_hit) {
            server->stats.cache_hits++;
        } else {
            server->stats.cache_misses++;
        }


        double total_time = server->stats.avg_processing_time * (server->stats.total_requests - 1);
        server->stats.avg_processing_time = (total_time + processing_time) / server->stats.total_requests;

        CHECK(pthread_mutex_unlock(&server->stats_mtx));

        printf(BOLD GREEN"[SERVER][INFO] Processed file: %s (%.3f ms, %s)"RES"\n",
               job.path, processing_time * 1000, cache_hit ? "cache hit" : "computed");
    }

    printf(BOLD YELLOW"[SERVER][INFO] Worker pthread terminated"RES"\n");
    return NULL;
}

int compute_sha256(const char* filepath, char* hash_hex) {
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        return -1;
    }
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
        sprintf(hash_hex + (i * 2), "%02x", hash[i]);
    }
    hash_hex[HASH_HEX_LEN] = '\0';

    return 0;
}

void close_queue(job_queue_t* q) {
    CHECK(pthread_mutex_lock(&q->mutex));

    job_t* current = q->head;
    while (current) {
        job_t* next = current->next;
        free(current);
        current = next;
    }
    q->head = NULL;
    q->dim = 0;

    CHECK(pthread_mutex_unlock(&q->mutex));
    CHECK(pthread_mutex_destroy(&q->mutex));
    CHECK(pthread_cond_destroy(&q->cond_var));
}

void add_to_queue(job_queue_t* q, const char* path, const char* response_fifo_path, pid_t pid, off_t size) {
    job_t* new_job = malloc(sizeof(job_t));
    if (!new_job) return;

    strncpy(new_job->path, path, MAX_PATH_LEN - 1);
    new_job->path[MAX_PATH_LEN - 1] = '\0';

    strncpy(new_job->response_fifo_path, response_fifo_path, MAX_PATH_LEN - 1);
    new_job->response_fifo_path[MAX_PATH_LEN - 1] = '\0';

    new_job->pid = pid;
    new_job->size = size;
    new_job->next = NULL;

    CHECK(pthread_mutex_lock(&q->mutex));

    if (q->isclosed) {
        free(new_job);
        CHECK(pthread_mutex_unlock(&q->mutex));
        return;
    }

    job_t** ptr = &q->head;

    while (*ptr) {

        bool continue_traversal = (q->order == ASCENDANT) ? (size >= (*ptr)->size) : (size <= (*ptr)->size);
        if (!continue_traversal) break;
        ptr = &(*ptr)->next;
    }
    new_job->next = *ptr;
    *ptr = new_job;

    q->dim++;
    CHECK(pthread_cond_signal(&q->cond_var));
    CHECK(pthread_mutex_unlock(&q->mutex));
}

int get_from_queue(job_queue_t* q, job_t* out) {
    CHECK(pthread_mutex_lock(&q->mutex));

    while (!q->head && !q->isclosed) {
        CHECK(pthread_cond_wait(&q->cond_var, &q->mutex));
    }

    if (q->isclosed && !q->head) {
        CHECK(pthread_mutex_unlock(&q->mutex));
        return -1;
    }

    job_t* job = q->head;
    q->head = job->next;
    q->dim--;

    *out = *job;
    free(job);

    CHECK(pthread_mutex_unlock(&q->mutex));
    return 0;
}

void close_cache(cache_t* cache) {
    CHECK(pthread_mutex_lock(&cache->mutex));

    for (size_t i = 0; i < cache->dim; i++) {
        cache_entry_t* entry = cache->buckets[i];
        while (entry) {
            cache_entry_t* next = entry->next;
            CHECK(pthread_mutex_destroy(&entry->mutex));
            CHECK(pthread_cond_destroy(&entry->cond_var));
            free(entry);
            entry = next;
        }
    }

    free(cache->buckets);
    CHECK(pthread_mutex_unlock(&cache->mutex));
    CHECK(pthread_mutex_destroy(&cache->mutex));
}

cache_entry_t* get_cache_entry(cache_t* cache, const char* path) {
    unsigned long hash = 5381;
    const char *p = path;
    while (*p) { hash = ((hash << 5) + hash) + *p; p++; } // hash del path
    size_t bucket = hash % cache->dim;

    CHECK(pthread_mutex_lock(&cache->mutex));

    cache_entry_t* entry = cache->buckets[bucket];
    while (entry && strcmp(entry->path, path) != 0) {
        entry = entry->next;
    }

    if (!entry) {
        entry = malloc(sizeof(cache_entry_t));
        if (entry) {
            *entry = (cache_entry_t){.next = cache->buckets[bucket]};
            strncpy(entry->path, path,  MAX_PATH_LEN - 1);
            entry->path[MAX_PATH_LEN - 1] = '\0';
            pthread_mutex_init(&entry->mutex, NULL);
            pthread_cond_init(&entry->cond_var, NULL);
            cache->buckets[bucket] = entry;
        }
    }

    CHECK(pthread_mutex_unlock(&cache->mutex));
    return entry;
}

bool search_cache(cache_t* cache, const char* path, off_t size, time_t last_upd_sec, long last_upd_nsec, char* hash_out) {
    cache_entry_t* entry = get_cache_entry(cache, path);
    if (!entry) {
        CHECK(pthread_mutex_lock(&cache->mutex));
        cache->misses++;
        CHECK(pthread_mutex_unlock(&cache->mutex));
        return false;
    }

    CHECK(pthread_mutex_lock(&entry->mutex));
    

    if (entry->iscomputed && entry->sz == size &&
        entry->last_upd_sec == last_upd_sec && entry->last_upd_nsec == last_upd_nsec) {
        strcpy(hash_out, entry->hash);
        CHECK(pthread_mutex_unlock(&entry->mutex));

        CHECK(pthread_mutex_lock(&cache->mutex));
        cache->hits++;
        CHECK(pthread_mutex_unlock(&cache->mutex));
        return true;
    }
    

    if (entry->iscomputing) {
        entry->num_waiters++;
        while (entry->iscomputing) {
            CHECK(pthread_cond_wait(&entry->cond_var, &entry->mutex));
        }
        entry->num_waiters--;
        

        if (entry->iscomputed && entry->sz == size &&
            entry->last_upd_sec == last_upd_sec && entry->last_upd_nsec == last_upd_nsec) {
            strcpy(hash_out, entry->hash);
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

void add_to_cache(cache_t* cache, const char* path, off_t size, time_t last_upd_sec, long last_upd_nsec, const char* hash) {
    cache_entry_t* entry = get_cache_entry(cache, path);
    if (!entry) return;

    CHECK(pthread_mutex_lock(&entry->mutex));

    strcpy(entry->hash, hash);
    entry->sz = size;
    entry->last_upd_sec = last_upd_sec;
    entry->last_upd_nsec = last_upd_nsec;
    entry->iscomputed = true;
    entry->iscomputing = false;

    if (entry->num_waiters > 0) {
        CHECK(pthread_cond_broadcast(&entry->cond_var));
    }

    CHECK(pthread_mutex_unlock(&entry->mutex));
}

void signal_handler(int sig) {
    if (g_server) {
        printf(BOLD YELLOW"\n[SERVER][INFO] Received signal %d, shutting down server"RES"\n", sig);
        g_server->isrunning = false;
        CHECK(pthread_mutex_lock(&g_server->queue.mutex));
        g_server->queue.isclosed = true;
        CHECK(pthread_cond_broadcast(&g_server->queue.cond_var));
        CHECK(pthread_mutex_unlock(&g_server->queue.mutex));
    }
}





void close_server(server_t* server) {
    server->isrunning = false;
    
    CHECK(pthread_mutex_lock(&server->queue.mutex));
    server->queue.isclosed = true;
    CHECK(pthread_cond_broadcast(&server->queue.cond_var));
    CHECK(pthread_mutex_unlock(&server->queue.mutex));

    for (int i = 0; i < server->num_workers; i++) {
        if (server->workers[i].isactive) {
            CHECK(pthread_join(server->workers[i].pthread, NULL));
            server->workers[i].isactive = false;
        }
    }

    close_queue(&server->queue);
    close_cache(&server->cache);
    CHECK(pthread_mutex_destroy(&server->stats_mtx));
}

int run_server(server_t* server) {
    int req_fd;
    request_msg_t req;
     
    CHECK_RET(create_fifo(REQUEST_FIFO_PATH, 0666));
    while (server->isrunning) {
        req_fd = open_fifo_read(REQUEST_FIFO_PATH);
        if (req_fd == -1) {
            if (errno == EINTR) continue;
            else perror("[SERVER][ERRORE] Open Fifo Read");
            break;
        }

        while (server->isrunning) {
            if (read_exact(req_fd, &req, sizeof(req)) == -1) { break; }
            
            switch (req.type) {
                case REQ_HASH_FILE: {
                    if (access(req.path, F_OK)!=0) {
                            response_msg_t resp = { .type = RESP_ERROR, .error_code = ENOENT, .message = "File not found" };
                            CHECK(send_response(req.response_fifo_path, resp));
                            break;
                    }
                    struct stat st; off_t size = (stat(req.path, &st) == 0) ? st.st_size : -1;
                    if (size == -1) {
                        response_msg_t resp = { .type = RESP_ERROR, .error_code = errno };
                        CHECK(snprintf(resp.message, sizeof(resp.message), "%s", strerror(errno)));
                        CHECK(send_response(req.response_fifo_path, resp));
                        break;
                    }
                    printf(BOLD GREEN"[SERVER][INFO] Received hash request for: %s (size: %lld bytes)"RES"\n", req.path, (long long)size);
                    add_to_queue(&server->queue, req.path, req.response_fifo_path, req.pid, size);
                    break;
                }
                case REQ_STATS: {
                    response_msg_t resp = { .type = RESP_STATS, .error_code = 0 };

                    CHECK(pthread_mutex_lock(&server->stats_mtx));
                    CHECK(pthread_mutex_lock(&server->cache.mutex));
                    server->stats.cache_hits = server->cache.hits;
                    server->stats.cache_misses = server->cache.misses;
                    CHECK(pthread_mutex_unlock(&server->cache.mutex));

                    resp.stats = server->stats;
                    CHECK(pthread_mutex_unlock(&server->stats_mtx));

                    CHECK(send_response(req.response_fifo_path, resp));
                    break;
                }
                case REQ_TERMINATE:
                    printf(BOLD YELLOW"[SERVER][INFO] Received termination request"RES"\n");
                    server->isrunning = false;
                    break;
                default:
                    fprintf(stderr, BOLD RED"[SERVER][ERRORE] Unknown request type: %d"RES"\n", req.type);
                    break;
            }
        }

        close(req_fd);
    }

    return 0;
}

void show_statistics(const stats_t* stats) {
    printf(BOLD BLUE"\tStatistiche"RES"\n");
    printf(BOLD BLUE"Cache Hit Ratio: %.2f%%"RES"\n", stats->total_requests > 0 ? (100.0 * stats->cache_hits / stats->total_requests) : 0.0);
    printf(BOLD BLUE"Numero File Processati: %lu"RES"\n", stats->files_processed);
    printf(BOLD BLUE"Tempo Medio di Processamento: %.3f ms"RES"\n", stats->avg_processing_time * 1000);
    printf(BOLD BLUE"Numero Richieste: %lu"RES"\n", stats->total_requests);
    printf(BOLD BLUE"Numero Cache Hits: %lu"RES"\n", stats->cache_hits);
    printf(BOLD BLUE"Numero Cache Misses: %lu"RES"\n", stats->cache_misses);
}