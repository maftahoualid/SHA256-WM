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


off_t file_size(const char* path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        return -1;
    }
    return st.st_size;
}

int get_file_mtime(const char* path, time_t* sec, long* nsec) {
    struct stat st;
    if (stat(path, &st) == -1) {
        return -1;
    }
    *sec = st.st_mtime;
    *nsec = st.st_mtim.tv_nsec;
    return 0;
}

bool file_exists(const char* path) {
    int result = access(path, F_OK);
    return (result == 0);
}

void print_stats(const stats_t* stats) {
    printf("=== Server Statistics ===\n");
    printf("Total requests: %lu\n", stats->total_requests);
    printf("Cache hits: %lu\n", stats->cache_hits);
    printf("Cache misses: %lu\n", stats->cache_misses);
    printf("Files processed: %lu\n", stats->files_processed);

    printf("Cache hit ratio: %.2f%%\n", stats->total_requests > 0 ? (100.0 * stats->cache_hits / stats->total_requests) : 0.0);
    printf("Average processing time: %.3f ms\n", stats->avg_processing_time * 1000);
    printf("========================\n");
}

int compute_sha256(const char* filepath, char* hash_hex) {
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        return -1;
    }
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);

    char buffer[8192];
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

void jq_init(job_queue_t* q, int order) {
    q->head = NULL;
    q->closed = false;
    q->order = order;
    q->count = 0;
    pthread_mutex_init(&q->mtx, NULL);
    pthread_cond_init(&q->cv, NULL);
}

void jq_destroy(job_queue_t* q) {
    pthread_mutex_lock(&q->mtx);

    job_t* current = q->head;
    while (current) {
        job_t* next = current->next;
        free(current);
        current = next;
    }
    q->head = NULL;
    q->count = 0;

    pthread_mutex_unlock(&q->mtx);
    pthread_mutex_destroy(&q->mtx);
    pthread_cond_destroy(&q->cv);
}

void jq_close(job_queue_t* q) {
    pthread_mutex_lock(&q->mtx);
    q->closed = true;
    pthread_cond_broadcast(&q->cv);
    pthread_mutex_unlock(&q->mtx);
}

void jq_push(job_queue_t* q, const char* path, const char* resp_fifo, pid_t client_pid, off_t size) {
    job_t* new_job = malloc(sizeof(job_t));
    if (!new_job) return;

    strncpy(new_job->path, path, MAX_PATH_LEN - 1);
    new_job->path[MAX_PATH_LEN - 1] = '\0';

    strncpy(new_job->resp_fifo, resp_fifo, MAX_PATH_LEN - 1);
    new_job->resp_fifo[MAX_PATH_LEN - 1] = '\0';

    new_job->client_pid = client_pid;
    new_job->size = size;
    new_job->next = NULL;

    pthread_mutex_lock(&q->mtx);

    if (q->closed) {
        free(new_job);
        pthread_mutex_unlock(&q->mtx);
        return;
    }

    job_t** ptr = &q->head;

    while (*ptr) {

        bool continue_traversal = (q->order == ORDER_ASC) ? (size >= (*ptr)->size) : (size <= (*ptr)->size);
        if (!continue_traversal) break;
        ptr = &(*ptr)->next;
    }
    new_job->next = *ptr;
    *ptr = new_job;

    q->count++;
    pthread_cond_signal(&q->cv);
    pthread_mutex_unlock(&q->mtx);
}

int jq_pop(job_queue_t* q, job_t* out) {
    pthread_mutex_lock(&q->mtx);

    while (!q->head && !q->closed) {
        pthread_cond_wait(&q->cv, &q->mtx);
    }

    if (q->closed && !q->head) {
        pthread_mutex_unlock(&q->mtx);
        return -1;
    }

    job_t* job = q->head;
    q->head = job->next;
    q->count--;

    *out = *job;
    free(job);

    pthread_mutex_unlock(&q->mtx);
    return 0;
}

unsigned long path_hash(const char *s) {
    unsigned long h = 5381;
    while (*s) h = ((h << 5) + h) + *s++;
    return h;
}

void cache_init(cache_t* c, size_t nbuckets) {
    c->buckets = calloc(nbuckets, sizeof(cache_entry_t*));
    c->nbuckets = nbuckets;
    c->hits = 0;
    c->misses = 0;
    pthread_mutex_init(&c->mtx, NULL);
}

void cache_destroy(cache_t* c) {
    pthread_mutex_lock(&c->mtx);

    for (size_t i = 0; i < c->nbuckets; i++) {
        cache_entry_t* entry = c->buckets[i];
        while (entry) {
            cache_entry_t* next = entry->next;
            pthread_mutex_destroy(&entry->mtx);
            pthread_cond_destroy(&entry->cv);
            free(entry);
            entry = next;
        }
    }

    free(c->buckets);
    pthread_mutex_unlock(&c->mtx);
    pthread_mutex_destroy(&c->mtx);
}

cache_entry_t* cache_get_or_create(cache_t* c, const char* path) {
    unsigned long hash = path_hash(path);
    size_t bucket = hash % c->nbuckets;

    pthread_mutex_lock(&c->mtx);

    cache_entry_t* entry = c->buckets[bucket];
    while (entry && strcmp(entry->path, path) != 0) {
        entry = entry->next;
    }

    if (!entry) {
        entry = malloc(sizeof(cache_entry_t));
        if (entry) {
            strncpy(entry->path, path, MAX_PATH_LEN - 1);
            entry->path[MAX_PATH_LEN - 1] = '\0';
            entry->hash[0] = '\0';
            entry->ready = false;
            entry->computing = false;
            entry->waiters = 0;
            entry->sz = 0;
            entry->mtime_sec = 0;
            entry->mtime_nsec = 0;
            pthread_mutex_init(&entry->mtx, NULL);
            pthread_cond_init(&entry->cv, NULL);
            entry->next = c->buckets[bucket];
            c->buckets[bucket] = entry;
        }
    }

    pthread_mutex_unlock(&c->mtx);
    return entry;
}

bool cache_lookup(cache_t* c, const char* path, off_t size, time_t mtime_sec, long mtime_nsec, char* hash_out) {
    cache_entry_t* entry = cache_get_or_create(c, path);
    if (!entry) {
        pthread_mutex_lock(&c->mtx);
        c->misses++;
        pthread_mutex_unlock(&c->mtx);
        return false;
    }

    pthread_mutex_lock(&entry->mtx);
    

    if (entry->ready && entry->sz == size &&
        entry->mtime_sec == mtime_sec && entry->mtime_nsec == mtime_nsec) {
        strcpy(hash_out, entry->hash);
        pthread_mutex_unlock(&entry->mtx);

        pthread_mutex_lock(&c->mtx);
        c->hits++;
        pthread_mutex_unlock(&c->mtx);
        return true;
    }
    

    if (entry->computing) {
        entry->waiters++;
        while (entry->computing) {
            pthread_cond_wait(&entry->cv, &entry->mtx);
        }
        entry->waiters--;
        

        if (entry->ready && entry->sz == size &&
            entry->mtime_sec == mtime_sec && entry->mtime_nsec == mtime_nsec) {
            strcpy(hash_out, entry->hash);
            pthread_mutex_unlock(&entry->mtx);

            pthread_mutex_lock(&c->mtx);
            c->hits++;
            pthread_mutex_unlock(&c->mtx);
            return true;
        }
    }
    

    if (!entry->computing) { entry->computing = true; }

    pthread_mutex_unlock(&entry->mtx);
    pthread_mutex_lock(&c->mtx);
    c->misses++;
    pthread_mutex_unlock(&c->mtx);
    return false;
}

void cache_store(cache_t* c, const char* path, off_t size, time_t mtime_sec, long mtime_nsec, const char* hash) {
    cache_entry_t* entry = cache_get_or_create(c, path);
    if (!entry) return;

    pthread_mutex_lock(&entry->mtx);

    strcpy(entry->hash, hash);
    entry->sz = size;
    entry->mtime_sec = mtime_sec;
    entry->mtime_nsec = mtime_nsec;
    entry->ready = true;
    entry->computing = false;

    if (entry->waiters > 0) {
        pthread_cond_broadcast(&entry->cv);
    }

    pthread_mutex_unlock(&entry->mtx);
}

void signal_handler(int sig) {
    if (g_server_ctx) {
        printf("\nReceived signal %d, shutting down server\n", sig);
        g_server_ctx->running = false;
        jq_close(&g_server_ctx->job_queue);
    }
}

void* worker_thread(void* arg) {
    server_ctx_t* ctx = (server_ctx_t*)arg;
    job_t job;

    printf("Worker thread started\n");

    while (ctx->running) {
        if (jq_pop(&ctx->job_queue, &job) == -1) { break; }
        struct timespec start_time, end_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        
        off_t size = file_size(job.path);
        time_t mtime_sec;
        long mtime_nsec;


        if (size == -1 || get_file_mtime(job.path, &mtime_sec, &mtime_nsec) == -1) {
            response_msg_t resp = { .type = RESP_ERROR, .error_code = errno };
            snprintf(resp.error_msg, sizeof(resp.error_msg), "Cannot access file: %s", strerror(errno));
            send_response(job.resp_fifo, resp);
            continue;
        }

        char hash_result[HASH_HEX_LEN + 1];

        bool cache_hit = cache_lookup(&ctx->cache, job.path, size, mtime_sec, mtime_nsec, hash_result);

        if (!cache_hit) {
            if (compute_sha256(job.path, hash_result) == -1) {
                    response_msg_t resp = { .type = RESP_ERROR, .error_code = errno };
                    snprintf(resp.error_msg, sizeof(resp.error_msg), "Cannot compute hash: %s", strerror(errno));
                    send_response(job.resp_fifo, resp);
                    continue;
            }

            cache_store(&ctx->cache, job.path, size, mtime_sec, mtime_nsec, hash_result);

            pthread_mutex_lock(&ctx->stats_mtx);
            ctx->stats.files_processed++;
            pthread_mutex_unlock(&ctx->stats_mtx);
        }

        response_msg_t resp = { .type = RESP_HASH, .error_code = 0, .error_msg = "" };
        strcpy(resp.hash, hash_result);
        int resp_fd = send_response(job.resp_fifo, resp);
        if (resp_fd == -1) printf("Warning: Cannot open response FIFO for client\n");

        clock_gettime(CLOCK_MONOTONIC, &end_time);
        double processing_time = get_time_diff(start_time, end_time);

        pthread_mutex_lock(&ctx->stats_mtx);
        ctx->stats.total_requests++;
        if (cache_hit) {
            ctx->stats.cache_hits++;
        } else {
            ctx->stats.cache_misses++;
        }


        double total_time = ctx->stats.avg_processing_time * (ctx->stats.total_requests - 1);
        ctx->stats.avg_processing_time = (total_time + processing_time) / ctx->stats.total_requests;

        pthread_mutex_unlock(&ctx->stats_mtx);

        printf("Processed file: %s (%.3f ms, %s)\n",
               job.path, processing_time * 1000, cache_hit ? "cache hit" : "computed");
    }

    printf("Worker thread terminated\n");
    return NULL;
}

int server_init(server_ctx_t* ctx, int num_workers, int order) {
    jq_init(&ctx->job_queue, order);

    cache_init(&ctx->cache, HASH_BUCKET_SIZE);

    memset(&ctx->stats, 0, sizeof(stats_t));
    pthread_mutex_init(&ctx->stats_mtx, NULL);

    ctx->num_workers = num_workers;
    ctx->running = true;

    for (int i = 0; i < num_workers; i++) {
        ctx->workers[i].id = i;
        ctx->workers[i].active = true;

        if (pthread_create(&ctx->workers[i].thread, NULL, worker_thread, ctx) != 0) {
            perror("pthread_create");
            return -1;
        }
    }

    return 0;
}

void server_destroy(server_ctx_t* ctx) {
    ctx->running = false;
    jq_close(&ctx->job_queue);

    for (int i = 0; i < ctx->num_workers; i++) {
        if (ctx->workers[i].active) {
            pthread_join(ctx->workers[i].thread, NULL);
            ctx->workers[i].active = false;
        }
    }

    jq_destroy(&ctx->job_queue);
    cache_destroy(&ctx->cache);
    pthread_mutex_destroy(&ctx->stats_mtx);
}

int server_run(server_ctx_t* ctx) {
    int req_fd;
    request_msg_t req;
    

    if (ensure_fifo(REQUEST_FIFO_PATH, 0666) == -1) { return -1; } 
    
    while (ctx->running) {
        req_fd = open_fifo_read(REQUEST_FIFO_PATH);
        if (req_fd == -1) {
            if (errno == EINTR) continue;
            perror("open request FIFO");
            break;
        }

        while (ctx->running) {
            if (read_exact(req_fd, &req, sizeof(req)) == -1) { break; }
            
            switch (req.type) {
                case REQ_HASH_FILE: {
                    if (!file_exists(req.path)) {
                            response_msg_t resp = { .type = RESP_ERROR, .error_code = ENOENT, .error_msg = "File not found" };
                            send_response(req.resp_fifo, resp);
                            break;
                    }
                    off_t size = file_size(req.path);
                    if (size == -1) {
                        response_msg_t resp = { .type = RESP_ERROR, .error_code = errno };
                        snprintf(resp.error_msg, sizeof(resp.error_msg), "%s", strerror(errno));
                        send_response(req.resp_fifo, resp);
                        break;
                    }
                    printf("Received hash request for: %s (size: %lld bytes)\n", req.path, (long long)size);
                    jq_push(&ctx->job_queue, req.path, req.resp_fifo, req.client_pid, size);
                    break;
                }
                case REQ_STATS: {
                    response_msg_t resp = { .type = RESP_STATS, .error_code = 0 };

                    pthread_mutex_lock(&ctx->stats_mtx);
                    pthread_mutex_lock(&ctx->cache.mtx);
                    ctx->stats.cache_hits = ctx->cache.hits;
                    ctx->stats.cache_misses = ctx->cache.misses;
                    pthread_mutex_unlock(&ctx->cache.mtx);

                    resp.stats = ctx->stats;
                    pthread_mutex_unlock(&ctx->stats_mtx);

                    send_response(req.resp_fifo, resp);
                    break;
                }
                case REQ_TERMINATE:
                    printf("Received termination request\n");
                    ctx->running = false;
                    break;
                default:
                    fprintf(stderr, "Unknown request type: %d\n", req.type);
                    break;
            }
        }

        close(req_fd);
    }

    return 0;
}