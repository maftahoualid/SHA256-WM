#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H

#include "server_structs.h"

extern server_ctx_t* g_server_ctx;

off_t file_size(const char* path);

int get_file_mtime(const char* path, time_t* sec, long* nsec);

bool file_exists(const char* path);

int compute_sha256(const char* filepath, char* hash_hex);

void jq_init(job_queue_t* q, int order);

void jq_destroy(job_queue_t* q);

void jq_close(job_queue_t* q);

void jq_push(job_queue_t* q, const char* path, const char* resp_fifo, pid_t client_pid, off_t size);

int jq_pop(job_queue_t* q, job_t* out);

unsigned long djb2_hash(const char* s);

void cache_init(cache_t* c, size_t nbuckets);

void cache_destroy(cache_t* c);

cache_entry_t* cache_get_or_create(cache_t* c, const char* path);

bool cache_lookup(cache_t* c, const char* path, off_t size, time_t mtime_sec, long mtime_nsec, char* hash_out);

void cache_store(cache_t* c, const char* path, off_t size, time_t mtime_sec, long mtime_nsec, const char* hash);

void signal_handler(int sig);

void* worker_thread(void* arg);

int server_init(server_ctx_t* ctx, int num_workers, int order);

void server_destroy(server_ctx_t* ctx);

int server_run(server_ctx_t* ctx);

void print_stats(const stats_t* stats);

#endif